//! OS-level sandbox enforcement.
//!
//! This module provides platform-specific process isolation for FCP connectors.
//! The sandbox enforces:
//!
//! - Resource limits (memory, CPU, wall-clock time)
//! - Filesystem access controls (read-only paths, writable paths)
//! - Process restrictions (deny exec, deny ptrace)
//! - Network model enforcement (all network via Network Guard in strict/moderate)
//!
//! # Platform Support
//!
//! - **Linux (Tier 1)**: seccomp-bpf + namespaces, optionally Landlock
//! - **macOS (Tier 1)**: seatbelt profiles (sandbox-exec)
//! - **Windows (Tier 2)**: `AppContainer` + job objects

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use fcp_manifest::{NetworkConstraints, SandboxProfile, SandboxSection};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============================================================================
// Errors
// ============================================================================

/// Errors from sandbox operations.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// Platform not supported.
    #[error("sandbox not supported on this platform: {0}")]
    UnsupportedPlatform(String),

    /// Failed to compile policy.
    #[error("failed to compile sandbox policy: {0}")]
    PolicyCompilationFailed(String),

    /// Failed to apply sandbox.
    #[error("failed to apply sandbox: {0}")]
    ApplyFailed(String),

    /// Resource limit exceeded.
    #[error("resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),

    /// Invalid configuration.
    #[error("invalid sandbox configuration: {0}")]
    InvalidConfig(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Syscall failed.
    #[error("syscall failed: {0}")]
    SyscallFailed(String),

    /// Timeout.
    #[error("wall-clock timeout exceeded")]
    Timeout,
}

// ============================================================================
// Compiled Policy
// ============================================================================

/// A compiled sandbox policy ready for application.
///
/// This is the platform-agnostic representation of sandbox rules after
/// compilation from `SandboxSection`. Platform-specific implementations
/// translate this into native enforcement primitives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledPolicy {
    /// Original sandbox profile level.
    pub profile: SandboxProfile,

    /// Memory limit in bytes.
    pub memory_limit_bytes: u64,

    /// CPU limit as a percentage (1-100).
    pub cpu_percent: u8,

    /// Wall-clock timeout.
    pub wall_clock_timeout: Duration,

    /// Paths allowed for read-only access.
    pub readonly_paths: Vec<PathBuf>,

    /// Paths allowed for read-write access.
    pub writable_paths: Vec<PathBuf>,

    /// Deny spawning child processes.
    pub deny_exec: bool,

    /// Deny ptrace/debugging.
    pub deny_ptrace: bool,

    /// Block direct network access (all network via Network Guard IPC).
    ///
    /// True for `strict` and `moderate` profiles.
    pub block_direct_network: bool,

    /// State directory for connector persistent data.
    ///
    /// This is typically `$CONNECTOR_STATE` expanded to an absolute path.
    pub state_dir: Option<PathBuf>,

    /// Additional platform-specific flags.
    pub platform_flags: PlatformFlags,
}

/// Windows `AppContainer` capability that allows outbound client sockets.
pub const WINDOWS_APPCONTAINER_INTERNET_CLIENT: &str = "internetClient";

/// Windows `AppContainer` capability that allows inbound and outbound internet sockets.
pub const WINDOWS_APPCONTAINER_INTERNET_CLIENT_SERVER: &str = "internetClientServer";

/// Windows `AppContainer` capability that allows private-network client/server sockets.
pub const WINDOWS_APPCONTAINER_PRIVATE_NETWORK_CLIENT_SERVER: &str = "privateNetworkClientServer";

const WINDOWS_APPCONTAINER_PROFILE_PREFIX: &str = "fcp";
const WINDOWS_APPCONTAINER_PROFILE_NAME_MAX_LEN: usize = 64;
const WINDOWS_APPCONTAINER_PROFILE_HASH_LEN: usize = 16;
const WINDOWS_FIREWALL_RULE_PREFIX: &str = "fcp-fw";
const WINDOWS_MANDATORY_LOW_RID: u32 = 0x1000;
const WINDOWS_MANDATORY_MEDIUM_RID: u32 = 0x2000;
const WINDOWS_NETWORK_APPCONTAINER_CAPABILITIES: [&str; 3] = [
    WINDOWS_APPCONTAINER_INTERNET_CLIENT,
    WINDOWS_APPCONTAINER_INTERNET_CLIENT_SERVER,
    WINDOWS_APPCONTAINER_PRIVATE_NETWORK_CLIENT_SERVER,
];

/// Platform-specific configuration flags.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PlatformFlags {
    /// Linux: Use Landlock if available (kernel 5.13+).
    #[serde(default)]
    pub linux_use_landlock: bool,

    /// Linux: Use user namespaces for isolation.
    #[serde(default)]
    pub linux_use_userns: bool,

    /// macOS: Entitlements to request.
    #[serde(default)]
    pub macos_entitlements: Vec<String>,

    /// Windows: Use low-integrity `AppContainer`.
    #[serde(default)]
    pub windows_low_integrity: bool,

    /// Windows: `AppContainer` capability names to grant when launching under `AppContainer`.
    ///
    /// Network capabilities are rejected for strict/moderate profiles because those profiles
    /// require all egress to pass through Network Guard. Permissive profiles get
    /// [`WINDOWS_APPCONTAINER_INTERNET_CLIENT`] by default when this list omits an explicit
    /// network capability.
    #[serde(default)]
    pub windows_appcontainer_capabilities: Vec<String>,
}

impl PlatformFlags {
    /// Check if all platform flags are at their default values.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.linux_use_landlock
            && !self.linux_use_userns
            && self.macos_entitlements.is_empty()
            && !self.windows_low_integrity
            && self.windows_appcontainer_capabilities.is_empty()
    }
}

impl CompiledPolicy {
    /// Create a compiled policy from a manifest sandbox section.
    ///
    /// # Arguments
    ///
    /// * `section` - The sandbox section from the connector manifest.
    /// * `state_dir` - Optional absolute path to the connector's state directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the policy cannot be compiled.
    pub fn from_manifest(
        section: &SandboxSection,
        state_dir: Option<PathBuf>,
    ) -> Result<Self, SandboxError> {
        // Validate resource limits — zero values make execution impossible
        if section.memory_mb == 0 {
            return Err(SandboxError::InvalidConfig(
                "memory_mb must be > 0: zero memory limit makes execution impossible".into(),
            ));
        }
        if section.wall_clock_timeout_ms == 0 {
            return Err(SandboxError::InvalidConfig(
                "wall_clock_timeout_ms must be > 0: zero timeout makes execution impossible".into(),
            ));
        }
        if section.cpu_percent == 0 {
            return Err(SandboxError::InvalidConfig(
                "cpu_percent must be > 0: zero CPU makes execution impossible".into(),
            ));
        }
        if section.cpu_percent > 100 {
            return Err(SandboxError::InvalidConfig(format!(
                "cpu_percent must be <= 100, got {}: invalid percentage",
                section.cpu_percent
            )));
        }

        // Expand special paths
        let readonly_paths = compile_paths(
            &section.fs_readonly_paths,
            state_dir.as_ref(),
            "sandbox.fs_readonly_paths",
        )?;

        let mut writable_paths = compile_paths(
            &section.fs_writable_paths,
            state_dir.as_ref(),
            "sandbox.fs_writable_paths",
        )?;

        // Always add state_dir to writable paths if provided
        if let Some(ref dir) = state_dir {
            if !writable_paths.contains(dir) {
                writable_paths.push(dir.clone());
            }
        }

        // Determine if direct network should be blocked
        let block_direct_network = matches!(
            section.profile,
            SandboxProfile::Strict | SandboxProfile::StrictPlus | SandboxProfile::Moderate
        );

        Ok(Self {
            profile: section.profile,
            memory_limit_bytes: u64::from(section.memory_mb) * 1024 * 1024,
            cpu_percent: section.cpu_percent,
            wall_clock_timeout: Duration::from_millis(section.wall_clock_timeout_ms),
            readonly_paths,
            writable_paths,
            deny_exec: section.deny_exec,
            deny_ptrace: section.deny_ptrace,
            block_direct_network,
            state_dir,
            platform_flags: PlatformFlags::default(),
        })
    }

    /// Set platform-specific flags.
    #[must_use]
    pub fn with_platform_flags(mut self, flags: PlatformFlags) -> Self {
        self.platform_flags = flags;
        self
    }

    /// Whether the manifest declared explicit filesystem path restrictions.
    ///
    /// `state_dir` is always merged into `writable_paths` regardless of what
    /// the manifest asked for, so it is excluded here — the signal is whether
    /// the connector author listed `fs_readonly_paths` or additional
    /// `fs_writable_paths`, i.e. expressed an intent to be confined to a
    /// specific set of paths.
    ///
    /// The Linux native sandbox uses this to fail closed rather than silently
    /// run a connector unconfined when no path-confinement mechanism
    /// (Landlock, or mount-namespace bind mounts) will actually enforce the
    /// declared restrictions (bead sandbox-linux-no-default-fs-confinement).
    #[must_use]
    pub fn declares_fs_path_restrictions(&self) -> bool {
        if !self.readonly_paths.is_empty() {
            return true;
        }
        self.writable_paths
            .iter()
            .any(|path| self.state_dir.as_ref() != Some(path))
    }

    /// Return the normalized Windows `AppContainer` capabilities implied by this policy.
    pub fn windows_appcontainer_capabilities(&self) -> Result<Vec<String>, SandboxError> {
        let mut capabilities = normalize_windows_appcontainer_capabilities(
            &self.platform_flags.windows_appcontainer_capabilities,
        )?;
        if !self.block_direct_network
            && !capabilities
                .iter()
                .any(|capability| is_windows_network_appcontainer_capability(capability))
        {
            capabilities.push(WINDOWS_APPCONTAINER_INTERNET_CLIENT.to_owned());
            capabilities.sort();
        }
        if self.block_direct_network {
            for capability in &capabilities {
                if is_windows_network_appcontainer_capability(capability) {
                    return Err(SandboxError::InvalidConfig(format!(
                        "windows AppContainer capability `{capability}` conflicts with sandbox profile {:?}: direct network must remain blocked",
                        self.profile
                    )));
                }
            }
        }

        Ok(capabilities)
    }

    /// Build the deterministic Windows `AppContainer` profile metadata for a connector.
    pub fn windows_appcontainer_profile(
        &self,
        connector_id: &str,
    ) -> Result<WindowsAppContainerProfile, SandboxError> {
        WindowsAppContainerProfile::from_policy(connector_id, self)
    }
}

/// Deterministic Windows `AppContainer` profile metadata derived from an FCP sandbox policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsAppContainerProfile {
    /// `AppContainer` profile name. Windows requires at most 64 characters matching
    /// `[-_. A-Za-z0-9]+`.
    pub name: String,

    /// Capability names that will be resolved to `AppContainer` capability SIDs.
    #[serde(default)]
    pub capabilities: Vec<String>,
}

/// Result from attempting to create a Windows `AppContainer` profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAppContainerCreateOutcome {
    /// A new per-user profile was created.
    Created,
    /// The profile already existed and should be resolved by name.
    AlreadyExists,
}

/// High-level lifecycle action taken for a Windows `AppContainer` profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAppContainerLifecycleAction {
    /// The operator has not enabled the Windows `AppContainer` launch path.
    SkippedInactive,
    /// A new profile was created.
    Created,
    /// An existing profile SID was resolved and reused.
    ReusedExisting,
    /// The profile metadata was valid, but the requested launch mechanism is unsupported.
    LaunchPathUnsupported,
}

/// Cleanup decision for a Windows `AppContainer` lifecycle attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAppContainerCleanupDecision {
    /// No profile was created or opened.
    None,
    /// The profile is retained for deterministic connector-instance reuse.
    RetainProfile,
    /// The profile was removed by an explicit smoke-test cleanup pass.
    DeleteProfile,
}

/// Fakeable profile API used by the Windows backend lifecycle controller.
#[cfg(any(test, target_os = "windows"))]
#[allow(clippy::redundant_pub_crate)]
pub(super) trait WindowsAppContainerProfileApi {
    /// Create the profile, or report that it already exists.
    fn create_profile(
        &mut self,
        profile: &WindowsAppContainerProfile,
    ) -> Result<WindowsAppContainerCreateOutcome, SandboxError>;

    /// Resolve the SID for an existing profile.
    fn derive_profile_sid(&mut self, profile_name: &str) -> Result<(), SandboxError>;

    /// Delete the profile for smoke/e2e cleanup.
    fn delete_profile(&mut self, profile_name: &str) -> Result<(), SandboxError>;
}

/// Structured report for Windows `AppContainer` profile preparation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsAppContainerLifecycleReport {
    /// Profile metadata used by the lifecycle operation.
    pub profile: WindowsAppContainerProfile,
    /// Lifecycle action taken.
    pub action: WindowsAppContainerLifecycleAction,
    /// Whether an `AppContainer` SID was obtained or resolved.
    pub sid_present: bool,
    /// Cleanup choice made by the lifecycle controller.
    pub cleanup: WindowsAppContainerCleanupDecision,
    /// Structured skip reason when no OS call was attempted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
}

#[cfg(any(test, target_os = "windows"))]
impl WindowsAppContainerLifecycleReport {
    fn inactive(profile: WindowsAppContainerProfile) -> Self {
        Self {
            profile,
            action: WindowsAppContainerLifecycleAction::SkippedInactive,
            sid_present: false,
            cleanup: WindowsAppContainerCleanupDecision::None,
            skip_reason: Some(
                "windows_appcontainer_not_active_createprocessasuser_path_unwired".to_owned(),
            ),
        }
    }

    const fn active(
        profile: WindowsAppContainerProfile,
        action: WindowsAppContainerLifecycleAction,
    ) -> Self {
        Self {
            profile,
            action,
            sid_present: true,
            cleanup: WindowsAppContainerCleanupDecision::RetainProfile,
            skip_reason: None,
        }
    }
}

/// Run Windows `AppContainer` profile create/reuse logic through a fakeable API.
#[cfg(any(test, target_os = "windows"))]
#[allow(clippy::redundant_pub_crate)]
pub(super) fn prepare_windows_appcontainer_lifecycle<A>(
    profile: WindowsAppContainerProfile,
    appcontainer_active: bool,
    api: &mut A,
) -> Result<WindowsAppContainerLifecycleReport, SandboxError>
where
    A: WindowsAppContainerProfileApi,
{
    if !appcontainer_active {
        return Ok(WindowsAppContainerLifecycleReport::inactive(profile));
    }

    match api.create_profile(&profile)? {
        WindowsAppContainerCreateOutcome::Created => {
            Ok(WindowsAppContainerLifecycleReport::active(
                profile,
                WindowsAppContainerLifecycleAction::Created,
            ))
        }
        WindowsAppContainerCreateOutcome::AlreadyExists => {
            api.derive_profile_sid(&profile.name)?;
            Ok(WindowsAppContainerLifecycleReport::active(
                profile,
                WindowsAppContainerLifecycleAction::ReusedExisting,
            ))
        }
    }
}

/// Delete a Windows `AppContainer` profile through the fakeable profile API.
#[cfg(any(test, target_os = "windows"))]
#[allow(clippy::redundant_pub_crate)]
#[allow(dead_code)]
pub(super) fn cleanup_windows_appcontainer_profile<A>(
    profile_name: &str,
    api: &mut A,
) -> Result<WindowsAppContainerCleanupDecision, SandboxError>
where
    A: WindowsAppContainerProfileApi,
{
    validate_windows_appcontainer_profile_name(profile_name)?;
    api.delete_profile(profile_name)?;
    Ok(WindowsAppContainerCleanupDecision::DeleteProfile)
}

/// Redaction-safe JSONL evidence for Windows `AppContainer` smoke/skips.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WindowsAppContainerEvidence {
    /// Schema marker for downstream evidence validators.
    pub schema: &'static str,
    /// Operating-system family for this evidence record.
    pub os: &'static str,
    /// Hashed connector id or connector seed.
    pub connector_id_hash: String,
    /// Hashed `AppContainer` profile name.
    pub profile_name_hash: String,
    /// Capability names after normalization and deny-policy checks.
    pub capabilities: Vec<String>,
    /// Capability mapping decision.
    pub capability_decision: &'static str,
    /// Lifecycle action result.
    pub lifecycle_action: WindowsAppContainerLifecycleAction,
    /// Whether an `AppContainer` SID was present.
    pub sid_present: bool,
    /// Whether the job object was attached after lifecycle preparation.
    pub job_object_attached: bool,
    /// Stable step ordering for appcontainer -> job-object enforcement.
    pub step_order: Vec<&'static str>,
    /// Final result string for the scripted/e2e action.
    pub action_result: &'static str,
    /// Cleanup decision.
    pub cleanup: WindowsAppContainerCleanupDecision,
    /// Structured skip reason when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
}

impl WindowsAppContainerEvidence {
    /// Build redaction-safe evidence from a lifecycle report.
    #[must_use]
    pub fn from_lifecycle(
        connector_id: &str,
        report: &WindowsAppContainerLifecycleReport,
        job_object_attached: bool,
        action_result: &'static str,
    ) -> Self {
        let mut step_order = vec!["appcontainer_lifecycle"];
        if job_object_attached {
            step_order.push("job_object_attach");
        }

        Self {
            schema: "fcp.windows_appcontainer_smoke.v1",
            os: "windows",
            connector_id_hash: stable_fnv1a64_hex(connector_id),
            profile_name_hash: stable_fnv1a64_hex(&report.profile.name),
            capabilities: report.profile.capabilities.clone(),
            capability_decision: if report.profile.capabilities.is_empty() {
                "none_required"
            } else {
                "mapped"
            },
            lifecycle_action: report.action,
            sid_present: report.sid_present,
            job_object_attached,
            step_order,
            action_result,
            cleanup: report.cleanup,
            skip_reason: report.skip_reason.clone(),
        }
    }

    /// Render this record as a single JSONL line.
    pub fn to_jsonl_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Process-launch mechanism selected for Windows `AppContainer` enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsAppContainerProcessLaunchMechanism {
    /// No process launch was attempted because `AppContainer` launch is inactive.
    SkippedInactive,
    /// `STARTUPINFOEX` security-capability attributes are used for launch.
    StartupInfoExSecurityCapabilities,
    /// `std::process::Command` mutation cannot carry `AppContainer` attributes.
    UnsupportedStdCommandMutation,
}

/// Intended job-object attachment for a Windows `AppContainer` launched process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsJobObjectAttachmentIntent {
    /// No child process is expected, so no job object attachment is planned.
    None,
    /// Attach the launched child process to a configured job object immediately after launch.
    AttachAfterLaunch,
}

/// Redaction-safe JSONL evidence for Windows `AppContainer` process-launch readiness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WindowsAppContainerProcessLaunchEvidence {
    /// Schema marker for downstream evidence validators.
    pub schema: &'static str,
    /// Operating-system family for this evidence record.
    pub os: &'static str,
    /// Hashed connector id or connector seed.
    pub connector_id_hash: String,
    /// Hashed `AppContainer` profile name.
    pub profile_name_hash: String,
    /// Capability names after normalization and deny-policy checks.
    pub capabilities: Vec<String>,
    /// Capability mapping decision.
    pub capability_decision: &'static str,
    /// Profile lifecycle action observed before launch.
    pub lifecycle_action: WindowsAppContainerLifecycleAction,
    /// Whether an `AppContainer` SID was present for launch.
    pub sid_present: bool,
    /// Launch mechanism selected by the Windows sandbox.
    pub launch_mechanism: WindowsAppContainerProcessLaunchMechanism,
    /// Integrity level requested for the child process.
    pub integrity_level: &'static str,
    /// Redaction-safe integrity enforcement mechanism.
    pub integrity_enforcement: &'static str,
    /// Whether a process was actually attached to a job object.
    pub job_object_attached: bool,
    /// Expected job-object attachment behavior.
    pub job_object_attachment_intent: WindowsJobObjectAttachmentIntent,
    /// Hashed launched process id when a child process was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_id_hash: Option<String>,
    /// Final readiness layer this evidence is allowed to claim today.
    pub final_filter_strength: FilterStrength,
    /// Stable step ordering for lifecycle, launch, and job attachment.
    pub step_order: Vec<&'static str>,
    /// Final result string for the scripted/e2e action.
    pub action_result: &'static str,
    /// Cleanup decision.
    pub cleanup: WindowsAppContainerCleanupDecision,
    /// Structured skip reason when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
}

impl WindowsAppContainerProcessLaunchEvidence {
    /// Build redaction-safe process-launch evidence from a lifecycle report.
    #[must_use]
    pub fn from_lifecycle(
        connector_id: &str,
        report: &WindowsAppContainerLifecycleReport,
        launch_mechanism: WindowsAppContainerProcessLaunchMechanism,
        job_object_attached: bool,
        action_result: &'static str,
        process_id: Option<u32>,
    ) -> Self {
        let mut step_order = vec!["appcontainer_lifecycle"];
        if launch_mechanism
            == WindowsAppContainerProcessLaunchMechanism::StartupInfoExSecurityCapabilities
        {
            step_order.push("startupinfoex_security_capabilities");
        }
        if job_object_attached {
            step_order.push("job_object_attach");
        }

        Self {
            schema: "fcp.windows_appcontainer_process_launch.v1",
            os: "windows",
            connector_id_hash: stable_fnv1a64_hex(connector_id),
            profile_name_hash: stable_fnv1a64_hex(&report.profile.name),
            capabilities: report.profile.capabilities.clone(),
            capability_decision: if report.profile.capabilities.is_empty() {
                "none_required"
            } else {
                "mapped"
            },
            lifecycle_action: report.action,
            sid_present: report.sid_present,
            launch_mechanism,
            integrity_level: "not_requested",
            integrity_enforcement: "none",
            job_object_attached,
            job_object_attachment_intent: if report.sid_present {
                WindowsJobObjectAttachmentIntent::AttachAfterLaunch
            } else {
                WindowsJobObjectAttachmentIntent::None
            },
            process_id_hash: process_id.map(|pid| stable_fnv1a64_hex(&pid.to_string())),
            final_filter_strength: FilterStrength::ProcessLimit,
            step_order,
            action_result,
            cleanup: report.cleanup,
            skip_reason: report.skip_reason.clone(),
        }
    }

    /// Record child-process integrity enforcement after the lifecycle record is built.
    #[must_use]
    pub fn with_integrity_enforcement(
        mut self,
        integrity_level: &'static str,
        integrity_enforcement: &'static str,
    ) -> Self {
        self.integrity_level = integrity_level;
        self.integrity_enforcement = integrity_enforcement;

        if integrity_enforcement != "none" {
            let insert_at = self
                .step_order
                .iter()
                .position(|step| *step == "job_object_attach")
                .unwrap_or(self.step_order.len());
            self.step_order
                .insert(insert_at, "integrity_level_enforcement");
        }

        self
    }

    /// Render this record as a single JSONL line.
    pub fn to_jsonl_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Requested Windows token integrity level for a connector process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsIntegrityLevelRequest {
    /// Inherit the caller's normal medium-integrity process token.
    Medium,
    /// Create a low-integrity primary token for the child process.
    Low,
}

impl WindowsIntegrityLevelRequest {
    const fn from_low_integrity_requested(low_integrity_requested: bool) -> Self {
        if low_integrity_requested {
            Self::Low
        } else {
            Self::Medium
        }
    }

    /// Stable text label for evidence and Windows logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    const fn mandatory_rid(self) -> u32 {
        match self {
            Self::Medium => WINDOWS_MANDATORY_MEDIUM_RID,
            Self::Low => WINDOWS_MANDATORY_LOW_RID,
        }
    }
}

/// Windows launch surface that determines whether low-integrity token setup is safe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsIntegrityOperationMode {
    /// Legacy in-process `Sandbox::apply` path.
    InProcessApply,
    /// `std::process::Command` mutation path, which cannot carry `STARTUPINFOEX`.
    StdCommandMutation,
    /// Dedicated `STARTUPINFOEX` child-process launch path.
    StartupInfoExChild,
}

/// Readiness status for Windows integrity-level enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsIntegrityPlanStatus {
    /// Medium integrity inherits the current process token; no token mutation is required.
    InheritedProcess,
    /// Low integrity can be enforced through a duplicated primary child token.
    LowPrimaryTokenRequired,
    /// Low integrity was requested on a launch surface that cannot safely enforce it.
    LowIntegrityRequiresChildLaunch,
    /// Low integrity was requested, but the `AppContainer` child-launch path is inactive.
    AppContainerInactive,
}

impl WindowsIntegrityPlanStatus {
    const fn skip_reason(self) -> Option<&'static str> {
        match self {
            Self::InheritedProcess | Self::LowPrimaryTokenRequired => None,
            Self::LowIntegrityRequiresChildLaunch => {
                Some("windows_low_integrity_requires_startupinfoex_child_launch")
            }
            Self::AppContainerInactive => {
                Some("windows_appcontainer_not_active_createprocessasuser_path_unwired")
            }
        }
    }
}

/// Lifecycle action recorded for Windows integrity-level setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsIntegrityLifecycleAction {
    /// Medium integrity inherited the process token.
    SkippedMediumIntegrity,
    /// Low-integrity child token setup was planned but not performed by this evidence path.
    PlannedLowIntegrityChildToken,
    /// Low-integrity child token setup completed.
    AppliedLowIntegrityChildToken,
    /// Low integrity was rejected before token APIs because the launch path is unsafe.
    RejectedUnsafeLaunchPath,
    /// Low integrity was rejected because the dedicated child-launch path is inactive.
    RejectedAppContainerInactive,
    /// A token API step failed deterministically.
    TokenSetupFailed,
}

/// Deterministic result for fakeable Windows token-integrity API calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsIntegrityTokenApiResult {
    /// Token APIs were not called.
    NotAttempted,
    /// Source token, primary child token, integrity SID, and token label were prepared.
    TokenPrepared,
    /// Required token API is unavailable on this Windows build.
    ApiUnavailable,
    /// The caller lacks the privilege required for the requested token operation.
    PrivilegeDenied,
    /// Opening the current process token failed.
    SourceTokenOpenFailed,
    /// Duplicating a primary child token failed.
    PrimaryTokenDuplicateFailed,
    /// Constructing the mandatory integrity SID failed.
    IntegritySidAllocationFailed,
    /// Applying `TokenIntegrityLevel` failed.
    TokenIntegritySetFailed,
}

impl WindowsIntegrityTokenApiResult {
    const fn skip_reason(self) -> Option<&'static str> {
        match self {
            Self::NotAttempted | Self::TokenPrepared => None,
            Self::ApiUnavailable => Some("windows_integrity_token_api_unavailable"),
            Self::PrivilegeDenied => Some("windows_integrity_token_privilege_denied"),
            Self::SourceTokenOpenFailed => Some("windows_integrity_source_token_open_failed"),
            Self::PrimaryTokenDuplicateFailed => {
                Some("windows_integrity_primary_token_duplicate_failed")
            }
            Self::IntegritySidAllocationFailed => Some("windows_integrity_sid_allocation_failed"),
            Self::TokenIntegritySetFailed => Some("windows_integrity_token_integrity_set_failed"),
        }
    }
}

/// Cleanup expectation for token handles touched during integrity setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsIntegrityTokenCleanupDecision {
    /// No token handles were opened.
    None,
    /// Only the source process token needs to be dropped.
    DropSourceToken,
    /// Source and child primary-token handles need to be dropped.
    DropSourceAndChildTokens,
}

/// Redaction-safe plan for Windows integrity-level token setup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WindowsIntegrityPolicyPlan {
    /// Hashed connector id or connector seed.
    pub connector_id_hash: String,
    /// Requested token integrity level.
    pub requested_level: WindowsIntegrityLevelRequest,
    /// Launch operation that will carry the token decision.
    pub operation: WindowsIntegrityOperationMode,
    /// Plan status.
    pub status: WindowsIntegrityPlanStatus,
    /// Mandatory integrity RID used to build the Windows SID.
    pub integrity_sid_rid: u32,
    /// CreateProcess-family API required by the plan.
    pub required_process_api: &'static str,
    /// Whether a primary child token must be duplicated and labeled.
    pub requires_primary_token: bool,
    /// Structured unsupported reason when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unsupported_reason: Option<&'static str>,
}

/// Report from applying or skipping a Windows integrity policy plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsIntegrityPolicyReport {
    /// Original plan.
    pub plan: WindowsIntegrityPolicyPlan,
    /// Lifecycle action observed.
    pub action: WindowsIntegrityLifecycleAction,
    /// Token API result.
    pub token_api_result: WindowsIntegrityTokenApiResult,
    /// Stable order of token setup steps.
    pub step_order: Vec<&'static str>,
    /// Cleanup decision for token handles.
    pub cleanup: WindowsIntegrityTokenCleanupDecision,
    /// Structured skip or failure reason when applicable.
    pub skip_reason: Option<&'static str>,
}

impl WindowsIntegrityPolicyReport {
    fn skipped(
        plan: WindowsIntegrityPolicyPlan,
        action: WindowsIntegrityLifecycleAction,
        token_api_result: WindowsIntegrityTokenApiResult,
    ) -> Self {
        let skip_reason = plan
            .status
            .skip_reason()
            .or_else(|| token_api_result.skip_reason());
        Self {
            plan,
            action,
            token_api_result,
            step_order: vec!["integrity_level_decision"],
            cleanup: WindowsIntegrityTokenCleanupDecision::None,
            skip_reason,
        }
    }

    #[cfg(any(test, target_os = "windows"))]
    const fn token_failure(
        plan: WindowsIntegrityPolicyPlan,
        token_api_result: WindowsIntegrityTokenApiResult,
        step_order: Vec<&'static str>,
        cleanup: WindowsIntegrityTokenCleanupDecision,
    ) -> Self {
        Self {
            plan,
            action: WindowsIntegrityLifecycleAction::TokenSetupFailed,
            token_api_result,
            step_order,
            cleanup,
            skip_reason: token_api_result.skip_reason(),
        }
    }
}

/// Fakeable Windows token-integrity API used by readiness and failure tests.
#[cfg(any(test, target_os = "windows"))]
#[allow(clippy::redundant_pub_crate)]
pub(super) trait WindowsIntegrityTokenApi {
    /// Open the current process token as the source identity.
    fn open_source_token(&mut self) -> Result<(), WindowsIntegrityTokenApiResult>;

    /// Duplicate the source token as a primary child token.
    fn duplicate_primary_token(&mut self) -> Result<(), WindowsIntegrityTokenApiResult>;

    /// Allocate a mandatory integrity SID for the requested RID.
    fn allocate_integrity_sid(
        &mut self,
        mandatory_rid: u32,
    ) -> Result<(), WindowsIntegrityTokenApiResult>;

    /// Apply the mandatory label to the child token.
    fn set_token_integrity_level(
        &mut self,
        mandatory_rid: u32,
    ) -> Result<(), WindowsIntegrityTokenApiResult>;
}

/// Build a Windows integrity-level token setup plan.
#[must_use]
pub fn plan_windows_integrity_policy(
    connector_id: &str,
    low_integrity_requested: bool,
    operation: WindowsIntegrityOperationMode,
    appcontainer_active: bool,
) -> WindowsIntegrityPolicyPlan {
    let requested_level =
        WindowsIntegrityLevelRequest::from_low_integrity_requested(low_integrity_requested);
    let status = match (requested_level, operation, appcontainer_active) {
        (WindowsIntegrityLevelRequest::Medium, _, _) => {
            WindowsIntegrityPlanStatus::InheritedProcess
        }
        (
            WindowsIntegrityLevelRequest::Low,
            WindowsIntegrityOperationMode::StartupInfoExChild,
            true,
        ) => WindowsIntegrityPlanStatus::LowPrimaryTokenRequired,
        (
            WindowsIntegrityLevelRequest::Low,
            WindowsIntegrityOperationMode::StartupInfoExChild,
            false,
        ) => WindowsIntegrityPlanStatus::AppContainerInactive,
        (WindowsIntegrityLevelRequest::Low, _, _) => {
            WindowsIntegrityPlanStatus::LowIntegrityRequiresChildLaunch
        }
    };
    let requires_primary_token = status == WindowsIntegrityPlanStatus::LowPrimaryTokenRequired;

    WindowsIntegrityPolicyPlan {
        connector_id_hash: stable_fnv1a64_hex(connector_id),
        requested_level,
        operation,
        status,
        integrity_sid_rid: requested_level.mandatory_rid(),
        required_process_api: if requires_primary_token {
            "CreateProcessAsUserW"
        } else {
            "CreateProcessW"
        },
        requires_primary_token,
        unsupported_reason: status.skip_reason(),
    }
}

/// Apply a Windows integrity plan through a fakeable token API.
#[cfg(any(test, target_os = "windows"))]
#[allow(clippy::redundant_pub_crate)]
pub(super) fn apply_windows_integrity_policy<A>(
    plan: WindowsIntegrityPolicyPlan,
    api: &mut A,
) -> WindowsIntegrityPolicyReport
where
    A: WindowsIntegrityTokenApi,
{
    match plan.status {
        WindowsIntegrityPlanStatus::InheritedProcess => {
            return WindowsIntegrityPolicyReport::skipped(
                plan,
                WindowsIntegrityLifecycleAction::SkippedMediumIntegrity,
                WindowsIntegrityTokenApiResult::NotAttempted,
            );
        }
        WindowsIntegrityPlanStatus::LowIntegrityRequiresChildLaunch => {
            return WindowsIntegrityPolicyReport::skipped(
                plan,
                WindowsIntegrityLifecycleAction::RejectedUnsafeLaunchPath,
                WindowsIntegrityTokenApiResult::NotAttempted,
            );
        }
        WindowsIntegrityPlanStatus::AppContainerInactive => {
            return WindowsIntegrityPolicyReport::skipped(
                plan,
                WindowsIntegrityLifecycleAction::RejectedAppContainerInactive,
                WindowsIntegrityTokenApiResult::NotAttempted,
            );
        }
        WindowsIntegrityPlanStatus::LowPrimaryTokenRequired => {}
    }

    let mut step_order = vec!["integrity_level_decision"];
    if let Err(result) = api.open_source_token() {
        return WindowsIntegrityPolicyReport::token_failure(
            plan,
            result,
            step_order,
            WindowsIntegrityTokenCleanupDecision::None,
        );
    }
    step_order.push("open_process_token");

    if let Err(result) = api.duplicate_primary_token() {
        return WindowsIntegrityPolicyReport::token_failure(
            plan,
            result,
            step_order,
            WindowsIntegrityTokenCleanupDecision::DropSourceToken,
        );
    }
    step_order.push("duplicate_primary_token");

    if let Err(result) = api.allocate_integrity_sid(plan.integrity_sid_rid) {
        return WindowsIntegrityPolicyReport::token_failure(
            plan,
            result,
            step_order,
            WindowsIntegrityTokenCleanupDecision::DropSourceAndChildTokens,
        );
    }
    step_order.push("allocate_integrity_sid");

    if let Err(result) = api.set_token_integrity_level(plan.integrity_sid_rid) {
        return WindowsIntegrityPolicyReport::token_failure(
            plan,
            result,
            step_order,
            WindowsIntegrityTokenCleanupDecision::DropSourceAndChildTokens,
        );
    }
    step_order.push("set_token_integrity_level");

    WindowsIntegrityPolicyReport {
        plan,
        action: WindowsIntegrityLifecycleAction::AppliedLowIntegrityChildToken,
        token_api_result: WindowsIntegrityTokenApiResult::TokenPrepared,
        step_order,
        cleanup: WindowsIntegrityTokenCleanupDecision::DropSourceAndChildTokens,
        skip_reason: None,
    }
}

/// Redaction-safe JSONL evidence for Windows integrity-level token setup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WindowsIntegrityPolicyEvidence {
    /// Schema marker for downstream evidence validators.
    pub schema: &'static str,
    /// Operating-system family for this evidence record.
    pub os: &'static str,
    /// Hashed connector id or connector seed.
    pub connector_id_hash: String,
    /// Requested token integrity level.
    pub requested_level: WindowsIntegrityLevelRequest,
    /// Launch operation that carried the decision.
    pub operation: WindowsIntegrityOperationMode,
    /// Readiness status.
    pub plan_status: WindowsIntegrityPlanStatus,
    /// Lifecycle action result.
    pub lifecycle_action: WindowsIntegrityLifecycleAction,
    /// Deterministic token API result.
    pub token_api_result: WindowsIntegrityTokenApiResult,
    /// Mandatory integrity RID used for SID construction.
    pub integrity_sid_rid: u32,
    /// CreateProcess-family API required by the plan.
    pub required_process_api: &'static str,
    /// Whether a primary child token was required.
    pub requires_primary_token: bool,
    /// Stable step ordering for readiness and token setup.
    pub step_order: Vec<&'static str>,
    /// Final readiness layer this evidence is allowed to claim today.
    pub final_filter_strength: FilterStrength,
    /// Cleanup decision for token handles.
    pub cleanup: WindowsIntegrityTokenCleanupDecision,
    /// Structured skip or failure reason when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<&'static str>,
}

impl WindowsIntegrityPolicyEvidence {
    /// Build redaction-safe evidence from an integrity policy report.
    #[must_use]
    pub fn from_report(report: &WindowsIntegrityPolicyReport) -> Self {
        Self {
            schema: "fcp.windows_integrity_policy.v1",
            os: "windows",
            connector_id_hash: report.plan.connector_id_hash.clone(),
            requested_level: report.plan.requested_level,
            operation: report.plan.operation,
            plan_status: report.plan.status,
            lifecycle_action: report.action,
            token_api_result: report.token_api_result,
            integrity_sid_rid: report.plan.integrity_sid_rid,
            required_process_api: report.plan.required_process_api,
            requires_primary_token: report.plan.requires_primary_token,
            step_order: report.step_order.clone(),
            final_filter_strength: FilterStrength::ProcessLimit,
            cleanup: report.cleanup,
            skip_reason: report
                .skip_reason
                .or(report.plan.unsupported_reason)
                .or_else(|| report.token_api_result.skip_reason()),
        }
    }

    /// Build redaction-safe evidence from a plan that has not called token APIs.
    #[must_use]
    pub fn planned_only(plan: WindowsIntegrityPolicyPlan) -> Self {
        let action = match plan.status {
            WindowsIntegrityPlanStatus::InheritedProcess => {
                WindowsIntegrityLifecycleAction::SkippedMediumIntegrity
            }
            WindowsIntegrityPlanStatus::LowPrimaryTokenRequired => {
                WindowsIntegrityLifecycleAction::PlannedLowIntegrityChildToken
            }
            WindowsIntegrityPlanStatus::LowIntegrityRequiresChildLaunch => {
                WindowsIntegrityLifecycleAction::RejectedUnsafeLaunchPath
            }
            WindowsIntegrityPlanStatus::AppContainerInactive => {
                WindowsIntegrityLifecycleAction::RejectedAppContainerInactive
            }
        };
        let report = WindowsIntegrityPolicyReport::skipped(
            plan,
            action,
            WindowsIntegrityTokenApiResult::NotAttempted,
        );
        Self::from_report(&report)
    }

    /// Render this record as a single JSONL line.
    pub fn to_jsonl_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

/// Default Windows firewall posture for a connector process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsFirewallDefaultDecision {
    /// Deny egress unless a more specific, policy-derived allow mechanism exists.
    Deny,
    /// Direct egress is allowed by the sandbox profile.
    Allow,
}

/// Direction for a Windows firewall rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsFirewallRuleDirection {
    /// Outbound connector egress.
    Outbound,
}

/// Action for a Windows firewall rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsFirewallRuleAction {
    /// Allow a specific outbound flow.
    Allow,
}

/// IP protocol for a Windows firewall rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsFirewallRuleProtocol {
    /// TCP, represented as protocol number 6 in Windows Firewall.
    Tcp,
}

impl WindowsFirewallRuleProtocol {
    /// Stable protocol label for deterministic rule names and evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
        }
    }

    /// Windows Firewall numeric protocol identifier.
    #[must_use]
    pub const fn windows_protocol_number(self) -> u16 {
        match self {
            Self::Tcp => 6,
        }
    }
}

/// Planning outcome for Windows firewall policy synthesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsFirewallPlanStatus {
    /// The sandbox profile allows direct network access, so no deny posture is installed.
    DirectNetworkAllowed,
    /// The current policy lacks operation-level `NetworkConstraints`.
    ConstraintsUnavailable,
    /// The manifest declares an explicit no-egress sentinel.
    NoEgress,
    /// Hostname allow rules cannot be installed directly as Windows Firewall remote addresses.
    HostAllowRequiresNetworkGuard,
    /// The plan contains IP/port/program-scoped allow rules.
    IpAllowRules,
    /// The plan contains IP rules, but hostname allow entries still need Network Guard.
    IpAllowRulesWithHostConstraints,
}

impl WindowsFirewallPlanStatus {
    const fn skip_reason(self) -> Option<&'static str> {
        match self {
            Self::DirectNetworkAllowed => Some("direct_network_allowed_by_sandbox_profile"),
            Self::ConstraintsUnavailable => {
                Some("operation_network_constraints_unavailable_to_windows_sandbox")
            }
            Self::NoEgress | Self::IpAllowRules => None,
            Self::HostAllowRequiresNetworkGuard | Self::IpAllowRulesWithHostConstraints => {
                Some("host_allow_requires_network_guard_dns_resolution")
            }
        }
    }
}

/// High-level lifecycle action for a Windows firewall policy attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsFirewallLifecycleAction {
    /// No rule was installed because direct network is allowed.
    SkippedDirectNetworkAllowed,
    /// No rule was installed because operation-level constraints were unavailable.
    NotInstalledMissingNetworkConstraints,
    /// No rule was installed because the manifest requested no egress.
    PlannedNoEgress,
    /// No rule was installed because the allowlist is hostname-only.
    SkippedHostAllowRequiresNetworkGuard,
    /// Rule specs were planned but not applied through an OS API.
    PlannedOnly,
    /// Stale deterministic rules could not be removed, so current rules were not applied.
    StaleCleanupFailed,
    /// Rule specs were applied through the firewall API.
    Applied,
    /// Rule specs were removed through the firewall API.
    Removed,
}

/// Cleanup decision for Windows firewall policy state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsFirewallCleanupDecision {
    /// No firewall rule exists for this plan.
    None,
    /// Rules remain installed for connector reuse.
    RetainRules,
    /// Stale rules were removed while retaining current rules for connector reuse.
    RemoveStaleRules,
    /// Rules were removed by an explicit cleanup pass.
    RemoveRules,
}

/// Result from creating or updating a Windows firewall rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsFirewallRuleApplyOutcome {
    /// A new rule was created.
    Created,
    /// An existing rule was updated to match the current policy.
    Updated,
    /// The existing rule already matched the current policy.
    AlreadyCurrent,
}

/// Result from removing a Windows firewall rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsFirewallRuleCleanupOutcome {
    /// The rule was removed.
    Removed,
    /// The rule did not exist.
    Missing,
}

/// Result from a stale-rule cleanup attempt during policy apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsFirewallStaleRuleCleanupOutcome {
    /// A stale rule was removed.
    Removed,
    /// A stale rule was already absent by the time cleanup ran.
    Missing,
    /// Stale cleanup failed; no current rules were applied.
    Failed,
}

/// A single Windows firewall rule spec derived from manifest network constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsFirewallRuleSpec {
    /// Deterministic rule name. The name contains hashes, not connector IDs or hostnames.
    pub name: String,
    /// Connector executable path to scope the rule to.
    pub application_path: PathBuf,
    /// Rule direction.
    pub direction: WindowsFirewallRuleDirection,
    /// Rule action.
    pub action: WindowsFirewallRuleAction,
    /// Network protocol.
    pub protocol: WindowsFirewallRuleProtocol,
    /// Remote IP address string. Hostname constraints are not represented here.
    pub remote_address: String,
    /// Remote TCP port.
    pub remote_port: u16,
    /// Redaction-safe class for the remote address.
    pub remote_address_class: &'static str,
}

/// Windows firewall policy plan derived from a connector executable and operation constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsFirewallPolicyPlan {
    /// Hashed connector id or connector seed.
    pub connector_id_hash: String,
    /// Hashed connector executable path.
    pub application_path_hash: String,
    /// Default egress posture.
    pub default_decision: WindowsFirewallDefaultDecision,
    /// Planning status.
    pub status: WindowsFirewallPlanStatus,
    /// IP/port/program-scoped allow rules that a Windows API backend can install.
    pub rules: Vec<WindowsFirewallRuleSpec>,
    /// Hashed hostname allow entries from the manifest.
    pub host_allow_hashes: Vec<String>,
    /// Hashed IP allow entries from the manifest.
    pub ip_allow_hashes: Vec<String>,
    /// Redaction-safe target address classes represented in this plan.
    pub target_address_classes: Vec<String>,
    /// Count of unique positive allowed ports.
    pub allowed_port_count: usize,
    /// Structured reason for non-installable or partial plans.
    pub unsupported_reason: Option<&'static str>,
}

/// Report from applying or skipping a Windows firewall policy plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsFirewallPolicyReport {
    /// Planned policy.
    pub plan: WindowsFirewallPolicyPlan,
    /// Lifecycle action taken.
    pub action: WindowsFirewallLifecycleAction,
    /// Rule outcomes returned by the firewall API.
    pub rule_outcomes: Vec<WindowsFirewallRuleApplyOutcome>,
    /// Cleanup choice made by the lifecycle controller.
    pub cleanup: WindowsFirewallCleanupDecision,
    /// Redaction-safe API result.
    pub firewall_api_result: &'static str,
    /// Structured skip reason when no rule was installed.
    pub skip_reason: Option<&'static str>,
    /// Stale rule names detected for this connector, hashed by evidence conversion.
    pub stale_rule_names: Vec<String>,
    /// Outcomes from stale-rule cleanup attempts.
    pub stale_rule_cleanup_outcomes: Vec<WindowsFirewallStaleRuleCleanupOutcome>,
}

impl WindowsFirewallPolicyReport {
    const fn skipped(
        plan: WindowsFirewallPolicyPlan,
        action: WindowsFirewallLifecycleAction,
        firewall_api_result: &'static str,
    ) -> Self {
        let skip_reason = plan.status.skip_reason();
        Self {
            plan,
            action,
            rule_outcomes: Vec::new(),
            cleanup: WindowsFirewallCleanupDecision::None,
            firewall_api_result,
            skip_reason,
            stale_rule_names: Vec::new(),
            stale_rule_cleanup_outcomes: Vec::new(),
        }
    }
}

/// Fakeable Windows firewall API used by the policy lifecycle controller.
#[cfg(any(test, target_os = "windows"))]
#[allow(clippy::redundant_pub_crate)]
pub(super) trait WindowsFirewallPolicyApi {
    /// List deterministic FCP firewall rule names scoped to the connector hash.
    fn rule_names_for_connector(
        &mut self,
        connector_id_hash: &str,
    ) -> Result<Vec<String>, SandboxError>;

    /// Create, update, or verify a firewall rule.
    fn upsert_rule(
        &mut self,
        rule: &WindowsFirewallRuleSpec,
    ) -> Result<WindowsFirewallRuleApplyOutcome, SandboxError>;

    /// Remove a firewall rule by deterministic name.
    fn remove_rule(
        &mut self,
        rule_name: &str,
    ) -> Result<WindowsFirewallRuleCleanupOutcome, SandboxError>;
}

/// Build a Windows firewall policy plan from operation-level network constraints.
///
/// Hostname allowlists are retained only as redacted hashes because Windows
/// Firewall remote-address rules cannot directly express DNS names. Those
/// entries still require Network Guard DNS/SNI enforcement or a later WFP-based
/// resolver layer.
///
/// # Errors
///
/// Returns an error when a normal egress plan contains port `0`, which is only
/// accepted for the explicit `none.invalid` no-egress sentinel.
pub fn plan_windows_firewall_policy(
    connector_id: &str,
    application_path: &Path,
    block_direct_network: bool,
    constraints: Option<&NetworkConstraints>,
) -> Result<WindowsFirewallPolicyPlan, SandboxError> {
    let connector_id_hash = stable_fnv1a64_hex(connector_id);
    let application_path_hash = stable_fnv1a64_hex(&application_path.display().to_string());

    if !block_direct_network {
        return Ok(WindowsFirewallPolicyPlan {
            connector_id_hash,
            application_path_hash,
            default_decision: WindowsFirewallDefaultDecision::Allow,
            status: WindowsFirewallPlanStatus::DirectNetworkAllowed,
            rules: Vec::new(),
            host_allow_hashes: Vec::new(),
            ip_allow_hashes: Vec::new(),
            target_address_classes: Vec::new(),
            allowed_port_count: 0,
            unsupported_reason: WindowsFirewallPlanStatus::DirectNetworkAllowed.skip_reason(),
        });
    }

    let Some(constraints) = constraints else {
        return Ok(WindowsFirewallPolicyPlan {
            connector_id_hash,
            application_path_hash,
            default_decision: WindowsFirewallDefaultDecision::Deny,
            status: WindowsFirewallPlanStatus::ConstraintsUnavailable,
            rules: Vec::new(),
            host_allow_hashes: Vec::new(),
            ip_allow_hashes: Vec::new(),
            target_address_classes: Vec::new(),
            allowed_port_count: 0,
            unsupported_reason: WindowsFirewallPlanStatus::ConstraintsUnavailable.skip_reason(),
        });
    };

    let host_allow_hashes = hashed_sorted_strings(&constraints.host_allow);
    let ip_allow_hashes = hashed_sorted_ips(&constraints.ip_allow);
    let target_address_classes = sorted_ip_classes(&constraints.ip_allow);

    if is_windows_firewall_no_egress_sentinel(constraints) {
        return Ok(WindowsFirewallPolicyPlan {
            connector_id_hash,
            application_path_hash,
            default_decision: WindowsFirewallDefaultDecision::Deny,
            status: WindowsFirewallPlanStatus::NoEgress,
            rules: Vec::new(),
            host_allow_hashes,
            ip_allow_hashes,
            target_address_classes,
            allowed_port_count: 0,
            unsupported_reason: None,
        });
    }

    let mut ports = BTreeSet::new();
    for port in &constraints.port_allow {
        if *port == 0 {
            return Err(SandboxError::InvalidConfig(
                "windows firewall egress rules cannot use port 0 outside the none.invalid no-egress sentinel"
                    .into(),
            ));
        }
        ports.insert(*port);
    }

    if constraints.ip_allow.is_empty() {
        return Ok(WindowsFirewallPolicyPlan {
            connector_id_hash,
            application_path_hash,
            default_decision: WindowsFirewallDefaultDecision::Deny,
            status: WindowsFirewallPlanStatus::HostAllowRequiresNetworkGuard,
            rules: Vec::new(),
            host_allow_hashes,
            ip_allow_hashes,
            target_address_classes,
            allowed_port_count: ports.len(),
            unsupported_reason: WindowsFirewallPlanStatus::HostAllowRequiresNetworkGuard
                .skip_reason(),
        });
    }

    let rules =
        windows_firewall_ip_allow_rules(&connector_id_hash, application_path, constraints, &ports)?;

    let status = if constraints.host_allow.is_empty() {
        WindowsFirewallPlanStatus::IpAllowRules
    } else {
        WindowsFirewallPlanStatus::IpAllowRulesWithHostConstraints
    };

    Ok(WindowsFirewallPolicyPlan {
        connector_id_hash,
        application_path_hash,
        default_decision: WindowsFirewallDefaultDecision::Deny,
        status,
        rules,
        host_allow_hashes,
        ip_allow_hashes,
        target_address_classes,
        allowed_port_count: ports.len(),
        unsupported_reason: status.skip_reason(),
    })
}

fn windows_firewall_ip_allow_rules(
    connector_id_hash: &str,
    application_path: &Path,
    constraints: &NetworkConstraints,
    ports: &BTreeSet<u16>,
) -> Result<Vec<WindowsFirewallRuleSpec>, SandboxError> {
    let mut ips = BTreeSet::new();
    for ip in &constraints.ip_allow {
        ips.insert(*ip);
    }

    let mut rules = Vec::with_capacity(ips.len() * ports.len());
    for ip in ips {
        let remote_address = ip.to_string();
        for port in ports {
            rules.push(WindowsFirewallRuleSpec {
                name: windows_firewall_rule_name(
                    connector_id_hash,
                    WindowsFirewallRuleProtocol::Tcp,
                    *port,
                    &remote_address,
                )?,
                application_path: application_path.to_path_buf(),
                direction: WindowsFirewallRuleDirection::Outbound,
                action: WindowsFirewallRuleAction::Allow,
                protocol: WindowsFirewallRuleProtocol::Tcp,
                remote_address: remote_address.clone(),
                remote_port: *port,
                remote_address_class: classify_ip_address(ip),
            });
        }
    }

    Ok(rules)
}

/// Apply a Windows firewall policy plan through a fakeable API.
///
/// # Errors
///
/// Returns an error if the API fails to create or update any planned rule.
#[cfg(any(test, target_os = "windows"))]
#[allow(clippy::redundant_pub_crate)]
pub(super) fn apply_windows_firewall_policy<A>(
    plan: WindowsFirewallPolicyPlan,
    api: &mut A,
) -> Result<WindowsFirewallPolicyReport, SandboxError>
where
    A: WindowsFirewallPolicyApi,
{
    match plan.status {
        WindowsFirewallPlanStatus::DirectNetworkAllowed => {
            return Ok(WindowsFirewallPolicyReport::skipped(
                plan,
                WindowsFirewallLifecycleAction::SkippedDirectNetworkAllowed,
                "not_attempted",
            ));
        }
        WindowsFirewallPlanStatus::ConstraintsUnavailable => {
            return Ok(WindowsFirewallPolicyReport::skipped(
                plan,
                WindowsFirewallLifecycleAction::NotInstalledMissingNetworkConstraints,
                "not_attempted",
            ));
        }
        WindowsFirewallPlanStatus::NoEgress => {
            return Ok(WindowsFirewallPolicyReport::skipped(
                plan,
                WindowsFirewallLifecycleAction::PlannedNoEgress,
                "not_attempted",
            ));
        }
        WindowsFirewallPlanStatus::HostAllowRequiresNetworkGuard => {
            return Ok(WindowsFirewallPolicyReport::skipped(
                plan,
                WindowsFirewallLifecycleAction::SkippedHostAllowRequiresNetworkGuard,
                "not_attempted",
            ));
        }
        WindowsFirewallPlanStatus::IpAllowRules
        | WindowsFirewallPlanStatus::IpAllowRulesWithHostConstraints => {}
    }

    let mut stale_rule_names = windows_firewall_stale_rule_names(&plan, api)?;
    let mut stale_rule_cleanup_outcomes = Vec::with_capacity(stale_rule_names.len());
    for stale_rule_name in &stale_rule_names {
        let outcome = match api.remove_rule(stale_rule_name) {
            Ok(WindowsFirewallRuleCleanupOutcome::Removed) => {
                WindowsFirewallStaleRuleCleanupOutcome::Removed
            }
            Ok(WindowsFirewallRuleCleanupOutcome::Missing) => {
                WindowsFirewallStaleRuleCleanupOutcome::Missing
            }
            Err(_) => WindowsFirewallStaleRuleCleanupOutcome::Failed,
        };
        stale_rule_cleanup_outcomes.push(outcome);
    }

    if stale_rule_cleanup_outcomes.contains(&WindowsFirewallStaleRuleCleanupOutcome::Failed) {
        stale_rule_names.sort();
        return Ok(WindowsFirewallPolicyReport {
            plan,
            action: WindowsFirewallLifecycleAction::StaleCleanupFailed,
            rule_outcomes: Vec::new(),
            cleanup: WindowsFirewallCleanupDecision::RemoveStaleRules,
            firewall_api_result: "stale_rule_cleanup_failed",
            skip_reason: Some("stale_rule_cleanup_failed"),
            stale_rule_names,
            stale_rule_cleanup_outcomes,
        });
    }

    let mut rule_outcomes = Vec::with_capacity(plan.rules.len());
    for rule in &plan.rules {
        rule_outcomes.push(api.upsert_rule(rule)?);
    }

    stale_rule_names.sort();
    let cleanup = if stale_rule_names.is_empty() {
        WindowsFirewallCleanupDecision::RetainRules
    } else {
        WindowsFirewallCleanupDecision::RemoveStaleRules
    };
    let firewall_api_result = if stale_rule_names.is_empty() {
        "rules_upserted"
    } else {
        "stale_rules_removed_rules_upserted"
    };

    Ok(WindowsFirewallPolicyReport {
        plan,
        action: WindowsFirewallLifecycleAction::Applied,
        rule_outcomes,
        cleanup,
        firewall_api_result,
        skip_reason: None,
        stale_rule_names,
        stale_rule_cleanup_outcomes,
    })
}

#[cfg(any(test, target_os = "windows"))]
fn windows_firewall_stale_rule_names<A>(
    plan: &WindowsFirewallPolicyPlan,
    api: &mut A,
) -> Result<Vec<String>, SandboxError>
where
    A: WindowsFirewallPolicyApi,
{
    let current_names = plan
        .rules
        .iter()
        .map(|rule| rule.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut stale_rule_names = api
        .rule_names_for_connector(&plan.connector_id_hash)?
        .into_iter()
        .filter(|name| windows_firewall_rule_name_matches_connector(name, &plan.connector_id_hash))
        .filter(|name| !current_names.contains(name.as_str()))
        .collect::<Vec<_>>();
    stale_rule_names.sort();
    stale_rule_names.dedup();
    Ok(stale_rule_names)
}

/// Remove rules from a Windows firewall policy plan through a fakeable API.
///
/// # Errors
///
/// Returns an error if the API fails to remove any planned rule.
#[cfg(any(test, target_os = "windows"))]
#[allow(clippy::redundant_pub_crate)]
pub(super) fn cleanup_windows_firewall_policy<A>(
    plan: WindowsFirewallPolicyPlan,
    api: &mut A,
) -> Result<WindowsFirewallPolicyReport, SandboxError>
where
    A: WindowsFirewallPolicyApi,
{
    if plan.rules.is_empty() {
        return Ok(WindowsFirewallPolicyReport::skipped(
            plan,
            WindowsFirewallLifecycleAction::Removed,
            "not_attempted_no_rules",
        ));
    }

    for rule in &plan.rules {
        let _ = api.remove_rule(&rule.name)?;
    }

    Ok(WindowsFirewallPolicyReport {
        plan,
        action: WindowsFirewallLifecycleAction::Removed,
        rule_outcomes: Vec::new(),
        cleanup: WindowsFirewallCleanupDecision::RemoveRules,
        firewall_api_result: "rules_removed",
        skip_reason: None,
        stale_rule_names: Vec::new(),
        stale_rule_cleanup_outcomes: Vec::new(),
    })
}

/// Redaction-safe JSONL evidence for Windows firewall policy planning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WindowsFirewallPolicyEvidence {
    /// Schema marker for downstream evidence validators.
    pub schema: &'static str,
    /// Operating-system family for this evidence record.
    pub os: &'static str,
    /// Hashed connector id or connector seed.
    pub connector_id_hash: String,
    /// Hashed connector executable path.
    pub application_path_hash: String,
    /// Default egress posture.
    pub default_decision: WindowsFirewallDefaultDecision,
    /// Planning status.
    pub plan_status: WindowsFirewallPlanStatus,
    /// Lifecycle action result.
    pub lifecycle_action: WindowsFirewallLifecycleAction,
    /// Firewall API result without raw OS error text.
    pub firewall_api_result: &'static str,
    /// Count of IP/port/program allow rules.
    pub allow_rule_count: usize,
    /// Hashed rule names.
    pub rule_name_hashes: Vec<String>,
    /// Hashed hostname allow entries.
    pub host_allow_hashes: Vec<String>,
    /// Hashed IP allow entries.
    pub ip_allow_hashes: Vec<String>,
    /// Redaction-safe target address classes.
    pub target_address_classes: Vec<String>,
    /// Count of unique positive ports represented by the plan.
    pub allowed_port_count: usize,
    /// Final readiness layer this evidence is allowed to claim today.
    pub final_filter_strength: FilterStrength,
    /// Cleanup decision.
    pub cleanup: WindowsFirewallCleanupDecision,
    /// Hashed stale rule names detected during apply.
    pub stale_rule_name_hashes: Vec<String>,
    /// Stale rule cleanup outcomes.
    pub stale_rule_cleanup_outcomes: Vec<WindowsFirewallStaleRuleCleanupOutcome>,
    /// Structured skip or partial-support reason when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<&'static str>,
}

impl WindowsFirewallPolicyEvidence {
    /// Build redaction-safe evidence from a firewall policy report.
    #[must_use]
    pub fn from_report(report: &WindowsFirewallPolicyReport) -> Self {
        let mut rule_name_hashes = report
            .plan
            .rules
            .iter()
            .map(|rule| stable_fnv1a64_hex(&rule.name))
            .collect::<Vec<_>>();
        rule_name_hashes.sort();
        let mut stale_rule_name_hashes = report
            .stale_rule_names
            .iter()
            .map(|name| stable_fnv1a64_hex(name))
            .collect::<Vec<_>>();
        stale_rule_name_hashes.sort();

        Self {
            schema: "fcp.windows_firewall_policy.v1",
            os: "windows",
            connector_id_hash: report.plan.connector_id_hash.clone(),
            application_path_hash: report.plan.application_path_hash.clone(),
            default_decision: report.plan.default_decision,
            plan_status: report.plan.status,
            lifecycle_action: report.action,
            firewall_api_result: report.firewall_api_result,
            allow_rule_count: report.plan.rules.len(),
            rule_name_hashes,
            host_allow_hashes: report.plan.host_allow_hashes.clone(),
            ip_allow_hashes: report.plan.ip_allow_hashes.clone(),
            target_address_classes: report.plan.target_address_classes.clone(),
            allowed_port_count: report.plan.allowed_port_count,
            final_filter_strength: FilterStrength::ProcessLimit,
            cleanup: report.cleanup,
            stale_rule_name_hashes,
            stale_rule_cleanup_outcomes: report.stale_rule_cleanup_outcomes.clone(),
            skip_reason: report.skip_reason.or(report.plan.unsupported_reason),
        }
    }

    /// Build redaction-safe evidence from a firewall policy plan that was explicitly skipped.
    #[must_use]
    pub fn from_skipped_plan(
        plan: WindowsFirewallPolicyPlan,
        action: WindowsFirewallLifecycleAction,
        firewall_api_result: &'static str,
    ) -> Self {
        let report = WindowsFirewallPolicyReport::skipped(plan, action, firewall_api_result);
        Self::from_report(&report)
    }

    /// Build redaction-safe evidence from a firewall policy plan that has not been applied.
    #[must_use]
    pub fn planned_only(plan: WindowsFirewallPolicyPlan) -> Self {
        let report = WindowsFirewallPolicyReport {
            plan,
            action: WindowsFirewallLifecycleAction::PlannedOnly,
            rule_outcomes: Vec::new(),
            cleanup: WindowsFirewallCleanupDecision::None,
            firewall_api_result: "not_attempted",
            skip_reason: None,
            stale_rule_names: Vec::new(),
            stale_rule_cleanup_outcomes: Vec::new(),
        };
        Self::from_report(&report)
    }

    /// Render this record as a single JSONL line.
    pub fn to_jsonl_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

impl WindowsAppContainerProfile {
    /// Derive a stable `AppContainer` profile from a connector id and compiled policy.
    pub fn from_policy(connector_id: &str, policy: &CompiledPolicy) -> Result<Self, SandboxError> {
        Ok(Self {
            name: windows_appcontainer_profile_name(connector_id)?,
            capabilities: policy.windows_appcontainer_capabilities()?,
        })
    }
}

fn windows_appcontainer_profile_name(connector_id: &str) -> Result<String, SandboxError> {
    let mut fragment = sanitize_windows_appcontainer_name_fragment(connector_id);
    let hash = stable_fnv1a64_hex(connector_id);
    let separators_len = 2;
    let max_fragment_len = WINDOWS_APPCONTAINER_PROFILE_NAME_MAX_LEN
        - WINDOWS_APPCONTAINER_PROFILE_PREFIX.len()
        - WINDOWS_APPCONTAINER_PROFILE_HASH_LEN
        - separators_len;
    fragment.truncate(max_fragment_len);

    let name = format!("{WINDOWS_APPCONTAINER_PROFILE_PREFIX}-{fragment}-{hash}");
    validate_windows_appcontainer_profile_name(&name)?;
    Ok(name)
}

fn sanitize_windows_appcontainer_name_fragment(value: &str) -> String {
    let mut fragment = String::with_capacity(value.len().min(43));
    let mut last_was_dash = false;

    for byte in value.bytes() {
        let next = if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_') {
            last_was_dash = false;
            char::from(byte.to_ascii_lowercase())
        } else if last_was_dash {
            continue;
        } else {
            last_was_dash = true;
            '-'
        };
        fragment.push(next);
    }

    let fragment = fragment.trim_matches('-');
    if fragment.is_empty() {
        "connector".to_owned()
    } else {
        fragment.to_owned()
    }
}

fn stable_fnv1a64_hex(value: &str) -> String {
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{hash:016x}")
}

fn hashed_sorted_strings(values: &[String]) -> Vec<String> {
    let mut hashes = values
        .iter()
        .map(|value| stable_fnv1a64_hex(value))
        .collect::<Vec<_>>();
    hashes.sort();
    hashes
}

fn hashed_sorted_ips(values: &[IpAddr]) -> Vec<String> {
    let mut hashes = values
        .iter()
        .map(|value| stable_fnv1a64_hex(&value.to_string()))
        .collect::<Vec<_>>();
    hashes.sort();
    hashes
}

fn sorted_ip_classes(values: &[IpAddr]) -> Vec<String> {
    let mut classes = BTreeSet::new();
    for value in values {
        classes.insert(classify_ip_address(*value).to_owned());
    }
    classes.into_iter().collect()
}

fn is_windows_firewall_no_egress_sentinel(constraints: &NetworkConstraints) -> bool {
    constraints.host_allow.len() == 1
        && constraints.host_allow[0] == "none.invalid"
        && constraints.port_allow.len() == 1
        && constraints.port_allow[0] == 0
        && constraints.ip_allow.is_empty()
}

fn windows_firewall_rule_name(
    connector_id_hash: &str,
    protocol: WindowsFirewallRuleProtocol,
    remote_port: u16,
    remote_address: &str,
) -> Result<String, SandboxError> {
    let remote_address_hash = stable_fnv1a64_hex(remote_address);
    let name = format!(
        "{WINDOWS_FIREWALL_RULE_PREFIX}-{connector_id_hash}-{}-{remote_port}-{remote_address_hash}",
        protocol.as_str()
    );
    validate_windows_firewall_rule_name(&name)?;
    Ok(name)
}

fn validate_windows_firewall_rule_name(name: &str) -> Result<(), SandboxError> {
    if name.is_empty() || name.len() > 128 {
        return Err(SandboxError::InvalidConfig(format!(
            "windows firewall rule name must be 1..=128 bytes, got {}",
            name.len()
        )));
    }

    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(SandboxError::InvalidConfig(format!(
            "windows firewall rule name `{name}` contains unsupported characters"
        )));
    }

    Ok(())
}

#[cfg(any(test, target_os = "windows"))]
fn windows_firewall_rule_name_matches_connector(name: &str, connector_id_hash: &str) -> bool {
    validate_windows_firewall_rule_name(name).is_ok()
        && name.starts_with(&format!(
            "{WINDOWS_FIREWALL_RULE_PREFIX}-{connector_id_hash}-"
        ))
}

fn classify_ip_address(address: IpAddr) -> &'static str {
    match address {
        IpAddr::V4(address) => classify_ipv4_address(address),
        IpAddr::V6(address) => classify_ipv6_address(address),
    }
}

fn classify_ipv4_address(address: Ipv4Addr) -> &'static str {
    if address.is_loopback() {
        "loopback_ip"
    } else if is_tailnet_ipv4(address) {
        "tailnet_ip"
    } else if address.is_private() {
        "private_ip"
    } else if address.is_link_local() {
        "link_local_ip"
    } else if address.is_unspecified() {
        "unspecified_ip"
    } else {
        "public_ip"
    }
}

const fn classify_ipv6_address(address: Ipv6Addr) -> &'static str {
    if address.is_loopback() {
        "loopback_ip"
    } else if is_tailnet_ipv6(address) {
        "tailnet_ip"
    } else if address.is_unique_local() {
        "private_ip"
    } else if address.is_unicast_link_local() {
        "link_local_ip"
    } else if address.is_unspecified() {
        "unspecified_ip"
    } else {
        "public_ip"
    }
}

fn is_tailnet_ipv4(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

const fn is_tailnet_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    segments[0] == 0xfd7a && segments[1] == 0x115c && segments[2] == 0xa1e0
}

fn validate_windows_appcontainer_profile_name(name: &str) -> Result<(), SandboxError> {
    if name.is_empty() || name.len() > WINDOWS_APPCONTAINER_PROFILE_NAME_MAX_LEN {
        return Err(SandboxError::InvalidConfig(format!(
            "windows AppContainer profile name must be 1..={WINDOWS_APPCONTAINER_PROFILE_NAME_MAX_LEN} bytes, got {}",
            name.len()
        )));
    }

    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b' '))
    {
        return Err(SandboxError::InvalidConfig(format!(
            "windows AppContainer profile name `{name}` contains characters outside [-_. A-Za-z0-9]"
        )));
    }

    Ok(())
}

fn normalize_windows_appcontainer_capabilities(
    requested: &[String],
) -> Result<Vec<String>, SandboxError> {
    let mut capabilities = BTreeSet::new();
    for capability in requested {
        let capability = capability.trim();
        validate_windows_appcontainer_capability_name(capability)?;
        if let Some(mapped) = fcp_sandbox_capability_to_windows_appcontainer(capability) {
            capabilities.insert(mapped.to_owned());
        } else if !fcp_sandbox_capability_has_no_windows_appcontainer_sid(capability) {
            capabilities.insert(capability.to_owned());
        }
    }

    Ok(capabilities.into_iter().collect())
}

fn fcp_sandbox_capability_to_windows_appcontainer(capability: &str) -> Option<&'static str> {
    match capability {
        "network.egress" | "network.outbound" => Some(WINDOWS_APPCONTAINER_INTERNET_CLIENT),
        "network.outbound_lan" | "network.outbound_tailnet" => {
            Some(WINDOWS_APPCONTAINER_PRIVATE_NETWORK_CLIENT_SERVER)
        }
        "network.listen" => Some(WINDOWS_APPCONTAINER_INTERNET_CLIENT_SERVER),
        "fs.read.user_profile" => Some("documentsLibrary"),
        _ => None,
    }
}

fn fcp_sandbox_capability_has_no_windows_appcontainer_sid(capability: &str) -> bool {
    matches!(
        capability,
        "network.dns"
            | "network.outbound_dns"
            | "network.tls.sni"
            | "network.tls.mtls"
            | "system.exec"
            | "system.privileged"
            | "filesystem.read"
            | "filesystem.write"
            | "fs.write.user_profile"
            | "fs.read.tmp"
            | "storage.state"
            | "media.download"
            | "media.upload"
    )
}

fn validate_windows_appcontainer_capability_name(name: &str) -> Result<(), SandboxError> {
    if name.is_empty() {
        return Err(SandboxError::InvalidConfig(
            "windows AppContainer capability names must not be empty".into(),
        ));
    }

    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(SandboxError::InvalidConfig(format!(
            "windows AppContainer capability `{name}` contains unsupported characters"
        )));
    }

    Ok(())
}

fn is_windows_network_appcontainer_capability(capability: &str) -> bool {
    WINDOWS_NETWORK_APPCONTAINER_CAPABILITIES.contains(&capability)
}

/// Expand special path variables.
fn compile_paths(
    paths: &[String],
    state_dir: Option<&PathBuf>,
    field_name: &str,
) -> Result<Vec<PathBuf>, SandboxError> {
    let mut compiled = Vec::with_capacity(paths.len());

    for path in paths {
        match expand_path(path, state_dir) {
            Ok(Some(expanded)) => compiled.push(expanded),
            Ok(None) => {}
            Err(message) => {
                return Err(SandboxError::PolicyCompilationFailed(format!(
                    "invalid {field_name} entry `{path}`: {message}"
                )));
            }
        }
    }

    Ok(compiled)
}

fn expand_path(path: &str, state_dir: Option<&PathBuf>) -> Result<Option<PathBuf>, &'static str> {
    validate_manifest_path(path)?;

    Ok(path.strip_prefix("$CONNECTOR_STATE/").map_or_else(
        || {
            if path == "$CONNECTOR_STATE" {
                state_dir.cloned()
            } else {
                Some(PathBuf::from(path))
            }
        },
        |suffix| state_dir.map(|sd| sd.join(suffix)),
    ))
}

fn validate_manifest_path(path: &str) -> Result<(), &'static str> {
    if path == "$CONNECTOR_STATE" {
        return Ok(());
    }

    if let Some(suffix) = path.strip_prefix("$CONNECTOR_STATE/") {
        return validate_connector_state_subpath(suffix);
    }

    if is_manifest_absolute_path(path) {
        return Ok(());
    }

    Err("paths must be absolute or use `$CONNECTOR_STATE[/subpath]`")
}

fn validate_connector_state_subpath(suffix: &str) -> Result<(), &'static str> {
    for component in Path::new(suffix).components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            return Err("`$CONNECTOR_STATE` subpaths must contain only normal path components");
        }
    }

    Ok(())
}

fn is_manifest_absolute_path(path: &str) -> bool {
    Path::new(path).is_absolute()
        || path.starts_with('/')
        || path.starts_with(r"\\")
        || path.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
            && matches!(path.as_bytes().get(1), Some(b':'))
            && matches!(path.as_bytes().get(2), Some(b'\\' | b'/'))
}

// ============================================================================
// Filter Strength (cross-platform parity metric)
// ============================================================================

/// Precision of the sandbox's enforcement boundary (NORMATIVE — cross-platform parity).
///
/// This is a coarse-grained classifier of "how narrow an attack surface does
/// this platform's sandbox actually filter?". Higher discriminant values
/// indicate stronger filtering. Use via `>=` comparison.
///
/// The three levels correspond to concrete mechanisms in the tree:
///
/// | Level            | Platform | Mechanism                                        |
/// |------------------|----------|--------------------------------------------------|
/// | `SyscallLevel`   | Linux    | seccomp-bpf with `SECCOMP_RET_KILL_PROCESS`      |
/// | `ProfileLevel`   | macOS    | `sandbox_init` / SBPL `(deny ...)` rules          |
/// | `ProcessLimit`   | Windows  | Job Object `ActiveProcessLimit` + memory limits  |
///
/// # Why this distinction matters
///
/// - **`SyscallLevel`** filters every syscall individually at the kernel
///   trap boundary. A hostile connector that discovers an unknown native
///   code path is still stopped at `int 0x80` / `syscall` because the
///   seccomp allowlist enumerates the kernel ABI, not a set of named
///   operations. `SECCOMP_RET_KILL_PROCESS` terminates the process
///   synchronously on any disallowed syscall.
///
/// - **`ProfileLevel`** filters *named* operations at the Mach/BSD API
///   layer (`process-exec`, `file-read*`, `network*`, etc.). Apple's
///   sandbox is enforced in-kernel, but the granularity is the operation
///   name the profile declares — not the underlying syscall. A previously
///   unknown native-API path or a syscall the profile does not explicitly
///   name may still reach the kernel. macOS is therefore strictly coarser
///   than Linux seccomp even though both are kernel-enforced.
///
/// - **`ProcessLimit`** does no per-operation filtering at all. Windows
///   job objects constrain *resource consumption* (process count, memory,
///   CPU time) but never inspect syscalls or API names. A connector that
///   stays inside its budget can invoke any Win32/NT API the process
///   integrity level allows. Any API-level denial that Linux seccomp or
///   macOS SBPL catches today is, on Windows, relying entirely on the
///   connector honoring the `deny_exec`/`deny_ptrace` contract in its
///   own code plus `ActiveProcessLimit = 1` catching `CreateProcess`.
///
/// # Parity gap (bead 459lp)
///
/// FCP's strict profile specifies kernel-enforced syscall-level filtering.
/// Today only Linux reaches `SyscallLevel`; macOS lands at `ProfileLevel`
/// and Windows at `ProcessLimit`. Strict-profile connectors that require
/// the full guarantee MUST run under [`WasiRuntime`](crate::WasiRuntime),
/// which never leaves the host process and so is unaffected by this gap.
///
/// [`WasiRuntime`]: crate::WasiRuntime
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum FilterStrength {
    /// Coarsest: only process and resource limits are enforced.
    ///
    /// Windows job objects live here. The sandbox can stop `deny_exec`
    /// via `ActiveProcessLimit = 1` and enforce memory/CPU ceilings, but
    /// it does not filter syscalls or named operations. Any native API
    /// the process integrity level permits is reachable.
    ProcessLimit = 0,

    /// Intermediate: named operations are denied at the OS API layer,
    /// but individual syscalls are not filtered.
    ///
    /// macOS `sandbox_init` with SBPL `(deny process-exec)` /
    /// `(deny file-read*)` / `(deny network*)` lives here. Enforcement is
    /// kernel-backed but operates on a named-operation vocabulary, so a
    /// syscall path not covered by a `(deny ...)` rule can still reach
    /// the kernel. Thread-as-process accounting also forces us to skip
    /// `RLIMIT_NPROC = 0` here (it would starve any async runtime),
    /// leaving the SBPL profile as the sole `deny_exec` enforcement.
    ProfileLevel = 1,

    /// Strongest: every syscall is individually filtered at the kernel
    /// trap boundary; denied syscalls terminate the process.
    ///
    /// Linux seccomp-bpf with `SECCOMP_RET_KILL_PROCESS` and an
    /// architecture-validated allowlist lives here. This is the only
    /// level that meets the strict-profile "no unknown syscall reaches
    /// the kernel" guarantee.
    SyscallLevel = 2,
}

impl FilterStrength {
    /// Stable string identifier (for audit logs and decision receipts).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProcessLimit => "process_limit",
            Self::ProfileLevel => "profile_level",
            Self::SyscallLevel => "syscall_level",
        }
    }

    /// The expected filter strength for a given target OS identifier
    /// (matches `std::env::consts::OS` values).
    ///
    /// Tests use this to assert that the current platform's `Sandbox`
    /// impl returns exactly the parity level documented here — guarding
    /// against silent regressions (e.g., Windows gaining a weaker
    /// mechanism that still claims a higher level, or macOS's profile
    /// being downgraded during a refactor).
    #[must_use]
    pub fn expected_for_target_os(os: &str) -> Option<Self> {
        // Intentionally exhaustive match on the documented targets. New
        // host targets added without a parity review will return None,
        // forcing the test to fail loudly rather than default-allow.
        match os {
            "linux" => Some(Self::SyscallLevel),
            "macos" => Some(Self::ProfileLevel),
            "windows" => Some(Self::ProcessLimit),
            _ => None,
        }
    }
}

// ============================================================================
// Sandbox Trait
// ============================================================================

/// Platform-specific sandbox implementation.
///
/// Each platform provides its own implementation that translates the
/// `CompiledPolicy` into native enforcement mechanisms.
pub trait Sandbox: Send + Sync {
    /// Report the precision of this sandbox's enforcement mechanism.
    ///
    /// See [`FilterStrength`] for the levels and their meaning. The default
    /// implementation returns the weakest level ([`FilterStrength::ProcessLimit`])
    /// so that any new [`Sandbox`] impl that forgets to override this method
    /// is classified as coarse-grained by default — a conservative choice
    /// that prevents the parity assertion from silently treating a weaker
    /// sandbox as stronger than it is.
    fn filter_strength(&self) -> FilterStrength {
        FilterStrength::ProcessLimit
    }

    /// Apply the sandbox to the current process.
    ///
    /// This should be called early in the connector's startup, before any
    /// untrusted code runs. Once applied, the sandbox restrictions cannot
    /// be relaxed.
    ///
    /// # Safety
    ///
    /// This function modifies process-wide security state. It should only
    /// be called once per process, typically from the main thread during
    /// initialization.
    ///
    /// # Errors
    ///
    /// Returns an error if the sandbox cannot be applied.
    fn apply(&self, policy: &CompiledPolicy) -> Result<(), SandboxError>;

    /// Apply the sandbox to a child process being spawned via `std::process::Command`.
    ///
    /// This should hook into the command setup (e.g., using `pre_exec` on Unix) to
    /// ensure the child process is fully sandboxed before executing the payload.
    /// Default implementation relies on the connector binary to invoke `apply()` itself,
    /// but platform-specific implementations (e.g., Linux namespaces, macOS seatbelt)
    /// may override this to enforce sandboxing immediately from the host.
    fn apply_to_command(
        &self,
        cmd: &mut std::process::Command,
        policy: &CompiledPolicy,
    ) -> Result<(), SandboxError> {
        let _ = (cmd, policy);
        Ok(())
    }

    /// Check if the sandbox can be applied on this platform.
    ///
    /// Returns `true` if all required kernel/OS features are available.
    fn is_available(&self) -> bool;

    /// Get the platform name (e.g., "linux", "macos", "windows").
    fn platform_name(&self) -> &'static str;

    /// Verify that a file operation would be allowed under the sandbox.
    ///
    /// This is useful for pre-flight checks before applying the sandbox.
    fn verify_file_access(
        &self,
        policy: &CompiledPolicy,
        path: &std::path::Path,
        write: bool,
    ) -> Result<(), SandboxError>;

    /// Verify that process spawning would be allowed.
    fn verify_exec_allowed(&self, policy: &CompiledPolicy) -> Result<(), SandboxError>;

    /// Verify that direct network access would be blocked.
    fn verify_network_blocked(&self, policy: &CompiledPolicy) -> Result<(), SandboxError>;
}

/// Normalize a path lexically without resolving symlinks or checking existence.
/// Resolves `.` and `..` components.
#[must_use]
pub fn normalize_path(path: &std::path::Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            std::path::Component::ParentDir => {
                let last = out.components().next_back();
                match last {
                    Some(std::path::Component::Normal(_)) => {
                        out.pop();
                    }
                    Some(std::path::Component::RootDir) => {
                        // At root, .. does nothing
                    }
                    _ => {
                        // Either empty, prefix, or another ..
                        out.push(std::path::Component::ParentDir);
                    }
                }
            }
            std::path::Component::CurDir => {}
            _ => out.push(comp),
        }
    }
    out
}

/// Resolve a path for policy checks, even when the leaf path does not exist yet.
///
/// This canonicalizes the full path when possible. If the leaf is missing, it
/// canonicalizes the nearest existing ancestor and then appends the unresolved
/// suffix. That keeps policy checks aligned with where the kernel will actually
/// traverse, including symlink-plus-`..` semantics in existing ancestors.
#[must_use]
pub fn resolve_policy_path(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }

    for ancestor in path.ancestors().skip(1) {
        if ancestor.as_os_str().is_empty() {
            continue;
        }

        if let Ok(canonical_ancestor) = ancestor.canonicalize() {
            let unresolved_suffix = path
                .strip_prefix(ancestor)
                .unwrap_or_else(|_| Path::new(""));
            return normalize_path(&canonical_ancestor.join(unresolved_suffix));
        }
    }

    if path.is_relative() {
        if let Ok(cwd) = std::env::current_dir() {
            return normalize_path(&cwd.join(path));
        }
    }

    normalize_path(path)
}

fn verify_file_access_policy(
    policy: &CompiledPolicy,
    path: &Path,
    write: bool,
) -> Result<(), SandboxError> {
    let path = resolve_policy_path(path);

    if write {
        for writable in &policy.writable_paths {
            let writable = resolve_policy_path(writable);
            if path.starts_with(&writable) {
                return Ok(());
            }
        }
        return Err(SandboxError::ApplyFailed(format!(
            "write access denied to path: {}",
            path.display()
        )));
    }

    for readable in policy.readonly_paths.iter().chain(&policy.writable_paths) {
        let readable = resolve_policy_path(readable);
        if path.starts_with(&readable) {
            return Ok(());
        }
    }

    Err(SandboxError::ApplyFailed(format!(
        "read access denied to path: {}",
        path.display()
    )))
}

fn verify_exec_policy(policy: &CompiledPolicy) -> Result<(), SandboxError> {
    if policy.deny_exec {
        Err(SandboxError::ApplyFailed(
            "process spawning is denied by sandbox policy".into(),
        ))
    } else {
        Ok(())
    }
}

fn verify_network_policy(policy: &CompiledPolicy) -> Result<(), SandboxError> {
    if policy.block_direct_network {
        Ok(())
    } else {
        Err(SandboxError::ApplyFailed(
            "direct network access is permitted by sandbox policy".into(),
        ))
    }
}

// ============================================================================
// Factory
// ============================================================================

/// Create the appropriate sandbox for the current platform.
///
/// # Errors
///
/// Returns an error if no sandbox implementation is available for this platform.
#[allow(unreachable_code)]
pub fn create_sandbox() -> Result<Box<dyn Sandbox>, SandboxError> {
    #[cfg(target_os = "linux")]
    {
        return Ok(Box::new(super::linux::LinuxSandbox::new()));
    }

    #[cfg(target_os = "macos")]
    {
        return Ok(Box::new(super::macos::MacOsSandbox::new()));
    }

    #[cfg(target_os = "windows")]
    {
        return Ok(Box::new(super::windows::WindowsSandbox::new()));
    }

    Err(SandboxError::UnsupportedPlatform(
        std::env::consts::OS.to_string(),
    ))
}

// ============================================================================
// Test Utilities
// ============================================================================

/// A no-op sandbox for testing.
#[derive(Debug, Default)]
pub struct NoOpSandbox;

impl Sandbox for NoOpSandbox {
    fn apply(&self, _policy: &CompiledPolicy) -> Result<(), SandboxError> {
        Ok(())
    }

    fn apply_to_command(
        &self,
        cmd: &mut std::process::Command,
        policy: &CompiledPolicy,
    ) -> Result<(), SandboxError> {
        let _ = (cmd, policy);
        Ok(())
    }

    fn is_available(&self) -> bool {
        true
    }

    fn platform_name(&self) -> &'static str {
        "noop"
    }

    fn verify_file_access(
        &self,
        policy: &CompiledPolicy,
        path: &std::path::Path,
        write: bool,
    ) -> Result<(), SandboxError> {
        verify_file_access_policy(policy, path, write)
    }

    fn verify_exec_allowed(&self, policy: &CompiledPolicy) -> Result<(), SandboxError> {
        verify_exec_policy(policy)
    }

    fn verify_network_blocked(&self, policy: &CompiledPolicy) -> Result<(), SandboxError> {
        verify_network_policy(policy)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sandbox_section() -> SandboxSection {
        SandboxSection {
            profile: SandboxProfile::Strict,
            memory_mb: 256,
            cpu_percent: 50,
            wall_clock_timeout_ms: 30_000,
            fs_readonly_paths: vec!["/usr".into(), "/lib".into()],
            fs_writable_paths: vec!["$CONNECTOR_STATE".into()],
            deny_exec: true,
            deny_ptrace: true,
        }
    }

    #[test]
    fn test_compile_policy() {
        let section = test_sandbox_section();
        let state_dir = Some(PathBuf::from("/var/lib/fcp/connectors/test"));
        let policy = CompiledPolicy::from_manifest(&section, state_dir).unwrap();

        assert_eq!(policy.profile, SandboxProfile::Strict);
        assert_eq!(policy.memory_limit_bytes, 256 * 1024 * 1024);
        assert_eq!(policy.cpu_percent, 50);
        assert_eq!(policy.wall_clock_timeout, Duration::from_secs(30));
        assert!(policy.readonly_paths.contains(&PathBuf::from("/usr")));
        assert!(policy.readonly_paths.contains(&PathBuf::from("/lib")));
        assert!(
            policy
                .writable_paths
                .iter()
                .any(|p| p.as_path() == Path::new("/var/lib/fcp/connectors/test"))
        );
        assert!(policy.deny_exec);
        assert!(policy.deny_ptrace);
        assert!(policy.block_direct_network);
    }

    #[test]
    fn test_expand_path_state_dir() {
        let state_dir = PathBuf::from("/var/lib/fcp/state");

        assert_eq!(
            expand_path("$CONNECTOR_STATE", Some(&state_dir)),
            Ok(Some(PathBuf::from("/var/lib/fcp/state")))
        );

        assert_eq!(
            expand_path("$CONNECTOR_STATE/data", Some(&state_dir)),
            Ok(Some(PathBuf::from("/var/lib/fcp/state/data")))
        );

        assert_eq!(
            expand_path("/usr/lib", Some(&state_dir)),
            Ok(Some(PathBuf::from("/usr/lib")))
        );

        assert_eq!(expand_path("$CONNECTOR_STATE", None), Ok(None));
    }

    #[test]
    fn test_block_network_by_profile() {
        let mut section = test_sandbox_section();

        section.profile = SandboxProfile::Strict;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(policy.block_direct_network);

        section.profile = SandboxProfile::StrictPlus;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(policy.block_direct_network);

        section.profile = SandboxProfile::Moderate;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(policy.block_direct_network);

        section.profile = SandboxProfile::Permissive;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(!policy.block_direct_network);
    }

    #[test]
    fn test_noop_sandbox() {
        let sandbox = NoOpSandbox;
        assert!(sandbox.is_available());
        assert_eq!(sandbox.platform_name(), "noop");

        let section = test_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(sandbox.apply(&policy).is_ok());
    }

    // ── New tests ──

    #[test]
    fn test_sandbox_error_display() {
        let e = SandboxError::UnsupportedPlatform("wasm".into());
        assert!(e.to_string().contains("wasm"));

        let e = SandboxError::PolicyCompilationFailed("bad rule".into());
        assert!(e.to_string().contains("bad rule"));

        let e = SandboxError::ApplyFailed("seccomp denied".into());
        assert!(e.to_string().contains("seccomp denied"));

        let e = SandboxError::ResourceLimitExceeded("memory".into());
        assert!(e.to_string().contains("memory"));

        let e = SandboxError::InvalidConfig("missing field".into());
        assert!(e.to_string().contains("missing field"));

        let e = SandboxError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "gone"));
        assert!(e.to_string().contains("gone"));

        let e = SandboxError::SyscallFailed("prctl".into());
        assert!(e.to_string().contains("prctl"));

        let e = SandboxError::Timeout;
        assert!(e.to_string().contains("timeout"));
    }

    #[test]
    fn test_platform_flags_default_is_empty() {
        let flags = PlatformFlags::default();
        assert!(flags.is_empty());
        assert!(!flags.linux_use_landlock);
        assert!(!flags.linux_use_userns);
        assert!(flags.macos_entitlements.is_empty());
        assert!(!flags.windows_low_integrity);
        assert!(flags.windows_appcontainer_capabilities.is_empty());
    }

    #[test]
    fn test_platform_flags_not_empty() {
        let flags = PlatformFlags {
            linux_use_landlock: true,
            ..Default::default()
        };
        assert!(!flags.is_empty());

        let flags = PlatformFlags {
            linux_use_userns: true,
            ..Default::default()
        };
        assert!(!flags.is_empty());

        let flags = PlatformFlags {
            macos_entitlements: vec!["com.apple.security.network.client".into()],
            ..Default::default()
        };
        assert!(!flags.is_empty());

        let flags = PlatformFlags {
            windows_low_integrity: true,
            ..Default::default()
        };
        assert!(!flags.is_empty());

        let flags = PlatformFlags {
            windows_appcontainer_capabilities: vec![WINDOWS_APPCONTAINER_INTERNET_CLIENT.into()],
            ..Default::default()
        };
        assert!(!flags.is_empty());
    }

    #[test]
    fn test_compiled_policy_with_platform_flags() {
        let section = test_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(policy.platform_flags.is_empty());

        let flags = PlatformFlags {
            linux_use_landlock: true,
            ..Default::default()
        };
        let policy = policy.with_platform_flags(flags);
        assert!(policy.platform_flags.linux_use_landlock);
    }

    #[test]
    fn declares_fs_path_restrictions_detects_manifest_intent() {
        // Manifest lists readonly paths -> declares restrictions.
        let section = test_sandbox_section();
        let state_dir = Some(PathBuf::from("/var/lib/fcp/connectors/test"));
        let policy = CompiledPolicy::from_manifest(&section, state_dir.clone()).unwrap();
        assert!(
            policy.declares_fs_path_restrictions(),
            "readonly paths declared in the manifest must count as confinement intent"
        );

        // Only the auto-added state_dir is writable, nothing else declared ->
        // no confinement intent (must not newly fail closed).
        let mut bare = test_sandbox_section();
        bare.fs_readonly_paths.clear();
        bare.fs_writable_paths.clear();
        let bare_policy = CompiledPolicy::from_manifest(&bare, state_dir).unwrap();
        assert!(
            !bare_policy.declares_fs_path_restrictions(),
            "a policy whose only writable path is the auto-added state_dir declares no restrictions"
        );

        // Manifest-declared writable path beyond state_dir -> confinement intent.
        let mut writable = test_sandbox_section();
        writable.fs_readonly_paths.clear();
        writable.fs_writable_paths = vec!["/srv/data".into()];
        let writable_policy = CompiledPolicy::from_manifest(
            &writable,
            Some(PathBuf::from("/var/lib/fcp/connectors/test")),
        )
        .unwrap();
        assert!(writable_policy.declares_fs_path_restrictions());
    }

    #[test]
    fn test_windows_appcontainer_profile_name_is_stable_and_bounded() {
        let section = test_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        let profile = policy
            .windows_appcontainer_profile("fcp.test.github:request-response:1.0.0")
            .unwrap();

        assert!(
            profile
                .name
                .starts_with("fcp-fcp.test.github-request-response-1.0.0-")
        );
        assert!(profile.name.len() <= 64);
        assert_eq!(
            profile,
            policy
                .windows_appcontainer_profile("fcp.test.github:request-response:1.0.0")
                .unwrap()
        );
    }

    #[test]
    fn test_windows_appcontainer_capabilities_follow_network_policy() {
        let mut section = test_sandbox_section();
        section.profile = SandboxProfile::Strict;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(
            policy
                .windows_appcontainer_capabilities()
                .unwrap()
                .is_empty()
        );

        section.profile = SandboxProfile::Permissive;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert_eq!(
            policy.windows_appcontainer_capabilities().unwrap(),
            vec![WINDOWS_APPCONTAINER_INTERNET_CLIENT]
        );
    }

    #[test]
    fn test_windows_appcontainer_capabilities_are_normalized() {
        let mut section = test_sandbox_section();
        section.profile = SandboxProfile::Permissive;
        let flags = PlatformFlags {
            windows_appcontainer_capabilities: vec![
                " custom.capability ".into(),
                WINDOWS_APPCONTAINER_PRIVATE_NETWORK_CLIENT_SERVER.into(),
                "custom.capability".into(),
            ],
            ..Default::default()
        };
        let policy = CompiledPolicy::from_manifest(&section, None)
            .unwrap()
            .with_platform_flags(flags);

        assert_eq!(
            policy.windows_appcontainer_capabilities().unwrap(),
            vec![
                "custom.capability",
                WINDOWS_APPCONTAINER_PRIVATE_NETWORK_CLIENT_SERVER
            ]
        );
    }

    #[test]
    fn test_windows_appcontainer_maps_manifest_network_capabilities() {
        let mut section = test_sandbox_section();
        section.profile = SandboxProfile::Permissive;
        let flags = PlatformFlags {
            windows_appcontainer_capabilities: vec![
                "network.egress".into(),
                "network.dns".into(),
                "network.tls.sni".into(),
                "network.tls.mtls".into(),
            ],
            ..Default::default()
        };
        let policy = CompiledPolicy::from_manifest(&section, None)
            .unwrap()
            .with_platform_flags(flags);

        assert_eq!(
            policy.windows_appcontainer_capabilities().unwrap(),
            vec![WINDOWS_APPCONTAINER_INTERNET_CLIENT]
        );
    }

    #[test]
    fn test_windows_appcontainer_maps_private_and_listen_capabilities() {
        let mut section = test_sandbox_section();
        section.profile = SandboxProfile::Permissive;
        let flags = PlatformFlags {
            windows_appcontainer_capabilities: vec![
                "network.outbound_lan".into(),
                "network.outbound_tailnet".into(),
                "network.listen".into(),
            ],
            ..Default::default()
        };
        let policy = CompiledPolicy::from_manifest(&section, None)
            .unwrap()
            .with_platform_flags(flags);

        assert_eq!(
            policy.windows_appcontainer_capabilities().unwrap(),
            vec![
                WINDOWS_APPCONTAINER_INTERNET_CLIENT_SERVER,
                WINDOWS_APPCONTAINER_PRIVATE_NETWORK_CLIENT_SERVER
            ]
        );
    }

    #[test]
    fn test_windows_appcontainer_maps_non_sid_manifest_capabilities_to_no_grant() {
        let mut section = test_sandbox_section();
        section.profile = SandboxProfile::Permissive;
        let flags = PlatformFlags {
            windows_appcontainer_capabilities: vec![
                "system.exec".into(),
                "system.privileged".into(),
                "filesystem.read".into(),
                "filesystem.write".into(),
                "storage.state".into(),
                "media.download".into(),
                "media.upload".into(),
            ],
            ..Default::default()
        };
        let policy = CompiledPolicy::from_manifest(&section, None)
            .unwrap()
            .with_platform_flags(flags);

        assert_eq!(
            policy.windows_appcontainer_capabilities().unwrap(),
            vec![WINDOWS_APPCONTAINER_INTERNET_CLIENT],
            "permissive policies retain the existing default outbound grant when no Windows network capability remains"
        );
    }

    #[test]
    fn test_windows_appcontainer_rejects_network_capabilities_when_network_blocked() {
        let section = test_sandbox_section();
        let flags = PlatformFlags {
            windows_appcontainer_capabilities: vec![
                WINDOWS_APPCONTAINER_INTERNET_CLIENT_SERVER.into(),
            ],
            ..Default::default()
        };
        let err = CompiledPolicy::from_manifest(&section, None)
            .unwrap()
            .with_platform_flags(flags)
            .windows_appcontainer_capabilities()
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("direct network must remain blocked")
        );
    }

    #[test]
    fn test_windows_appcontainer_rejects_invalid_capability_name() {
        let mut section = test_sandbox_section();
        section.profile = SandboxProfile::Permissive;
        let flags = PlatformFlags {
            windows_appcontainer_capabilities: vec!["camera/read".into()],
            ..Default::default()
        };
        let err = CompiledPolicy::from_manifest(&section, None)
            .unwrap()
            .with_platform_flags(flags)
            .windows_appcontainer_capabilities()
            .unwrap_err();

        assert!(err.to_string().contains("unsupported characters"));
    }

    #[derive(Debug, Clone, Copy)]
    enum FakeCreateProfileResult {
        Created,
        AlreadyExists,
        Fail,
    }

    struct FakeWindowsAppContainerApi {
        create_result: FakeCreateProfileResult,
        derive_fails: bool,
        delete_fails: bool,
        calls: Vec<String>,
    }

    impl FakeWindowsAppContainerApi {
        fn new(create_result: FakeCreateProfileResult) -> Self {
            Self {
                create_result,
                derive_fails: false,
                delete_fails: false,
                calls: Vec::new(),
            }
        }

        fn with_derive_failure(mut self) -> Self {
            self.derive_fails = true;
            self
        }

        fn with_delete_failure(mut self) -> Self {
            self.delete_fails = true;
            self
        }
    }

    impl WindowsAppContainerProfileApi for FakeWindowsAppContainerApi {
        fn create_profile(
            &mut self,
            profile: &WindowsAppContainerProfile,
        ) -> Result<WindowsAppContainerCreateOutcome, SandboxError> {
            self.calls.push(format!("create:{}", profile.name));
            match self.create_result {
                FakeCreateProfileResult::Created => Ok(WindowsAppContainerCreateOutcome::Created),
                FakeCreateProfileResult::AlreadyExists => {
                    Ok(WindowsAppContainerCreateOutcome::AlreadyExists)
                }
                FakeCreateProfileResult::Fail => Err(SandboxError::SyscallFailed(
                    "CreateAppContainerProfile failed: access denied".into(),
                )),
            }
        }

        fn derive_profile_sid(&mut self, profile_name: &str) -> Result<(), SandboxError> {
            self.calls.push(format!("derive:{profile_name}"));
            if self.derive_fails {
                Err(SandboxError::SyscallFailed(
                    "DeriveAppContainerSidFromAppContainerName failed: invalid argument".into(),
                ))
            } else {
                Ok(())
            }
        }

        fn delete_profile(&mut self, profile_name: &str) -> Result<(), SandboxError> {
            self.calls.push(format!("delete:{profile_name}"));
            if self.delete_fails {
                Err(SandboxError::SyscallFailed(
                    "DeleteAppContainerProfile failed: access denied".into(),
                ))
            } else {
                Ok(())
            }
        }
    }

    fn fake_windows_appcontainer_profile() -> WindowsAppContainerProfile {
        WindowsAppContainerProfile {
            name: "fcp-test-connector-0123456789abcdef".into(),
            capabilities: vec![WINDOWS_APPCONTAINER_INTERNET_CLIENT.into()],
        }
    }

    #[test]
    fn test_windows_appcontainer_lifecycle_skips_without_active_backend() {
        let profile = fake_windows_appcontainer_profile();
        let mut api = FakeWindowsAppContainerApi::new(FakeCreateProfileResult::Fail);

        let report =
            prepare_windows_appcontainer_lifecycle(profile.clone(), false, &mut api).unwrap();

        assert_eq!(report.profile, profile);
        assert_eq!(
            report.action,
            WindowsAppContainerLifecycleAction::SkippedInactive
        );
        assert!(!report.sid_present);
        assert_eq!(report.cleanup, WindowsAppContainerCleanupDecision::None);
        assert!(report.skip_reason.is_some());
        assert!(api.calls.is_empty());
    }

    #[test]
    fn test_windows_appcontainer_lifecycle_records_profile_create() {
        let profile = fake_windows_appcontainer_profile();
        let mut api = FakeWindowsAppContainerApi::new(FakeCreateProfileResult::Created);

        let report =
            prepare_windows_appcontainer_lifecycle(profile.clone(), true, &mut api).unwrap();

        assert_eq!(report.profile, profile);
        assert_eq!(report.action, WindowsAppContainerLifecycleAction::Created);
        assert!(report.sid_present);
        assert_eq!(
            report.cleanup,
            WindowsAppContainerCleanupDecision::RetainProfile
        );
        assert_eq!(
            api.calls,
            vec!["create:fcp-test-connector-0123456789abcdef"]
        );
    }

    #[test]
    fn test_windows_appcontainer_lifecycle_reuses_existing_profile_sid() {
        let profile = fake_windows_appcontainer_profile();
        let mut api = FakeWindowsAppContainerApi::new(FakeCreateProfileResult::AlreadyExists);

        let report =
            prepare_windows_appcontainer_lifecycle(profile.clone(), true, &mut api).unwrap();

        assert_eq!(report.profile, profile);
        assert_eq!(
            report.action,
            WindowsAppContainerLifecycleAction::ReusedExisting
        );
        assert!(report.sid_present);
        assert_eq!(
            api.calls,
            vec![
                "create:fcp-test-connector-0123456789abcdef",
                "derive:fcp-test-connector-0123456789abcdef"
            ]
        );
    }

    #[test]
    fn test_windows_appcontainer_lifecycle_maps_create_failure() {
        let profile = fake_windows_appcontainer_profile();
        let mut api = FakeWindowsAppContainerApi::new(FakeCreateProfileResult::Fail);

        let err = prepare_windows_appcontainer_lifecycle(profile, true, &mut api).unwrap_err();

        assert!(err.to_string().contains("CreateAppContainerProfile"));
        assert_eq!(
            api.calls,
            vec!["create:fcp-test-connector-0123456789abcdef"]
        );
    }

    #[test]
    fn test_windows_appcontainer_lifecycle_maps_sid_derivation_failure() {
        let profile = fake_windows_appcontainer_profile();
        let mut api = FakeWindowsAppContainerApi::new(FakeCreateProfileResult::AlreadyExists)
            .with_derive_failure();

        let err = prepare_windows_appcontainer_lifecycle(profile, true, &mut api).unwrap_err();

        assert!(
            err.to_string()
                .contains("DeriveAppContainerSidFromAppContainerName")
        );
        assert_eq!(
            api.calls,
            vec![
                "create:fcp-test-connector-0123456789abcdef",
                "derive:fcp-test-connector-0123456789abcdef"
            ]
        );
    }

    #[test]
    fn test_windows_appcontainer_cleanup_deletes_profile() {
        let profile = fake_windows_appcontainer_profile();
        let mut api = FakeWindowsAppContainerApi::new(FakeCreateProfileResult::Created);

        let cleanup = cleanup_windows_appcontainer_profile(&profile.name, &mut api).unwrap();

        assert_eq!(cleanup, WindowsAppContainerCleanupDecision::DeleteProfile);
        assert_eq!(
            api.calls,
            vec!["delete:fcp-test-connector-0123456789abcdef"]
        );
    }

    #[test]
    fn test_windows_appcontainer_cleanup_maps_delete_failure() {
        let profile = fake_windows_appcontainer_profile();
        let mut api =
            FakeWindowsAppContainerApi::new(FakeCreateProfileResult::Created).with_delete_failure();

        let err = cleanup_windows_appcontainer_profile(&profile.name, &mut api).unwrap_err();

        assert!(err.to_string().contains("DeleteAppContainerProfile"));
        assert_eq!(
            api.calls,
            vec!["delete:fcp-test-connector-0123456789abcdef"]
        );
    }

    #[test]
    fn test_windows_appcontainer_evidence_records_cleanup_delete() {
        let report = WindowsAppContainerLifecycleReport {
            profile: fake_windows_appcontainer_profile(),
            action: WindowsAppContainerLifecycleAction::Created,
            sid_present: true,
            cleanup: WindowsAppContainerCleanupDecision::DeleteProfile,
            skip_reason: None,
        };
        let evidence =
            WindowsAppContainerEvidence::from_lifecycle("connector", &report, true, "real_smoke");
        let line = evidence.to_jsonl_line().unwrap();

        assert_eq!(
            evidence.cleanup,
            WindowsAppContainerCleanupDecision::DeleteProfile
        );
        assert!(line.contains("\"cleanup\":\"delete_profile\""));
        assert_eq!(evidence.action_result, "real_smoke");
    }

    #[test]
    fn test_windows_appcontainer_evidence_redacts_connector_and_profile_names() {
        let profile = WindowsAppContainerProfile {
            name: "fcp-secret-customer-0123456789abcdef".into(),
            capabilities: vec!["custom.capability".into()],
        };
        let report = WindowsAppContainerLifecycleReport::inactive(profile);
        let evidence = WindowsAppContainerEvidence::from_lifecycle(
            "secret-customer@example.com",
            &report,
            false,
            "skip",
        );
        let line = evidence.to_jsonl_line().unwrap();

        assert!(line.contains("fcp.windows_appcontainer_smoke.v1"));
        assert!(line.contains("windows_appcontainer_not_active"));
        assert!(!line.contains("secret-customer@example.com"));
        assert!(!line.contains("fcp-secret-customer"));
        assert!(evidence.step_order.contains(&"appcontainer_lifecycle"));
        assert!(!evidence.step_order.contains(&"job_object_attach"));
    }

    #[test]
    fn test_windows_appcontainer_evidence_records_job_object_attachment_order() {
        let profile = fake_windows_appcontainer_profile();
        let report = WindowsAppContainerLifecycleReport::active(
            profile,
            WindowsAppContainerLifecycleAction::Created,
        );
        let evidence =
            WindowsAppContainerEvidence::from_lifecycle("connector", &report, true, "apply");

        assert!(evidence.job_object_attached);
        assert_eq!(
            evidence.step_order,
            vec!["appcontainer_lifecycle", "job_object_attach"]
        );
        assert_eq!(evidence.action_result, "apply");
        assert!(evidence.sid_present);
        assert_eq!(
            evidence.cleanup,
            WindowsAppContainerCleanupDecision::RetainProfile
        );
    }

    #[test]
    fn test_windows_appcontainer_process_launch_evidence_records_startupinfoex_path() {
        let profile = fake_windows_appcontainer_profile();
        let report = WindowsAppContainerLifecycleReport::active(
            profile,
            WindowsAppContainerLifecycleAction::Created,
        );
        let evidence = WindowsAppContainerProcessLaunchEvidence::from_lifecycle(
            "connector",
            &report,
            WindowsAppContainerProcessLaunchMechanism::StartupInfoExSecurityCapabilities,
            true,
            "launched",
            Some(4242),
        );
        let line = evidence.to_jsonl_line().unwrap();
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();

        assert_eq!(
            value["schema"],
            "fcp.windows_appcontainer_process_launch.v1"
        );
        assert_eq!(
            value["launch_mechanism"],
            "startup_info_ex_security_capabilities"
        );
        assert_eq!(value["integrity_level"], "not_requested");
        assert_eq!(value["integrity_enforcement"], "none");
        assert_eq!(value["job_object_attachment_intent"], "attach_after_launch");
        assert_eq!(value["job_object_attached"].as_bool(), Some(true));
        assert_eq!(value["final_filter_strength"], "process_limit");
        assert!(value["process_id_hash"].as_str().is_some());
        assert_eq!(
            evidence.step_order,
            vec![
                "appcontainer_lifecycle",
                "startupinfoex_security_capabilities",
                "job_object_attach"
            ]
        );
        assert!(!line.contains("4242"));
    }

    #[test]
    fn test_windows_appcontainer_process_launch_evidence_records_integrity_order() {
        let profile = fake_windows_appcontainer_profile();
        let report = WindowsAppContainerLifecycleReport::active(
            profile,
            WindowsAppContainerLifecycleAction::Created,
        );
        let evidence = WindowsAppContainerProcessLaunchEvidence::from_lifecycle(
            "connector",
            &report,
            WindowsAppContainerProcessLaunchMechanism::StartupInfoExSecurityCapabilities,
            true,
            "launched",
            Some(4242),
        )
        .with_integrity_enforcement("low", "low_primary_integrity");
        let line = evidence.to_jsonl_line().unwrap();
        let value: serde_json::Value = serde_json::from_str(&line).unwrap();

        assert_eq!(value["integrity_level"], "low");
        assert_eq!(value["integrity_enforcement"], "low_primary_integrity");
        assert_eq!(
            evidence.step_order,
            vec![
                "appcontainer_lifecycle",
                "startupinfoex_security_capabilities",
                "integrity_level_enforcement",
                "job_object_attach"
            ]
        );
        assert!(!line.contains("primary_token"));
    }

    #[test]
    fn test_windows_appcontainer_process_launch_evidence_redacts_skip_names() {
        let profile = WindowsAppContainerProfile {
            name: "fcp-secret-customer-0123456789abcdef".into(),
            capabilities: vec!["custom.capability".into()],
        };
        let report = WindowsAppContainerLifecycleReport::inactive(profile);
        let evidence = WindowsAppContainerProcessLaunchEvidence::from_lifecycle(
            "secret-customer@example.com",
            &report,
            WindowsAppContainerProcessLaunchMechanism::SkippedInactive,
            false,
            "skip",
            None,
        );
        let line = evidence.to_jsonl_line().unwrap();

        assert!(line.contains("fcp.windows_appcontainer_process_launch.v1"));
        assert!(line.contains("windows_appcontainer_not_active"));
        assert!(!line.contains("secret-customer@example.com"));
        assert!(!line.contains("fcp-secret-customer"));
        assert_eq!(
            evidence.job_object_attachment_intent,
            WindowsJobObjectAttachmentIntent::None
        );
        assert!(evidence.process_id_hash.is_none());
        assert_eq!(evidence.final_filter_strength, FilterStrength::ProcessLimit);
    }

    #[derive(Debug, Default)]
    struct FakeWindowsIntegrityTokenApi {
        fail_at: Option<WindowsIntegrityTokenApiResult>,
        calls: Vec<String>,
        sid_rids: Vec<u32>,
    }

    impl FakeWindowsIntegrityTokenApi {
        fn with_failure(fail_at: WindowsIntegrityTokenApiResult) -> Self {
            Self {
                fail_at: Some(fail_at),
                calls: Vec::new(),
                sid_rids: Vec::new(),
            }
        }

        fn maybe_fail(
            &self,
            failure: WindowsIntegrityTokenApiResult,
        ) -> Result<(), WindowsIntegrityTokenApiResult> {
            if self.fail_at == Some(failure) {
                Err(failure)
            } else {
                Ok(())
            }
        }
    }

    impl WindowsIntegrityTokenApi for FakeWindowsIntegrityTokenApi {
        fn open_source_token(&mut self) -> Result<(), WindowsIntegrityTokenApiResult> {
            self.calls.push("open_source_token".to_owned());
            self.maybe_fail(WindowsIntegrityTokenApiResult::SourceTokenOpenFailed)?;
            self.maybe_fail(WindowsIntegrityTokenApiResult::ApiUnavailable)
        }

        fn duplicate_primary_token(&mut self) -> Result<(), WindowsIntegrityTokenApiResult> {
            self.calls.push("duplicate_primary_token".to_owned());
            self.maybe_fail(WindowsIntegrityTokenApiResult::PrimaryTokenDuplicateFailed)?;
            self.maybe_fail(WindowsIntegrityTokenApiResult::PrivilegeDenied)
        }

        fn allocate_integrity_sid(
            &mut self,
            mandatory_rid: u32,
        ) -> Result<(), WindowsIntegrityTokenApiResult> {
            self.calls
                .push(format!("allocate_integrity_sid:{mandatory_rid}"));
            self.sid_rids.push(mandatory_rid);
            self.maybe_fail(WindowsIntegrityTokenApiResult::IntegritySidAllocationFailed)
        }

        fn set_token_integrity_level(
            &mut self,
            mandatory_rid: u32,
        ) -> Result<(), WindowsIntegrityTokenApiResult> {
            self.calls
                .push(format!("set_token_integrity_level:{mandatory_rid}"));
            self.sid_rids.push(mandatory_rid);
            self.maybe_fail(WindowsIntegrityTokenApiResult::TokenIntegritySetFailed)
        }
    }

    #[test]
    fn test_windows_integrity_policy_medium_inherits_process_token() {
        let plan = plan_windows_integrity_policy(
            "tenant-secret@example.com",
            false,
            WindowsIntegrityOperationMode::InProcessApply,
            false,
        );
        let mut api = FakeWindowsIntegrityTokenApi::default();
        let report = apply_windows_integrity_policy(plan.clone(), &mut api);
        let evidence = WindowsIntegrityPolicyEvidence::from_report(&report);
        let line = evidence.to_jsonl_line().unwrap();

        assert_eq!(plan.status, WindowsIntegrityPlanStatus::InheritedProcess);
        assert_eq!(
            report.action,
            WindowsIntegrityLifecycleAction::SkippedMediumIntegrity
        );
        assert_eq!(
            report.token_api_result,
            WindowsIntegrityTokenApiResult::NotAttempted
        );
        assert!(api.calls.is_empty());
        assert_eq!(
            evidence.requested_level,
            WindowsIntegrityLevelRequest::Medium
        );
        assert_eq!(evidence.integrity_sid_rid, WINDOWS_MANDATORY_MEDIUM_RID);
        assert!(!evidence.requires_primary_token);
        assert_eq!(evidence.final_filter_strength, FilterStrength::ProcessLimit);
        assert!(!line.contains("tenant-secret@example.com"));
    }

    #[test]
    fn test_windows_integrity_policy_low_child_token_order_and_cleanup() {
        let plan = plan_windows_integrity_policy(
            "connector",
            true,
            WindowsIntegrityOperationMode::StartupInfoExChild,
            true,
        );
        let mut api = FakeWindowsIntegrityTokenApi::default();
        let report = apply_windows_integrity_policy(plan.clone(), &mut api);
        let evidence = WindowsIntegrityPolicyEvidence::from_report(&report);
        let line = evidence.to_jsonl_line().unwrap();

        assert_eq!(
            plan.status,
            WindowsIntegrityPlanStatus::LowPrimaryTokenRequired
        );
        assert_eq!(
            report.action,
            WindowsIntegrityLifecycleAction::AppliedLowIntegrityChildToken
        );
        assert_eq!(
            report.token_api_result,
            WindowsIntegrityTokenApiResult::TokenPrepared
        );
        assert_eq!(
            report.step_order,
            vec![
                "integrity_level_decision",
                "open_process_token",
                "duplicate_primary_token",
                "allocate_integrity_sid",
                "set_token_integrity_level"
            ]
        );
        assert_eq!(
            api.calls,
            vec![
                "open_source_token".to_owned(),
                "duplicate_primary_token".to_owned(),
                format!("allocate_integrity_sid:{WINDOWS_MANDATORY_LOW_RID}"),
                format!("set_token_integrity_level:{WINDOWS_MANDATORY_LOW_RID}")
            ]
        );
        assert_eq!(
            report.cleanup,
            WindowsIntegrityTokenCleanupDecision::DropSourceAndChildTokens
        );
        assert_eq!(
            api.sid_rids,
            vec![WINDOWS_MANDATORY_LOW_RID, WINDOWS_MANDATORY_LOW_RID]
        );
        assert_eq!(evidence.requested_level, WindowsIntegrityLevelRequest::Low);
        assert_eq!(evidence.required_process_api, "CreateProcessAsUserW");
        assert!(evidence.requires_primary_token);
        assert!(line.contains("low_primary_token_required"));
        assert!(!line.contains("connector.exe"));
        assert!(!line.contains("primary_token_handle"));
    }

    #[test]
    fn test_windows_integrity_policy_low_in_process_apply_rejected_without_api_calls() {
        let plan = plan_windows_integrity_policy(
            "connector",
            true,
            WindowsIntegrityOperationMode::InProcessApply,
            true,
        );
        let mut api = FakeWindowsIntegrityTokenApi::default();
        let report = apply_windows_integrity_policy(plan, &mut api);
        let evidence = WindowsIntegrityPolicyEvidence::from_report(&report);

        assert_eq!(
            report.action,
            WindowsIntegrityLifecycleAction::RejectedUnsafeLaunchPath
        );
        assert_eq!(
            evidence.plan_status,
            WindowsIntegrityPlanStatus::LowIntegrityRequiresChildLaunch
        );
        assert_eq!(
            evidence.skip_reason,
            Some("windows_low_integrity_requires_startupinfoex_child_launch")
        );
        assert!(api.calls.is_empty());
        assert_eq!(evidence.final_filter_strength, FilterStrength::ProcessLimit);
    }

    #[test]
    fn test_windows_integrity_policy_appcontainer_inactive_is_not_profile_level() {
        let plan = plan_windows_integrity_policy(
            "connector",
            true,
            WindowsIntegrityOperationMode::StartupInfoExChild,
            false,
        );
        let evidence = WindowsIntegrityPolicyEvidence::planned_only(plan);

        assert_eq!(
            evidence.lifecycle_action,
            WindowsIntegrityLifecycleAction::RejectedAppContainerInactive
        );
        assert_eq!(
            evidence.skip_reason,
            Some("windows_appcontainer_not_active_createprocessasuser_path_unwired")
        );
        assert_eq!(evidence.final_filter_strength, FilterStrength::ProcessLimit);
        assert_eq!(
            evidence.token_api_result,
            WindowsIntegrityTokenApiResult::NotAttempted
        );
    }

    #[test]
    fn test_windows_integrity_policy_privilege_denied_mapping_and_cleanup() {
        let plan = plan_windows_integrity_policy(
            "connector",
            true,
            WindowsIntegrityOperationMode::StartupInfoExChild,
            true,
        );
        let mut api = FakeWindowsIntegrityTokenApi::with_failure(
            WindowsIntegrityTokenApiResult::PrivilegeDenied,
        );
        let report = apply_windows_integrity_policy(plan, &mut api);
        let evidence = WindowsIntegrityPolicyEvidence::from_report(&report);

        assert_eq!(
            report.action,
            WindowsIntegrityLifecycleAction::TokenSetupFailed
        );
        assert_eq!(
            report.token_api_result,
            WindowsIntegrityTokenApiResult::PrivilegeDenied
        );
        assert_eq!(
            report.cleanup,
            WindowsIntegrityTokenCleanupDecision::DropSourceToken
        );
        assert_eq!(
            api.calls,
            vec!["open_source_token", "duplicate_primary_token"]
        );
        assert_eq!(
            evidence.skip_reason,
            Some("windows_integrity_token_privilege_denied")
        );
        assert_eq!(evidence.final_filter_strength, FilterStrength::ProcessLimit);
    }

    #[test]
    fn test_windows_integrity_policy_api_unavailable_mapping() {
        let plan = plan_windows_integrity_policy(
            "connector",
            true,
            WindowsIntegrityOperationMode::StartupInfoExChild,
            true,
        );
        let mut api = FakeWindowsIntegrityTokenApi::with_failure(
            WindowsIntegrityTokenApiResult::ApiUnavailable,
        );
        let report = apply_windows_integrity_policy(plan, &mut api);
        let evidence = WindowsIntegrityPolicyEvidence::from_report(&report);

        assert_eq!(
            report.action,
            WindowsIntegrityLifecycleAction::TokenSetupFailed
        );
        assert_eq!(
            report.token_api_result,
            WindowsIntegrityTokenApiResult::ApiUnavailable
        );
        assert_eq!(report.cleanup, WindowsIntegrityTokenCleanupDecision::None);
        assert_eq!(api.calls, vec!["open_source_token"]);
        assert_eq!(
            evidence.skip_reason,
            Some("windows_integrity_token_api_unavailable")
        );
    }

    #[test]
    fn test_windows_integrity_policy_redacts_connector_identity() {
        let plan = plan_windows_integrity_policy(
            "tenant-secret@example.com",
            true,
            WindowsIntegrityOperationMode::StartupInfoExChild,
            true,
        );
        let evidence = WindowsIntegrityPolicyEvidence::planned_only(plan);
        let line = evidence.to_jsonl_line().unwrap();

        assert!(line.contains("fcp.windows_integrity_policy.v1"));
        assert!(line.contains("planned_low_integrity_child_token"));
        assert!(!line.contains("tenant-secret@example.com"));
        assert!(!line.contains("token_handle"));
        assert_eq!(evidence.integrity_sid_rid, WINDOWS_MANDATORY_LOW_RID);
        assert_eq!(evidence.final_filter_strength, FilterStrength::ProcessLimit);
    }

    fn windows_firewall_constraints(
        hosts: &[&str],
        ports: &[u16],
        ips: &[&str],
    ) -> NetworkConstraints {
        NetworkConstraints {
            host_allow: hosts.iter().map(|host| (*host).to_owned()).collect(),
            port_allow: ports.to_vec(),
            ip_allow: ips.iter().map(|ip| ip.parse::<IpAddr>().unwrap()).collect(),
            cidr_deny: Vec::new(),
            deny_localhost: true,
            deny_private_ranges: true,
            deny_tailnet_ranges: true,
            require_sni: true,
            spki_pins: Vec::new(),
            deny_ip_literals: true,
            require_host_canonicalization: true,
            dns_max_ips: 16,
            max_redirects: 5,
            connect_timeout_ms: 10_000,
            total_timeout_ms: 60_000,
            max_response_bytes: 10_485_760,
        }
    }

    #[test]
    fn test_windows_firewall_policy_plans_ip_allow_rules() {
        let constraints =
            windows_firewall_constraints(&["api.example.com"], &[443], &["203.0.113.10"]);
        let plan = plan_windows_firewall_policy(
            "tenant-secret@example.com",
            Path::new(r"C:\Users\secret\connector.exe"),
            true,
            Some(&constraints),
        )
        .unwrap();

        assert_eq!(
            plan.status,
            WindowsFirewallPlanStatus::IpAllowRulesWithHostConstraints
        );
        assert_eq!(plan.default_decision, WindowsFirewallDefaultDecision::Deny);
        assert_eq!(plan.rules.len(), 1);
        assert_eq!(plan.allowed_port_count, 1);
        assert_eq!(
            plan.unsupported_reason,
            Some("host_allow_requires_network_guard_dns_resolution")
        );

        let rule = &plan.rules[0];
        assert!(rule.name.starts_with("fcp-fw-"));
        assert!(!rule.name.contains("tenant-secret"));
        assert!(!rule.name.contains("203.0.113.10"));
        assert_eq!(rule.direction, WindowsFirewallRuleDirection::Outbound);
        assert_eq!(rule.action, WindowsFirewallRuleAction::Allow);
        assert_eq!(rule.protocol, WindowsFirewallRuleProtocol::Tcp);
        assert_eq!(rule.protocol.windows_protocol_number(), 6);
        assert_eq!(rule.remote_address, "203.0.113.10");
        assert_eq!(rule.remote_port, 443);
        assert_eq!(rule.remote_address_class, "public_ip");
    }

    #[test]
    fn test_windows_firewall_policy_no_egress_sentinel() {
        let constraints = windows_firewall_constraints(&["none.invalid"], &[0], &[]);
        let plan = plan_windows_firewall_policy(
            "connector",
            Path::new(r"C:\fcp\connector.exe"),
            true,
            Some(&constraints),
        )
        .unwrap();

        assert_eq!(plan.status, WindowsFirewallPlanStatus::NoEgress);
        assert_eq!(plan.default_decision, WindowsFirewallDefaultDecision::Deny);
        assert!(plan.rules.is_empty());
        assert_eq!(plan.allowed_port_count, 0);
        assert!(plan.unsupported_reason.is_none());
    }

    #[test]
    fn test_windows_firewall_policy_host_only_requires_network_guard() {
        let constraints = windows_firewall_constraints(&["api.example.com"], &[443], &[]);
        let plan = plan_windows_firewall_policy(
            "connector",
            Path::new(r"C:\fcp\connector.exe"),
            true,
            Some(&constraints),
        )
        .unwrap();

        assert_eq!(
            plan.status,
            WindowsFirewallPlanStatus::HostAllowRequiresNetworkGuard
        );
        assert!(plan.rules.is_empty());
        assert_eq!(plan.host_allow_hashes.len(), 1);
        assert_eq!(
            plan.unsupported_reason,
            Some("host_allow_requires_network_guard_dns_resolution")
        );
    }

    #[test]
    fn test_windows_firewall_policy_rejects_zero_port_outside_no_egress() {
        let constraints = windows_firewall_constraints(&["api.example.com"], &[0], &[]);
        let err = plan_windows_firewall_policy(
            "connector",
            Path::new(r"C:\fcp\connector.exe"),
            true,
            Some(&constraints),
        )
        .unwrap_err();

        assert!(err.to_string().contains("port 0"));
    }

    #[test]
    fn test_windows_firewall_policy_records_missing_constraints() {
        let plan = plan_windows_firewall_policy(
            "connector",
            Path::new(r"C:\fcp\connector.exe"),
            true,
            None,
        )
        .unwrap();
        let evidence = WindowsFirewallPolicyEvidence::from_skipped_plan(
            plan,
            WindowsFirewallLifecycleAction::NotInstalledMissingNetworkConstraints,
            "not_attempted",
        );
        let line = evidence.to_jsonl_line().unwrap();

        assert_eq!(evidence.schema, "fcp.windows_firewall_policy.v1");
        assert_eq!(
            evidence.plan_status,
            WindowsFirewallPlanStatus::ConstraintsUnavailable
        );
        assert_eq!(
            evidence.skip_reason,
            Some("operation_network_constraints_unavailable_to_windows_sandbox")
        );
        assert_eq!(evidence.allow_rule_count, 0);
        assert_eq!(evidence.final_filter_strength, FilterStrength::ProcessLimit);
        assert!(line.contains("not_installed_missing_network_constraints"));
    }

    #[derive(Debug)]
    struct FakeWindowsFirewallApi {
        apply_outcome: WindowsFirewallRuleApplyOutcome,
        cleanup_outcome: WindowsFirewallRuleCleanupOutcome,
        stale_rule_names: Vec<String>,
        cleanup_fail_for: BTreeSet<String>,
        calls: Vec<String>,
    }

    impl Default for FakeWindowsFirewallApi {
        fn default() -> Self {
            Self {
                apply_outcome: WindowsFirewallRuleApplyOutcome::Created,
                cleanup_outcome: WindowsFirewallRuleCleanupOutcome::Removed,
                stale_rule_names: Vec::new(),
                cleanup_fail_for: BTreeSet::new(),
                calls: Vec::new(),
            }
        }
    }

    impl WindowsFirewallPolicyApi for FakeWindowsFirewallApi {
        fn rule_names_for_connector(
            &mut self,
            connector_id_hash: &str,
        ) -> Result<Vec<String>, SandboxError> {
            self.calls.push(format!("list:{connector_id_hash}"));
            Ok(self.stale_rule_names.clone())
        }

        fn upsert_rule(
            &mut self,
            rule: &WindowsFirewallRuleSpec,
        ) -> Result<WindowsFirewallRuleApplyOutcome, SandboxError> {
            self.calls.push(format!("upsert:{}", rule.name));
            Ok(self.apply_outcome)
        }

        fn remove_rule(
            &mut self,
            rule_name: &str,
        ) -> Result<WindowsFirewallRuleCleanupOutcome, SandboxError> {
            self.calls.push(format!("remove:{rule_name}"));
            if self.cleanup_fail_for.contains(rule_name) {
                return Err(SandboxError::ApplyFailed(
                    "simulated stale firewall cleanup failure".into(),
                ));
            }
            Ok(self.cleanup_outcome)
        }
    }

    #[test]
    fn test_windows_firewall_policy_fake_api_apply_and_cleanup() {
        let constraints = windows_firewall_constraints(&[], &[443], &["198.51.100.7"]);
        let plan = plan_windows_firewall_policy(
            "connector",
            Path::new(r"C:\fcp\connector.exe"),
            true,
            Some(&constraints),
        )
        .unwrap();
        let rule_name = plan.rules[0].name.clone();
        let mut api = FakeWindowsFirewallApi::default();

        let report = apply_windows_firewall_policy(plan.clone(), &mut api).unwrap();
        assert_eq!(report.action, WindowsFirewallLifecycleAction::Applied);
        assert_eq!(report.firewall_api_result, "rules_upserted");
        assert_eq!(
            report.rule_outcomes,
            vec![WindowsFirewallRuleApplyOutcome::Created]
        );
        assert_eq!(
            api.calls,
            vec![
                format!("list:{}", plan.connector_id_hash),
                format!("upsert:{rule_name}")
            ]
        );

        let cleanup = cleanup_windows_firewall_policy(plan, &mut api).unwrap();
        assert_eq!(cleanup.action, WindowsFirewallLifecycleAction::Removed);
        assert_eq!(cleanup.cleanup, WindowsFirewallCleanupDecision::RemoveRules);
        assert_eq!(
            api.calls,
            vec![
                format!("list:{}", cleanup.plan.connector_id_hash),
                format!("upsert:{rule_name}"),
                format!("remove:{rule_name}")
            ]
        );
    }

    #[test]
    fn test_windows_firewall_policy_removes_stale_rules_before_upsert() {
        let constraints = windows_firewall_constraints(&[], &[443], &["198.51.100.7"]);
        let plan = plan_windows_firewall_policy(
            "connector",
            Path::new(r"C:\fcp\connector.exe"),
            true,
            Some(&constraints),
        )
        .unwrap();
        let current_rule_name = plan.rules[0].name.clone();
        let stale_rule_name = windows_firewall_rule_name(
            &plan.connector_id_hash,
            WindowsFirewallRuleProtocol::Tcp,
            8443,
            "198.51.100.8",
        )
        .unwrap();
        let mut api = FakeWindowsFirewallApi {
            stale_rule_names: vec![
                current_rule_name.clone(),
                stale_rule_name.clone(),
                "not-fcp-owned".to_owned(),
            ],
            ..FakeWindowsFirewallApi::default()
        };

        let report = apply_windows_firewall_policy(plan.clone(), &mut api).unwrap();
        let evidence = WindowsFirewallPolicyEvidence::from_report(&report);
        let line = evidence.to_jsonl_line().unwrap();

        assert_eq!(report.action, WindowsFirewallLifecycleAction::Applied);
        assert_eq!(
            report.firewall_api_result,
            "stale_rules_removed_rules_upserted"
        );
        assert_eq!(
            report.cleanup,
            WindowsFirewallCleanupDecision::RemoveStaleRules
        );
        assert_eq!(report.stale_rule_names, vec![stale_rule_name.clone()]);
        assert_eq!(
            report.stale_rule_cleanup_outcomes,
            vec![WindowsFirewallStaleRuleCleanupOutcome::Removed]
        );
        assert_eq!(
            api.calls,
            vec![
                format!("list:{}", plan.connector_id_hash),
                format!("remove:{stale_rule_name}"),
                format!("upsert:{current_rule_name}")
            ]
        );
        assert_eq!(evidence.stale_rule_name_hashes.len(), 1);
        assert!(!line.contains(&stale_rule_name));
        assert!(!line.contains(&current_rule_name));
    }

    #[test]
    fn test_windows_firewall_policy_reports_stale_cleanup_failure_without_upsert() {
        let constraints = windows_firewall_constraints(&[], &[443], &["198.51.100.7"]);
        let plan = plan_windows_firewall_policy(
            "connector",
            Path::new(r"C:\fcp\connector.exe"),
            true,
            Some(&constraints),
        )
        .unwrap();
        let current_rule_name = plan.rules[0].name.clone();
        let stale_rule_name = windows_firewall_rule_name(
            &plan.connector_id_hash,
            WindowsFirewallRuleProtocol::Tcp,
            8443,
            "198.51.100.8",
        )
        .unwrap();
        let mut cleanup_fail_for = BTreeSet::new();
        cleanup_fail_for.insert(stale_rule_name.clone());
        let mut api = FakeWindowsFirewallApi {
            stale_rule_names: vec![stale_rule_name.clone()],
            cleanup_fail_for,
            ..FakeWindowsFirewallApi::default()
        };

        let report = apply_windows_firewall_policy(plan.clone(), &mut api).unwrap();
        let evidence = WindowsFirewallPolicyEvidence::from_report(&report);

        assert_eq!(
            report.action,
            WindowsFirewallLifecycleAction::StaleCleanupFailed
        );
        assert_eq!(report.firewall_api_result, "stale_rule_cleanup_failed");
        assert_eq!(report.skip_reason, Some("stale_rule_cleanup_failed"));
        assert_eq!(
            report.stale_rule_cleanup_outcomes,
            vec![WindowsFirewallStaleRuleCleanupOutcome::Failed]
        );
        assert_eq!(
            api.calls,
            vec![
                format!("list:{}", plan.connector_id_hash),
                format!("remove:{stale_rule_name}")
            ]
        );
        assert!(!api.calls.contains(&format!("upsert:{current_rule_name}")));
        assert_eq!(evidence.skip_reason, Some("stale_rule_cleanup_failed"));
        assert_eq!(evidence.stale_rule_name_hashes.len(), 1);
    }

    #[test]
    fn test_windows_firewall_evidence_redacts_connector_path_host_and_rule_names() {
        let constraints =
            windows_firewall_constraints(&["tenant-secret.example.com"], &[443], &["203.0.113.10"]);
        let plan = plan_windows_firewall_policy(
            "tenant-secret@example.com",
            Path::new(r"C:\Users\secret\connector.exe"),
            true,
            Some(&constraints),
        )
        .unwrap();
        let evidence = WindowsFirewallPolicyEvidence::planned_only(plan);
        let line = evidence.to_jsonl_line().unwrap();

        assert!(line.contains("fcp.windows_firewall_policy.v1"));
        assert!(!line.contains("tenant-secret@example.com"));
        assert!(!line.contains("tenant-secret.example.com"));
        assert!(!line.contains(r"C:\Users\secret\connector.exe"));
        assert!(!line.contains("203.0.113.10"));
        assert!(!line.contains("fcp-fw-"));
        assert_eq!(evidence.host_allow_hashes.len(), 1);
        assert_eq!(evidence.ip_allow_hashes.len(), 1);
        assert_eq!(evidence.rule_name_hashes.len(), 1);
        assert_eq!(evidence.target_address_classes, vec!["public_ip"]);
    }

    #[test]
    fn test_expand_path_connector_state_subpath() {
        let state_dir = PathBuf::from("/data/state");
        assert_eq!(
            expand_path("$CONNECTOR_STATE/db/main.sqlite", Some(&state_dir)),
            Ok(Some(PathBuf::from("/data/state/db/main.sqlite")))
        );
    }

    #[test]
    fn test_expand_path_absolute_ignores_state_dir() {
        let state_dir = PathBuf::from("/data/state");
        assert_eq!(
            expand_path("/etc/hosts", Some(&state_dir)),
            Ok(Some(PathBuf::from("/etc/hosts")))
        );
    }

    #[test]
    fn test_compiled_policy_state_dir_added_to_writable() {
        let mut section = test_sandbox_section();
        section.fs_writable_paths = vec![]; // No writable paths
        let state_dir = Some(PathBuf::from("/data/state"));
        let policy = CompiledPolicy::from_manifest(&section, state_dir).unwrap();
        assert!(
            policy
                .writable_paths
                .iter()
                .any(|p| p.as_path() == Path::new("/data/state"))
        );
    }

    #[test]
    fn test_compiled_policy_state_dir_not_duplicated() {
        let mut section = test_sandbox_section();
        section.fs_writable_paths = vec!["$CONNECTOR_STATE".into()];
        let state_dir = Some(PathBuf::from("/data/state"));
        let policy = CompiledPolicy::from_manifest(&section, state_dir).unwrap();
        // $CONNECTOR_STATE expands to /data/state, and state_dir is also /data/state
        // Should not be duplicated
        let count = policy
            .writable_paths
            .iter()
            .filter(|p| p.as_path() == Path::new("/data/state"))
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_create_sandbox_returns_platform_backend() -> Result<(), SandboxError> {
        let expected = if cfg!(target_os = "linux") {
            "linux"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else if cfg!(target_os = "windows") {
            "windows"
        } else {
            return Ok(());
        };

        let sandbox = match create_sandbox() {
            Ok(sandbox) => sandbox,
            Err(SandboxError::UnsupportedPlatform(_)) => return Ok(()),
            Err(other) => return Err(other),
        };

        assert_eq!(sandbox.platform_name(), expected);
        assert!(sandbox.is_available());
        Ok(())
    }

    #[test]
    fn test_noop_sandbox_verify_file_access() {
        let sandbox = NoOpSandbox;
        let section = test_sandbox_section();
        // `$CONNECTOR_STATE` in fs_writable_paths only expands when a
        // state_dir is supplied; without it, the writable set is empty
        // and the cache.db assertion below fails spuriously. Mirror
        // test_compile_policy's `state_dir` so the NoOp verifier has a
        // populated writable set to match against.
        let state_dir = Some(PathBuf::from("/var/lib/fcp/connectors/test"));
        let policy = CompiledPolicy::from_manifest(&section, state_dir).unwrap();
        assert!(
            sandbox
                .verify_file_access(&policy, std::path::Path::new("/usr/lib/libc.so"), false)
                .is_ok()
        );
        assert!(
            sandbox
                .verify_file_access(
                    &policy,
                    std::path::Path::new("/var/lib/fcp/connectors/test/cache.db"),
                    true,
                )
                .is_ok()
        );
        assert!(
            sandbox
                .verify_file_access(&policy, std::path::Path::new("/anything"), false)
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_resolve_policy_path_rejects_symlink_escape_for_missing_leaf() {
        use std::fs;
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // Canonicalize temp_dir to resolve macOS symlinks (/var → /private/var)
        // so that policy path comparisons use consistent prefixes.
        let base = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "fcp-sandbox-path-resolution-{}-{unique}",
            std::process::id()
        ));
        let allowed = base.join("allowed");
        let escaped = base.join("escaped");
        let link = allowed.join("link");
        let pending_write = link.join("future.txt");

        fs::create_dir_all(&allowed).unwrap();
        fs::create_dir_all(&escaped).unwrap();
        symlink(&escaped, &link).unwrap();

        assert_eq!(
            resolve_policy_path(&pending_write),
            escaped.join("future.txt")
        );

        let section = SandboxSection {
            profile: SandboxProfile::Strict,
            memory_mb: 256,
            cpu_percent: 50,
            wall_clock_timeout_ms: 30_000,
            fs_readonly_paths: Vec::new(),
            fs_writable_paths: vec![allowed.display().to_string()],
            deny_exec: true,
            deny_ptrace: true,
        };
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        let sandbox = create_sandbox().unwrap();

        let result = sandbox.verify_file_access(&policy, &pending_write, true);
        assert!(
            result.is_err(),
            "symlinked existing ancestors must not bypass writable path checks",
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_resolve_policy_path_preserves_symlink_parent_semantics() {
        use std::fs;
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "fcp-sandbox-symlink-parent-{}-{unique}",
            std::process::id()
        ));
        let allowed = base.join("allowed");
        let escaped = base.join("escaped");
        let link = allowed.join("link");
        let sneaky_write = link.join("..").join("future.txt");

        fs::create_dir_all(&allowed).unwrap();
        fs::create_dir_all(&escaped).unwrap();
        symlink(&escaped, &link).unwrap();

        let expected = sneaky_write
            .parent()
            .and_then(|parent| parent.canonicalize().ok())
            .expect("parent with symlink and .. should canonicalize")
            .join("future.txt");

        assert_eq!(resolve_policy_path(&sneaky_write), expected);
        assert_ne!(
            expected,
            allowed.join("future.txt"),
            "symlink parent traversal must not collapse lexically inside the allowed tree",
        );
    }

    #[test]
    fn test_noop_sandbox_verify_exec_and_network() {
        let sandbox = NoOpSandbox;
        let section = test_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(sandbox.verify_exec_allowed(&policy).is_err());
        assert!(sandbox.verify_network_blocked(&policy).is_ok());
    }

    #[test]
    fn test_compiled_policy_serde_roundtrip() {
        let section = test_sandbox_section();
        let state_dir = Some(PathBuf::from("/tmp/state"));
        let policy = CompiledPolicy::from_manifest(&section, state_dir).unwrap();

        let json = serde_json::to_string(&policy).unwrap();
        let roundtrip: CompiledPolicy = serde_json::from_str(&json).unwrap();

        assert_eq!(roundtrip.profile, policy.profile);
        assert_eq!(roundtrip.memory_limit_bytes, policy.memory_limit_bytes);
        assert_eq!(roundtrip.cpu_percent, policy.cpu_percent);
        assert_eq!(roundtrip.deny_exec, policy.deny_exec);
        assert_eq!(roundtrip.deny_ptrace, policy.deny_ptrace);
        assert_eq!(roundtrip.block_direct_network, policy.block_direct_network);
    }

    #[test]
    fn test_platform_flags_serde_roundtrip() {
        let flags = PlatformFlags {
            linux_use_landlock: true,
            linux_use_userns: true,
            macos_entitlements: vec!["com.apple.security.network.client".into()],
            windows_low_integrity: true,
            windows_appcontainer_capabilities: vec![WINDOWS_APPCONTAINER_INTERNET_CLIENT.into()],
        };

        let json = serde_json::to_string(&flags).unwrap();
        let roundtrip: PlatformFlags = serde_json::from_str(&json).unwrap();

        assert!(roundtrip.linux_use_landlock);
        assert!(roundtrip.linux_use_userns);
        assert_eq!(roundtrip.macos_entitlements.len(), 1);
        assert!(roundtrip.windows_low_integrity);
        assert_eq!(
            roundtrip.windows_appcontainer_capabilities,
            vec![WINDOWS_APPCONTAINER_INTERNET_CLIENT]
        );
    }

    // ── New tests: CompiledPolicy clone + debug ──

    #[test]
    fn test_compiled_policy_clone() {
        let section = test_sandbox_section();
        let state_dir = Some(PathBuf::from("/tmp/clone-test"));
        let original = CompiledPolicy::from_manifest(&section, state_dir).unwrap();
        let cloned = original.clone();
        assert_eq!(original.profile, cloned.profile);
        assert_eq!(original.memory_limit_bytes, cloned.memory_limit_bytes);
        assert_eq!(original.cpu_percent, cloned.cpu_percent);
        assert_eq!(original.wall_clock_timeout, cloned.wall_clock_timeout);
        assert_eq!(original.readonly_paths, cloned.readonly_paths);
        assert_eq!(original.writable_paths, cloned.writable_paths);
        assert_eq!(original.deny_exec, cloned.deny_exec);
        assert_eq!(original.deny_ptrace, cloned.deny_ptrace);
        assert_eq!(original.block_direct_network, cloned.block_direct_network);
        assert_eq!(original.state_dir, cloned.state_dir);
    }

    #[test]
    fn test_compiled_policy_debug() {
        let section = test_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        let debug = format!("{policy:?}");
        assert!(debug.contains("CompiledPolicy"));
        assert!(debug.contains("Strict"));
    }

    #[test]
    fn test_platform_flags_clone() {
        let original = PlatformFlags {
            linux_use_landlock: true,
            linux_use_userns: true,
            macos_entitlements: vec!["ent1".into(), "ent2".into()],
            windows_low_integrity: true,
            windows_appcontainer_capabilities: vec!["custom.capability".into()],
        };
        let cloned = original.clone();
        assert_eq!(original.linux_use_landlock, cloned.linux_use_landlock);
        assert_eq!(original.linux_use_userns, cloned.linux_use_userns);
        assert_eq!(original.macos_entitlements, cloned.macos_entitlements);
        assert_eq!(original.windows_low_integrity, cloned.windows_low_integrity);
        assert_eq!(
            original.windows_appcontainer_capabilities,
            cloned.windows_appcontainer_capabilities
        );
    }

    #[test]
    fn test_platform_flags_debug() {
        let flags = PlatformFlags::default();
        let debug = format!("{flags:?}");
        assert!(debug.contains("PlatformFlags"));
    }

    #[test]
    fn test_compiled_policy_no_state_dir() {
        let section = test_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(policy.state_dir.is_none());
        // $CONNECTOR_STATE paths should be skipped when state_dir is None
        assert!(
            !policy
                .writable_paths
                .iter()
                .any(|p| p.display().to_string().contains("CONNECTOR_STATE"))
        );
    }

    #[test]
    fn test_compiled_policy_memory_conversion() {
        let mut section = test_sandbox_section();
        section.memory_mb = 1024;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert_eq!(policy.memory_limit_bytes, 1024 * 1024 * 1024);
    }

    #[test]
    fn test_compiled_policy_wall_clock_conversion() {
        let mut section = test_sandbox_section();
        section.wall_clock_timeout_ms = 60_000;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert_eq!(policy.wall_clock_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_compiled_policy_zero_memory() {
        let mut section = test_sandbox_section();
        section.memory_mb = 0;
        let err = CompiledPolicy::from_manifest(&section, None).unwrap_err();
        assert!(matches!(err, SandboxError::InvalidConfig(_)));
        assert!(err.to_string().contains("memory_mb"));
    }

    #[test]
    fn test_compiled_policy_max_cpu() {
        let mut section = test_sandbox_section();
        section.cpu_percent = 100;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert_eq!(policy.cpu_percent, 100);
    }

    #[test]
    fn test_compiled_policy_min_cpu() {
        let mut section = test_sandbox_section();
        section.cpu_percent = 1;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert_eq!(policy.cpu_percent, 1);
    }

    #[test]
    fn test_compiled_policy_zero_cpu() {
        let mut section = test_sandbox_section();
        section.cpu_percent = 0;
        let err = CompiledPolicy::from_manifest(&section, None).unwrap_err();
        assert!(matches!(err, SandboxError::InvalidConfig(_)));
        assert!(err.to_string().contains("cpu_percent"));
    }

    #[test]
    fn test_compiled_policy_cpu_over_100() {
        let mut section = test_sandbox_section();
        section.cpu_percent = 101;
        let err = CompiledPolicy::from_manifest(&section, None).unwrap_err();
        assert!(matches!(err, SandboxError::InvalidConfig(_)));
        assert!(err.to_string().contains("cpu_percent"));
        assert!(err.to_string().contains("101"));
    }

    #[test]
    fn test_compiled_policy_cpu_max_u8() {
        let mut section = test_sandbox_section();
        section.cpu_percent = 255;
        let err = CompiledPolicy::from_manifest(&section, None).unwrap_err();
        assert!(matches!(err, SandboxError::InvalidConfig(_)));
        assert!(err.to_string().contains("255"));
    }

    #[test]
    fn test_expand_path_no_state_dir_prefix() {
        // A path that starts with $CONNECTOR_STATE/ but state_dir is None
        assert_eq!(expand_path("$CONNECTOR_STATE/data", None), Ok(None));
    }

    #[test]
    fn test_expand_path_regular_path_no_state_dir() {
        // Regular paths don't need state_dir
        assert_eq!(
            expand_path("/etc/config", None),
            Ok(Some(PathBuf::from("/etc/config")))
        );
    }

    #[test]
    fn test_expand_path_nested_subpath() {
        let state_dir = PathBuf::from("/data");
        assert_eq!(
            expand_path("$CONNECTOR_STATE/a/b/c/d", Some(&state_dir)),
            Ok(Some(PathBuf::from("/data/a/b/c/d")))
        );
    }

    #[test]
    fn test_noop_sandbox_debug() {
        let sandbox = NoOpSandbox;
        let debug = format!("{sandbox:?}");
        assert!(debug.contains("NoOpSandbox"));
    }

    #[test]
    fn test_noop_sandbox_apply_to_command() {
        let sandbox = NoOpSandbox;
        let section = test_sandbox_section();
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        let mut cmd = std::process::Command::new("echo");
        assert!(sandbox.apply_to_command(&mut cmd, &policy).is_ok());
    }

    #[test]
    fn test_compiled_policy_serde_with_platform_flags() {
        let section = test_sandbox_section();
        let flags = PlatformFlags {
            linux_use_landlock: true,
            linux_use_userns: false,
            macos_entitlements: vec!["com.apple.security.app-sandbox".into()],
            windows_low_integrity: true,
            windows_appcontainer_capabilities: vec!["custom.capability".into()],
        };
        let policy = CompiledPolicy::from_manifest(&section, None)
            .unwrap()
            .with_platform_flags(flags);
        let json = serde_json::to_string(&policy).unwrap();
        let roundtrip: CompiledPolicy = serde_json::from_str(&json).unwrap();
        assert!(roundtrip.platform_flags.linux_use_landlock);
        assert!(!roundtrip.platform_flags.linux_use_userns);
        assert_eq!(roundtrip.platform_flags.macos_entitlements.len(), 1);
        assert!(roundtrip.platform_flags.windows_low_integrity);
        assert_eq!(
            roundtrip.platform_flags.windows_appcontainer_capabilities,
            vec!["custom.capability"]
        );
    }

    #[test]
    fn test_platform_flags_serde_defaults_omitted() {
        // Default flags deserialized from empty JSON object
        let json = "{}";
        let flags: PlatformFlags = serde_json::from_str(json).unwrap();
        assert!(flags.is_empty());
    }

    #[test]
    fn test_compiled_policy_multiple_readonly_paths() {
        let mut section = test_sandbox_section();
        section.fs_readonly_paths =
            vec!["/usr".into(), "/lib".into(), "/opt".into(), "/etc".into()];
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert_eq!(policy.readonly_paths.len(), 4);
    }

    #[test]
    fn test_compiled_policy_multiple_writable_paths_with_state() {
        let mut section = test_sandbox_section();
        section.fs_writable_paths = vec![
            "$CONNECTOR_STATE".into(),
            "$CONNECTOR_STATE/cache".into(),
            "/tmp/scratch".into(),
        ];
        let state_dir = Some(PathBuf::from("/var/state"));
        let policy = CompiledPolicy::from_manifest(&section, state_dir).unwrap();
        assert!(policy.writable_paths.contains(&PathBuf::from("/var/state")));
        assert!(
            policy
                .writable_paths
                .contains(&PathBuf::from("/var/state/cache"))
        );
        assert!(
            policy
                .writable_paths
                .contains(&PathBuf::from("/tmp/scratch"))
        );
    }

    #[test]
    fn test_sandbox_error_debug() {
        let e = SandboxError::Timeout;
        let debug = format!("{e:?}");
        assert!(debug.contains("Timeout"));
    }

    #[test]
    fn test_sandbox_error_io_from() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no access");
        let e: SandboxError = io_err.into();
        assert!(e.to_string().contains("no access"));
    }

    #[test]
    fn test_compiled_policy_strict_plus_blocks_network() {
        let mut section = test_sandbox_section();
        section.profile = SandboxProfile::StrictPlus;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(policy.block_direct_network);
    }

    #[test]
    fn test_compiled_policy_moderate_blocks_network() {
        let mut section = test_sandbox_section();
        section.profile = SandboxProfile::Moderate;
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(policy.block_direct_network);
    }

    // ── New batch: SandboxError display and debug additional variants ──

    #[test]
    fn test_sandbox_error_unsupported_platform_display() {
        let e = SandboxError::UnsupportedPlatform("haiku".into());
        let msg = e.to_string();
        assert!(msg.contains("haiku"));
        assert!(msg.contains("not supported"));
    }

    #[test]
    fn test_sandbox_error_policy_compilation_display() {
        let e = SandboxError::PolicyCompilationFailed("invalid path".into());
        let msg = e.to_string();
        assert!(msg.contains("invalid path"));
        assert!(msg.contains("compile"));
    }

    #[test]
    fn test_sandbox_error_apply_failed_display() {
        let e = SandboxError::ApplyFailed("seccomp rejected".into());
        let msg = e.to_string();
        assert!(msg.contains("seccomp rejected"));
        assert!(msg.contains("apply"));
    }

    #[test]
    fn test_sandbox_error_resource_limit_display() {
        let e = SandboxError::ResourceLimitExceeded("cpu time".into());
        let msg = e.to_string();
        assert!(msg.contains("cpu time"));
    }

    #[test]
    fn test_sandbox_error_invalid_config_display() {
        let e = SandboxError::InvalidConfig("cpu_percent > 100".into());
        let msg = e.to_string();
        assert!(msg.contains("cpu_percent > 100"));
    }

    #[test]
    fn test_sandbox_error_syscall_display() {
        let e = SandboxError::SyscallFailed("prctl(PR_SET_NO_NEW_PRIVS)".into());
        let msg = e.to_string();
        assert!(msg.contains("prctl"));
    }

    #[test]
    fn test_sandbox_error_timeout_display() {
        let e = SandboxError::Timeout;
        let msg = e.to_string();
        assert!(msg.contains("timeout"));
    }

    #[test]
    fn test_sandbox_error_io_permission_denied() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let e: SandboxError = io_err.into();
        let msg = e.to_string();
        assert!(msg.contains("access denied"));
    }

    #[test]
    fn test_sandbox_error_io_not_found() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let e: SandboxError = io_err.into();
        let msg = e.to_string();
        assert!(msg.contains("file missing"));
    }

    #[test]
    fn test_sandbox_error_debug_all_variants() {
        let errors: Vec<SandboxError> = vec![
            SandboxError::UnsupportedPlatform("os".into()),
            SandboxError::PolicyCompilationFailed("x".into()),
            SandboxError::ApplyFailed("y".into()),
            SandboxError::ResourceLimitExceeded("z".into()),
            SandboxError::InvalidConfig("a".into()),
            SandboxError::SyscallFailed("b".into()),
            SandboxError::Timeout,
        ];
        for err in &errors {
            let dbg = format!("{err:?}");
            assert!(!dbg.is_empty());
        }
    }

    // ── New batch: PlatformFlags edge cases ──

    #[test]
    fn test_platform_flags_with_multiple_entitlements() {
        let flags = PlatformFlags {
            linux_use_landlock: false,
            linux_use_userns: false,
            macos_entitlements: vec![
                "com.apple.security.app-sandbox".into(),
                "com.apple.security.network.client".into(),
                "com.apple.security.files.user-selected.read-only".into(),
            ],
            windows_low_integrity: false,
            windows_appcontainer_capabilities: Vec::new(),
        };
        assert!(!flags.is_empty());
        assert_eq!(flags.macos_entitlements.len(), 3);
    }

    #[test]
    fn test_platform_flags_all_fields_set() {
        let flags = PlatformFlags {
            linux_use_landlock: true,
            linux_use_userns: true,
            macos_entitlements: vec!["ent".into()],
            windows_low_integrity: true,
            windows_appcontainer_capabilities: vec!["custom.capability".into()],
        };
        assert!(!flags.is_empty());
        let json = serde_json::to_string(&flags).unwrap();
        let rt: PlatformFlags = serde_json::from_str(&json).unwrap();
        assert!(rt.linux_use_landlock);
        assert!(rt.linux_use_userns);
        assert_eq!(rt.macos_entitlements.len(), 1);
        assert!(rt.windows_low_integrity);
        assert_eq!(
            rt.windows_appcontainer_capabilities,
            vec!["custom.capability"]
        );
    }

    #[test]
    fn test_platform_flags_serde_partial_fields() {
        // Only some fields present in JSON; rest should default
        let json = r#"{"linux_use_landlock": true}"#;
        let flags: PlatformFlags = serde_json::from_str(json).unwrap();
        assert!(flags.linux_use_landlock);
        assert!(!flags.linux_use_userns);
        assert!(flags.macos_entitlements.is_empty());
        assert!(!flags.windows_low_integrity);
        assert!(flags.windows_appcontainer_capabilities.is_empty());
    }

    // ── New batch: CompiledPolicy edge cases ──

    #[test]
    fn test_compiled_policy_empty_readonly_and_writable() {
        let mut section = test_sandbox_section();
        section.fs_readonly_paths = vec![];
        section.fs_writable_paths = vec![];
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert!(policy.readonly_paths.is_empty());
        assert!(policy.writable_paths.is_empty());
    }

    #[test]
    fn test_compiled_policy_zero_timeout() {
        let mut section = test_sandbox_section();
        section.wall_clock_timeout_ms = 0;
        let err = CompiledPolicy::from_manifest(&section, None).unwrap_err();
        assert!(matches!(err, SandboxError::InvalidConfig(_)));
        assert!(err.to_string().contains("wall_clock_timeout_ms"));
    }

    #[test]
    fn test_compiled_policy_large_memory() {
        let mut section = test_sandbox_section();
        section.memory_mb = 32_768; // 32 GB
        let policy = CompiledPolicy::from_manifest(&section, None).unwrap();
        assert_eq!(policy.memory_limit_bytes, 32_768 * 1024 * 1024);
    }

    #[test]
    fn test_compiled_policy_serde_json_roundtrip_all_fields() {
        let section = test_sandbox_section();
        let state_dir = Some(PathBuf::from("/var/data"));
        let flags = PlatformFlags {
            linux_use_landlock: true,
            linux_use_userns: false,
            macos_entitlements: vec!["ent".into()],
            windows_low_integrity: true,
            windows_appcontainer_capabilities: vec!["custom.capability".into()],
        };
        let policy = CompiledPolicy::from_manifest(&section, state_dir)
            .unwrap()
            .with_platform_flags(flags);
        let json = serde_json::to_string_pretty(&policy).unwrap();
        let rt: CompiledPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.profile, policy.profile);
        assert_eq!(rt.memory_limit_bytes, policy.memory_limit_bytes);
        assert_eq!(rt.cpu_percent, policy.cpu_percent);
        assert_eq!(rt.deny_exec, policy.deny_exec);
        assert_eq!(rt.deny_ptrace, policy.deny_ptrace);
        assert_eq!(rt.block_direct_network, policy.block_direct_network);
        assert_eq!(rt.state_dir, policy.state_dir);
        assert!(rt.platform_flags.linux_use_landlock);
        assert!(rt.platform_flags.windows_low_integrity);
        assert_eq!(
            rt.platform_flags.windows_appcontainer_capabilities,
            vec!["custom.capability"]
        );
    }

    // ── New batch: expand_path edge cases ──

    #[test]
    fn test_expand_path_state_dir_with_deep_nesting() {
        let sd = PathBuf::from("/mnt/data");
        assert_eq!(
            expand_path("$CONNECTOR_STATE/a/b/c/d/e/f", Some(&sd)),
            Ok(Some(PathBuf::from("/mnt/data/a/b/c/d/e/f")))
        );
    }

    #[test]
    fn test_expand_path_rejects_unknown_dollar_prefix() {
        let err = expand_path("$HOME/data", None).unwrap_err();
        assert!(err.contains("absolute"));
    }

    #[test]
    fn test_expand_path_rejects_relative_path() {
        let err = expand_path("relative/path", None).unwrap_err();
        assert!(err.contains("absolute"));
    }

    #[test]
    fn test_expand_path_rejects_connector_state_parent_escape() {
        let err =
            expand_path("$CONNECTOR_STATE/../cache", Some(&PathBuf::from("/state"))).unwrap_err();
        assert!(err.contains("normal path components"));
    }

    #[test]
    fn test_compiled_policy_rejects_relative_paths() {
        let mut section = test_sandbox_section();
        section.fs_readonly_paths = vec!["relative/path".into()];
        let err = CompiledPolicy::from_manifest(&section, None).unwrap_err();
        assert!(matches!(err, SandboxError::PolicyCompilationFailed(_)));
        assert!(err.to_string().contains("fs_readonly_paths"));
    }

    #[test]
    fn test_compiled_policy_rejects_connector_state_escape() {
        let mut section = test_sandbox_section();
        section.fs_writable_paths = vec!["$CONNECTOR_STATE/../cache".into()];
        let err =
            CompiledPolicy::from_manifest(&section, Some(PathBuf::from("/state"))).unwrap_err();
        assert!(matches!(err, SandboxError::PolicyCompilationFailed(_)));
        assert!(err.to_string().contains("normal path components"));
    }

    // ── New batch: NoOpSandbox default trait ──

    #[test]
    fn test_noop_sandbox_default_trait() {
        let sandbox = NoOpSandbox;
        assert!(sandbox.is_available());
        assert_eq!(sandbox.platform_name(), "noop");
    }

    #[test]
    fn test_noop_sandbox_verify_all_operations() {
        let sandbox = NoOpSandbox;
        let section = test_sandbox_section();
        // Provide state_dir so `$CONNECTOR_STATE` in fs_writable_paths
        // expands; without it the writable set is empty and the
        // cache.db write assertion below fails spuriously.
        let state_dir = Some(PathBuf::from("/var/lib/fcp/connectors/test"));
        let policy = CompiledPolicy::from_manifest(&section, state_dir).unwrap();

        assert!(
            sandbox
                .verify_file_access(&policy, std::path::Path::new("/usr/bin/test"), false)
                .is_ok()
        );
        assert!(
            sandbox
                .verify_file_access(
                    &policy,
                    std::path::Path::new("/var/lib/fcp/connectors/test/cache.db"),
                    true,
                )
                .is_ok()
        );
        assert!(
            sandbox
                .verify_file_access(&policy, std::path::Path::new("/etc/secret"), true)
                .is_err()
        );
        assert!(sandbox.verify_exec_allowed(&policy).is_err());
        assert!(sandbox.verify_network_blocked(&policy).is_ok());
        assert!(sandbox.apply(&policy).is_ok());
    }

    // ── FilterStrength parity matrix (bead 459lp) ─────────────────────────
    //
    // These tests lock in the cross-platform filter-coarseness contract
    // documented on [`FilterStrength`]. The matrix is intentionally
    // explicit: if a platform's backing mechanism changes (AppContainer
    // lands on Windows, macOS tightens its SBPL, Linux drops seccomp,
    // etc.) we want the failure to show up as a test regression rather
    // than a silent guarantee change. Update the matrix *and* the
    // [`FilterStrength::expected_for_target_os`] table together.

    #[test]
    fn filter_strength_ordering_strongest_last() {
        // SyscallLevel > ProfileLevel > ProcessLimit. Comparisons use
        // PartialOrd, so trait consumers can assert
        // `sandbox.filter_strength() >= required_level`.
        assert!(FilterStrength::SyscallLevel > FilterStrength::ProfileLevel);
        assert!(FilterStrength::ProfileLevel > FilterStrength::ProcessLimit);
        assert!(FilterStrength::SyscallLevel > FilterStrength::ProcessLimit);
    }

    #[test]
    fn filter_strength_expected_matrix() {
        // Documented parity table. These asserts are the source of truth
        // paired with the table in the FilterStrength rustdoc.
        assert_eq!(
            FilterStrength::expected_for_target_os("linux"),
            Some(FilterStrength::SyscallLevel),
        );
        assert_eq!(
            FilterStrength::expected_for_target_os("macos"),
            Some(FilterStrength::ProfileLevel),
        );
        assert_eq!(
            FilterStrength::expected_for_target_os("windows"),
            Some(FilterStrength::ProcessLimit),
        );
        // Unknown targets MUST NOT default-allow to any strength;
        // returning None forces a deliberate parity review.
        assert_eq!(
            FilterStrength::expected_for_target_os("freebsd"),
            None,
            "new host targets must be reviewed before claiming a strength tier",
        );
    }

    #[test]
    fn filter_strength_default_is_conservative() {
        // Any Sandbox impl that forgets to override filter_strength gets
        // ProcessLimit (the weakest level). The NoOpSandbox doesn't
        // override it, so this test also doubles as a guard on the
        // trait default.
        struct MinimalSandbox;
        impl Sandbox for MinimalSandbox {
            fn apply(&self, _p: &CompiledPolicy) -> Result<(), SandboxError> {
                Ok(())
            }
            fn is_available(&self) -> bool {
                true
            }
            fn platform_name(&self) -> &'static str {
                "minimal"
            }
            fn verify_file_access(
                &self,
                _p: &CompiledPolicy,
                _path: &std::path::Path,
                _w: bool,
            ) -> Result<(), SandboxError> {
                Ok(())
            }
            fn verify_exec_allowed(&self, _p: &CompiledPolicy) -> Result<(), SandboxError> {
                Ok(())
            }
            fn verify_network_blocked(&self, _p: &CompiledPolicy) -> Result<(), SandboxError> {
                Ok(())
            }
        }
        assert_eq!(
            MinimalSandbox.filter_strength(),
            FilterStrength::ProcessLimit,
        );
        assert_eq!(NoOpSandbox.filter_strength(), FilterStrength::ProcessLimit);
    }

    #[test]
    fn filter_strength_as_str_stable_snake_case() {
        // These identifiers are emitted into audit trails — freezing
        // them here stops drive-by rename refactors from breaking
        // downstream log consumers.
        assert_eq!(FilterStrength::ProcessLimit.as_str(), "process_limit");
        assert_eq!(FilterStrength::ProfileLevel.as_str(), "profile_level");
        assert_eq!(FilterStrength::SyscallLevel.as_str(), "syscall_level");
    }

    /// Assert that the active host sandbox reports exactly the
    /// documented filter strength for this target OS.
    ///
    /// Compiled once per host target, so the workspace test matrix
    /// naturally ends up with one assertion per (OS, arch) pair — the
    /// "platform-matrix" coverage the parity bead asks for.
    #[test]
    fn host_sandbox_matches_documented_filter_strength() -> Result<(), SandboxError> {
        let Some(expected) = FilterStrength::expected_for_target_os(std::env::consts::OS) else {
            // Running on a host we haven't reviewed for sandbox parity
            // (e.g., freebsd, solaris). create_sandbox() will fail; we
            // just record that no strength contract applies.
            return Ok(());
        };

        let sandbox = match create_sandbox() {
            Ok(s) => s,
            Err(SandboxError::UnsupportedPlatform(_)) => {
                // Same guard as above, but via the runtime path.
                return Ok(());
            }
            Err(other) => return Err(other),
        };

        assert_eq!(
            sandbox.filter_strength(),
            expected,
            "host sandbox on {} must report FilterStrength::{:?} per the parity matrix; \
             got {:?}. If you intentionally changed the backing mechanism, update \
             both FilterStrength::expected_for_target_os and the rustdoc table.",
            std::env::consts::OS,
            expected,
            sandbox.filter_strength(),
        );
        Ok(())
    }

    // Per-platform compile-gated assertions. These give each CI leg
    // (linux, macos, windows) a concrete failure site when only that
    // platform's parity contract regresses.

    #[cfg(target_os = "linux")]
    #[test]
    fn platform_matrix_linux_is_syscall_level() {
        let sandbox = crate::linux::LinuxSandbox::new();
        assert_eq!(sandbox.filter_strength(), FilterStrength::SyscallLevel);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn platform_matrix_macos_is_profile_level() {
        let sandbox = crate::macos::MacOsSandbox::new();
        assert_eq!(sandbox.filter_strength(), FilterStrength::ProfileLevel);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn platform_matrix_windows_is_process_limit() {
        let sandbox = crate::windows::WindowsSandbox::new();
        assert_eq!(sandbox.filter_strength(), FilterStrength::ProcessLimit);
    }
}
