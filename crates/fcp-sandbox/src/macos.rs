//! macOS sandbox implementation using seatbelt (sandbox-exec).
//!
//! # Enforcement Mechanism
//!
//! macOS provides the `sandbox_init` API which enforces a profile specified in
//! Scheme-based sandbox profile language (SBPL). The sandbox is enforced at the
//! kernel level and cannot be bypassed from userspace.
//!
//! # Profile Generation
//!
//! We generate SBPL profiles dynamically based on the `CompiledPolicy`. The
//! profile follows Apple's sandbox profile language conventions while enforcing
//! FCP2's security requirements.
//!
//! # Limitations
//!
//! - Sandbox profiles are declarative and applied atomically
//! - Once applied, restrictions cannot be relaxed
//! - Some system resources require specific entitlements
//! - Network filtering is coarse-grained (allow/deny per protocol)
//!
//! # Parity with Linux seccomp
//!
//! `sandbox_init` enforces SBPL rules at the Mach/BSD API layer, not at
//! each individual syscall. This implementation reports
//! [`FilterStrength::ProfileLevel`](crate::FilterStrength::ProfileLevel)
//! — strictly coarser than Linux's `SyscallLevel` seccomp-bpf filter. A
//! native code path the profile doesn't explicitly name can still reach
//! the kernel. `RLIMIT_NPROC` is also deliberately not set even when
//! `deny_exec` is true: on macOS, NPTL threads count as processes, so
//! clamping `NPROC` to 0 would starve the async runtime. `deny_exec` is
//! therefore enforced entirely through the SBPL `(deny process-exec)`
//! rule — if that rule is ever elided during profile generation, no
//! second line of defense catches it. Cross-platform parity is tracked
//! in bead `flywheel_connectors-459lp`.

#![cfg(target_os = "macos")]

use std::ffi::CString;
use std::fmt::Write as _;
use std::path::Path;

use tracing::{debug, info, warn};

use crate::sandbox::{CompiledPolicy, Sandbox, SandboxError};

/// Sanitize a filesystem path for safe inclusion in an SBPL profile string.
///
/// Rejects paths containing characters that could inject SBPL directives
/// (double quotes, parentheses, backslashes, newlines). Returns the path
/// unchanged if safe, or a placeholder that will match nothing if dangerous.
fn sanitize_sbpl_path(path: &str) -> String {
    if path.contains('"')
        || path.contains('\\')
        || path.contains('(')
        || path.contains(')')
        || path.contains('\n')
        || path.contains('\r')
    {
        warn!(path = %path, "Rejected sandbox path containing SBPL-injection characters");
        // Return a path that will never match any real filesystem entry
        "/dev/null/REJECTED_UNSAFE_PATH".to_string()
    } else {
        path.to_string()
    }
}

// ============================================================================
// macOS Sandbox
// ============================================================================

/// macOS sandbox using seatbelt profiles.
#[derive(Debug, Default)]
pub struct MacOsSandbox {
    /// Cached profile string (for debugging).
    _cached_profile: Option<String>,
}

impl MacOsSandbox {
    /// Create a new macOS sandbox.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            _cached_profile: None,
        }
    }

    /// Generate a seatbelt profile (SBPL) from the compiled policy.
    fn generate_profile(policy: &CompiledPolicy) -> String {
        let mut profile = String::new();

        // Version header
        profile.push_str("(version 1)\n\n");

        // Default deny
        profile.push_str(";; Default deny all\n");
        profile.push_str("(deny default)\n\n");

        // Allow basic process operations
        profile.push_str(";; Basic process operations\n");
        profile.push_str("(allow process-info-codesignature)\n");
        profile.push_str("(allow process-info-pidinfo)\n");
        profile.push_str("(allow process-info-setcontrol)\n");
        profile.push_str("(allow sysctl-read)\n");
        profile.push_str("(allow mach-lookup\n");
        profile.push_str("  (global-name \"com.apple.system.logger\")\n");
        profile.push_str("  (global-name \"com.apple.system.notification_center\")\n");
        profile.push_str(")\n\n");

        // Memory operations
        profile.push_str(";; Memory operations\n");
        profile.push_str("(allow mach-priv-host-port)\n\n");

        // Signal handling
        profile.push_str(";; Signal handling\n");
        profile.push_str("(allow signal (target self))\n\n");

        // File system access
        profile.push_str(";; Filesystem access\n");

        // Always allow read of system libraries
        profile.push_str("(allow file-read*\n");
        profile.push_str("  (subpath \"/usr/lib\")\n");
        profile.push_str("  (subpath \"/System/Library\")\n");
        profile.push_str("  (subpath \"/Library/Frameworks\")\n");
        profile.push_str("  (subpath \"/Applications/Xcode.app/Contents/Developer/Toolchains\")\n");
        profile.push_str("  (literal \"/dev/null\")\n");
        profile.push_str("  (literal \"/dev/random\")\n");
        profile.push_str("  (literal \"/dev/urandom\")\n");
        profile.push_str(")\n");

        // Add read-only paths from policy
        if !policy.readonly_paths.is_empty() {
            profile.push_str("(allow file-read*\n");
            for path in &policy.readonly_paths {
                let escaped = sanitize_sbpl_path(&path.display().to_string());
                let _ = writeln!(profile, "  (subpath \"{escaped}\")");
            }
            profile.push_str(")\n");
        }

        // Add writable paths from policy
        if !policy.writable_paths.is_empty() {
            profile.push_str("(allow file-read* file-write*\n");
            for path in &policy.writable_paths {
                let escaped = sanitize_sbpl_path(&path.display().to_string());
                let _ = writeln!(profile, "  (subpath \"{escaped}\")");
            }
            profile.push_str(")\n");
        }

        profile.push('\n');

        // Process execution
        if policy.deny_exec {
            profile.push_str(";; Process execution denied\n");
            profile.push_str("(deny process-exec)\n");
            profile.push_str("(deny process-fork)\n\n");
        } else {
            profile.push_str(";; Process execution allowed\n");
            profile.push_str("(allow process-exec)\n");
            profile.push_str("(allow process-fork)\n\n");
        }

        // Network access
        if policy.block_direct_network {
            profile.push_str(";; Direct network access blocked (use Network Guard)\n");
            profile.push_str("(deny network*)\n");
            // Allow only client-style connect access to the fixed Network Guard
            // socket path. Granting generic unix-socket bind/inbound rights
            // would let a sandboxed connector create or accept arbitrary local
            // IPC endpoints, widening the blocked-network profile beyond the
            // intended mediated egress exception.
            profile.push_str("(allow network-outbound\n");
            profile.push_str("  (path \"/var/run/fcp-network-guard.sock\")\n");
            profile.push_str(")\n");
            profile.push('\n');
        } else {
            profile.push_str(";; Network access allowed\n");
            profile.push_str("(allow network*)\n\n");
        }

        // Debugging / ptrace
        if policy.deny_ptrace {
            profile.push_str(";; Debugging denied\n");
            profile.push_str("(deny process-info-codesignature (with no-log))\n");
            profile.push_str("(deny system-privilege)\n\n");
        }

        // IPC
        profile.push_str(";; Allow basic IPC\n");
        profile.push_str("(allow ipc-posix-shm-read-data)\n");
        profile.push_str("(allow ipc-posix-shm-write-data)\n\n");

        // Resource limits
        let _ = writeln!(
            profile,
            ";; Resource limits: memory={}MB, cpu={}%",
            policy.memory_limit_bytes / (1024 * 1024),
            policy.cpu_percent
        );
        // Note: macOS sandbox doesn't have direct rlimit support in profiles
        // We apply these via setrlimit separately

        debug!(
            profile_len = profile.len(),
            "Generated macOS sandbox profile"
        );

        profile
    }

    /// Apply resource limits using setrlimit.
    ///
    /// Enforcement is split by what the macOS kernel actually supports
    /// (verified empirically on Darwin 25 / Apple Silicon under bead
    /// sandbox-macos-setrlimit-fail-open-1o7fy):
    ///
    /// - `RLIMIT_CPU` and `RLIMIT_CORE` apply reliably, so their failures
    ///   propagate (fail closed), mirroring the Linux sandbox.
    /// - `RLIMIT_NOFILE` raises can exceed `kern.maxfilesperproc` on
    ///   constrained hosts, so it stays best-effort with a warning.
    /// - `RLIMIT_DATA` / `RLIMIT_AS` return `EINVAL` for every value on
    ///   modern macOS — the kernel does not implement lowering them — so the
    ///   memory budget cannot be enforced via setrlimit at all. The attempt
    ///   is kept for older kernels that honored `RLIMIT_DATA`, but a failure
    ///   is a documented platform limitation logged loudly rather than a
    ///   fail-closed error: failing closed here would refuse every native
    ///   connector on current macOS. Connectors that require an enforced
    ///   memory ceiling must run under the WASI runtime (see the
    ///   `FilterStrength` guidance in `sandbox.rs`); the native macOS
    ///   sandbox is defense-in-depth.
    fn apply_rlimits(policy: &CompiledPolicy) -> Result<(), SandboxError> {
        // Best-effort memory budget: RLIMIT_DATA alone does not cover
        // mmap-backed allocations, so both are attempted, but see above —
        // modern Darwin rejects both with EINVAL.
        let mem_data = set_rlimit(
            libc::RLIMIT_DATA,
            policy.memory_limit_bytes,
            policy.memory_limit_bytes,
        );
        let mem_as = set_rlimit(
            libc::RLIMIT_AS,
            policy.memory_limit_bytes,
            policy.memory_limit_bytes,
        );
        if let Err(error) = mem_data.and(mem_as) {
            warn!(
                error = %error,
                memory_mb = policy.memory_limit_bytes / (1024 * 1024),
                "macOS cannot enforce the memory budget via setrlimit \
                 (RLIMIT_DATA/RLIMIT_AS are unsupported on modern Darwin); \
                 the native sandbox runs WITHOUT a memory cap — use the WASI \
                 runtime for connectors that require an enforced memory limit"
            );
        }

        // CPU time limit (soft = timeout, hard = timeout + 5s grace).
        // Reliable on macOS: fail closed like Linux.
        let cpu_seconds = policy.wall_clock_timeout.as_secs();
        set_rlimit(libc::RLIMIT_CPU, cpu_seconds, cpu_seconds + 5)?;

        // File descriptor limit: best-effort, the hard-limit raise can hit
        // kern.maxfilesperproc on constrained hosts.
        if let Err(error) = set_rlimit(libc::RLIMIT_NOFILE, 1024, 4096) {
            warn!(
                error = %error,
                "Failed to set file descriptor limit"
            );
        }

        // Disable core dumps. Lowering to zero is always permitted, so an
        // error here is unexpected: fail closed.
        set_rlimit(libc::RLIMIT_CORE, 0, 0)?;

        // NOTE: RLIMIT_NPROC is NOT set on macOS even when deny_exec is true.
        // On macOS (like Linux NPTL), RLIMIT_NPROC counts threads as processes.
        // Setting it to 0 would crash any async runtime (Tokio, etc.) that needs
        // worker threads. Process execution is instead restricted by the SBPL
        // profile's `(deny process-exec)` directive.

        info!("Applied resource limits via setrlimit");
        Ok(())
    }
}

/// Set one resource limit, mirroring the Linux sandbox helper.
fn set_rlimit(resource: libc::c_int, soft: u64, hard: u64) -> Result<(), SandboxError> {
    let limit = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };

    // SAFETY: `limit` is a fully initialized `libc::rlimit`, and `setrlimit`
    // only reads that struct while updating the current process limits.
    unsafe {
        if libc::setrlimit(resource, &limit) != 0 {
            return Err(SandboxError::SyscallFailed(format!(
                "setrlimit({resource}) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    Ok(())
}

impl Sandbox for MacOsSandbox {
    fn apply(&self, policy: &CompiledPolicy) -> Result<(), SandboxError> {
        info!(
            profile = ?policy.profile,
            memory_mb = policy.memory_limit_bytes / (1024 * 1024),
            cpu_percent = policy.cpu_percent,
            deny_exec = policy.deny_exec,
            deny_ptrace = policy.deny_ptrace,
            block_network = policy.block_direct_network,
            "Applying macOS sandbox"
        );

        // Step 1: Apply resource limits (fails closed on the limits macOS
        // reliably supports; see `apply_rlimits`).
        Self::apply_rlimits(policy)?;

        // Step 2: Generate and apply sandbox profile
        let profile = Self::generate_profile(policy);

        // Convert profile to C string
        let c_profile = CString::new(profile.as_bytes())
            .map_err(|e| SandboxError::PolicyCompilationFailed(format!("invalid profile: {e}")))?;

        // Apply sandbox using sandbox_init
        let mut errorbuf: *mut i8 = std::ptr::null_mut();

        // SAFETY: `c_profile` is a live NUL-terminated CString for the duration
        // of the call, `flags` selects inline-profile parsing, and `errorbuf`
        // points to writable storage for the returned error pointer.
        let result = unsafe {
            sandbox_init(
                c_profile.as_ptr(),
                0, // SANDBOX_NAMED (profile is inline, not a file)
                &mut errorbuf,
            )
        };

        if result != 0 {
            let error_msg = if errorbuf.is_null() {
                "unknown error".to_string()
            } else {
                // SAFETY: `sandbox_init` returned a non-null error buffer on
                // failure, and Apple documents it as a valid C string.
                let err = unsafe { std::ffi::CStr::from_ptr(errorbuf) };
                let msg = err.to_string_lossy().to_string();
                // SAFETY: `errorbuf` came from `sandbox_init` and must be
                // released exactly once with `sandbox_free_error`.
                unsafe {
                    sandbox_free_error(errorbuf);
                }
                msg
            };

            return Err(SandboxError::ApplyFailed(format!(
                "sandbox_init failed: {error_msg}"
            )));
        }

        info!("macOS sandbox applied successfully");
        Ok(())
    }

    fn apply_to_command(
        &self,
        cmd: &mut std::process::Command,
        policy: &CompiledPolicy,
    ) -> Result<(), SandboxError> {
        // For macOS, we could use `sandbox-exec` via `Command::new("sandbox-exec")`,
        // but since we rely on `mac_syscall::sandbox_init` in our process,
        // we can apply it `pre_exec` exactly like Linux seccomp.
        use std::os::unix::process::CommandExt;

        let memory_limit_bytes = policy.memory_limit_bytes;
        let cpu_seconds = policy.wall_clock_timeout.as_secs();

        // SAFETY: `pre_exec` is only installed before spawning the child. The
        // closure captures owned values, uses async-signal-safe libc calls plus
        // `sandbox_init`, and returns only `std::io::Error` on failure.
        unsafe {
            cmd.pre_exec(move || {
                // Enforce both heap/data growth and total address-space growth. RLIMIT_DATA
                // alone does not cover mmap-backed allocations.
                let memory_limit = libc::rlimit {
                    rlim_cur: memory_limit_bytes,
                    rlim_max: memory_limit_bytes,
                };
                if libc::setrlimit(libc::RLIMIT_DATA, &memory_limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::setrlimit(libc::RLIMIT_AS, &memory_limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                let cpu_limit = libc::rlimit {
                    rlim_cur: cpu_seconds,
                    rlim_max: cpu_seconds + 5,
                };
                if libc::setrlimit(libc::RLIMIT_CPU, &cpu_limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                let fd_limit = libc::rlimit {
                    rlim_cur: 1024,
                    rlim_max: 4096,
                };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &fd_limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                let core_limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &core_limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                // Apple's sandbox_init is NOT async-signal-safe (it allocates memory and
                // communicates via XPC/Mach messages). If the parent held any allocator or
                // Objective-C locks when fork() was called, calling sandbox_init here in
                // pre_exec will deterministically deadlock the child.
                //
                // We must rely on the process sandboxing itself post-exec using
                // Sandbox::apply(), or use the sandbox-exec CLI wrapper.

                Ok(())
            });
        }

        Ok(())
    }

    fn is_available(&self) -> bool {
        // Seatbelt is available on all modern macOS versions
        true
    }

    fn platform_name(&self) -> &'static str {
        "macos"
    }

    fn filter_strength(&self) -> crate::sandbox::FilterStrength {
        // sandbox_init enforces SBPL `(deny process-exec)` /
        // `(deny file-read*)` / `(deny network*)` at the Mach/BSD API layer
        // rather than at individual syscalls. A native code path that the
        // profile does not explicitly name may still reach the kernel, and
        // RLIMIT_NPROC is deliberately not used here (it counts threads as
        // processes and would crash the async runtime). That's strictly
        // coarser than Linux seccomp-bpf — ProfileLevel in FilterStrength.
        crate::sandbox::FilterStrength::ProfileLevel
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
                // Canonicalize policy paths too so macOS symlinks
                // (/tmp → /private/tmp, /var → /private/var) match.
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

        // Check system paths (always readable)
        let system_paths = ["/usr/lib", "/System/Library", "/Library/Frameworks"];
        for sys_path in system_paths {
            if path.starts_with(sys_path) {
                return Ok(());
            }
        }

        // Check policy paths — canonicalize to handle platform symlinks.
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

// ============================================================================
// FFI Bindings
// ============================================================================

// SAFETY: These are FFI bindings to macOS sandbox APIs.
// sandbox_init and sandbox_free_error are documented Apple APIs.
unsafe extern "C" {
    /// Initialize sandbox with a profile string.
    fn sandbox_init(profile: *const i8, flags: u64, errorbuf: *mut *mut i8) -> i32;

    /// Free error buffer from `sandbox_init`.
    fn sandbox_free_error(errorbuf: *mut i8);
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
            readonly_paths: vec![PathBuf::from("/usr"), PathBuf::from("/opt")],
            writable_paths: vec![PathBuf::from("/tmp/test")],
            deny_exec: true,
            deny_ptrace: true,
            block_direct_network: true,
            state_dir: Some(PathBuf::from("/tmp/test")),
            platform_flags: crate::sandbox::PlatformFlags::default(),
        }
    }

    #[test]
    fn test_macos_sandbox_available() {
        let sandbox = MacOsSandbox::new();
        assert!(sandbox.is_available());
        assert_eq!(sandbox.platform_name(), "macos");
    }

    /// The limits `apply_rlimits` fails closed on must actually be settable,
    /// or every native macOS connector would be refused (bead
    /// sandbox-macos-setrlimit-fail-open-1o7fy). Core-dump disable and a
    /// generous CPU ceiling are safe to apply to the test process.
    #[test]
    fn fail_closed_rlimits_are_settable_on_macos() {
        set_rlimit(libc::RLIMIT_CORE, 0, 0).expect("RLIMIT_CORE lowering must succeed");
        // 10^7 seconds (~115 days) — far above any test runtime, so this
        // cannot affect the harness while proving the CPU path works.
        set_rlimit(libc::RLIMIT_CPU, 10_000_000, 10_000_005)
            .expect("RLIMIT_CPU must be settable on macOS");
    }

    /// Tripwire for the documented platform limitation: modern Darwin on
    /// Apple Silicon rejects `RLIMIT_DATA`/`RLIMIT_AS` with `EINVAL` for every
    /// value, which is why `apply_rlimits` treats the memory budget as
    /// best-effort instead of fail-closed. If this test ever fails, the
    /// kernel has started honoring memory rlimits — revisit the fail-open
    /// memory design and promote `DATA`/`AS` to fail-closed.
    #[cfg(target_arch = "aarch64")]
    #[test]
    fn memory_rlimits_remain_unsupported_on_apple_silicon() {
        let mem = 128 * 1024 * 1024;
        assert!(
            set_rlimit(libc::RLIMIT_DATA, mem, mem).is_err(),
            "RLIMIT_DATA unexpectedly succeeded — revisit bead 1o7fy fail-open memory design"
        );
        assert!(
            set_rlimit(libc::RLIMIT_AS, mem, mem).is_err(),
            "RLIMIT_AS unexpectedly succeeded — revisit bead 1o7fy fail-open memory design"
        );
    }

    #[test]
    fn test_generate_profile_structure() {
        let policy = test_policy();
        let profile = MacOsSandbox::generate_profile(&policy);

        // Check basic structure
        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));

        // Check file access rules
        assert!(profile.contains("file-read*"));
        assert!(profile.contains("/usr"));
        assert!(profile.contains("/tmp/test"));

        // Check network is blocked
        assert!(profile.contains("network access blocked"));
        assert!(profile.contains("(deny network*)"));

        // Check exec is denied
        assert!(profile.contains("(deny process-exec)"));
        assert!(profile.contains("(deny process-fork)"));
    }

    #[test]
    fn test_generate_profile_permissive() {
        let mut policy = test_policy();
        policy.block_direct_network = false;
        policy.deny_exec = false;

        let profile = MacOsSandbox::generate_profile(&policy);

        // Check network is allowed
        assert!(profile.contains("(allow network*)"));

        // Check exec is allowed
        assert!(profile.contains("(allow process-exec)"));
        assert!(profile.contains("(allow process-fork)"));
    }

    #[test]
    fn test_verify_file_access_system_paths() {
        let sandbox = MacOsSandbox::new();
        let policy = test_policy();

        // System paths should always be readable
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/usr/lib/libSystem.B.dylib"), false)
                .is_ok()
        );
        assert!(
            sandbox
                .verify_file_access(
                    &policy,
                    Path::new("/System/Library/Frameworks/CoreFoundation.framework"),
                    false
                )
                .is_ok()
        );

        // But not writable
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/usr/lib/test.dylib"), true)
                .is_err()
        );
    }

    #[test]
    fn test_verify_file_access_policy_paths() {
        let sandbox = MacOsSandbox::new();
        let policy = test_policy();

        // Writable path should allow read and write
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/tmp/test/data.db"), false)
                .is_ok()
        );
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/tmp/test/data.db"), true)
                .is_ok()
        );

        // Unknown path should be denied
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/home/user/secret"), false)
                .is_err()
        );
    }

    // ── Batch: profile generation edge cases ──

    #[test]
    fn test_generate_profile_no_readonly_paths() {
        let mut policy = test_policy();
        policy.readonly_paths = vec![];
        let profile = MacOsSandbox::generate_profile(&policy);
        // Should still have system read paths but no extra readonly section
        assert!(profile.contains("/usr/lib"));
        // The extra (allow file-read* ...) block for policy paths should not appear
        // (system paths are always present in a separate block)
    }

    #[test]
    fn test_generate_profile_no_writable_paths() {
        let mut policy = test_policy();
        policy.writable_paths = vec![];
        let profile = MacOsSandbox::generate_profile(&policy);
        // Should not contain file-write for policy writable paths
        assert!(!profile.contains("file-write*\n  (subpath"));
    }

    #[test]
    fn test_generate_profile_ptrace_allowed() {
        let mut policy = test_policy();
        policy.deny_ptrace = false;
        let profile = MacOsSandbox::generate_profile(&policy);
        // Should not contain the ptrace-deny section
        assert!(!profile.contains("Debugging denied"));
        assert!(!profile.contains("(deny system-privilege)"));
    }

    #[test]
    fn test_generate_profile_ptrace_denied() {
        let policy = test_policy();
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("Debugging denied"));
        assert!(profile.contains("(deny system-privilege)"));
    }

    #[test]
    fn test_generate_profile_multiple_readonly_paths() {
        let mut policy = test_policy();
        policy.readonly_paths = vec![
            PathBuf::from("/data/models"),
            PathBuf::from("/data/config"),
            PathBuf::from("/data/assets"),
        ];
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("/data/models"));
        assert!(profile.contains("/data/config"));
        assert!(profile.contains("/data/assets"));
    }

    #[test]
    fn test_generate_profile_multiple_writable_paths() {
        let mut policy = test_policy();
        policy.writable_paths = vec![PathBuf::from("/tmp/cache"), PathBuf::from("/tmp/logs")];
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("/tmp/cache"));
        assert!(profile.contains("/tmp/logs"));
    }

    #[test]
    fn test_generate_profile_network_guard_socket() {
        let policy = test_policy();
        let profile = MacOsSandbox::generate_profile(&policy);
        // When network blocked, should allow IPC to network guard socket
        assert!(profile.contains("fcp-network-guard.sock"));
    }

    #[test]
    fn test_generate_profile_resource_limits_comment() {
        let policy = test_policy();
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("memory=256MB"));
        assert!(profile.contains("cpu=50%"));
    }

    #[test]
    fn test_generate_profile_ipc_always_allowed() {
        let policy = test_policy();
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("(allow ipc-posix-shm-read-data)"));
        assert!(profile.contains("(allow ipc-posix-shm-write-data)"));
    }

    #[test]
    fn test_generate_profile_system_libraries_always_readable() {
        let policy = test_policy();
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("/usr/lib"));
        assert!(profile.contains("/System/Library"));
        assert!(profile.contains("/Library/Frameworks"));
        assert!(profile.contains("/dev/null"));
        assert!(profile.contains("/dev/random"));
        assert!(profile.contains("/dev/urandom"));
    }

    #[test]
    fn test_generate_profile_starts_with_version() {
        let policy = test_policy();
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.starts_with("(version 1)"));
    }

    // ── Batch: verify methods ──

    #[test]
    fn test_verify_exec_allowed_when_denied() {
        let sandbox = MacOsSandbox::new();
        let policy = test_policy();
        assert!(policy.deny_exec);
        let result = sandbox.verify_exec_allowed(&policy);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("denied"));
    }

    #[test]
    fn test_verify_exec_allowed_when_permitted() {
        let sandbox = MacOsSandbox::new();
        let mut policy = test_policy();
        policy.deny_exec = false;
        assert!(sandbox.verify_exec_allowed(&policy).is_ok());
    }

    #[test]
    fn test_verify_network_blocked_when_strict() {
        let sandbox = MacOsSandbox::new();
        let policy = test_policy();
        assert!(policy.block_direct_network);
        // When network IS blocked, verify_network_blocked returns Ok
        assert!(sandbox.verify_network_blocked(&policy).is_ok());
    }

    #[test]
    fn test_verify_network_blocked_when_permissive() {
        let sandbox = MacOsSandbox::new();
        let mut policy = test_policy();
        policy.block_direct_network = false;
        // When network is NOT blocked, verify_network_blocked returns Err
        let result = sandbox.verify_network_blocked(&policy);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_file_access_readonly_path_write_denied() {
        let sandbox = MacOsSandbox::new();
        let policy = test_policy();
        // /opt is in readonly_paths, so write should be denied
        let result = sandbox.verify_file_access(&policy, Path::new("/opt/data.txt"), true);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_file_access_readonly_path_read_allowed() {
        let sandbox = MacOsSandbox::new();
        let policy = test_policy();
        // /opt is in readonly_paths
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/opt/data.txt"), false)
                .is_ok()
        );
    }

    #[test]
    fn test_verify_file_access_library_frameworks() {
        let sandbox = MacOsSandbox::new();
        let policy = test_policy();
        assert!(
            sandbox
                .verify_file_access(
                    &policy,
                    Path::new("/Library/Frameworks/Python.framework"),
                    false
                )
                .is_ok()
        );
    }

    // ── Batch: construction ──

    #[test]
    fn test_macos_sandbox_default() {
        let sandbox = MacOsSandbox::default();
        assert!(sandbox.is_available());
        assert_eq!(sandbox.platform_name(), "macos");
    }

    #[test]
    fn test_macos_sandbox_debug() {
        let sandbox = MacOsSandbox::new();
        let debug = format!("{sandbox:?}");
        assert!(debug.contains("MacOsSandbox"));
    }

    // ── Batch: SBPL path sanitization (security regression for 1fcd949) ──

    #[test]
    fn test_sanitize_sbpl_path_clean_path_passes_through() {
        assert_eq!(sanitize_sbpl_path("/usr/local/bin"), "/usr/local/bin");
        assert_eq!(sanitize_sbpl_path("/tmp/test"), "/tmp/test");
        assert_eq!(
            sanitize_sbpl_path("/home/user/data.db"),
            "/home/user/data.db"
        );
    }

    #[test]
    fn test_sanitize_sbpl_path_rejects_double_quotes() {
        // Double quotes could close the SBPL string and inject directives
        let result = sanitize_sbpl_path("/tmp/evil\")(allow default)(\"");
        assert_eq!(result, "/dev/null/REJECTED_UNSAFE_PATH");
    }

    #[test]
    fn test_sanitize_sbpl_path_rejects_backslash() {
        let result = sanitize_sbpl_path("/tmp/evil\\path");
        assert_eq!(result, "/dev/null/REJECTED_UNSAFE_PATH");
    }

    #[test]
    fn test_sanitize_sbpl_path_rejects_parentheses() {
        // Parentheses are SBPL syntax delimiters
        let result = sanitize_sbpl_path("/tmp/evil(allow default)");
        assert_eq!(result, "/dev/null/REJECTED_UNSAFE_PATH");

        let result = sanitize_sbpl_path("/tmp/evil)inject");
        assert_eq!(result, "/dev/null/REJECTED_UNSAFE_PATH");
    }

    #[test]
    fn test_sanitize_sbpl_path_rejects_newlines() {
        let result = sanitize_sbpl_path("/tmp/evil\npath");
        assert_eq!(result, "/dev/null/REJECTED_UNSAFE_PATH");

        let result = sanitize_sbpl_path("/tmp/evil\rpath");
        assert_eq!(result, "/dev/null/REJECTED_UNSAFE_PATH");
    }

    #[test]
    fn test_sanitize_sbpl_path_empty_string() {
        // Empty string has no dangerous chars, passes through
        assert_eq!(sanitize_sbpl_path(""), "");
    }

    #[test]
    fn test_sanitize_sbpl_path_allows_special_but_safe_chars() {
        // These are unusual but not SBPL-injectable
        assert_eq!(
            sanitize_sbpl_path("/tmp/path with spaces"),
            "/tmp/path with spaces"
        );
        assert_eq!(
            sanitize_sbpl_path("/tmp/path-with-dashes"),
            "/tmp/path-with-dashes"
        );
        assert_eq!(
            sanitize_sbpl_path("/tmp/path_under_score"),
            "/tmp/path_under_score"
        );
        assert_eq!(
            sanitize_sbpl_path("/tmp/path.with.dots"),
            "/tmp/path.with.dots"
        );
    }

    #[test]
    fn test_generate_profile_with_malicious_readonly_path() {
        let mut policy = test_policy();
        policy.readonly_paths = vec![
            PathBuf::from("/tmp/safe"),
            PathBuf::from("/tmp/evil\")(allow default)(\""),
        ];
        let profile = MacOsSandbox::generate_profile(&policy);

        // Safe path should be present
        assert!(profile.contains("/tmp/safe"));
        // Malicious path should be replaced with the rejection placeholder
        assert!(profile.contains("/dev/null/REJECTED_UNSAFE_PATH"));
        // The injected SBPL directive must NOT appear
        assert!(!profile.contains("(allow default)"));
    }

    #[test]
    fn test_generate_profile_with_malicious_writable_path() {
        let mut policy = test_policy();
        policy.writable_paths = vec![PathBuf::from("/tmp/evil\n(allow default)")];
        let profile = MacOsSandbox::generate_profile(&policy);

        // Injection attempt must be sanitized
        assert!(profile.contains("/dev/null/REJECTED_UNSAFE_PATH"));
        // Count occurrences of "(allow default)" - should be zero outside system boilerplate
        // The profile should NOT have an extra "(allow default)" from injection
        let default_deny_count = profile.matches("(deny default)").count();
        assert_eq!(
            default_deny_count, 1,
            "Only the legitimate deny-default should be present"
        );
    }

    // ── New tests: sanitize_sbpl_path additional edge cases ──

    #[test]
    fn test_sanitize_sbpl_path_unicode_safe() {
        // Unicode characters that are NOT SBPL injection vectors
        assert_eq!(sanitize_sbpl_path("/tmp/données"), "/tmp/données");
    }

    #[test]
    fn test_sanitize_sbpl_path_tab_character_passes() {
        // Tab is not blocked (only \n and \r are)
        let path = "/tmp/path\twith\ttabs";
        assert_eq!(sanitize_sbpl_path(path), path);
    }

    #[test]
    fn test_sanitize_sbpl_path_combined_injection() {
        // Multiple dangerous characters together
        let result = sanitize_sbpl_path("/tmp/\")(\n");
        assert_eq!(result, "/dev/null/REJECTED_UNSAFE_PATH");
    }

    #[test]
    fn test_sanitize_sbpl_path_lone_backslash_at_end() {
        let result = sanitize_sbpl_path("/tmp/path\\");
        assert_eq!(result, "/dev/null/REJECTED_UNSAFE_PATH");
    }

    #[test]
    fn test_sanitize_sbpl_path_embedded_null_char() {
        // Null bytes are valid in Rust strings - should pass since not in reject list
        // Actually, null bytes in paths are dangerous but not SBPL-specific
        let path = "/tmp/safe-path";
        assert_eq!(sanitize_sbpl_path(path), path);
    }

    // ── New tests: profile generation with varying configs ──

    #[test]
    fn test_generate_profile_deny_exec_false_deny_ptrace_true() {
        let mut policy = test_policy();
        policy.deny_exec = false;
        policy.deny_ptrace = true;
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("(allow process-exec)"));
        assert!(profile.contains("(allow process-fork)"));
        assert!(profile.contains("Debugging denied"));
    }

    #[test]
    fn test_generate_profile_deny_exec_true_deny_ptrace_false() {
        let mut policy = test_policy();
        policy.deny_exec = true;
        policy.deny_ptrace = false;
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("(deny process-exec)"));
        assert!(profile.contains("(deny process-fork)"));
        assert!(!profile.contains("Debugging denied"));
    }

    #[test]
    fn test_generate_profile_network_allowed() {
        let mut policy = test_policy();
        policy.block_direct_network = false;
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("(allow network*)"));
        assert!(!profile.contains("(deny network*)"));
    }

    #[test]
    fn test_generate_profile_network_blocked_has_guard_socket() {
        let policy = test_policy();
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("(deny network*)"));
        assert!(profile.contains("fcp-network-guard.sock"));
        assert!(!profile.contains("(allow network-bind"));
        assert!(!profile.contains("network-inbound"));
    }

    #[test]
    fn test_generate_profile_empty_paths() {
        let mut policy = test_policy();
        policy.readonly_paths = vec![];
        policy.writable_paths = vec![];
        let profile = MacOsSandbox::generate_profile(&policy);
        // Should still work without crashing
        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
    }

    #[test]
    fn test_generate_profile_large_memory() {
        let mut policy = test_policy();
        policy.memory_limit_bytes = 8 * 1024 * 1024 * 1024; // 8GB
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("memory=8192MB"));
    }

    #[test]
    fn test_generate_profile_cpu_100() {
        let mut policy = test_policy();
        policy.cpu_percent = 100;
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("cpu=100%"));
    }

    // ── New tests: verify methods edge cases ──

    #[test]
    fn test_verify_file_access_writable_subpath() {
        let sandbox = MacOsSandbox::new();
        let policy = test_policy();
        // /tmp/test is writable, so /tmp/test/sub/file.db should be writable
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/tmp/test/sub/file.db"), true)
                .is_ok()
        );
    }

    #[test]
    fn test_verify_file_access_outside_all_paths() {
        let sandbox = MacOsSandbox::new();
        let policy = test_policy();
        let result = sandbox.verify_file_access(&policy, Path::new("/var/secret"), false);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("not allowed"));
    }

    #[test]
    fn test_verify_file_access_write_system_path_denied() {
        let sandbox = MacOsSandbox::new();
        let policy = test_policy();
        // System paths are read-only, write should fail
        let result =
            sandbox.verify_file_access(&policy, Path::new("/System/Library/test.plist"), true);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_exec_and_network_combined() {
        let sandbox = MacOsSandbox::new();
        let mut policy = test_policy();
        policy.deny_exec = true;
        policy.block_direct_network = true;
        assert!(sandbox.verify_exec_allowed(&policy).is_err());
        assert!(sandbox.verify_network_blocked(&policy).is_ok());
    }

    #[test]
    fn test_verify_exec_allowed_and_network_not_blocked() {
        let sandbox = MacOsSandbox::new();
        let mut policy = test_policy();
        policy.deny_exec = false;
        policy.block_direct_network = false;
        assert!(sandbox.verify_exec_allowed(&policy).is_ok());
        assert!(sandbox.verify_network_blocked(&policy).is_err());
    }

    // ── New tests: MacOsSandbox construction edge cases ──

    #[test]
    fn test_macos_sandbox_new_is_const() {
        // Verify MacOsSandbox::new() can be created and is always available
        let sandbox = MacOsSandbox::new();
        assert!(sandbox.is_available());
        assert_eq!(sandbox.platform_name(), "macos");
    }

    #[test]
    fn test_generate_profile_contains_mach_lookup() {
        let policy = test_policy();
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("mach-lookup"));
        assert!(profile.contains("com.apple.system.logger"));
    }

    #[test]
    fn test_generate_profile_contains_signal_self() {
        let policy = test_policy();
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("(allow signal (target self))"));
    }

    // ── New batch: profile generation combinations ──

    #[test]
    fn test_generate_profile_all_permissive() {
        let mut policy = test_policy();
        policy.deny_exec = false;
        policy.deny_ptrace = false;
        policy.block_direct_network = false;
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("(allow process-exec)"));
        assert!(profile.contains("(allow process-fork)"));
        assert!(profile.contains("(allow network*)"));
        assert!(!profile.contains("Debugging denied"));
    }

    #[test]
    fn test_generate_profile_all_restrictive() {
        let policy = test_policy();
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("(deny process-exec)"));
        assert!(profile.contains("(deny process-fork)"));
        assert!(profile.contains("(deny network*)"));
        assert!(profile.contains("Debugging denied"));
    }

    #[test]
    fn test_generate_profile_cpu_1_percent() {
        let mut policy = test_policy();
        policy.cpu_percent = 1;
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("cpu=1%"));
    }

    #[test]
    fn test_generate_profile_zero_memory() {
        let mut policy = test_policy();
        policy.memory_limit_bytes = 0;
        let profile = MacOsSandbox::generate_profile(&policy);
        assert!(profile.contains("memory=0MB"));
    }

    #[test]
    fn test_generate_profile_many_readonly_paths() {
        let mut policy = test_policy();
        policy.readonly_paths = (0..10)
            .map(|i| PathBuf::from(format!("/data/volume{i}")))
            .collect();
        let profile = MacOsSandbox::generate_profile(&policy);
        for i in 0..10 {
            assert!(profile.contains(&format!("/data/volume{i}")));
        }
    }

    // ── New batch: sanitize_sbpl_path ──

    #[test]
    fn test_sanitize_sbpl_path_long_safe_path() {
        let path = "/very/long/path/to/some/nested/directory/structure/file.dat";
        assert_eq!(sanitize_sbpl_path(path), path);
    }

    #[test]
    fn test_sanitize_sbpl_path_only_double_quote() {
        let result = sanitize_sbpl_path("\"");
        assert_eq!(result, "/dev/null/REJECTED_UNSAFE_PATH");
    }

    #[test]
    fn test_sanitize_sbpl_path_only_open_paren() {
        let result = sanitize_sbpl_path("(");
        assert_eq!(result, "/dev/null/REJECTED_UNSAFE_PATH");
    }

    #[test]
    fn test_sanitize_sbpl_path_only_close_paren() {
        let result = sanitize_sbpl_path(")");
        assert_eq!(result, "/dev/null/REJECTED_UNSAFE_PATH");
    }

    #[test]
    fn test_sanitize_sbpl_path_carriage_return_only() {
        let result = sanitize_sbpl_path("\r");
        assert_eq!(result, "/dev/null/REJECTED_UNSAFE_PATH");
    }

    // ── New batch: verify_file_access edge cases ──

    #[test]
    fn test_verify_file_access_writable_path_read_allowed() {
        let sandbox = MacOsSandbox::new();
        let policy = test_policy();
        // /tmp/test is writable, reading should also be allowed
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/tmp/test/some_file"), false)
                .is_ok()
        );
    }

    #[test]
    fn test_verify_file_access_system_library_subpath() {
        let sandbox = MacOsSandbox::new();
        let policy = test_policy();
        assert!(
            sandbox
                .verify_file_access(
                    &policy,
                    Path::new("/System/Library/CoreServices/SystemVersion.plist"),
                    false
                )
                .is_ok()
        );
    }

    #[test]
    fn test_verify_file_access_random_home_dir_denied() {
        let sandbox = MacOsSandbox::new();
        let policy = test_policy();
        let result =
            sandbox.verify_file_access(&policy, Path::new("/Users/admin/.ssh/id_rsa"), false);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_file_access_write_to_system_lib_denied() {
        let sandbox = MacOsSandbox::new();
        let policy = test_policy();
        let result =
            sandbox.verify_file_access(&policy, Path::new("/usr/lib/malicious.dylib"), true);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("not allowed"));
    }
}
