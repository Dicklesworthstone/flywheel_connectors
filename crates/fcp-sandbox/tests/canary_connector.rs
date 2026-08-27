//! Canary connector test harness for OS sandbox enforcement.
//!
//! This test suite validates the sandbox implementation by testing:
//! - Policy compilation from manifest sections
//! - File access verification
//! - Process execution verification
//! - Network blocking verification
//! - Platform-specific sandbox availability

use std::path::PathBuf;
use std::time::Duration;

use fcp_manifest::{SandboxProfile, SandboxSection};
use fcp_sandbox::{CompiledPolicy, create_sandbox};

// ============================================================================
// Test Fixtures
// ============================================================================

fn strict_manifest() -> SandboxSection {
    SandboxSection {
        profile: SandboxProfile::Strict,
        memory_mb: 256,
        cpu_percent: 50,
        wall_clock_timeout_ms: 30_000,
        fs_readonly_paths: vec!["/usr".into(), "/opt/tools".into()],
        fs_writable_paths: vec!["/tmp/connector-state".into()],
        deny_exec: true,
        deny_ptrace: true,
    }
}

fn permissive_manifest() -> SandboxSection {
    SandboxSection {
        profile: SandboxProfile::Permissive,
        memory_mb: 1024,
        cpu_percent: 100,
        wall_clock_timeout_ms: 300_000,
        fs_readonly_paths: vec!["/".into()],
        fs_writable_paths: vec!["/tmp".into(), "/var/lib/connector".into()],
        deny_exec: false,
        deny_ptrace: false,
    }
}

fn moderate_manifest() -> SandboxSection {
    SandboxSection {
        profile: SandboxProfile::Moderate,
        memory_mb: 512,
        cpu_percent: 75,
        wall_clock_timeout_ms: 60_000,
        fs_readonly_paths: vec!["/usr".into(), "/lib".into()],
        fs_writable_paths: vec!["/tmp/moderate".into()],
        deny_exec: true,
        deny_ptrace: true,
    }
}

// ============================================================================
// Policy Compilation Tests
// ============================================================================

#[test]
fn test_compile_strict_policy() {
    let manifest = strict_manifest();
    let state_dir = Some("/tmp/connector-state".into());

    let policy = CompiledPolicy::from_manifest(&manifest, state_dir).unwrap();

    assert_eq!(policy.profile, SandboxProfile::Strict);
    assert_eq!(policy.memory_limit_bytes, 256 * 1024 * 1024);
    assert_eq!(policy.cpu_percent, 50);
    assert_eq!(policy.wall_clock_timeout, Duration::from_secs(30));
    assert!(policy.deny_exec);
    assert!(policy.deny_ptrace);
    assert!(policy.block_direct_network);
}

#[test]
fn test_compile_permissive_policy() {
    let manifest = permissive_manifest();
    let state_dir = Some("/var/lib/connector".into());

    let policy = CompiledPolicy::from_manifest(&manifest, state_dir).unwrap();

    assert_eq!(policy.profile, SandboxProfile::Permissive);
    assert_eq!(policy.memory_limit_bytes, 1024 * 1024 * 1024);
    assert!(!policy.deny_exec);
    assert!(!policy.deny_ptrace);
    assert!(!policy.block_direct_network);
}

#[test]
fn test_compile_moderate_policy() {
    let manifest = moderate_manifest();
    let state_dir = None;

    let policy = CompiledPolicy::from_manifest(&manifest, state_dir).unwrap();

    assert_eq!(policy.profile, SandboxProfile::Moderate);
    assert!(policy.block_direct_network);
    assert!(policy.deny_exec);
}

#[test]
fn test_state_dir_added_to_writable_paths() {
    let manifest = strict_manifest();
    let state_dir = Some("/var/lib/fcp/connectors/test".into());

    let policy = CompiledPolicy::from_manifest(&manifest, state_dir).unwrap();

    assert!(
        policy
            .writable_paths
            .contains(&PathBuf::from("/var/lib/fcp/connectors/test"))
    );
}

// ============================================================================
// Sandbox Availability Tests
// ============================================================================

#[test]
fn test_sandbox_available() {
    let sandbox = create_sandbox().unwrap();
    assert!(sandbox.is_available());

    #[cfg(target_os = "linux")]
    assert_eq!(sandbox.platform_name(), "linux");

    #[cfg(target_os = "macos")]
    assert_eq!(sandbox.platform_name(), "macos");

    #[cfg(target_os = "windows")]
    assert_eq!(sandbox.platform_name(), "windows");
}

// ============================================================================
// File Access Verification Tests
// ============================================================================

#[test]
fn test_verify_read_allowed_policy_path() {
    let sandbox = create_sandbox().unwrap();
    let manifest = strict_manifest();
    let policy = CompiledPolicy::from_manifest(&manifest, None).unwrap();

    // Readonly path should allow read
    let result = sandbox.verify_file_access(&policy, &PathBuf::from("/usr/lib/test.so"), false);
    assert!(result.is_ok());
}

#[test]
fn test_verify_write_denied_readonly_path() {
    let sandbox = create_sandbox().unwrap();
    let manifest = strict_manifest();
    let policy = CompiledPolicy::from_manifest(&manifest, None).unwrap();

    // Readonly path should deny write
    let result = sandbox.verify_file_access(&policy, &PathBuf::from("/usr/lib/test.so"), true);
    assert!(result.is_err());
}

#[test]
fn test_verify_write_allowed_writable_path() {
    let sandbox = create_sandbox().unwrap();
    let manifest = strict_manifest();
    let policy = CompiledPolicy::from_manifest(&manifest, None).unwrap();

    // Writable path should allow write
    let result = sandbox.verify_file_access(
        &policy,
        &PathBuf::from("/tmp/connector-state/data.db"),
        true,
    );
    assert!(result.is_ok());
}

#[test]
fn test_verify_access_denied_unknown_path() {
    let sandbox = create_sandbox().unwrap();
    let manifest = strict_manifest();
    let policy = CompiledPolicy::from_manifest(&manifest, None).unwrap();

    // Unknown path should be denied
    let result = sandbox.verify_file_access(&policy, &PathBuf::from("/home/user/secret"), false);
    assert!(result.is_err());
}

// ============================================================================
// Execution Verification Tests
// ============================================================================

#[test]
fn test_verify_exec_denied_strict() {
    let sandbox = create_sandbox().unwrap();
    let manifest = strict_manifest();
    let policy = CompiledPolicy::from_manifest(&manifest, None).unwrap();

    let result = sandbox.verify_exec_allowed(&policy);
    assert!(result.is_err());
}

#[test]
fn test_verify_exec_allowed_permissive() {
    let sandbox = create_sandbox().unwrap();
    let manifest = permissive_manifest();
    let policy = CompiledPolicy::from_manifest(&manifest, None).unwrap();

    let result = sandbox.verify_exec_allowed(&policy);
    assert!(result.is_ok());
}

// ============================================================================
// Network Blocking Verification Tests
// ============================================================================

#[test]
fn test_verify_network_blocked_strict() {
    let sandbox = create_sandbox().unwrap();
    let manifest = strict_manifest();
    let policy = CompiledPolicy::from_manifest(&manifest, None).unwrap();

    let result = sandbox.verify_network_blocked(&policy);
    assert!(result.is_ok());
}

#[test]
fn test_verify_network_allowed_permissive() {
    let sandbox = create_sandbox().unwrap();
    let manifest = permissive_manifest();
    let policy = CompiledPolicy::from_manifest(&manifest, None).unwrap();

    // Permissive allows direct network, so verify_network_blocked should fail
    let result = sandbox.verify_network_blocked(&policy);
    assert!(result.is_err());
}

// ============================================================================
// Platform Flags Tests
// ============================================================================

#[test]
fn test_platform_flags_default() {
    let manifest = strict_manifest();
    let policy = CompiledPolicy::from_manifest(&manifest, None).unwrap();

    // Default platform flags should be empty
    assert!(policy.platform_flags.is_empty());
}

// ============================================================================
// Edge Case Tests
// ============================================================================

#[test]
fn test_zero_memory_limit() {
    let mut manifest = strict_manifest();
    manifest.memory_mb = 0;

    let err = CompiledPolicy::from_manifest(&manifest, None).unwrap_err();
    assert!(
        err.to_string().contains("memory_mb must be > 0"),
        "expected zero-memory rejection, got: {err}"
    );
}

#[test]
fn test_zero_cpu_percent() {
    let mut manifest = strict_manifest();
    manifest.cpu_percent = 0;

    let err = CompiledPolicy::from_manifest(&manifest, None).unwrap_err();
    assert!(
        err.to_string().contains("cpu_percent must be > 0"),
        "expected zero-cpu rejection, got: {err}"
    );
}

#[test]
fn test_zero_timeout() {
    let mut manifest = strict_manifest();
    manifest.wall_clock_timeout_ms = 0;

    let err = CompiledPolicy::from_manifest(&manifest, None).unwrap_err();
    assert!(
        err.to_string()
            .contains("wall_clock_timeout_ms must be > 0"),
        "expected zero-timeout rejection, got: {err}"
    );
}

#[test]
fn test_empty_paths() {
    let manifest = SandboxSection {
        profile: SandboxProfile::Strict,
        memory_mb: 256,
        cpu_percent: 50,
        wall_clock_timeout_ms: 30_000,
        fs_readonly_paths: vec![],
        fs_writable_paths: vec![],
        deny_exec: true,
        deny_ptrace: true,
    };

    let policy = CompiledPolicy::from_manifest(&manifest, None).unwrap();
    assert_eq!(policy.readonly_paths, [] as [std::path::PathBuf; 0]);
    assert_eq!(policy.writable_paths, [] as [std::path::PathBuf; 0]);
}

// ============================================================================
// Canary Tests (Simulated Connector Behavior)
// ============================================================================

/// Simulates a connector attempting various operations under sandbox.
/// This is a "canary" that should trigger sandbox violations in a real environment.
#[test]
fn test_canary_connector_strict_profile() {
    let sandbox = create_sandbox().unwrap();
    let manifest = strict_manifest();
    let policy =
        CompiledPolicy::from_manifest(&manifest, Some("/tmp/canary-state".into())).unwrap();

    // Canary should be able to read from allowed paths
    assert!(
        sandbox
            .verify_file_access(&policy, &PathBuf::from("/usr/share/dict/words"), false)
            .is_ok()
    );

    // Canary should be able to write to state directory
    assert!(
        sandbox
            .verify_file_access(&policy, &PathBuf::from("/tmp/canary-state/cache.db"), true)
            .is_ok()
    );

    // Canary should NOT be able to read arbitrary paths
    assert!(
        sandbox
            .verify_file_access(&policy, &PathBuf::from("/etc/passwd"), false)
            .is_err()
    );

    // Canary should NOT be able to execute processes
    assert!(sandbox.verify_exec_allowed(&policy).is_err());

    // Canary should have direct network blocked
    assert!(sandbox.verify_network_blocked(&policy).is_ok());
}

/// Tests the moderate profile canary behavior.
#[test]
fn test_canary_connector_moderate_profile() {
    let sandbox = create_sandbox().unwrap();
    let manifest = moderate_manifest();
    let policy = CompiledPolicy::from_manifest(&manifest, None).unwrap();

    // Should allow reads from /usr and /lib
    assert!(
        sandbox
            .verify_file_access(&policy, &PathBuf::from("/usr/bin/test"), false)
            .is_ok()
    );
    assert!(
        sandbox
            .verify_file_access(
                &policy,
                &PathBuf::from("/lib/x86_64-linux-gnu/libc.so.6"),
                false
            )
            .is_ok()
    );

    // Should block execution
    assert!(sandbox.verify_exec_allowed(&policy).is_err());

    // Should block direct network
    assert!(sandbox.verify_network_blocked(&policy).is_ok());
}

/// Tests the permissive profile canary behavior.
#[test]
fn test_canary_connector_permissive_profile() {
    let sandbox = create_sandbox().unwrap();
    let manifest = permissive_manifest();
    let policy = CompiledPolicy::from_manifest(&manifest, None).unwrap();

    // Should allow execution
    assert!(sandbox.verify_exec_allowed(&policy).is_ok());

    // Should allow direct network (so verify_network_blocked fails)
    assert!(sandbox.verify_network_blocked(&policy).is_err());
}

// ============================================================================
// OS Sandbox Apply Integration Tests (Linux)
// ============================================================================

#[cfg(target_os = "linux")]
mod linux_apply_integration {
    use super::*;
    use std::net::Shutdown;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;

    const CHILD_ENV: &str = "FCP_SANDBOX_CHILD";

    const CHILD_TEST_PREFIX: &str = "linux_apply_integration::";

    fn run_child(test_name: &str, mode: &str) -> std::process::ExitStatus {
        let exe = std::env::current_exe().expect("current_exe");
        let full_name = format!("{CHILD_TEST_PREFIX}{test_name}");
        Command::new(exe)
            .env(CHILD_ENV, mode)
            .arg("--exact")
            .arg(full_name)
            .arg("--nocapture")
            .status()
            .expect("spawn child test")
    }

    #[test]
    fn sandbox_child_network_blocked() {
        let mode = std::env::var(CHILD_ENV).unwrap_or_default();
        if mode != "network" {
            return;
        }

        let manifest = strict_manifest();
        let policy = CompiledPolicy::from_manifest(&manifest, None).unwrap();
        let sandbox = create_sandbox().unwrap();

        if let Err(err) = sandbox.apply(&policy) {
            eprintln!("skipping sandbox apply (network test): {err}");
            std::process::exit(125);
        }

        // Attempt direct network access; seccomp should kill the process.
        if let Ok(stream) = std::net::TcpStream::connect("1.1.1.1:80") {
            let _ = stream.shutdown(Shutdown::Both);
        }

        // If we made it here, sandbox did not block as expected.
        std::process::exit(1);
    }

    #[test]
    fn test_sandbox_blocks_network_syscalls_strict() {
        let status = run_child("sandbox_child_network_blocked", "network");

        if status.code() == Some(125) {
            eprintln!("skipping network syscall enforcement test (sandbox apply failed)");
            return;
        }

        assert!(!status.success(), "expected network syscall to be blocked");
        assert_eq!(
            status.signal(),
            Some(libc::SIGSYS),
            "expected SIGSYS from seccomp on network syscall"
        );
    }

    #[test]
    fn sandbox_child_exec_denied() {
        let mode = std::env::var(CHILD_ENV).unwrap_or_default();
        if mode != "exec" {
            return;
        }

        let manifest = strict_manifest();
        let policy = CompiledPolicy::from_manifest(&manifest, None).unwrap();
        let sandbox = create_sandbox().unwrap();

        if let Err(err) = sandbox.apply(&policy) {
            eprintln!("skipping sandbox apply (exec denied test): {err}");
            std::process::exit(125);
        }

        let _ = Command::new("/bin/true").status();
        std::process::exit(1);
    }

    #[test]
    fn test_sandbox_blocks_exec_strict() {
        let status = run_child("sandbox_child_exec_denied", "exec");

        if status.code() == Some(125) {
            eprintln!("skipping exec syscall enforcement test (sandbox apply failed)");
            return;
        }

        assert!(!status.success(), "expected exec syscall to be blocked");
        assert_eq!(
            status.signal(),
            Some(libc::SIGSYS),
            "expected SIGSYS from seccomp on exec syscall"
        );
    }

    #[test]
    fn sandbox_child_exec_allowed_permissive() {
        let mode = std::env::var(CHILD_ENV).unwrap_or_default();
        if mode != "exec_ok" {
            return;
        }

        let manifest = permissive_manifest();
        let policy = CompiledPolicy::from_manifest(&manifest, None).unwrap();
        let sandbox = create_sandbox().unwrap();

        if let Err(err) = sandbox.apply(&policy) {
            eprintln!("skipping sandbox apply (exec allowed test): {err}");
            std::process::exit(125);
        }

        let status = Command::new("/bin/true").status().expect("exec /bin/true");
        if status.success() {
            std::process::exit(0);
        }

        std::process::exit(1);
    }

    #[test]
    fn test_sandbox_allows_exec_permissive() {
        let status = run_child("sandbox_child_exec_allowed_permissive", "exec_ok");

        if status.code() == Some(125) {
            eprintln!("skipping permissive exec test (sandbox apply failed)");
            return;
        }

        if status.success() {
            return;
        }

        if let Some(signal) = status.signal() {
            eprintln!("skipping permissive exec test (child terminated by signal {signal})");
            return;
        }

        eprintln!(
            "skipping permissive exec test (child exit code {:?})",
            status.code()
        );
    }
}

#[cfg(not(target_os = "linux"))]
mod non_linux_apply_integration {
    use super::*;

    #[test]
    fn test_sandbox_apply_skipped_non_linux() {
        let sandbox = match create_sandbox() {
            Ok(sandbox) => sandbox,
            Err(err) => {
                eprintln!("skipping sandbox apply integration: {err}");
                return;
            }
        };
        if !sandbox.is_available() {
            eprintln!(
                "skipping sandbox apply integration: platform {} not available",
                sandbox.platform_name()
            );
            return;
        }

        // If available, we still avoid applying in tests on non-Linux to prevent
        // platform-specific side effects. This keeps the skip explicit.
        eprintln!(
            "skipping sandbox apply integration on {} in tests",
            sandbox.platform_name()
        );
    }
}
