//! Bounded subprocess runner for `osascript` invocations.
//!
//! Bead: `flywheel_connectors-krxpn` (H.1 production hardening). The
//! Apple Notes connector historically called
//! `Command::new(...).output()` with no kill/timeout boundary — a
//! hung Notes `AppleEvent` could pin the connector indefinitely. This
//! module ships the bounded runner that:
//!
//!   * Spawns the child with `stdin = null` (the script cannot block
//!     waiting for input) and piped stdout/stderr.
//!   * Drains stdout/stderr concurrently in worker threads with a
//!     bounded read cap (per [`MAX_OUTPUT_BYTES`]) so the pipes
//!     cannot fill up and cause the child to deadlock waiting for
//!     the parent to read.
//!   * Polls [`std::process::Child::try_wait`] with a 50 ms cadence
//!     against a deadline. On expiry, calls [`Child::kill`](std::process::Child::kill) and
//!     surfaces [`SubprocessError::Timeout`].
//!   * Truncates stderr to a documented byte cap to keep error
//!     messages bounded even when the child is verbose.
//!
//! ## Why polling vs blocking
//!
//! `wait_with_output()` is the one-shot blocking call but offers no
//! deadline. Adding the `wait_timeout` crate would solve this, but
//! introduces a workspace-level dep for two connectors. The 50 ms
//! polling cadence is empirically fine for human-interactive `AppleEvents`
//! (osascript invocations are typically 10-200 ms). For sub-millisecond-
//! latency-sensitive use this would matter; for desktop-automation it
//! does not.

use std::io::Read;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Maximum bytes captured from each of stdout / stderr. Larger output
/// is silently truncated to keep error log lines bounded and to
/// prevent a verbose child from triggering OOM in the parent. 1 MiB
/// per stream is generous for `osascript` (typical output is < 10 KB).
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// Polling cadence for [`Child::try_wait`](std::process::Child::try_wait). Lower → tighter timeout
/// resolution + more wakeups; higher → coarser deadline rounding.
/// 50 ms is a good balance for desktop-automation latencies.
pub const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Output captured from a bounded subprocess invocation. Mirrors
/// `std::process::Output` but with truncated stdout/stderr per
/// [`MAX_OUTPUT_BYTES`].
#[derive(Debug)]
pub struct BoundedOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Error variants from the bounded subprocess runner. Translation
/// to connector-facing errors lives at the call-site (see
/// `map_subprocess_error` in `client.rs`).
#[derive(Debug)]
pub enum SubprocessError {
    /// `Command::spawn()` failed (binary missing, permission
    /// denied, etc).
    Spawn(String),
    /// Polling for completion or collecting drain-thread output
    /// failed.
    Wait(String),
    /// Wall-clock deadline elapsed before the child exited. The
    /// child has been sent SIGKILL (or platform equivalent) before
    /// this error returns.
    Timeout { timeout_secs: u64 },
}

/// Run `command` to completion under a wall-clock `timeout`.
///
/// Closes stdin (the script cannot read input), pipes and bounds
/// stdout/stderr to [`MAX_OUTPUT_BYTES`], polls for completion at
/// [`POLL_INTERVAL`] until either the child exits or the deadline
/// fires.
///
/// On deadline expiry, the child is killed (best-effort
/// [`Child::kill`](std::process::Child::kill) + [`Child::wait`](std::process::Child::wait)) and
/// [`SubprocessError::Timeout`] returns. The drain threads are
/// joined unconditionally so no resources leak across timeouts.
///
/// # Errors
///
/// Returns [`SubprocessError::Spawn`] if [`Command::spawn`] fails,
/// [`SubprocessError::Timeout`] if the deadline expires,
/// [`SubprocessError::Wait`] if polling itself errors.
pub fn run_with_timeout(
    mut command: Command,
    timeout: Duration,
) -> Result<BoundedOutput, SubprocessError> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| SubprocessError::Spawn(e.to_string()))?;

    // Take ownership of the pipes BEFORE the polling loop so the
    // drain threads can run concurrently with the wait loop. If we
    // left them attached to `child` and called `try_wait` repeatedly
    // without draining, a verbose child could fill the pipe buffers
    // and block forever on its own writes.
    let stdout_pipe = child
        .stdout
        .take()
        .ok_or_else(|| SubprocessError::Spawn("stdout pipe missing after spawn".into()))?;
    let stderr_pipe = child
        .stderr
        .take()
        .ok_or_else(|| SubprocessError::Spawn("stderr pipe missing after spawn".into()))?;

    let stdout_thread = thread::spawn(move || drain_to_cap(stdout_pipe));
    let stderr_thread = thread::spawn(move || drain_to_cap(stderr_pipe));

    let timeout_secs = timeout.as_secs();
    let deadline = Instant::now() + timeout;

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = stdout_thread.join().unwrap_or_default();
                let stderr = stderr_thread.join().unwrap_or_default();
                return Ok(BoundedOutput {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    // Best-effort kill + reap. Errors here are not
                    // surfaced — the timeout is the primary failure
                    // signal; child cleanup is housekeeping.
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_thread.join();
                    let _ = stderr_thread.join();
                    return Err(SubprocessError::Timeout { timeout_secs });
                }
                thread::sleep(POLL_INTERVAL);
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_thread.join();
                let _ = stderr_thread.join();
                return Err(SubprocessError::Wait(e.to_string()));
            }
        }
    }
}

/// Read up to [`MAX_OUTPUT_BYTES`] from `pipe`, returning the bytes
/// captured. Excess bytes are discarded silently — the upstream
/// connector error logging documents that stderr is bounded.
fn drain_to_cap<R: Read>(mut pipe: R) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4096);
    let _ = (&mut pipe)
        .take(MAX_OUTPUT_BYTES as u64)
        .read_to_end(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// Helper: command that sleeps for `secs` seconds. Direct sleep
    /// invocation (NOT `sh -c "sleep ..."`) so killing the child
    /// kills the actual sleep process — under a shell wrapper the
    /// orphaned sleep keeps holding the inherited pipes after the
    /// shell exits, which would block our drain threads. Production
    /// `osascript` is invoked directly so this fidelity matters.
    fn sleep_command(secs: u64) -> Command {
        let mut cmd = Command::new("/bin/sleep");
        cmd.arg(format!("{secs}"));
        cmd
    }

    /// Helper: command that exits 0 immediately with stdout output.
    fn echo_command(text: &str) -> Command {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(format!("echo {text}"));
        cmd
    }

    /// Helper: command that exits 1 with stderr output.
    fn fail_command(stderr_msg: &str) -> Command {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(format!("echo {stderr_msg} >&2; exit 1"));
        cmd
    }

    #[test]
    fn fast_command_completes_within_timeout() {
        let out = run_with_timeout(echo_command("hello"), Duration::from_secs(5))
            .expect("echo completes");
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello");
    }

    #[test]
    fn slow_command_kills_on_timeout_expiry() {
        // Sleep 30s but timeout in 1s — must return Timeout, not
        // hang waiting for the sleep to finish.
        let started = Instant::now();
        let err =
            run_with_timeout(sleep_command(30), Duration::from_secs(1)).expect_err("must time out");
        let elapsed = started.elapsed();
        assert!(matches!(err, SubprocessError::Timeout { timeout_secs: 1 }));
        // Elapsed must be close to the timeout (within 2s slop for
        // poll cadence + kill overhead) — the SIGKILL path must NOT
        // wait the full 30s.
        assert!(
            elapsed < Duration::from_secs(3),
            "kill-on-expiry took {elapsed:?}, must be near 1s"
        );
    }

    #[test]
    fn nonzero_exit_status_returns_status_with_stderr() {
        let out =
            run_with_timeout(fail_command("oops"), Duration::from_secs(5)).expect("command runs");
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("oops"));
    }

    #[test]
    fn missing_binary_returns_spawn_error() {
        let mut cmd = Command::new("/no/such/binary/xyzzy");
        cmd.arg("ignored");
        let err = run_with_timeout(cmd, Duration::from_secs(1)).expect_err("must fail spawn");
        assert!(matches!(err, SubprocessError::Spawn(_)));
    }

    #[test]
    fn stdout_is_truncated_at_cap() {
        // Generate output well over 1 MiB and confirm it gets capped.
        // Using yes is too slow / unbounded for tests; use a
        // tightly-bounded printf instead.
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(format!(
            "printf '%.0sa' $(seq 1 {})",
            MAX_OUTPUT_BYTES + 1024
        ));
        let out = run_with_timeout(cmd, Duration::from_secs(10)).expect("printf completes");
        assert!(
            out.stdout.len() <= MAX_OUTPUT_BYTES,
            "stdout grew to {} bytes, exceeding cap {MAX_OUTPUT_BYTES}",
            out.stdout.len()
        );
    }

    #[test]
    fn stderr_is_truncated_at_cap() {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg(format!(
            "printf '%.0se' $(seq 1 {}) >&2",
            MAX_OUTPUT_BYTES + 1024
        ));
        let out = run_with_timeout(cmd, Duration::from_secs(10)).expect("printf completes");
        assert!(
            out.stderr.len() <= MAX_OUTPUT_BYTES,
            "stderr grew to {} bytes, exceeding cap {MAX_OUTPUT_BYTES}",
            out.stderr.len()
        );
    }

    #[test]
    fn stdin_closed_command_does_not_hang_waiting_for_input() {
        // `cat` with no args reads stdin. If our runner doesn't close
        // stdin, this hangs until the timeout. With Stdio::null the
        // child sees immediate EOF and exits cleanly.
        let started = Instant::now();
        let out = run_with_timeout(Command::new("cat"), Duration::from_secs(5))
            .expect("cat with closed stdin exits");
        assert!(out.status.success());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "cat hung waiting for stdin"
        );
    }

    #[test]
    fn timeout_zero_seconds_treated_as_immediate_deadline() {
        // Edge case: zero-second timeout. The runner spawns then
        // checks the deadline — the child may or may not have
        // finished depending on race. We accept either Timeout OR
        // success for trivially-fast commands.
        let result = run_with_timeout(echo_command("x"), Duration::from_secs(0));
        let accepted_zero_timeout_outcome = match result {
            Ok(out) => out.status.success(),
            Err(SubprocessError::Timeout { timeout_secs }) => timeout_secs == 0,
            Err(_) => false,
        };
        assert!(accepted_zero_timeout_outcome);
    }

    #[test]
    fn drain_to_cap_caps_at_max_bytes_exactly() {
        let big = vec![b'x'; MAX_OUTPUT_BYTES + 4096];
        let captured = drain_to_cap(big.as_slice());
        assert_eq!(captured.len(), MAX_OUTPUT_BYTES);
    }

    #[test]
    fn drain_to_cap_returns_short_input_unchanged() {
        let small = b"hello world";
        let captured = drain_to_cap(small.as_slice());
        assert_eq!(captured.as_slice(), small);
    }
}
