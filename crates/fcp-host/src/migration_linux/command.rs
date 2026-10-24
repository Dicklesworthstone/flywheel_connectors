//! Bounded synchronous CRIU execution, without pipe-EOF or reader-thread waits.
//!
//! The CRIU child is owned until observed exit or attempted termination. This
//! module never terminates a restored PID or retries a restore. An interrupted
//! CRIU invocation may already have created a process tree; its outcome remains
//! unknown even when the CRIU child itself has been reaped.

use std::ffi::OsString;
use std::io;
use std::path::Path;
use std::process::Output;
use std::time::Duration;

/// Independent CRIU subprocess limits, applied to both dump and restore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CriuCommandLimits {
    /// Time budget for setup, the CRIU command and diagnostic capture.
    /// Kernel spawn/kill/wait calls are not preemptible by this synchronous API.
    pub timeout: Duration,
    /// Combined retained stdout and stderr bytes; exceeding this is an error,
    /// not a successful response with silently truncated diagnostics.
    pub max_output_bytes: usize,
}

impl Default for CriuCommandLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(60),
            max_output_bytes: 1024 * 1024,
        }
    }
}

impl CriuCommandLimits {
    pub(super) fn validate(self) -> Result<(), CriuCommandError> {
        if self.timeout.is_zero() || self.max_output_bytes == 0 {
            return Err(CriuCommandError::InvalidLimits);
        }
        Ok(())
    }
}

/// Reason an admitted CRIU command was interrupted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CriuCommandStopReason {
    /// The single command budget expired, including while consuming output.
    Timeout,
    /// The combined stdout/stderr byte budget was exceeded.
    OutputLimit,
    /// Captured diagnostics could not be read or retained.
    CaptureIo,
    /// The CRIU child's exit state could not be observed.
    WaitFailed,
}

/// Errors from the subprocess boundary, distinct from a nonzero CRIU exit.
#[derive(Debug, thiserror::Error)]
pub enum CriuCommandError {
    /// No process was started because a resource limit was zero.
    #[error("CRIU command timeout and output limit must be positive")]
    InvalidLimits,
    /// No process was started because preparation exhausted the budget.
    #[error("CRIU command deadline expired before process launch")]
    DeadlineBeforeSpawn,
    /// This capture implementation requires Unix file descriptors.
    #[error("bounded CRIU command execution requires Unix")]
    UnsupportedPlatform,
    /// Preparing the capture channels or spawning CRIU failed.
    #[error("CRIU command setup failed while {stage}: {source}")]
    Setup {
        /// Fixed operation label, not subprocess output.
        stage: &'static str,
        /// Underlying operating-system error.
        #[source]
        source: io::Error,
    },
    /// An admitted command did not produce an acceptable completion.
    #[error("CRIU command interrupted ({reason:?}); CRIU child {criu_pid} reaped: {child_reaped}; restored state is unknown; reconcile before retrying")]
    Interrupted {
        /// Why execution stopped.
        reason: CriuCommandStopReason,
        /// The owned CRIU subprocess, never an inferred restored-process PID.
        criu_pid: u32,
        /// True only after wait/try_wait observed this exact child's exit.
        /// It says nothing about restored descendants or their side effects.
        child_reaped: bool,
    },
}

#[cfg(unix)]
pub(super) fn run(
    binary: &Path,
    args: &[OsString],
    limits: CriuCommandLimits,
) -> Result<Output, CriuCommandError> {
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let started = Instant::now();
    limits.validate()?;
    let setup = |stage| move |source| CriuCommandError::Setup { stage, source };
    let (mut stdout, child_stdout) = UnixStream::pair().map_err(setup("creating stdout channel"))?;
    let (mut stderr, child_stderr) = UnixStream::pair().map_err(setup("creating stderr channel"))?;
    stdout.set_nonblocking(true).map_err(setup("configuring stdout channel"))?;
    stderr.set_nonblocking(true).map_err(setup("configuring stderr channel"))?;
    let mut command = Command::new(binary);
    command.args(args).stdin(Stdio::null())
        .stdout(Stdio::from(OwnedFd::from(child_stdout)))
        .stderr(Stdio::from(OwnedFd::from(child_stderr)));
    if started.elapsed() >= limits.timeout {
        return Err(CriuCommandError::DeadlineBeforeSpawn);
    }
    let child = command.spawn().map_err(setup("spawning CRIU"))?;
    let mut owned = OwnedChild { child, reaped: false };
    // Command keeps its configured descriptor owners after spawn. Release
    // them now; otherwise even a normal child's capture channel stays open.
    drop(command);
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut remaining = limits.max_output_bytes;
    let mut status = None;
    loop {
        if started.elapsed() >= limits.timeout {
            return Err(owned.interrupt(CriuCommandStopReason::Timeout));
        }
        if status.is_none() {
            status = match owned.child.try_wait() {
                Ok(status) => status,
                Err(_) => return Err(owned.interrupt(CriuCommandStopReason::WaitFailed)),
            };
            owned.reaped = status.is_some();
        }
        // One bounded read from each stream per turn prevents a continuously
        // writing stdout from starving stderr, exit observation or the deadline.
        let progress = match (
            read_once(&mut stdout, &mut out, &mut remaining),
            read_once(&mut stderr, &mut err, &mut remaining),
        ) {
            (Ok(out), Ok(err)) => out || err,
            (Err(reason), _) | (_, Err(reason)) => return Err(owned.interrupt(reason)),
        };
        if started.elapsed() >= limits.timeout {
            return Err(owned.interrupt(CriuCommandStopReason::Timeout));
        }
        if let Some(status) = status {
            if !progress {
                // Drain bytes available after the observed CRIU exit, but do
                // not await EOF from a descendant retaining a diagnostic FD.
                // This boundary captures CRIU diagnostics, not connector stdio.
                return Ok(Output { status, stdout: out, stderr: err });
            }
        } else if !progress {
            std::thread::sleep(
                Duration::from_millis(5).min(limits.timeout.saturating_sub(started.elapsed())),
            );
        }
    }
}

#[cfg(not(unix))]
pub(super) fn run(
    _binary: &Path,
    _args: &[OsString],
    limits: CriuCommandLimits,
) -> Result<Output, CriuCommandError> {
    limits.validate()?;
    Err(CriuCommandError::UnsupportedPlatform)
}

#[cfg(unix)]
fn read_once(
    stream: &mut std::os::unix::net::UnixStream,
    output: &mut Vec<u8>,
    remaining: &mut usize,
) -> Result<bool, CriuCommandStopReason> {
    use std::io::Read;
    let mut buffer = [0_u8; 8192];
    match stream.read(&mut buffer) {
        Ok(0) => Ok(false),
        Ok(count) => {
            if count > *remaining {
                return Err(CriuCommandStopReason::OutputLimit);
            }
            output.try_reserve_exact(count).map_err(|_| CriuCommandStopReason::CaptureIo)?;
            output.extend_from_slice(&buffer[..count]);
            *remaining -= count;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(true),
        Err(_) => Err(CriuCommandStopReason::CaptureIo),
    }
}

#[cfg(unix)]
struct OwnedChild {
    child: std::process::Child,
    reaped: bool,
}

#[cfg(unix)]
impl OwnedChild {
    fn retire(&mut self) -> bool {
        if self.reaped {
            return true;
        }
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            self.reaped = true;
            return true;
        }
        // Never signal a parsed PID, a process group or a restored child. A
        // successful kill still needs wait; a failed kill is not an exit proof.
        if self.child.kill().is_ok() {
            self.reaped = self.child.wait().is_ok();
        } else {
            self.reaped = matches!(self.child.try_wait(), Ok(Some(_)));
        }
        self.reaped
    }

    fn interrupt(mut self, reason: CriuCommandStopReason) -> CriuCommandError {
        let criu_pid = self.child.id();
        let child_reaped = self.retire();
        CriuCommandError::Interrupted { reason, criu_pid, child_reaped }
    }
}

#[cfg(unix)]
impl Drop for OwnedChild {
    fn drop(&mut self) {
        // Also retain termination responsibility across unexpected unwinding.
        // Reaped children are never signalled again (their PID can be reused).
        self.retire();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::Instant;

    fn shell(script: &str, limits: CriuCommandLimits) -> Result<Output, CriuCommandError> {
        run(Path::new("/bin/sh"), &[OsString::from("-c"), OsString::from(script)], limits)
    }

    fn limits(bytes: usize) -> CriuCommandLimits {
        CriuCommandLimits { timeout: Duration::from_secs(2), max_output_bytes: bytes }
    }

    #[test]
    fn capture_preserves_both_streams_and_nonzero_exit() {
        let output = shell("printf 'stdout'; printf 'stderr' >&2; exit 17", limits(12)).unwrap();
        assert_eq!(output.stdout, b"stdout");
        assert_eq!(output.stderr, b"stderr");
        assert_eq!(output.status.code(), Some(17));
    }

    #[test]
    fn combined_output_limit_is_exact_and_never_silently_truncates() {
        let output = shell("printf '123'; printf '456' >&2", limits(6)).unwrap();
        assert_eq!(output.stdout.len() + output.stderr.len(), 6);
        assert!(matches!(
            shell("printf '123'; printf '456' >&2", limits(5)),
            Err(CriuCommandError::Interrupted { reason: CriuCommandStopReason::OutputLimit, child_reaped: true, .. })
        ));
    }

    #[test]
    fn command_deadline_kills_and_reaps_the_owned_child() {
        let started = Instant::now();
        let error = shell("exec sleep 30", CriuCommandLimits {
            timeout: Duration::from_millis(100), max_output_bytes: 1024,
        }).unwrap_err();
        assert!(matches!(error, CriuCommandError::Interrupted {
            reason: CriuCommandStopReason::Timeout, child_reaped: true, ..
        }));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(error.to_string().contains("reconcile before retrying"));
    }

    #[test]
    fn continuously_writing_child_cannot_hide_exit_or_exhaust_memory() {
        let error = shell("while :; do printf '0123456789'; done", limits(1024)).unwrap_err();
        assert!(matches!(error, CriuCommandError::Interrupted {
            reason: CriuCommandStopReason::OutputLimit, child_reaped: true, ..
        }));
    }

    #[test]
    fn capture_does_not_wait_for_eof_from_an_inheriting_descendant() {
        let started = Instant::now();
        let output = shell("sleep 2 & printf 'complete'; exit 0", limits(1024)).unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"complete");
        assert!(started.elapsed() < Duration::from_secs(1));
        // The bounded fixture descendant exits naturally. It is not a target
        // for the command owner's termination authority.
    }

    #[test]
    fn closed_diagnostic_streams_do_not_mean_the_process_has_exited() {
        let error = shell("exec 1>&- 2>&-; exec sleep 30", CriuCommandLimits {
            timeout: Duration::from_millis(100), max_output_bytes: 1024,
        }).unwrap_err();
        assert!(matches!(error, CriuCommandError::Interrupted {
            reason: CriuCommandStopReason::Timeout, child_reaped: true, ..
        }));
    }

    #[test]
    fn invalid_limits_are_refused_before_process_launch() {
        for invalid in [
            CriuCommandLimits { timeout: Duration::ZERO, max_output_bytes: 10 },
            CriuCommandLimits { timeout: Duration::from_secs(1), max_output_bytes: 0 },
        ] {
            assert!(matches!(run(Path::new("/does-not-exist"), &[], invalid),
                Err(CriuCommandError::InvalidLimits)));
        }
    }

    #[test]
    fn overflowing_instant_budget_does_not_panic_or_shorten_the_deadline() {
        let output = shell("printf 'ok'", CriuCommandLimits {
            timeout: Duration::MAX, max_output_bytes: 2,
        }).unwrap();
        assert_eq!(output.stdout, b"ok");
    }

    #[test]
    fn single_stream_capture_refuses_bytes_before_extending_the_buffer() {
        use std::io::Write;
        let (mut parent, mut child) = std::os::unix::net::UnixStream::pair().unwrap();
        parent.set_nonblocking(true).unwrap();
        child.write_all(b"1234").unwrap();
        let mut output = Vec::new();
        let mut remaining = 3;
        assert_eq!(read_once(&mut parent, &mut output, &mut remaining),
            Err(CriuCommandStopReason::OutputLimit));
        assert!(output.is_empty());
        assert_eq!(remaining, 3);
    }
}
