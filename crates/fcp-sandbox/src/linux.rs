//! Linux sandbox implementation using seccomp-bpf and namespaces.
//!
//! # Enforcement Layers
//!
//! 1. **seccomp-bpf**: Syscall filtering to block dangerous operations
//! 2. **User namespaces**: UID/GID remapping for privilege separation
//! 3. **Mount namespaces**: `CLONE_NEWNS` isolation. NOTE: the current
//!    implementation unshares the mount namespace but does NOT install bind
//!    mounts or `pivot_root`, so it does not by itself confine filesystem
//!    *paths*. Path confinement is delivered by Landlock (layer 5); when a
//!    connector declares `fs_readonly_paths`/`fs_writable_paths` but Landlock
//!    will not run, the sandbox fails closed rather than running unconfined.
//! 4. **Network namespaces**: Network isolation (all traffic via Network Guard)
//! 5. **Landlock** (optional, Linux 5.13+): Path-based access control — the
//!    only wired path-confinement mechanism.
//! 6. **rlimit**: Resource limits for memory, CPU time, file descriptors
//!
//! # Profile Mapping
//!
//! | Profile      | seccomp | namespaces | Landlock | network ns |
//! |--------------|---------|------------|----------|------------|
//! | strict       | yes     | full       | if avail | isolated   |
//! | strict_plus  | yes     | full       | required | microVM    |
//! | moderate     | yes     | partial    | if avail | isolated   |
//! | permissive   | minimal | none       | no       | shared     |
//!
//! When a policy declares filesystem path restrictions, path confinement
//! requires Landlock to be both available and requested
//! (`linux_use_landlock`); otherwise [`LinuxSandbox::apply`] and
//! [`LinuxSandbox::apply_to_command`] fail closed. High-risk connectors that
//! need guaranteed path confinement should run under the WASI runtime.

#![cfg(target_os = "linux")]
// Allow patterns common in low-level syscall/FFI code
#![allow(clippy::unused_self)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::wildcard_imports)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::ref_as_ptr)]

use std::path::Path;

use tracing::{debug, info, warn};

use crate::sandbox::{CompiledPolicy, Sandbox, SandboxError};

// ============================================================================
// Constants
// ============================================================================

/// Seccomp filter action: allow syscall.
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

/// Seccomp filter action: kill process.
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

/// Seccomp filter action: return errno.
#[allow(dead_code)]
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

// Syscall numbers (x86_64)
#[cfg(target_arch = "x86_64")]
#[allow(dead_code)]
mod syscall_nr {
    pub const READ: u32 = 0;
    pub const WRITE: u32 = 1;
    pub const OPEN: u32 = 2;
    pub const CLOSE: u32 = 3;
    pub const STAT: u32 = 4;
    pub const FSTAT: u32 = 5;
    pub const LSTAT: u32 = 6;
    pub const POLL: u32 = 7;
    pub const LSEEK: u32 = 8;
    pub const MMAP: u32 = 9;
    pub const MPROTECT: u32 = 10;
    pub const MUNMAP: u32 = 11;
    pub const BRK: u32 = 12;
    pub const RT_SIGACTION: u32 = 13;
    pub const RT_SIGPROCMASK: u32 = 14;
    pub const RT_SIGRETURN: u32 = 15;
    pub const IOCTL: u32 = 16;
    pub const PREAD64: u32 = 17;
    pub const PWRITE64: u32 = 18;
    pub const READV: u32 = 19;
    pub const WRITEV: u32 = 20;
    pub const ACCESS: u32 = 21;
    pub const PIPE: u32 = 22;
    pub const SELECT: u32 = 23;
    pub const SCHED_YIELD: u32 = 24;
    pub const MREMAP: u32 = 25;
    pub const DUP: u32 = 32;
    pub const DUP2: u32 = 33;
    pub const NANOSLEEP: u32 = 35;
    pub const GETPID: u32 = 39;
    pub const SOCKET: u32 = 41;
    pub const CONNECT: u32 = 42;
    pub const SENDTO: u32 = 44;
    pub const RECVFROM: u32 = 45;
    pub const SENDMSG: u32 = 46;
    pub const RECVMSG: u32 = 47;
    pub const SHUTDOWN: u32 = 48;
    pub const BIND: u32 = 49;
    pub const LISTEN: u32 = 50;
    pub const GETSOCKNAME: u32 = 51;
    pub const GETPEERNAME: u32 = 52;
    pub const SETSOCKOPT: u32 = 54;
    pub const GETSOCKOPT: u32 = 55;
    pub const CLONE: u32 = 56;
    pub const FORK: u32 = 57;
    pub const VFORK: u32 = 58;
    pub const EXECVE: u32 = 59;
    pub const EXECVEAT: u32 = 322;
    pub const EXIT: u32 = 60;
    pub const WAIT4: u32 = 61;
    pub const KILL: u32 = 62;
    pub const FCNTL: u32 = 72;
    pub const FLOCK: u32 = 73;
    pub const FSYNC: u32 = 74;
    pub const FDATASYNC: u32 = 75;
    pub const TRUNCATE: u32 = 76;
    pub const FTRUNCATE: u32 = 77;
    pub const GETDENTS: u32 = 78;
    pub const GETCWD: u32 = 79;
    pub const CHDIR: u32 = 80;
    pub const FCHDIR: u32 = 81;
    pub const RENAME: u32 = 82;
    pub const MKDIR: u32 = 83;
    pub const RMDIR: u32 = 84;
    pub const CREAT: u32 = 85;
    pub const LINK: u32 = 86;
    pub const UNLINK: u32 = 87;
    pub const SYMLINK: u32 = 88;
    pub const READLINK: u32 = 89;
    pub const CHMOD: u32 = 90;
    pub const FCHMOD: u32 = 91;
    pub const CHOWN: u32 = 92;
    pub const FCHOWN: u32 = 93;
    pub const LCHOWN: u32 = 94;
    pub const UMASK: u32 = 95;
    pub const GETTIMEOFDAY: u32 = 96;
    pub const GETRLIMIT: u32 = 97;
    pub const SYSINFO: u32 = 99;
    pub const TIMES: u32 = 100;
    pub const PTRACE: u32 = 101;
    pub const GETUID: u32 = 102;
    pub const GETGID: u32 = 104;
    pub const GETEUID: u32 = 107;
    pub const GETEGID: u32 = 108;
    pub const SETPGID: u32 = 109;
    pub const GETPPID: u32 = 110;
    pub const GETPGRP: u32 = 111;
    pub const SETSID: u32 = 112;
    pub const SETREUID: u32 = 113;
    pub const SETREGID: u32 = 114;
    pub const GETGROUPS: u32 = 115;
    pub const SETRESUID: u32 = 117;
    pub const GETRESUID: u32 = 118;
    pub const SETRESGID: u32 = 119;
    pub const GETRESGID: u32 = 120;
    pub const GETPGID: u32 = 121;
    pub const GETSID: u32 = 124;
    pub const UNAME: u32 = 63;
    pub const PRCTL: u32 = 157;
    pub const ARCH_PRCTL: u32 = 158;
    pub const FUTEX: u32 = 202;
    pub const EPOLL_CREATE: u32 = 213;
    pub const GETDENTS64: u32 = 217;
    pub const SET_TID_ADDRESS: u32 = 218;
    pub const CLOCK_GETTIME: u32 = 228;
    pub const CLOCK_GETRES: u32 = 229;
    pub const CLOCK_NANOSLEEP: u32 = 230;
    pub const EXIT_GROUP: u32 = 231;
    pub const EPOLL_WAIT: u32 = 232;
    pub const EPOLL_CTL: u32 = 233;
    pub const TGKILL: u32 = 234;
    pub const OPENAT: u32 = 257;
    pub const MKDIRAT: u32 = 258;
    pub const NEWFSTATAT: u32 = 262;
    pub const UNLINKAT: u32 = 263;
    pub const RENAMEAT: u32 = 264;
    pub const READLINKAT: u32 = 267;
    pub const FCHMODAT: u32 = 268;
    pub const FACCESSAT: u32 = 269;
    pub const PPOLL: u32 = 271;
    pub const SET_ROBUST_LIST: u32 = 273;
    pub const ACCEPT4: u32 = 288;
    pub const EPOLL_CREATE1: u32 = 291;
    pub const DUP3: u32 = 292;
    pub const PIPE2: u32 = 293;
    pub const PRLIMIT64: u32 = 302;
    pub const GETRANDOM: u32 = 318;
    pub const STATX: u32 = 332;
    pub const RSEQ: u32 = 334;
    pub const CLONE3: u32 = 435;
    pub const CLOSE_RANGE: u32 = 436;
    pub const OPENAT2: u32 = 437;
    pub const FACCESSAT2: u32 = 439;
}

#[cfg(target_arch = "aarch64")]
mod syscall_nr {
    // ARM64 syscall numbers - subset for basic functionality
    pub const READ: u32 = 63;
    pub const WRITE: u32 = 64;
    pub const OPENAT: u32 = 56;
    pub const CLOSE: u32 = 57;
    pub const FSTAT: u32 = 80;
    pub const LSEEK: u32 = 62;
    pub const EXIT: u32 = 93;
    pub const EXIT_GROUP: u32 = 94;
    pub const CLONE: u32 = 220;
    pub const CLONE3: u32 = 435;
    pub const WAIT4: u32 = 260;
    pub const EXECVE: u32 = 221;
    pub const EXECVEAT: u32 = 281;
    pub const MMAP: u32 = 222;
    pub const MPROTECT: u32 = 226;
    pub const MUNMAP: u32 = 215;
    pub const MREMAP: u32 = 216;
    pub const BRK: u32 = 214;
    pub const SOCKET: u32 = 198;
    pub const CONNECT: u32 = 203;
    pub const ACCEPT4: u32 = 242;
    pub const BIND: u32 = 200;
    pub const LISTEN: u32 = 201;
    pub const SENDTO: u32 = 206;
    pub const RECVFROM: u32 = 207;
    pub const SENDMSG: u32 = 211;
    pub const RECVMSG: u32 = 212;
    pub const SHUTDOWN: u32 = 210;
    pub const GETSOCKNAME: u32 = 204;
    pub const GETPEERNAME: u32 = 205;
    pub const SETSOCKOPT: u32 = 208;
    pub const GETSOCKOPT: u32 = 209;
    pub const PTRACE: u32 = 117;
    pub const FORK: u32 = 1079; // Not available on aarch64, use clone
    pub const VFORK: u32 = 1071; // Not available on aarch64
    pub const CLOCK_GETTIME: u32 = 113;
    pub const CLOCK_GETRES: u32 = 114;
    pub const GETTIMEOFDAY: u32 = 169;
    pub const NANOSLEEP: u32 = 101;
    pub const CLOCK_NANOSLEEP: u32 = 115;
    pub const GETRANDOM: u32 = 278;
    pub const FUTEX: u32 = 98;
    pub const EPOLL_CREATE1: u32 = 20;
    pub const EPOLL_CTL: u32 = 21;
    pub const EPOLL_PWAIT: u32 = 22;
    pub const SCHED_YIELD: u32 = 124;
    pub const TGKILL: u32 = 131;
    pub const SET_TID_ADDRESS: u32 = 96;
    pub const SET_ROBUST_LIST: u32 = 99;
    pub const RSEQ: u32 = 293;
    pub const GETPID: u32 = 172;
    pub const GETPPID: u32 = 173;
    pub const GETUID: u32 = 174;
    pub const GETEUID: u32 = 175;
    pub const GETGID: u32 = 176;
    pub const GETEGID: u32 = 177;
    pub const GETGROUPS: u32 = 158;
    pub const GETRESUID: u32 = 149;
    pub const GETRESGID: u32 = 151;
    pub const GETPGRP: u32 = 155;
    pub const GETPGID: u32 = 154;
    pub const GETSID: u32 = 156;
    pub const UNAME: u32 = 160;
    pub const SYSINFO: u32 = 179;
    pub const TIMES: u32 = 153;
    pub const GETRLIMIT: u32 = 163;
    pub const PRLIMIT64: u32 = 261;
    pub const IOCTL: u32 = 29;
    pub const PRCTL: u32 = 167;
    pub const DUP: u32 = 23;
    pub const DUP3: u32 = 24;
    pub const PIPE2: u32 = 59;
    pub const FCNTL: u32 = 25;
    pub const FLOCK: u32 = 32;
    pub const FSYNC: u32 = 82;
    pub const FDATASYNC: u32 = 83;
    pub const TRUNCATE: u32 = 45;
    pub const FTRUNCATE: u32 = 46;
    pub const GETDENTS64: u32 = 61;
    pub const GETCWD: u32 = 17;
    pub const CHDIR: u32 = 49;
    pub const FCHDIR: u32 = 50;
    pub const RENAMEAT: u32 = 38;
    pub const MKDIRAT: u32 = 34;
    pub const UNLINKAT: u32 = 35;
    pub const SYMLINKAT: u32 = 36;
    pub const READLINKAT: u32 = 78;
    pub const FCHMOD: u32 = 52;
    pub const FCHMODAT: u32 = 53;
    pub const FCHOWN: u32 = 55;
    pub const FCHOWNAT: u32 = 54;
    pub const UMASK: u32 = 166;
    pub const PREAD64: u32 = 67;
    pub const PWRITE64: u32 = 68;
    pub const READV: u32 = 65;
    pub const WRITEV: u32 = 66;
    pub const PPOLL: u32 = 73;
    pub const STATX: u32 = 291;
    pub const OPENAT2: u32 = 437;
    pub const FACCESSAT: u32 = 48;
    pub const FACCESSAT2: u32 = 439;
}

// ============================================================================
// Linux Sandbox
// ============================================================================

/// Linux sandbox using seccomp-bpf, namespaces, and optionally Landlock.
#[derive(Debug)]
pub struct LinuxSandbox {
    /// Whether Landlock is available.
    landlock_available: bool,
    /// Whether user namespaces are available.
    #[allow(dead_code)]
    userns_available: bool,
}

impl LinuxSandbox {
    /// Create a new Linux sandbox, detecting available features.
    #[must_use]
    pub fn new() -> Self {
        let landlock_available = check_landlock_available();
        let userns_available = check_userns_available();

        if landlock_available {
            info!("Landlock is available for path-based access control");
        } else {
            debug!("Landlock not available, using seccomp-only enforcement");
        }

        if userns_available {
            info!("User namespaces available for privilege separation");
        } else {
            warn!("User namespaces not available, some isolation features disabled");
        }

        Self {
            landlock_available,
            userns_available,
        }
    }

    /// Build a seccomp BPF filter for the given policy.
    fn build_seccomp_filter(&self, policy: &CompiledPolicy) -> Vec<SockFilter> {
        // Build allowlist based on policy
        let (allowed_syscalls, graceful_error_syscalls) = self.build_syscall_allowlist(policy);

        // Calculate exact capacity to prevent reallocation during BPF assembly.
        // 4 header instructions + (2 per allowed) + (2 per graceful) + 1 catch-all.
        let capacity = 4 + (allowed_syscalls.len() * 2) + (graceful_error_syscalls.len() * 2) + 1;
        let mut filter = Vec::with_capacity(capacity);

        // 1. Validate Architecture
        // Load architecture into accumulator
        // BPF_LD | BPF_W | BPF_ABS, offset 4 = arch
        filter.push(SockFilter::stmt(0x20, 4));

        #[cfg(target_arch = "x86_64")]
        let expected_arch = 0xC000_003E; // AUDIT_ARCH_X86_64
        #[cfg(target_arch = "aarch64")]
        let expected_arch = 0xC00000B7; // AUDIT_ARCH_AARCH64

        // JEQ expected_arch, 1, 0
        // If equal, jump 1 (skip KILL); if not equal, jump 0 (execute KILL)
        filter.push(SockFilter::jump(0x15, expected_arch, 1, 0));
        filter.push(SockFilter::stmt(0x06, SECCOMP_RET_KILL_PROCESS));

        // 2. Validate Syscall Number
        // Load syscall number into accumulator
        // BPF_LD | BPF_W | BPF_ABS, offset 0 = syscall number
        filter.push(SockFilter::stmt(0x20, 0));

        // Add jump table for allowed syscalls
        for &syscall in &allowed_syscalls {
            // JEQ syscall, 0, 1 -> if equal, skip next (which denies)
            filter.push(SockFilter::jump(0x15, syscall, 0, 1));
            // Allow this syscall
            filter.push(SockFilter::stmt(0x06, SECCOMP_RET_ALLOW));
        }

        // Add jump table for graceful errors (instead of killing)
        for &syscall in &graceful_error_syscalls {
            filter.push(SockFilter::jump(0x15, syscall, 0, 1));
            // Return EPERM (1)
            filter.push(SockFilter::stmt(0x06, SECCOMP_RET_ERRNO | 1));
        }

        // Default: kill process for unallowed syscalls
        filter.push(SockFilter::stmt(0x06, SECCOMP_RET_KILL_PROCESS));

        filter
    }

    /// Build the syscall allowlist based on policy.
    /// Returns (allowed_syscalls, graceful_error_syscalls).
    #[cfg(target_arch = "x86_64")]
    fn build_syscall_allowlist(&self, policy: &CompiledPolicy) -> (Vec<u32>, Vec<u32>) {
        use syscall_nr::*;

        let mut allowed = vec![
            // Essential syscalls
            READ,
            WRITE,
            CLOSE,
            FSTAT,
            LSEEK,
            MMAP,
            MPROTECT,
            MUNMAP,
            BRK,
            RT_SIGACTION,
            RT_SIGPROCMASK,
            RT_SIGRETURN,
            PREAD64,
            PWRITE64,
            READV,
            WRITEV,
            POLL,
            PPOLL,
            SELECT,
            NANOSLEEP,
            CLOCK_NANOSLEEP,
            // File operations (limited by Landlock if available)
            OPENAT,
            OPENAT2,
            STAT,
            LSTAT,
            NEWFSTATAT,
            STATX,
            ACCESS,
            FACCESSAT,
            FACCESSAT2,
            GETDENTS,
            GETDENTS64,
            GETCWD,
            READLINK,
            READLINKAT,
            // Memory management
            MREMAP,
            // File descriptors
            DUP,
            DUP2,
            DUP3,
            PIPE,
            PIPE2,
            FCNTL,
            // IOCTL is handled in graceful errors
            // Synchronization
            FUTEX,
            FLOCK,
            FSYNC,
            FDATASYNC,
            // Process info (read-only)
            GETPID,
            GETPPID,
            GETUID,
            GETEUID,
            GETGID,
            GETEGID,
            GETGROUPS,
            GETRESUID,
            GETRESGID,
            GETPGRP,
            GETPGID,
            GETSID,
            UNAME,
            SYSINFO,
            TIMES,
            // Time
            GETTIMEOFDAY,
            CLOCK_GETTIME,
            CLOCK_GETRES,
            // Random
            GETRANDOM,
            // Resource limits (read)
            GETRLIMIT,
            PRLIMIT64,
            // epoll
            EPOLL_CREATE,
            EPOLL_CREATE1,
            EPOLL_CTL,
            EPOLL_WAIT,
            // Signals
            TGKILL,
            // KILL is dropped to prevent sending signals outside the process
            // Thread support
            SET_TID_ADDRESS,
            SET_ROBUST_LIST,
            RSEQ,
            ARCH_PRCTL,
            // PRCTL is handled in graceful errors
            // Exit
            EXIT,
            EXIT_GROUP,
            // Sched
            SCHED_YIELD,
            // Process and Thread creation (Threads are required for Rust/Go async runtimes)
            CLONE,
            CLONE3,
            WAIT4,
        ];

        // File modification syscalls (if writable paths exist)
        if !policy.writable_paths.is_empty() {
            allowed.extend([
                TRUNCATE, FTRUNCATE, RENAME, RENAMEAT, MKDIR, MKDIRAT, RMDIR, UNLINK, UNLINKAT,
                LINK, SYMLINK, CREAT, CHMOD, FCHMOD, FCHMODAT, CHOWN, FCHOWN, LCHOWN, UMASK, CHDIR,
                FCHDIR,
            ]);
        }

        // Network syscalls (only if direct network is allowed)
        if !policy.block_direct_network {
            allowed.extend([
                SOCKET,
                CONNECT,
                ACCEPT4,
                BIND,
                LISTEN,
                SENDTO,
                RECVFROM,
                SENDMSG,
                RECVMSG,
                SHUTDOWN,
                GETSOCKNAME,
                GETPEERNAME,
                SETSOCKOPT,
                GETSOCKOPT,
            ]);
        }

        // Process creation syscalls (if exec is allowed)
        if !policy.deny_exec {
            allowed.extend([FORK, VFORK, EXECVE, EXECVEAT]);
        }

        // Ptrace (if allowed)
        if !policy.deny_ptrace {
            allowed.push(PTRACE);
        }

        let graceful = vec![IOCTL, PRCTL];

        (allowed, graceful)
    }

    #[cfg(target_arch = "aarch64")]
    fn build_syscall_allowlist(&self, policy: &CompiledPolicy) -> (Vec<u32>, Vec<u32>) {
        use syscall_nr::*;

        let mut allowed = vec![
            READ,
            WRITE,
            CLOSE,
            FSTAT,
            LSEEK,
            MMAP,
            MPROTECT,
            MUNMAP,
            MREMAP,
            BRK,
            PREAD64,
            PWRITE64,
            READV,
            WRITEV,
            PPOLL,
            NANOSLEEP,
            CLOCK_NANOSLEEP,
            OPENAT,
            OPENAT2,
            STATX,
            FACCESSAT,
            FACCESSAT2,
            GETDENTS64,
            GETCWD,
            READLINKAT,
            DUP,
            DUP3,
            PIPE2,
            FCNTL,
            FUTEX,
            FLOCK,
            FSYNC,
            FDATASYNC,
            GETPID,
            GETPPID,
            GETUID,
            GETEUID,
            GETGID,
            GETEGID,
            GETGROUPS,
            GETRESUID,
            GETRESGID,
            GETPGRP,
            GETPGID,
            GETSID,
            UNAME,
            SYSINFO,
            TIMES,
            GETTIMEOFDAY,
            CLOCK_GETTIME,
            CLOCK_GETRES,
            GETRANDOM,
            GETRLIMIT,
            PRLIMIT64,
            EPOLL_CREATE1,
            EPOLL_CTL,
            EPOLL_PWAIT,
            TGKILL,
            SET_TID_ADDRESS,
            SET_ROBUST_LIST,
            RSEQ,
            EXIT,
            EXIT_GROUP,
            SCHED_YIELD,
            CLONE,
            CLONE3,
            WAIT4,
        ];

        // File modification syscalls (if writable paths exist)
        if !policy.writable_paths.is_empty() {
            allowed.extend([
                TRUNCATE, FTRUNCATE, RENAMEAT, MKDIRAT, UNLINKAT, SYMLINKAT, FCHMOD, FCHMODAT,
                FCHOWN, FCHOWNAT, UMASK, CHDIR, FCHDIR,
            ]);
        }

        // Network syscalls (only if direct network is allowed)
        if !policy.block_direct_network {
            allowed.extend([
                SOCKET,
                CONNECT,
                ACCEPT4,
                BIND,
                LISTEN,
                SENDTO,
                RECVFROM,
                SENDMSG,
                RECVMSG,
                SHUTDOWN,
                GETSOCKNAME,
                GETPEERNAME,
                SETSOCKOPT,
                GETSOCKOPT,
            ]);
        }

        // Process creation syscalls (if exec is allowed)
        if !policy.deny_exec {
            allowed.extend([FORK, VFORK, EXECVE, EXECVEAT]);
        }

        // Ptrace (if allowed)
        if !policy.deny_ptrace {
            allowed.push(PTRACE);
        }

        let graceful = vec![IOCTL, PRCTL];

        (allowed, graceful)
    }

    /// Apply resource limits using rlimit.
    fn apply_rlimits(&self, policy: &CompiledPolicy) -> Result<(), SandboxError> {
        // Enforce both heap/data growth and total address-space growth. RLIMIT_DATA
        // alone does not cover mmap-backed allocations, so guests could otherwise
        // bypass the memory budget via repeated anonymous mappings.
        set_rlimit(
            libc::RLIMIT_DATA,
            policy.memory_limit_bytes,
            policy.memory_limit_bytes,
        )?;
        set_rlimit(
            libc::RLIMIT_AS,
            policy.memory_limit_bytes,
            policy.memory_limit_bytes,
        )?;

        // CPU time limit (soft = timeout, hard = timeout + 5s grace)
        let cpu_seconds = policy.wall_clock_timeout.as_secs();
        set_rlimit(libc::RLIMIT_CPU, cpu_seconds, cpu_seconds + 5)?;

        // File descriptor limit
        set_rlimit(libc::RLIMIT_NOFILE, 1024, 4096)?;

        // Core dump disabled
        set_rlimit(libc::RLIMIT_CORE, 0, 0)?;

        // No new processes if deny_exec
        if policy.deny_exec {
            // Note: RLIMIT_NPROC limits BOTH threads and processes on Linux (NPTL).
            // Setting this to 0 prevents multi-threaded connectors (like those using Tokio)
            // from spawning worker threads. We rely on the seccomp filter blocking EXECVE/FORK instead.
            // set_rlimit(libc::RLIMIT_NPROC, 0, 0)?;
        }

        info!(
            memory_mb = policy.memory_limit_bytes / (1024 * 1024),
            cpu_seconds = cpu_seconds,
            "Applied resource limits"
        );

        Ok(())
    }

    /// Apply seccomp filter.
    fn apply_seccomp(&self, policy: &CompiledPolicy) -> Result<(), SandboxError> {
        let filter = self.build_seccomp_filter(policy);

        let filter_len = u16::try_from(filter.len())
            .map_err(|_| SandboxError::SyscallFailed("seccomp filter too large".into()))?;
        // Convert to sock_fprog
        let prog = SockFprog {
            len: filter_len,
            filter: filter.as_ptr(),
        };

        // Set no new privileges (required for seccomp without CAP_SYS_ADMIN)
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(SandboxError::SyscallFailed(
                    "prctl(PR_SET_NO_NEW_PRIVS) failed".into(),
                ));
            }
        }

        // Apply seccomp filter
        unsafe {
            if libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &prog as *const _,
                0,
                0,
            ) != 0
            {
                return Err(SandboxError::SyscallFailed(format!(
                    "seccomp(SECCOMP_MODE_FILTER) failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }

        info!(syscall_count = filter.len(), "Applied seccomp-bpf filter");

        Ok(())
    }
}

impl Default for LinuxSandbox {
    fn default() -> Self {
        Self::new()
    }
}

impl Sandbox for LinuxSandbox {
    fn apply(&self, policy: &CompiledPolicy) -> Result<(), SandboxError> {
        info!(
            profile = ?policy.profile,
            memory_mb = policy.memory_limit_bytes / (1024 * 1024),
            cpu_percent = policy.cpu_percent,
            deny_exec = policy.deny_exec,
            deny_ptrace = policy.deny_ptrace,
            block_network = policy.block_direct_network,
            "Applying Linux sandbox"
        );

        // Step 1: Apply resource limits
        self.apply_rlimits(policy)?;

        // Step 2: Apply Landlock, or fail closed if the policy declared
        // filesystem restrictions we cannot actually enforce.
        //
        // Landlock is the only wired path-confinement mechanism on Linux:
        // the mount namespace established via `apply_to_command` unshares
        // CLONE_NEWNS but installs no bind mounts / pivot_root, and seccomp
        // cannot filter `openat` by path. So if the connector declared
        // `fs_readonly_paths` / `fs_writable_paths` but Landlock will not run
        // (kernel < 5.13, or `linux_use_landlock` not requested), the
        // declared confinement would be silently ignored — the connector
        // could open arbitrary paths. Refuse rather than run unconfined
        // (bead sandbox-linux-no-default-fs-confinement). High-risk
        // connectors should run under the WASI runtime, whose FsCapabilityGate
        // enforces path confinement independently of Landlock availability.
        let landlock_will_apply =
            self.landlock_available && policy.platform_flags.linux_use_landlock;
        if landlock_will_apply {
            apply_landlock(policy)?;
        } else if policy.declares_fs_path_restrictions() {
            return Err(SandboxError::ApplyFailed(format!(
                "connector declares filesystem path restrictions but no path-confinement \
                 mechanism is active (landlock_available={}, linux_use_landlock={}); refusing \
                 to run unconfined — enable Landlock (kernel 5.13+) or run this connector \
                 under the WASI runtime",
                self.landlock_available, policy.platform_flags.linux_use_landlock
            )));
        }

        // Step 3: Apply seccomp filter (must be last as it restricts prctl)
        self.apply_seccomp(policy)?;

        info!("Linux sandbox applied successfully");
        Ok(())
    }

    fn apply_to_command(
        &self,
        cmd: &mut std::process::Command,
        policy: &CompiledPolicy,
    ) -> Result<(), SandboxError> {
        use std::os::unix::process::CommandExt;

        let policy_clone = policy.clone();
        let userns_available = self.userns_available;
        let landlock_available = self.landlock_available;

        // Fail closed BEFORE registering pre_exec: the child closure cannot
        // surface a rich error, and silently launching a connector that
        // declared filesystem restrictions without a confinement mechanism is
        // the bug this guards (bead sandbox-linux-no-default-fs-confinement).
        // Same rationale as `apply`: Landlock is the only wired path-
        // confinement mechanism; the unshared mount namespace installs no bind
        // mounts, and seccomp cannot filter openat by path.
        let landlock_will_apply = landlock_available && policy.platform_flags.linux_use_landlock;
        if !landlock_will_apply && policy.declares_fs_path_restrictions() {
            return Err(SandboxError::ApplyFailed(format!(
                "connector declares filesystem path restrictions but no path-confinement \
                 mechanism is active (landlock_available={landlock_available}, \
                 linux_use_landlock={}); refusing to launch unconfined — enable Landlock \
                 (kernel 5.13+) or run this connector under the WASI runtime",
                policy.platform_flags.linux_use_landlock
            )));
        }

        // Pre-compute seccomp filter to avoid allocation in child
        let filter = self.build_seccomp_filter(policy);

        // Pre-compute CStrings for Landlock paths to avoid allocation in child
        let mut readonly_cpaths = Vec::with_capacity(policy.readonly_paths.len());
        for p in &policy.readonly_paths {
            use std::os::unix::ffi::OsStrExt;
            readonly_cpaths.push(
                std::ffi::CString::new(p.as_os_str().as_bytes())
                    .map_err(|e| SandboxError::InvalidConfig(format!("invalid path: {e}")))?,
            );
        }

        let mut writable_cpaths = Vec::with_capacity(policy.writable_paths.len());
        for p in &policy.writable_paths {
            use std::os::unix::ffi::OsStrExt;
            writable_cpaths.push(
                std::ffi::CString::new(p.as_os_str().as_bytes())
                    .map_err(|e| SandboxError::InvalidConfig(format!("invalid path: {e}")))?,
            );
        }

        unsafe {
            cmd.pre_exec(move || {
                // Avoid logging or allocating in pre_exec to maintain async-signal-safety.

                if userns_available {
                    let mut flags = libc::CLONE_NEWUSER
                        | libc::CLONE_NEWNS
                        | libc::CLONE_NEWIPC
                        | libc::CLONE_NEWUTS;
                    if policy_clone.block_direct_network {
                        flags |= libc::CLONE_NEWNET;
                    }
                    libc::unshare(flags); // Ignore errors silently in child
                }

                // Apply rlimits directly
                let memory_limit_bytes = policy_clone.memory_limit_bytes;
                let cpu_seconds = policy_clone.wall_clock_timeout.as_secs();

                let limit_data = libc::rlimit {
                    rlim_cur: memory_limit_bytes,
                    rlim_max: memory_limit_bytes,
                };
                if libc::setrlimit(libc::RLIMIT_DATA, &limit_data) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let limit_as = libc::rlimit {
                    rlim_cur: memory_limit_bytes,
                    rlim_max: memory_limit_bytes,
                };
                if libc::setrlimit(libc::RLIMIT_AS, &limit_as) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                let limit_cpu = libc::rlimit {
                    rlim_cur: cpu_seconds,
                    rlim_max: cpu_seconds + 5,
                };
                if libc::setrlimit(libc::RLIMIT_CPU, &limit_cpu) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                let limit_fd = libc::rlimit {
                    rlim_cur: 1024,
                    rlim_max: 4096,
                };
                if libc::setrlimit(libc::RLIMIT_NOFILE, &limit_fd) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                let limit_core = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_CORE, &limit_core) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                // Landlock requires PR_SET_NO_NEW_PRIVS if we lack CAP_SYS_ADMIN
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

                // Apply Landlock if available
                if landlock_available && policy_clone.platform_flags.linux_use_landlock {
                    let all_fs_access = LANDLOCK_ACCESS_FS_EXECUTE
                        | LANDLOCK_ACCESS_FS_WRITE_FILE
                        | LANDLOCK_ACCESS_FS_READ_FILE
                        | LANDLOCK_ACCESS_FS_READ_DIR
                        | LANDLOCK_ACCESS_FS_REMOVE_DIR
                        | LANDLOCK_ACCESS_FS_REMOVE_FILE
                        | LANDLOCK_ACCESS_FS_MAKE_CHAR
                        | LANDLOCK_ACCESS_FS_MAKE_DIR
                        | LANDLOCK_ACCESS_FS_MAKE_REG
                        | LANDLOCK_ACCESS_FS_MAKE_SOCK
                        | LANDLOCK_ACCESS_FS_MAKE_FIFO
                        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
                        | LANDLOCK_ACCESS_FS_MAKE_SYM;

                    let readonly_access =
                        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

                    let writable_access = readonly_access
                        | LANDLOCK_ACCESS_FS_WRITE_FILE
                        | LANDLOCK_ACCESS_FS_REMOVE_DIR
                        | LANDLOCK_ACCESS_FS_REMOVE_FILE
                        | LANDLOCK_ACCESS_FS_MAKE_DIR
                        | LANDLOCK_ACCESS_FS_MAKE_REG
                        | LANDLOCK_ACCESS_FS_MAKE_SYM;

                    let attr = LandlockRulesetAttr {
                        handled_access_fs: all_fs_access,
                    };
                    let raw_fd = libc::syscall(
                        libc::SYS_landlock_create_ruleset,
                        &attr as *const _,
                        std::mem::size_of::<LandlockRulesetAttr>(),
                        0,
                    );
                    let ruleset_fd = i32::try_from(raw_fd).unwrap_or(-1);

                    if ruleset_fd >= 0 {
                        // Add rules
                        let apply_rule = |c_path: &std::ffi::CString,
                                          access: u64|
                         -> Result<(), std::io::Error> {
                            let fd = libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC);
                            if fd >= 0 {
                                let rule_attr = LandlockPathBeneathAttr {
                                    allowed_access: access,
                                    parent_fd: fd,
                                };
                                let res = libc::syscall(
                                    libc::SYS_landlock_add_rule,
                                    ruleset_fd,
                                    LANDLOCK_RULE_PATH_BENEATH,
                                    &rule_attr as *const _,
                                    0,
                                );
                                libc::close(fd);
                                if res != 0 {
                                    return Err(std::io::Error::last_os_error());
                                }
                            } else {
                                return Err(std::io::Error::last_os_error());
                            }
                            Ok(())
                        };

                        for c_path in &readonly_cpaths {
                            apply_rule(c_path, readonly_access)?;
                        }
                        for c_path in &writable_cpaths {
                            apply_rule(c_path, writable_access)?;
                        }

                        if libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0) != 0 {
                            let err = std::io::Error::last_os_error();
                            libc::close(ruleset_fd);
                            return Err(err);
                        }
                        libc::close(ruleset_fd);
                    } else {
                        return Err(std::io::Error::last_os_error());
                    }
                }

                // Apply seccomp filter
                let filter_len = u16::try_from(filter.len()).unwrap_or_else(|_| libc::abort());
                let prog = SockFprog {
                    len: filter_len,
                    filter: filter.as_ptr(),
                };

                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }

                if libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &prog as *const _,
                    0,
                    0,
                ) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }

                Ok(())
            });
        }

        Ok(())
    }

    fn is_available(&self) -> bool {
        // seccomp is available on all modern Linux kernels (3.5+)
        true
    }

    fn platform_name(&self) -> &'static str {
        "linux"
    }

    fn filter_strength(&self) -> crate::sandbox::FilterStrength {
        // Linux installs a seccomp-bpf filter with SECCOMP_RET_KILL_PROCESS as
        // the terminator and an arch-validated allowlist; every syscall that
        // isn't explicitly allowed terminates the process at the kernel trap
        // boundary. That matches SyscallLevel semantics in FilterStrength.
        crate::sandbox::FilterStrength::SyscallLevel
    }

    fn verify_file_access(
        &self,
        policy: &CompiledPolicy,
        path: &Path,
        write: bool,
    ) -> Result<(), SandboxError> {
        let path = crate::sandbox::resolve_policy_path(path);

        if write {
            // Check if path is under any writable path
            for writable in &policy.writable_paths {
                if path.starts_with(writable) {
                    return Ok(());
                }
            }
            return Err(SandboxError::PolicyCompilationFailed(format!(
                "write access to {} not allowed",
                path.display()
            )));
        }

        // For read access, check both readonly and writable paths
        for readable in policy.readonly_paths.iter().chain(&policy.writable_paths) {
            if path.starts_with(readable) {
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
// BPF Structures
// ============================================================================

/// BPF filter instruction (sock_filter).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

impl SockFilter {
    /// Create a statement instruction.
    const fn stmt(code: u16, k: u32) -> Self {
        Self {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    /// Create a jump instruction.
    const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Self {
        Self { code, jt, jf, k }
    }
}

/// BPF program (sock_fprog).
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if Landlock is available (Linux 5.13+).
fn check_landlock_available() -> bool {
    // Try to create a Landlock ruleset to check availability
    unsafe {
        let attr = LandlockRulesetAttr {
            handled_access_fs: 0xFFFF, // All access types
        };
        let fd = libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const _,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0,
        );
        let fd_i32 = i32::try_from(fd).unwrap_or(-1);
        if fd_i32 >= 0 {
            libc::close(fd_i32);
            true
        } else {
            false
        }
    }
}

/// Check if user namespaces are available.
fn check_userns_available() -> bool {
    // Check /proc/sys/kernel/unprivileged_userns_clone
    std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        .map_or(true, |s| s.trim() == "1") // Default to available if file doesn't exist
}

/// Set resource limit.
fn set_rlimit(
    resource: libc::__rlimit_resource_t,
    soft: u64,
    hard: u64,
) -> Result<(), SandboxError> {
    let limit = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };

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

/// Landlock ruleset attribute structure.
#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

/// Landlock path beneath attribute structure.
#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

/// Landlock access flags.
const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

const LANDLOCK_RULE_PATH_BENEATH: i32 = 1;

/// Apply Landlock filesystem restrictions.
fn apply_landlock(policy: &CompiledPolicy) -> Result<(), SandboxError> {
    // Landlock requires PR_SET_NO_NEW_PRIVS if we lack CAP_SYS_ADMIN
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(SandboxError::SyscallFailed(format!(
                "prctl(PR_SET_NO_NEW_PRIVS) failed before landlock: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    let all_fs_access = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM;

    let readonly_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

    let writable_access = readonly_access
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SYM;

    // Create ruleset
    let attr = LandlockRulesetAttr {
        handled_access_fs: all_fs_access,
    };

    let ruleset_fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const _,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0,
        )
    };

    if ruleset_fd < 0 {
        return Err(SandboxError::SyscallFailed(format!(
            "landlock_create_ruleset failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let ruleset_fd = i32::try_from(ruleset_fd).map_err(|_| {
        SandboxError::SyscallFailed("landlock_create_ruleset returned invalid fd".into())
    })?;

    // Add rules for readonly paths
    for path in &policy.readonly_paths {
        if let Err(e) = add_landlock_rule(ruleset_fd, path, readonly_access) {
            warn!(path = %path.display(), error = %e, "Failed to add Landlock readonly rule");
        }
    }

    // Add rules for writable paths
    for path in &policy.writable_paths {
        if let Err(e) = add_landlock_rule(ruleset_fd, path, writable_access) {
            warn!(path = %path.display(), error = %e, "Failed to add Landlock writable rule");
        }
    }

    // Enforce the ruleset
    let ret = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0) };

    unsafe {
        libc::close(ruleset_fd);
    }

    if ret < 0 {
        return Err(SandboxError::SyscallFailed(format!(
            "landlock_restrict_self failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    info!(
        readonly_count = policy.readonly_paths.len(),
        writable_count = policy.writable_paths.len(),
        "Applied Landlock filesystem restrictions"
    );

    Ok(())
}

/// Add a Landlock rule for a path.
fn add_landlock_rule(
    ruleset_fd: i32,
    path: &std::path::Path,
    access: u64,
) -> Result<(), SandboxError> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|e| SandboxError::InvalidConfig(format!("invalid path: {e}")))?;

    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(SandboxError::Io(std::io::Error::last_os_error()));
    }

    let attr = LandlockPathBeneathAttr {
        allowed_access: access,
        parent_fd: fd,
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &attr as *const _,
            0,
        )
    };

    unsafe {
        libc::close(fd);
    }

    if ret < 0 {
        return Err(SandboxError::SyscallFailed(format!(
            "landlock_add_rule failed for {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::{CompiledPolicy, PlatformFlags};
    use fcp_manifest::SandboxProfile;
    use std::path::PathBuf;
    use std::time::Duration;

    fn test_policy() -> CompiledPolicy {
        CompiledPolicy {
            profile: SandboxProfile::Strict,
            memory_limit_bytes: 256 * 1024 * 1024,
            cpu_percent: 50,
            wall_clock_timeout: Duration::from_secs(30),
            readonly_paths: vec![PathBuf::from("/usr"), PathBuf::from("/lib")],
            writable_paths: vec![PathBuf::from("/tmp/test")],
            deny_exec: true,
            deny_ptrace: true,
            block_direct_network: true,
            state_dir: Some(PathBuf::from("/tmp/test")),
            platform_flags: PlatformFlags::default(),
        }
    }

    #[test]
    fn test_linux_sandbox_available() {
        let sandbox = LinuxSandbox::new();
        assert!(sandbox.is_available());
        assert_eq!(sandbox.platform_name(), "linux");
    }

    /// bead sandbox-linux-no-default-fs-confinement: a policy that declares
    /// filesystem path restrictions must NOT be launched unconfined. With
    /// `linux_use_landlock` unset (the default), `apply_to_command` must fail
    /// closed rather than register a pre_exec that never confines paths.
    /// `apply_to_command` only *registers* the child hook, so the parent test
    /// process is not mutated.
    #[test]
    fn apply_to_command_fails_closed_when_fs_restrictions_unenforced() {
        let sandbox = LinuxSandbox::new();
        // test_policy() declares readonly_paths and does not request Landlock.
        let policy = test_policy();
        assert!(policy.declares_fs_path_restrictions());
        assert!(!policy.platform_flags.linux_use_landlock);

        let mut cmd = std::process::Command::new("/bin/true");
        let err = sandbox.apply_to_command(&mut cmd, &policy).expect_err(
            "declared fs restrictions without a confinement mechanism must fail closed",
        );
        assert!(matches!(err, SandboxError::ApplyFailed(_)), "got {err:?}");
    }

    /// The guard must NOT fire for a policy that declares no filesystem path
    /// restrictions beyond the auto-added state dir — that would newly break
    /// connectors that never asked to be path-confined.
    #[test]
    fn apply_to_command_allows_policy_without_fs_restrictions() {
        let sandbox = LinuxSandbox::new();
        let mut policy = test_policy();
        policy.readonly_paths.clear();
        policy.writable_paths = policy.state_dir.iter().cloned().collect();
        assert!(!policy.declares_fs_path_restrictions());

        let mut cmd = std::process::Command::new("/bin/true");
        sandbox
            .apply_to_command(&mut cmd, &policy)
            .expect("a policy with no declared fs restrictions must not fail closed");
    }

    #[test]
    fn test_verify_file_access_readonly() {
        let sandbox = LinuxSandbox::new();
        let policy = test_policy();

        // Should allow read from readonly paths
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/usr/lib/test.so"), false)
                .is_ok()
        );

        // Should deny write to readonly paths
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/usr/lib/test.so"), true)
                .is_err()
        );
    }

    #[test]
    fn test_verify_file_access_writable() {
        let sandbox = LinuxSandbox::new();
        let policy = test_policy();

        // Should allow read and write to writable paths
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
    }

    #[test]
    fn test_verify_exec_denied() {
        let sandbox = LinuxSandbox::new();
        let policy = test_policy();

        assert!(sandbox.verify_exec_allowed(&policy).is_err());
    }

    #[test]
    fn test_verify_network_blocked() {
        let sandbox = LinuxSandbox::new();
        let policy = test_policy();

        assert!(sandbox.verify_network_blocked(&policy).is_ok());
    }

    #[test]
    fn test_build_filter_structure() {
        let sandbox = LinuxSandbox::new();
        let policy = test_policy();
        let filter = sandbox.build_seccomp_filter(&policy);

        // Filter should not be empty
        assert!(!filter.is_empty());

        // First instruction should load arch (offset 4)
        assert_eq!(filter[0].code, 0x20);
        assert_eq!(filter[0].k, 4);

        // Fourth instruction should load syscall number (offset 0)
        assert_eq!(filter[3].code, 0x20);
        assert_eq!(filter[3].k, 0);

        // Last instruction should be the default deny
        let last = filter.last().unwrap();
        assert_eq!(last.code, 0x06);
        assert_eq!(last.k, SECCOMP_RET_KILL_PROCESS);
    }

    // ── New tests ──

    #[test]
    fn test_linux_sandbox_default() {
        let sandbox = LinuxSandbox::default();
        assert!(sandbox.is_available());
        assert_eq!(sandbox.platform_name(), "linux");
    }

    #[test]
    fn test_syscall_allowlist_no_network() {
        let sandbox = LinuxSandbox::new();
        let policy = test_policy(); // block_direct_network = true
        let (allowed, _graceful) = sandbox.build_syscall_allowlist(&policy);

        // Network syscalls should NOT be present when network is blocked
        assert!(!allowed.contains(&syscall_nr::SOCKET));
        assert!(!allowed.contains(&syscall_nr::CONNECT));
        assert!(!allowed.contains(&syscall_nr::BIND));
    }

    #[test]
    fn test_syscall_allowlist_with_network() {
        let sandbox = LinuxSandbox::new();
        let mut policy = test_policy();
        policy.block_direct_network = false;
        let (allowed, _graceful) = sandbox.build_syscall_allowlist(&policy);

        // Network syscalls SHOULD be present when network is not blocked
        assert!(allowed.contains(&syscall_nr::SOCKET));
        assert!(allowed.contains(&syscall_nr::CONNECT));
        assert!(allowed.contains(&syscall_nr::BIND));
    }

    #[test]
    fn test_syscall_allowlist_deny_exec() {
        let sandbox = LinuxSandbox::new();
        let policy = test_policy(); // deny_exec = true
        let (allowed, _graceful) = sandbox.build_syscall_allowlist(&policy);

        // Exec syscalls should NOT be present when exec is denied
        assert!(!allowed.contains(&syscall_nr::EXECVE));
        assert!(!allowed.contains(&syscall_nr::FORK));
        // CLONE is always allowed (required for threading in Rust/Go async runtimes)
        assert!(allowed.contains(&syscall_nr::CLONE));
    }

    #[test]
    fn test_syscall_allowlist_allow_exec() {
        let sandbox = LinuxSandbox::new();
        let mut policy = test_policy();
        policy.deny_exec = false;
        let (allowed, _graceful) = sandbox.build_syscall_allowlist(&policy);

        assert!(allowed.contains(&syscall_nr::EXECVE));
        assert!(allowed.contains(&syscall_nr::FORK));
        assert!(allowed.contains(&syscall_nr::CLONE));
    }

    #[test]
    fn test_syscall_allowlist_deny_ptrace() {
        let sandbox = LinuxSandbox::new();
        let policy = test_policy(); // deny_ptrace = true
        let (allowed, _graceful) = sandbox.build_syscall_allowlist(&policy);

        assert!(!allowed.contains(&syscall_nr::PTRACE));
    }

    #[test]
    fn test_syscall_allowlist_allow_ptrace() {
        let sandbox = LinuxSandbox::new();
        let mut policy = test_policy();
        policy.deny_ptrace = false;
        let (allowed, _graceful) = sandbox.build_syscall_allowlist(&policy);

        assert!(allowed.contains(&syscall_nr::PTRACE));
    }

    #[test]
    fn test_syscall_allowlist_writable_paths_add_fs_modify() {
        let sandbox = LinuxSandbox::new();
        let policy = test_policy(); // has writable_paths = ["/tmp/test"]
        let (allowed, _graceful) = sandbox.build_syscall_allowlist(&policy);

        // File modification syscalls should be present
        assert!(allowed.contains(&syscall_nr::MKDIR));
        assert!(allowed.contains(&syscall_nr::UNLINK));
        assert!(allowed.contains(&syscall_nr::RENAME));
    }

    #[test]
    fn test_syscall_allowlist_no_writable_paths_no_fs_modify() {
        let sandbox = LinuxSandbox::new();
        let mut policy = test_policy();
        policy.writable_paths = vec![];
        let (allowed, _graceful) = sandbox.build_syscall_allowlist(&policy);

        assert!(!allowed.contains(&syscall_nr::MKDIR));
        assert!(!allowed.contains(&syscall_nr::UNLINK));
        assert!(!allowed.contains(&syscall_nr::RENAME));
    }

    #[test]
    fn test_sock_filter_stmt() {
        let f = SockFilter::stmt(0x06, 0x7fff_0000);
        assert_eq!(f.code, 0x06);
        assert_eq!(f.jt, 0);
        assert_eq!(f.jf, 0);
        assert_eq!(f.k, 0x7fff_0000);
    }

    #[test]
    fn test_sock_filter_jump() {
        let f = SockFilter::jump(0x15, 42, 1, 0);
        assert_eq!(f.code, 0x15);
        assert_eq!(f.k, 42);
        assert_eq!(f.jt, 1);
        assert_eq!(f.jf, 0);
    }

    #[test]
    fn test_verify_file_access_denied_path() {
        let sandbox = LinuxSandbox::new();
        let policy = test_policy();

        // Path not in readonly or writable paths
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/etc/shadow"), false)
                .is_err()
        );
        assert!(
            sandbox
                .verify_file_access(&policy, Path::new("/etc/shadow"), true)
                .is_err()
        );
    }

    #[test]
    fn test_verify_exec_allowed_when_permitted() {
        let sandbox = LinuxSandbox::new();
        let mut policy = test_policy();
        policy.deny_exec = false;
        assert!(sandbox.verify_exec_allowed(&policy).is_ok());
    }

    #[test]
    fn test_verify_network_not_blocked() {
        let sandbox = LinuxSandbox::new();
        let mut policy = test_policy();
        policy.block_direct_network = false;
        assert!(sandbox.verify_network_blocked(&policy).is_err());
    }

    #[test]
    fn test_build_filter_with_all_features_enabled() {
        let sandbox = LinuxSandbox::new();
        let mut policy = test_policy();
        policy.deny_exec = false;
        policy.deny_ptrace = false;
        policy.block_direct_network = false;
        let filter = sandbox.build_seccomp_filter(&policy);

        // Should have more instructions with all features enabled
        let restricted_policy = test_policy();
        let restricted_filter = sandbox.build_seccomp_filter(&restricted_policy);
        assert!(filter.len() > restricted_filter.len());
    }
}
