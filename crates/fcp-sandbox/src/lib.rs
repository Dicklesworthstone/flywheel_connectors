//! FCP2 sandbox enforcement (OS sandbox profiles + egress guard).
//!
//! This crate provides two key security components:
//!
//! 1. **Network Guard** (egress proxy): The only outbound network path for connectors
//!    under `strict`/`moderate` sandbox profiles.
//!
//! 2. **OS Sandboxes**: Platform-specific process isolation using:
//!    - Linux: seccomp-bpf + namespaces (+ Landlock on 5.13+)
//!    - macOS: seatbelt profiles (sandbox-exec)
//!    - Windows: `AppContainer` + job objects
//!
//! # Core Invariants (NORMATIVE)
//!
//! - Connectors in `strict`/`moderate` profiles MUST NOT open outbound sockets directly.
//! - All outbound network activity MUST be mediated through the Network Guard.
//! - The Network Guard is **deny-by-default**.
//! - OS sandboxes enforce filesystem, process, and network restrictions per manifest.
//!
//! # Network Guard Example
//!
//! ```rust,ignore
//! use fcp_sandbox::{EgressGuard, EgressRequest, EgressHttpRequest};
//! use fcp_manifest::NetworkConstraints;
//!
//! let guard = EgressGuard::new();
//! let constraints = NetworkConstraints { /* ... */ };
//!
//! let request = EgressRequest::Http(EgressHttpRequest {
//!     url: "https://api.example.com/v1/data".into(),
//!     method: "GET".into(),
//!     headers: vec![],
//!     body: None,
//!     credential_id: None,
//! });
//!
//! match guard.evaluate(&request, &constraints) {
//!     Ok(decision) => { /* proceed with request */ }
//!     Err(e) => { /* deny: log and return error */ }
//! }
//! ```
//!
//! # OS Sandbox Example
//!
//! ```rust,ignore
//! use fcp_sandbox::{CompiledPolicy, create_sandbox};
//! use fcp_manifest::SandboxSection;
//!
//! let manifest_section: SandboxSection = /* ... */;
//! let state_dir = Some("/var/lib/fcp/connectors/my-connector".into());
//!
//! let policy = CompiledPolicy::from_manifest(&manifest_section, state_dir)?;
//! let sandbox = create_sandbox()?;
//!
//! // Apply sandbox early in connector startup (irreversible!)
//! sandbox.apply(&policy)?;
//! ```
//!
//! # WASI Runtime Example
//!
//! ```rust,ignore
//! use fcp_sandbox::{CompiledPolicy, WasiConfig, WasiRuntime};
//!
//! // 1. Compile policy from manifest
//! let policy = CompiledPolicy::from_manifest(&manifest.sandbox, Some(state_dir))?;
//!
//! // 2. Create WASI runtime with policy
//! let config = WasiConfig::from_policy(&policy)?;
//! let runtime = WasiRuntime::new(config)?;
//!
//! // 3. Load and run connector component
//! let component = runtime.load_component(&wasm_bytes)?;
//! let args = vec!["--dry-run".to_string()];
//! let result = runtime.invoke(&component, "run", &args).await?;
//! assert_eq!(result.exit_code, 0);
//! ```

// unsafe_code stays allowed for this crate (OS sandbox syscalls: seccomp,
// landlock, seatbelt, AppContainer FFI). The workspace table denies it; a
// crate-root source attribute outranks the manifest-derived flag.
#![allow(unsafe_code)]
// Allow FFI-related patterns common in OS sandbox implementations
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::borrow_as_ptr)]

mod egress;
mod sandbox;
mod wasi;

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::{WindowsAppContainerChild, WindowsSandbox};

pub use egress::*;
pub use sandbox::*;
pub use wasi::*;
