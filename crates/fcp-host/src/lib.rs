//! FCP Host - Node Gateway/Orchestrator for the Flywheel Connector Protocol
//!
//! This crate implements the host/orchestrator that:
//! - Supervises connector binaries in sandboxes
//! - Exposes an agent-facing API (local or mesh-facing)
//! - Delegates enforcement decisions to the `MeshNode` + policy engine
//! - Manages lifecycle (install/verify, configure, health, restart)
//!
//! Based on FCP Specification Section 10 (Gateway Architecture) and
//! bead `flywheel_connectors-oip0`.

#![deny(unsafe_code)]
// Lint groups come from [workspace.lints.clippy]; duplicating them here would
// override that table and defeat its allow entries.
#![allow(clippy::module_name_repetitions)]

mod admin_state;
mod agent_api;
mod batch;
mod budget;
mod cancellation;
mod credentials;
mod cutover;
mod deployment_mode;
mod discovery;
mod doctor;
mod emergency_revocation;
mod enforcement;
mod error;
// Retained-but-unwired: composite host-health framework
// (`HealthAggregator`, `CompositeHealthStatus`, tri-state `HealthState`,
// merge/rollup logic across connector / mesh / resource / named-component
// inputs). Production `/rpc/health` at `crates/fcp-host/src/bin/fcp-host.rs`
// `health_handler` instead builds a flat `HostHealthResponse` directly from
// `state.registry.list()` and `ConnectorHealth` (from fcp-kernel); the
// composite shape here was the prototype that did not get adopted when the
// host binary landed. Module is intentionally retained — its 77 unit tests
// pin the target shape for a future composite-health redesign and the
// types are the natural starting point if `/rpc/health` ever needs to
// surface mesh or resource subsystems alongside connectors. Same pattern
// as `enforcement::EnforcementPipeline` (br-ike8x diagnosis). Visibility
// stays private (no `pub use health::*`) so the module cannot accidentally
// be picked up by external callers expecting it to drive production
// health responses.
#[allow(dead_code)]
mod health;
mod invoke_audit;
mod migration_linux;
#[cfg(target_os = "macos")]
mod migration_macos;
mod network_policy;
mod output_capture;
mod progress;
mod redaction;
mod resilience;
mod resource_ledger;
mod resume_handshake;
mod rollout;
mod supervisor;
mod supply_chain;
mod tailnet_evidence;

pub use admin_state::*;
pub use agent_api::*;
pub use batch::*;
pub use budget::*;
pub use cancellation::*;
pub use credentials::*;
pub use cutover::*;
pub use deployment_mode::*;
pub use discovery::*;
pub use doctor::*;
pub use emergency_revocation::*;
pub use enforcement::*;
pub use error::*;
pub use invoke_audit::*;
pub use migration_linux::*;
#[cfg(target_os = "macos")]
pub use migration_macos::*;
pub use network_policy::*;
pub use output_capture::*;
pub use progress::*;
pub use redaction::*;
pub use resilience::*;
pub use resource_ledger::*;
pub use resume_handshake::*;
pub use rollout::*;
pub use supervisor::*;
pub use supply_chain::*;
pub use tailnet_evidence::*;
