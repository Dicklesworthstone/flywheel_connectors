//! Library re-exports for benchmarks and integration tests.
//!
//! The primary entry point is the `fwc` binary (`main.rs`).  This thin
//! library crate exposes the subset of modules needed by criterion
//! benchmarks and integration tests without restructuring the CLI.

pub mod access_cmd;
pub mod agent_bootstrap;
pub mod capability_replay;
pub mod connector_state;
pub mod doctor;
pub mod mesh_cmd;
pub mod pipe;
pub mod proof_readiness;
pub mod proof_request;
pub mod readiness;
pub mod recovery;
pub mod schema_nav;
pub mod search;
pub mod test_observability;
