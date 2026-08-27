//! FCP Core - legacy compatibility barrel for shared FCP primitives and
//! not-yet-carved platform semantics.
//!
//! During the FCP3 split, the semantic owner crates are `fcp-kernel`,
//! `fcp-policy`, and `fcp-evidence`, but many of their type definitions still
//! physically live here and are re-exported outward. The long-term goal is for
//! `fcp-core` to shrink to a narrow shared-primitive surface.
//!
//! See `docs/FCP3_Semantic_Ownership_Inventory.md` for the current residue map.

#![forbid(unsafe_code)]
// Lint groups come from [workspace.lints.clippy]; duplicating them here would
// override that table and defeat its allow entries.
#![allow(clippy::module_name_repetitions)]

// ── Acceptable shared primitive residue ──────────────────────────────
mod error;
pub mod tool_schema;
pub mod util;

// ── Assigned to fcp-kernel (execution lifecycle) ────────────────────
mod connector;
mod connector_artifacts;
mod connector_descriptors;
mod connector_state;
mod crdt;
mod credential;
mod event;
mod health;
mod lease;
mod lifecycle;
mod operation;
pub mod pem;
mod protocol;
mod provisioning;
mod quorum;
mod ratelimit;
mod release;
mod secret;

// ── Assigned to fcp-policy (zone, capability, trust) ────────────────
mod capability;
mod enforcement;
mod enrollment;
pub mod pcs;
mod policy;
mod posture;
mod provenance;
mod zone_keys;

// ── Assigned to fcp-evidence (audit, revocation, objects) ───────────
mod audit;
mod checkpoint;
mod object;
pub mod quotient_filter;
mod revocation;
mod supply_chain;

// Legacy wildcard barrel during the FCP3 carve-out. These re-exports keep
// existing `use fcp_core::*` imports working while semantic ownership
// migrates to fcp-kernel, fcp-policy, and fcp-evidence. New code should
// import from the owner crate, not from fcp-core.
pub use audit::*;
pub use capability::*;
pub use checkpoint::*;
pub use connector::*;
pub use connector_artifacts::*;
pub use connector_descriptors::*;
pub use connector_state::*;
pub use crdt::*;
pub use credential::*;
pub use enforcement::*;
pub use enrollment::*;
pub use error::*;
pub use event::*;
pub use health::*;
pub use lease::*;
pub use lifecycle::*;
pub use object::*;
pub use operation::*;
pub use policy::*;
pub use posture::*;
pub use protocol::*;
pub use provenance::*;
pub use provisioning::*;
pub use quorum::*;
pub use quotient_filter::*;
pub use ratelimit::*;
pub use release::*;
pub use revocation::*;
pub use secret::*;
pub use supply_chain::*;
pub use zone_keys::*;

// Re-export commonly used external types
pub use async_trait::async_trait;
pub use chrono::{DateTime, Utc};
pub use uuid::Uuid;
