//! Connector-author access to the shared manifest operation contracts.
//!
//! The host and connector runtime use one validator implementation, so schema
//! checks, response correlation and uncertain-outcome semantics cannot drift.

pub use fcp_manifest::OperationContractSet;
