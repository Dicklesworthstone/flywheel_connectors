//! Owner-key rate limiting and VDF enforcement gates (`flywheel_connectors-angoc.17.5`).

pub mod vdf_gate;

pub use vdf_gate::{
     DEFAULT_OWNER_KEY_HOURLY_CAP, OwnerKeyGateDecision, OwnerKeyRateAuditAlert,
    OwnerKeyVdfRateGate, OwnerKeyVdfSubmission, VdfRateDoctorReport,
};
