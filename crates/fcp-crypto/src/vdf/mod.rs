//! Verifiable Delay Functions (VDF) for FCP owner-key rate limiting (`flywheel_connectors-angoc.17.5`).

pub mod wesolowski;

pub use wesolowski::{
    DEFAULT_OWNER_KEY_VDF_ITERATIONS, VDF_ELEMENT_BYTES, VDF_PROOF_MAX_BYTES, VdfError, VdfOutput,
    VdfParams, VdfProof, WesolowskiVdf,
};
