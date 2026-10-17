//! FCP2 protocol framing and session primitives (`FCPS`/`FCPC`).

#![forbid(unsafe_code)]

pub mod architecture;
mod control_plane;
mod fcpc;
mod fcps;
pub mod operation_info;
pub mod session;
mod symbol_envelope;

pub use control_plane::*;
pub use fcpc::*;
pub use fcps::*;
pub use operation_info::*;
pub use session::*;
pub use symbol_envelope::*;
