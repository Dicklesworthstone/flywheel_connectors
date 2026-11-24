//! FCP2 Bootstrap and Genesis
//!
//! This crate implements the bootstrap workflow for FCP2 meshes, including:
//!
//! - **First-run workflow**: Initial mesh creation with owner key ceremony
//! - **Genesis state**: The initial state of a mesh
//! - **Cold recovery**: Zero-peer disaster recovery from a recovery phrase
//! - **Threshold ceremonies**: FROST-based distributed key generation
//! - **Time validation**: NTP-based clock drift detection
//! - **Hardware token support**: PKCS#11 integration for hardware security modules
//!
//! # Architecture
//!
//! The bootstrap process follows a state machine model:
//!
//! ```text
//! ┌─────────────────┐
//! │   Uninitialized │
//! └────────┬────────┘
//!          │ fcp init
//!          ▼
//! ┌─────────────────┐     ┌─────────────────┐
//! │ TimeValidation  │────▶│  KeyGeneration  │
//! └────────┬────────┘     └────────┬────────┘
//!          │                       │
//!          ▼                       ▼
//! ┌─────────────────┐     ┌─────────────────┐
//! │ CeremonySetup   │────▶│ CeremonyRound1  │
//! └────────┬────────┘     └────────┬────────┘
//!          │                       │
//!          ▼                       ▼
//! ┌─────────────────┐     ┌─────────────────┐
//! │ CeremonyRound2  │────▶│  GenesisCreate  │
//! └────────┬────────┘     └────────┬────────┘
//!          │                       │
//!          ▼                       ▼
//! ┌─────────────────┐     ┌─────────────────┐
//! │  Enrollment     │────▶│   Completed     │
//! └─────────────────┘     └─────────────────┘
//! ```
//!
//! # Example: First-Run Bootstrap
//!
//! ```ignore
//! use fcp_bootstrap::{BootstrapConfig, BootstrapWorkflow, BootstrapMode};
//!
//! let config = BootstrapConfig::builder()
//!     .data_dir("/path/to/.fcp")
//!     .mode(BootstrapMode::SingleDevice)
//!     .build()?;
//!
//! let workflow = BootstrapWorkflow::new(config)?;
//! let genesis = workflow.run()?;
//!
//! println!("Genesis fingerprint: {}", genesis.fingerprint());
//! ```
//!
//! # Example: Cold Recovery
//!
//! ```ignore
//! use fcp_bootstrap::{ColdRecovery, RecoveryPhrase};
//!
//! let phrase = RecoveryPhrase::from_mnemonic("abandon abandon ... about")?;
//! let recovery = ColdRecovery::from_phrase(
//!     &phrase,
//!     Some("BLAKE3:expected_fingerprint"),
//! )?;
//!
//! for warning in &recovery.warnings {
//!     tracing::warn!(?warning, "Cold recovery warning");
//! }
//!
//! let genesis = recovery.genesis;
//! ```
//!
//! # Security Considerations
//!
//! - Recovery phrases MUST be generated with sufficient entropy (256 bits)
//! - Recovery phrases MUST be stored securely offline
//! - Hardware tokens are recommended for production deployments
//! - Time validation prevents replay attacks using stale timestamps
//! - All cryptographic material is zeroized on drop

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod ceremony;
pub mod cold_recovery;
pub mod error;
pub mod genesis;
pub mod hardware_token;
pub mod phase;
pub mod recovery_phrase;
#[cfg(test)]
mod soft_token;
pub mod time_validation;
pub mod workflow;

// Re-export commonly used types at crate root
pub use ceremony::{
    CeremonyAbortResult, CeremonyCheckpoint, CeremonyId, CeremonyPhase, CeremonyResumeError,
    EncryptedShare, FrostCommitment, ParticipantId, ThresholdCeremony, ThresholdConfig,
    ThresholdSignatureArtifact,
};
pub use cold_recovery::{ColdRecovery, ColdRecoveryError, ColdRecoveryWarning};
pub use error::{BootstrapError, BootstrapResult};
pub use genesis::{GenesisState, GenesisValidationError};
pub use hardware_token::{
    AuthenticatedSessionState, AuthenticatedTokenSession, CertificateKeyPair,
    CertificateSelectionRefusal, DetectedToken, DetectionIssue, DetectionStage, HardwareTokenEnrollment,
    HardwareTokenPin, HardwareTokenProvider, ProviderDetectionResult, ProvisioningMaterial,
    SessionSelectionOutcome,
    TokenCertificate, TokenDetectionReport, TokenDetector, TokenKeyInfo, TokenKeyType,
};
pub use phase::{BootstrapPhase, InitResult, InitSuggestion, PartialStateSuggestion};
pub use recovery_phrase::{RecoveryPhrase, RecoveryPhraseError};
pub use time_validation::{TimeValidation, TimeValidationResult};
pub use workflow::{BootstrapConfig, BootstrapMode, BootstrapWorkflow};
