//! Cold recovery (zero-peer disaster recovery).
//!
//! When ALL peers are gone and only the recovery phrase exists, this module
//! enables recreating the genesis state and starting fresh.

use crate::genesis::GenesisState;
use crate::recovery_phrase::{OwnerKeypair, RecoveryPhrase};
use thiserror::Error;

/// Warnings generated during cold recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColdRecoveryWarning {
    /// No audit history available (starting fresh).
    NoAuditHistory,

    /// Cannot verify revocation state (no peers to query).
    RevocationStateUnknown,

    /// Starting with a single node (no quorum possible).
    SingleNodeStart,

    /// Objects created after the original genesis will be lost.
    DataLoss,

    /// Fingerprint verification was skipped (no expected fingerprint provided).
    FingerprintNotVerified,
}

impl std::fmt::Display for ColdRecoveryWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoAuditHistory => write!(f, "No audit history available - starting fresh"),
            Self::RevocationStateUnknown => {
                write!(f, "Cannot verify revocation state without peers")
            }
            Self::SingleNodeStart => write!(f, "Starting with single node - no quorum possible"),
            Self::DataLoss => {
                write!(f, "Objects created after original genesis will be lost")
            }
            Self::FingerprintNotVerified => {
                write!(f, "Fingerprint verification was skipped")
            }
        }
    }
}

/// Errors during cold recovery.
#[derive(Debug, Error)]
pub enum ColdRecoveryError {
    /// Genesis fingerprint does not match expected.
    #[error("fingerprint mismatch: expected {expected}, actual {actual}")]
    FingerprintMismatch {
        /// Expected fingerprint.
        expected: String,
        /// Actual fingerprint computed.
        actual: String,
    },

    /// Invalid recovery phrase.
    #[error("invalid recovery phrase: {0}")]
    InvalidPhrase(#[from] crate::recovery_phrase::RecoveryPhraseError),

    /// Genesis validation failed.
    #[error("genesis validation failed: {0}")]
    ValidationFailed(#[from] crate::genesis::GenesisValidationError),
}

/// Result of a cold recovery operation.
#[derive(Debug)]
pub struct ColdRecovery {
    /// The derived owner keypair from the recovery phrase.
    pub owner_keypair: OwnerKeypair,

    /// The recreated genesis state.
    ///
    /// **CRITICAL:** This creates a fresh genesis with the same owner key.
    /// Any objects/zones created after the original genesis are LOST.
    pub genesis: GenesisState,

    /// Warnings about the limitations of cold recovery.
    pub warnings: Vec<ColdRecoveryWarning>,
}

impl ColdRecovery {
    /// Recover from a recovery phrase when no peers exist.
    ///
    /// # Arguments
    ///
    /// * `phrase` - The BIP39 recovery phrase.
    /// * `expected_fingerprint` - Optional expected genesis fingerprint for verification.
    ///
    /// Fresh phrase-backed bootstrap and import use the same deterministic
    /// genesis. Older timestamped genesis records cannot be reconstructed from
    /// a phrase alone; restore their saved metadata instead. Their fingerprints
    /// remain distinct and are refused rather than silently treated as matches.
    ///
    /// # Returns
    ///
    /// A `ColdRecovery` struct containing the recreated genesis and warnings.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The expected fingerprint doesn't match the computed fingerprint.
    /// - The genesis validation fails.
    ///
    /// # Security
    ///
    /// Cold recovery should only be used as a last resort when no peers are
    /// reachable. The recovered genesis will not have:
    /// - Audit history
    /// - Revocation state
    /// - Objects created after the original bootstrap
    pub fn from_phrase(
        phrase: &RecoveryPhrase,
        expected_fingerprint: Option<&str>,
    ) -> Result<Self, ColdRecoveryError> {
        // 1. Derive owner keypair from the recovery phrase
        let owner_keypair = phrase.derive_owner_keypair();

        // 2. Recreate genesis (deterministic from owner pubkey)
        let genesis = GenesisState::create_deterministic(&owner_keypair.public());

        // 3. Validate the genesis
        genesis.validate()?;

        // 4. Verify fingerprint if provided
        let fingerprint = genesis.fingerprint();
        let mut warnings = Vec::new();

        if let Some(expected) = expected_fingerprint {
            if fingerprint != expected {
                return Err(ColdRecoveryError::FingerprintMismatch {
                    expected: expected.to_string(),
                    actual: fingerprint,
                });
            }
        } else {
            warnings.push(ColdRecoveryWarning::FingerprintNotVerified);
        }

        // 5. Add standard cold recovery warnings
        warnings.push(ColdRecoveryWarning::NoAuditHistory);
        warnings.push(ColdRecoveryWarning::RevocationStateUnknown);
        warnings.push(ColdRecoveryWarning::SingleNodeStart);
        warnings.push(ColdRecoveryWarning::DataLoss);

        Ok(Self {
            owner_keypair,
            genesis,
            warnings,
        })
    }

    /// Check if verification was performed.
    #[must_use]
    pub fn was_verified(&self) -> bool {
        !self
            .warnings
            .contains(&ColdRecoveryWarning::FingerprintNotVerified)
    }

    /// Get the genesis fingerprint.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        self.genesis.fingerprint()
    }
}

/// Interactive prompts for CLI cold recovery flow.
pub mod cli {
    use super::ColdRecoveryWarning;

    /// Prompts and responses for the cold recovery CLI flow.
    #[derive(Debug, Clone)]
    pub struct ColdRecoveryPrompts {
        /// Whether the user confirmed they have no backup.
        pub confirmed_no_backup: bool,

        /// Whether the user confirmed they understand data loss.
        pub confirmed_data_loss: bool,

        /// Optional expected fingerprint provided by user.
        pub expected_fingerprint: Option<String>,
    }

    /// Format a warning message for CLI display.
    #[must_use]
    pub fn format_warning(warning: &ColdRecoveryWarning) -> String {
        match warning {
            ColdRecoveryWarning::NoAuditHistory => {
                "\u{26A0}\u{FE0F}  No audit history will be available".to_string()
            }
            ColdRecoveryWarning::RevocationStateUnknown => {
                "\u{26A0}\u{FE0F}  Cannot verify if any keys/tokens were revoked".to_string()
            }
            ColdRecoveryWarning::SingleNodeStart => {
                "\u{26A0}\u{FE0F}  Starting as single node (threshold signing unavailable)"
                    .to_string()
            }
            ColdRecoveryWarning::DataLoss => {
                "\u{26A0}\u{FE0F}  Objects created after original bootstrap will be LOST"
                    .to_string()
            }
            ColdRecoveryWarning::FingerprintNotVerified => {
                "\u{26A0}\u{FE0F}  Fingerprint was not verified (consider providing expected fingerprint)"
                    .to_string()
            }
        }
    }

    /// Format the cold recovery confirmation message.
    #[must_use]
    pub const fn format_confirmation_message() -> &'static str {
        r"
⚠️  COLD START RECOVERY
No existing mesh peers found. This will:
- Create fresh genesis from owner key
- Lose any objects created after original bootstrap
- Lose audit history
- Start with single node (no quorum)

If you have a backup of your .fcp directory, restore it instead.
"
    }
}

#[cfg(test)]
mod tests {
    use super::{ColdRecovery, ColdRecoveryError, ColdRecoveryWarning};
    use crate::recovery_phrase::RecoveryPhrase;

    fn test_phrase() -> RecoveryPhrase {
        RecoveryPhrase::from_mnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        ).unwrap()
    }

    #[test]
    fn test_cold_recovery_basic() {
        let phrase = test_phrase();
        let recovery = ColdRecovery::from_phrase(&phrase, None).unwrap();

        assert!(recovery.genesis.validate().is_ok());
        assert!(!recovery.was_verified());
        assert!(
            recovery
                .warnings
                .contains(&ColdRecoveryWarning::FingerprintNotVerified)
        );
    }

    #[test]
    fn test_cold_recovery_with_fingerprint_verification() {
        let phrase = test_phrase();

        // First, get the expected fingerprint
        let recovery1 = ColdRecovery::from_phrase(&phrase, None).unwrap();
        let expected = recovery1.fingerprint();

        // Now recover with verification
        let recovery2 = ColdRecovery::from_phrase(&phrase, Some(&expected)).unwrap();
        assert!(recovery2.was_verified());
    }

    #[test]
    fn test_cold_recovery_fingerprint_mismatch() {
        let phrase = test_phrase();
        let result = ColdRecovery::from_phrase(&phrase, Some("BLAKE3:wrongfingerprint"));

        assert!(matches!(
            result,
            Err(ColdRecoveryError::FingerprintMismatch { .. })
        ));
    }

    #[test]
    fn cold_recovery_refuses_original_timestamped_genesis_fingerprint() {
        let phrase = test_phrase();
        let owner_key = phrase.derive_owner_keypair().public();
        let mut timestamped = crate::genesis::GenesisState::create(&owner_key);
        timestamped.created_at = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
        let original_bytes = timestamped.to_cbor().unwrap();
        let expected = timestamped.fingerprint();
        let deterministic = crate::genesis::GenesisState::create_deterministic(&owner_key);

        let result = ColdRecovery::from_phrase(&phrase, Some(&expected));
        assert!(matches!(
            result,
            Err(ColdRecoveryError::FingerprintMismatch { expected: rejected, actual })
                if rejected == expected && actual == deterministic.fingerprint()
        ));
        assert_eq!(timestamped.to_cbor().unwrap(), original_bytes);
    }

    #[test]
    fn test_cold_recovery_deterministic() {
        let phrase = test_phrase();

        let recovery1 = ColdRecovery::from_phrase(&phrase, None).unwrap();
        let recovery2 = ColdRecovery::from_phrase(&phrase, None).unwrap();

        assert_eq!(recovery1.fingerprint(), recovery2.fingerprint());
    }

    // ---- Warning counts ----

    #[test]
    fn cold_recovery_without_fingerprint_has_5_warnings() {
        let phrase = test_phrase();
        let recovery = ColdRecovery::from_phrase(&phrase, None).unwrap();
        // FingerprintNotVerified + NoAuditHistory + RevocationStateUnknown +
        // SingleNodeStart + DataLoss
        assert_eq!(recovery.warnings.len(), 5);
    }

    #[test]
    fn cold_recovery_with_fingerprint_has_4_warnings() {
        let phrase = test_phrase();
        let recovery1 = ColdRecovery::from_phrase(&phrase, None).unwrap();
        let expected = recovery1.fingerprint();
        let recovery2 = ColdRecovery::from_phrase(&phrase, Some(&expected)).unwrap();
        // No FingerprintNotVerified, only the 4 standard warnings
        assert_eq!(recovery2.warnings.len(), 4);
        assert!(
            !recovery2
                .warnings
                .contains(&ColdRecoveryWarning::FingerprintNotVerified)
        );
    }

    #[test]
    fn cold_recovery_always_has_standard_warnings() {
        let phrase = test_phrase();
        let recovery = ColdRecovery::from_phrase(&phrase, None).unwrap();
        assert!(
            recovery
                .warnings
                .contains(&ColdRecoveryWarning::NoAuditHistory)
        );
        assert!(
            recovery
                .warnings
                .contains(&ColdRecoveryWarning::RevocationStateUnknown)
        );
        assert!(
            recovery
                .warnings
                .contains(&ColdRecoveryWarning::SingleNodeStart)
        );
        assert!(recovery.warnings.contains(&ColdRecoveryWarning::DataLoss));
    }

    // ---- Warning Display ----

    #[test]
    fn cold_recovery_warning_display() {
        assert!(
            ColdRecoveryWarning::NoAuditHistory
                .to_string()
                .contains("audit")
        );
        assert!(
            ColdRecoveryWarning::RevocationStateUnknown
                .to_string()
                .contains("revocation")
        );
        assert!(
            ColdRecoveryWarning::SingleNodeStart
                .to_string()
                .contains("single node")
        );
        assert!(ColdRecoveryWarning::DataLoss.to_string().contains("lost"));
        assert!(
            ColdRecoveryWarning::FingerprintNotVerified
                .to_string()
                .contains("skipped")
        );
    }

    // ---- ColdRecoveryError Display ----

    #[test]
    fn cold_recovery_error_display() {
        let err = ColdRecoveryError::FingerprintMismatch {
            expected: "BLAKE3:abc".into(),
            actual: "BLAKE3:xyz".into(),
        };
        let s = err.to_string();
        assert!(s.contains("BLAKE3:abc"));
        assert!(s.contains("BLAKE3:xyz"));
    }

    // ---- CLI module ----

    #[test]
    fn cli_format_warning_all_variants() {
        use super::cli::format_warning;
        let variants = [
            ColdRecoveryWarning::NoAuditHistory,
            ColdRecoveryWarning::RevocationStateUnknown,
            ColdRecoveryWarning::SingleNodeStart,
            ColdRecoveryWarning::DataLoss,
            ColdRecoveryWarning::FingerprintNotVerified,
        ];
        for variant in &variants {
            let formatted = format_warning(variant);
            assert!(
                !formatted.is_empty(),
                "format_warning should not be empty for {variant}"
            );
        }
    }

    #[test]
    fn cli_format_confirmation_message_is_non_empty() {
        use super::cli::format_confirmation_message;
        let msg = format_confirmation_message();
        assert!(msg.contains("COLD START RECOVERY"));
        assert!(msg.contains("genesis"));
    }

    // ---- was_verified ----

    #[test]
    fn was_verified_true_when_fingerprint_matches() {
        let phrase = test_phrase();
        let r1 = ColdRecovery::from_phrase(&phrase, None).unwrap();
        let fp = r1.fingerprint();
        let r2 = ColdRecovery::from_phrase(&phrase, Some(&fp)).unwrap();
        assert!(r2.was_verified());
    }

    #[test]
    fn was_verified_false_when_no_fingerprint() {
        let phrase = test_phrase();
        let recovery = ColdRecovery::from_phrase(&phrase, None).unwrap();
        assert!(!recovery.was_verified());
    }

    // ---- Genesis is valid after recovery ----

    #[test]
    fn cold_recovery_genesis_validates() {
        let phrase = test_phrase();
        let recovery = ColdRecovery::from_phrase(&phrase, None).unwrap();
        assert!(recovery.genesis.validate().is_ok());
        assert_eq!(recovery.genesis.schema_version, 1);
        assert_eq!(recovery.genesis.initial_zones.len(), 5);
    }

    // ---- Debug output ----

    #[test]
    fn cold_recovery_debug_output() {
        let phrase = test_phrase();
        let recovery = ColdRecovery::from_phrase(&phrase, None).unwrap();
        let debug = format!("{recovery:?}");
        assert!(debug.contains("ColdRecovery"));
        assert!(debug.contains("genesis"));
        assert!(debug.contains("warnings"));
    }

    // ---- Warning clone and eq ----

    #[test]
    fn cold_recovery_warning_clone() {
        let w = ColdRecoveryWarning::DataLoss;
        let cloned = w.clone();
        assert_eq!(w, cloned);
    }

    #[test]
    fn cold_recovery_warning_all_eq() {
        let variants = [
            ColdRecoveryWarning::NoAuditHistory,
            ColdRecoveryWarning::RevocationStateUnknown,
            ColdRecoveryWarning::SingleNodeStart,
            ColdRecoveryWarning::DataLoss,
            ColdRecoveryWarning::FingerprintNotVerified,
        ];
        for v in &variants {
            assert_eq!(*v, v.clone());
        }
    }

    #[test]
    fn cold_recovery_warning_ne() {
        assert_ne!(
            ColdRecoveryWarning::DataLoss,
            ColdRecoveryWarning::NoAuditHistory
        );
        assert_ne!(
            ColdRecoveryWarning::SingleNodeStart,
            ColdRecoveryWarning::FingerprintNotVerified
        );
    }

    // ---- ColdRecoveryError is std::error::Error ----

    #[test]
    fn cold_recovery_error_is_error_trait() {
        let err = ColdRecoveryError::FingerprintMismatch {
            expected: "a".into(),
            actual: "b".into(),
        };
        let _: &dyn std::error::Error = &err;
    }

    // ---- Fingerprint is deterministic across recoveries ----

    #[test]
    fn cold_recovery_fingerprint_deterministic_multiple() {
        let phrase = test_phrase();
        let fps: Vec<String> = (0..3)
            .map(|_| {
                ColdRecovery::from_phrase(&phrase, None)
                    .unwrap()
                    .fingerprint()
            })
            .collect();
        assert_eq!(fps[0], fps[1]);
        assert_eq!(fps[1], fps[2]);
    }

    // ---- Owner keypair from recovery signs correctly ----

    #[test]
    fn cold_recovery_owner_keypair_signs() {
        let phrase = test_phrase();
        let recovery = ColdRecovery::from_phrase(&phrase, None).unwrap();
        let msg = b"test recovery sign";
        let sig = recovery.owner_keypair.sign(msg);
        assert!(recovery.owner_keypair.public().verify(msg, &sig).is_ok());
    }

    // ---- CLI prompts ----

    #[test]
    fn cli_prompts_debug() {
        let prompts = super::cli::ColdRecoveryPrompts {
            confirmed_no_backup: true,
            confirmed_data_loss: false,
            expected_fingerprint: Some("BLAKE3:test".to_string()),
        };
        let debug = format!("{prompts:?}");
        assert!(debug.contains("ColdRecoveryPrompts"));
        assert!(debug.contains("confirmed_no_backup"));
    }

    #[test]
    fn cli_prompts_clone() {
        let prompts = super::cli::ColdRecoveryPrompts {
            confirmed_no_backup: true,
            confirmed_data_loss: true,
            expected_fingerprint: None,
        };
        let cloned = prompts.clone();
        assert_eq!(prompts.confirmed_no_backup, cloned.confirmed_no_backup);
        assert_eq!(prompts.confirmed_data_loss, cloned.confirmed_data_loss);
        assert_eq!(prompts.expected_fingerprint, cloned.expected_fingerprint);
    }

    // ---- Recovery produces valid genesis zones ----

    #[test]
    fn cold_recovery_genesis_has_5_zones() {
        let phrase = test_phrase();
        let recovery = ColdRecovery::from_phrase(&phrase, None).unwrap();
        assert_eq!(recovery.genesis.initial_zones.len(), 5);
    }

    #[test]
    fn cold_recovery_genesis_has_owner_zone() {
        let phrase = test_phrase();
        let recovery = ColdRecovery::from_phrase(&phrase, None).unwrap();
        assert!(
            recovery
                .genesis
                .initial_zones
                .iter()
                .any(|z| z.zone_id == "z:owner")
        );
    }

    // ---- Fingerprint format ----

    #[test]
    fn cold_recovery_fingerprint_starts_with_sha256() {
        let phrase = test_phrase();
        let recovery = ColdRecovery::from_phrase(&phrase, None).unwrap();
        assert!(recovery.fingerprint().starts_with("BLAKE3:"));
    }

    #[test]
    fn cold_recovery_fingerprint_has_expected_length() {
        let phrase = test_phrase();
        let recovery = ColdRecovery::from_phrase(&phrase, None).unwrap();
        let fp = recovery.fingerprint();
        // "BLAKE3:" prefix + 16 chars base64
        assert_eq!(fp.len(), 7 + 16);
    }

    // ---- Owner keypair consistency ----

    #[test]
    fn cold_recovery_owner_keypair_deterministic() {
        let phrase = test_phrase();
        let r1 = ColdRecovery::from_phrase(&phrase, None).unwrap();
        let r2 = ColdRecovery::from_phrase(&phrase, None).unwrap();
        assert_eq!(
            r1.owner_keypair.public().to_bytes(),
            r2.owner_keypair.public().to_bytes()
        );
    }

    #[test]
    fn cold_recovery_owner_keypair_matches_genesis_key() {
        let phrase = test_phrase();
        let recovery = ColdRecovery::from_phrase(&phrase, None).unwrap();
        assert_eq!(
            recovery.owner_keypair.public().to_bytes(),
            recovery.genesis.owner_public_key
        );
    }

    // ---- Warning ordering ----

    #[test]
    fn cold_recovery_warning_order_without_fingerprint() {
        let phrase = test_phrase();
        let recovery = ColdRecovery::from_phrase(&phrase, None).unwrap();
        // First warning should be FingerprintNotVerified
        assert_eq!(
            recovery.warnings[0],
            ColdRecoveryWarning::FingerprintNotVerified
        );
        assert_eq!(recovery.warnings[1], ColdRecoveryWarning::NoAuditHistory);
        assert_eq!(
            recovery.warnings[2],
            ColdRecoveryWarning::RevocationStateUnknown
        );
        assert_eq!(recovery.warnings[3], ColdRecoveryWarning::SingleNodeStart);
        assert_eq!(recovery.warnings[4], ColdRecoveryWarning::DataLoss);
    }

    #[test]
    fn cold_recovery_warning_order_with_fingerprint() {
        let phrase = test_phrase();
        let r1 = ColdRecovery::from_phrase(&phrase, None).unwrap();
        let fp = r1.fingerprint();
        let r2 = ColdRecovery::from_phrase(&phrase, Some(&fp)).unwrap();
        // First warning should be NoAuditHistory (no FingerprintNotVerified)
        assert_eq!(r2.warnings[0], ColdRecoveryWarning::NoAuditHistory);
    }

    // ---- ColdRecoveryError Debug ----

    #[test]
    fn cold_recovery_error_debug() {
        let err = ColdRecoveryError::FingerprintMismatch {
            expected: "a".into(),
            actual: "b".into(),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("FingerprintMismatch"));
    }

    // ---- CLI format_warning content ----

    #[test]
    fn cli_format_warning_no_audit_history_content() {
        use super::cli::format_warning;
        let msg = format_warning(&ColdRecoveryWarning::NoAuditHistory);
        assert!(msg.contains("audit"));
    }

    #[test]
    fn cli_format_warning_data_loss_content() {
        use super::cli::format_warning;
        let msg = format_warning(&ColdRecoveryWarning::DataLoss);
        assert!(msg.contains("LOST"));
    }

    #[test]
    fn cli_format_warning_fingerprint_not_verified_content() {
        use super::cli::format_warning;
        let msg = format_warning(&ColdRecoveryWarning::FingerprintNotVerified);
        assert!(msg.contains("fingerprint"));
    }

    // ---- CLI prompts with different states ----

    #[test]
    fn cli_prompts_all_false() {
        let prompts = super::cli::ColdRecoveryPrompts {
            confirmed_no_backup: false,
            confirmed_data_loss: false,
            expected_fingerprint: None,
        };
        assert!(!prompts.confirmed_no_backup);
        assert!(!prompts.confirmed_data_loss);
        assert!(prompts.expected_fingerprint.is_none());
    }

    // ---- ColdRecoveryWarning Debug ----

    #[test]
    fn cold_recovery_warning_debug_all_variants() {
        let variants = [
            ColdRecoveryWarning::NoAuditHistory,
            ColdRecoveryWarning::RevocationStateUnknown,
            ColdRecoveryWarning::SingleNodeStart,
            ColdRecoveryWarning::DataLoss,
            ColdRecoveryWarning::FingerprintNotVerified,
        ];
        for v in &variants {
            let debug = format!("{v:?}");
            assert!(!debug.is_empty());
        }
    }

    // ---- ColdRecoveryError from InvalidPhrase ----

    #[test]
    fn cold_recovery_error_from_invalid_phrase() {
        let phrase_err = crate::recovery_phrase::RecoveryPhraseError::WrongWordCount(12);
        let err: ColdRecoveryError = phrase_err.into();
        let s = err.to_string();
        assert!(s.contains("invalid recovery phrase"));
        assert!(s.contains("12"));
    }

    // ---- ColdRecoveryError Debug for InvalidPhrase variant ----

    #[test]
    fn cold_recovery_error_debug_invalid_phrase() {
        let phrase_err = crate::recovery_phrase::RecoveryPhraseError::InvalidMnemonic("bad".into());
        let err: ColdRecoveryError = phrase_err.into();
        let debug = format!("{err:?}");
        assert!(debug.contains("InvalidPhrase"));
    }

    // ---- ColdRecovery fingerprint is non-empty ----

    #[test]
    fn cold_recovery_fingerprint_is_non_empty() {
        let phrase = test_phrase();
        let recovery = ColdRecovery::from_phrase(&phrase, None).unwrap();
        let fp = recovery.fingerprint();
        assert!(!fp.is_empty());
        assert!(fp.len() > 10);
    }

    // ---- ColdRecovery genesis owner key matches phrase ----

    #[test]
    fn cold_recovery_genesis_owner_key_matches_derived_key() {
        let phrase = test_phrase();
        let recovery = ColdRecovery::from_phrase(&phrase, None).unwrap();
        let derived_pub = phrase.derive_owner_keypair().public().to_bytes();
        assert_eq!(recovery.genesis.owner_public_key, derived_pub);
    }

    // ---- ColdRecovery with different phrases produces different fingerprints ----

    #[test]
    fn cold_recovery_different_phrases_different_fingerprints() {
        let p1 = crate::RecoveryPhrase::generate().unwrap();
        let p2 = crate::RecoveryPhrase::generate().unwrap();
        let r1 = ColdRecovery::from_phrase(&p1, None).unwrap();
        let r2 = ColdRecovery::from_phrase(&p2, None).unwrap();
        assert_ne!(r1.fingerprint(), r2.fingerprint());
    }

    // ---- CLI format_warning contains emoji ----

    #[test]
    fn cli_format_warning_revocation_state_content() {
        use super::cli::format_warning;
        let msg = format_warning(&ColdRecoveryWarning::RevocationStateUnknown);
        assert!(msg.contains("revoked"));
    }

    #[test]
    fn cli_format_warning_single_node_start_content() {
        use super::cli::format_warning;
        let msg = format_warning(&ColdRecoveryWarning::SingleNodeStart);
        assert!(msg.contains("single node"));
    }

    // ---- ColdRecoveryWarning Display exact messages ----

    #[test]
    fn cold_recovery_warning_display_exact_no_audit_history() {
        assert_eq!(
            ColdRecoveryWarning::NoAuditHistory.to_string(),
            "No audit history available - starting fresh"
        );
    }

    #[test]
    fn cold_recovery_warning_display_exact_data_loss() {
        assert_eq!(
            ColdRecoveryWarning::DataLoss.to_string(),
            "Objects created after original genesis will be lost"
        );
    }
}
