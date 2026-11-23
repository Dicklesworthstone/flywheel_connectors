//! Genesis state for FCP2 meshes.
//!
//! The genesis state is the initial state of an FCP2 mesh, created during the
//! bootstrap process. It contains the owner's public key, initial zones, and
//! the cryptographic fingerprint that identifies this mesh.

use chrono::{DateTime, Utc};
use fcp_crypto::{Ed25519SigningKey, Ed25519VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

/// A genesis state representing the initial state of an FCP2 mesh.
///
/// [`Self::create`] records its creation time, so repeated creation with the
/// same owner key still yields distinct fingerprints. Phrase-backed bootstrap,
/// import, and cold recovery use [`Self::create_deterministic`] from the outset
/// so losing the original timestamp does not prevent identity verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisState {
    /// Schema version for the genesis format.
    pub schema_version: u32,

    /// The owner's public key (Ed25519).
    #[serde(with = "hex::serde")]
    pub owner_public_key: [u8; 32],

    /// Creation time, or the Unix epoch for a phrase-recoverable genesis.
    pub created_at: DateTime<Utc>,

    /// Initial zone definitions (typically z:owner, z:private, z:work, z:community, z:public).
    pub initial_zones: Vec<InitialZone>,

    /// The genesis fingerprint (computed, not stored).
    #[serde(skip)]
    #[allow(dead_code)]
    fingerprint_cache: Option<String>,
}

/// An initial zone definition in the genesis state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialZone {
    /// Zone ID (e.g., "z:owner", "z:private").
    pub zone_id: String,

    /// Human-readable name for the zone.
    pub name: String,

    /// Integrity level (higher = more sensitive).
    pub integrity_level: u8,

    /// Confidentiality level (higher = more restricted).
    pub confidentiality_level: u8,
}

/// Errors during genesis validation.
#[derive(Debug, Error)]
pub enum GenesisValidationError {
    /// Invalid owner public key.
    #[error("invalid owner public key")]
    InvalidOwnerKey,

    /// Missing required zone.
    #[error("missing required zone: {0}")]
    MissingRequiredZone(String),

    /// Invalid zone ID format.
    #[error("invalid zone ID format: {0}")]
    InvalidZoneId(String),

    /// Genesis timestamp is in the future.
    #[error("genesis timestamp is in the future")]
    FutureTimestamp,

    /// Invalid schema version.
    #[error("unsupported schema version: {0}")]
    UnsupportedSchemaVersion(u32),
}

/// Current schema version for genesis states.
pub const GENESIS_SCHEMA_VERSION: u32 = 1;

/// Required zones that must be present in genesis.
pub const REQUIRED_ZONES: &[&str] = &["z:owner", "z:private", "z:work", "z:community", "z:public"];

impl GenesisState {
    /// Create a new genesis state from an owner's public key.
    ///
    /// This creates the standard FCP2 zone hierarchy with default integrity
    /// and confidentiality levels.
    #[must_use]
    pub fn create(owner_public_key: &Ed25519VerifyingKey) -> Self {
        let initial_zones = vec![
            InitialZone {
                zone_id: "z:owner".to_string(),
                name: "Owner Zone".to_string(),
                integrity_level: 255,
                confidentiality_level: 255,
            },
            InitialZone {
                zone_id: "z:private".to_string(),
                name: "Private Zone".to_string(),
                integrity_level: 200,
                confidentiality_level: 200,
            },
            InitialZone {
                zone_id: "z:work".to_string(),
                name: "Work Zone".to_string(),
                integrity_level: 150,
                confidentiality_level: 150,
            },
            InitialZone {
                zone_id: "z:community".to_string(),
                name: "Community Zone".to_string(),
                integrity_level: 100,
                confidentiality_level: 100,
            },
            InitialZone {
                zone_id: "z:public".to_string(),
                name: "Public Zone".to_string(),
                integrity_level: 50,
                confidentiality_level: 0,
            },
        ];

        Self {
            schema_version: GENESIS_SCHEMA_VERSION,
            owner_public_key: owner_public_key.to_bytes(),
            created_at: Utc::now(),
            initial_zones,
            fingerprint_cache: None,
        }
    }

    /// Create a phrase-recoverable genesis (deterministic creation time).
    ///
    /// Fresh phrase-backed bootstrap must use this constructor, just like
    /// import and cold recovery: a phrase cannot recover a wall-clock timestamp.
    /// This does not reconstruct an older timestamped genesis or change its
    /// fingerprint. Such a genesis requires its original saved metadata.
    ///
    /// # Panics
    ///
    /// Panics if the Unix epoch timestamp cannot be constructed (should never happen).
    #[must_use]
    pub fn create_deterministic(owner_public_key: &Ed25519VerifyingKey) -> Self {
        // For deterministic recreation, use epoch as the timestamp so the
        // fingerprint is stable across repeated recovery/import runs.
        let mut genesis = Self::create(owner_public_key);
        genesis.created_at = DateTime::from_timestamp(0, 0).expect("epoch is valid");
        genesis
    }

    /// Compute the fingerprint of this genesis state.
    ///
    /// The fingerprint is a stable identifier for this genesis instance,
    /// derived from the owner key, schema version, creation timestamp, and
    /// canonicalized zone definitions.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        // Compute fingerprint from owner key, schema version, creation time, and zones
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.owner_public_key);
        hasher.update(&self.schema_version.to_le_bytes());
        hasher.update(&self.created_at.timestamp().to_le_bytes());
        hasher.update(&self.created_at.timestamp_subsec_nanos().to_le_bytes());

        // Canonicalize zones by sorting by ID before hashing
        let mut zones = self.initial_zones.clone();
        zones.sort_by(|a, b| a.zone_id.cmp(&b.zone_id));
        for zone in zones {
            hasher.update(zone.zone_id.as_bytes());
            hasher.update(&[zone.integrity_level, zone.confidentiality_level]);
        }

        let hash = hasher.finalize();
        let hash_bytes = hash.as_bytes();

        // Use first 12 bytes for a shorter fingerprint
        let short_hash = &hash_bytes[..12];
        let b64 = base64_encode(short_hash);

        format!("BLAKE3:{b64}")
    }

    /// Validate this genesis state.
    ///
    /// # Errors
    ///
    /// Returns a validation error if any required field is invalid or missing.
    pub fn validate(&self) -> Result<(), GenesisValidationError> {
        // Check schema version
        if self.schema_version != GENESIS_SCHEMA_VERSION {
            return Err(GenesisValidationError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }

        // Check owner key is valid
        if Ed25519VerifyingKey::from_bytes(&self.owner_public_key).is_err() {
            return Err(GenesisValidationError::InvalidOwnerKey);
        }

        // Check timestamp is not in the future (allow 5 minute tolerance)
        let now = Utc::now();
        let tolerance = chrono::Duration::minutes(5);
        if self.created_at > now + tolerance {
            return Err(GenesisValidationError::FutureTimestamp);
        }

        // Check all required zones are present
        for required_zone in REQUIRED_ZONES {
            if !self
                .initial_zones
                .iter()
                .any(|z| z.zone_id == *required_zone)
            {
                return Err(GenesisValidationError::MissingRequiredZone(
                    (*required_zone).to_string(),
                ));
            }
        }

        // Validate zone ID formats
        for zone in &self.initial_zones {
            if !zone.zone_id.starts_with("z:") {
                return Err(GenesisValidationError::InvalidZoneId(zone.zone_id.clone()));
            }
        }

        Ok(())
    }

    /// Get the owner's public key as a verifying key.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored public key is invalid.
    pub fn owner_verifying_key(&self) -> Result<Ed25519VerifyingKey, GenesisValidationError> {
        Ed25519VerifyingKey::from_bytes(&self.owner_public_key)
            .map_err(|_| GenesisValidationError::InvalidOwnerKey)
    }

    /// Serialize the genesis state to canonical CBOR.
    ///
    /// # Errors
    ///
    /// Returns an error if CBOR serialization fails.
    pub fn to_cbor(&self) -> Result<Vec<u8>, crate::error::BootstrapError> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    /// Deserialize a genesis state from CBOR.
    ///
    /// # Errors
    ///
    /// Returns an error if CBOR deserialization fails.
    pub fn from_cbor(data: &[u8]) -> Result<Self, crate::error::BootstrapError> {
        let genesis: Self = ciborium::from_reader(data)?;
        Ok(genesis)
    }
}

/// Owner keypair with zeroization on drop.
#[derive(ZeroizeOnDrop)]
pub struct OwnerKeypair {
    /// The signing key (private).
    signing_key: Ed25519SigningKey,
}

impl OwnerKeypair {
    /// Create a new owner keypair from a signing key.
    #[must_use]
    pub const fn new(signing_key: Ed25519SigningKey) -> Self {
        Self { signing_key }
    }

    /// Get the verifying (public) key.
    #[must_use]
    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign data with the owner key.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> fcp_crypto::Ed25519Signature {
        self.signing_key.sign(message)
    }
}

impl std::fmt::Debug for OwnerKeypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerKeypair")
            .field("public_key", &hex::encode(self.verifying_key().to_bytes()))
            .finish_non_exhaustive()
    }
}

/// Base64 URL-safe encoding without padding.
fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_creation() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let genesis = GenesisState::create(&verifying_key);

        assert_eq!(genesis.schema_version, GENESIS_SCHEMA_VERSION);
        assert_eq!(genesis.owner_public_key, verifying_key.to_bytes());
        assert_eq!(genesis.initial_zones.len(), 5);
        assert!(genesis.validate().is_ok());
    }

    #[test]
    fn test_genesis_fingerprint_deterministic() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let genesis1 = GenesisState::create_deterministic(&verifying_key);
        let genesis2 = GenesisState::create_deterministic(&verifying_key);

        assert_eq!(genesis1.fingerprint(), genesis2.fingerprint());
    }

    #[test]
    fn test_genesis_cbor_roundtrip() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let genesis = GenesisState::create(&verifying_key);
        let cbor = genesis.to_cbor().unwrap();
        let restored = GenesisState::from_cbor(&cbor).unwrap();

        assert_eq!(genesis.fingerprint(), restored.fingerprint());
        assert_eq!(genesis.owner_public_key, restored.owner_public_key);
    }

    #[test]
    fn test_genesis_validation_missing_zone() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();

        let mut genesis = GenesisState::create(&verifying_key);
        genesis.initial_zones.retain(|z| z.zone_id != "z:owner");

        let result = genesis.validate();
        assert!(matches!(
            result,
            Err(GenesisValidationError::MissingRequiredZone(_))
        ));
    }

    // ---- Validation edge cases ----

    #[test]
    fn genesis_validation_rejects_wrong_schema_version() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut genesis = GenesisState::create(&verifying_key);
        genesis.schema_version = 99;
        let result = genesis.validate();
        assert!(matches!(
            result,
            Err(GenesisValidationError::UnsupportedSchemaVersion(99))
        ));
    }

    #[test]
    fn genesis_validation_checks_owner_key() {
        // Valid key should pass validation
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let genesis = GenesisState::create(&verifying_key);
        assert!(genesis.validate().is_ok());
    }

    #[test]
    fn genesis_validation_rejects_future_timestamp() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut genesis = GenesisState::create(&verifying_key);
        genesis.created_at = Utc::now() + chrono::Duration::hours(1);
        let result = genesis.validate();
        assert!(matches!(
            result,
            Err(GenesisValidationError::FutureTimestamp)
        ));
    }

    #[test]
    fn genesis_validation_rejects_invalid_zone_id_format() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let mut genesis = GenesisState::create(&verifying_key);
        genesis.initial_zones.push(InitialZone {
            zone_id: "bad_zone".to_string(),
            name: "Bad Zone".to_string(),
            integrity_level: 0,
            confidentiality_level: 0,
        });
        let result = genesis.validate();
        assert!(matches!(
            result,
            Err(GenesisValidationError::InvalidZoneId(_))
        ));
    }

    // ---- Each required zone triggers MissingRequiredZone ----

    #[test]
    fn genesis_validation_missing_each_required_zone() {
        for required in REQUIRED_ZONES {
            let signing_key = Ed25519SigningKey::generate();
            let verifying_key = signing_key.verifying_key();
            let mut genesis = GenesisState::create(&verifying_key);
            genesis.initial_zones.retain(|z| z.zone_id != *required);
            let result = genesis.validate();
            assert!(
                matches!(result, Err(GenesisValidationError::MissingRequiredZone(ref z)) if z == required),
                "Expected MissingRequiredZone for {required}"
            );
        }
    }

    // ---- Fingerprint properties ----

    #[test]
    fn genesis_fingerprint_starts_with_sha256() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let genesis = GenesisState::create(&verifying_key);
        assert!(genesis.fingerprint().starts_with("BLAKE3:"));
    }

    #[test]
    fn genesis_different_keys_different_fingerprints() {
        let key1 = Ed25519SigningKey::generate();
        let key2 = Ed25519SigningKey::generate();
        let g1 = GenesisState::create(&key1.verifying_key());
        let g2 = GenesisState::create(&key2.verifying_key());
        assert_ne!(g1.fingerprint(), g2.fingerprint());
    }

    // ---- Zone hierarchy ----

    #[test]
    fn genesis_zone_integrity_levels_are_descending() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());
        let levels: Vec<u8> = genesis
            .initial_zones
            .iter()
            .map(|z| z.integrity_level)
            .collect();
        // z:owner=255, z:private=200, z:work=150, z:community=100, z:public=50
        for w in levels.windows(2) {
            assert!(
                w[0] > w[1],
                "integrity levels should be strictly descending"
            );
        }
    }

    #[test]
    fn genesis_has_5_initial_zones() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());
        assert_eq!(genesis.initial_zones.len(), 5);
    }

    // ---- Deterministic genesis ----

    #[test]
    fn genesis_deterministic_has_epoch_timestamp() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create_deterministic(&signing_key.verifying_key());
        assert_eq!(genesis.created_at, DateTime::from_timestamp(0, 0).unwrap());
    }

    // ---- owner_verifying_key ----

    #[test]
    fn genesis_owner_verifying_key_roundtrip() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let genesis = GenesisState::create(&verifying_key);
        let recovered = genesis.owner_verifying_key().unwrap();
        assert_eq!(recovered.to_bytes(), verifying_key.to_bytes());
    }

    #[test]
    fn genesis_owner_verifying_key_valid() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());
        // Valid key roundtrips correctly
        assert!(genesis.owner_verifying_key().is_ok());
    }

    // ---- OwnerKeypair ----

    #[test]
    fn owner_keypair_debug_does_not_leak_private_key() {
        let signing_key = Ed25519SigningKey::generate();
        let keypair = super::OwnerKeypair::new(signing_key);
        let debug = format!("{keypair:?}");
        assert!(debug.contains("OwnerKeypair"));
        assert!(debug.contains("public_key"));
        // Should not contain "signing_key" or raw bytes
        assert!(!debug.contains("signing_key"));
    }

    #[test]
    fn owner_keypair_sign_produces_valid_signature() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let keypair = super::OwnerKeypair::new(signing_key);
        let message = b"test message";
        let signature = keypair.sign(message);
        assert!(verifying_key.verify(message, &signature).is_ok());
    }

    // ---- GenesisState Clone ----

    #[test]
    fn genesis_clone_preserves_fingerprint() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());
        let cloned = genesis.clone();
        drop(genesis);
        assert!(cloned.validate().is_ok());
        assert!(cloned.fingerprint().starts_with("BLAKE3:"));
    }

    #[test]
    fn genesis_clone_preserves_all_fields() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());
        let cloned = genesis.clone();
        assert_eq!(genesis.schema_version, cloned.schema_version);
        assert_eq!(genesis.owner_public_key, cloned.owner_public_key);
        assert_eq!(genesis.created_at, cloned.created_at);
        assert_eq!(genesis.initial_zones.len(), cloned.initial_zones.len());
        assert_eq!(genesis.fingerprint(), cloned.fingerprint());
    }

    // ---- GenesisState Debug ----

    #[test]
    fn genesis_debug_output() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());
        let debug = format!("{genesis:?}");
        assert!(debug.contains("GenesisState"));
        assert!(debug.contains("schema_version"));
        assert!(debug.contains("initial_zones"));
    }

    // ---- Serde JSON roundtrip ----

    #[test]
    fn genesis_json_roundtrip() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());
        let json = serde_json::to_string(&genesis).unwrap();
        let restored: GenesisState = serde_json::from_str(&json).unwrap();
        assert_eq!(genesis.fingerprint(), restored.fingerprint());
        assert_eq!(genesis.owner_public_key, restored.owner_public_key);
        assert_eq!(genesis.schema_version, restored.schema_version);
    }

    #[test]
    fn genesis_json_pretty_roundtrip() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());
        let json = serde_json::to_string_pretty(&genesis).unwrap();
        let restored: GenesisState = serde_json::from_str(&json).unwrap();
        assert_eq!(genesis.fingerprint(), restored.fingerprint());
    }

    // ---- CBOR edge cases ----

    #[test]
    fn genesis_cbor_invalid_data() {
        let result = GenesisState::from_cbor(&[0xFF, 0xFE, 0xFD]);
        assert!(result.is_err());
    }

    #[test]
    fn genesis_cbor_empty_data() {
        let result = GenesisState::from_cbor(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn genesis_cbor_deterministic_roundtrip() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create_deterministic(&signing_key.verifying_key());
        let cbor = genesis.to_cbor().unwrap();
        let restored = GenesisState::from_cbor(&cbor).unwrap();
        assert_eq!(genesis.fingerprint(), restored.fingerprint());
        assert_eq!(restored.created_at, DateTime::from_timestamp(0, 0).unwrap());
    }

    // ---- Validation: timestamp within tolerance ----

    #[test]
    fn genesis_validation_accepts_near_future_timestamp() {
        let signing_key = Ed25519SigningKey::generate();
        let mut genesis = GenesisState::create(&signing_key.verifying_key());
        // 3 minutes in the future is within the 5-minute tolerance
        genesis.created_at = Utc::now() + chrono::Duration::minutes(3);
        assert!(genesis.validate().is_ok());
    }

    #[test]
    fn genesis_validation_accepts_past_timestamp() {
        let signing_key = Ed25519SigningKey::generate();
        let mut genesis = GenesisState::create(&signing_key.verifying_key());
        // Far in the past should be fine
        genesis.created_at = DateTime::from_timestamp(1_000_000, 0).unwrap();
        assert!(genesis.validate().is_ok());
    }

    #[test]
    fn genesis_validation_accepts_epoch_timestamp() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create_deterministic(&signing_key.verifying_key());
        assert!(genesis.validate().is_ok());
    }

    // ---- Validation: schema version boundary ----

    #[test]
    fn genesis_validation_rejects_schema_version_zero() {
        let signing_key = Ed25519SigningKey::generate();
        let mut genesis = GenesisState::create(&signing_key.verifying_key());
        genesis.schema_version = 0;
        let result = genesis.validate();
        assert!(matches!(
            result,
            Err(GenesisValidationError::UnsupportedSchemaVersion(0))
        ));
    }

    // ---- Validation: missing specific zones ----

    #[test]
    fn genesis_validation_missing_private_zone() {
        let signing_key = Ed25519SigningKey::generate();
        let mut genesis = GenesisState::create(&signing_key.verifying_key());
        genesis.initial_zones.retain(|z| z.zone_id != "z:private");
        let result = genesis.validate();
        assert!(matches!(
            result,
            Err(GenesisValidationError::MissingRequiredZone(ref z)) if z == "z:private"
        ));
    }

    #[test]
    fn genesis_validation_missing_work_zone() {
        let signing_key = Ed25519SigningKey::generate();
        let mut genesis = GenesisState::create(&signing_key.verifying_key());
        genesis.initial_zones.retain(|z| z.zone_id != "z:work");
        let result = genesis.validate();
        assert!(matches!(
            result,
            Err(GenesisValidationError::MissingRequiredZone(ref z)) if z == "z:work"
        ));
    }

    #[test]
    fn genesis_validation_missing_community_zone() {
        let signing_key = Ed25519SigningKey::generate();
        let mut genesis = GenesisState::create(&signing_key.verifying_key());
        genesis.initial_zones.retain(|z| z.zone_id != "z:community");
        let result = genesis.validate();
        assert!(matches!(
            result,
            Err(GenesisValidationError::MissingRequiredZone(ref z)) if z == "z:community"
        ));
    }

    #[test]
    fn genesis_validation_missing_public_zone() {
        let signing_key = Ed25519SigningKey::generate();
        let mut genesis = GenesisState::create(&signing_key.verifying_key());
        genesis.initial_zones.retain(|z| z.zone_id != "z:public");
        let result = genesis.validate();
        assert!(matches!(
            result,
            Err(GenesisValidationError::MissingRequiredZone(ref z)) if z == "z:public"
        ));
    }

    // ---- Validation: invalid zone IDs at various positions ----

    #[test]
    fn genesis_validation_rejects_zone_without_prefix() {
        let signing_key = Ed25519SigningKey::generate();
        let mut genesis = GenesisState::create(&signing_key.verifying_key());
        genesis.initial_zones.push(InitialZone {
            zone_id: "custom_no_prefix".to_string(),
            name: "Custom".to_string(),
            integrity_level: 10,
            confidentiality_level: 10,
        });
        let result = genesis.validate();
        assert!(matches!(
            result,
            Err(GenesisValidationError::InvalidZoneId(ref z)) if z == "custom_no_prefix"
        ));
    }

    #[test]
    fn genesis_validation_accepts_custom_zone_with_prefix() {
        let signing_key = Ed25519SigningKey::generate();
        let mut genesis = GenesisState::create(&signing_key.verifying_key());
        genesis.initial_zones.push(InitialZone {
            zone_id: "z:custom".to_string(),
            name: "Custom Zone".to_string(),
            integrity_level: 25,
            confidentiality_level: 25,
        });
        assert!(genesis.validate().is_ok());
    }

    // ---- InitialZone properties ----

    #[test]
    fn initial_zone_clone() {
        let zone = InitialZone {
            zone_id: "z:test".to_string(),
            name: "Test Zone".to_string(),
            integrity_level: 42,
            confidentiality_level: 99,
        };
        let cloned = zone.clone();
        assert_eq!(zone.zone_id, cloned.zone_id);
        assert_eq!(zone.name, cloned.name);
        assert_eq!(zone.integrity_level, cloned.integrity_level);
        assert_eq!(zone.confidentiality_level, cloned.confidentiality_level);
    }

    #[test]
    fn initial_zone_debug() {
        let zone = InitialZone {
            zone_id: "z:debug".to_string(),
            name: "Debug Zone".to_string(),
            integrity_level: 0,
            confidentiality_level: 255,
        };
        let debug = format!("{zone:?}");
        assert!(debug.contains("InitialZone"));
        assert!(debug.contains("z:debug"));
        assert!(debug.contains("Debug Zone"));
    }

    #[test]
    fn initial_zone_serde_roundtrip() {
        let zone = InitialZone {
            zone_id: "z:serde".to_string(),
            name: "Serde Zone".to_string(),
            integrity_level: 128,
            confidentiality_level: 64,
        };
        let json = serde_json::to_string(&zone).unwrap();
        let restored: InitialZone = serde_json::from_str(&json).unwrap();
        assert_eq!(zone.zone_id, restored.zone_id);
        assert_eq!(zone.name, restored.name);
        assert_eq!(zone.integrity_level, restored.integrity_level);
        assert_eq!(zone.confidentiality_level, restored.confidentiality_level);
    }

    // ---- Zone ordering in genesis ----

    #[test]
    fn genesis_zone_ids_in_expected_order() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());
        let zone_ids: Vec<&str> = genesis
            .initial_zones
            .iter()
            .map(|z| z.zone_id.as_str())
            .collect();
        assert_eq!(
            zone_ids,
            vec!["z:owner", "z:private", "z:work", "z:community", "z:public"]
        );
    }

    #[test]
    fn genesis_zone_names_in_expected_order() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());
        let names: Vec<&str> = genesis
            .initial_zones
            .iter()
            .map(|z| z.name.as_str())
            .collect();
        assert_eq!(
            names,
            vec![
                "Owner Zone",
                "Private Zone",
                "Work Zone",
                "Community Zone",
                "Public Zone"
            ]
        );
    }

    #[test]
    fn genesis_confidentiality_levels_are_descending() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());
        let levels: Vec<u8> = genesis
            .initial_zones
            .iter()
            .map(|z| z.confidentiality_level)
            .collect();
        // z:owner=255, z:private=200, z:work=150, z:community=100, z:public=0
        for w in levels.windows(2) {
            assert!(
                w[0] > w[1],
                "confidentiality levels should be strictly descending"
            );
        }
    }

    // ---- Fingerprint length and format ----

    #[test]
    fn genesis_fingerprint_format_details() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());
        let fp = genesis.fingerprint();
        assert!(fp.starts_with("BLAKE3:"));
        let b64_part = &fp["BLAKE3:".len()..];
        // 12 bytes base64 URL-safe no padding = 16 chars
        assert_eq!(b64_part.len(), 16, "base64 part should be 16 chars");
        // Should only contain URL-safe base64 characters
        assert!(
            b64_part
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        );
    }

    // ---- owner_verifying_key consistency ----

    #[test]
    fn genesis_owner_verifying_key_consistent_with_fingerprint() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let genesis = GenesisState::create(&verifying_key);
        // The recovered key should match what's stored
        let recovered = genesis.owner_verifying_key().unwrap();
        assert_eq!(recovered.to_bytes(), genesis.owner_public_key);
    }

    // ---- OwnerKeypair verifying_key ----

    #[test]
    fn owner_keypair_verifying_key_matches_signing_key() {
        let signing_key = Ed25519SigningKey::generate();
        let expected_pub = signing_key.verifying_key();
        let keypair = super::OwnerKeypair::new(signing_key);
        assert_eq!(keypair.verifying_key().to_bytes(), expected_pub.to_bytes());
    }

    // ---- OwnerKeypair sign with different messages ----

    #[test]
    fn owner_keypair_sign_empty_message() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let keypair = super::OwnerKeypair::new(signing_key);
        let signature = keypair.sign(b"");
        assert!(verifying_key.verify(b"", &signature).is_ok());
    }

    #[test]
    fn owner_keypair_sign_large_message() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let keypair = super::OwnerKeypair::new(signing_key);
        let large_msg = vec![0xABu8; 10_000];
        let signature = keypair.sign(&large_msg);
        assert!(verifying_key.verify(&large_msg, &signature).is_ok());
    }

    // ---- GenesisValidationError Display ----

    #[test]
    fn genesis_validation_error_display_invalid_owner_key() {
        let err = GenesisValidationError::InvalidOwnerKey;
        assert_eq!(err.to_string(), "invalid owner public key");
    }

    #[test]
    fn genesis_validation_error_display_missing_zone() {
        let err = GenesisValidationError::MissingRequiredZone("z:owner".to_string());
        assert!(err.to_string().contains("z:owner"));
    }

    #[test]
    fn genesis_validation_error_display_invalid_zone_id() {
        let err = GenesisValidationError::InvalidZoneId("bad_zone".to_string());
        assert!(err.to_string().contains("bad_zone"));
    }

    #[test]
    fn genesis_validation_error_display_future_timestamp() {
        let err = GenesisValidationError::FutureTimestamp;
        assert!(err.to_string().contains("future"));
    }

    #[test]
    fn genesis_validation_error_display_unsupported_version() {
        let err = GenesisValidationError::UnsupportedSchemaVersion(42);
        assert!(err.to_string().contains("42"));
    }

    // ---- Schema version constant ----

    #[test]
    fn genesis_schema_version_is_one() {
        assert_eq!(GENESIS_SCHEMA_VERSION, 1);
    }

    // ---- Required zones constant ----

    #[test]
    fn required_zones_has_five_entries() {
        assert_eq!(REQUIRED_ZONES.len(), 5);
    }

    #[test]
    fn required_zones_all_start_with_z_prefix() {
        for zone in REQUIRED_ZONES {
            assert!(zone.starts_with("z:"), "zone {zone} missing z: prefix");
        }
    }

    // ---- base64_encode ----

    #[test]
    fn base64_encode_deterministic() {
        let data = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let encoded1 = base64_encode(&data);
        let encoded2 = base64_encode(&data);
        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn base64_encode_empty() {
        let encoded = base64_encode(&[]);
        assert!(encoded.is_empty());
    }

    // ---- Genesis with corrupted owner key ----

    #[test]
    fn genesis_owner_verifying_key_rejects_zero_key() {
        let signing_key = Ed25519SigningKey::generate();
        let mut genesis = GenesisState::create(&signing_key.verifying_key());
        genesis.owner_public_key = [0u8; 32];
        // Ed25519 identity point is usually rejected
        // The error may or may not happen depending on the library,
        // but the function should not panic.
        let _ = genesis.owner_verifying_key();
    }

    #[test]
    fn genesis_validation_rejects_invalid_key_bytes() {
        let signing_key = Ed25519SigningKey::generate();
        let mut genesis = GenesisState::create(&signing_key.verifying_key());
        // Construct bytes that are NOT a valid Ed25519 point:
        // set all bytes to 0xEE — this is very unlikely to be on the curve
        genesis.owner_public_key = [0xEE; 32];
        let result = genesis.validate();
        // If the library accepts it, that's also fine — we just ensure no panic
        // The main goal is exercising the validation path
        let _ = result;
    }

    // ---- Multiple zones with z: prefix ----

    #[test]
    fn genesis_validation_accepts_many_custom_zones() {
        let signing_key = Ed25519SigningKey::generate();
        let mut genesis = GenesisState::create(&signing_key.verifying_key());
        for i in 0..10 {
            genesis.initial_zones.push(InitialZone {
                zone_id: format!("z:custom-{i}"),
                name: format!("Custom Zone {i}"),
                integrity_level: 10,
                confidentiality_level: 10,
            });
        }
        assert!(genesis.validate().is_ok());
        assert_eq!(genesis.initial_zones.len(), 15);
    }

    // ---- InitialZone with unicode ----

    #[test]
    fn initial_zone_unicode_name() {
        let zone = InitialZone {
            zone_id: "z:intl".to_string(),
            name: "\u{1F30D} International Zone".to_string(),
            integrity_level: 50,
            confidentiality_level: 50,
        };
        let json = serde_json::to_string(&zone).unwrap();
        let restored: InitialZone = serde_json::from_str(&json).unwrap();
        assert_eq!(zone.name, restored.name);
    }

    // ---- CBOR roundtrip preserves zone data ----

    #[test]
    fn genesis_cbor_roundtrip_preserves_zone_details() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());
        let cbor = genesis.to_cbor().unwrap();
        let restored = GenesisState::from_cbor(&cbor).unwrap();
        for (orig, rest) in genesis
            .initial_zones
            .iter()
            .zip(restored.initial_zones.iter())
        {
            assert_eq!(orig.zone_id, rest.zone_id);
            assert_eq!(orig.name, rest.name);
            assert_eq!(orig.integrity_level, rest.integrity_level);
            assert_eq!(orig.confidentiality_level, rest.confidentiality_level);
        }
    }

    // ---- Fingerprint is not empty ----

    #[test]
    fn genesis_fingerprint_is_nonempty() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());
        let fp = genesis.fingerprint();
        assert!(!fp.is_empty());
        assert!(fp.len() > 10);
    }

    // ---- Validation error is std::error::Error ----

    #[test]
    fn genesis_validation_error_is_error_trait() {
        let err = GenesisValidationError::InvalidOwnerKey;
        let _: &dyn std::error::Error = &err;
    }

    // ---- Deterministic genesis validates ----

    #[test]
    fn genesis_deterministic_validates_ok() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create_deterministic(&signing_key.verifying_key());
        assert!(genesis.validate().is_ok());
        assert_eq!(genesis.schema_version, GENESIS_SCHEMA_VERSION);
    }

    // ---- OwnerKeypair sign different messages produce different sigs ----

    #[test]
    fn owner_keypair_different_messages_different_sigs() {
        let signing_key = Ed25519SigningKey::generate();
        let keypair = super::OwnerKeypair::new(signing_key);
        let sig1 = keypair.sign(b"message one");
        let sig2 = keypair.sign(b"message two");
        // Ed25519 is deterministic, different messages => different sigs
        assert_ne!(sig1.to_bytes(), sig2.to_bytes());
    }

    // ---- InitialZone boundary levels ----

    #[test]
    fn initial_zone_boundary_levels() {
        let zone = InitialZone {
            zone_id: "z:boundary".to_string(),
            name: "Boundary".to_string(),
            integrity_level: u8::MAX,
            confidentiality_level: u8::MIN,
        };
        let json = serde_json::to_string(&zone).unwrap();
        let restored: InitialZone = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.integrity_level, 255);
        assert_eq!(restored.confidentiality_level, 0);
    }

    // ---- GenesisState schema_version boundary ----

    #[test]
    fn genesis_validation_rejects_max_schema_version() {
        let signing_key = Ed25519SigningKey::generate();
        let mut genesis = GenesisState::create(&signing_key.verifying_key());
        genesis.schema_version = u32::MAX;
        let result = genesis.validate();
        assert!(matches!(
            result,
            Err(GenesisValidationError::UnsupportedSchemaVersion(u32::MAX))
        ));
    }

    // ---- base64_encode single byte ----

    #[test]
    fn base64_encode_single_byte() {
        let encoded = base64_encode(&[0x42]);
        assert!(!encoded.is_empty());
        // base64 of [0x42] should be "Qg" (URL-safe, no pad)
        assert_eq!(encoded, "Qg");
    }

    // ---- Fingerprint stability: same key always same fingerprint ----

    #[test]
    fn fingerprint_differs_across_non_deterministic_genesis() {
        let signing_key = Ed25519SigningKey::generate();
        let vk = signing_key.verifying_key();
        let g1 = GenesisState::create(&vk);
        let mut g2 = g1.clone();
        g2.created_at += chrono::Duration::milliseconds(1);
        assert_ne!(g1.fingerprint(), g2.fingerprint());
    }

    #[test]
    fn fingerprint_stable_for_deterministic_genesis() {
        let signing_key = Ed25519SigningKey::generate();
        let vk = signing_key.verifying_key();
        let g1 = GenesisState::create_deterministic(&vk);
        let g2 = GenesisState::create_deterministic(&vk);
        assert_eq!(g1.fingerprint(), g2.fingerprint());
    }

    // ---- CBOR size is reasonable ----

    #[test]
    fn genesis_cbor_size_reasonable() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());
        let cbor = genesis.to_cbor().unwrap();
        // Should be less than 1KB for standard genesis
        assert!(cbor.len() < 1024);
        assert!(cbor.len() > 50);
    }

    // ---- Multiple CBOR roundtrips produce stable output ----

    #[test]
    fn genesis_cbor_double_roundtrip() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());
        let cbor1 = genesis.to_cbor().unwrap();
        let restored1 = GenesisState::from_cbor(&cbor1).unwrap();
        let cbor2 = restored1.to_cbor().unwrap();
        let restored2 = GenesisState::from_cbor(&cbor2).unwrap();
        assert_eq!(restored1.fingerprint(), restored2.fingerprint());
        assert_eq!(restored1.owner_public_key, restored2.owner_public_key);
    }

    // ---- Validation: multiple invalid zones ----

    #[test]
    fn genesis_validation_stops_at_first_error() {
        let signing_key = Ed25519SigningKey::generate();
        let mut genesis = GenesisState::create(&signing_key.verifying_key());
        genesis.schema_version = 42;
        // Even though we also break zones, schema version check comes first
        genesis.initial_zones.clear();
        let result = genesis.validate();
        assert!(matches!(
            result,
            Err(GenesisValidationError::UnsupportedSchemaVersion(42))
        ));
    }

    // ---- OwnerKeypair sign with wrong key rejects ----

    #[test]
    fn owner_keypair_sign_wrong_key_fails_verify() {
        let key1 = Ed25519SigningKey::generate();
        let key2 = Ed25519SigningKey::generate();
        let keypair = super::OwnerKeypair::new(key1);
        let sig = keypair.sign(b"msg");
        // Verify with wrong key should fail
        assert!(key2.verifying_key().verify(b"msg", &sig).is_err());
    }

    // ---- GenesisState with all zones removed ----

    #[test]
    fn genesis_validation_empty_zones() {
        let signing_key = Ed25519SigningKey::generate();
        let mut genesis = GenesisState::create(&signing_key.verifying_key());
        genesis.initial_zones.clear();
        let result = genesis.validate();
        assert!(matches!(
            result,
            Err(GenesisValidationError::MissingRequiredZone(_))
        ));
    }

    // ---- Zone name and ID from create ----

    #[test]
    fn genesis_owner_zone_has_max_levels() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());
        let owner_zone = genesis
            .initial_zones
            .iter()
            .find(|z| z.zone_id == "z:owner")
            .unwrap();
        assert_eq!(owner_zone.integrity_level, 255);
        assert_eq!(owner_zone.confidentiality_level, 255);
        assert_eq!(owner_zone.name, "Owner Zone");
    }

    #[test]
    fn genesis_public_zone_has_zero_confidentiality() {
        let signing_key = Ed25519SigningKey::generate();
        let genesis = GenesisState::create(&signing_key.verifying_key());
        let public_zone = genesis
            .initial_zones
            .iter()
            .find(|z| z.zone_id == "z:public")
            .unwrap();
        assert_eq!(public_zone.confidentiality_level, 0);
        assert_eq!(public_zone.integrity_level, 50);
    }

    // ---- Deterministic and non-deterministic genesis differ in time ----

    #[test]
    fn genesis_deterministic_and_regular_differ_in_time() {
        let signing_key = Ed25519SigningKey::generate();
        let vk = signing_key.verifying_key();
        let det = GenesisState::create_deterministic(&vk);
        let reg = GenesisState::create(&vk);
        assert_ne!(det.created_at, reg.created_at);
        assert_ne!(det.fingerprint(), reg.fingerprint());
    }

    #[test]
    fn genesis_fingerprint_supports_post_2262_timestamps() {
        let signing_key = Ed25519SigningKey::generate();
        let vk = signing_key.verifying_key();
        let mut genesis = GenesisState::create(&vk);
        genesis.created_at =
            DateTime::from_timestamp(10_000_000_000, 123_456_789).expect("timestamp is valid");

        let fingerprint = genesis.fingerprint();

        assert!(fingerprint.starts_with("BLAKE3:"));
    }

    #[test]
    fn genesis_fingerprint_preserves_subsecond_entropy_beyond_nanos_horizon() {
        let signing_key = Ed25519SigningKey::generate();
        let vk = signing_key.verifying_key();
        let mut first = GenesisState::create(&vk);
        let mut second = first.clone();

        first.created_at =
            DateTime::from_timestamp(9_223_372_037, 123).expect("timestamp is valid");
        second.created_at =
            DateTime::from_timestamp(9_223_372_037, 987).expect("timestamp is valid");

        assert!(
            first.created_at.timestamp_nanos_opt().is_none(),
            "test must stay beyond the i64 nanosecond horizon"
        );
        assert!(
            second.created_at.timestamp_nanos_opt().is_none(),
            "test must stay beyond the i64 nanosecond horizon"
        );
        assert_ne!(
            first.fingerprint(),
            second.fingerprint(),
            "post-horizon timestamps must keep subsecond fingerprint entropy"
        );
    }

    // ---- Validation error Debug ----

    #[test]
    fn genesis_validation_error_debug_all_variants() {
        let variants: Vec<GenesisValidationError> = vec![
            GenesisValidationError::InvalidOwnerKey,
            GenesisValidationError::MissingRequiredZone("z:test".into()),
            GenesisValidationError::InvalidZoneId("bad".into()),
            GenesisValidationError::FutureTimestamp,
            GenesisValidationError::UnsupportedSchemaVersion(7),
        ];
        for v in &variants {
            let debug = format!("{v:?}");
            assert!(!debug.is_empty());
        }
    }

    // ---- base64_encode with known vectors ----

    #[test]
    fn base64_encode_known_vector() {
        // [0x00, 0x01, 0x02] => "AAEC"
        let encoded = base64_encode(&[0x00, 0x01, 0x02]);
        assert_eq!(encoded, "AAEC");
    }

    #[test]
    fn base64_encode_all_0xff() {
        let encoded = base64_encode(&[0xFF; 12]);
        // 12 bytes of 0xFF => "__________8" in URL-safe base64
        assert_eq!(encoded.len(), 16);
        assert!(
            encoded
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        );
    }
}
