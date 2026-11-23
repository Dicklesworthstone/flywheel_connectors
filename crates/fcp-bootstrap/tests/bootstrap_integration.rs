//! Bootstrap/Genesis integration tests.
//!
//! Tests for first-run mesh initialization and owner key ceremony.
//! Per flywheel_connectors-8bfb specification.

use chrono::Utc;
use fcp_bootstrap::{
    BootstrapConfig, BootstrapError, BootstrapMode, BootstrapWorkflow, ColdRecovery, DetectedToken,
    GenesisState, GenesisValidationError, RecoveryPhrase, RecoveryPhraseError,
};
use fcp_crypto::Ed25519SigningKey;
use serde::Serialize;
use std::path::PathBuf;
use tempfile::TempDir;
use uuid::Uuid;

// ─────────────────────────────────────────────────────────────────────────────
// Test Logging Infrastructure (per 1n78.35)
// ─────────────────────────────────────────────────────────────────────────────

/// Structured log entry for test output.
#[derive(Debug, Serialize)]
struct TestLogEntry {
    timestamp: String,
    test_name: &'static str,
    phase: &'static str,
    correlation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    genesis_objects: Option<Vec<&'static str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_pubkey_fingerprint: Option<String>,
    result: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

impl TestLogEntry {
    fn new(test_name: &'static str, phase: &'static str) -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            test_name,
            phase,
            correlation_id: Uuid::new_v4().to_string(),
            genesis_objects: None,
            owner_pubkey_fingerprint: None,
            result: "pending",
            error: None,
            details: None,
        }
    }

    const fn with_result(mut self, result: &'static str) -> Self {
        self.result = result;
        self
    }

    fn with_error(mut self, error: &impl ToString) -> Self {
        self.error = Some(error.to_string());
        self.result = "fail";
        self
    }

    fn with_genesis_objects(mut self, objects: Vec<&'static str>) -> Self {
        self.genesis_objects = Some(objects);
        self
    }

    fn with_fingerprint(mut self, fingerprint: &impl ToString) -> Self {
        self.owner_pubkey_fingerprint = Some(fingerprint.to_string());
        self
    }

    fn emit(&self) {
        if let Ok(json) = serde_json::to_string(self) {
            println!("{json}");
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Owner Key Generation Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_owner_key_generation_succeeds() {
    let mut log = TestLogEntry::new("test_owner_key_generation_succeeds", "execute");

    // Generate a recovery phrase with 256 bits of entropy
    let phrase = RecoveryPhrase::generate().expect("should generate phrase");

    // Derive owner keypair
    let keypair = phrase.derive_owner_keypair();
    let public_key = keypair.public();

    log = log
        .with_fingerprint(&hex::encode(public_key.to_bytes()))
        .with_result("pass");
    log.emit();

    // Verify the keypair is valid by checking we can sign and verify
    let test_message = b"test message for signature verification";
    let signature = keypair.sign(test_message);
    assert!(
        public_key.verify(test_message, &signature).is_ok(),
        "signature should verify"
    );
}

#[test]
fn test_recovery_phrase_has_24_words() {
    let mut log = TestLogEntry::new("test_recovery_phrase_has_24_words", "execute");

    let phrase = RecoveryPhrase::generate().expect("should generate phrase");
    let words = phrase.words();

    log = log
        .with_result(if words.len() == 24 { "pass" } else { "fail" })
        .with_fingerprint(&format!("word_count={}", words.len()));
    log.emit();

    assert_eq!(
        words.len(),
        24,
        "recovery phrase must have exactly 24 words"
    );
}

#[test]
fn test_public_key_fingerprint_is_stable() {
    let mut log = TestLogEntry::new("test_public_key_fingerprint_is_stable", "execute");

    // Use a deterministic test phrase
    let test_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    let phrase = RecoveryPhrase::from_mnemonic(test_phrase).expect("valid phrase");

    // Derive keypair multiple times
    let keypair1 = phrase.derive_owner_keypair();
    let keypair2 = phrase.derive_owner_keypair();

    let pk1_hex = hex::encode(keypair1.public().to_bytes());
    let pk2_hex = hex::encode(keypair2.public().to_bytes());

    log = log
        .with_fingerprint(&pk1_hex)
        .with_result(if pk1_hex == pk2_hex { "pass" } else { "fail" });
    log.emit();

    assert_eq!(pk1_hex, pk2_hex, "same phrase must derive same public key");
}

#[test]
fn test_different_phrases_yield_different_keys() {
    let log = TestLogEntry::new("test_different_phrases_yield_different_keys", "execute");

    let phrase1 = RecoveryPhrase::generate().expect("generate phrase 1");
    let phrase2 = RecoveryPhrase::generate().expect("generate phrase 2");

    let pk1 = phrase1.derive_owner_keypair().public().to_bytes();
    let pk2 = phrase2.derive_owner_keypair().public().to_bytes();

    let result = if pk1 == pk2 { "fail" } else { "pass" };
    log.with_result(result).emit();

    assert_ne!(pk1, pk2, "different phrases must yield different keys");
}

// ─────────────────────────────────────────────────────────────────────────────
// Genesis Object Creation Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_genesis_state_has_all_required_zones() {
    let mut log = TestLogEntry::new("test_genesis_state_has_all_required_zones", "execute");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let genesis = GenesisState::create(&verifying_key);

    let required_zones = ["z:owner", "z:private", "z:work", "z:community", "z:public"];
    let zone_ids: Vec<&str> = genesis
        .initial_zones
        .iter()
        .map(|z| z.zone_id.as_str())
        .collect();

    let all_present = required_zones.iter().all(|z| zone_ids.contains(z));

    log = log
        .with_genesis_objects(required_zones.to_vec())
        .with_fingerprint(&genesis.fingerprint())
        .with_result(if all_present { "pass" } else { "fail" });
    log.emit();

    for zone in required_zones {
        assert!(
            zone_ids.contains(&zone),
            "genesis must contain zone: {zone}"
        );
    }
}

#[test]
fn test_genesis_fingerprint_is_deterministic() {
    let mut log = TestLogEntry::new("test_genesis_fingerprint_is_deterministic", "execute");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();

    // Create deterministic genesis states
    let genesis1 = GenesisState::create_deterministic(&verifying_key);
    let genesis2 = GenesisState::create_deterministic(&verifying_key);

    let fp1 = genesis1.fingerprint();
    let fp2 = genesis2.fingerprint();

    log = log
        .with_fingerprint(&fp1)
        .with_result(if fp1 == fp2 { "pass" } else { "fail" });
    log.emit();

    assert_eq!(fp1, fp2, "deterministic genesis must have same fingerprint");
}

#[test]
fn test_genesis_cbor_serialization_roundtrip() {
    let mut log = TestLogEntry::new("test_genesis_cbor_serialization_roundtrip", "execute");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let genesis = GenesisState::create(&verifying_key);

    // Serialize to CBOR
    let cbor_bytes = genesis.to_cbor().expect("serialize to CBOR");

    // Deserialize back
    let restored = GenesisState::from_cbor(&cbor_bytes).expect("deserialize from CBOR");

    let matches = genesis.fingerprint() == restored.fingerprint()
        && genesis.owner_public_key == restored.owner_public_key;

    log = log
        .with_genesis_objects(vec!["genesis_state"])
        .with_fingerprint(&genesis.fingerprint())
        .with_result(if matches { "pass" } else { "fail" });
    log.emit();

    assert_eq!(
        genesis.fingerprint(),
        restored.fingerprint(),
        "fingerprint must match after roundtrip"
    );
    assert_eq!(
        genesis.owner_public_key, restored.owner_public_key,
        "owner key must match after roundtrip"
    );
}

#[test]
fn test_genesis_validation_rejects_missing_zone() {
    let mut log = TestLogEntry::new("test_genesis_validation_rejects_missing_zone", "execute");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let mut genesis = GenesisState::create(&verifying_key);

    // Remove z:owner zone
    genesis.initial_zones.retain(|z| z.zone_id != "z:owner");

    let result = genesis.validate();

    let is_correct_error = matches!(result, Err(GenesisValidationError::MissingRequiredZone(_)));

    log = log.with_result(if is_correct_error { "pass" } else { "fail" });
    log.emit();

    assert!(
        is_correct_error,
        "validation must reject genesis with missing required zone"
    );
}

#[test]
fn test_genesis_validation_rejects_invalid_zone_id() {
    let mut log = TestLogEntry::new("test_genesis_validation_rejects_invalid_zone_id", "execute");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let mut genesis = GenesisState::create(&verifying_key);

    // Add an invalid zone ID (doesn't start with "z:")
    genesis
        .initial_zones
        .push(fcp_bootstrap::genesis::InitialZone {
            zone_id: "invalid-zone".to_string(),
            name: "Invalid Zone".to_string(),
            integrity_level: 100,
            confidentiality_level: 100,
        });

    let result = genesis.validate();

    let is_correct_error = matches!(result, Err(GenesisValidationError::InvalidZoneId(_)));

    log = log.with_result(if is_correct_error { "pass" } else { "fail" });
    log.emit();

    assert!(
        is_correct_error,
        "validation must reject genesis with invalid zone ID format"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Cold Recovery Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_cold_recovery_from_phrase() {
    let mut log = TestLogEntry::new("test_cold_recovery_from_phrase", "execute");

    // Use a well-known test phrase
    let test_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    let phrase = RecoveryPhrase::from_mnemonic(test_phrase).expect("valid phrase");

    // Perform cold recovery
    let recovery = ColdRecovery::from_phrase(&phrase, None).expect("recovery should succeed");

    log = log
        .with_fingerprint(&recovery.genesis.fingerprint())
        .with_genesis_objects(vec!["genesis_state"])
        .with_result("pass");
    log.emit();

    // Verify the genesis is valid
    assert!(
        recovery.genesis.validate().is_ok(),
        "recovered genesis must be valid"
    );
}

#[test]
fn test_cold_recovery_fingerprint_matches() {
    let mut log = TestLogEntry::new("test_cold_recovery_fingerprint_matches", "execute");

    let test_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    let phrase = RecoveryPhrase::from_mnemonic(test_phrase).expect("valid phrase");

    // Get expected fingerprint
    let keypair = phrase.derive_owner_keypair();
    let expected_genesis = GenesisState::create_deterministic(&keypair.public());
    let expected_fp = expected_genesis.fingerprint();

    // Perform cold recovery with fingerprint verification
    let recovery =
        ColdRecovery::from_phrase(&phrase, Some(&expected_fp)).expect("recovery should succeed");

    log = log.with_fingerprint(&expected_fp).with_result(
        if recovery.genesis.fingerprint() == expected_fp {
            "pass"
        } else {
            "fail"
        },
    );
    log.emit();

    assert_eq!(
        recovery.genesis.fingerprint(),
        expected_fp,
        "recovered genesis fingerprint must match expected"
    );
}

#[test]
fn test_cold_recovery_deterministic() {
    let mut log = TestLogEntry::new("test_cold_recovery_deterministic", "execute");

    let test_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    let phrase = RecoveryPhrase::from_mnemonic(test_phrase).expect("valid phrase");

    let recovery1 = ColdRecovery::from_phrase(&phrase, None).expect("recovery 1");
    let recovery2 = ColdRecovery::from_phrase(&phrase, None).expect("recovery 2");

    let fp1 = recovery1.genesis.fingerprint();
    let fp2 = recovery2.genesis.fingerprint();

    log = log
        .with_fingerprint(&fp1)
        .with_result(if fp1 == fp2 { "pass" } else { "fail" });
    log.emit();

    assert_eq!(fp1, fp2, "cold recovery must be deterministic");
}

// ─────────────────────────────────────────────────────────────────────────────
// Recovery Phrase Error Handling Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_recovery_phrase_rejects_wrong_word_count() {
    let log = TestLogEntry::new("test_recovery_phrase_rejects_wrong_word_count", "execute");

    // Only 12 words instead of 24
    let short_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    let result = RecoveryPhrase::from_mnemonic(short_phrase);

    let is_correct_error = matches!(result, Err(RecoveryPhraseError::WrongWordCount(12)));

    log.with_result(if is_correct_error { "pass" } else { "fail" })
        .emit();

    assert!(is_correct_error, "must reject phrase with wrong word count");
}

#[test]
fn test_recovery_phrase_rejects_invalid_words() {
    let log = TestLogEntry::new("test_recovery_phrase_rejects_invalid_words", "execute");

    // Invalid BIP39 words
    let invalid_phrase = "invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid invalid";

    let result = RecoveryPhrase::from_mnemonic(invalid_phrase);

    let is_correct_error = matches!(result, Err(RecoveryPhraseError::InvalidMnemonic(_)));

    log.with_result(if is_correct_error { "pass" } else { "fail" })
        .emit();

    assert!(
        is_correct_error,
        "must reject phrase with invalid BIP39 words"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Bootstrap Workflow Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_bootstrap_workflow_single_device() {
    let mut log = TestLogEntry::new("test_bootstrap_workflow_single_device", "execute");

    let temp_dir = TempDir::new().expect("create temp dir");

    let config = BootstrapConfig::builder()
        .data_dir(temp_dir.path())
        .mode(BootstrapMode::SingleDevice)
        .build()
        .expect("build config");

    let workflow = BootstrapWorkflow::new(config).expect("create workflow");

    // Run the bootstrap workflow
    let result = workflow.run();

    match result {
        Ok(outcome) => {
            let genesis = outcome.into_genesis();
            log = log
                .with_genesis_objects(vec!["genesis_state", "owner_key"])
                .with_fingerprint(&genesis.fingerprint())
                .with_result("pass");
            log.emit();
            assert!(genesis.validate().is_ok(), "genesis must be valid");
        }
        Err(e) => {
            log = log.with_error(&e);
            log.emit();
            panic!("bootstrap workflow failed");
        }
    }
}

#[test]
fn test_bootstrap_workflow_detects_existing_genesis() {
    let mut log = TestLogEntry::new(
        "test_bootstrap_workflow_detects_existing_genesis",
        "execute",
    );

    let temp_dir = TempDir::new().expect("create temp dir");

    // First bootstrap
    let config1 = BootstrapConfig::builder()
        .data_dir(temp_dir.path())
        .mode(BootstrapMode::SingleDevice)
        .build()
        .expect("build config");

    let workflow1 = BootstrapWorkflow::new(config1).expect("create workflow 1");
    let genesis1 = workflow1
        .run()
        .expect("first bootstrap succeeds")
        .into_genesis();

    // Second bootstrap attempt should detect existing genesis
    let config2 = BootstrapConfig::builder()
        .data_dir(temp_dir.path())
        .mode(BootstrapMode::SingleDevice)
        .build()
        .expect("build config");

    // Second bootstrap attempt should detect existing genesis and return AlreadyExists error
    let workflow2_result = BootstrapWorkflow::new(config2);

    // Verify that the error contains the correct fingerprint
    let already_exists = matches!(
        workflow2_result,
        Err(BootstrapError::AlreadyExists { ref fingerprint }) if fingerprint == &genesis1.fingerprint()
    );

    log = log
        .with_fingerprint(&genesis1.fingerprint())
        .with_result(if already_exists { "pass" } else { "fail" });
    log.emit();

    assert!(
        already_exists,
        "re-bootstrap must detect existing genesis and return AlreadyExists error"
    );
}

#[test]
fn test_bootstrap_workflow_import_mode() {
    let mut log = TestLogEntry::new("test_bootstrap_workflow_import_mode", "execute");

    let temp_dir = TempDir::new().expect("create temp dir");
    let phrase_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    let phrase = RecoveryPhrase::from_mnemonic(phrase_str).expect("valid phrase");

    let config = BootstrapConfig::builder()
        .data_dir(temp_dir.path())
        .mode(BootstrapMode::Import {
            phrase: phrase.clone(),
        })
        .skip_time_validation(true)
        .build()
        .expect("build config");

    let workflow = BootstrapWorkflow::new(config).expect("create workflow");
    let genesis = workflow
        .run()
        .expect("import bootstrap succeeds")
        .into_genesis();

    let expected = GenesisState::create_deterministic(&phrase.derive_owner_keypair().public());

    log = log
        .with_genesis_objects(vec!["genesis_state", "owner_key"])
        .with_fingerprint(&genesis.fingerprint())
        .with_result(if genesis.fingerprint() == expected.fingerprint() {
            "pass"
        } else {
            "fail"
        });
    log.emit();

    assert_eq!(
        genesis.fingerprint(),
        expected.fingerprint(),
        "import mode should produce deterministic genesis fingerprint"
    );

    let stored = std::fs::read(temp_dir.path().join("genesis.cbor"))
        .expect("genesis.cbor should be written");
    let restored = GenesisState::from_cbor(&stored).expect("genesis.cbor should decode");
    assert_eq!(
        restored.fingerprint(),
        genesis.fingerprint(),
        "stored genesis must match returned genesis"
    );
}

#[test]
fn test_bootstrap_workflow_multi_device_produces_threshold_genesis() {
    let mut log = TestLogEntry::new(
        "test_bootstrap_workflow_multi_device_produces_threshold_genesis",
        "execute",
    );

    let temp_dir = TempDir::new().expect("create temp dir");
    let config = BootstrapConfig::builder()
        .data_dir(temp_dir.path())
        .mode(BootstrapMode::MultiDevice {
            device_count: 2,
            threshold: 2,
        })
        .skip_time_validation(true)
        .build()
        .expect("build config");

    let workflow = BootstrapWorkflow::new(config).expect("create workflow");
    let genesis = workflow
        .run()
        .expect("multi-device bootstrap succeeds")
        .into_genesis();
    let owner_key = genesis
        .owner_verifying_key()
        .expect("threshold bootstrap emits a valid owner key");

    log = log
        .with_fingerprint(&genesis.fingerprint())
        .with_result("pass");
    log.emit();

    assert_eq!(owner_key.to_bytes(), genesis.owner_public_key);
    assert!(
        std::fs::metadata(temp_dir.path().join("genesis.cbor")).is_ok(),
        "multi-device bootstrap should persist genesis.cbor"
    );
}

#[test]
fn test_bootstrap_workflow_hardware_token_returns_error() {
    let mut log = TestLogEntry::new(
        "test_bootstrap_workflow_hardware_token_returns_error",
        "execute",
    );

    let temp_dir = TempDir::new().expect("create temp dir");
    let token = DetectedToken {
        provider: PathBuf::from("/dev/null"),
        slot: 0,
        label: "test-token".to_string(),
        manufacturer: "test-manufacturer".to_string(),
        serial: "test-serial".to_string(),
        mechanisms: vec!["ED25519".to_string()],
    };

    let config = BootstrapConfig::builder()
        .data_dir(temp_dir.path())
        .mode(BootstrapMode::HardwareToken { token })
        .skip_time_validation(true)
        .build()
        .expect("build config");

    let workflow = BootstrapWorkflow::new(config).expect("create workflow");
    let result = workflow.run();

    let has_truthful_pin_refusal = matches!(&result, Err(BootstrapError::HardwareTokenPinRequired));
    if let Err(err) = &result {
        log = log.with_error(err);
    }
    log = log.with_result(if has_truthful_pin_refusal {
        "pass"
    } else {
        "fail"
    });
    log.emit();

    assert!(
        has_truthful_pin_refusal,
        "hardware token bootstrap should refuse missing PIN before attempting token login"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Zone Hierarchy Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_zone_integrity_levels_are_ordered() {
    let mut log = TestLogEntry::new("test_zone_integrity_levels_are_ordered", "execute");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let genesis = GenesisState::create(&verifying_key);

    // z:owner > z:private > z:work > z:community > z:public (integrity)
    let get_integrity = |zone_id: &str| -> u8 {
        genesis
            .initial_zones
            .iter()
            .find(|z| z.zone_id == zone_id)
            .map_or(0, |z| z.integrity_level)
    };

    let owner = get_integrity("z:owner");
    let private = get_integrity("z:private");
    let work = get_integrity("z:work");
    let community = get_integrity("z:community");
    let public = get_integrity("z:public");

    let ordered = owner > private && private > work && work > community && community > public;

    log = log.with_result(if ordered { "pass" } else { "fail" });
    log.emit();

    assert!(
        ordered,
        "zone integrity levels must be ordered: owner({owner}) > private({private}) > work({work}) > community({community}) > public({public})"
    );
}

#[test]
fn test_zone_confidentiality_levels_are_ordered() {
    let mut log = TestLogEntry::new("test_zone_confidentiality_levels_are_ordered", "execute");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    let genesis = GenesisState::create(&verifying_key);

    let get_conf = |zone_id: &str| -> u8 {
        genesis
            .initial_zones
            .iter()
            .find(|z| z.zone_id == zone_id)
            .map_or(0, |z| z.confidentiality_level)
    };

    let owner = get_conf("z:owner");
    let private = get_conf("z:private");
    let work = get_conf("z:work");
    let community = get_conf("z:community");
    let public = get_conf("z:public");

    // Public zone has confidentiality 0, others are ordered
    let ordered = owner > private && private > work && work > community && community > public;

    log = log.with_result(if ordered { "pass" } else { "fail" });
    log.emit();

    assert!(ordered, "zone confidentiality levels must be ordered");
}

// ─────────────────────────────────────────────────────────────────────────────
// Signature Verification Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn test_owner_signature_verification() {
    let mut log = TestLogEntry::new("test_owner_signature_verification", "execute");

    let phrase = RecoveryPhrase::generate().expect("generate phrase");
    let keypair = phrase.derive_owner_keypair();

    // Sign a test message
    let message = b"genesis verification message";
    let signature = keypair.sign(message);

    // Verify with the public key
    let public_key = keypair.public();
    let verify_result = public_key.verify(message, &signature);

    log = log
        .with_fingerprint(&hex::encode(public_key.to_bytes()))
        .with_result(if verify_result.is_ok() {
            "pass"
        } else {
            "fail"
        });
    log.emit();

    assert!(
        verify_result.is_ok(),
        "signature must verify with correct public key"
    );
}

#[test]
fn test_owner_signature_rejects_tampered_message() {
    let log = TestLogEntry::new("test_owner_signature_rejects_tampered_message", "execute");

    let phrase = RecoveryPhrase::generate().expect("generate phrase");
    let keypair = phrase.derive_owner_keypair();

    // Sign a message
    let message = b"original message";
    let signature = keypair.sign(message);

    // Try to verify with a different message
    let tampered = b"tampered message";
    let public_key = keypair.public();
    let verify_result = public_key.verify(tampered, &signature);

    log.with_result(if verify_result.is_err() {
        "pass"
    } else {
        "fail"
    })
    .emit();

    assert!(
        verify_result.is_err(),
        "signature must reject tampered message"
    );
}
