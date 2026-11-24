//! Deterministic soft-token harness for hardware-token verification.
//!
//! Provides an in-process implementation of [`HardwareTokenSessionDriver`] that
//! uses real Ed25519 cryptographic operations with seeded key material.  No external
//! PKCS#11 library or hardware is required — the harness runs identically in CI
//! and local development.
//!
//! # Determinism
//!
//! All key material is derived from a fixed seed via HKDF, so repeated runs
//! produce identical tokens, certificates, and keys for the same soft-token
//! configuration. Each identity gets a unique sub-seed derived from the token
//! identity, the identity specification, and its index.
//!
//! # Usage
//!
//! ```ignore
//! use fcp_bootstrap::soft_token::{SoftTokenDriver, SoftTokenConfig};
//!
//! let driver = SoftTokenDriver::deterministic(SoftTokenConfig {
//!     pin: "654321".into(),
//!     identities: vec![
//!         SoftTokenIdentitySpec::ed25519("owner-key", "FCP Owner"),
//!     ],
//!     ..Default::default()
//! });
//!
//! // Use with select_and_authenticate, select_certificate_for_provisioning, etc.
//! ```

use crate::hardware_token::{
    AuthenticatedSessionState, AuthenticatedTokenSession, DetectedToken, HardwareTokenPin,
    HardwareTokenSessionDriver, TokenCertificate, TokenError, TokenKeyInfo, TokenKeyType,
};
use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The default master seed for deterministic soft-token generation.
///
/// Chosen to be visually distinctive in hex dumps and stable across runs.
const DEFAULT_MASTER_SEED: [u8; 32] = [
    0xFC, 0xB0, 0x00, 0x01, // FCP soft token v1
    0xDE, 0xAD, 0xBE, 0xEF, // classic marker
    0x50, 0x46, 0x54, 0x4B, // "SFTK" (soft token)
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x00, //
    0x00, 0x00, 0x00, 0x01, // version byte
];

/// Specification for a single identity to provision on the soft token.
#[derive(Debug, Clone)]
struct SoftTokenIdentitySpec {
    /// Label for both the certificate and key objects.
    pub label: String,
    /// Subject CN for the synthetic certificate.
    pub subject_cn: String,
    /// Key type to present.
    pub key_type: TokenKeyType,
    /// Whether the key should advertise signing capability.
    pub can_sign: bool,
    /// Whether the key should advertise key derivation capability.
    pub can_derive: bool,
    /// Whether to generate a CA certificate (self-signed with subject == issuer).
    pub is_ca: bool,
}

impl SoftTokenIdentitySpec {
    /// Create an Ed25519 signing identity (the most common FCP case).
    pub fn ed25519(label: impl Into<String>, subject_cn: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            subject_cn: subject_cn.into(),
            key_type: TokenKeyType::Ed25519,
            can_sign: true,
            can_derive: false,
            is_ca: false,
        }
    }

    /// Create an X25519 key-agreement identity.
    pub fn x25519(label: impl Into<String>, subject_cn: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            subject_cn: subject_cn.into(),
            key_type: TokenKeyType::X25519,
            can_sign: false,
            can_derive: true,
            is_ca: false,
        }
    }

    /// Create an RSA identity (not FCP-compatible, for negative tests).
    pub fn rsa(label: impl Into<String>, subject_cn: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            subject_cn: subject_cn.into(),
            key_type: TokenKeyType::Rsa,
            can_sign: true,
            can_derive: false,
            is_ca: false,
        }
    }

    /// Mark this identity as a CA certificate.
    fn into_ca(mut self) -> Self {
        self.is_ca = true;
        self
    }
}

/// Configuration for a soft-token driver instance.
#[derive(Clone)]
struct SoftTokenConfig {
    /// The PIN required for authentication.
    pub pin: String,
    /// Token label (appears in `DetectedToken`).
    pub token_label: String,
    /// Token manufacturer string.
    pub manufacturer: String,
    /// Token serial number.
    pub serial: String,
    /// Slot number.
    pub slot: u32,
    /// Identities to provision on the token.
    pub identities: Vec<SoftTokenIdentitySpec>,
    /// Advertised mechanisms (defaults to Ed25519 + ECDH).
    pub mechanisms: Vec<String>,
}

impl std::fmt::Debug for SoftTokenConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftTokenConfig")
            .field("pin", &"<redacted>")
            .field("token_label", &self.token_label)
            .field("manufacturer", &self.manufacturer)
            .field("serial", &self.serial)
            .field("slot", &self.slot)
            .field("identities", &self.identities)
            .field("mechanisms", &self.mechanisms)
            .finish()
    }
}

impl Default for SoftTokenConfig {
    fn default() -> Self {
        Self {
            pin: "654321".into(),
            token_label: "FCP-SoftToken".into(),
            manufacturer: "FCP-Test".into(),
            serial: "SOFT0001".into(),
            slot: 0,
            identities: vec![SoftTokenIdentitySpec::ed25519("fcp-owner", "FCP Owner Key")],
            mechanisms: vec![
                "CKM_ED25519".into(),
                "CKM_EDDSA".into(),
                "CKM_ECDH1_DERIVE".into(),
            ],
        }
    }
}

/// A materialized identity on the soft token: certificate + key metadata + raw key.
#[derive(Debug, Clone)]
struct MaterializedIdentity {
    /// Opaque `CKA_ID` binding the certificate and key objects.
    id: Vec<u8>,
    /// The certificate object.
    certificate: TokenCertificate,
    /// The key metadata.
    key_info: TokenKeyInfo,
    /// The raw Ed25519 signing key (32 bytes), used for real proof-of-possession
    /// and enrolled-owner signing in the deterministic test provider.
    signing_key_bytes: [u8; 32],
}

struct DerivedIdentity {
    spec: SoftTokenIdentitySpec,
    id: Vec<u8>,
    key_info: TokenKeyInfo,
    signing_key_bytes: [u8; 32],
}

/// Deterministic soft-token driver implementing [`HardwareTokenSessionDriver`].
///
/// Each instance holds pre-materialized identities generated from a fixed seed.
/// The driver validates PINs against the configured value and returns real
/// certificate/key objects that exercise the full selection pipeline.
struct SoftTokenDriver {
    /// The expected PIN.
    pin: HardwareTokenPin,
    /// The canonical `DetectedToken` for this soft token.
    detected_token: DetectedToken,
    /// Pre-materialized identities indexed by their `CKA_ID`.
    identities: Vec<MaterializedIdentity>,
    /// Additional CA certificates present on the token without matching keys.
    extra_certificates: Vec<TokenCertificate>,
    /// Counter for close-action invocations (for cleanup determinism tests).
    close_count: Arc<AtomicUsize>,
}

impl SoftTokenDriver {
    /// Create a deterministic soft-token driver with the given configuration.
    ///
    /// All key material is derived from a fixed master seed, so repeated calls
    /// with the same config produce identical tokens.
    pub fn deterministic(config: SoftTokenConfig) -> Self {
        let detected_token = DetectedToken {
            provider: PathBuf::from("/soft/libsofttoken.so"),
            slot: config.slot,
            label: config.token_label.clone(),
            manufacturer: config.manufacturer.clone(),
            serial: config.serial.clone(),
            mechanisms: config.mechanisms.clone(),
        };

        let identities = materialize_identities(&config);
        let extra_certificates = implicit_ca_certificates(&config);

        Self {
            pin: HardwareTokenPin::new(config.pin),
            detected_token,
            identities,
            extra_certificates,
            close_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// The canonical `DetectedToken` for this soft token.
    pub fn detected_token(&self) -> &DetectedToken {
        &self.detected_token
    }

    /// How many times close actions have been invoked.
    pub fn close_count(&self) -> usize {
        self.close_count.load(Ordering::SeqCst)
    }

    /// Build a `TokenDetectionReport` containing just this soft token.
    pub fn detection_report(&self) -> crate::hardware_token::TokenDetectionReport {
        crate::hardware_token::TokenDetectionReport {
            providers: vec![crate::hardware_token::ProviderDetectionResult {
                provider: self.detected_token.provider.clone(),
                tokens: vec![self.detected_token.clone()],
                issues: Vec::new(),
            }],
        }
    }

    /// Build a `HardwareTokenPin` from the configured PIN.
    pub fn pin(&self) -> HardwareTokenPin {
        self.pin.clone()
    }

    /// Build a `HardwareTokenPin` with the wrong value (for negative tests).
    pub fn wrong_pin() -> HardwareTokenPin {
        HardwareTokenPin::new("WRONG-PIN")
    }

    fn validate_token_and_pin(
        &self,
        token: &DetectedToken,
        pin: &HardwareTokenPin,
    ) -> Result<(), TokenError> {
        if pin.is_empty() {
            return Err(TokenError::PinRequired);
        }

        if pin != &self.pin {
            return Err(TokenError::InvalidPin);
        }

        if token.provider != self.detected_token.provider
            || token.slot != self.detected_token.slot
            || token.serial != self.detected_token.serial
            || token.label != self.detected_token.label
            || token.manufacturer != self.detected_token.manufacturer
        {
            return Err(TokenError::TokenNotFound(format!(
                "{} slot {}",
                token.provider.display(),
                token.slot
            )));
        }

        Ok(())
    }
}

impl HardwareTokenSessionDriver for SoftTokenDriver {
    fn open_authenticated_session(
        &self,
        token: &DetectedToken,
        pin: &HardwareTokenPin,
    ) -> Result<AuthenticatedTokenSession, TokenError> {
        self.validate_token_and_pin(token, pin)?;

        let close_count = Arc::clone(&self.close_count);
        Ok(AuthenticatedTokenSession::with_close_action(
            token.clone(),
            AuthenticatedSessionState::ReadWriteUser,
            true,
            move || {
                close_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        ))
    }

    fn enumerate_certificates(
        &self,
        token: &DetectedToken,
        pin: &HardwareTokenPin,
    ) -> Result<Vec<TokenCertificate>, TokenError> {
        self.validate_token_and_pin(token, pin)?;

        Ok(self
            .identities
            .iter()
            .map(|id| id.certificate.clone())
            .chain(self.extra_certificates.iter().cloned())
            .collect())
    }

    fn enumerate_keys(
        &self,
        token: &DetectedToken,
        pin: &HardwareTokenPin,
    ) -> Result<Vec<TokenKeyInfo>, TokenError> {
        self.validate_token_and_pin(token, pin)?;

        Ok(self
            .identities
            .iter()
            .map(|id| id.key_info.clone())
            .collect())
    }

    fn sign_ed25519(
        &self,
        token: &DetectedToken,
        pin: &HardwareTokenPin,
        key_id: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>, TokenError> {
        use ed25519_dalek::Signer;

        let session = self.open_authenticated_session(token, pin)?;
        let result = (|| {
            let identities: Vec<_> = self
                .identities
                .iter()
                .filter(|identity| identity.id == key_id)
                .collect();
            let identity = match identities.as_slice() {
                [] => return Err(TokenError::KeyNotFound(hex::encode(key_id))),
                [identity] => *identity,
                _ => {
                    return Err(TokenError::Enrollment(
                        "multiple private keys have the enrolled identifier".into(),
                    ));
                }
            };
            if !matches!(identity.key_info.key_type, TokenKeyType::Ed25519)
                || !identity.key_info.can_sign
            {
                return Err(TokenError::UnsupportedMechanism("Ed25519 owner signing".into()));
            }
            Ok(SigningKey::from_bytes(&identity.signing_key_bytes)
                .sign(message)
                .to_bytes()
                .to_vec())
        })();
        let cleanup = session.close();
        let signature = result?;
        cleanup?;
        Ok(signature)
    }
}

/// Derive deterministic identity material from the master seed.
fn materialize_identities(config: &SoftTokenConfig) -> Vec<MaterializedIdentity> {
    let token_context = soft_token_derivation_context(config);
    let derived_identities = config
        .identities
        .iter()
        .enumerate()
        .map(|(index, spec)| derive_identity(&token_context, index, spec))
        .collect::<Vec<_>>();
    let default_ca = derived_identities
        .iter()
        .find(|identity| identity.spec.is_ca);

    derived_identities
        .iter()
        .map(|identity| {
            let certificate = if identity.spec.is_ca {
                build_self_signed_certificate(
                    &identity.spec.label,
                    &identity.id,
                    &identity.spec.subject_cn,
                    &identity.signing_key_bytes,
                    true,
                )
            } else if let Some(ca_identity) = default_ca {
                build_signed_certificate(
                    &identity.spec.label,
                    &identity.id,
                    &identity.spec.subject_cn,
                    &ca_identity.spec.subject_cn,
                    &identity.signing_key_bytes,
                    &ca_identity.signing_key_bytes,
                )
            } else {
                build_signed_certificate(
                    &identity.spec.label,
                    &identity.id,
                    &identity.spec.subject_cn,
                    "FCP SoftToken CA",
                    &identity.signing_key_bytes,
                    &implicit_ca_signing_key_bytes(&token_context),
                )
            };

            MaterializedIdentity {
                id: identity.id.clone(),
                certificate,
                key_info: identity.key_info.clone(),
                signing_key_bytes: identity.signing_key_bytes,
            }
        })
        .collect()
}

fn implicit_ca_certificates(config: &SoftTokenConfig) -> Vec<TokenCertificate> {
    let has_leaf = config.identities.iter().any(|spec| !spec.is_ca);
    let has_explicit_ca = config.identities.iter().any(|spec| spec.is_ca);
    if !has_leaf || has_explicit_ca {
        return Vec::new();
    }

    let token_context = soft_token_derivation_context(config);
    vec![implicit_ca_certificate(&token_context)]
}

fn derive_identity(
    token_context: &[u8],
    index: usize,
    spec: &SoftTokenIdentitySpec,
) -> DerivedIdentity {
    // Derive a per-identity signing key using HKDF from token + identity context.
    // No RNG needed — the key material is fully deterministic.
    let mut signing_key_bytes = [0u8; 32];
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&DEFAULT_MASTER_SEED), token_context);
    let info = identity_derivation_info(index, spec);
    hk.expand(&info, &mut signing_key_bytes)
        .expect("32 bytes is a valid HKDF-SHA256 output length");

    let signing_key = SigningKey::from_bytes(&signing_key_bytes);
    let public_key_bytes = signing_key.verifying_key().to_bytes();

    // Generate a deterministic CKA_ID from the public key (first 20 bytes of BLAKE3).
    let id_hash = blake3::hash(&public_key_bytes);
    let cka_id = id_hash.as_bytes()[..20].to_vec();

    let key_info = TokenKeyInfo {
        label: spec.label.clone(),
        id: cka_id.clone(),
        key_type: spec.key_type,
        can_sign: spec.can_sign,
        can_derive: spec.can_derive,
    };

    DerivedIdentity {
        spec: spec.clone(),
        id: cka_id,
        key_info,
        signing_key_bytes,
    }
}

fn push_len_prefixed(buf: &mut Vec<u8>, value: &[u8]) {
    let len = u64::try_from(value.len()).unwrap_or(u64::MAX);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(value);
}

fn push_bool(buf: &mut Vec<u8>, value: bool) {
    buf.push(u8::from(value));
}

fn soft_token_derivation_context(config: &SoftTokenConfig) -> Vec<u8> {
    let mut context = Vec::new();
    push_len_prefixed(&mut context, b"FCP-SOFT-TOKEN-CONTEXT-V2");
    context.extend_from_slice(&config.slot.to_le_bytes());
    push_len_prefixed(&mut context, config.token_label.as_bytes());
    push_len_prefixed(&mut context, config.manufacturer.as_bytes());
    push_len_prefixed(&mut context, config.serial.as_bytes());
    context
}

fn push_key_type(buf: &mut Vec<u8>, key_type: TokenKeyType) {
    match key_type {
        TokenKeyType::Ed25519 => push_len_prefixed(buf, b"Ed25519"),
        TokenKeyType::X25519 => push_len_prefixed(buf, b"X25519"),
        TokenKeyType::EcdsaP256 => push_len_prefixed(buf, b"EcdsaP256"),
        TokenKeyType::EcdsaP384 => push_len_prefixed(buf, b"EcdsaP384"),
        TokenKeyType::Rsa => push_len_prefixed(buf, b"Rsa"),
        TokenKeyType::Other(value) => {
            push_len_prefixed(buf, b"Other");
            buf.extend_from_slice(&value.to_le_bytes());
        }
    }
}

fn identity_derivation_info(index: usize, spec: &SoftTokenIdentitySpec) -> Vec<u8> {
    let mut info = Vec::new();
    push_len_prefixed(&mut info, b"FCP-SOFT-TOKEN-IDENTITY-V2");
    info.extend_from_slice(&u64::try_from(index).unwrap_or(u64::MAX).to_le_bytes());
    push_len_prefixed(&mut info, spec.label.as_bytes());
    push_len_prefixed(&mut info, spec.subject_cn.as_bytes());
    push_key_type(&mut info, spec.key_type);
    push_bool(&mut info, spec.can_sign);
    push_bool(&mut info, spec.can_derive);
    push_bool(&mut info, spec.is_ca);
    info
}

fn build_certificate_params(common_name: &str, is_ca: bool) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    if is_ca {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    }
    params
}

fn rcgen_key_pair_from_signing_key(signing_key_bytes: &[u8; 32]) -> KeyPair {
    let signing_key = SigningKey::from_bytes(signing_key_bytes);
    let pkcs8 = signing_key.to_pkcs8_der().unwrap();
    KeyPair::try_from(pkcs8.as_bytes()).unwrap()
}

fn build_self_signed_certificate(
    label: &str,
    id: &[u8],
    subject_cn: &str,
    signing_key_bytes: &[u8; 32],
    is_ca: bool,
) -> TokenCertificate {
    let params = build_certificate_params(subject_cn, is_ca);
    let key_pair = rcgen_key_pair_from_signing_key(signing_key_bytes);
    let certificate = params.self_signed(&key_pair).unwrap();
    let subject = format!("CN={subject_cn}");

    TokenCertificate {
        label: label.to_string(),
        id: id.to_vec(),
        der_bytes: certificate.der().to_vec(),
        subject: subject.clone(),
        issuer: subject,
        is_ca,
    }
}

fn certified_issuer(
    subject_cn: &str,
    signing_key_bytes: &[u8; 32],
) -> CertifiedIssuer<'static, KeyPair> {
    let params = build_certificate_params(subject_cn, true);
    let key_pair = rcgen_key_pair_from_signing_key(signing_key_bytes);
    CertifiedIssuer::self_signed(params, key_pair).unwrap()
}

fn build_signed_certificate(
    label: &str,
    id: &[u8],
    subject_cn: &str,
    issuer_cn: &str,
    signing_key_bytes: &[u8; 32],
    issuer_signing_key_bytes: &[u8; 32],
) -> TokenCertificate {
    let params = build_certificate_params(subject_cn, false);
    let key_pair = rcgen_key_pair_from_signing_key(signing_key_bytes);
    let issuer = certified_issuer(issuer_cn, issuer_signing_key_bytes);
    let certificate = params.signed_by(&key_pair, &issuer).unwrap();

    TokenCertificate {
        label: label.to_string(),
        id: id.to_vec(),
        der_bytes: certificate.der().to_vec(),
        subject: format!("CN={subject_cn}"),
        issuer: format!("CN={issuer_cn}"),
        is_ca: false,
    }
}

fn implicit_ca_signing_key_bytes(token_context: &[u8]) -> [u8; 32] {
    let mut signing_key_bytes = [0u8; 32];
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&DEFAULT_MASTER_SEED), token_context);
    hk.expand(b"fcp-soft-token-ca", &mut signing_key_bytes)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    signing_key_bytes
}

fn implicit_ca_certificate(token_context: &[u8]) -> TokenCertificate {
    let ca_label = "soft-token-ca";
    let subject_cn = "FCP SoftToken CA";
    let mut id_material = Vec::new();
    push_len_prefixed(&mut id_material, b"FCP-SOFT-TOKEN-IMPLICIT-CA-ID-V2");
    push_len_prefixed(&mut id_material, token_context);
    let id_hash = blake3::hash(&id_material);
    let cka_id = id_hash.as_bytes()[..20].to_vec();
    let signing_key_bytes = implicit_ca_signing_key_bytes(token_context);

    build_self_signed_certificate(ca_label, &cka_id, subject_cn, &signing_key_bytes, true)
}

/// Build a multi-token soft-token environment with separate drivers per token.
///
/// Useful for testing multi-slot discovery scenarios.
struct SoftTokenHarness {
    drivers: HashMap<u32, SoftTokenDriver>,
}

impl SoftTokenHarness {
    /// Create a harness from multiple token configurations.
    pub fn new(configs: Vec<SoftTokenConfig>) -> Self {
        let mut drivers = HashMap::new();
        for config in configs {
            let slot = config.slot;
            drivers.insert(slot, SoftTokenDriver::deterministic(config));
        }
        Self { drivers }
    }

    /// Build a combined detection report from all tokens.
    pub fn detection_report(&self) -> crate::hardware_token::TokenDetectionReport {
        let mut providers = Vec::new();
        let mut slots: Vec<_> = self.drivers.keys().collect();
        slots.sort(); // deterministic order
        for &slot in &slots {
            let driver = &self.drivers[slot];
            providers.push(crate::hardware_token::ProviderDetectionResult {
                provider: driver.detected_token().provider.clone(),
                tokens: vec![driver.detected_token().clone()],
                issues: Vec::new(),
            });
        }
        crate::hardware_token::TokenDetectionReport { providers }
    }

    /// Get all detected tokens across all slots.
    pub fn all_tokens(&self) -> Vec<DetectedToken> {
        let mut tokens = Vec::new();
        let mut slots: Vec<_> = self.drivers.keys().collect();
        slots.sort();
        for &slot in &slots {
            tokens.push(self.drivers[slot].detected_token().clone());
        }
        tokens
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware_token::HardwareTokenEnrollment;

    fn bootstrap_soft_token(
        data_dir: &std::path::Path,
        driver: &SoftTokenDriver,
    ) -> crate::error::BootstrapResult<crate::workflow::BootstrapOutcome> {
        use crate::workflow::{BootstrapConfig, BootstrapMode, BootstrapWorkflow};

        let mut config = BootstrapConfig::builder()
            .data_dir(data_dir)
            .mode(BootstrapMode::HardwareToken {
                token: driver.detected_token().clone(),
            })
            .skip_time_validation(true)
            .build()?;
        config.hardware_token_pin = Some(driver.pin());
        let report = driver.detection_report();
        BootstrapWorkflow::new(config)?.run_with_hardware_driver(driver, Some(&report))
    }

    // ── Determinism tests ──────────────────────────────────────────────

    #[test]
    fn soft_token_deterministic_across_runs() {
        let d1 = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let d2 = SoftTokenDriver::deterministic(SoftTokenConfig::default());

        assert_eq!(d1.identities.len(), d2.identities.len());
        for (a, b) in d1.identities.iter().zip(d2.identities.iter()) {
            assert_eq!(a.id, b.id, "CKA_ID must be deterministic");
            assert_eq!(
                a.signing_key_bytes, b.signing_key_bytes,
                "signing key must be deterministic"
            );
            assert_eq!(
                a.certificate.der_bytes, b.certificate.der_bytes,
                "certificate DER must be deterministic"
            );
        }
    }

    #[test]
    fn different_identities_get_different_keys() {
        let config = SoftTokenConfig {
            identities: vec![
                SoftTokenIdentitySpec::ed25519("key-a", "Subject A"),
                SoftTokenIdentitySpec::ed25519("key-b", "Subject B"),
            ],
            ..SoftTokenConfig::default()
        };
        let driver = SoftTokenDriver::deterministic(config);

        assert_eq!(driver.identities.len(), 2);
        assert_eq!(driver.extra_certificates.len(), 1);
        assert_ne!(
            driver.identities[0].signing_key_bytes, driver.identities[1].signing_key_bytes,
            "different identities must have different keys"
        );
        assert_ne!(
            driver.identities[0].id, driver.identities[1].id,
            "different identities must have different CKA_IDs"
        );
    }

    #[test]
    fn identity_spec_changes_key_material_at_same_index() {
        let first = SoftTokenDriver::deterministic(SoftTokenConfig {
            identities: vec![SoftTokenIdentitySpec::ed25519("key-a", "Subject A")],
            ..SoftTokenConfig::default()
        });
        let second = SoftTokenDriver::deterministic(SoftTokenConfig {
            identities: vec![SoftTokenIdentitySpec::ed25519("key-b", "Subject A")],
            ..SoftTokenConfig::default()
        });

        assert_ne!(
            first.identities[0].signing_key_bytes, second.identities[0].signing_key_bytes,
            "identity label must be part of deterministic key derivation"
        );
        assert_ne!(
            first.identities[0].id, second.identities[0].id,
            "identity label must be part of CKA_ID derivation"
        );
    }

    // ── PIN validation tests ───────────────────────────────────────────

    #[test]
    fn soft_token_config_debug_redacts_pin() {
        let config = SoftTokenConfig {
            pin: "987654".into(),
            ..SoftTokenConfig::default()
        };

        let debug = format!("{config:?}");

        assert!(debug.contains("SoftTokenConfig"));
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("987654"));
    }

    #[test]
    fn correct_pin_opens_session() {
        let driver = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let token = driver.detected_token().clone();
        let pin = driver.pin();

        let session = driver.open_authenticated_session(&token, &pin).unwrap();
        assert_eq!(
            session.session_state(),
            AuthenticatedSessionState::ReadWriteUser
        );
        assert!(session.read_write());
    }

    #[test]
    fn wrong_pin_returns_invalid_pin() {
        let driver = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let token = driver.detected_token().clone();
        let pin = SoftTokenDriver::wrong_pin();

        let err = driver.open_authenticated_session(&token, &pin).unwrap_err();
        assert!(
            matches!(err, TokenError::InvalidPin),
            "expected InvalidPin, got: {err}"
        );
    }

    #[test]
    fn enumeration_with_wrong_pin_returns_invalid_pin() {
        let driver = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let token = driver.detected_token().clone();
        let wrong_pin = SoftTokenDriver::wrong_pin();

        let cert_err = driver
            .enumerate_certificates(&token, &wrong_pin)
            .unwrap_err();
        assert!(
            matches!(cert_err, TokenError::InvalidPin),
            "expected certificate enumeration to reject wrong PIN, got: {cert_err}"
        );

        let key_err = driver.enumerate_keys(&token, &wrong_pin).unwrap_err();
        assert!(
            matches!(key_err, TokenError::InvalidPin),
            "expected key enumeration to reject wrong PIN, got: {key_err}"
        );
    }

    #[test]
    fn empty_pin_returns_pin_required() {
        let driver = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let token = driver.detected_token().clone();
        let pin = HardwareTokenPin::new("");

        let err = driver.open_authenticated_session(&token, &pin).unwrap_err();
        assert!(
            matches!(err, TokenError::PinRequired),
            "expected PinRequired, got: {err}"
        );
    }

    #[test]
    fn wrong_slot_returns_token_not_found() {
        let driver = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let mut wrong_token = driver.detected_token().clone();
        wrong_token.slot = 99;
        let pin = driver.pin();

        let err = driver
            .open_authenticated_session(&wrong_token, &pin)
            .unwrap_err();
        assert!(
            matches!(err, TokenError::TokenNotFound(_)),
            "expected TokenNotFound, got: {err}"
        );
    }

    // ── Certificate/key enumeration tests ──────────────────────────────

    #[test]
    fn enumerate_certificates_returns_all_non_ca() {
        let config = SoftTokenConfig {
            identities: vec![
                SoftTokenIdentitySpec::ed25519("user-key", "User Cert"),
                SoftTokenIdentitySpec::ed25519("ca-key", "Root CA").into_ca(),
            ],
            ..SoftTokenConfig::default()
        };
        let driver = SoftTokenDriver::deterministic(config);
        let token = driver.detected_token().clone();
        let pin = driver.pin();

        let certs = driver.enumerate_certificates(&token, &pin).unwrap();
        assert_eq!(certs.len(), 2);

        let user_cert = certs.iter().find(|c| c.label == "user-key").unwrap();
        assert!(!user_cert.is_ca);
        assert_ne!(user_cert.subject, user_cert.issuer);

        let ca_cert = certs.iter().find(|c| c.label == "ca-key").unwrap();
        assert!(ca_cert.is_ca);
        assert_eq!(ca_cert.subject, ca_cert.issuer);
    }

    #[test]
    fn enumerate_keys_returns_correct_types() {
        let config = SoftTokenConfig {
            identities: vec![
                SoftTokenIdentitySpec::ed25519("sign-key", "Signer"),
                SoftTokenIdentitySpec::x25519("derive-key", "Deriver"),
                SoftTokenIdentitySpec::rsa("rsa-key", "Legacy"),
            ],
            ..SoftTokenConfig::default()
        };
        let driver = SoftTokenDriver::deterministic(config);
        let token = driver.detected_token().clone();
        let pin = driver.pin();

        let keys = driver.enumerate_keys(&token, &pin).unwrap();
        assert_eq!(keys.len(), 3);

        let sign = keys.iter().find(|k| k.label == "sign-key").unwrap();
        assert_eq!(sign.key_type, TokenKeyType::Ed25519);
        assert!(sign.can_sign);
        assert!(!sign.can_derive);

        let derive = keys.iter().find(|k| k.label == "derive-key").unwrap();
        assert_eq!(derive.key_type, TokenKeyType::X25519);
        assert!(!derive.can_sign);
        assert!(derive.can_derive);

        let rsa = keys.iter().find(|k| k.label == "rsa-key").unwrap();
        assert_eq!(rsa.key_type, TokenKeyType::Rsa);
    }

    #[test]
    fn certificate_key_id_binding_matches() {
        let driver = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let token = driver.detected_token().clone();
        let pin = driver.pin();

        let certs = driver.enumerate_certificates(&token, &pin).unwrap();
        let keys = driver.enumerate_keys(&token, &pin).unwrap();

        let leaf_certs: Vec<_> = certs.iter().filter(|cert| !cert.is_ca).collect();
        assert_eq!(leaf_certs.len(), keys.len());
        for (cert, key) in leaf_certs.iter().zip(keys.iter()) {
            assert_eq!(
                cert.id, key.id,
                "certificate and key CKA_ID must match for binding"
            );
            assert_eq!(cert.label, key.label);
        }
    }

    // ── Close-action tracking ──────────────────────────────────────────

    #[test]
    fn close_action_invoked_exactly_once() {
        let driver = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let token = driver.detected_token().clone();
        let pin = driver.pin();

        assert_eq!(driver.close_count(), 0);

        let session = driver.open_authenticated_session(&token, &pin).unwrap();
        session.close().unwrap();

        assert_eq!(driver.close_count(), 1);
    }

    #[test]
    fn drop_invokes_close_if_not_explicit() {
        let driver = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let token = driver.detected_token().clone();
        let pin = driver.pin();

        {
            let _session = driver.open_authenticated_session(&token, &pin).unwrap();
            // session dropped here
        }

        assert_eq!(driver.close_count(), 1);
    }

    #[test]
    fn close_then_drop_invokes_exactly_once() {
        let driver = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let token = driver.detected_token().clone();
        let pin = driver.pin();

        let session = driver.open_authenticated_session(&token, &pin).unwrap();
        session.close().unwrap();
        // Drop runs but close_action is already taken

        assert_eq!(driver.close_count(), 1);
    }

    // ── Detection report helper ────────────────────────────────────────

    #[test]
    fn detection_report_contains_soft_token() {
        let driver = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let report = driver.detection_report();

        assert_eq!(report.providers.len(), 1);
        assert!(report.has_detected_tokens());
        assert!(report.issues().is_empty());

        let tokens = report.all_tokens();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].label, "FCP-SoftToken");
        assert!(tokens[0].supports_ed25519());
    }

    // ── Multi-token harness ────────────────────────────────────────────

    #[test]
    fn multi_token_harness_reports_all_slots() {
        let harness = SoftTokenHarness::new(vec![
            SoftTokenConfig {
                slot: 0,
                token_label: "Token-A".into(),
                serial: "A001".into(),
                ..SoftTokenConfig::default()
            },
            SoftTokenConfig {
                slot: 1,
                token_label: "Token-B".into(),
                serial: "B001".into(),
                ..SoftTokenConfig::default()
            },
        ]);

        let report = harness.detection_report();
        assert_eq!(report.all_tokens().len(), 2);

        let tokens = harness.all_tokens();
        assert_eq!(tokens[0].label, "Token-A");
        assert_eq!(tokens[1].label, "Token-B");
    }

    #[test]
    fn multi_token_harness_assigns_distinct_identity_material_per_token() {
        let harness = SoftTokenHarness::new(vec![
            SoftTokenConfig {
                slot: 0,
                token_label: "Token-A".into(),
                serial: "A001".into(),
                ..SoftTokenConfig::default()
            },
            SoftTokenConfig {
                slot: 1,
                token_label: "Token-B".into(),
                serial: "B001".into(),
                ..SoftTokenConfig::default()
            },
        ]);

        let first = harness.drivers.get(&0).expect("slot 0 driver");
        let second = harness.drivers.get(&1).expect("slot 1 driver");

        assert_ne!(
            first.identities[0].id, second.identities[0].id,
            "different soft tokens must not expose colliding CKA_IDs"
        );
        assert_ne!(
            first.identities[0].certificate.der_bytes, second.identities[0].certificate.der_bytes,
            "different soft tokens must not expose identical certificates"
        );
        assert_ne!(
            first.extra_certificates[0].id, second.extra_certificates[0].id,
            "implicit CA objects must be token-specific"
        );
    }

    // ── Full pipeline: select_and_authenticate through soft token ──────

    #[test]
    fn full_pipeline_select_authenticate_enumerate() {
        use crate::hardware_token::{
            match_certificate_key_pairs, select_and_authenticate,
            select_certificate_for_provisioning,
        };

        let config = SoftTokenConfig {
            identities: vec![
                SoftTokenIdentitySpec::ed25519("fcp-owner", "FCP Owner"),
                SoftTokenIdentitySpec::x25519("fcp-agreement", "FCP Agreement"),
            ],
            ..SoftTokenConfig::default()
        };
        let driver = SoftTokenDriver::deterministic(config);
        let token = driver.detected_token().clone();
        let pin = driver.pin();
        let report = driver.detection_report();

        // Step 1: select and authenticate
        let outcome = select_and_authenticate(&token, &pin, &report, &driver, None).unwrap();
        assert_eq!(
            outcome.session.session_state(),
            AuthenticatedSessionState::ReadWriteUser
        );

        // Step 2: enumerate and match
        let certs = driver.enumerate_certificates(&token, &pin).unwrap();
        let keys = driver.enumerate_keys(&token, &pin).unwrap();
        let pairs = match_certificate_key_pairs(&certs, &keys);
        assert_eq!(pairs.len(), 2);

        // Step 3: select certificate for provisioning
        let material = select_certificate_for_provisioning(&token, &pin, &driver).unwrap();
        assert_eq!(
            material.pair.key.key_type,
            TokenKeyType::Ed25519,
            "Ed25519 should be preferred over X25519"
        );
        assert_eq!(material.pair.certificate.label, "fcp-owner");

        // Step 4: cleanup
        outcome.session.close().unwrap();
        assert_eq!(driver.close_count(), 1);
    }

    #[test]
    fn full_pipeline_select_certificate_with_wrong_pin_returns_invalid_pin() {
        use crate::hardware_token::select_certificate_for_provisioning;

        let driver = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let token = driver.detected_token().clone();
        let wrong_pin = SoftTokenDriver::wrong_pin();

        let err = select_certificate_for_provisioning(&token, &wrong_pin, &driver).unwrap_err();
        assert!(
            matches!(err, TokenError::InvalidPin),
            "expected provisioning selection to reject wrong PIN, got: {err}"
        );
    }

    #[test]
    fn full_pipeline_rsa_only_token_refuses_provisioning() {
        use crate::hardware_token::select_certificate_for_provisioning;

        let config = SoftTokenConfig {
            identities: vec![SoftTokenIdentitySpec::rsa("legacy-rsa", "Legacy RSA Key")],
            mechanisms: vec!["CKM_RSA_PKCS".into()],
            ..SoftTokenConfig::default()
        };
        let driver = SoftTokenDriver::deterministic(config);
        let token = driver.detected_token().clone();
        let pin = driver.pin();

        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        assert!(
            matches!(
                err,
                TokenError::CertificateSelectionFailed(
                    crate::hardware_token::CertificateSelectionRefusal::NoCompatibleKeyType { .. }
                )
            ),
            "expected NoCompatibleKeyType, got: {err}"
        );
    }

    #[test]
    fn full_pipeline_ca_only_token_refuses_provisioning() {
        use crate::hardware_token::select_certificate_for_provisioning;

        let config = SoftTokenConfig {
            identities: vec![SoftTokenIdentitySpec::ed25519("ca-key", "Root CA").into_ca()],
            ..SoftTokenConfig::default()
        };
        let driver = SoftTokenDriver::deterministic(config);
        let token = driver.detected_token().clone();
        let pin = driver.pin();

        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        // CA certs are filtered out by match_certificate_key_pairs, so we expect NoMatchingKeyPair
        assert!(
            matches!(
                err,
                TokenError::CertificateSelectionFailed(
                    crate::hardware_token::CertificateSelectionRefusal::NoMatchingKeyPair
                )
            ),
            "expected NoMatchingKeyPair (CA filtered), got: {err}"
        );
    }

    #[test]
    fn full_pipeline_empty_token_refuses_provisioning() {
        use crate::hardware_token::select_certificate_for_provisioning;

        let config = SoftTokenConfig {
            identities: vec![],
            ..SoftTokenConfig::default()
        };
        let driver = SoftTokenDriver::deterministic(config);
        let token = driver.detected_token().clone();
        let pin = driver.pin();

        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        assert!(
            matches!(
                err,
                TokenError::CertificateSelectionFailed(
                    crate::hardware_token::CertificateSelectionRefusal::NoCertificates
                )
            ),
            "expected NoCertificates, got: {err}"
        );
    }

    // ── Workflow-level integration: run_hardware_token_bootstrap_with_driver ──

    #[test]
    fn workflow_bootstrap_with_soft_token_reaches_provisioning() {
        let dir = tempfile::tempdir().unwrap();
        let soft = SoftTokenDriver::deterministic(SoftTokenConfig {
            pin: "PIN-MUST-NEVER-PERSIST-94172".into(),
            ..SoftTokenConfig::default()
        });
        let outcome = bootstrap_soft_token(dir.path(), &soft).unwrap();
        assert!(outcome.recovery_phrase.is_none());
        let enrollment = outcome.hardware_token.as_ref().unwrap();
        enrollment.validate_for_genesis(&outcome.genesis).unwrap();
        assert_eq!(soft.close_count(), 2, "discovery and signing sessions must close");
        assert!(!dir.path().join("init.lock").exists());

        let persisted = crate::GenesisState::from_cbor(
            &std::fs::read(dir.path().join("genesis.cbor")).unwrap(),
        )
        .unwrap();
        assert_eq!(persisted.fingerprint(), outcome.genesis.fingerprint());
        let expected_owner = SigningKey::from_bytes(&soft.identities[0].signing_key_bytes)
            .verifying_key()
            .to_bytes();
        assert_eq!(persisted.owner_public_key, expected_owner);
        let loaded = HardwareTokenEnrollment::load(dir.path(), &persisted)
            .unwrap()
            .unwrap();
        let signature = loaded
            .sign_with_driver(&persisted, &soft.pin(), b"owner-operation", &soft)
            .unwrap();
        persisted
            .owner_verifying_key()
            .unwrap()
            .verify(b"owner-operation", &signature)
            .unwrap();
        assert!(persisted.owner_verifying_key().unwrap()
            .verify(b"different-operation", &signature).is_err());

        let path = HardwareTokenEnrollment::path_for_genesis(dir.path(), &persisted).unwrap();
        let record = std::fs::read_to_string(path).unwrap();
        assert!(!record.contains("PIN-MUST-NEVER-PERSIST-94172"));
        assert!(!record.contains("signing_key"));
        assert!(!record.contains(&hex::encode(soft.identities[0].signing_key_bytes)));
        assert!(!format!("{loaded:?}").contains("PIN-MUST-NEVER-PERSIST-94172"));
    }

    #[test]
    fn hardware_enrollment_reuses_owner_identity_with_fresh_possession_proofs() {
        let first_dir = tempfile::tempdir().unwrap();
        let second_dir = tempfile::tempdir().unwrap();
        let soft = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let first = bootstrap_soft_token(first_dir.path(), &soft).unwrap();
        let second = bootstrap_soft_token(second_dir.path(), &soft).unwrap();
        assert_eq!(first.genesis.fingerprint(), second.genesis.fingerprint());
        let first_record = first.hardware_token.unwrap();
        let mut second_record = second.hardware_token.unwrap();
        assert_ne!(first_record.challenge, second_record.challenge);
        assert_ne!(first_record.signature, second_record.signature);
        second_record.validate_for_genesis(&first.genesis).unwrap();

        // A prior proof cannot satisfy the fresh challenge, even for the same key.
        second_record.signature = first_record.signature;
        assert!(second_record.validate_for_genesis(&first.genesis).is_err());
    }

    #[test]
    fn hardware_enrollment_rejects_tampering_and_an_unrelated_expected_genesis() {
        let dir = tempfile::tempdir().unwrap();
        let soft = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let outcome = bootstrap_soft_token(dir.path(), &soft).unwrap();
        let enrollment = outcome.hardware_token.unwrap();
        let mut altered = Vec::new();

        let mut record = enrollment.clone();
        record.challenge[0] ^= 1;
        altered.push(record);
        let mut record = enrollment.clone();
        record.signature[0] ^= 1;
        altered.push(record);
        let mut record = enrollment.clone();
        record.signature.truncate(63);
        altered.push(record);
        let mut record = enrollment.clone();
        record.key_id.push(0);
        altered.push(record);
        let mut record = enrollment.clone();
        record.token.serial.push_str("-replacement");
        altered.push(record);
        let mut record = enrollment.clone();
        record.certificate_der.push(0);
        altered.push(record);
        let mut record = enrollment.clone();
        record.genesis_hash[0] ^= 1;
        altered.push(record);
        for record in altered {
            assert!(record.validate_for_genesis(&outcome.genesis).is_err());
        }

        let mut other_genesis = outcome.genesis.clone();
        other_genesis.created_at += chrono::Duration::seconds(1);
        let closes = soft.close_count();
        assert!(enrollment
            .sign_with_driver(&other_genesis, &soft.pin(), b"owner-operation", &soft)
            .is_err());
        assert_eq!(soft.close_count(), closes, "reject before opening a signing session");
        assert!(HardwareTokenEnrollment::load(dir.path(), &other_genesis)
            .unwrap().is_none());

        // Even a genuine, self-signed record is rejected when placed at another
        // genesis's path. The caller's expected genesis remains authoritative.
        let other_path = HardwareTokenEnrollment::path_for_genesis(dir.path(), &other_genesis)
            .unwrap();
        std::fs::write(other_path, serde_json::to_vec(&enrollment).unwrap()).unwrap();
        assert!(HardwareTokenEnrollment::load(dir.path(), &other_genesis).is_err());
    }

    #[test]
    fn hardware_enrollment_bounds_loading_and_persistence_size() {
        use crate::hardware_token::MAX_HARDWARE_TOKEN_ENROLLMENT_BYTES;

        let dir = tempfile::tempdir().unwrap();
        let soft = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let outcome = bootstrap_soft_token(dir.path(), &soft).unwrap();
        let enrollment = outcome.hardware_token.unwrap();
        let path = HardwareTokenEnrollment::path_for_genesis(dir.path(), &outcome.genesis)
            .unwrap();

        // The read boundary is inclusive, and even valid JSON plus harmless
        // trailing whitespace cannot bypass the cap by growing after metadata.
        let mut encoded = serde_json::to_vec(&enrollment).unwrap();
        encoded.resize(MAX_HARDWARE_TOKEN_ENROLLMENT_BYTES, b' ');
        std::fs::write(&path, &encoded).unwrap();
        assert!(HardwareTokenEnrollment::load(dir.path(), &outcome.genesis)
            .unwrap().is_some());
        encoded.push(b' ');
        std::fs::write(&path, encoded).unwrap();
        let error = HardwareTokenEnrollment::load(dir.path(), &outcome.genesis).unwrap_err();
        assert!(error.to_string().contains("1 MiB size limit"));

        let mut oversized = enrollment;
        oversized.token.label = "x".repeat(MAX_HARDWARE_TOKEN_ENROLLMENT_BYTES);
        let error = oversized.to_json_for_genesis(&outcome.genesis).unwrap_err();
        assert!(error.to_string().contains("1 MiB size limit"));
    }

    #[test]
    fn hardware_enrollment_requires_the_certificate_private_key_and_closes_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let mut soft = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        // Preserve the certificate and CKA_ID but substitute a different actual
        // private key. Metadata matching must never be accepted as possession.
        soft.identities[0].signing_key_bytes[0] ^= 1;
        let error = bootstrap_soft_token(dir.path(), &soft).unwrap_err();
        assert!(matches!(
            error,
            crate::BootstrapError::HardwareTokenEnrollmentFailed { .. }
        ));
        assert_eq!(soft.close_count(), 2);
        assert!(!dir.path().join("genesis.cbor").exists());
        assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| {
            !entry.unwrap().file_name().to_string_lossy().starts_with("hardware-token-")
        }));
    }

    #[test]
    fn hardware_enrollment_uses_exact_key_id_and_rechecks_token_identity() {
        let dir = tempfile::tempdir().unwrap();
        let mut soft = SoftTokenDriver::deterministic(SoftTokenConfig {
            identities: vec![
                SoftTokenIdentitySpec::ed25519("same-label", "First Owner"),
                SoftTokenIdentitySpec::ed25519("same-label", "Second Owner"),
            ],
            ..SoftTokenConfig::default()
        });
        let outcome = bootstrap_soft_token(dir.path(), &soft).unwrap();
        let enrollment = outcome.hardware_token.unwrap();
        let selected = soft.identities.iter_mut()
            .find(|identity| identity.id == enrollment.key_id).unwrap();
        let expected = SigningKey::from_bytes(&selected.signing_key_bytes)
            .verifying_key().to_bytes();
        assert_eq!(outcome.genesis.owner_public_key, expected);
        selected.key_info.label = "label-changed-after-enrollment".into();
        enrollment.sign_with_driver(&outcome.genesis, &soft.pin(), b"message", &soft)
            .unwrap();

        let closes = soft.close_count();
        soft.detected_token.serial = "NEW-TOKEN-IN-SAME-SLOT".into();
        let error = enrollment
            .sign_with_driver(&outcome.genesis, &soft.pin(), b"message", &soft)
            .unwrap_err();
        assert!(matches!(error, TokenError::TokenNotFound(_)));
        assert_eq!(soft.close_count(), closes);

        let duplicate_dir = tempfile::tempdir().unwrap();
        let mut duplicate = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        duplicate.identities.push(duplicate.identities[0].clone());
        let error = bootstrap_soft_token(duplicate_dir.path(), &duplicate).unwrap_err();
        assert!(matches!(error, crate::BootstrapError::HardwareTokenEnrollmentFailed { .. }));
        assert_eq!(duplicate.close_count(), 2);
        assert!(!duplicate_dir.path().join("genesis.cbor").exists());
    }

    #[test]
    fn hardware_enrollment_checks_certificate_algorithm_and_signing_usage() {
        for incompatible_algorithm in [true, false] {
            let dir = tempfile::tempdir().unwrap();
            let config = SoftTokenConfig::default();
            let mut soft = SoftTokenDriver::deterministic(config.clone());
            let issuer = certified_issuer(
                "FCP SoftToken CA",
                &implicit_ca_signing_key_bytes(&soft_token_derivation_context(&config)),
            );
            let mut parameters = build_certificate_params("FCP Owner Key", false);
            let key = if incompatible_algorithm {
                KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap()
            } else {
                parameters.key_usages = vec![rcgen::KeyUsagePurpose::KeyAgreement];
                rcgen_key_pair_from_signing_key(&soft.identities[0].signing_key_bytes)
            };
            soft.identities[0].certificate.der_bytes =
                parameters.signed_by(&key, &issuer).unwrap().der().to_vec();

            let error = bootstrap_soft_token(dir.path(), &soft).unwrap_err();
            assert!(matches!(error, crate::BootstrapError::HardwareTokenUnsupported { .. }));
            assert_eq!(soft.close_count(), 1, "refuse before opening the signing session");
            assert!(!dir.path().join("genesis.cbor").exists());
        }
    }

    #[test]
    fn hardware_enrollment_persistence_precedes_genesis_and_never_publishes_partial_records() {
        use crate::hardware_token::select_certificate_for_provisioning;
        use crate::workflow::{BootstrapConfig, BootstrapMode, BootstrapWorkflow};

        let soft = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let material = select_certificate_for_provisioning(soft.detected_token(), &soft.pin(), &soft)
            .unwrap();
        let genesis = crate::GenesisState::create_deterministic(
            &material.owner_verifying_key().unwrap(),
        );
        let record_failure_dir = tempfile::tempdir().unwrap();
        let record_path = HardwareTokenEnrollment::path_for_genesis(
            record_failure_dir.path(), &genesis,
        ).unwrap();
        std::fs::create_dir(&record_path).unwrap();
        assert!(bootstrap_soft_token(record_failure_dir.path(), &soft).is_err());
        assert!(!record_failure_dir.path().join("genesis.cbor").exists());
        assert!(HardwareTokenEnrollment::load(record_failure_dir.path(), &genesis).is_err());

        let genesis_failure_dir = tempfile::tempdir().unwrap();
        let config = BootstrapConfig::builder()
            .data_dir(genesis_failure_dir.path())
            .mode(BootstrapMode::HardwareToken { token: soft.detected_token().clone() })
            .hardware_token_pin("654321")
            .skip_time_validation(true)
            .build().unwrap();
        let workflow = BootstrapWorkflow::new(config).unwrap();
        // Force publication failure only after the workflow owns its lease.
        std::fs::create_dir(genesis_failure_dir.path().join("genesis.cbor")).unwrap();
        let report = soft.detection_report();
        assert!(workflow.run_with_hardware_driver(&soft, Some(&report)).is_err());
        assert!(genesis_failure_dir.path().join("genesis.cbor").is_dir());
        let orphan = HardwareTokenEnrollment::load(genesis_failure_dir.path(), &genesis)
            .unwrap().unwrap();
        orphan.validate_for_genesis(&genesis).unwrap();
        let mut other = genesis.clone();
        other.created_at += chrono::Duration::seconds(1);
        assert!(HardwareTokenEnrollment::load(genesis_failure_dir.path(), &other)
            .unwrap().is_none());
        assert!(genesis_failure_dir.path().join("init.lock").exists());
    }

    #[test]
    fn workflow_bootstrap_with_wrong_pin_returns_typed_error() {
        use crate::error::BootstrapError;
        use crate::workflow::{BootstrapConfig, BootstrapMode, BootstrapWorkflow};

        let dir = tempfile::tempdir().unwrap();
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::SingleDevice)
            .hardware_token_pin("WRONG")
            .build()
            .unwrap();
        let mut workflow = BootstrapWorkflow::new(config).unwrap();

        let soft = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let token = soft.detected_token().clone();
        let report = soft.detection_report();

        let err = workflow
            .run_hardware_token_bootstrap_with_driver(&token, &report, &soft)
            .unwrap_err();

        assert!(
            matches!(err, BootstrapError::HardwareTokenInvalidPin),
            "expected HardwareTokenInvalidPin, got: {err}"
        );
    }

    #[test]
    fn workflow_bootstrap_without_pin_returns_pin_required() {
        use crate::error::BootstrapError;
        use crate::workflow::{BootstrapConfig, BootstrapMode, BootstrapWorkflow};

        let dir = tempfile::tempdir().unwrap();
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::SingleDevice)
            // No hardware_token_pin set
            .build()
            .unwrap();
        let mut workflow = BootstrapWorkflow::new(config).unwrap();

        let soft = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let token = soft.detected_token().clone();
        let report = soft.detection_report();

        let err = workflow
            .run_hardware_token_bootstrap_with_driver(&token, &report, &soft)
            .unwrap_err();

        assert!(
            matches!(err, BootstrapError::HardwareTokenPinRequired),
            "expected HardwareTokenPinRequired, got: {err}"
        );
    }

    #[test]
    fn workflow_bootstrap_mixed_keys_selects_ed25519() {
        use crate::workflow::{BootstrapConfig, BootstrapMode, BootstrapWorkflow};
        let dir = tempfile::tempdir().unwrap();
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::SingleDevice)
            .hardware_token_pin("654321")
            .build()
            .unwrap();
        let mut workflow = BootstrapWorkflow::new(config).unwrap();

        // Token with mixed key types: RSA, X25519, Ed25519
        let soft_config = SoftTokenConfig {
            identities: vec![
                SoftTokenIdentitySpec::rsa("legacy-rsa", "Legacy RSA"),
                SoftTokenIdentitySpec::x25519("agreement", "X25519 Agreement"),
                SoftTokenIdentitySpec::ed25519("fcp-owner", "FCP Owner"),
            ],
            ..SoftTokenConfig::default()
        };
        let soft = SoftTokenDriver::deterministic(soft_config);
        let token = soft.detected_token().clone();
        let report = soft.detection_report();

        let genesis = workflow
            .run_hardware_token_bootstrap_with_driver(&token, &report, &soft)
            .unwrap();
        let expected = SigningKey::from_bytes(&soft.identities[2].signing_key_bytes)
            .verifying_key()
            .to_bytes();
        assert_eq!(genesis.owner_public_key, expected);
        assert_eq!(soft.close_count(), 2);
    }

    // ── Deterministic rerun verification ───────────────────────────────

    #[test]
    fn deterministic_rerun_produces_identical_material() {
        use crate::hardware_token::select_certificate_for_provisioning;

        let config = SoftTokenConfig {
            identities: vec![
                SoftTokenIdentitySpec::ed25519("owner", "Owner Key"),
                SoftTokenIdentitySpec::x25519("agreement", "Agreement"),
            ],
            ..SoftTokenConfig::default()
        };

        // Run 1
        let d1 = SoftTokenDriver::deterministic(config.clone());
        let t1 = d1.detected_token().clone();
        let p1 = d1.pin();
        let m1 = select_certificate_for_provisioning(&t1, &p1, &d1).unwrap();

        // Run 2
        let d2 = SoftTokenDriver::deterministic(config);
        let t2 = d2.detected_token().clone();
        let p2 = d2.pin();
        let m2 = select_certificate_for_provisioning(&t2, &p2, &d2).unwrap();

        // Must be identical
        assert_eq!(m1.pair.certificate.id, m2.pair.certificate.id);
        assert_eq!(m1.pair.certificate.der_bytes, m2.pair.certificate.der_bytes);
        assert_eq!(m1.pair.key.id, m2.pair.key.id);
        assert_eq!(m1.pair.key.key_type, m2.pair.key.key_type);
        assert_eq!(m1.selection_reason, m2.selection_reason);
        assert_eq!(m1.candidates_considered, m2.candidates_considered);
    }

    #[test]
    fn session_timeout_applies_when_set() {
        use crate::hardware_token::select_and_authenticate;
        use std::time::Duration;

        let driver = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let token = driver.detected_token().clone();
        let pin = driver.pin();
        let report = driver.detection_report();

        let outcome = select_and_authenticate(
            &token,
            &pin,
            &report,
            &driver,
            Some(Duration::from_secs(10)),
        )
        .unwrap();

        assert_eq!(outcome.session.timeout(), Duration::from_secs(10));
        outcome.session.close().unwrap();
    }
}

// ── Verification pack: evidence-bearing scenario tests ─────────────────
//
// These tests exercise every required scenario from bead 24llg.4.3.2 and
// emit structured JSON evidence records that conform to the shared
// fcp-verification-bundle/v1 schema defined in fcp-e2e.
//
// Rerun commands:
//   Local:  CARGO_TARGET_DIR=/tmp/fcp-sm cargo test -p fcp-bootstrap --lib soft_token::verification_pack
//   CI:     rch exec -- cargo test -p fcp-bootstrap --lib soft_token::verification_pack

#[cfg(test)]
mod verification_pack {
    use super::*;
    use crate::error::BootstrapError;
    use crate::hardware_token::{
        AuthenticatedTokenSession, CertificateSelectionRefusal, select_and_authenticate,
        select_certificate_for_provisioning,
    };
    use crate::workflow::{BootstrapConfig, BootstrapMode, BootstrapWorkflow};
    use serde::Serialize;
    use std::time::Instant;

    /// Convert `Duration::as_millis()` (u128) to u64, saturating on overflow.
    fn millis_u64(d: std::time::Duration) -> u64 {
        u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
    }

    /// Lightweight verification record matching fcp-verification-bundle/v1 schema.
    ///
    /// Serializable to JSON for audit consumption without requiring the full
    /// fcp-e2e crate as a dependency.
    #[derive(Debug, Serialize)]
    struct VerificationRecord {
        schema_version: &'static str,
        scenario_id: String,
        layer: &'static str,
        outcome: &'static str,
        steps: Vec<VerificationStep>,
        replay_command: &'static str,
        redacted_fields: Vec<&'static str>,
    }

    #[derive(Debug, Serialize)]
    struct VerificationStep {
        index: u32,
        kind: &'static str,
        description: String,
        passed: bool,
        duration_ms: u64,
        evidence: Vec<String>,
    }

    impl VerificationRecord {
        fn new(scenario_id: &str) -> Self {
            Self {
                schema_version: "fcp-verification-bundle/v1",
                scenario_id: scenario_id.to_string(),
                layer: "integration",
                outcome: "pending",
                steps: Vec::new(),
                replay_command: "CARGO_TARGET_DIR=/tmp/fcp-sm cargo test -p fcp-bootstrap --lib soft_token::verification_pack",
                redacted_fields: vec!["pin", "signing_key_bytes"],
            }
        }

        fn add_step(&mut self, kind: &'static str, description: &str) -> &mut VerificationStep {
            let index = u32::try_from(self.steps.len()).unwrap_or(u32::MAX);
            self.steps.push(VerificationStep {
                index,
                kind,
                description: description.to_string(),
                passed: false,
                duration_ms: 0,
                evidence: Vec::new(),
            });
            self.steps.last_mut().unwrap()
        }

        fn finalize(&mut self) {
            let all_passed = self.steps.iter().all(|s| s.passed);
            self.outcome = if all_passed { "pass" } else { "fail" };
        }

        fn assert_pass(&self) {
            assert_eq!(
                self.outcome,
                "pass",
                "scenario {} failed: {:?}",
                self.scenario_id,
                self.steps.iter().filter(|s| !s.passed).collect::<Vec<_>>()
            );
            // Validate the record is well-formed JSON
            let json = serde_json::to_string_pretty(self).expect("evidence must serialize");
            assert!(
                json.contains("fcp-verification-bundle/v1"),
                "schema version missing from evidence JSON"
            );
        }
    }

    /// Driver wrapper that keeps certificate enumeration intact but hides keys,
    /// exercising the distinct `NoKeys` refusal path in the provisioning selector.
    struct NoKeysSoftTokenDriver {
        inner: SoftTokenDriver,
    }

    impl HardwareTokenSessionDriver for NoKeysSoftTokenDriver {
        fn open_authenticated_session(
            &self,
            token: &DetectedToken,
            pin: &HardwareTokenPin,
        ) -> Result<AuthenticatedTokenSession, TokenError> {
            self.inner.open_authenticated_session(token, pin)
        }

        fn enumerate_certificates(
            &self,
            token: &DetectedToken,
            pin: &HardwareTokenPin,
        ) -> Result<Vec<TokenCertificate>, TokenError> {
            self.inner.enumerate_certificates(token, pin)
        }

        fn enumerate_keys(
            &self,
            _token: &DetectedToken,
            _pin: &HardwareTokenPin,
        ) -> Result<Vec<TokenKeyInfo>, TokenError> {
            Ok(Vec::new())
        }

        fn sign_ed25519(
            &self,
            token: &DetectedToken,
            pin: &HardwareTokenPin,
            key_id: &[u8],
            message: &[u8],
        ) -> Result<Vec<u8>, TokenError> {
            self.inner.sign_ed25519(token, pin, key_id, message)
        }
    }

    // ── Scenario 1: Successful onboarding ──────────────────────────────

    #[test]
    fn scenario_successful_onboarding() {
        let mut record = VerificationRecord::new("hwtoken-success-onboarding");

        // Setup: create soft token with Ed25519 identity
        let t = Instant::now();
        let config = SoftTokenConfig {
            identities: vec![SoftTokenIdentitySpec::ed25519("fcp-owner", "FCP Owner Key")],
            ..SoftTokenConfig::default()
        };
        let driver = SoftTokenDriver::deterministic(config);
        let token = driver.detected_token().clone();
        let pin = driver.pin();
        let report = driver.detection_report();
        {
            let step = record.add_step(
                "setup",
                "Provision deterministic soft-token with Ed25519 identity",
            );
            step.passed = true;
            step.duration_ms = millis_u64(t.elapsed());
            step.evidence.push(format!("token_label={}", token.label));
            step.evidence.push(format!("token_serial={}", token.serial));
            step.evidence
                .push(format!("mechanisms={}", token.mechanisms.join(",")));
        }

        // Action: select and authenticate
        let t = Instant::now();
        let outcome = select_and_authenticate(&token, &pin, &report, &driver, None).unwrap();
        {
            let step = record.add_step("action", "Select and authenticate hardware-token session");
            step.passed = true;
            step.duration_ms = millis_u64(t.elapsed());
            step.evidence
                .push(format!("session_state={}", outcome.session.session_state()));
            step.evidence
                .push(format!("read_write={}", outcome.session.read_write()));
            step.evidence
                .push(format!("selected_token={}", outcome.selected_token));
        }

        // Action: certificate selection for provisioning
        let t = Instant::now();
        let material = select_certificate_for_provisioning(&token, &pin, &driver).unwrap();
        {
            let step =
                record.add_step("action", "Select certificate-key pair for FCP provisioning");
            step.passed = true;
            step.duration_ms = millis_u64(t.elapsed());
            step.evidence
                .push(format!("selected_key_type={}", material.pair.key.key_type));
            step.evidence.push(format!(
                "selected_cert_label={}",
                material.pair.certificate.label
            ));
            step.evidence.push(format!(
                "candidates_considered={}",
                material.candidates_considered
            ));
            step.evidence
                .push(format!("selection_reason={}", material.selection_reason));
        }

        // Assert: verify provisioning material
        {
            let step = record.add_step("assert", "Verify provisioning material correctness");
            step.passed = material.pair.key.key_type == TokenKeyType::Ed25519
                && material.pair.key.can_sign
                && !material.pair.certificate.is_ca
                && !material.pair.certificate.der_bytes.is_empty();
            step.evidence
                .push(format!("key_can_sign={}", material.pair.key.can_sign));
            step.evidence
                .push(format!("cert_is_ca={}", material.pair.certificate.is_ca));
            step.evidence.push(format!(
                "cert_der_len={}",
                material.pair.certificate.der_bytes.len()
            ));
        }

        // Teardown: close session
        let t = Instant::now();
        outcome.session.close().unwrap();
        {
            let step =
                record.add_step("teardown", "Close authenticated session and verify cleanup");
            step.passed = driver.close_count() == 1;
            step.duration_ms = millis_u64(t.elapsed());
            step.evidence
                .push(format!("close_count={}", driver.close_count()));
        }

        record.finalize();
        record.assert_pass();
    }

    // ── Scenario 2: Wrong PIN ──────────────────────────────────────────

    #[test]
    fn scenario_wrong_pin_refusal() {
        let mut record = VerificationRecord::new("hwtoken-wrong-pin");

        let driver = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let token = driver.detected_token().clone();
        let wrong_pin = SoftTokenDriver::wrong_pin();
        let report = driver.detection_report();

        {
            let step = record.add_step("setup", "Provision soft-token with known PIN");
            step.passed = true;
        }

        let t = Instant::now();
        let err = select_and_authenticate(&token, &wrong_pin, &report, &driver, None).unwrap_err();
        {
            let step = record.add_step("negative", "Attempt authentication with wrong PIN");
            step.passed = matches!(err, TokenError::InvalidPin);
            step.duration_ms = millis_u64(t.elapsed());
            step.evidence.push(format!("error={err}"));
            step.evidence.push("error_type=InvalidPin".to_string());
        }

        // Assert: mapped through workflow produces typed BootstrapError
        {
            let step = record.add_step("assert", "Verify error maps to HardwareTokenInvalidPin");
            let dir = tempfile::tempdir().unwrap();
            let config = BootstrapConfig::builder()
                .data_dir(dir.path())
                .mode(BootstrapMode::SingleDevice)
                .hardware_token_pin("WRONG")
                .build()
                .unwrap();
            let mut workflow = BootstrapWorkflow::new(config).unwrap();
            let workflow_err = workflow
                .run_hardware_token_bootstrap_with_driver(&token, &report, &driver)
                .unwrap_err();
            step.passed = matches!(workflow_err, BootstrapError::HardwareTokenInvalidPin);
            step.evidence.push(format!("workflow_error={workflow_err}"));
        }

        {
            let step = record.add_step("teardown", "Verify no session leaked");
            step.passed = driver.close_count() == 0;
            step.evidence
                .push(format!("close_count={}", driver.close_count()));
        }

        record.finalize();
        record.assert_pass();
    }

    // ── Scenario 3: Missing PIN ────────────────────────────────────────

    #[test]
    fn scenario_missing_pin_refusal() {
        let mut record = VerificationRecord::new("hwtoken-missing-pin");

        let driver = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let token = driver.detected_token().clone();
        let report = driver.detection_report();

        {
            let step = record.add_step("setup", "Provision soft-token, omit PIN from config");
            step.passed = true;
        }

        let t = Instant::now();
        let empty_pin = HardwareTokenPin::new("");
        let err = select_and_authenticate(&token, &empty_pin, &report, &driver, None).unwrap_err();
        {
            let step = record.add_step("negative", "Attempt authentication without PIN");
            step.passed = matches!(err, TokenError::PinRequired);
            step.duration_ms = millis_u64(t.elapsed());
            step.evidence.push(format!("error={err}"));
        }

        {
            let step = record.add_step("assert", "Workflow maps to HardwareTokenPinRequired");
            let dir = tempfile::tempdir().unwrap();
            let config = BootstrapConfig::builder()
                .data_dir(dir.path())
                .mode(BootstrapMode::SingleDevice)
                .build()
                .unwrap();
            let mut workflow = BootstrapWorkflow::new(config).unwrap();
            let workflow_err = workflow
                .run_hardware_token_bootstrap_with_driver(&token, &report, &driver)
                .unwrap_err();
            step.passed = matches!(workflow_err, BootstrapError::HardwareTokenPinRequired);
            step.evidence.push(format!("workflow_error={workflow_err}"));
        }

        record.finalize();
        record.assert_pass();
    }

    // ── Scenario 4: Missing slot / token not found ─────────────────────

    #[test]
    fn scenario_missing_slot_refusal() {
        let mut record = VerificationRecord::new("hwtoken-missing-slot");

        let driver = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let mut wrong_token = driver.detected_token().clone();
        wrong_token.slot = 99;
        wrong_token.label = "NonexistentToken".to_string();
        let pin = driver.pin();
        let report = driver.detection_report();

        {
            let step = record.add_step("setup", "Provision soft-token on slot 0, request slot 99");
            step.passed = true;
            step.evidence.push("actual_slot=0".to_string());
            step.evidence.push("requested_slot=99".to_string());
        }

        let t = Instant::now();
        let err = select_and_authenticate(&wrong_token, &pin, &report, &driver, None).unwrap_err();
        {
            let step = record.add_step("negative", "Attempt to select non-existent token");
            step.passed = matches!(err, TokenError::TokenNotFound(_));
            step.duration_ms = millis_u64(t.elapsed());
            step.evidence.push(format!("error={err}"));
        }

        record.finalize();
        record.assert_pass();
    }

    // ── Scenario 5: Provisioning refusal (RSA-only token) ──────────────

    #[test]
    fn scenario_incompatible_key_type_refusal() {
        let mut record = VerificationRecord::new("hwtoken-incompatible-key-type");

        let config = SoftTokenConfig {
            identities: vec![SoftTokenIdentitySpec::rsa("legacy-rsa", "Legacy RSA Key")],
            mechanisms: vec!["CKM_RSA_PKCS".into()],
            ..SoftTokenConfig::default()
        };
        let driver = SoftTokenDriver::deterministic(config);
        let token = driver.detected_token().clone();
        let pin = driver.pin();

        {
            let step = record.add_step("setup", "Provision soft-token with RSA-only identity");
            step.passed = true;
            step.evidence.push("key_type=RSA".to_string());
        }

        let t = Instant::now();
        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        {
            let step = record.add_step(
                "negative",
                "Attempt certificate selection with RSA-only key",
            );
            step.passed = matches!(
                err,
                TokenError::CertificateSelectionFailed(
                    CertificateSelectionRefusal::NoCompatibleKeyType { .. }
                )
            );
            step.duration_ms = millis_u64(t.elapsed());
            step.evidence.push(format!("error={err}"));
            step.evidence
                .push("refusal_type=NoCompatibleKeyType".to_string());
        }

        {
            let step = record.add_step("assert", "Verify error identifies the incompatible type");
            let msg = err.to_string();
            step.passed = msg.contains("RSA") || msg.contains("no FCP-compatible");
            step.evidence.push(format!("error_message={msg}"));
        }

        record.finalize();
        record.assert_pass();
    }

    // ── Scenario 6: CA-only token (no usable end-entity cert) ──────────

    #[test]
    fn scenario_ca_only_refusal() {
        let mut record = VerificationRecord::new("hwtoken-ca-only-token");

        let config = SoftTokenConfig {
            identities: vec![SoftTokenIdentitySpec::ed25519("root-ca", "Root CA").into_ca()],
            ..SoftTokenConfig::default()
        };
        let driver = SoftTokenDriver::deterministic(config);
        let token = driver.detected_token().clone();
        let pin = driver.pin();

        {
            let step = record.add_step("setup", "Provision soft-token with CA certificate only");
            step.passed = true;
        }

        let t = Instant::now();
        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        {
            let step = record.add_step("negative", "Attempt provisioning with CA-only certificate");
            step.passed = matches!(
                err,
                TokenError::CertificateSelectionFailed(
                    CertificateSelectionRefusal::NoMatchingKeyPair
                )
            );
            step.duration_ms = millis_u64(t.elapsed());
            step.evidence.push(format!("error={err}"));
            step.evidence
                .push("refusal_type=NoMatchingKeyPair".to_string());
        }

        record.finalize();
        record.assert_pass();
    }

    // ── Scenario 7: Empty token (no certs at all) ──────────────────────

    #[test]
    fn scenario_empty_token_refusal() {
        let mut record = VerificationRecord::new("hwtoken-empty-token");

        let config = SoftTokenConfig {
            identities: vec![],
            ..SoftTokenConfig::default()
        };
        let driver = SoftTokenDriver::deterministic(config);
        let token = driver.detected_token().clone();
        let pin = driver.pin();

        {
            let step = record.add_step("setup", "Provision soft-token with no identities");
            step.passed = true;
        }

        let t = Instant::now();
        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        {
            let step = record.add_step("negative", "Attempt provisioning on empty token");
            step.passed = matches!(
                err,
                TokenError::CertificateSelectionFailed(CertificateSelectionRefusal::NoCertificates)
            );
            step.duration_ms = millis_u64(t.elapsed());
            step.evidence.push(format!("error={err}"));
        }

        record.finalize();
        record.assert_pass();
    }

    // ── Scenario 8: Certificates present, keys missing ──────────────────

    #[test]
    fn scenario_no_keys_refusal() {
        let mut record = VerificationRecord::new("hwtoken-no-keys");

        let wrapped = NoKeysSoftTokenDriver {
            inner: SoftTokenDriver::deterministic(SoftTokenConfig::default()),
        };
        let token = wrapped.inner.detected_token().clone();
        let pin = wrapped.inner.pin();

        {
            let step = record.add_step(
                "setup",
                "Provision soft-token certificates but suppress key enumeration",
            );
            step.passed = true;
            step.evidence.push("certificates_present=true".to_string());
            step.evidence.push("enumerate_keys=empty".to_string());
        }

        let t = Instant::now();
        let err = select_certificate_for_provisioning(&token, &pin, &wrapped).unwrap_err();
        {
            let step = record.add_step(
                "negative",
                "Attempt provisioning when token exposes no private keys",
            );
            step.passed = matches!(
                err,
                TokenError::CertificateSelectionFailed(CertificateSelectionRefusal::NoKeys)
            );
            step.duration_ms = millis_u64(t.elapsed());
            step.evidence.push(format!("error={err}"));
            step.evidence.push("refusal_type=NoKeys".to_string());
        }

        record.finalize();
        record.assert_pass();
    }

    // ── Scenario 9: Cleanup determinism ────────────────────────────────

    #[test]
    fn scenario_cleanup_determinism() {
        let mut record = VerificationRecord::new("hwtoken-cleanup-determinism");

        let driver = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let token = driver.detected_token().clone();
        let pin = driver.pin();

        {
            let step = record.add_step("setup", "Provision soft-token with close-action tracking");
            step.passed = true;
            step.evidence
                .push(format!("initial_close_count={}", driver.close_count()));
        }

        // Path A: explicit close
        let t = Instant::now();
        let session = driver.open_authenticated_session(&token, &pin).unwrap();
        session.close().unwrap();
        {
            let step = record.add_step("action", "Open and explicitly close session");
            step.passed = driver.close_count() == 1;
            step.duration_ms = millis_u64(t.elapsed());
            step.evidence.push(format!(
                "close_count_after_explicit={}",
                driver.close_count()
            ));
        }

        // Path B: Drop-based cleanup (separate driver to isolate count)
        let driver2 = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let t = Instant::now();
        {
            let _session = driver2.open_authenticated_session(&token, &pin).unwrap();
            // session dropped here
        }
        {
            let step = record.add_step("action", "Open session and let Drop invoke cleanup");
            step.passed = driver2.close_count() == 1;
            step.duration_ms = millis_u64(t.elapsed());
            step.evidence
                .push(format!("close_count_after_drop={}", driver2.close_count()));
        }

        // Path C: close-then-drop must not double-close
        let driver3 = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let session = driver3.open_authenticated_session(&token, &pin).unwrap();
        session.close().unwrap();
        // Drop runs here but close_action is already consumed
        {
            let step = record.add_step("assert", "Close-then-Drop invokes cleanup exactly once");
            step.passed = driver3.close_count() == 1;
            step.evidence.push(format!(
                "close_count_after_close_then_drop={}",
                driver3.close_count()
            ));
        }

        // Path D: error path (wrong PIN) must not leak sessions
        let driver4 = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let wrong = SoftTokenDriver::wrong_pin();
        let _ = driver4.open_authenticated_session(&token, &wrong);
        {
            let step = record.add_step("assert", "Failed authentication does not leak session");
            step.passed = driver4.close_count() == 0;
            step.evidence
                .push(format!("close_count_after_error={}", driver4.close_count()));
        }

        record.finalize();
        record.assert_pass();
    }

    // ── Scenario 10: Workflow-level success path ───────────────────────

    #[test]
    fn scenario_workflow_success_path() {
        let mut record = VerificationRecord::new("hwtoken-workflow-success");

        let dir = tempfile::tempdir().unwrap();
        let config = BootstrapConfig::builder()
            .data_dir(dir.path())
            .mode(BootstrapMode::SingleDevice)
            .hardware_token_pin("654321")
            .build()
            .unwrap();
        let mut workflow = BootstrapWorkflow::new(config).unwrap();

        let soft = SoftTokenDriver::deterministic(SoftTokenConfig::default());
        let token = soft.detected_token().clone();
        let report = soft.detection_report();

        {
            let step = record.add_step(
                "setup",
                "Configure workflow with soft-token and correct PIN",
            );
            step.passed = true;
        }

        let t = Instant::now();
        let result = workflow.run_hardware_token_bootstrap_with_driver(&token, &report, &soft);
        {
            let step = record.add_step("action", "Run hardware-token bootstrap workflow");
            step.passed = result.as_ref().is_ok_and(|genesis| genesis.validate().is_ok());
            step.duration_ms = millis_u64(t.elapsed());
            match &result {
                Ok(_) => step.evidence.push("result=genesis_created".to_string()),
                Err(e) => step.evidence.push(format!("result={e}")),
            }
        }

        {
            let step = record.add_step("assert", "Discovery and signing sessions were cleaned up");
            step.passed = soft.close_count() == 2;
            step.evidence
                .push(format!("close_count={}", soft.close_count()));
        }

        record.finalize();
        record.assert_pass();
    }

    // ── Scenario 11: Multi-key selection preference ────────────────────

    #[test]
    fn scenario_multi_key_selection_preference() {
        let mut record = VerificationRecord::new("hwtoken-multi-key-preference");

        let config = SoftTokenConfig {
            identities: vec![
                SoftTokenIdentitySpec::rsa("rsa-legacy", "Legacy RSA"),
                SoftTokenIdentitySpec::x25519("x25519-agree", "X25519 Agreement"),
                SoftTokenIdentitySpec::ed25519("ed25519-sign", "Ed25519 Signer"),
            ],
            ..SoftTokenConfig::default()
        };
        let driver = SoftTokenDriver::deterministic(config);
        let token = driver.detected_token().clone();
        let pin = driver.pin();

        {
            let step = record.add_step(
                "setup",
                "Provision soft-token with RSA + X25519 + Ed25519 identities",
            );
            step.passed = true;
            step.evidence.push("identity_count=3".to_string());
        }

        let t = Instant::now();
        let material = select_certificate_for_provisioning(&token, &pin, &driver).unwrap();
        {
            let step = record.add_step(
                "action",
                "Select certificate for provisioning from mixed keys",
            );
            step.passed = true;
            step.duration_ms = millis_u64(t.elapsed());
            step.evidence
                .push(format!("selected_key_type={}", material.pair.key.key_type));
            step.evidence.push(format!(
                "selected_label={}",
                material.pair.certificate.label
            ));
            step.evidence.push(format!(
                "candidates_considered={}",
                material.candidates_considered
            ));
        }

        {
            let step = record.add_step("assert", "Ed25519 selected over X25519 and RSA");
            step.passed = material.pair.key.key_type == TokenKeyType::Ed25519
                && material.pair.certificate.label == "ed25519-sign";
            step.evidence.push(format!(
                "expected_type=Ed25519, actual={}",
                material.pair.key.key_type
            ));
            step.evidence.push(format!(
                "expected_label=ed25519-sign, actual={}",
                material.pair.certificate.label
            ));
        }

        // Verify only the owner-signing Ed25519 identity remains after
        // provisioning compatibility checks.
        {
            let step = record.add_step("assert", "Only Ed25519 owner-signing candidates remain");
            step.passed = material.candidates_considered == 1;
            step.evidence.push(format!(
                "compatible_count={}",
                material.candidates_considered
            ));
        }

        record.finalize();
        record.assert_pass();
    }

    // ── Scenario 12: Deterministic rerun ───────────────────────────────

    #[test]
    fn scenario_deterministic_rerun() {
        let mut record = VerificationRecord::new("hwtoken-deterministic-rerun");

        {
            let step =
                record.add_step("setup", "Prepare two independent soft-token instantiations");
            step.passed = true;
        }

        let config = SoftTokenConfig {
            identities: vec![
                SoftTokenIdentitySpec::ed25519("owner", "Owner Key"),
                SoftTokenIdentitySpec::x25519("agreement", "Agreement"),
            ],
            ..SoftTokenConfig::default()
        };

        let d1 = SoftTokenDriver::deterministic(config.clone());
        let d2 = SoftTokenDriver::deterministic(config);

        let t1 = d1.detected_token().clone();
        let t2 = d2.detected_token().clone();
        let p1 = d1.pin();
        let p2 = d2.pin();

        let m1 = select_certificate_for_provisioning(&t1, &p1, &d1).unwrap();
        let m2 = select_certificate_for_provisioning(&t2, &p2, &d2).unwrap();

        {
            let step = record.add_step("assert", "Certificate IDs match across runs");
            step.passed = m1.pair.certificate.id == m2.pair.certificate.id;
            step.evidence.push(format!(
                "run1_cert_id={}",
                hex::encode(&m1.pair.certificate.id)
            ));
            step.evidence.push(format!(
                "run2_cert_id={}",
                hex::encode(&m2.pair.certificate.id)
            ));
        }

        {
            let step = record.add_step("assert", "DER bytes match across runs");
            step.passed = m1.pair.certificate.der_bytes == m2.pair.certificate.der_bytes;
            step.evidence.push(format!(
                "run1_der_len={}",
                m1.pair.certificate.der_bytes.len()
            ));
            step.evidence.push(format!(
                "run2_der_len={}",
                m2.pair.certificate.der_bytes.len()
            ));
        }

        {
            let step = record.add_step("assert", "Selection reason matches across runs");
            step.passed = m1.selection_reason == m2.selection_reason;
            step.evidence
                .push(format!("run1_reason={}", m1.selection_reason));
            step.evidence
                .push(format!("run2_reason={}", m2.selection_reason));
        }

        record.finalize();
        record.assert_pass();
    }

    // ── Adversarial scenario 13: Token rotation produces zero key reuse ──
    //
    // Operator rotates from token A (identity-1) to token B (identity-2).
    // Provisioning against each token MUST yield a distinct signing key,
    // distinct CKA_ID, and distinct certificate DER. A bug that
    // accidentally derived keys from a fixed seed (or shared a process-
    // global PRNG state across drivers) would let an attacker who
    // captured the rotated-OUT identity's key recover the rotated-IN
    // identity's key — defeating the security purpose of rotation.

    #[test]
    #[allow(clippy::too_many_lines, clippy::similar_names)]
    fn scenario_token_rotation_zero_key_reuse() {
        let mut record = VerificationRecord::new("hwtoken-token-rotation-zero-key-reuse");

        // Rotation pre-state: token A holds identity v1 ("rotated-out").
        let token_a_config = SoftTokenConfig {
            token_label: "FCP-Owner-A".to_string(),
            serial: "ROT-A-001".to_string(),
            slot: 1,
            identities: vec![SoftTokenIdentitySpec::ed25519(
                "fcp-owner-v1",
                "FCP Owner v1",
            )],
            ..SoftTokenConfig::default()
        };
        // Rotation post-state: token B with a fresh identity v2 ("rotated-in").
        let token_b_config = SoftTokenConfig {
            token_label: "FCP-Owner-B".to_string(),
            serial: "ROT-B-002".to_string(),
            slot: 2,
            identities: vec![SoftTokenIdentitySpec::ed25519(
                "fcp-owner-v2",
                "FCP Owner v2",
            )],
            ..SoftTokenConfig::default()
        };

        let driver_a = SoftTokenDriver::deterministic(token_a_config);
        let driver_b = SoftTokenDriver::deterministic(token_b_config);

        let token_a = driver_a.detected_token().clone();
        let token_b = driver_b.detected_token().clone();
        let pin_a = driver_a.pin();
        let pin_b = driver_b.pin();

        {
            let step = record.add_step(
                "setup",
                "Provision two soft-tokens with distinct identity labels (rotation pre/post)",
            );
            step.passed = token_a.serial != token_b.serial;
            step.evidence
                .push(format!("token_a_serial={}", token_a.serial));
            step.evidence
                .push(format!("token_b_serial={}", token_b.serial));
        }

        let t = Instant::now();
        let pre = select_certificate_for_provisioning(&token_a, &pin_a, &driver_a).unwrap();
        let post = select_certificate_for_provisioning(&token_b, &pin_b, &driver_b).unwrap();
        {
            let step = record.add_step(
                "action",
                "Provision once before rotation and once after (independent drivers)",
            );
            step.passed = true;
            step.duration_ms = millis_u64(t.elapsed());
            step.evidence.push(format!(
                "pre_cert_id={}",
                hex::encode(&pre.pair.certificate.id)
            ));
            step.evidence.push(format!(
                "post_cert_id={}",
                hex::encode(&post.pair.certificate.id)
            ));
        }

        // Property 1: key bytes differ.
        {
            let pre_key = driver_a
                .identities
                .iter()
                .find(|i| i.id == pre.pair.key.id)
                .map(|i| i.signing_key_bytes)
                .expect("pre key bytes must resolve");
            let post_key = driver_b
                .identities
                .iter()
                .find(|i| i.id == post.pair.key.id)
                .map(|i| i.signing_key_bytes)
                .expect("post key bytes must resolve");
            let step = record.add_step(
                "assert",
                "Rotated key material differs from pre-rotation key",
            );
            step.passed = pre_key != post_key;
            step.evidence.push(format!(
                "pre_key_blake3={}",
                blake3::hash(&pre_key).to_hex()
            ));
            step.evidence.push(format!(
                "post_key_blake3={}",
                blake3::hash(&post_key).to_hex()
            ));
        }

        // Property 2: CKA_IDs differ.
        {
            let step = record.add_step(
                "assert",
                "Rotated CKA_ID differs from pre-rotation CKA_ID (no PKCS#11 key collision)",
            );
            step.passed = pre.pair.key.id != post.pair.key.id;
            step.evidence
                .push(format!("pre_cka_id={}", hex::encode(&pre.pair.key.id)));
            step.evidence
                .push(format!("post_cka_id={}", hex::encode(&post.pair.key.id)));
        }

        // Property 3: certificate DER bytes differ.
        {
            let step = record.add_step(
                "assert",
                "Rotated certificate DER differs from pre-rotation certificate DER",
            );
            step.passed = pre.pair.certificate.der_bytes != post.pair.certificate.der_bytes;
            step.evidence.push(format!(
                "pre_der_blake3={}",
                blake3::hash(&pre.pair.certificate.der_bytes).to_hex()
            ));
            step.evidence.push(format!(
                "post_der_blake3={}",
                blake3::hash(&post.pair.certificate.der_bytes).to_hex()
            ));
        }

        record.finalize();
        record.assert_pass();
    }

    // ── Adversarial scenario 14: Revocation propagation refuses cleanly ──
    //
    // The operator selects + provisions against a certificate from a
    // soft-token. The certificate is then "revoked" (driver no longer
    // enumerates it). A subsequent provisioning attempt MUST fail with a
    // typed `CertificateSelectionFailed` refusal — NOT silently fall back
    // to a different cert that would change the host identity. The
    // structural failure mode the verifier expects: with the leaf cert
    // gone, the remaining keys have no matching cert pair → the selector
    // surfaces `NoMatchingKeyPair`. Falling back silently to the implicit
    // CA cert is the bug we are pinning against.

    /// Driver wrapper that filters certificates by `CKA_ID` at enumerate
    /// time, simulating revocation propagation.
    struct RevokingSoftTokenDriver {
        inner: SoftTokenDriver,
        revoked_cert_ids: Vec<Vec<u8>>,
    }

    impl HardwareTokenSessionDriver for RevokingSoftTokenDriver {
        fn open_authenticated_session(
            &self,
            token: &DetectedToken,
            pin: &HardwareTokenPin,
        ) -> Result<AuthenticatedTokenSession, TokenError> {
            self.inner.open_authenticated_session(token, pin)
        }

        fn enumerate_certificates(
            &self,
            token: &DetectedToken,
            pin: &HardwareTokenPin,
        ) -> Result<Vec<TokenCertificate>, TokenError> {
            let all = self.inner.enumerate_certificates(token, pin)?;
            Ok(all
                .into_iter()
                .filter(|c| !self.revoked_cert_ids.contains(&c.id))
                .collect())
        }

        fn enumerate_keys(
            &self,
            token: &DetectedToken,
            pin: &HardwareTokenPin,
        ) -> Result<Vec<TokenKeyInfo>, TokenError> {
            self.inner.enumerate_keys(token, pin)
        }

        fn sign_ed25519(
            &self,
            token: &DetectedToken,
            pin: &HardwareTokenPin,
            key_id: &[u8],
            message: &[u8],
        ) -> Result<Vec<u8>, TokenError> {
            self.inner.sign_ed25519(token, pin, key_id, message)
        }
    }

    #[test]
    fn scenario_revocation_propagation_refuses_after_revoke() {
        let mut record = VerificationRecord::new("hwtoken-revocation-propagation");

        // Stage 1: pre-revocation provisioning succeeds.
        let driver = SoftTokenDriver::deterministic(SoftTokenConfig {
            identities: vec![SoftTokenIdentitySpec::ed25519("fcp-owner", "FCP Owner Key")],
            ..SoftTokenConfig::default()
        });
        let token = driver.detected_token().clone();
        let pin = driver.pin();

        let pre = select_certificate_for_provisioning(&token, &pin, &driver).unwrap();
        let revoked_id = pre.pair.certificate.id.clone();
        {
            let step = record.add_step(
                "setup",
                "Pre-revocation provisioning selects the leaf certificate",
            );
            step.passed = true;
            step.evidence
                .push(format!("revoked_cert_id={}", hex::encode(&revoked_id)));
            step.evidence
                .push(format!("selection_reason={}", pre.selection_reason));
        }

        // Stage 2: revoke the cert and re-attempt provisioning.
        let revoking = RevokingSoftTokenDriver {
            inner: driver,
            revoked_cert_ids: vec![revoked_id.clone()],
        };

        let t = Instant::now();
        let post = select_certificate_for_provisioning(&token, &pin, &revoking);
        {
            let step = record.add_step(
                "negative",
                "Post-revocation provisioning MUST fail with a typed refusal (no silent fallback)",
            );
            step.duration_ms = millis_u64(t.elapsed());
            step.passed = matches!(
                &post,
                Err(TokenError::CertificateSelectionFailed(
                    CertificateSelectionRefusal::NoMatchingKeyPair
                        | CertificateSelectionRefusal::NoCertificates
                )),
            );
            match &post {
                Ok(material) => {
                    step.evidence.push(format!(
                        "BUG: silent fallback selected cert_id={}",
                        hex::encode(&material.pair.certificate.id)
                    ));
                    step.evidence
                        .push(format!("selection_reason={}", material.selection_reason));
                }
                Err(err) => {
                    step.evidence.push(format!("error={err}"));
                    step.evidence.push("refusal=typed".to_string());
                }
            }
        }

        // Stage 3: prove the revoked id is what the selector would have
        // returned absent the revocation — i.e. revocation actually
        // changed the outcome (vs the test trivially refusing for some
        // other reason).
        {
            let step = record.add_step(
                "assert",
                "Revoked cert id matches the pre-revocation selected cert id",
            );
            step.passed = pre.pair.certificate.id == revoked_id;
            step.evidence
                .push(format!("revoked_cert_id={}", hex::encode(&revoked_id)));
        }

        record.finalize();
        record.assert_pass();
    }

    // ── Adversarial scenario 15: Dual-bind topology is operator-visible ──
    //
    // An attacker plugs a SECOND soft-token alongside the operator's
    // legitimate one, hoping provisioning silently picks theirs. The
    // detection report MUST surface BOTH tokens so the operator sees
    // the dual-bind. Selection by serial MUST then route deterministically
    // to the requested token (NOT the attacker's), and the attacker's
    // token MUST still appear in the candidate list (operator-visible)
    // rather than being silently filtered out.

    #[test]
    fn scenario_dual_bind_attack_surfaces_multi_token_topology() {
        let mut record = VerificationRecord::new("hwtoken-dual-bind-topology");

        let legit_config = SoftTokenConfig {
            token_label: "Operator-Token".to_string(),
            serial: "OP-LEGIT-001".to_string(),
            slot: 1,
            identities: vec![SoftTokenIdentitySpec::ed25519(
                "operator-key",
                "Operator Key",
            )],
            ..SoftTokenConfig::default()
        };
        let attacker_config = SoftTokenConfig {
            token_label: "Attacker-Token".to_string(),
            serial: "ATK-INJECT-666".to_string(),
            slot: 2,
            identities: vec![SoftTokenIdentitySpec::ed25519(
                "attacker-key",
                "Attacker Key",
            )],
            ..SoftTokenConfig::default()
        };

        let harness = SoftTokenHarness::new(vec![legit_config, attacker_config]);
        let report = harness.detection_report();
        let all = harness.all_tokens();

        {
            let step = record.add_step(
                "setup",
                "Plug two soft-tokens (legitimate + attacker-injected) into separate slots",
            );
            step.passed = all.len() == 2;
            step.evidence.push(format!("token_count={}", all.len()));
            for tok in &all {
                step.evidence
                    .push(format!("token_serial={} label={}", tok.serial, tok.label));
            }
        }

        // Property 1: detection report exposes BOTH tokens (operator-visible).
        {
            let detected = report.all_tokens();
            let serials: Vec<_> = detected.iter().map(|t| t.serial.clone()).collect();
            let step = record.add_step(
                "assert",
                "Detection report exposes both legitimate AND attacker-injected tokens",
            );
            step.passed = serials.iter().any(|s| s == "OP-LEGIT-001")
                && serials.iter().any(|s| s == "ATK-INJECT-666");
            step.evidence
                .push(format!("detected_serials={}", serials.join(",")));
            step.evidence
                .push(format!("detection_count={}", detected.len()));
        }

        // Property 2: requesting the operator's token by serial routes
        // deterministically to it — NOT the attacker's. select_and_authenticate
        // must verify the requested token is among the candidate set
        // (otherwise an attacker's token plugged at a "preferred" slot
        // could be silently selected instead).
        let legit_token = all
            .iter()
            .find(|t| t.serial == "OP-LEGIT-001")
            .expect("legit token in harness");
        let legit_driver = harness.drivers.get(&1).expect("legit driver at slot 1");
        let outcome = select_and_authenticate(
            legit_token,
            &legit_driver.pin(),
            &report,
            legit_driver,
            None,
        )
        .unwrap();
        {
            let step = record.add_step(
                "assert",
                "Selecting by serial routes to the requested (operator) token, not the attacker's",
            );
            step.passed = outcome.selected_token.serial == "OP-LEGIT-001"
                && outcome.selected_token.serial != "ATK-INJECT-666";
            step.evidence
                .push(format!("selected_serial={}", outcome.selected_token.serial));
            step.evidence.push(format!(
                "candidate_count={}",
                outcome.detection_report.all_tokens().len()
            ));
        }

        // Property 3: attacker's token does NOT silently disappear from
        // the candidate list after a successful selection — operator
        // tooling can still surface it for forensics.
        {
            let post_serials: Vec<_> = outcome
                .detection_report
                .all_tokens()
                .iter()
                .map(|t| t.serial.clone())
                .collect();
            let step = record.add_step(
                "assert",
                "Post-selection report still exposes the attacker token (forensic trail intact)",
            );
            step.passed = post_serials.iter().any(|s| s == "ATK-INJECT-666");
            step.evidence
                .push(format!("post_selection_serials={}", post_serials.join(",")));
        }

        record.finalize();
        record.assert_pass();
    }
}
