//! Hardware token detection and integration.
//!
//! This module provides cross-platform support for detecting and using
//! hardware security modules (HSMs) and smart cards via PKCS#11.

use crate::error::{BootstrapError, BootstrapResult};
use crate::genesis::GenesisState;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as Pkcs11Error, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, SessionState, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;
use fcp_crypto::{Ed25519Signature, Ed25519VerifyingKey};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use x509_parser::{certificate::X509Certificate, parse_x509_certificate, time::ASN1Time};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Information about a detected hardware token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedToken {
    /// PKCS#11 provider library path.
    pub provider: PathBuf,

    /// Slot number.
    pub slot: u32,

    /// Token label.
    pub label: String,

    /// Manufacturer name.
    pub manufacturer: String,

    /// Token serial number.
    pub serial: String,

    /// Supported mechanisms.
    pub mechanisms: Vec<String>,
}

impl DetectedToken {
    /// Check if this token supports Ed25519.
    #[must_use]
    pub fn supports_ed25519(&self) -> bool {
        self.mechanisms
            .iter()
            .any(|m| m.contains("ED25519") || m.contains("EDDSA"))
    }

    /// Check if this token supports ECDH for X25519.
    #[must_use]
    pub fn supports_x25519(&self) -> bool {
        self.mechanisms
            .iter()
            .any(|m| m.contains("X25519") || m.contains("ECDH"))
    }
}

impl std::fmt::Display for DetectedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} ({}) [slot {}]",
            self.label, self.manufacturer, self.slot
        )
    }
}

/// Discovery stages for provider and slot probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionStage {
    /// The configured provider path does not exist on disk.
    ProviderMissing,
    /// The provider library could not be loaded.
    LoadProvider,
    /// The provider library could not be initialized.
    InitializeProvider,
    /// Slot enumeration failed.
    EnumerateSlots,
    /// The slot identifier could not be represented in `DetectedToken`.
    NormalizeSlotId,
    /// Token metadata could not be read for a slot.
    ReadTokenInfo,
    /// Mechanism enumeration failed for a slot.
    ReadMechanisms,
    /// The provider library could not be finalized cleanly.
    FinalizeProvider,
}

/// A specific discovery failure surfaced during PKCS#11 probing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectionIssue {
    /// Provider library path that produced the issue.
    pub provider: PathBuf,
    /// Detection stage that failed.
    pub stage: DetectionStage,
    /// Optional raw slot identifier associated with the issue.
    pub slot: Option<u64>,
    /// Human-readable failure details.
    pub message: String,
}

impl DetectionIssue {
    fn new(
        provider: &Path,
        stage: DetectionStage,
        slot: Option<u64>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            provider: provider.to_path_buf(),
            stage,
            slot,
            message: message.into(),
        }
    }
}

/// The result of probing a single PKCS#11 provider library.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderDetectionResult {
    /// Provider library path that was probed.
    pub provider: PathBuf,
    /// Token candidates discovered from this provider.
    pub tokens: Vec<DetectedToken>,
    /// Structured issues encountered while probing this provider.
    pub issues: Vec<DetectionIssue>,
}

impl ProviderDetectionResult {
    fn new(provider: &Path) -> Self {
        Self {
            provider: provider.to_path_buf(),
            tokens: Vec::new(),
            issues: Vec::new(),
        }
    }

    fn push_issue(&mut self, stage: DetectionStage, slot: Option<u64>, message: impl Into<String>) {
        self.issues
            .push(DetectionIssue::new(&self.provider, stage, slot, message));
    }
}

/// Aggregate report for a hardware-token discovery pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TokenDetectionReport {
    /// Per-provider probe results in probe order.
    pub providers: Vec<ProviderDetectionResult>,
}

impl TokenDetectionReport {
    /// Return every discovered token candidate across all providers.
    #[must_use]
    pub fn all_tokens(&self) -> Vec<DetectedToken> {
        self.providers
            .iter()
            .flat_map(|provider| provider.tokens.iter().cloned())
            .collect()
    }

    /// Return only FCP-compatible tokens across all providers.
    #[must_use]
    pub fn fcp_compatible_tokens(&self) -> Vec<DetectedToken> {
        self.providers
            .iter()
            .flat_map(|provider| provider.tokens.iter().cloned())
            .filter(DetectedToken::supports_ed25519)
            .collect()
    }

    /// Return every structured issue reported during discovery.
    #[must_use]
    pub fn issues(&self) -> Vec<DetectionIssue> {
        self.providers
            .iter()
            .flat_map(|provider| provider.issues.iter().cloned())
            .collect()
    }

    /// Whether discovery found at least one token candidate.
    #[must_use]
    pub fn has_detected_tokens(&self) -> bool {
        self.providers
            .iter()
            .any(|provider| !provider.tokens.is_empty())
    }
}

/// Redacted PIN material for hardware-token login.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HardwareTokenPin {
    value: String,
    // Compare on a fixed-width digest so length mismatches do not short-circuit.
    digest: [u8; 32],
}

impl PartialEq for HardwareTokenPin {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        self.digest.ct_eq(&other.digest).into()
    }
}

impl Eq for HardwareTokenPin {}

impl HardwareTokenPin {
    /// Create a new hardware-token PIN wrapper.
    #[must_use]
    pub fn new(pin: impl Into<String>) -> Self {
        let value = pin.into();
        let digest = *blake3::hash(value.as_bytes()).as_bytes();
        Self { value, digest }
    }

    /// Whether the provided PIN is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    fn to_auth_pin(&self) -> AuthPin {
        AuthPin::new(self.value.clone().into())
    }
}

impl fmt::Debug for HardwareTokenPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Normalized state for an authenticated PKCS#11 session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthenticatedSessionState {
    /// Read-only session, no authenticated user.
    ReadOnlyPublic,
    /// Read-only session authenticated as a normal user.
    ReadOnlyUser,
    /// Read-write session, no authenticated user.
    ReadWritePublic,
    /// Read-write session authenticated as a normal user.
    ReadWriteUser,
    /// Read-write session authenticated as the security officer.
    ReadWriteSecurityOfficer,
}

impl From<SessionState> for AuthenticatedSessionState {
    fn from(value: SessionState) -> Self {
        match value {
            SessionState::RoPublic => Self::ReadOnlyPublic,
            SessionState::RoUser => Self::ReadOnlyUser,
            SessionState::RwPublic => Self::ReadWritePublic,
            SessionState::RwUser => Self::ReadWriteUser,
            SessionState::RwSecurityOfficer => Self::ReadWriteSecurityOfficer,
        }
    }
}

impl fmt::Display for AuthenticatedSessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ReadOnlyPublic => "ro-public",
            Self::ReadOnlyUser => "ro-user",
            Self::ReadWritePublic => "rw-public",
            Self::ReadWriteUser => "rw-user",
            Self::ReadWriteSecurityOfficer => "rw-so",
        };
        f.write_str(label)
    }
}

/// Default session timeout: 5 minutes.
const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(300);

/// A live authenticated hardware-token session with redaction-safe metadata.
pub struct AuthenticatedTokenSession {
    token: DetectedToken,
    session_state: AuthenticatedSessionState,
    read_write: bool,
    created_at: Instant,
    timeout: Duration,
    close_action: Option<Box<dyn FnOnce() -> Result<(), TokenError>>>,
}

impl fmt::Debug for AuthenticatedTokenSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedTokenSession")
            .field("token", &self.token)
            .field("session_state", &self.session_state)
            .field("read_write", &self.read_write)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedTokenSession {
    /// Create an authenticated session wrapper with an injected close action.
    pub(crate) fn with_close_action(
        token: DetectedToken,
        session_state: AuthenticatedSessionState,
        read_write: bool,
        close_action: impl FnOnce() -> Result<(), TokenError> + 'static,
    ) -> Self {
        Self {
            token,
            session_state,
            read_write,
            created_at: Instant::now(),
            timeout: DEFAULT_SESSION_TIMEOUT,
            close_action: Some(Box::new(close_action)),
        }
    }

    /// The canonical detected token that was authenticated.
    #[must_use]
    pub const fn token(&self) -> &DetectedToken {
        &self.token
    }

    /// The authenticated session state reported by the token.
    #[must_use]
    pub const fn session_state(&self) -> AuthenticatedSessionState {
        self.session_state
    }

    /// Whether the session has read-write access.
    #[must_use]
    pub const fn read_write(&self) -> bool {
        self.read_write
    }

    /// Whether this session has exceeded its timeout.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.created_at.elapsed() > self.timeout
    }

    /// The elapsed time since this session was authenticated.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.created_at.elapsed()
    }

    /// The configured session timeout.
    #[must_use]
    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Set a custom session timeout.
    pub const fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Check that the session is still valid (not expired) before use.
    ///
    /// # Errors
    ///
    /// Returns `TokenError::Disconnected` if the session has expired.
    pub fn check_alive(&self) -> Result<(), TokenError> {
        if self.is_expired() {
            return Err(TokenError::SessionExpired {
                elapsed: self.created_at.elapsed(),
                timeout: self.timeout,
            });
        }
        Ok(())
    }

    /// Close the authenticated session immediately.
    ///
    /// # Errors
    ///
    /// Returns a token error if logout or session cleanup fails.
    pub fn close(mut self) -> Result<(), TokenError> {
        if let Some(close_action) = self.close_action.take() {
            return close_action();
        }
        Ok(())
    }
}

impl Drop for AuthenticatedTokenSession {
    fn drop(&mut self) {
        if let Some(close_action) = self.close_action.take() {
            if let Err(err) = close_action() {
                tracing::warn!(
                    provider = %self.token.provider.display(),
                    slot = self.token.slot,
                    label = %self.token.label,
                    ?err,
                    "Failed to close authenticated hardware-token session"
                );
            }
        }
    }
}

/// Driver abstraction for opening authenticated hardware-token sessions
/// and enumerating certificate/key objects.
pub(crate) trait HardwareTokenSessionDriver: Send + Sync {
    /// Open and authenticate a session for the selected token.
    ///
    /// # Errors
    ///
    /// Returns a token error if the provider, slot, or login sequence fails.
    fn open_authenticated_session(
        &self,
        token: &DetectedToken,
        pin: &HardwareTokenPin,
    ) -> Result<AuthenticatedTokenSession, TokenError>;

    /// Enumerate all certificate objects visible in the authenticated session.
    ///
    /// # Errors
    ///
    /// Returns a token error if the PKCS#11 find-objects call fails.
    fn enumerate_certificates(
        &self,
        token: &DetectedToken,
        pin: &HardwareTokenPin,
    ) -> Result<Vec<TokenCertificate>, TokenError>;

    /// Enumerate all private key objects visible in the authenticated session.
    ///
    /// # Errors
    ///
    /// Returns a token error if the PKCS#11 find-objects call fails.
    fn enumerate_keys(
        &self,
        token: &DetectedToken,
        pin: &HardwareTokenPin,
    ) -> Result<Vec<TokenKeyInfo>, TokenError>;

    /// Sign with the unique Ed25519 private key having this exact `CKA_ID`.
    /// The driver must close its authenticated session before returning.
    fn sign_ed25519(
        &self,
        token: &DetectedToken,
        pin: &HardwareTokenPin,
        key_id: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>, TokenError>;
}

/// Real PKCS#11-backed session driver.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Pkcs11SessionDriver;

impl HardwareTokenSessionDriver for Pkcs11SessionDriver {
    fn open_authenticated_session(
        &self,
        token: &DetectedToken,
        pin: &HardwareTokenPin,
    ) -> Result<AuthenticatedTokenSession, TokenError> {
        if pin.is_empty() {
            return Err(TokenError::PinRequired);
        }

        let pkcs11 = acquire_provider_context(&token.provider)?;

        let slot = Slot::try_from(u64::from(token.slot))
            .map_err(|err| TokenError::Pkcs11(err.to_string()))?;
        let session = match pkcs11.open_rw_session(slot) {
            Ok(session) => session,
            Err(err) => {
                let _ = finalize_pkcs11_context(&token.provider, pkcs11);
                return Err(map_pkcs11_error(err));
            }
        };

        if let Err(error) = validate_live_token_identity(&pkcs11, slot, token) {
            cleanup_failed_session(&token.provider, session, pkcs11);
            return Err(error);
        }
        let auth_pin = pin.to_auth_pin();
        match session.login(UserType::User, Some(&auth_pin)) {
            Ok(()) | Err(Pkcs11Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
            Err(err) => {
                cleanup_failed_session(&token.provider, session, pkcs11);
                return Err(map_pkcs11_error(err));
            }
        }

        let session_info = match session.get_session_info() {
            Ok(session_info) => session_info,
            Err(err) => {
                cleanup_failed_session(&token.provider, session, pkcs11);
                return Err(map_pkcs11_error(err));
            }
        };

        let session_state = AuthenticatedSessionState::from(session_info.session_state());
        let read_write = session_info.read_write();
        let provider = token.provider.clone();

        Ok(AuthenticatedTokenSession::with_close_action(
            token.clone(),
            session_state,
            read_write,
            move || {
                let close_result = close_pkcs11_session(session, session_state);
                let finalize_result = finalize_pkcs11_context(&provider, pkcs11);
                close_result.and(finalize_result)
            },
        ))
    }

    fn enumerate_certificates(
        &self,
        token: &DetectedToken,
        pin: &HardwareTokenPin,
    ) -> Result<Vec<TokenCertificate>, TokenError> {
        if pin.is_empty() {
            return Err(TokenError::PinRequired);
        }

        let enumeration = open_enumeration_session(token, pin)?;
        let template = [Attribute::Class(ObjectClass::CERTIFICATE)];
        let handles = enumeration
            .session()
            .find_objects(&template)
            .map_err(map_pkcs11_error)?;

        let mut certs = Vec::new();
        for handle in handles {
            match read_certificate_object(enumeration.session(), handle) {
                Ok(cert) => certs.push(cert),
                Err(err) => {
                    tracing::warn!(
                        handle = ?handle,
                        error = %err,
                        "Skipping unreadable certificate object"
                    );
                }
            }
        }

        enumeration.close()?;
        Ok(certs)
    }

    fn enumerate_keys(
        &self,
        token: &DetectedToken,
        pin: &HardwareTokenPin,
    ) -> Result<Vec<TokenKeyInfo>, TokenError> {
        if pin.is_empty() {
            return Err(TokenError::PinRequired);
        }

        let enumeration = open_enumeration_session(token, pin)?;
        let template = [Attribute::Class(ObjectClass::PRIVATE_KEY)];
        let handles = enumeration
            .session()
            .find_objects(&template)
            .map_err(map_pkcs11_error)?;

        let mut keys = Vec::new();
        for handle in handles {
            match read_key_object(enumeration.session(), handle) {
                Ok(key) => keys.push(key),
                Err(err) => {
                    tracing::warn!(
                        handle = ?handle,
                        error = %err,
                        "Skipping unreadable key object"
                    );
                }
            }
        }

        enumeration.close()?;
        Ok(keys)
    }

    fn sign_ed25519(
        &self,
        token: &DetectedToken,
        pin: &HardwareTokenPin,
        key_id: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>, TokenError> {
        if key_id.is_empty() {
            return Err(TokenError::Enrollment("owner key identifier is empty".into()));
        }

        // Reopen by token identity and object ID, never by a session-local
        // object handle or a potentially duplicated human-readable label.
        let signing = open_enumeration_session(token, pin)?;
        let result = (|| {
            let handles = signing
                .session()
                .find_objects(&[
                    Attribute::Class(ObjectClass::PRIVATE_KEY),
                    Attribute::Id(key_id.to_vec()),
                ])
                .map_err(map_pkcs11_error)?;
            let handle = match handles.as_slice() {
                [] => return Err(TokenError::KeyNotFound(hex::encode(key_id))),
                [handle] => *handle,
                _ => {
                    return Err(TokenError::Enrollment(
                        "multiple private keys have the enrolled identifier".into(),
                    ));
                }
            };
            let key = read_key_object(signing.session(), handle)?;
            if key.id != key_id || !is_owner_signing_key(&key) {
                return Err(TokenError::UnsupportedMechanism(
                    "the enrolled key must support Ed25519 signing".into(),
                ));
            }
            signing
                .session()
                .sign(
                    &Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519)),
                    handle,
                    message,
                )
                .map_err(map_pkcs11_error)
        })();
        let cleanup = signing.close();
        let signature = result?;
        cleanup?;
        Ok(signature)
    }
}

/// RAII wrapper for a PIN-authenticated enumeration session (br-tcp0f).
///
/// Pre-tcp0f the enumeration path opened a read-write user session via
/// PKCS#11 `C_Login`, returned the bare `Session`, and the callers invoked
/// only `session.close()` afterwards — never `C_Logout` and never
/// `C_Finalize`. The token was therefore left in an authenticated state
/// and the provider context initialized after the temporary PIN-authenticated
/// browse step, extending the lifetime of authenticated hardware-token
/// access without re-prompting for the PIN.
///
/// This wrapper owns the PKCS#11 context + session
/// and routes teardown through [`close_pkcs11_session`] (logout + close)
/// and [`finalize_pkcs11_context`]. An [`EnumerationSession::close`]
/// consuming method is the preferred exit path; [`Drop`] runs the same
/// cleanup on panic or early return as a defense-in-depth backstop.
struct EnumerationSession {
    provider: PathBuf,
    pkcs11: Option<Pkcs11>,
    session: Option<Session>,
}

impl EnumerationSession {
    const fn session(&self) -> &Session {
        self.session
            .as_ref()
            .expect("enumeration session is still open")
    }

    fn close(mut self) -> Result<(), TokenError> {
        self.run_cleanup()
    }

    fn run_cleanup(&mut self) -> Result<(), TokenError> {
        let session = self.session.take();
        let pkcs11 = self.pkcs11.take();
        match (session, pkcs11) {
            (Some(session), Some(pkcs11)) => {
                // Login was performed as UserType::User on a read-write
                // session (see `open_enumeration_session`), so the state
                // at close time is always ReadWriteUser.
                let close_result =
                    close_pkcs11_session(session, AuthenticatedSessionState::ReadWriteUser);
                let finalize_result = finalize_pkcs11_context(&self.provider, pkcs11);
                close_result.and(finalize_result)
            }
            _ => Ok(()),
        }
    }
}

impl Drop for EnumerationSession {
    fn drop(&mut self) {
        if self.session.is_none() && self.pkcs11.is_none() {
            return;
        }
        if let Err(err) = self.run_cleanup() {
            tracing::warn!(
                component = "fcp_bootstrap.hardware_token",
                error = %err,
                "EnumerationSession dropped without close(); best-effort cleanup failed"
            );
        } else {
            tracing::warn!(
                component = "fcp_bootstrap.hardware_token",
                "EnumerationSession dropped without close(); fell back to best-effort cleanup"
            );
        }
    }
}

/// Open a temporary authenticated session for object enumeration.
///
/// The returned [`EnumerationSession`] carries the PKCS#11 context
/// and read-write user session so that teardown
/// (logout + close + finalize) always runs, whether via
/// [`EnumerationSession::close`] or [`Drop`]. See br-tcp0f.
fn open_enumeration_session(
    token: &DetectedToken,
    pin: &HardwareTokenPin,
) -> Result<EnumerationSession, TokenError> {
    if pin.is_empty() {
        return Err(TokenError::PinRequired);
    }

    let pkcs11 = acquire_provider_context(&token.provider)?;

    let slot = match Slot::try_from(u64::from(token.slot)) {
        Ok(slot) => slot,
        Err(err) => {
            let _ = finalize_pkcs11_context(&token.provider, pkcs11);
            return Err(TokenError::Pkcs11(err.to_string()));
        }
    };

    let session = match pkcs11.open_rw_session(slot) {
        Ok(session) => session,
        Err(err) => {
            let _ = finalize_pkcs11_context(&token.provider, pkcs11);
            return Err(map_pkcs11_error(err));
        }
    };

    // Slot numbers may be reassigned after removal. Check the physical token
    // identity on the reopened slot before presenting its PIN or using a key.
    if let Err(error) = validate_live_token_identity(&pkcs11, slot, token) {
        cleanup_failed_session(&token.provider, session, pkcs11);
        return Err(error);
    }
    let auth_pin = pin.to_auth_pin();
    match session.login(UserType::User, Some(&auth_pin)) {
        Ok(()) | Err(Pkcs11Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
        Err(err) => {
            cleanup_failed_session(&token.provider, session, pkcs11);
            return Err(map_pkcs11_error(err));
        }
    }

    Ok(EnumerationSession {
        provider: token.provider.clone(),
        pkcs11: Some(pkcs11),
        session: Some(session),
    })
}

fn validate_live_token_identity(
    pkcs11: &Pkcs11,
    slot: Slot,
    expected: &DetectedToken,
) -> Result<(), TokenError> {
    let info = pkcs11.get_token_info(slot).map_err(map_pkcs11_error)?;
    if normalize_token_field(info.serial_number()) != expected.serial
        || normalize_token_field(info.label()) != expected.label
        || normalize_token_field(info.manufacturer_id()) != expected.manufacturer
    {
        return Err(TokenError::TokenNotFound(token_locator(expected)));
    }
    Ok(())
}

/// Read a certificate object's attributes from its handle.
fn read_certificate_object(
    session: &Session,
    handle: ObjectHandle,
) -> Result<TokenCertificate, TokenError> {
    let attrs = session
        .get_attributes(
            handle,
            &[
                AttributeType::Label,
                AttributeType::Id,
                AttributeType::Value,
                AttributeType::Subject,
                AttributeType::Issuer,
            ],
        )
        .map_err(map_pkcs11_error)?;

    let mut label = String::new();
    let mut id = Vec::new();
    let mut der_bytes = Vec::new();
    let mut subject = String::new();
    let mut issuer = String::new();

    for attr in attrs {
        match attr {
            Attribute::Label(v) => label = String::from_utf8_lossy(&v).into_owned(),
            Attribute::Id(v) => id = v,
            Attribute::Value(v) => der_bytes = v,
            Attribute::Subject(v) => {
                subject = String::from_utf8_lossy(&v).into_owned();
            }
            Attribute::Issuer(v) => {
                issuer = String::from_utf8_lossy(&v).into_owned();
            }
            _ => {}
        }
    }

    // Heuristic: if subject == issuer the certificate is likely self-signed / CA.
    // CKA_CERTIFICATE_CATEGORY is not available in our cryptoki version.
    let is_ca = !subject.is_empty() && subject == issuer;

    Ok(TokenCertificate {
        label,
        id,
        der_bytes,
        subject,
        issuer,
        is_ca,
    })
}

/// Read a private key object's attributes from its handle.
fn read_key_object(session: &Session, handle: ObjectHandle) -> Result<TokenKeyInfo, TokenError> {
    let attrs = session
        .get_attributes(
            handle,
            &[
                AttributeType::Label,
                AttributeType::Id,
                AttributeType::KeyType,
                AttributeType::Sign,
                AttributeType::Derive,
            ],
        )
        .map_err(map_pkcs11_error)?;

    let mut label = String::new();
    let mut id = Vec::new();
    let mut key_type = TokenKeyType::Other(0);
    let mut can_sign = false;
    let mut can_derive = false;

    for attr in attrs {
        match attr {
            Attribute::Label(v) => label = String::from_utf8_lossy(&v).into_owned(),
            Attribute::Id(v) => id = v,
            Attribute::KeyType(kt) => {
                key_type = map_cryptoki_key_type(kt);
            }
            Attribute::Sign(v) => can_sign = v,
            Attribute::Derive(v) => can_derive = v,
            _ => {}
        }
    }

    Ok(TokenKeyInfo {
        label,
        id,
        key_type,
        can_sign,
        can_derive,
    })
}

/// Map a cryptoki `KeyType` to our `TokenKeyType`.
fn map_cryptoki_key_type(kt: KeyType) -> TokenKeyType {
    if kt == KeyType::EC_EDWARDS {
        TokenKeyType::Ed25519
    } else if kt == KeyType::EC_MONTGOMERY {
        TokenKeyType::X25519
    } else if kt == KeyType::EC {
        // EC could be P-256 or P-384; without OID inspection we classify as P-256.
        TokenKeyType::EcdsaP256
    } else if kt == KeyType::RSA {
        TokenKeyType::Rsa
    } else {
        TokenKeyType::Other(0)
    }
}

/// Rank detected tokens into a deterministic bootstrap order.
#[must_use]
pub fn rank_detected_tokens(tokens: &[DetectedToken]) -> Vec<DetectedToken> {
    let mut ranked = tokens.to_vec();
    ranked.sort_by_key(token_rank_key);
    ranked
}

type TokenRankKey = (
    Reverse<bool>,
    Reverse<bool>,
    PathBuf,
    u32,
    String,
    String,
    String,
);

fn token_rank_key(token: &DetectedToken) -> TokenRankKey {
    (
        Reverse(token.supports_ed25519()),
        Reverse(token.supports_x25519()),
        token.provider.clone(),
        token.slot,
        token.serial.clone(),
        token.label.clone(),
        token.manufacturer.clone(),
    )
}

fn token_identity_matches(requested: &DetectedToken, candidate: &DetectedToken) -> bool {
    requested.provider == candidate.provider
        && requested.slot == candidate.slot
        && token_field_matches(&requested.label, &candidate.label)
        && token_field_matches(&requested.manufacturer, &candidate.manufacturer)
        && token_field_matches(&requested.serial, &candidate.serial)
}

fn token_field_matches(requested: &str, candidate: &str) -> bool {
    // An unspecified request may accept discovered metadata. Discovery must
    // never erase a known requested identity by replacing it with "unknown".
    requested == candidate || requested == "unknown"
}

/// Canonicalize a requested bootstrap token against the latest discovery pass.
///
/// # Errors
///
/// Returns a typed refusal if the token is absent or lacks the required
/// Ed25519 signing capability.
pub(crate) fn select_bootstrap_token(
    requested: &DetectedToken,
    candidates: &[DetectedToken],
) -> Result<DetectedToken, TokenError> {
    if candidates.is_empty() {
        return Err(TokenError::NoTokens);
    }

    let ranked = rank_detected_tokens(candidates);
    let Some(candidate) = ranked
        .into_iter()
        .find(|candidate| token_identity_matches(requested, candidate))
    else {
        return Err(TokenError::TokenNotFound(token_locator(requested)));
    };

    if !candidate.supports_ed25519() {
        return Err(TokenError::UnsupportedMechanism(
            "Ed25519 signing".to_string(),
        ));
    }

    Ok(candidate)
}

/// Establish a truthful authenticated bootstrap session for a selected token.
///
/// # Errors
///
/// Returns a typed refusal if the PIN is missing, the token is unavailable, or
/// PKCS#11 login fails.
pub(crate) fn authenticate_bootstrap_session_with_driver<D: HardwareTokenSessionDriver>(
    requested: &DetectedToken,
    candidates: &[DetectedToken],
    pin: &HardwareTokenPin,
    driver: &D,
) -> Result<AuthenticatedTokenSession, TokenError> {
    if pin.is_empty() {
        return Err(TokenError::PinRequired);
    }

    let selected = select_bootstrap_token(requested, candidates)?;
    driver.open_authenticated_session(&selected, pin)
}

/// The outcome of a hardware-token session-selection flow.
///
/// Captures both the authenticated session and the discovery context
/// so downstream consumers (certificate selection, provisioning) can
/// make decisions with full context.
#[derive(Debug)]
pub struct SessionSelectionOutcome {
    /// The authenticated session, ready for downstream operations.
    pub session: AuthenticatedTokenSession,
    /// The full discovery report that produced the candidate list.
    pub detection_report: TokenDetectionReport,
    /// The token that was selected after ranking.
    pub selected_token: DetectedToken,
}

// ── Certificate and key enumeration types ─────────────────────────────

/// The cryptographic key type of a PKCS#11 object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenKeyType {
    /// `Ed25519` signing key (`EdDSA`).
    Ed25519,
    /// X25519 key agreement.
    X25519,
    /// ECDSA with P-256 curve.
    EcdsaP256,
    /// ECDSA with P-384 curve.
    EcdsaP384,
    /// RSA key.
    Rsa,
    /// Unknown or unsupported key type.
    Other(u32),
}

impl fmt::Display for TokenKeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519 => write!(f, "Ed25519"),
            Self::X25519 => write!(f, "X25519"),
            Self::EcdsaP256 => write!(f, "ECDSA-P256"),
            Self::EcdsaP384 => write!(f, "ECDSA-P384"),
            Self::Rsa => write!(f, "RSA"),
            Self::Other(id) => write!(f, "Other({id})"),
        }
    }
}

/// A certificate object discovered on a hardware token.
///
/// Abstracts away PKCS#11 object handles so downstream consumers
/// do not need provider-specific trivia.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenCertificate {
    /// Human-readable label assigned to the certificate object.
    pub label: String,
    /// Opaque PKCS#11 object identifier (`CKA_ID`).
    pub id: Vec<u8>,
    /// DER-encoded X.509 certificate bytes (`CKA_VALUE`).
    pub der_bytes: Vec<u8>,
    /// Certificate subject (common name or full DN string).
    pub subject: String,
    /// Certificate issuer (common name or full DN string).
    pub issuer: String,
    /// Whether this is a CA certificate.
    pub is_ca: bool,
}

impl fmt::Display for TokenCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id_hex = hex::encode(&self.id);
        if self.is_ca {
            write!(f, "{} (CA, id={})", self.label, id_hex)
        } else {
            write!(f, "{} (id={})", self.label, id_hex)
        }
    }
}

/// A private key discovered on a hardware token.
///
/// The actual key material never leaves the token — this struct
/// carries only metadata needed for selection and matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenKeyInfo {
    /// Human-readable label.
    pub label: String,
    /// Opaque PKCS#11 object identifier (`CKA_ID`), used to match
    /// certificates with their corresponding private keys.
    pub id: Vec<u8>,
    /// The key type.
    pub key_type: TokenKeyType,
    /// Whether the key supports signing operations.
    pub can_sign: bool,
    /// Whether the key supports key derivation / agreement.
    pub can_derive: bool,
}

impl fmt::Display for TokenKeyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let id_hex = hex::encode(&self.id);
        write!(f, "{} ({}, id={})", self.label, self.key_type, id_hex)
    }
}

/// A matched certificate–private-key pair on a hardware token.
///
/// The pairing is done by matching the PKCS#11 `CKA_ID` attribute
/// between the certificate and private key objects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateKeyPair {
    /// The certificate.
    pub certificate: TokenCertificate,
    /// The matching private key metadata.
    pub key: TokenKeyInfo,
}

impl fmt::Display for CertificateKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "cert={} key={}", self.certificate.label, self.key)
    }
}

/// Validated cryptographic material ready for provisioning handoff.
///
/// This is the typed boundary between hardware-token bootstrap and
/// the provisioning layer.  It carries enough information to proceed
/// with enrollment without exposing PKCS#11 session internals.
#[derive(Debug, Clone)]
pub struct ProvisioningMaterial {
    /// The selected certificate–key pair.
    pub pair: CertificateKeyPair,
    /// The token that holds the key material.
    pub token: DetectedToken,
    /// All candidate pairs that were considered (for audit logs).
    pub candidates_considered: usize,
    /// Human-readable reason for selecting this pair.
    pub selection_reason: String,
}

impl ProvisioningMaterial {
    /// Extract the owner key from the selected certificate's actual SPKI.
    ///
    /// Key metadata alone is insufficient: `CKK_EC_EDWARDS` also includes
    /// Ed448, and matching object IDs do not prove possession of either key.
    ///
    /// # Errors
    ///
    /// Rejects mismatched IDs, CA identities, unsupported public-key
    /// algorithms, malformed encodings, and certificates that forbid signing.
    pub fn owner_verifying_key(&self) -> Result<Ed25519VerifyingKey, TokenError> {
        if self.pair.key.id.is_empty()
            || self.pair.key.id != self.pair.certificate.id
            || self.pair.certificate.is_ca
        {
            return Err(TokenError::Enrollment(
                "certificate and owner key identifiers do not match".into(),
            ));
        }
        if !is_owner_signing_key(&self.pair.key) {
            return Err(TokenError::UnsupportedMechanism(
                "an Ed25519 owner-signing key is required".into(),
            ));
        }
        owner_key_from_certificate(&self.pair.certificate.der_bytes)
    }
}

const HARDWARE_TOKEN_ENROLLMENT_VERSION: u32 = 1;
pub(crate) const MAX_HARDWARE_TOKEN_ENROLLMENT_BYTES: usize = 1024 * 1024;
const HARDWARE_TOKEN_ENROLLMENT_DOMAIN: &[u8] = b"FCP-HARDWARE-TOKEN-ENROLLMENT-V1\0";

/// Durable public evidence and the exact key locator for a hardware owner.
///
/// This record contains no PIN or private key. Its proof binds the token,
/// certificate, object ID, and a fresh challenge to an expected genesis.
/// Always validate against that independently supplied genesis before use.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HardwareTokenEnrollment {
    /// Enrollment record version.
    pub schema_version: u32,
    /// BLAKE3 of the canonical genesis CBOR.
    #[serde(with = "hex::serde")]
    pub genesis_hash: [u8; 32],
    /// Owner public key proved by the token.
    #[serde(with = "hex::serde")]
    pub owner_public_key: [u8; 32],
    /// Provider, slot, and physical token identity used for enrollment.
    pub token: DetectedToken,
    /// Exact private-key `CKA_ID`; labels are never used for key lookup.
    #[serde(with = "hex::serde")]
    pub key_id: Vec<u8>,
    /// Selected leaf certificate as DER, retained as public evidence.
    #[serde(with = "hex::serde")]
    pub certificate_der: Vec<u8>,
    /// Fresh random challenge used for proof of possession.
    #[serde(with = "hex::serde")]
    pub challenge: [u8; 32],
    /// Ed25519 signature over the domain-separated enrollment binding.
    #[serde(with = "hex::serde")]
    pub signature: Vec<u8>,
}

impl HardwareTokenEnrollment {
    /// The record path associated with this exact genesis.
    ///
    /// The genesis hash in the filename prevents a partial bootstrap from
    /// replacing the locator belonging to a different committed genesis.
    ///
    /// # Errors
    ///
    /// Returns an error if the supplied genesis is invalid or cannot be encoded.
    pub fn path_for_genesis(data_dir: &Path, genesis: &GenesisState) -> BootstrapResult<PathBuf> {
        let hash = enrollment_genesis_hash(genesis).map_err(enrollment_bootstrap_error)?;
        Ok(data_dir.join(format!("hardware-token-{}.json", hex::encode(hash))))
    }

    /// Load and verify enrollment for an independently supplied genesis.
    ///
    /// Returns `None` when that genesis has no hardware enrollment record.
    /// A record for any other genesis is never selected as a fallback.
    ///
    /// # Errors
    ///
    /// Rejects invalid files, incompatible records, and invalid possession proofs.
    pub fn load(
        data_dir: &Path,
        expected_genesis: &GenesisState,
    ) -> BootstrapResult<Option<Self>> {
        let path = Self::path_for_genesis(data_dir, expected_genesis)?;
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if !metadata.is_file() || metadata.file_type().is_symlink() => {
                return Err(BootstrapError::HardwareTokenEnrollmentFailed {
                    detail: "enrollment record must be a regular file".into(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        use std::io::Read;

        let mut raw = Vec::new();
        std::fs::File::open(path)?
            .take((MAX_HARDWARE_TOKEN_ENROLLMENT_BYTES + 1) as u64)
            .read_to_end(&mut raw)?;
        if raw.len() > MAX_HARDWARE_TOKEN_ENROLLMENT_BYTES {
            return Err(BootstrapError::HardwareTokenEnrollmentFailed {
                detail: "enrollment record exceeds the 1 MiB size limit".into(),
            });
        }
        let enrollment: Self = serde_json::from_slice(&raw)
            .map_err(|error| BootstrapError::Serialization(error.to_string()))?;
        enrollment
            .validate_for_genesis(expected_genesis)
            .map_err(enrollment_bootstrap_error)?;
        Ok(Some(enrollment))
    }

    pub(crate) fn to_json_for_genesis(&self, genesis: &GenesisState) -> BootstrapResult<Vec<u8>> {
        let encoded = serde_json::to_vec_pretty(self)
            .map_err(|error| BootstrapError::Serialization(error.to_string()))?;
        if encoded.len() > MAX_HARDWARE_TOKEN_ENROLLMENT_BYTES {
            return Err(BootstrapError::HardwareTokenEnrollmentFailed {
                detail: "enrollment record exceeds the 1 MiB size limit".into(),
            });
        }
        self.validate_for_genesis(genesis).map_err(enrollment_bootstrap_error)?;
        Ok(encoded)
    }

    /// Verify the certificate, genesis binding, and possession proof.
    ///
    /// The historical certificate's expiry is not reinterpreted here:
    /// enrollment already validated its issuer chain and validity. The owner
    /// key from the independently supplied genesis is the trust anchor.
    ///
    /// # Errors
    ///
    /// Rejects changed metadata, another genesis, unsupported keys, or bad proofs.
    pub fn validate_for_genesis(&self, expected_genesis: &GenesisState) -> Result<(), TokenError> {
        if self.schema_version != HARDWARE_TOKEN_ENROLLMENT_VERSION {
            return Err(TokenError::Enrollment("unsupported enrollment version".into()));
        }
        if self.key_id.is_empty()
            || self.owner_public_key != expected_genesis.owner_public_key
            || self.genesis_hash != enrollment_genesis_hash(expected_genesis)?
        {
            return Err(TokenError::Enrollment(
                "enrollment does not match the expected genesis and owner key".into(),
            ));
        }
        let owner = owner_key_from_certificate(&self.certificate_der)?;
        if owner.to_bytes() != self.owner_public_key {
            return Err(TokenError::Enrollment(
                "enrollment certificate does not contain the expected owner key".into(),
            ));
        }
        verify_token_signature(&owner, &self.proof_message()?, &self.signature)?;
        Ok(())
    }

    /// Sign a message with this enrolled hardware owner.
    ///
    /// Revalidates the enrollment against the expected genesis, checks physical
    /// token identity on the reopened slot, and verifies the returned signature.
    /// The caller supplies the PIN in memory; it is never retained in the record.
    ///
    /// # Errors
    ///
    /// Returns a typed token error for invalid enrollment, failed login, changed
    /// token identity, missing or ambiguous keys, cleanup failure, or a bad signature.
    pub fn sign(
        &self,
        expected_genesis: &GenesisState,
        pin: &HardwareTokenPin,
        message: &[u8],
    ) -> Result<Ed25519Signature, TokenError> {
        self.sign_with_driver(expected_genesis, pin, message, &Pkcs11SessionDriver)
    }

    pub(crate) fn sign_with_driver<D: HardwareTokenSessionDriver>(
        &self,
        expected_genesis: &GenesisState,
        pin: &HardwareTokenPin,
        message: &[u8],
        driver: &D,
    ) -> Result<Ed25519Signature, TokenError> {
        self.validate_for_genesis(expected_genesis)?;
        let signature = driver.sign_ed25519(&self.token, pin, &self.key_id, message)?;
        let owner = expected_genesis
            .owner_verifying_key()
            .map_err(|error| TokenError::Enrollment(error.to_string()))?;
        verify_token_signature(&owner, message, &signature)
    }

    pub(crate) fn enroll_with_driver<D: HardwareTokenSessionDriver>(
        material: &ProvisioningMaterial,
        genesis: &GenesisState,
        pin: &HardwareTokenPin,
        driver: &D,
    ) -> Result<Self, TokenError> {
        use rand::RngCore;

        let owner = material.owner_verifying_key()?;
        if owner.to_bytes() != genesis.owner_public_key {
            return Err(TokenError::Enrollment(
                "selected certificate does not match the genesis owner".into(),
            ));
        }
        let mut challenge = [0u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut challenge)
            .map_err(|_| TokenError::Enrollment("secure challenge generation failed".into()))?;
        let mut enrollment = Self {
            schema_version: HARDWARE_TOKEN_ENROLLMENT_VERSION,
            genesis_hash: enrollment_genesis_hash(genesis)?,
            owner_public_key: owner.to_bytes(),
            token: material.token.clone(),
            key_id: material.pair.key.id.clone(),
            certificate_der: material.pair.certificate.der_bytes.clone(),
            challenge,
            signature: Vec::new(),
        };
        enrollment.signature = driver.sign_ed25519(
            &enrollment.token,
            pin,
            &enrollment.key_id,
            &enrollment.proof_message()?,
        )?;
        enrollment.validate_for_genesis(genesis)?;
        Ok(enrollment)
    }

    fn proof_message(&self) -> Result<Vec<u8>, TokenError> {
        // A fixed-position tuple makes every variable-length field unambiguous.
        // The signature is deliberately excluded from its own signed message.
        let binding = serde_json::to_vec(&(
            self.schema_version,
            self.genesis_hash,
            self.owner_public_key,
            (
                &self.token.provider,
                self.token.slot,
                &self.token.label,
                &self.token.manufacturer,
                &self.token.serial,
                &self.token.mechanisms,
            ),
            &self.key_id,
            &self.certificate_der,
            self.challenge,
        ))
        .map_err(|_| TokenError::Enrollment("enrollment binding cannot be encoded".into()))?;
        let mut message = Vec::with_capacity(HARDWARE_TOKEN_ENROLLMENT_DOMAIN.len() + binding.len());
        message.extend_from_slice(HARDWARE_TOKEN_ENROLLMENT_DOMAIN);
        message.extend_from_slice(&binding);
        Ok(message)
    }
}

fn enrollment_genesis_hash(genesis: &GenesisState) -> Result<[u8; 32], TokenError> {
    genesis
        .validate()
        .map_err(|error| TokenError::Enrollment(error.to_string()))?;
    let encoded = genesis
        .to_cbor()
        .map_err(|error| TokenError::Enrollment(error.to_string()))?;
    Ok(*blake3::hash(&encoded).as_bytes())
}

fn enrollment_bootstrap_error(error: TokenError) -> BootstrapError {
    BootstrapError::HardwareTokenEnrollmentFailed {
        detail: error.to_string(),
    }
}

fn verify_token_signature(
    owner: &Ed25519VerifyingKey,
    message: &[u8],
    signature: &[u8],
) -> Result<Ed25519Signature, TokenError> {
    let signature = Ed25519Signature::try_from_slice(signature)
        .map_err(|_| TokenError::Enrollment("token returned an invalid signature length".into()))?;
    owner
        .verify(message, &signature)
        .map_err(|_| TokenError::Enrollment("token signature does not match the owner key".into()))?;
    Ok(signature)
}

fn owner_key_from_certificate(der: &[u8]) -> Result<Ed25519VerifyingKey, TokenError> {
    let (remaining, certificate) = parse_x509_certificate(der)
        .map_err(|_| TokenError::Enrollment("owner certificate is not valid DER".into()))?;
    if !remaining.is_empty() || x509_basic_constraints_ca(&certificate) != Some(false) {
        return Err(TokenError::Enrollment(
            "owner certificate must be a single non-CA leaf certificate".into(),
        ));
    }
    let public_key = certificate.public_key();
    // RFC 8410: Ed25519 is 1.3.101.112, parameters MUST be absent, and the
    // BIT STRING contains exactly the 32 public-key bytes, without padding.
    if public_key.algorithm.algorithm.to_id_string() != "1.3.101.112"
        || public_key.algorithm.parameters.is_some()
        || public_key.subject_public_key.unused_bits != 0
        || public_key.subject_public_key.data.len() != 32
    {
        return Err(TokenError::UnsupportedMechanism(
            "the owner certificate must contain an RFC 8410 Ed25519 public key".into(),
        ));
    }
    match certificate.key_usage() {
        Ok(Some(usage)) if !usage.value.digital_signature() => {
            return Err(TokenError::UnsupportedMechanism(
                "the owner certificate does not permit digital signatures".into(),
            ));
        }
        Err(_) => {
            return Err(TokenError::Enrollment("owner certificate key usage is invalid".into()));
        }
        _ => {}
    }
    let bytes: [u8; 32] = public_key.subject_public_key.data.as_ref().try_into().map_err(|_| {
        TokenError::Enrollment("owner certificate public-key length is invalid".into())
    })?;
    Ed25519VerifyingKey::from_bytes(&bytes)
        .map_err(|_| TokenError::Enrollment("owner certificate public key is invalid".into()))
}

/// Result of selecting a certificate/key pair from token object metadata.
#[derive(Debug, Clone)]
pub struct CertificateSelection {
    /// The selected certificate/key pair.
    pub pair: CertificateKeyPair,
    /// Number of compatible candidates considered after policy filters.
    pub candidates_considered: usize,
    /// Human-readable reason for selecting the pair.
    pub selection_reason: String,
}

impl fmt::Display for ProvisioningMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProvisioningMaterial({}, selected from {} candidates: {})",
            self.pair, self.candidates_considered, self.selection_reason
        )
    }
}

/// Reason why certificate selection could not produce provisioning material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateSelectionRefusal {
    /// No certificates found on the token.
    NoCertificates,
    /// No private keys found on the token.
    NoKeys,
    /// Certificates exist but none have a matching private key.
    NoMatchingKeyPair,
    /// Matching pairs exist but none expose an owner-signing Ed25519 key.
    NoCompatibleKeyType {
        /// The key types that were found.
        found: Vec<TokenKeyType>,
    },
    /// Signing-capable leaf certificates exist, but none chain to a verifiable issuer.
    NoVerifiedIssuerChain,
    /// Multiple ambiguous matches with no deterministic winner.
    AmbiguousSelection {
        /// The number of equally-ranked candidates.
        count: usize,
    },
}

impl fmt::Display for CertificateSelectionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCertificates => write!(f, "no certificates found on token"),
            Self::NoKeys => write!(f, "no private keys found on token"),
            Self::NoMatchingKeyPair => {
                write!(f, "no certificate has a matching private key on this token")
            }
            Self::NoCompatibleKeyType { found } => {
                let types: Vec<_> = found.iter().map(ToString::to_string).collect();
                write!(
                    f,
                    "no signing-capable Ed25519 provisioning identity found (have: {})",
                    types.join(", ")
                )
            }
            Self::NoVerifiedIssuerChain => write!(
                f,
                "no provisioning certificate has a verifiable issuer chain on this token"
            ),
            Self::AmbiguousSelection { count } => {
                write!(
                    f,
                    "{count} equally-ranked certificate candidates; cannot select deterministically"
                )
            }
        }
    }
}

/// Run the full session-selection state machine: detect → rank → select → authenticate.
///
/// This is the canonical entry point for hardware-token bootstrap.  It returns a
/// live authenticated session or a typed refusal.  The caller is responsible for
/// closing the session when done (via `session.close()` or `Drop`).
///
/// # Errors
///
/// Returns a typed `TokenError` if detection finds no tokens, the requested
/// token is missing or incompatible, the PIN is missing/invalid, or the
/// PKCS#11 login fails.
pub(crate) fn select_and_authenticate<D: HardwareTokenSessionDriver>(
    requested: &DetectedToken,
    pin: &HardwareTokenPin,
    detection_report: &TokenDetectionReport,
    driver: &D,
    session_timeout: Option<Duration>,
) -> Result<SessionSelectionOutcome, TokenError> {
    // Fail fast on missing PIN before any PKCS#11 work.
    if pin.is_empty() {
        return Err(TokenError::PinRequired);
    }

    let candidates = detection_report.all_tokens();

    tracing::info!(
        requested_provider = %requested.provider.display(),
        requested_slot = requested.slot,
        candidate_count = candidates.len(),
        detection_issues = detection_report.issues().len(),
        "Session-selection: ranking token candidates"
    );

    let selected = select_bootstrap_token(requested, &candidates)?;

    tracing::info!(
        provider = %selected.provider.display(),
        slot = selected.slot,
        label = %selected.label,
        ed25519 = selected.supports_ed25519(),
        x25519 = selected.supports_x25519(),
        "Session-selection: opening authenticated session"
    );

    let mut session =
        authenticate_bootstrap_session_with_driver(requested, &candidates, pin, driver)?;

    if let Some(timeout) = session_timeout {
        session.set_timeout(timeout);
    }

    tracing::info!(
        provider = %session.token().provider.display(),
        slot = session.token().slot,
        label = %session.token().label,
        session_state = %session.session_state(),
        read_write = session.read_write(),
        timeout_secs = session.timeout().as_secs(),
        "Session-selection: authenticated session established"
    );

    Ok(SessionSelectionOutcome {
        session,
        detection_report: detection_report.clone(),
        selected_token: selected,
    })
}

// ── Certificate selection and provisioning handoff ────────────────────

/// Match certificates with their private keys by `CKA_ID`.
#[must_use]
pub fn match_certificate_key_pairs(
    certs: &[TokenCertificate],
    keys: &[TokenKeyInfo],
) -> Vec<CertificateKeyPair> {
    let mut key_by_id: HashMap<&[u8], &TokenKeyInfo> = HashMap::with_capacity(keys.len());
    for key in keys {
        key_by_id.entry(key.id.as_slice()).or_insert(key);
    }

    let mut pairs = Vec::new();
    for cert in certs {
        if cert.is_ca || cert.id.is_empty() {
            continue;
        }
        if let Some(key) = key_by_id.get(cert.id.as_slice()) {
            pairs.push(CertificateKeyPair {
                certificate: cert.clone(),
                key: (*key).clone(),
            });
        }
    }
    pairs
}

const fn is_owner_signing_key(key: &TokenKeyInfo) -> bool {
    matches!(key.key_type, TokenKeyType::Ed25519) && key.can_sign
}

struct ParsedTokenCertificate<'a> {
    parsed: X509Certificate<'a>,
    der_declares_ca: Option<bool>,
    valid_for_bootstrap: bool,
    signing_allowed: Option<bool>,
    subject_raw: Vec<u8>,
    issuer_raw: Vec<u8>,
}

/// Precomputed certificate-selection index for hardware-token provisioning.
///
/// The index is built once from enumerated token objects and then used for
/// O(1) key lookup by `CKA_ID`, cached DER metadata, and issuer lookup by
/// X.509 subject. This keeps policy matching from repeatedly scanning every
/// certificate/key object for each candidate.
pub struct CertificateSelectionIndex<'a> {
    certs: &'a [TokenCertificate],
    keys: &'a [TokenKeyInfo],
    key_by_id: HashMap<&'a [u8], usize>,
    parsed_by_cert: Vec<Option<usize>>,
    parsed_certs: Vec<ParsedTokenCertificate<'a>>,
    issuers_by_subject: HashMap<Vec<u8>, Vec<usize>>,
    verified_chain_cache: Vec<Option<bool>>,
    cached_selection: Result<CertificateSelection, CertificateSelectionRefusal>,
}

impl<'a> CertificateSelectionIndex<'a> {
    /// Build an index over enumerated certificate and key objects.
    #[must_use]
    pub fn new(certs: &'a [TokenCertificate], keys: &'a [TokenKeyInfo]) -> Self {
        let mut key_by_id = HashMap::with_capacity(keys.len());
        for (index, key) in keys.iter().enumerate() {
            key_by_id.entry(key.id.as_slice()).or_insert(index);
        }

        let mut parsed_by_cert = vec![None; certs.len()];
        let mut parsed_certs = Vec::with_capacity(certs.len());
        let mut issuers_by_subject: HashMap<Vec<u8>, Vec<usize>> =
            HashMap::with_capacity(certs.len());

        for (cert_index, cert) in certs.iter().enumerate() {
            let Ok((remaining, parsed)) = parse_x509_certificate(&cert.der_bytes) else {
                continue;
            };
            if !remaining.is_empty() {
                continue;
            }

            let der_declares_ca = x509_basic_constraints_ca(&parsed);
            let valid_for_bootstrap = x509_certificate_valid_for_bootstrap(&parsed);
            let signing_allowed = x509_cert_signing_allowed(&parsed);
            let subject_raw = parsed.subject().as_raw().to_vec();
            let issuer_raw = parsed.issuer().as_raw().to_vec();

            parsed_by_cert[cert_index] = Some(parsed_certs.len());
            issuers_by_subject
                .entry(subject_raw.clone())
                .or_default()
                .push(cert_index);
            parsed_certs.push(ParsedTokenCertificate {
                parsed,
                der_declares_ca,
                valid_for_bootstrap,
                signing_allowed,
                subject_raw,
                issuer_raw,
            });
        }

        let mut index = Self {
            certs,
            keys,
            key_by_id,
            parsed_by_cert,
            parsed_certs,
            issuers_by_subject,
            verified_chain_cache: vec![None; certs.len()],
            cached_selection: Err(CertificateSelectionRefusal::NoMatchingKeyPair),
        };
        index.cached_selection = index.compute_selection();
        index
    }

    /// Select the best provisioning certificate/key pair from the indexed data.
    ///
    /// # Errors
    ///
    /// Returns a typed [`CertificateSelectionRefusal`] if no suitable pair
    /// exists or the deterministic tie-break remains ambiguous.
    pub fn select_for_provisioning(
        &self,
    ) -> Result<CertificateSelection, CertificateSelectionRefusal> {
        self.cached_selection.clone()
    }

    fn compute_selection(&mut self) -> Result<CertificateSelection, CertificateSelectionRefusal> {
        let mut pair_count = 0_usize;
        let mut has_owner_signing_key = false;
        let mut found = Vec::new();
        let mut candidates_considered = 0_usize;
        let mut best: Option<(usize, usize)> = None;

        for cert_index in 0..self.certs.len() {
            let cert = &self.certs[cert_index];
            if cert.is_ca || cert.id.is_empty() {
                continue;
            }

            let Some(key_index) = self.key_index_for_cert(cert) else {
                continue;
            };
            pair_count += 1;

            let key = &self.keys[key_index];
            found.push(key.key_type);
            if !is_owner_signing_key(key) {
                continue;
            }
            has_owner_signing_key = true;

            if self.certificate_der_declares_ca(cert_index) != Some(false) {
                continue;
            }
            if !self.has_verified_issuer_chain(cert_index) {
                continue;
            }

            candidates_considered += 1;
            if best.is_none_or(|(best_cert, best_key)| {
                let best_cert = &self.certs[best_cert];
                let best_key = &self.keys[best_key];
                cert.label
                    .cmp(&best_cert.label)
                    .then_with(|| key.id.cmp(&best_key.id))
                    .is_lt()
            }) {
                best = Some((cert_index, key_index));
            }
        }

        let Some((cert_index, key_index)) = best else {
            return Err(if pair_count == 0 {
                CertificateSelectionRefusal::NoMatchingKeyPair
            } else if has_owner_signing_key {
                CertificateSelectionRefusal::NoVerifiedIssuerChain
            } else {
                CertificateSelectionRefusal::NoCompatibleKeyType { found }
            });
        };

        let selection_reason = format!(
            "Ed25519 signing certificate with verified issuer chain selected among {candidates_considered} compatible pair(s)"
        );

        Ok(CertificateSelection {
            pair: CertificateKeyPair {
                certificate: self.certs[cert_index].clone(),
                key: self.keys[key_index].clone(),
            },
            candidates_considered,
            selection_reason,
        })
    }

    fn key_index_for_cert(&self, cert: &TokenCertificate) -> Option<usize> {
        self.key_by_id.get(cert.id.as_slice()).copied()
    }

    fn certificate_der_declares_ca(&self, cert_index: usize) -> Option<bool> {
        self.parsed_by_cert
            .get(cert_index)
            .and_then(|parsed_index| {
                parsed_index.map(|index| self.parsed_certs[index].der_declares_ca)
            })
            .flatten()
    }

    fn has_verified_issuer_chain(&mut self, cert_index: usize) -> bool {
        let mut visited = HashSet::new();
        self.has_verified_issuer_chain_inner(cert_index, &mut visited)
    }

    fn has_verified_issuer_chain_inner(
        &mut self,
        cert_index: usize,
        visited: &mut HashSet<usize>,
    ) -> bool {
        if let Some(cached) = self.verified_chain_cache[cert_index] {
            return cached;
        }
        if !visited.insert(cert_index) {
            return false;
        }

        let result = self.verify_chain_for_cert_index(cert_index, visited);
        visited.remove(&cert_index);
        if result {
            self.verified_chain_cache[cert_index] = Some(true);
        }
        result
    }

    fn verify_chain_for_cert_index(
        &mut self,
        cert_index: usize,
        visited: &mut HashSet<usize>,
    ) -> bool {
        let Some(parsed_index) = self.parsed_by_cert[cert_index] else {
            return false;
        };
        let parsed = &self.parsed_certs[parsed_index];
        if !parsed.valid_for_bootstrap {
            return false;
        }
        let Some(parsed_is_ca) = parsed.der_declares_ca else {
            return false;
        };

        if parsed_is_ca && parsed.subject_raw == parsed.issuer_raw {
            return parsed.signing_allowed == Some(true)
                && parsed.parsed.verify_signature(None).is_ok();
        }

        let issuer_candidates = self
            .issuers_by_subject
            .get(&parsed.issuer_raw)
            .cloned()
            .unwrap_or_default();

        for issuer_cert_index in issuer_candidates {
            if self.certs[issuer_cert_index].id == self.certs[cert_index].id {
                continue;
            }
            if self.issuer_verifies_certificate(cert_index, issuer_cert_index)
                && self.has_verified_issuer_chain_inner(issuer_cert_index, visited)
            {
                return true;
            }
        }

        false
    }

    fn issuer_verifies_certificate(&self, cert_index: usize, issuer_cert_index: usize) -> bool {
        let Some(parsed_index) = self.parsed_by_cert[cert_index] else {
            return false;
        };
        let Some(issuer_parsed_index) = self.parsed_by_cert[issuer_cert_index] else {
            return false;
        };
        let parsed = &self.parsed_certs[parsed_index];
        let issuer = &self.parsed_certs[issuer_parsed_index];

        issuer.valid_for_bootstrap
            && issuer.signing_allowed == Some(true)
            && parsed.issuer_raw == issuer.subject_raw
            && parsed
                .parsed
                .verify_signature(Some(&issuer.parsed.tbs_certificate.subject_pki))
                .is_ok()
    }
}

const BOOTSTRAP_CERT_NOT_BEFORE_SKEW_SECS: i64 = 60;

fn x509_certificate_valid_for_bootstrap(certificate: &X509Certificate<'_>) -> bool {
    let validity = certificate.validity();
    let now = ASN1Time::now();
    let Ok(not_before_skew_limit) = ASN1Time::from_timestamp(
        now.timestamp()
            .saturating_add(BOOTSTRAP_CERT_NOT_BEFORE_SKEW_SECS),
    ) else {
        return false;
    };

    validity.not_before <= validity.not_after
        && validity.not_before <= not_before_skew_limit
        && now <= validity.not_after
}

fn x509_basic_constraints_ca(certificate: &X509Certificate<'_>) -> Option<bool> {
    certificate
        .basic_constraints()
        .ok()
        .map(|constraints| constraints.is_some_and(|extension| extension.value.ca))
}

fn x509_cert_signing_allowed(certificate: &X509Certificate<'_>) -> Option<bool> {
    if x509_basic_constraints_ca(certificate) != Some(true) {
        return Some(false);
    }

    match certificate.key_usage() {
        Ok(Some(usage)) => Some(usage.value.key_cert_sign()),
        Ok(None) => Some(true),
        Err(_) => None,
    }
}

/// Select the best certificate–key pair for FCP provisioning.
///
/// Selection rules:
/// 1. Only signing-capable Ed25519 identities are considered.
/// 2. The certificate must chain to a verifiable issuer on the token.
/// 3. Final tiebreak: lexicographic on (label, id) for determinism.
///
/// # Errors
///
/// Returns a typed `TokenError::CertificateSelectionFailed` with the
/// specific refusal reason if no suitable pair exists.
pub(crate) fn select_certificate_for_provisioning<D: HardwareTokenSessionDriver>(
    token: &DetectedToken,
    pin: &HardwareTokenPin,
    driver: &D,
) -> Result<ProvisioningMaterial, TokenError> {
    if pin.is_empty() {
        return Err(TokenError::PinRequired);
    }

    let certs = driver.enumerate_certificates(token, pin)?;
    if certs.is_empty() {
        return Err(TokenError::CertificateSelectionFailed(
            CertificateSelectionRefusal::NoCertificates,
        ));
    }

    let keys = driver.enumerate_keys(token, pin)?;
    if keys.is_empty() {
        return Err(TokenError::CertificateSelectionFailed(
            CertificateSelectionRefusal::NoKeys,
        ));
    }

    tracing::info!(
        certs = certs.len(),
        keys = keys.len(),
        "Enumerating certificate-key pairs for provisioning"
    );

    let selection_index = CertificateSelectionIndex::new(&certs, &keys);
    let selection = selection_index
        .select_for_provisioning()
        .map_err(TokenError::CertificateSelectionFailed)?;

    tracing::info!(
        selected_cert = %selection.pair.certificate,
        selected_key = %selection.pair.key,
        candidates = selection.candidates_considered,
        reason = %selection.selection_reason,
        "Certificate selected for provisioning"
    );

    Ok(ProvisioningMaterial {
        pair: selection.pair,
        token: token.clone(),
        candidates_considered: selection.candidates_considered,
        selection_reason: selection.selection_reason,
    })
}

fn token_locator(token: &DetectedToken) -> String {
    format!(
        "{} [{}] via {} slot {}",
        token.label,
        token.serial,
        token.provider.display(),
        token.slot
    )
}

fn cleanup_failed_session(provider: &Path, session: Session, pkcs11: Pkcs11) {
    let _ = session.close();
    let _ = finalize_pkcs11_context(provider, pkcs11);
}

fn close_pkcs11_session(
    session: Session,
    session_state: AuthenticatedSessionState,
) -> Result<(), TokenError> {
    let logout_result = match session_state {
        AuthenticatedSessionState::ReadOnlyUser
        | AuthenticatedSessionState::ReadWriteUser
        | AuthenticatedSessionState::ReadWriteSecurityOfficer => match session.logout() {
            Ok(()) | Err(Pkcs11Error::Pkcs11(RvError::UserNotLoggedIn, _)) => Ok(()),
            Err(err) => Err(map_pkcs11_error(err)),
        },
        AuthenticatedSessionState::ReadOnlyPublic | AuthenticatedSessionState::ReadWritePublic => {
            Ok(())
        }
    };

    let close_result = session.close().map_err(map_pkcs11_error);
    logout_result.and(close_result)
}

fn acquire_provider_context(provider: &Path) -> Result<Pkcs11, TokenError> {
    acquire_provider_context_with_stage(provider).map_err(|(_, err)| err)
}

fn acquire_provider_context_with_stage(
    provider: &Path,
) -> Result<Pkcs11, (DetectionStage, TokenError)> {
    let mut sessions = provider_session_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let pkcs11 = Pkcs11::new(provider)
        .map_err(|err| (DetectionStage::LoadProvider, map_pkcs11_error(err)))?;
    let initialized_here =
        match pkcs11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
            Ok(()) => true,
            Err(Pkcs11Error::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => false,
            Err(err) => return Err((DetectionStage::InitializeProvider, map_pkcs11_error(err))),
        };

    note_provider_session_open(&mut sessions, provider, initialized_here);
    Ok(pkcs11)
}

#[allow(
    clippy::significant_drop_tightening,
    reason = "the provider registry lock intentionally spans finalize to serialize PKCS#11 teardown"
)]
fn finalize_pkcs11_context(provider: &Path, pkcs11: Pkcs11) -> Result<(), TokenError> {
    // br-idk2k: hold the registry lock across the actual pkcs11.finalize()
    // call so no concurrent acquire_provider_context can observe the
    // dangling "already initialized but about to be finalized" state.
    //
    // Old code dropped the lock immediately after
    // note_provider_session_close returned should_finalize = true, then
    // called finalize outside the lock. A racing acquire could slip
    // between the drop and the finalize:
    //   1. Thread A: note_close → should_finalize=true, drop lock.
    //   2. Thread B: acquire lock, Pkcs11::new OK, initialize() returns
    //      CryptokiAlreadyInitialized (A hasn't finalized yet), so
    //      initialized_here=false. note_open records active=1,
    //      finalize_required=false. B drops lock and uses Pkcs11 handle.
    //   3. Thread A: finalize() runs, tearing down the shared runtime
    //      out from under B. B's next C_* call fails with
    //      CryptokiNotInitialized.
    //
    // Keeping the lock across finalize serializes A's teardown against
    // B's startup. `finalize` is already a short, rare operation so the
    // extra hold time is negligible vs. the correctness gain.
    //
    // Poison handling: PoisonError::into_inner lets us keep making
    // forward progress even if a prior lock holder panicked; finalize
    // is the cleanup path we most want to run after a panic.
    let mut sessions = provider_session_registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let should_finalize = note_provider_session_close(&mut sessions, provider);

    if should_finalize {
        pkcs11.finalize().map_err(map_pkcs11_error)
    } else {
        Ok(())
    }
    // `sessions` guard drops here (end of scope), AFTER finalize has
    // returned — new acquires will see a clean uninitialized state.
}

fn map_pkcs11_error(error: Pkcs11Error) -> TokenError {
    match error {
        Pkcs11Error::Pkcs11(
            RvError::PinIncorrect
            | RvError::PinInvalid
            | RvError::PinExpired
            | RvError::UserPinNotInitialized,
            _,
        ) => TokenError::InvalidPin,
        Pkcs11Error::Pkcs11(RvError::PinLocked, _) => TokenError::PinLocked,
        Pkcs11Error::Pkcs11(
            RvError::Cancel | RvError::FunctionCanceled | RvError::FunctionRejected,
            _,
        ) => TokenError::Cancelled,
        Pkcs11Error::Pkcs11(
            RvError::MechanismInvalid
            | RvError::MechanismParamInvalid
            | RvError::KeyTypeInconsistent
            | RvError::KeyFunctionNotPermitted,
            _,
        ) => TokenError::UnsupportedMechanism("Ed25519 owner signing".into()),
        Pkcs11Error::Pkcs11(
            RvError::DeviceRemoved
            | RvError::TokenNotPresent
            | RvError::SessionClosed
            | RvError::SessionHandleInvalid
            | RvError::SlotIdInvalid,
            _,
        ) => TokenError::Disconnected,
        other => TokenError::Pkcs11(other.to_string()),
    }
}

/// Provider for hardware token operations.
pub trait HardwareTokenProvider: Send + Sync {
    /// List available tokens.
    fn list_tokens(&self) -> Vec<DetectedToken>;

    /// Generate an Ed25519 keypair on the token.
    ///
    /// # Errors
    ///
    /// Returns a token error if key generation fails or the token is unavailable.
    fn generate_keypair(
        &self,
        token: &DetectedToken,
        pin: &str,
        label: &str,
    ) -> Result<[u8; 32], TokenError>;

    /// Sign data with a key on the token.
    ///
    /// # Errors
    ///
    /// Returns a token error if signing fails or the token is unavailable.
    fn sign(
        &self,
        token: &DetectedToken,
        pin: &str,
        key_label: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, TokenError>;
}

/// Errors during token operations.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// No tokens found.
    #[error("no hardware tokens detected")]
    NoTokens,

    /// A PIN is required before a login attempt can be made.
    #[error("hardware token PIN is required")]
    PinRequired,

    /// Token not found.
    #[error("token not found: {0}")]
    TokenNotFound(String),

    /// Invalid PIN.
    #[error("invalid PIN")]
    InvalidPin,

    /// The PIN is locked after repeated failures.
    #[error("hardware token PIN is locked")]
    PinLocked,

    /// The user canceled or rejected the login flow.
    #[error("hardware token login was cancelled")]
    Cancelled,

    /// Key not found.
    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// Mechanism not supported.
    #[error("mechanism not supported: {0}")]
    UnsupportedMechanism(String),

    /// PKCS#11 error.
    #[error("PKCS#11 error: {0}")]
    Pkcs11(String),

    /// Token disconnected during operation.
    #[error("token disconnected")]
    Disconnected,

    /// Enrollment metadata or proof of possession was rejected.
    #[error("hardware token enrollment: {0}")]
    Enrollment(String),

    /// Certificate selection failed — no suitable identity on this token.
    #[error("certificate selection failed: {0}")]
    CertificateSelectionFailed(CertificateSelectionRefusal),

    /// Session expired due to timeout.
    #[error("hardware token session expired after {elapsed:?} (timeout: {timeout:?})")]
    SessionExpired {
        /// How long the session has been alive.
        elapsed: Duration,
        /// The configured timeout.
        timeout: Duration,
    },
}

/// Cross-platform token detector.
pub struct TokenDetector {
    /// Provider paths to search.
    provider_paths: Vec<PathBuf>,
}

impl TokenDetector {
    /// Create a new token detector with default provider paths.
    #[must_use]
    pub fn new() -> Self {
        Self::from_provider_paths(default_provider_paths())
    }

    /// Create a detector with an explicit provider search list.
    #[must_use]
    pub const fn from_provider_paths(provider_paths: Vec<PathBuf>) -> Self {
        Self { provider_paths }
    }

    /// Add a custom provider path.
    pub fn add_provider(&mut self, path: PathBuf) {
        self.provider_paths.push(path);
    }

    /// Probe all configured providers and return a structured discovery report.
    #[must_use]
    pub fn detect_report(&self) -> TokenDetectionReport {
        TokenDetectionReport {
            providers: self
                .provider_paths
                .iter()
                .map(|provider| detect_tokens_for_provider(provider.as_path()))
                .collect(),
        }
    }

    /// Detect all available tokens.
    #[must_use]
    pub fn detect_all(&self) -> Vec<DetectedToken> {
        self.detect_report().all_tokens()
    }

    /// Detect tokens that support the required mechanisms for FCP.
    #[must_use]
    pub fn detect_fcp_compatible(&self) -> Vec<DetectedToken> {
        self.detect_report().fcp_compatible_tokens()
    }
}

impl Default for TokenDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Get default PKCS#11 provider paths for the current platform.
fn default_provider_paths() -> Vec<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        vec![
            PathBuf::from("/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so"),
            PathBuf::from("/usr/lib/opensc-pkcs11.so"),
            PathBuf::from("/usr/lib64/opensc-pkcs11.so"),
            PathBuf::from("/usr/lib/x86_64-linux-gnu/libykcs11.so"),
            PathBuf::from("/usr/lib/libykcs11.so"),
        ]
    }

    #[cfg(target_os = "macos")]
    {
        vec![
            PathBuf::from("/usr/local/lib/opensc-pkcs11.so"),
            PathBuf::from("/opt/homebrew/lib/opensc-pkcs11.so"),
            PathBuf::from("/Library/OpenSC/lib/opensc-pkcs11.so"),
            PathBuf::from("/usr/local/lib/libykcs11.dylib"),
            PathBuf::from("/opt/homebrew/lib/libykcs11.dylib"),
        ]
    }

    #[cfg(target_os = "windows")]
    {
        vec![
            PathBuf::from(r"C:\Windows\System32\opensc-pkcs11.dll"),
            PathBuf::from(r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"),
            PathBuf::from(r"C:\Program Files\Yubico\Yubico PIV Tool\bin\libykcs11.dll"),
        ]
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        vec![]
    }
}

/// Detect tokens for a specific PKCS#11 provider and surface discovery failures.
fn detect_tokens_for_provider(provider: &Path) -> ProviderDetectionResult {
    let _probe_guard = provider_probe_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let mut result = ProviderDetectionResult::new(provider);

    if !provider.exists() {
        result.push_issue(
            DetectionStage::ProviderMissing,
            None,
            format!("provider library not found at {}", provider.display()),
        );
        return result;
    }

    tracing::debug!(provider = %provider.display(), "Probing PKCS#11 provider");

    let pkcs11 = match acquire_provider_context_with_stage(provider) {
        Ok(pkcs11) => pkcs11,
        Err((stage, err)) => {
            result.push_issue(stage, None, err.to_string());
            return result;
        }
    };

    match pkcs11.get_slots_with_token() {
        Ok(slots) => {
            for slot in slots {
                probe_slot(&pkcs11, slot, &mut result);
            }
        }
        Err(err) => result.push_issue(DetectionStage::EnumerateSlots, None, err.to_string()),
    }

    if let Err(err) = finalize_pkcs11_context(provider, pkcs11) {
        result.push_issue(DetectionStage::FinalizeProvider, None, err.to_string());
    }

    result
}

fn probe_slot(pkcs11: &Pkcs11, slot: Slot, result: &mut ProviderDetectionResult) {
    let raw_slot = slot.id();
    let slot_id = match u32::try_from(raw_slot) {
        Ok(slot_id) => slot_id,
        Err(err) => {
            result.push_issue(
                DetectionStage::NormalizeSlotId,
                Some(raw_slot),
                err.to_string(),
            );
            return;
        }
    };

    let token_info = match pkcs11.get_token_info(slot) {
        Ok(token_info) => token_info,
        Err(err) => {
            result.push_issue(
                DetectionStage::ReadTokenInfo,
                Some(raw_slot),
                err.to_string(),
            );
            return;
        }
    };

    let mechanisms = match pkcs11.get_mechanism_list(slot) {
        Ok(mechanisms) => {
            let mut names: Vec<String> = mechanisms
                .into_iter()
                .map(|item| item.to_string())
                .collect();
            names.sort();
            names.dedup();
            names
        }
        Err(err) => {
            result.push_issue(
                DetectionStage::ReadMechanisms,
                Some(raw_slot),
                err.to_string(),
            );
            Vec::new()
        }
    };

    let label = normalize_token_field(token_info.label());
    let manufacturer = normalize_token_field(token_info.manufacturer_id());
    let serial = normalize_token_field(token_info.serial_number());

    tracing::debug!(
        provider = %result.provider.display(),
        slot = raw_slot,
        label = %label,
        manufacturer = %manufacturer,
        mechanism_count = mechanisms.len(),
        "Discovered PKCS#11 token candidate"
    );

    result.tokens.push(DetectedToken {
        provider: result.provider.clone(),
        slot: slot_id,
        label,
        manufacturer,
        serial,
        mechanisms,
    });
}

fn normalize_token_field(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

fn provider_probe_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ProviderSessionState {
    active_sessions: usize,
    finalize_required: bool,
}

fn note_provider_session_open(
    sessions: &mut HashMap<PathBuf, ProviderSessionState>,
    provider: &Path,
    initialized_here: bool,
) {
    let state = sessions.entry(provider.to_path_buf()).or_default();
    state.active_sessions += 1;
    state.finalize_required |= initialized_here;
}

fn note_provider_session_close(
    sessions: &mut HashMap<PathBuf, ProviderSessionState>,
    provider: &Path,
) -> bool {
    let provider_key = provider.to_path_buf();
    let Some(mut state) = sessions.remove(&provider_key) else {
        return false;
    };

    if state.active_sessions > 1 {
        state.active_sessions -= 1;
        sessions.insert(provider_key, state);
        return false;
    }

    state.finalize_required
}

fn provider_session_registry() -> &'static Mutex<HashMap<PathBuf, ProviderSessionState>> {
    static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, ProviderSessionState>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Mock token provider for testing.
#[cfg(test)]
pub mod mock {
    use super::*;

    /// A mock hardware token provider for testing.
    pub struct MockTokenProvider {
        tokens: Vec<DetectedToken>,
    }

    impl MockTokenProvider {
        /// Create a new mock provider with no tokens.
        #[must_use]
        pub fn new() -> Self {
            Self { tokens: Vec::new() }
        }

        /// Add a mock token.
        pub fn add_token(&mut self, token: DetectedToken) {
            self.tokens.push(token);
        }
    }

    impl Default for MockTokenProvider {
        fn default() -> Self {
            Self::new()
        }
    }

    impl HardwareTokenProvider for MockTokenProvider {
        fn list_tokens(&self) -> Vec<DetectedToken> {
            self.tokens.clone()
        }

        fn generate_keypair(
            &self,
            _token: &DetectedToken,
            _pin: &str,
            _label: &str,
        ) -> Result<[u8; 32], TokenError> {
            use rand::RngCore;
            // Generate a random public key for testing
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            Ok(key)
        }

        fn sign(
            &self,
            _token: &DetectedToken,
            _pin: &str,
            _key_label: &str,
            _data: &[u8],
        ) -> Result<Vec<u8>, TokenError> {
            use rand::RngCore;
            // Generate a random signature for testing
            let mut sig = vec![0u8; 64];
            rand::thread_rng().fill_bytes(&mut sig);
            Ok(sig)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tempfile::tempdir;
    use time::{Duration as TimeDuration, OffsetDateTime};

    fn test_token() -> DetectedToken {
        DetectedToken {
            provider: PathBuf::from("/test/provider.so"),
            slot: 0,
            label: "Test Token".to_string(),
            manufacturer: "Test Manufacturer".to_string(),
            serial: "123456".to_string(),
            mechanisms: vec!["CKM_ED25519".to_string(), "CKM_ECDH".to_string()],
        }
    }

    #[test]
    fn test_token_supports_ed25519() {
        let token = test_token();
        assert!(token.supports_ed25519());
    }

    #[test]
    fn test_token_display() {
        let token = test_token();
        let display = format!("{token}");
        assert!(display.contains("Test Token"));
        assert!(display.contains("Test Manufacturer"));
    }

    #[test]
    fn test_detector_creation() {
        let detector = TokenDetector::new();
        assert!(!detector.provider_paths.is_empty());
    }

    #[test]
    fn test_mock_provider() {
        use mock::MockTokenProvider;

        let mut provider = MockTokenProvider::new();
        provider.add_token(test_token());

        let tokens = provider.list_tokens();
        assert_eq!(tokens.len(), 1);

        let pubkey = provider
            .generate_keypair(&tokens[0], "1234", "test-key")
            .unwrap();
        assert_eq!(pubkey.len(), 32);
    }

    #[test]
    fn hardware_token_pin_debug_is_redacted() {
        let pin = HardwareTokenPin::new("123456");
        assert_eq!(format!("{pin:?}"), "<redacted>");
    }

    #[test]
    fn hardware_token_pin_equality_uses_fixed_width_digest() {
        let short = HardwareTokenPin::new("1");
        let long = HardwareTokenPin::new("123456");
        let long_again = HardwareTokenPin::new("123456");

        assert_eq!(short.digest.len(), 32);
        assert_eq!(long.digest.len(), 32);
        assert_eq!(long, long_again);
        assert_ne!(short, long);
    }

    #[test]
    fn hardware_token_pin_preserves_surrounding_whitespace() {
        let raw = HardwareTokenPin::new("123456");
        let padded = HardwareTokenPin::new(" 123456 ");

        assert!(!padded.is_empty());
        assert_ne!(raw, padded);
        assert_eq!(padded.value.as_bytes(), b" 123456 ");
    }

    #[test]
    fn hardware_token_pin_preserves_unicode_byte_identity() {
        let composed = HardwareTokenPin::new("\u{00e9}");
        let decomposed = HardwareTokenPin::new("e\u{0301}");

        assert!(!composed.is_empty());
        assert!(!decomposed.is_empty());
        assert_ne!(composed, decomposed);
        assert_ne!(composed.value.as_bytes(), decomposed.value.as_bytes());
    }

    #[test]
    fn hardware_token_pin_counts_nul_as_secret_material() {
        let empty = HardwareTokenPin::new("");
        let nul = HardwareTokenPin::new("\0");
        let embedded_nul = HardwareTokenPin::new("12\0");

        assert!(empty.is_empty());
        assert!(!nul.is_empty());
        assert!(!embedded_nul.is_empty());
        assert_ne!(empty, nul);
        assert_eq!(nul.value.as_bytes(), b"\0");
        assert_eq!(embedded_nul.value.as_bytes(), b"12\0");
    }

    #[test]
    fn rank_detected_tokens_prefers_fcp_capabilities_and_stable_order() {
        let mut weaker = test_token();
        weaker.slot = 9;
        weaker.mechanisms = vec!["CKM_RSA_PKCS".to_string()];

        let mut ed25519_only = test_token();
        ed25519_only.slot = 2;
        ed25519_only.serial = "A".to_string();
        ed25519_only.mechanisms = vec!["CKM_ED25519".to_string()];

        let mut ed25519_and_x25519 = test_token();
        ed25519_and_x25519.slot = 1;
        ed25519_and_x25519.serial = "B".to_string();
        ed25519_and_x25519.mechanisms = vec!["CKM_ECDH".to_string(), "CKM_ED25519".to_string()];

        let ranked =
            rank_detected_tokens(&[weaker, ed25519_only.clone(), ed25519_and_x25519.clone()]);

        assert_eq!(ranked[0], ed25519_and_x25519);
        assert_eq!(ranked[1], ed25519_only);
        assert!(!ranked[2].supports_ed25519());
    }

    #[test]
    fn select_bootstrap_token_matches_requested_identity() {
        let requested = test_token();
        let mut distractor = requested.clone();
        distractor.slot = 7;
        distractor.serial = "different".to_string();

        let selected =
            select_bootstrap_token(&requested, &[distractor, requested.clone()]).unwrap();
        assert_eq!(selected, requested);
    }

    #[test]
    fn authenticate_bootstrap_session_refuses_missing_pin() {
        let requested = test_token();
        let pin = HardwareTokenPin::new("");
        let result = authenticate_bootstrap_session_with_driver(
            &requested,
            std::slice::from_ref(&requested),
            &pin,
            &MockSessionDriver::default(),
        );

        assert!(matches!(result, Err(TokenError::PinRequired)));
    }

    #[test]
    fn authenticate_bootstrap_session_refuses_unsupported_mechanism() {
        let mut requested = test_token();
        requested.mechanisms = vec!["CKM_RSA_PKCS".to_string()];
        let pin = HardwareTokenPin::new("123456");

        let result = authenticate_bootstrap_session_with_driver(
            &requested,
            std::slice::from_ref(&requested),
            &pin,
            &MockSessionDriver::default(),
        );

        assert!(matches!(
            result,
            Err(TokenError::UnsupportedMechanism(mechanism)) if mechanism.contains("Ed25519")
        ));
    }

    #[test]
    fn authenticate_bootstrap_session_returns_authenticated_session_and_closes_it() {
        let requested = test_token();
        let pin = HardwareTokenPin::new("123456");
        let driver = MockSessionDriver::default();

        let session = authenticate_bootstrap_session_with_driver(
            &requested,
            std::slice::from_ref(&requested),
            &pin,
            &driver,
        )
        .unwrap();

        assert_eq!(session.token(), &requested);
        assert_eq!(
            session.session_state(),
            AuthenticatedSessionState::ReadWriteUser
        );
        assert!(session.read_write());
        assert_eq!(driver.close_count(), 0);

        session.close().unwrap();
        assert_eq!(driver.close_count(), 1);
    }

    // ---- DetectedToken mechanism checks ----

    #[test]
    fn token_without_ed25519_mechanism() {
        let mut token = test_token();
        token.mechanisms = vec!["CKM_RSA_PKCS".to_string()];
        assert!(!token.supports_ed25519());
    }

    #[test]
    fn token_supports_ed25519_via_eddsa() {
        let mut token = test_token();
        token.mechanisms = vec!["CKM_EDDSA".to_string()];
        assert!(token.supports_ed25519());
    }

    #[test]
    fn token_supports_x25519_via_ecdh() {
        let token = test_token();
        assert!(token.supports_x25519());
    }

    #[test]
    fn token_without_x25519_mechanism() {
        let mut token = test_token();
        token.mechanisms = vec!["CKM_RSA_PKCS".to_string()];
        assert!(!token.supports_x25519());
    }

    #[test]
    fn token_supports_x25519_via_x25519_mechanism() {
        let mut token = test_token();
        token.mechanisms = vec!["CKM_X25519".to_string()];
        assert!(token.supports_x25519());
    }

    #[test]
    fn token_empty_mechanisms() {
        let mut token = test_token();
        token.mechanisms = vec![];
        assert!(!token.supports_ed25519());
        assert!(!token.supports_x25519());
    }

    // ---- DetectedToken Display ----

    #[test]
    fn token_display_format() {
        let token = test_token();
        let display = format!("{token}");
        assert_eq!(display, "Test Token (Test Manufacturer) [slot 0]");
    }

    // ---- DetectedToken serde roundtrip ----

    #[test]
    fn token_serde_roundtrip() {
        let token = test_token();
        let json = serde_json::to_string(&token).unwrap();
        let restored: DetectedToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token, restored);
    }

    // ---- TokenDetector ----

    #[test]
    fn detector_default_same_as_new() {
        let d1 = TokenDetector::new();
        let d2 = TokenDetector::default();
        assert_eq!(d1.provider_paths.len(), d2.provider_paths.len());
    }

    #[test]
    fn detector_from_provider_paths() {
        let providers = vec![PathBuf::from("/one.so"), PathBuf::from("/two.so")];
        let detector = TokenDetector::from_provider_paths(providers.clone());
        assert_eq!(detector.provider_paths, providers);
    }

    #[test]
    fn detector_add_provider() {
        let mut detector = TokenDetector::new();
        let original_count = detector.provider_paths.len();
        detector.add_provider(PathBuf::from("/custom/pkcs11.so"));
        assert_eq!(detector.provider_paths.len(), original_count + 1);
    }

    #[test]
    fn detector_detect_all_returns_empty_in_ci() {
        let detector = TokenDetector::new();
        let tokens = detector.detect_all();
        // No real PKCS#11 providers in CI
        assert!(tokens.is_empty());
    }

    #[test]
    fn detector_detect_fcp_compatible_returns_empty_in_ci() {
        let detector = TokenDetector::new();
        let tokens = detector.detect_fcp_compatible();
        assert!(tokens.is_empty());
    }

    #[test]
    fn detector_report_records_missing_provider() {
        let provider = PathBuf::from("/definitely/missing/pkcs11-provider.so");
        let detector = TokenDetector::from_provider_paths(vec![provider.clone()]);
        let report = detector.detect_report();

        assert!(!report.has_detected_tokens());
        assert!(report.all_tokens().is_empty());
        assert_eq!(report.providers.len(), 1);
        assert_eq!(report.providers[0].provider, provider);
        assert_eq!(report.providers[0].issues.len(), 1);
        assert_eq!(
            report.providers[0].issues[0].stage,
            DetectionStage::ProviderMissing
        );
    }

    #[test]
    fn detector_report_records_load_failure_for_non_library_file() {
        let dir = tempdir().unwrap();
        let provider = dir.path().join("not-a-library.txt");
        std::fs::write(&provider, "plain text").unwrap();

        let detector = TokenDetector::from_provider_paths(vec![provider.clone()]);
        let report = detector.detect_report();
        let issues = &report.providers[0].issues;

        assert!(report.all_tokens().is_empty());
        assert!(
            issues
                .iter()
                .any(|issue| issue.stage == DetectionStage::LoadProvider)
        );
        assert_eq!(issues[0].provider, provider);
    }

    #[test]
    fn token_detection_report_filters_fcp_compatible_tokens() {
        let mut incompatible = test_token();
        incompatible.mechanisms = vec!["CKM_RSA_PKCS".to_string()];

        let report = TokenDetectionReport {
            providers: vec![ProviderDetectionResult {
                provider: PathBuf::from("/provider.so"),
                tokens: vec![test_token(), incompatible],
                issues: Vec::new(),
            }],
        };

        let compatible = report.fcp_compatible_tokens();
        assert_eq!(compatible.len(), 1);
        assert!(compatible[0].supports_ed25519());
    }

    #[test]
    fn token_detection_report_collects_issues() {
        let issue = DetectionIssue::new(
            Path::new("/provider.so"),
            DetectionStage::LoadProvider,
            None,
            "load failed",
        );
        let report = TokenDetectionReport {
            providers: vec![ProviderDetectionResult {
                provider: PathBuf::from("/provider.so"),
                tokens: Vec::new(),
                issues: vec![issue.clone()],
            }],
        };

        assert_eq!(report.issues(), vec![issue]);
    }

    // ---- MockTokenProvider ----

    #[test]
    fn mock_provider_default() {
        use mock::MockTokenProvider;
        let provider = MockTokenProvider::default();
        assert!(provider.list_tokens().is_empty());
    }

    #[test]
    fn mock_provider_sign_returns_64_bytes() {
        use mock::MockTokenProvider;
        let mut provider = MockTokenProvider::new();
        let token = test_token();
        provider.add_token(token.clone());
        let sig = provider.sign(&token, "1234", "test-key", b"data").unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[test]
    fn mock_provider_multiple_tokens() {
        use mock::MockTokenProvider;
        let mut provider = MockTokenProvider::new();
        let mut t1 = test_token();
        t1.slot = 0;
        t1.label = "Token A".into();
        let mut t2 = test_token();
        t2.slot = 1;
        t2.label = "Token B".into();
        provider.add_token(t1);
        provider.add_token(t2);
        assert_eq!(provider.list_tokens().len(), 2);
    }

    // ---- TokenError Display ----

    #[test]
    fn token_error_display() {
        assert_eq!(
            TokenError::NoTokens.to_string(),
            "no hardware tokens detected"
        );
        assert!(
            TokenError::TokenNotFound("yubikey".into())
                .to_string()
                .contains("yubikey")
        );
        assert_eq!(TokenError::InvalidPin.to_string(), "invalid PIN");
        assert!(
            TokenError::KeyNotFound("owner".into())
                .to_string()
                .contains("owner")
        );
        assert!(
            TokenError::UnsupportedMechanism("RSA".into())
                .to_string()
                .contains("RSA")
        );
        assert!(
            TokenError::Pkcs11("init failed".into())
                .to_string()
                .contains("init failed")
        );
        assert_eq!(TokenError::Disconnected.to_string(), "token disconnected");
    }

    // ---- DetectedToken clone ----

    #[test]
    fn detected_token_clone() {
        let token = test_token();
        let cloned = token.clone();
        assert_eq!(token.provider, cloned.provider);
        assert_eq!(token.slot, cloned.slot);
        assert_eq!(token.label, cloned.label);
        assert_eq!(token.manufacturer, cloned.manufacturer);
        assert_eq!(token.serial, cloned.serial);
        assert_eq!(token.mechanisms, cloned.mechanisms);
    }

    // ---- DetectedToken debug ----

    #[test]
    fn detected_token_debug() {
        let token = test_token();
        let debug = format!("{token:?}");
        assert!(debug.contains("DetectedToken"));
        assert!(debug.contains("Test Token"));
        assert!(debug.contains("123456"));
    }

    // ---- DetectedToken with many mechanisms ----

    #[test]
    fn token_with_many_mechanisms() {
        let mut token = test_token();
        token.mechanisms = vec![
            "CKM_RSA_PKCS".to_string(),
            "CKM_ED25519".to_string(),
            "CKM_ECDH".to_string(),
            "CKM_AES_CBC".to_string(),
            "CKM_X25519".to_string(),
        ];
        assert!(token.supports_ed25519());
        assert!(token.supports_x25519());
    }

    // ---- Token Display with different slots ----

    #[test]
    fn token_display_different_slots() {
        let mut token = test_token();
        token.slot = 42;
        let display = format!("{token}");
        assert!(display.contains("[slot 42]"));
    }

    // ---- Token serde with empty mechanisms ----

    #[test]
    fn token_serde_roundtrip_empty_mechanisms() {
        let mut token = test_token();
        token.mechanisms = vec![];
        let json = serde_json::to_string(&token).unwrap();
        let restored: DetectedToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token, restored);
        assert!(restored.mechanisms.is_empty());
    }

    // ---- TokenError Debug ----

    #[test]
    fn token_error_debug() {
        let err = TokenError::InvalidPin;
        let debug = format!("{err:?}");
        assert!(debug.contains("InvalidPin"));
    }

    #[test]
    fn token_error_disconnected_debug() {
        let err = TokenError::Disconnected;
        let debug = format!("{err:?}");
        assert!(debug.contains("Disconnected"));
    }

    // ---- TokenError is std::error::Error ----

    #[test]
    fn token_error_is_error_trait() {
        let err = TokenError::NoTokens;
        let _: &dyn std::error::Error = &err;
    }

    // ---- Token with unicode label ----

    #[test]
    fn token_unicode_label() {
        let mut token = test_token();
        token.label = "S\u{00e9}curit\u{00e9} Token".to_string();
        let display = format!("{token}");
        assert!(display.contains("S\u{00e9}curit\u{00e9}"));
        let json = serde_json::to_string(&token).unwrap();
        let restored: DetectedToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token.label, restored.label);
    }

    // ---- DetectedToken supports_ed25519 with partial match ----

    #[test]
    fn token_supports_ed25519_case_sensitive() {
        let mut token = test_token();
        token.mechanisms = vec!["ckm_ed25519".to_string()];
        // Mechanism check uses contains, which is case-sensitive
        assert!(!token.supports_ed25519());
    }

    #[test]
    fn token_supports_x25519_case_sensitive() {
        let mut token = test_token();
        token.mechanisms = vec!["ckm_x25519".to_string()];
        assert!(!token.supports_x25519());
    }

    // ---- DetectedToken with mixed mechanisms ----

    #[test]
    fn token_ed25519_but_not_x25519() {
        let mut token = test_token();
        token.mechanisms = vec!["CKM_ED25519".to_string()];
        assert!(token.supports_ed25519());
        assert!(!token.supports_x25519());
    }

    #[test]
    fn token_x25519_but_not_ed25519() {
        let mut token = test_token();
        token.mechanisms = vec!["CKM_X25519".to_string()];
        assert!(!token.supports_ed25519());
        assert!(token.supports_x25519());
    }

    // ---- DetectedToken serde with special chars ----

    #[test]
    fn token_serde_with_special_chars_in_serial() {
        let mut token = test_token();
        token.serial = "SN/2026-#001".to_string();
        let json = serde_json::to_string(&token).unwrap();
        let restored: DetectedToken = serde_json::from_str(&json).unwrap();
        assert_eq!(token.serial, restored.serial);
    }

    // ---- DetectedToken PartialEq ----

    #[test]
    fn detected_token_eq_identical() {
        let t1 = test_token();
        let t2 = test_token();
        assert_eq!(t1, t2);
    }

    #[test]
    fn detected_token_ne_different_slot() {
        let t1 = test_token();
        let mut t2 = test_token();
        t2.slot = 99;
        assert_ne!(t1, t2);
    }

    #[test]
    fn detected_token_ne_different_serial() {
        let t1 = test_token();
        let mut t2 = test_token();
        t2.serial = "DIFFERENT".to_string();
        assert_ne!(t1, t2);
    }

    // ---- TokenError Debug for all variants ----

    #[test]
    fn token_error_debug_no_tokens() {
        let err = TokenError::NoTokens;
        let debug = format!("{err:?}");
        assert!(debug.contains("NoTokens"));
    }

    #[test]
    fn token_error_debug_pin_required() {
        let err = TokenError::PinRequired;
        let debug = format!("{err:?}");
        assert!(debug.contains("PinRequired"));
    }

    #[test]
    fn token_error_debug_token_not_found() {
        let err = TokenError::TokenNotFound("slot-3".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("TokenNotFound"));
        assert!(debug.contains("slot-3"));
    }

    #[test]
    fn token_error_debug_unsupported_mechanism() {
        let err = TokenError::UnsupportedMechanism("CKM_RSA".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("UnsupportedMechanism"));
    }

    #[test]
    fn token_error_debug_pkcs11() {
        let err = TokenError::Pkcs11("CKR_DEVICE_ERROR".into());
        let debug = format!("{err:?}");
        assert!(debug.contains("Pkcs11"));
    }

    #[test]
    fn detection_issue_serde_roundtrip() {
        let issue = DetectionIssue::new(
            Path::new("/provider.so"),
            DetectionStage::ReadMechanisms,
            Some(7),
            "mechanism enumeration failed",
        );
        let json = serde_json::to_string(&issue).unwrap();
        let restored: DetectionIssue = serde_json::from_str(&json).unwrap();
        assert_eq!(issue, restored);
    }

    // ---- MockTokenProvider generate_keypair returns different keys ----

    #[test]
    fn mock_provider_generate_keypair_returns_32_bytes() {
        use mock::MockTokenProvider;
        let provider = MockTokenProvider::new();
        let token = test_token();
        let key = provider.generate_keypair(&token, "0000", "key1").unwrap();
        assert_eq!(key.len(), 32);
    }

    // ---- Multi-provider discovery report ----

    #[test]
    fn token_detection_report_multi_provider_aggregates_tokens_and_issues() {
        let mut good_token = test_token();
        good_token.provider = PathBuf::from("/good/provider.so");

        let issue = DetectionIssue::new(
            Path::new("/bad/provider.so"),
            DetectionStage::ProviderMissing,
            None,
            "provider not found",
        );

        let report = TokenDetectionReport {
            providers: vec![
                ProviderDetectionResult {
                    provider: PathBuf::from("/good/provider.so"),
                    tokens: vec![good_token.clone()],
                    issues: Vec::new(),
                },
                ProviderDetectionResult {
                    provider: PathBuf::from("/bad/provider.so"),
                    tokens: Vec::new(),
                    issues: vec![issue],
                },
            ],
        };

        assert_eq!(report.all_tokens().len(), 1);
        assert_eq!(report.all_tokens()[0], good_token);
        assert!(report.has_detected_tokens());
        assert_eq!(report.issues().len(), 1);
        assert_eq!(report.fcp_compatible_tokens().len(), 1);
    }

    // ---- Token identity matching edge cases ----

    #[test]
    fn token_identity_matches_unknown_field_wildcards() {
        let mut requested = test_token();
        requested.label = "unknown".to_string();

        let candidate = test_token();

        // "unknown" in requested should match any candidate label
        assert!(token_identity_matches(&requested, &candidate));
    }

    #[test]
    fn token_identity_does_not_downgrade_known_requested_metadata() {
        let requested = test_token();

        let mut candidate = requested.clone();
        candidate.manufacturer = "unknown".to_string();
        assert!(!token_identity_matches(&requested, &candidate));
        assert!(matches!(
            select_bootstrap_token(&requested, &[candidate]),
            Err(TokenError::TokenNotFound(_))
        ));

        let mut candidate = requested.clone();
        candidate.serial = "unknown".to_string();
        assert!(matches!(
            select_bootstrap_token(&requested, &[candidate.clone()]),
            Err(TokenError::TokenNotFound(_))
        ));
        let mut unspecified = requested;
        unspecified.serial = "unknown".to_string();
        assert!(select_bootstrap_token(&unspecified, &[candidate]).is_ok());
    }

    #[test]
    fn token_identity_does_not_match_different_slot() {
        let requested = test_token();
        let mut candidate = test_token();
        candidate.slot = 99;

        assert!(!token_identity_matches(&requested, &candidate));
    }

    #[test]
    fn token_identity_does_not_match_different_provider() {
        let requested = test_token();
        let mut candidate = test_token();
        candidate.provider = PathBuf::from("/other/provider.so");

        assert!(!token_identity_matches(&requested, &candidate));
    }

    // ---- AuthenticatedSessionState coverage ----

    #[test]
    fn authenticated_session_state_display_all_variants() {
        assert_eq!(
            AuthenticatedSessionState::ReadOnlyPublic.to_string(),
            "ro-public"
        );
        assert_eq!(
            AuthenticatedSessionState::ReadOnlyUser.to_string(),
            "ro-user"
        );
        assert_eq!(
            AuthenticatedSessionState::ReadWritePublic.to_string(),
            "rw-public"
        );
        assert_eq!(
            AuthenticatedSessionState::ReadWriteUser.to_string(),
            "rw-user"
        );
        assert_eq!(
            AuthenticatedSessionState::ReadWriteSecurityOfficer.to_string(),
            "rw-so"
        );
    }

    #[test]
    fn authenticated_session_state_serde_roundtrip_all_variants() {
        let variants = [
            AuthenticatedSessionState::ReadOnlyPublic,
            AuthenticatedSessionState::ReadOnlyUser,
            AuthenticatedSessionState::ReadWritePublic,
            AuthenticatedSessionState::ReadWriteUser,
            AuthenticatedSessionState::ReadWriteSecurityOfficer,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let restored: AuthenticatedSessionState = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, restored);
        }
    }

    // ---- TokenDetectionReport serde roundtrip ----

    #[test]
    fn token_detection_report_serde_roundtrip() {
        let issue = DetectionIssue::new(
            Path::new("/missing.so"),
            DetectionStage::ProviderMissing,
            None,
            "not found",
        );
        let report = TokenDetectionReport {
            providers: vec![
                ProviderDetectionResult {
                    provider: PathBuf::from("/good.so"),
                    tokens: vec![test_token()],
                    issues: Vec::new(),
                },
                ProviderDetectionResult {
                    provider: PathBuf::from("/missing.so"),
                    tokens: Vec::new(),
                    issues: vec![issue],
                },
            ],
        };

        let json = serde_json::to_string(&report).unwrap();
        let restored: TokenDetectionReport = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.providers.len(), 2);
        assert_eq!(restored.all_tokens().len(), 1);
        assert_eq!(restored.issues().len(), 1);
    }

    // ---- Select bootstrap token edge cases ----

    #[test]
    fn select_bootstrap_token_empty_candidates_returns_no_tokens() {
        let result = select_bootstrap_token(&test_token(), &[]);
        assert!(matches!(result, Err(TokenError::NoTokens)));
    }

    #[test]
    fn select_bootstrap_token_not_found_returns_descriptive_error() {
        let requested = test_token();
        let mut other = test_token();
        other.slot = 99;
        other.serial = "different".to_string();
        other.provider = PathBuf::from("/other.so");

        let result = select_bootstrap_token(&requested, &[other]);
        assert!(matches!(result, Err(TokenError::TokenNotFound(_))));
    }

    // ---- HardwareTokenPin ----

    #[test]
    fn hardware_token_pin_is_empty_for_empty_string() {
        let pin = HardwareTokenPin::new("");
        assert!(pin.is_empty());
    }

    #[test]
    fn hardware_token_pin_is_not_empty_for_real_pin() {
        let pin = HardwareTokenPin::new("123456");
        assert!(!pin.is_empty());
    }

    #[test]
    fn provider_session_state_finalizes_after_last_overlapping_close() {
        let provider = Path::new("/test/provider.so");
        let mut sessions = HashMap::new();

        note_provider_session_open(&mut sessions, provider, true);
        note_provider_session_open(&mut sessions, provider, false);

        assert!(!note_provider_session_close(&mut sessions, provider));
        assert_eq!(
            sessions.get(provider),
            Some(&ProviderSessionState {
                active_sessions: 1,
                finalize_required: true,
            })
        );

        assert!(note_provider_session_close(&mut sessions, provider));
        assert!(!sessions.contains_key(provider));
    }

    #[test]
    fn provider_session_state_skips_finalize_for_externally_initialized_provider() {
        let provider = Path::new("/test/provider.so");
        let mut sessions = HashMap::new();

        note_provider_session_open(&mut sessions, provider, false);
        note_provider_session_open(&mut sessions, provider, false);

        assert!(!note_provider_session_close(&mut sessions, provider));
        assert!(!note_provider_session_close(&mut sessions, provider));
        assert!(!sessions.contains_key(provider));
    }

    #[test]
    fn provider_detection_close_does_not_finalize_live_bootstrap_session() {
        let provider = Path::new("/test/provider.so");
        let mut sessions = HashMap::new();

        note_provider_session_open(&mut sessions, provider, true);
        note_provider_session_open(&mut sessions, provider, false);

        assert!(
            !note_provider_session_close(&mut sessions, provider),
            "a discovery pass that observed an already-initialized provider must not finalize it"
        );
        assert_eq!(
            sessions.get(provider),
            Some(&ProviderSessionState {
                active_sessions: 1,
                finalize_required: true,
            })
        );
        assert!(
            note_provider_session_close(&mut sessions, provider),
            "the bootstrap session that initialized the provider remains responsible for finalize"
        );
    }

    // ---- DetectionStage serde roundtrip ----

    #[test]
    fn detection_stage_serde_roundtrip_all_variants() {
        let stages = [
            DetectionStage::ProviderMissing,
            DetectionStage::LoadProvider,
            DetectionStage::InitializeProvider,
            DetectionStage::EnumerateSlots,
            DetectionStage::NormalizeSlotId,
            DetectionStage::ReadTokenInfo,
            DetectionStage::ReadMechanisms,
            DetectionStage::FinalizeProvider,
        ];
        for stage in &stages {
            let json = serde_json::to_string(stage).unwrap();
            let restored: DetectionStage = serde_json::from_str(&json).unwrap();
            assert_eq!(*stage, restored);
        }
    }

    // ---- Session drop does not panic without close action ----

    #[test]
    fn authenticated_session_drop_without_close_action_does_not_panic() {
        let session = AuthenticatedTokenSession::with_close_action(
            test_token(),
            AuthenticatedSessionState::ReadWriteUser,
            true,
            || Ok(()),
        );
        drop(session); // Should not panic
    }

    // ---- Session timeout ----

    #[test]
    fn session_not_expired_immediately() {
        let session = AuthenticatedTokenSession::with_close_action(
            test_token(),
            AuthenticatedSessionState::ReadWriteUser,
            true,
            || Ok(()),
        );
        assert!(!session.is_expired());
        session.check_alive().unwrap();
    }

    #[test]
    fn session_expired_after_zero_timeout() {
        let mut session = AuthenticatedTokenSession::with_close_action(
            test_token(),
            AuthenticatedSessionState::ReadWriteUser,
            true,
            || Ok(()),
        );
        session.set_timeout(Duration::ZERO);
        // Even Duration::ZERO may not trigger immediately on fast CPUs,
        // but with a tiny sleep it definitely will.
        std::thread::sleep(Duration::from_millis(1));
        assert!(session.is_expired());
        assert!(matches!(
            session.check_alive(),
            Err(TokenError::SessionExpired { .. })
        ));
    }

    #[test]
    fn session_default_timeout_is_5_minutes() {
        let session = AuthenticatedTokenSession::with_close_action(
            test_token(),
            AuthenticatedSessionState::ReadWriteUser,
            true,
            || Ok(()),
        );
        assert_eq!(session.timeout(), Duration::from_secs(300));
    }

    #[test]
    fn session_custom_timeout() {
        let mut session = AuthenticatedTokenSession::with_close_action(
            test_token(),
            AuthenticatedSessionState::ReadWriteUser,
            true,
            || Ok(()),
        );
        session.set_timeout(Duration::from_secs(60));
        assert_eq!(session.timeout(), Duration::from_secs(60));
    }

    #[test]
    fn session_elapsed_is_nonnegative() {
        let session = AuthenticatedTokenSession::with_close_action(
            test_token(),
            AuthenticatedSessionState::ReadWriteUser,
            true,
            || Ok(()),
        );
        assert!(session.elapsed() < Duration::from_secs(5));
    }

    // ---- SessionExpired error display ----

    #[test]
    fn session_expired_error_display() {
        let err = TokenError::SessionExpired {
            elapsed: Duration::from_secs(301),
            timeout: Duration::from_secs(300),
        };
        let display = err.to_string();
        assert!(display.contains("expired"));
        assert!(display.contains("301"));
    }

    #[test]
    fn session_expired_error_debug() {
        let err = TokenError::SessionExpired {
            elapsed: Duration::from_secs(10),
            timeout: Duration::from_secs(5),
        };
        let debug = format!("{err:?}");
        assert!(debug.contains("SessionExpired"));
    }

    // ---- select_and_authenticate state machine ----

    #[test]
    fn select_and_authenticate_returns_outcome_with_session() {
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");
        let driver = MockSessionDriver::default();
        let report = TokenDetectionReport {
            providers: vec![ProviderDetectionResult {
                provider: token.provider.clone(),
                tokens: vec![token.clone()],
                issues: Vec::new(),
            }],
        };

        let outcome = select_and_authenticate(&token, &pin, &report, &driver, None).unwrap();
        assert_eq!(outcome.selected_token, token);
        assert_eq!(
            outcome.session.session_state(),
            AuthenticatedSessionState::ReadWriteUser
        );
        assert!(outcome.session.read_write());
        assert!(!outcome.session.is_expired());
        outcome.session.close().unwrap();
        assert_eq!(driver.close_count(), 1);
    }

    #[test]
    fn select_and_authenticate_applies_custom_timeout() {
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");
        let driver = MockSessionDriver::default();
        let report = TokenDetectionReport {
            providers: vec![ProviderDetectionResult {
                provider: token.provider.clone(),
                tokens: vec![token.clone()],
                issues: Vec::new(),
            }],
        };

        let outcome = select_and_authenticate(
            &token,
            &pin,
            &report,
            &driver,
            Some(Duration::from_secs(60)),
        )
        .unwrap();
        assert_eq!(outcome.session.timeout(), Duration::from_secs(60));
    }

    #[test]
    fn select_and_authenticate_refuses_empty_pin() {
        let token = test_token();
        let pin = HardwareTokenPin::new("");
        let driver = MockSessionDriver::default();
        let report = TokenDetectionReport::default();

        let result = select_and_authenticate(&token, &pin, &report, &driver, None);
        assert!(matches!(result, Err(TokenError::PinRequired)));
    }

    #[test]
    fn select_and_authenticate_refuses_missing_token() {
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");
        let driver = MockSessionDriver::default();
        let report = TokenDetectionReport::default();

        let result = select_and_authenticate(&token, &pin, &report, &driver, None);
        assert!(matches!(result, Err(TokenError::NoTokens)));
    }

    #[test]
    fn select_and_authenticate_refuses_incompatible_token() {
        let mut token = test_token();
        token.mechanisms = vec!["CKM_RSA_PKCS".to_string()];
        let pin = HardwareTokenPin::new("123456");
        let driver = MockSessionDriver::default();
        let report = TokenDetectionReport {
            providers: vec![ProviderDetectionResult {
                provider: token.provider.clone(),
                tokens: vec![token.clone()],
                issues: Vec::new(),
            }],
        };

        let result = select_and_authenticate(&token, &pin, &report, &driver, None);
        assert!(matches!(result, Err(TokenError::UnsupportedMechanism(_))));
    }

    #[test]
    fn select_and_authenticate_picks_best_from_multiple_candidates() {
        let mut weaker = test_token();
        weaker.slot = 1;
        weaker.serial = "weak".to_string();
        weaker.mechanisms = vec!["CKM_RSA_PKCS".to_string()];

        let strong = test_token(); // has Ed25519 + ECDH

        let pin = HardwareTokenPin::new("123456");
        let driver = MockSessionDriver::default();
        let report = TokenDetectionReport {
            providers: vec![ProviderDetectionResult {
                provider: strong.provider.clone(),
                tokens: vec![weaker, strong.clone()],
                issues: Vec::new(),
            }],
        };

        let outcome = select_and_authenticate(&strong, &pin, &report, &driver, None).unwrap();
        assert_eq!(outcome.selected_token, strong);
    }

    #[derive(Default)]
    struct MockSessionDriver {
        close_count: Arc<AtomicUsize>,
        certs: Arc<Mutex<Vec<TokenCertificate>>>,
        keys: Arc<Mutex<Vec<TokenKeyInfo>>>,
    }

    impl MockSessionDriver {
        fn close_count(&self) -> usize {
            self.close_count.load(Ordering::SeqCst)
        }

        fn with_certs_and_keys(certs: Vec<TokenCertificate>, keys: Vec<TokenKeyInfo>) -> Self {
            Self {
                close_count: Arc::new(AtomicUsize::new(0)),
                certs: Arc::new(Mutex::new(certs)),
                keys: Arc::new(Mutex::new(keys)),
            }
        }
    }

    impl HardwareTokenSessionDriver for MockSessionDriver {
        fn open_authenticated_session(
            &self,
            token: &DetectedToken,
            _pin: &HardwareTokenPin,
        ) -> Result<AuthenticatedTokenSession, TokenError> {
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
            _token: &DetectedToken,
            _pin: &HardwareTokenPin,
        ) -> Result<Vec<TokenCertificate>, TokenError> {
            Ok(self.certs.lock().unwrap().clone())
        }

        fn enumerate_keys(
            &self,
            _token: &DetectedToken,
            _pin: &HardwareTokenPin,
        ) -> Result<Vec<TokenKeyInfo>, TokenError> {
            Ok(self.keys.lock().unwrap().clone())
        }

        fn sign_ed25519(
            &self,
            _token: &DetectedToken,
            _pin: &HardwareTokenPin,
            key_id: &[u8],
            _message: &[u8],
        ) -> Result<Vec<u8>, TokenError> {
            Err(TokenError::KeyNotFound(hex::encode(key_id)))
        }
    }

    // ── Test helpers for certificate selection ───────────────────────────

    fn deterministic_test_signing_key(label: &str, id: &[u8], purpose: &[u8]) -> SigningKey {
        let mut signing_key_bytes = [0u8; 32];
        let mut key_context = Vec::with_capacity(purpose.len() + label.len() + id.len() + 2);
        key_context.extend_from_slice(purpose);
        key_context.push(0);
        key_context.extend_from_slice(label.as_bytes());
        key_context.push(0);
        key_context.extend_from_slice(id);

        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"fcp-bootstrap-test-cert"), &key_context);
        hk.expand(b"fcp-bootstrap-test-cert-ed25519", &mut signing_key_bytes)
            .expect("32 bytes is a valid HKDF-SHA256 output length");

        SigningKey::from_bytes(&signing_key_bytes)
    }

    fn deterministic_test_key_pair(label: &str, id: &[u8], purpose: &[u8]) -> KeyPair {
        let signing_key = deterministic_test_signing_key(label, id, purpose);
        let pkcs8 = signing_key.to_pkcs8_der().unwrap();
        KeyPair::try_from(pkcs8.as_bytes()).unwrap()
    }

    fn deterministic_test_ca(label: &str) -> CertifiedIssuer<'static, KeyPair> {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, label);
        let key_pair = deterministic_test_key_pair(label, b"", b"ca");
        CertifiedIssuer::self_signed(params, key_pair).unwrap()
    }

    fn test_cert(label: &str, id: &[u8]) -> TokenCertificate {
        let issuer = deterministic_test_ca("TestCA");
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, label);
        let key_pair = deterministic_test_key_pair(label, id, b"leaf");
        let cert = params.signed_by(&key_pair, &issuer).unwrap();

        TokenCertificate {
            label: label.to_string(),
            id: id.to_vec(),
            der_bytes: cert.der().to_vec(),
            subject: format!("CN={label}"),
            issuer: "CN=TestCA".to_string(),
            is_ca: false,
        }
    }

    fn test_ca_cert(label: &str, id: &[u8]) -> TokenCertificate {
        let issuer = deterministic_test_ca(label);
        TokenCertificate {
            label: label.to_string(),
            id: id.to_vec(),
            der_bytes: issuer.der().to_vec(),
            subject: format!("CN={label}"),
            issuer: format!("CN={label}"),
            is_ca: true,
        }
    }

    fn test_key(label: &str, id: &[u8], key_type: TokenKeyType) -> TokenKeyInfo {
        TokenKeyInfo {
            label: label.to_string(),
            id: id.to_vec(),
            key_type,
            can_sign: true,
            can_derive: false,
        }
    }

    fn test_x509_certificate(
        label: &str,
        id: &[u8],
        issuer_label: &str,
        is_ca: bool,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
        signing_issuer: Option<&CertifiedIssuer<'_, KeyPair>>,
    ) -> TokenCertificate {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.not_before = not_before;
        params.not_after = not_after;
        params.distinguished_name.push(DnType::CommonName, label);
        if is_ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        }

        let key_pair = KeyPair::generate().unwrap();
        let cert = signing_issuer.map_or_else(
            || params.self_signed(&key_pair).unwrap(),
            |issuer| params.signed_by(&key_pair, issuer).unwrap(),
        );

        TokenCertificate {
            label: label.to_string(),
            id: id.to_vec(),
            der_bytes: cert.der().to_vec(),
            subject: format!("CN={label}"),
            issuer: format!("CN={issuer_label}"),
            is_ca,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn test_x509_leaf_signed_by_ca(
        label: &str,
        id: &[u8],
        issuer_id: &[u8],
        issuer_label: &str,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
        issuer_not_before: OffsetDateTime,
        issuer_not_after: OffsetDateTime,
    ) -> (TokenCertificate, TokenCertificate) {
        let mut issuer_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        issuer_params.not_before = issuer_not_before;
        issuer_params.not_after = issuer_not_after;
        issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        issuer_params
            .distinguished_name
            .push(DnType::CommonName, issuer_label);
        let issuer_key = KeyPair::generate().unwrap();
        let issuer = CertifiedIssuer::self_signed(issuer_params, issuer_key).unwrap();

        let leaf = test_x509_certificate(
            label,
            id,
            issuer_label,
            false,
            not_before,
            not_after,
            Some(&issuer),
        );

        let ca = TokenCertificate {
            label: issuer_label.to_string(),
            id: issuer_id.to_vec(),
            der_bytes: issuer.der().to_vec(),
            subject: format!("CN={issuer_label}"),
            issuer: format!("CN={issuer_label}"),
            is_ca: true,
        };

        (leaf, ca)
    }

    fn test_x509_leaf_signed_by_non_ca_metadata_issuer(
        label: &str,
        id: &[u8],
        issuer_id: &[u8],
        issuer_label: &str,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> (TokenCertificate, TokenCertificate) {
        let mut issuer_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        issuer_params.not_before = not_before;
        issuer_params.not_after = not_after;
        issuer_params
            .distinguished_name
            .push(DnType::CommonName, issuer_label);
        let issuer_key = KeyPair::generate().unwrap();
        let issuer = CertifiedIssuer::self_signed(issuer_params, issuer_key).unwrap();

        let leaf = test_x509_certificate(
            label,
            id,
            issuer_label,
            false,
            not_before,
            not_after,
            Some(&issuer),
        );

        let issuer_cert = TokenCertificate {
            label: issuer_label.to_string(),
            id: issuer_id.to_vec(),
            der_bytes: issuer.der().to_vec(),
            subject: format!("CN={issuer_label}"),
            issuer: format!("CN={issuer_label}"),
            is_ca: true,
        };

        (leaf, issuer_cert)
    }

    fn test_x509_leaf_signed_by_ca_without_key_cert_sign(
        label: &str,
        id: &[u8],
        issuer_id: &[u8],
        issuer_label: &str,
        not_before: OffsetDateTime,
        not_after: OffsetDateTime,
    ) -> (TokenCertificate, TokenCertificate) {
        let mut issuer_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        issuer_params.not_before = not_before;
        issuer_params.not_after = not_after;
        issuer_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        issuer_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        issuer_params
            .distinguished_name
            .push(DnType::CommonName, issuer_label);
        let issuer_key = KeyPair::generate().unwrap();
        let issuer = CertifiedIssuer::self_signed(issuer_params, issuer_key).unwrap();

        let leaf = test_x509_certificate(
            label,
            id,
            issuer_label,
            false,
            not_before,
            not_after,
            Some(&issuer),
        );

        let issuer_cert = TokenCertificate {
            label: issuer_label.to_string(),
            id: issuer_id.to_vec(),
            der_bytes: issuer.der().to_vec(),
            subject: format!("CN={issuer_label}"),
            issuer: format!("CN={issuer_label}"),
            is_ca: true,
        };

        (leaf, issuer_cert)
    }

    // ── Certificate/key type tests ──────────────────────────────────────

    #[test]
    fn token_key_type_display_all_variants() {
        assert_eq!(TokenKeyType::Ed25519.to_string(), "Ed25519");
        assert_eq!(TokenKeyType::X25519.to_string(), "X25519");
        assert_eq!(TokenKeyType::EcdsaP256.to_string(), "ECDSA-P256");
        assert_eq!(TokenKeyType::EcdsaP384.to_string(), "ECDSA-P384");
        assert_eq!(TokenKeyType::Rsa.to_string(), "RSA");
        assert_eq!(TokenKeyType::Other(42).to_string(), "Other(42)");
    }

    #[test]
    fn token_key_type_serde_roundtrip() {
        let variants = [
            TokenKeyType::Ed25519,
            TokenKeyType::X25519,
            TokenKeyType::EcdsaP256,
            TokenKeyType::EcdsaP384,
            TokenKeyType::Rsa,
            TokenKeyType::Other(99),
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let restored: TokenKeyType = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, restored);
        }
    }

    #[test]
    fn token_certificate_display() {
        let cert = test_cert("my-cert", &[0x01, 0x02]);
        assert!(cert.to_string().contains("my-cert"));
        assert!(cert.to_string().contains("0102"));
    }

    #[test]
    fn token_certificate_ca_display() {
        let mut cert = test_cert("root-ca", &[0xaa]);
        cert.is_ca = true;
        assert!(cert.to_string().contains("CA"));
    }

    #[test]
    fn token_key_info_display() {
        let key = test_key("my-key", &[0x01], TokenKeyType::Ed25519);
        let display = key.to_string();
        assert!(display.contains("my-key"));
        assert!(display.contains("Ed25519"));
    }

    #[test]
    fn certificate_key_pair_display() {
        let pair = CertificateKeyPair {
            certificate: test_cert("cert-1", &[0x01]),
            key: test_key("key-1", &[0x01], TokenKeyType::Ed25519),
        };
        let display = pair.to_string();
        assert!(display.contains("cert-1"));
        assert!(display.contains("key-1"));
    }

    #[test]
    fn provisioning_material_display() {
        let mat = ProvisioningMaterial {
            pair: CertificateKeyPair {
                certificate: test_cert("c", &[1]),
                key: test_key("k", &[1], TokenKeyType::Ed25519),
            },
            token: test_token(),
            candidates_considered: 3,
            selection_reason: "best key type".to_string(),
        };
        let display = mat.to_string();
        assert!(display.contains("3 candidates"));
    }

    // ── match_certificate_key_pairs ─────────────────────────────────────

    #[test]
    fn match_pairs_by_id() {
        let certs = vec![
            test_cert("c1", &[0x01]),
            test_cert("c2", &[0x02]),
            test_cert("c3", &[0x03]),
        ];
        let keys = vec![
            test_key("k2", &[0x02], TokenKeyType::Ed25519),
            test_key("k3", &[0x03], TokenKeyType::X25519),
        ];
        let pairs = match_certificate_key_pairs(&certs, &keys);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].certificate.label, "c2");
        assert_eq!(pairs[1].certificate.label, "c3");
    }

    #[test]
    fn match_pairs_skips_ca_certs() {
        let mut ca = test_cert("ca", &[0x01]);
        ca.is_ca = true;
        let certs = vec![ca, test_cert("end", &[0x02])];
        let keys = vec![
            test_key("k1", &[0x01], TokenKeyType::Ed25519),
            test_key("k2", &[0x02], TokenKeyType::Ed25519),
        ];
        let pairs = match_certificate_key_pairs(&certs, &keys);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].certificate.label, "end");
    }

    #[test]
    fn match_pairs_skips_empty_id_certs() {
        let certs = vec![test_cert("no-id", &[])];
        let keys = vec![test_key("k", &[], TokenKeyType::Ed25519)];
        let pairs = match_certificate_key_pairs(&certs, &keys);
        assert!(pairs.is_empty());
    }

    #[test]
    fn match_pairs_no_overlap_returns_empty() {
        let certs = vec![test_cert("c", &[0x01])];
        let keys = vec![test_key("k", &[0x02], TokenKeyType::Ed25519)];
        let pairs = match_certificate_key_pairs(&certs, &keys);
        assert!(pairs.is_empty());
    }

    // ── select_certificate_for_provisioning ─────────────────────────────

    #[test]
    fn select_cert_no_certs_returns_refusal() {
        let driver = MockSessionDriver::with_certs_and_keys(vec![], vec![]);
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        assert!(matches!(
            err,
            TokenError::CertificateSelectionFailed(CertificateSelectionRefusal::NoCertificates)
        ));
    }

    #[test]
    fn select_cert_empty_pin_returns_pin_required() {
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![test_cert("c1", &[1])],
            vec![test_key("k1", &[1], TokenKeyType::Ed25519)],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("");

        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        assert!(matches!(err, TokenError::PinRequired));
    }

    #[test]
    fn select_cert_no_keys_returns_refusal() {
        let driver = MockSessionDriver::with_certs_and_keys(vec![test_cert("c1", &[1])], vec![]);
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        assert!(matches!(
            err,
            TokenError::CertificateSelectionFailed(CertificateSelectionRefusal::NoKeys)
        ));
    }

    #[test]
    fn select_cert_no_matching_pair_returns_refusal() {
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![test_cert("c1", &[1])],
            vec![test_key("k1", &[2], TokenKeyType::Ed25519)],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        assert!(matches!(
            err,
            TokenError::CertificateSelectionFailed(CertificateSelectionRefusal::NoMatchingKeyPair)
        ));
    }

    #[test]
    fn select_cert_incompatible_key_type_returns_refusal() {
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![test_cert("c1", &[1])],
            vec![test_key("k1", &[1], TokenKeyType::Rsa)],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        match err {
            TokenError::CertificateSelectionFailed(
                CertificateSelectionRefusal::NoCompatibleKeyType { found },
            ) => {
                assert_eq!(found, vec![TokenKeyType::Rsa]);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn select_cert_prefers_ed25519_over_ecdsa() {
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![
                test_cert("ecdsa-cert", &[1]),
                test_cert("ed-cert", &[2]),
                test_ca_cert("TestCA", &[9]),
            ],
            vec![
                test_key("ecdsa-key", &[1], TokenKeyType::EcdsaP256),
                test_key("ed-key", &[2], TokenKeyType::Ed25519),
            ],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let material = select_certificate_for_provisioning(&token, &pin, &driver).unwrap();
        assert_eq!(material.pair.key.key_type, TokenKeyType::Ed25519);
        assert_eq!(material.pair.certificate.label, "ed-cert");
        assert_eq!(material.candidates_considered, 1);
    }

    #[test]
    fn select_cert_x25519_only_returns_refusal() {
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![
                test_cert("ec-cert", &[1]),
                test_cert("x-cert", &[2]),
                test_ca_cert("TestCA", &[9]),
            ],
            vec![
                test_key("ec-key", &[1], TokenKeyType::EcdsaP384),
                test_key("x-key", &[2], TokenKeyType::X25519),
            ],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        match err {
            TokenError::CertificateSelectionFailed(
                CertificateSelectionRefusal::NoCompatibleKeyType { found },
            ) => {
                assert_eq!(found, vec![TokenKeyType::EcdsaP384, TokenKeyType::X25519]);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn select_cert_single_ed25519_pair_succeeds() {
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![test_cert("my-cert", &[0xAB]), test_ca_cert("TestCA", &[9])],
            vec![test_key("my-key", &[0xAB], TokenKeyType::Ed25519)],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let material = select_certificate_for_provisioning(&token, &pin, &driver).unwrap();
        assert_eq!(material.pair.certificate.label, "my-cert");
        assert_eq!(material.pair.key.label, "my-key");
        assert_eq!(material.pair.key.key_type, TokenKeyType::Ed25519);
        assert_eq!(material.candidates_considered, 1);
        assert_eq!(material.token, token);
    }

    #[test]
    fn certificate_selection_index_bounds_lookup_for_large_token_configs() {
        let now = OffsetDateTime::now_utc();
        let (selected_leaf, ca) = test_x509_leaf_signed_by_ca(
            "selected-leaf",
            &[1],
            &[9],
            "Indexed Test CA",
            now - TimeDuration::days(7),
            now + TimeDuration::days(7),
            now - TimeDuration::days(60),
            now + TimeDuration::days(60),
        );

        let mut certs = Vec::with_capacity(1_000);
        certs.push(selected_leaf.clone());
        certs.push(ca);
        for index in 2_usize..1_000 {
            let mut noise = selected_leaf.clone();
            noise.label = format!("noise-cert-{index:04}");
            noise.id = u32::try_from(index)
                .expect("test index fits u32")
                .to_be_bytes()
                .to_vec();
            certs.push(noise);
        }
        let keys = vec![test_key("selected-key", &[1], TokenKeyType::Ed25519)];

        let index = CertificateSelectionIndex::new(&certs, &keys);
        let started = Instant::now();
        let selection = index
            .select_for_provisioning()
            .expect("indexed selection succeeds");
        let elapsed = started.elapsed();

        assert_eq!(selection.pair.certificate.label, "selected-leaf");
        assert_eq!(selection.candidates_considered, 1);
        assert!(
            elapsed < Duration::from_secs(1),
            "cached selection lookup should be bounded for 1000 certs, took {elapsed:?}"
        );
    }

    #[test]
    fn select_cert_signing_key_preferred_over_derive_only() {
        let mut derive_key = test_key("derive-key", &[1], TokenKeyType::Ed25519);
        derive_key.can_sign = false;
        derive_key.can_derive = true;

        let sign_key = test_key("sign-key", &[2], TokenKeyType::Ed25519);

        let driver = MockSessionDriver::with_certs_and_keys(
            vec![
                test_cert("d-cert", &[1]),
                test_cert("s-cert", &[2]),
                test_ca_cert("TestCA", &[9]),
            ],
            vec![derive_key, sign_key],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let material = select_certificate_for_provisioning(&token, &pin, &driver).unwrap();
        assert_eq!(material.pair.certificate.label, "s-cert");
        assert!(material.pair.key.can_sign);
    }

    #[test]
    fn select_cert_deterministic_tiebreak_by_label() {
        // Two Ed25519 signing keys — tiebreak by certificate label.
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![
                test_cert("beta-cert", &[2]),
                test_cert("alpha-cert", &[1]),
                test_ca_cert("TestCA", &[9]),
            ],
            vec![
                test_key("k2", &[2], TokenKeyType::Ed25519),
                test_key("k1", &[1], TokenKeyType::Ed25519),
            ],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let material = select_certificate_for_provisioning(&token, &pin, &driver).unwrap();
        assert_eq!(material.pair.certificate.label, "alpha-cert");
    }

    #[test]
    fn select_cert_missing_verified_issuer_chain_returns_refusal() {
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![test_cert("leaf-cert", &[1])],
            vec![test_key("leaf-key", &[1], TokenKeyType::Ed25519)],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        assert!(matches!(
            err,
            TokenError::CertificateSelectionFailed(
                CertificateSelectionRefusal::NoVerifiedIssuerChain
            )
        ));
    }

    #[test]
    fn select_cert_expired_x509_leaf_returns_refusal() {
        let now = OffsetDateTime::now_utc();
        let (expired_leaf, ca) = test_x509_leaf_signed_by_ca(
            "expired-leaf",
            &[1],
            &[9],
            "Valid Test CA",
            now - TimeDuration::days(30),
            now - TimeDuration::days(1),
            now - TimeDuration::days(60),
            now + TimeDuration::days(60),
        );
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![expired_leaf, ca],
            vec![test_key("expired-key", &[1], TokenKeyType::Ed25519)],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        assert!(matches!(
            err,
            TokenError::CertificateSelectionFailed(
                CertificateSelectionRefusal::NoVerifiedIssuerChain
            )
        ));
    }

    #[test]
    fn select_cert_not_yet_valid_x509_leaf_returns_refusal() {
        let now = OffsetDateTime::now_utc();
        let (future_leaf, ca) = test_x509_leaf_signed_by_ca(
            "future-leaf",
            &[2],
            &[9],
            "Valid Test CA",
            now + TimeDuration::days(1),
            now + TimeDuration::days(30),
            now - TimeDuration::days(60),
            now + TimeDuration::days(60),
        );
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![future_leaf, ca],
            vec![test_key("future-key", &[2], TokenKeyType::Ed25519)],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        assert!(matches!(
            err,
            TokenError::CertificateSelectionFailed(
                CertificateSelectionRefusal::NoVerifiedIssuerChain
            )
        ));
    }

    #[test]
    fn select_cert_accepts_leaf_and_ca_not_before_within_bootstrap_skew() {
        let now = OffsetDateTime::now_utc();
        let (leaf, ca) = test_x509_leaf_signed_by_ca(
            "slightly-future-leaf",
            &[7],
            &[9],
            "Slightly Future CA",
            now + TimeDuration::seconds(30),
            now + TimeDuration::days(30),
            now + TimeDuration::seconds(30),
            now + TimeDuration::days(60),
        );
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![leaf, ca],
            vec![test_key("slightly-future-key", &[7], TokenKeyType::Ed25519)],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let material = select_certificate_for_provisioning(&token, &pin, &driver).unwrap();
        assert_eq!(material.pair.certificate.label, "slightly-future-leaf");
    }

    /// REVIEW fresh-eyes pin (`cc_1)`: the accept-within-skew test at
    /// `select_cert_accepts_leaf_and_ca_not_before_within_bootstrap_skew`
    /// would silently keep passing if a future commit widened
    /// `BOOTSTRAP_CERT_NOT_BEFORE_SKEW_SECS` to a large value (e.g.
    /// a day). This test pins the upper bound so any accidental
    /// widening trips a failure.
    ///
    /// A cert with `not_before = now + 600s` is 10× the 60-second
    /// tolerance and must be rejected. If the constant is widened
    /// beyond 600s this test needs updating — the failure surfaces
    /// the decision.
    #[test]
    fn select_cert_rejects_leaf_not_before_far_beyond_bootstrap_skew() {
        let now = OffsetDateTime::now_utc();
        let (leaf, ca) = test_x509_leaf_signed_by_ca(
            "far-future-leaf",
            &[11],
            &[13],
            "Far Future CA",
            now + TimeDuration::seconds(600),
            now + TimeDuration::days(30),
            now - TimeDuration::days(1),
            now + TimeDuration::days(60),
        );
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![leaf, ca],
            vec![test_key("far-future-key", &[11], TokenKeyType::Ed25519)],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        assert!(
            matches!(
                err,
                TokenError::CertificateSelectionFailed(
                    CertificateSelectionRefusal::NoVerifiedIssuerChain
                )
            ),
            "expected NoVerifiedIssuerChain for leaf with not_before 10× beyond skew, got {err:?}"
        );
    }

    #[test]
    fn select_cert_expired_x509_ca_returns_refusal() {
        let now = OffsetDateTime::now_utc();
        let (leaf, expired_ca) = test_x509_leaf_signed_by_ca(
            "leaf-with-expired-ca",
            &[3],
            &[9],
            "Expired Test CA",
            now - TimeDuration::days(7),
            now + TimeDuration::days(7),
            now - TimeDuration::days(90),
            now - TimeDuration::days(1),
        );
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![leaf, expired_ca],
            vec![test_key("leaf-key", &[3], TokenKeyType::Ed25519)],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        assert!(matches!(
            err,
            TokenError::CertificateSelectionFailed(
                CertificateSelectionRefusal::NoVerifiedIssuerChain
            )
        ));
    }

    #[test]
    fn select_cert_non_ca_issuer_with_ca_metadata_returns_refusal() {
        let now = OffsetDateTime::now_utc();
        let (leaf, metadata_ca) = test_x509_leaf_signed_by_non_ca_metadata_issuer(
            "leaf-with-metadata-ca",
            &[4],
            &[9],
            "Metadata Only CA",
            now - TimeDuration::days(7),
            now + TimeDuration::days(7),
        );
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![leaf, metadata_ca],
            vec![test_key("leaf-key", &[4], TokenKeyType::Ed25519)],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        assert!(matches!(
            err,
            TokenError::CertificateSelectionFailed(
                CertificateSelectionRefusal::NoVerifiedIssuerChain
            )
        ));
    }

    #[test]
    fn select_cert_der_ca_leaf_with_false_metadata_returns_refusal() {
        let now = OffsetDateTime::now_utc();
        let mut ca_leaf = test_x509_certificate(
            "ca-leaf",
            &[5],
            "ca-leaf",
            true,
            now - TimeDuration::days(7),
            now + TimeDuration::days(7),
            None,
        );
        ca_leaf.is_ca = false;
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![ca_leaf],
            vec![test_key("ca-key", &[5], TokenKeyType::Ed25519)],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        assert!(matches!(
            err,
            TokenError::CertificateSelectionFailed(
                CertificateSelectionRefusal::NoVerifiedIssuerChain
            )
        ));
    }

    #[test]
    fn select_cert_ca_issuer_without_key_cert_sign_returns_refusal() {
        let now = OffsetDateTime::now_utc();
        let (leaf, ca_without_cert_sign) = test_x509_leaf_signed_by_ca_without_key_cert_sign(
            "leaf-with-ku-limited-ca",
            &[6],
            &[10],
            "CA Without Cert Sign",
            now - TimeDuration::days(7),
            now + TimeDuration::days(7),
        );
        let driver = MockSessionDriver::with_certs_and_keys(
            vec![leaf, ca_without_cert_sign],
            vec![test_key("leaf-key", &[6], TokenKeyType::Ed25519)],
        );
        let token = test_token();
        let pin = HardwareTokenPin::new("123456");

        let err = select_certificate_for_provisioning(&token, &pin, &driver).unwrap_err();
        assert!(matches!(
            err,
            TokenError::CertificateSelectionFailed(
                CertificateSelectionRefusal::NoVerifiedIssuerChain
            )
        ));
    }

    // ── CertificateSelectionRefusal display ─────────────────────────────

    #[test]
    fn certificate_selection_refusal_display_all_variants() {
        assert!(
            CertificateSelectionRefusal::NoCertificates
                .to_string()
                .contains("no certificates")
        );
        assert!(
            CertificateSelectionRefusal::NoKeys
                .to_string()
                .contains("no private keys")
        );
        assert!(
            CertificateSelectionRefusal::NoMatchingKeyPair
                .to_string()
                .contains("matching private key")
        );
        let no_compat = CertificateSelectionRefusal::NoCompatibleKeyType {
            found: vec![TokenKeyType::Rsa],
        };
        assert!(no_compat.to_string().contains("RSA"));
        assert!(
            CertificateSelectionRefusal::NoVerifiedIssuerChain
                .to_string()
                .contains("issuer chain")
        );
        let ambig = CertificateSelectionRefusal::AmbiguousSelection { count: 3 };
        assert!(ambig.to_string().contains('3'));
    }

    // ── TokenError::CertificateSelectionFailed display ──────────────────

    #[test]
    fn certificate_selection_failed_error_display() {
        let err =
            TokenError::CertificateSelectionFailed(CertificateSelectionRefusal::NoCertificates);
        let display = err.to_string();
        assert!(display.contains("certificate selection failed"));
        assert!(display.contains("no certificates"));
    }
}
