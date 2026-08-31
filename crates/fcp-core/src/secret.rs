//! Secret storage and access types for FCP (NORMATIVE).
//!
//! This module implements `SecretObject` and `SecretAccessToken` as described in
//! `FCP_Specification_V3.md` §11.8 (Threshold Secret Use) and §5.6 (Network Guard
//! and Secret Use) for secure credential handling.
//!
//! **Security guarantees:**
//! - Secret material MUST be zeroized immediately after use.
//! - Every successful access MUST emit an `AuditEvent` with `event_type = "secret.access"`.
//! - Secret bytes MUST NOT appear in logs or error messages.
//! - Threshold secrets (k-of-n) are supported via wrapped shares.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{FcpError, FcpResult, ObjectHeader, ObjectId, PrincipalId, ZoneId};

const RAW_SECRET_CONFIG_FIELDS: &[&str] = &[
    "token",
    "access_token",
    "app_token",
    "bearer",
    "api_key",
    "client_secret",
    "refresh_token",
    "password",
    "secret_key",
];

const SLACK_SECRET_PREFIXES: &[&str] = &["xoxb-", "xoxa-", "xoxp-", "xoxs-", "xoxr-"];

/// Reject raw secret material at connector configuration boundaries.
///
/// Connector configuration may carry credential references and non-sensitive
/// setup hints, but it must not carry provider tokens, passwords, API keys, or
/// obvious token-shaped values. The returned error hashes the field name and
/// records only a stable detector label.
///
/// # Errors
/// Returns [`FcpError::ConfigurationLeakedSecret`] when a blocked field name or
/// token-shaped value is found anywhere in the JSON tree.
pub fn reject_secret_config_material(value: &serde_json::Value) -> FcpResult<()> {
    reject_secret_config_material_inner(value, None)
}

fn reject_secret_config_material_inner(
    value: &serde_json::Value,
    field_name: Option<&str>,
) -> FcpResult<()> {
    match value {
        serde_json::Value::Object(map) => {
            for (field_name, field_value) in map {
                if RAW_SECRET_CONFIG_FIELDS
                    .iter()
                    .any(|blocked| field_name.eq_ignore_ascii_case(blocked))
                {
                    return Err(FcpError::configuration_leaked_secret(
                        field_name,
                        "raw_secret_config_field",
                    ));
                }
                reject_secret_config_material_inner(field_value, Some(field_name))?;
            }
            Ok(())
        }
        serde_json::Value::Array(items) => {
            for item in items {
                reject_secret_config_material_inner(item, field_name)?;
            }
            Ok(())
        }
        serde_json::Value::String(raw) => {
            if let Some(detector) = detect_raw_secret_config_value(raw) {
                return Err(FcpError::configuration_leaked_secret(
                    field_name.unwrap_or("value"),
                    detector,
                ));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn detect_raw_secret_config_value(raw: &str) -> Option<&'static str> {
    let value = raw.trim();
    if is_bearer_secret_value(value) {
        return Some("raw_secret_config_value_bearer");
    }
    if is_jwt_secret_value(value) {
        return Some("raw_secret_config_value_jwt");
    }
    if is_openai_secret_value(value) {
        return Some("raw_secret_config_value_openai");
    }
    if is_slack_secret_value(value) {
        return Some("raw_secret_config_value_slack");
    }
    if is_github_secret_value(value) {
        return Some("raw_secret_config_value_github");
    }
    if is_aws_access_key_value(value) {
        return Some("raw_secret_config_value_aws");
    }
    None
}

fn is_bearer_secret_value(value: &str) -> bool {
    value
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("bearer "))
        && value[7..].trim().len() >= 8
}

fn is_jwt_secret_value(value: &str) -> bool {
    let mut parts = value.split('.');
    let Some(header) = parts.next() else {
        return false;
    };
    let Some(payload) = parts.next() else {
        return false;
    };
    let Some(signature) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    header.starts_with("eyJ")
        && payload.starts_with("eyJ")
        && signature.len() >= 8
        && [header, payload, signature]
            .into_iter()
            .all(is_base64url_token_segment)
}

fn is_base64url_token_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn is_openai_secret_value(value: &str) -> bool {
    value.starts_with("sk-") && value.len() > 3
}

fn is_slack_secret_value(value: &str) -> bool {
    SLACK_SECRET_PREFIXES
        .iter()
        .any(|prefix| value.starts_with(prefix) && value.len() > prefix.len())
}

fn is_github_secret_value(value: &str) -> bool {
    ["ghp_", "ghs_"].into_iter().any(|prefix| {
        value
            .strip_prefix(prefix)
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_alphanumeric()))
    })
}

fn is_aws_access_key_value(value: &str) -> bool {
    value.strip_prefix("AKIA").is_some_and(|rest| {
        rest.len() >= 4
            && rest
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    })
}

/// Canonical secret identifier (NORMATIVE).
///
/// A `SecretId` uniquely identifies a secret within a zone. It is used to
/// reference secrets without exposing their content.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretId(Uuid);

impl SecretId {
    /// Create a new random `SecretId`.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Create a `SecretId` from a UUID.
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// Get the inner UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Parse a `SecretId` from a string.
    ///
    /// # Errors
    /// Returns an error if the string is not a valid UUID.
    pub fn parse(s: &str) -> Result<Self, uuid::Error> {
        Ok(Self(Uuid::parse_str(s)?))
    }

    /// Create a test `SecretId` from bytes (for testing only).
    #[cfg(test)]
    #[must_use]
    pub const fn test_id(bytes: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }
}

impl Default for SecretId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SecretId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SecretId")
            .field(&self.0.to_string())
            .finish()
    }
}

impl fmt::Display for SecretId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Type of secret stored (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretType {
    /// API key or bearer token.
    ApiKey,
    /// OAuth access/refresh token.
    OAuthToken,
    /// Webhook signing secret.
    WebhookSecret,
    /// Database password.
    DatabasePassword,
    /// TLS client certificate and key.
    ClientCertificate,
    /// SSH private key.
    SshKey,
    /// Generic secret (opaque bytes).
    Generic,
    /// HMAC signing key.
    HmacKey,
    /// Encryption key material.
    EncryptionKey,
}

/// Secret storage format (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretFormat {
    /// Raw bytes, encrypted at rest.
    Raw,
    /// PEM-armored text bytes.
    Pem,
    /// DER-encoded binary bytes.
    Der,
    /// Base64-encoded text bytes.
    Base64,
    /// Threshold secret share (k-of-n).
    ThresholdShare {
        /// Share index (1-based).
        index: u8,
        /// Total shares required for reconstruction.
        threshold: u8,
        /// Total shares in the scheme.
        total: u8,
    },
    /// Wrapped key (encrypted with zone key).
    WrappedKey,
}

/// Cryptographic secret sharing scheme (NORMATIVE per V2 Spec §17.3).
///
/// Determines the algorithm used to split secrets into threshold shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretSharingScheme {
    /// Shamir's Secret Sharing over GF(2^8).
    ///
    /// Uses the same Galois field as AES, providing:
    /// - Information-theoretic security (k-1 shares reveal nothing)
    /// - Constant-time operations (timing-attack resistant)
    /// - Efficient byte-by-byte processing
    #[default]
    ShamirGf256,
}

/// Secret rotation policy (NORMATIVE per V2 Spec §17.3).
///
/// Controls automatic rotation of threshold secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretRotationPolicy {
    /// Rotate after this many seconds.
    pub rotate_after_secs: u64,

    /// Both old and new secrets are valid during this overlap window (seconds).
    ///
    /// This allows graceful migration without downtime.
    pub overlap_secs: u64,
}

impl SecretRotationPolicy {
    /// Create a new rotation policy.
    #[must_use]
    pub const fn new(rotate_after_secs: u64, overlap_secs: u64) -> Self {
        Self {
            rotate_after_secs,
            overlap_secs,
        }
    }

    /// Default policy: rotate every 90 days with 24-hour overlap.
    #[must_use]
    pub const fn default_policy() -> Self {
        Self {
            rotate_after_secs: 90 * 24 * 60 * 60, // 90 days
            overlap_secs: 24 * 60 * 60,           // 24 hours
        }
    }

    /// Check if rotation is due.
    #[must_use]
    pub const fn is_rotation_due(&self, secret_age_secs: u64) -> bool {
        secret_age_secs >= self.rotate_after_secs
    }

    /// Check if we're in the overlap window.
    #[must_use]
    pub const fn in_overlap_window(&self, since_rotation_secs: u64) -> bool {
        since_rotation_secs < self.overlap_secs
    }
}

impl Default for SecretRotationPolicy {
    fn default() -> Self {
        Self::default_policy()
    }
}

/// Threshold secret object (NORMATIVE per V2 Spec §17.3).
///
/// Stores a secret split into k-of-n shares using Shamir's Secret Sharing.
/// Each share is wrapped (encrypted) to a specific node's X25519 key using HPKE.
///
/// **Design philosophy:** "Secrets are never complete anywhere."
///
/// Unlike `SecretObject` which stores encrypted raw secrets, this type
/// distributes shares across nodes so no single node can reconstruct the
/// secret without cooperation from k-1 others.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdSecretObject {
    /// Standard object header.
    pub header: ObjectHeader,

    /// Unique identifier for this secret.
    pub secret_id: SecretId,

    /// Zone binding.
    pub zone_id: ZoneId,

    /// Threshold: number of shares needed to reconstruct (k).
    pub k: u8,

    /// Total number of shares distributed (n).
    pub n: u8,

    /// Secret sharing scheme used.
    pub scheme: SecretSharingScheme,

    /// Wrapped shares keyed by node identifier.
    ///
    /// Each share is HPKE-sealed to the node's X25519 public key.
    /// A node can only decrypt its own share.
    pub wrapped_shares: std::collections::HashMap<String, WrappedShare>,

    /// Rotation policy.
    pub rotation: SecretRotationPolicy,

    /// Secret type for application semantics.
    pub secret_type: SecretType,

    /// Human-readable label (MUST NOT contain secret material).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// When this secret was created (Unix timestamp).
    pub created_at: u64,

    /// When this secret expires (Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,

    /// Generation number (increments on rotation).
    pub generation: u32,
}

impl ThresholdSecretObject {
    /// Check if this secret has expired.
    #[must_use]
    pub fn is_expired(&self, now_unix: u64) -> bool {
        self.expires_at.is_some_and(|exp| now_unix >= exp)
    }

    /// Check if rotation is due.
    #[must_use]
    pub const fn needs_rotation(&self, now_unix: u64) -> bool {
        let age = now_unix.saturating_sub(self.created_at);
        self.rotation.is_rotation_due(age)
    }

    /// Get the zone ID.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.zone_id
    }
}

/// A wrapped (HPKE-sealed) share for a specific node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedShare {
    /// Share index (1-based, corresponds to Shamir x-coordinate).
    pub index: u8,

    /// HPKE-sealed share data.
    ///
    /// Format: HPKE ciphertext sealed to the node's X25519 public key.
    /// AAD binding includes: `zone_id`, `recipient_node_id`, `issued_at`.
    #[serde(with = "crate::util::hex_or_bytes_vec")]
    pub sealed_data: Vec<u8>,

    /// Key ID of the recipient's X25519 key.
    pub recipient_key_id: String,
}

/// Mesh-stored secret object (NORMATIVE).
///
/// Secrets are stored/represented as mesh objects. The actual secret material
/// is encrypted; accessing it requires a valid `SecretAccessToken`.
///
/// **IMPORTANT**: The `encrypted_payload` field contains the encrypted secret.
/// The plaintext secret bytes MUST NEVER be logged, serialized to JSON for
/// debugging, or stored anywhere except ephemeral memory during use.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretObject {
    /// Standard object header.
    pub header: ObjectHeader,

    /// Unique identifier for this secret.
    pub secret_id: SecretId,

    /// Type of secret (determines application semantics).
    pub secret_type: SecretType,

    /// Storage format (raw, PEM, DER, base64, threshold share, wrapped).
    pub format: SecretFormat,

    /// Human-readable label (MUST NOT contain secret material).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// Encrypted secret payload (zone-key encrypted).
    ///
    /// Format: `COSE_Encrypt0` with ChaCha20-Poly1305.
    /// AAD includes: `secret_id` || `zone_id` || `schema_hash`.
    #[serde(with = "crate::util::hex_or_bytes_vec")]
    pub encrypted_payload: Vec<u8>,

    /// Key derivation info for the encryption.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_derivation_info: Option<KeyDerivationInfo>,

    /// When this secret expires (Unix timestamp).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,

    /// Maximum times this secret can be accessed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_access_count: Option<u32>,

    /// Current access count (for rate limiting).
    #[serde(default)]
    pub access_count: u32,

    /// Object ID of the revocation entry if revoked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<ObjectId>,
}

impl SecretObject {
    /// Check if this secret has expired.
    #[must_use]
    pub fn is_expired(&self, now_unix: u64) -> bool {
        self.expires_at.is_some_and(|exp| now_unix >= exp)
    }

    /// Check if this secret has been revoked.
    #[must_use]
    pub const fn is_revoked(&self) -> bool {
        self.revoked_by.is_some()
    }

    /// Check if access count limit has been reached.
    #[must_use]
    pub fn is_access_exhausted(&self) -> bool {
        self.max_access_count
            .is_some_and(|max| self.access_count >= max)
    }

    /// Check if this secret is currently usable.
    #[must_use]
    pub fn is_usable(&self, now_unix: u64) -> bool {
        !self.is_expired(now_unix) && !self.is_revoked() && !self.is_access_exhausted()
    }

    /// Get the zone ID from the header.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.header.zone_id
    }
}

/// Key derivation information for secret encryption (NORMATIVE when present).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationInfo {
    /// Algorithm used (e.g., "HKDF-SHA256").
    pub algorithm: String,

    /// Salt (if applicable).
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        with = "crate::util::hex_or_bytes_vec"
    )]
    pub salt: Vec<u8>,

    /// Info/context string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info: Option<String>,
}

/// Short-lived authorization to access a secret (NORMATIVE).
///
/// A `SecretAccessToken` grants temporary permission to decrypt and use a secret.
/// Every use of this token MUST emit an audit event.
///
/// **Security properties:**
/// - Short-lived (typically < 5 minutes).
/// - Single-use or bounded-use.
/// - Bound to a specific principal and purpose.
/// - Audited on creation and use.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretAccessToken {
    /// Unique token identifier (for audit correlation).
    #[zeroize(skip)]
    pub token_id: Uuid,

    /// Secret this token grants access to.
    #[zeroize(skip)]
    pub secret_id: SecretId,

    /// Zone where this token is valid.
    #[zeroize(skip)]
    pub zone_id: ZoneId,

    /// Principal who requested access.
    #[zeroize(skip)]
    pub requester: PrincipalId,

    /// Purpose/reason for access (for audit).
    #[zeroize(skip)]
    pub purpose: String,

    /// When this token was issued (Unix timestamp).
    #[zeroize(skip)]
    pub issued_at: u64,

    /// When this token expires (Unix timestamp).
    #[zeroize(skip)]
    pub expires_at: u64,

    /// Maximum number of times this token can be used.
    #[zeroize(skip)]
    pub max_uses: u32,

    /// Current use count.
    #[zeroize(skip)]
    pub use_count: u32,

    /// Cryptographic authorization (signed by zone authority).
    /// Format: `COSE_Sign1` over (`token_id` || `secret_id` || `zone_id` || requester || `expires_at`).
    authorization: Vec<u8>,
}

impl SecretAccessToken {
    /// Create a new `SecretAccessToken`.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        secret_id: SecretId,
        zone_id: ZoneId,
        requester: PrincipalId,
        purpose: String,
        issued_at: u64,
        expires_at: u64,
        max_uses: u32,
        authorization: Vec<u8>,
    ) -> Self {
        Self {
            token_id: Uuid::new_v4(),
            secret_id,
            zone_id,
            requester,
            purpose,
            issued_at,
            expires_at,
            max_uses,
            use_count: 0,
            authorization,
        }
    }

    /// Check if this token has expired.
    #[must_use]
    pub const fn is_expired(&self, now_unix: u64) -> bool {
        now_unix >= self.expires_at
    }

    /// Check if this token has been exhausted.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.use_count >= self.max_uses
    }

    /// Check if this token is currently valid (not expired and not exhausted).
    #[must_use]
    pub const fn is_valid(&self, now_unix: u64) -> bool {
        !self.is_expired(now_unix) && !self.is_exhausted()
    }

    /// Record a use of this token.
    ///
    /// Returns `true` if the use was allowed, `false` if exhausted.
    pub const fn record_use(&mut self) -> bool {
        if self.is_exhausted() {
            return false;
        }
        self.use_count += 1;
        true
    }

    /// Get the authorization bytes (for verification).
    #[must_use]
    pub fn authorization(&self) -> &[u8] {
        &self.authorization
    }

    /// Remaining uses for this token.
    #[must_use]
    pub const fn remaining_uses(&self) -> u32 {
        self.max_uses.saturating_sub(self.use_count)
    }
}

impl fmt::Debug for SecretAccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // MUST NOT expose authorization bytes in debug output
        f.debug_struct("SecretAccessToken")
            .field("token_id", &self.token_id)
            .field("secret_id", &self.secret_id)
            .field("zone_id", &self.zone_id)
            .field("requester", &self.requester)
            .field("purpose", &self.purpose)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("max_uses", &self.max_uses)
            .field("use_count", &self.use_count)
            .field("authorization", &"[redacted]")
            .finish()
    }
}

/// Decrypted secret material (NORMATIVE).
///
/// This type holds the actual secret bytes after decryption. It implements
/// `Zeroize` and `ZeroizeOnDrop` to ensure the secret is securely erased from
/// memory when dropped.
///
/// **CRITICAL**: This type MUST NOT implement `Serialize`, `Clone`, or any other
/// trait that would allow the secret to persist beyond its intended use.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretMaterial {
    /// The decrypted secret bytes.
    bytes: Vec<u8>,
}

impl SecretMaterial {
    /// Create new secret material from bytes.
    ///
    /// The bytes are moved into this type and will be zeroized on drop.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Access the secret bytes.
    ///
    /// **WARNING**: Do not log, serialize, or persist these bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the length of the secret.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // MUST NOT expose secret bytes in debug output
        f.debug_struct("SecretMaterial")
            .field("len", &self.bytes.len())
            .field("bytes", &"[redacted]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Provenance;
    use fcp_cbor::SchemaId;
    use semver::Version;
    use serde_json::json;

    fn test_header() -> ObjectHeader {
        ObjectHeader {
            encryption_kind: Default::default(),
            schema: SchemaId::new("fcp.core", "SecretObject", Version::new(1, 0, 0)),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        }
    }

    fn test_principal() -> PrincipalId {
        PrincipalId::new("user:alice").expect("valid principal")
    }

    #[test]
    fn secret_config_rejects_blocked_field_names() {
        for &field_name in RAW_SECRET_CONFIG_FIELDS {
            let mut nested = serde_json::Map::new();
            nested.insert(field_name.to_string(), json!("redacted"));
            let config = json!({
                "credential_id": Uuid::new_v4().to_string(),
                "nested": nested
            });

            let error = reject_secret_config_material(&config)
                .expect_err("blocked field name must be rejected");
            match error {
                FcpError::ConfigurationLeakedSecret {
                    field_name_hash,
                    detector,
                } => {
                    assert_eq!(detector, "raw_secret_config_field");
                    assert_eq!(field_name_hash.len(), 64);
                    assert!(!field_name_hash.contains(field_name));
                }
                other => panic!("Expected ConfigurationLeakedSecret, got {other:?}"),
            }
        }
    }

    #[test]
    fn secret_config_rejects_token_shaped_values() {
        let cases = [
            ("Bearer abcdefgh123", "raw_secret_config_value_bearer"),
            (
                "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ.abcdefgh",
                "raw_secret_config_value_jwt",
            ),
            ("sk-live-test", "raw_secret_config_value_openai"),
            ("xoxb-1234567890abcdef", "raw_secret_config_value_slack"),
            ("ghp_ABCdef123456", "raw_secret_config_value_github"),
            ("AKIAIOSFODNN7EXAMPLE", "raw_secret_config_value_aws"),
        ];

        for (value, expected_detector) in cases {
            let config = json!({
                "credential_id": Uuid::new_v4().to_string(),
                "metadata": {
                    "sample": value
                }
            });

            let error = reject_secret_config_material(&config)
                .expect_err("token-shaped value must be rejected");
            match error {
                FcpError::ConfigurationLeakedSecret { detector, .. } => {
                    assert_eq!(detector, expected_detector);
                }
                other => panic!("Expected ConfigurationLeakedSecret, got {other:?}"),
            }
        }
    }

    #[test]
    fn secret_config_allows_credential_references_and_public_values() {
        let config = json!({
            "credential_id": Uuid::new_v4().to_string(),
            "base_url": "https://api.github.com",
            "required_scopes": ["read:user"],
            "metadata": {
                "label": "operator-owned credential reference"
            }
        });

        reject_secret_config_material(&config).expect("safe config should be accepted");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecretId Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_id_new_is_unique() {
        let id1 = SecretId::new();
        let id2 = SecretId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn secret_id_parse_roundtrip() {
        let id = SecretId::new();
        let s = id.to_string();
        let parsed = SecretId::parse(&s).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn secret_id_display_is_uuid() {
        let uuid = Uuid::from_bytes([0xAB; 16]);
        let id = SecretId::from_uuid(uuid);
        assert_eq!(id.to_string(), uuid.to_string());
    }

    #[test]
    fn secret_id_debug_redacts_nothing() {
        let id = SecretId::test_id([0x12; 16]);
        let debug = format!("{id:?}");
        assert!(debug.contains("SecretId"));
    }

    #[test]
    fn secret_id_serialization_roundtrip() {
        let id = SecretId::new();
        let json = serde_json::to_string(&id).unwrap();
        let deserialized: SecretId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, deserialized);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecretType Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_type_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&SecretType::ApiKey).unwrap(),
            "\"api_key\""
        );
        assert_eq!(
            serde_json::to_string(&SecretType::OAuthToken).unwrap(),
            "\"o_auth_token\""
        );
        assert_eq!(
            serde_json::to_string(&SecretType::WebhookSecret).unwrap(),
            "\"webhook_secret\""
        );
        assert_eq!(
            serde_json::to_string(&SecretType::DatabasePassword).unwrap(),
            "\"database_password\""
        );
        assert_eq!(
            serde_json::to_string(&SecretType::ClientCertificate).unwrap(),
            "\"client_certificate\""
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecretObject Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_object_is_expired() {
        let secret = SecretObject {
            header: test_header(),
            secret_id: SecretId::new(),
            secret_type: SecretType::ApiKey,
            format: SecretFormat::Raw,
            label: Some("test-secret".into()),
            encrypted_payload: vec![0u8; 32],
            key_derivation_info: None,
            expires_at: Some(1_700_000_100),
            max_access_count: None,
            access_count: 0,
            revoked_by: None,
        };

        assert!(!secret.is_expired(1_700_000_000));
        assert!(!secret.is_expired(1_700_000_099));
        assert!(secret.is_expired(1_700_000_100));
        assert!(secret.is_expired(1_700_000_200));
    }

    #[test]
    fn secret_object_no_expiry_never_expires() {
        let secret = SecretObject {
            header: test_header(),
            secret_id: SecretId::new(),
            secret_type: SecretType::ApiKey,
            format: SecretFormat::Raw,
            label: None,
            encrypted_payload: vec![0u8; 32],
            key_derivation_info: None,
            expires_at: None,
            max_access_count: None,
            access_count: 0,
            revoked_by: None,
        };

        assert!(!secret.is_expired(u64::MAX));
    }

    #[test]
    fn secret_object_is_revoked() {
        let mut secret = SecretObject {
            header: test_header(),
            secret_id: SecretId::new(),
            secret_type: SecretType::ApiKey,
            format: SecretFormat::Raw,
            label: None,
            encrypted_payload: vec![0u8; 32],
            key_derivation_info: None,
            expires_at: None,
            max_access_count: None,
            access_count: 0,
            revoked_by: None,
        };

        assert!(!secret.is_revoked());

        secret.revoked_by = Some(ObjectId::from_bytes([0xFF; 32]));
        assert!(secret.is_revoked());
    }

    #[test]
    fn secret_object_access_exhausted() {
        let mut secret = SecretObject {
            header: test_header(),
            secret_id: SecretId::new(),
            secret_type: SecretType::ApiKey,
            format: SecretFormat::Raw,
            label: None,
            encrypted_payload: vec![0u8; 32],
            key_derivation_info: None,
            expires_at: None,
            max_access_count: Some(5),
            access_count: 0,
            revoked_by: None,
        };

        assert!(!secret.is_access_exhausted());
        secret.access_count = 4;
        assert!(!secret.is_access_exhausted());
        secret.access_count = 5;
        assert!(secret.is_access_exhausted());
        secret.access_count = 6;
        assert!(secret.is_access_exhausted());
    }

    #[test]
    fn secret_object_is_usable() {
        let secret = SecretObject {
            header: test_header(),
            secret_id: SecretId::new(),
            secret_type: SecretType::ApiKey,
            format: SecretFormat::Raw,
            label: None,
            encrypted_payload: vec![0u8; 32],
            key_derivation_info: None,
            expires_at: Some(1_700_000_100),
            max_access_count: Some(5),
            access_count: 3,
            revoked_by: None,
        };

        assert!(secret.is_usable(1_700_000_000));
    }

    #[test]
    fn secret_object_not_usable_when_expired() {
        let secret = SecretObject {
            header: test_header(),
            secret_id: SecretId::new(),
            secret_type: SecretType::ApiKey,
            format: SecretFormat::Raw,
            label: None,
            encrypted_payload: vec![0u8; 32],
            key_derivation_info: None,
            expires_at: Some(1_700_000_100),
            max_access_count: None,
            access_count: 0,
            revoked_by: None,
        };

        assert!(!secret.is_usable(1_700_000_200));
    }

    #[test]
    fn secret_object_serialization_roundtrip() {
        let secret = SecretObject {
            header: test_header(),
            secret_id: SecretId::new(),
            secret_type: SecretType::DatabasePassword,
            format: SecretFormat::WrappedKey,
            label: Some("db-prod".into()),
            encrypted_payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            key_derivation_info: Some(KeyDerivationInfo {
                algorithm: "HKDF-SHA256".into(),
                salt: vec![0x01, 0x02, 0x03],
                info: Some("db-password-v1".into()),
            }),
            expires_at: Some(1_800_000_000),
            max_access_count: Some(100),
            access_count: 5,
            revoked_by: None,
        };

        let json = serde_json::to_string(&secret).unwrap();
        let decoded: SecretObject = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.secret_id, secret.secret_id);
        assert_eq!(decoded.secret_type, SecretType::DatabasePassword);
        assert_eq!(decoded.label.as_deref(), Some("db-prod"));
        assert_eq!(decoded.encrypted_payload, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecretFormat Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_format_threshold_share() {
        let format = SecretFormat::ThresholdShare {
            index: 1,
            threshold: 3,
            total: 5,
        };

        let json = serde_json::to_string(&format).unwrap();
        assert!(json.contains("threshold_share"));
        assert!(json.contains("\"index\":1"));
        assert!(json.contains("\"threshold\":3"));
        assert!(json.contains("\"total\":5"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecretAccessToken Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_access_token_validity() {
        let token = SecretAccessToken::new(
            SecretId::new(),
            ZoneId::work(),
            test_principal(),
            "connector-egress".into(),
            1_700_000_000,
            1_700_000_300, // 5 minute validity
            3,
            vec![0u8; 64],
        );

        assert!(token.is_valid(1_700_000_000));
        assert!(token.is_valid(1_700_000_299));
        assert!(!token.is_valid(1_700_000_300)); // expired
        assert!(!token.is_valid(1_700_000_500)); // expired
    }

    #[test]
    fn secret_access_token_exhaustion() {
        let mut token = SecretAccessToken::new(
            SecretId::new(),
            ZoneId::work(),
            test_principal(),
            "test".into(),
            1_700_000_000,
            1_700_000_300,
            2,
            vec![0u8; 64],
        );

        assert!(!token.is_exhausted());
        assert_eq!(token.remaining_uses(), 2);

        assert!(token.record_use());
        assert!(!token.is_exhausted());
        assert_eq!(token.remaining_uses(), 1);

        assert!(token.record_use());
        assert!(token.is_exhausted());
        assert_eq!(token.remaining_uses(), 0);

        assert!(!token.record_use()); // Should fail - exhausted
    }

    #[test]
    fn secret_access_token_debug_redacts_authorization() {
        let token = SecretAccessToken::new(
            SecretId::new(),
            ZoneId::work(),
            test_principal(),
            "test".into(),
            1_700_000_000,
            1_700_000_300,
            1,
            vec![0xDE, 0xAD, 0xBE, 0xEF],
        );

        let debug = format!("{token:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("dead"));
        assert!(!debug.contains("beef"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecretMaterial Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_material_access() {
        let material = SecretMaterial::new(vec![1, 2, 3, 4]);
        assert_eq!(material.as_bytes(), &[1, 2, 3, 4]);
        assert_eq!(material.len(), 4);
        assert!(!material.is_empty());
    }

    #[test]
    fn secret_material_empty() {
        let material = SecretMaterial::new(vec![]);
        assert!(material.is_empty());
        assert_eq!(material.len(), 0);
    }

    #[test]
    fn secret_material_debug_redacts() {
        let material = SecretMaterial::new(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let debug = format!("{material:?}");
        assert!(debug.contains("[redacted]"));
        assert!(debug.contains("len"));
        assert!(!debug.contains("dead"));
        assert!(!debug.contains("beef"));
    }

    #[test]
    fn secret_material_zeroize_on_drop() {
        // This test verifies the type has ZeroizeOnDrop derive
        // We can't easily verify the actual zeroization without unsafe code,
        // but we can verify the type compiles with the derive
        let material = SecretMaterial::new(vec![0xFF; 100]);
        assert_eq!(material.len(), 100);
        drop(material);
        // If we got here without panic, the drop succeeded
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecretSharingScheme Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_sharing_scheme_default_is_shamir() {
        assert_eq!(
            SecretSharingScheme::default(),
            SecretSharingScheme::ShamirGf256
        );
    }

    #[test]
    fn secret_sharing_scheme_serialization() {
        let scheme = SecretSharingScheme::ShamirGf256;
        let json = serde_json::to_string(&scheme).unwrap();
        assert_eq!(json, "\"shamir_gf256\"");

        let deserialized: SecretSharingScheme = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, SecretSharingScheme::ShamirGf256);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecretRotationPolicy Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn rotation_policy_default() {
        let policy = SecretRotationPolicy::default();
        assert_eq!(policy.rotate_after_secs, 90 * 24 * 60 * 60); // 90 days
        assert_eq!(policy.overlap_secs, 24 * 60 * 60); // 24 hours
    }

    #[test]
    fn rotation_policy_is_rotation_due() {
        let policy = SecretRotationPolicy::new(3600, 300); // 1 hour rotation, 5 min overlap

        assert!(!policy.is_rotation_due(0));
        assert!(!policy.is_rotation_due(3599));
        assert!(policy.is_rotation_due(3600));
        assert!(policy.is_rotation_due(7200));
    }

    #[test]
    fn rotation_policy_in_overlap_window() {
        let policy = SecretRotationPolicy::new(3600, 300); // 1 hour rotation, 5 min overlap

        assert!(policy.in_overlap_window(0));
        assert!(policy.in_overlap_window(299));
        assert!(!policy.in_overlap_window(300));
        assert!(!policy.in_overlap_window(600));
    }

    #[test]
    fn rotation_policy_serialization_roundtrip() {
        let policy = SecretRotationPolicy::new(86400, 3600);
        let json = serde_json::to_string(&policy).unwrap();
        let deserialized: SecretRotationPolicy = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.rotate_after_secs, 86400);
        assert_eq!(deserialized.overlap_secs, 3600);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ThresholdSecretObject Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn threshold_secret_is_expired() {
        let secret = ThresholdSecretObject {
            header: test_header(),
            secret_id: SecretId::new(),
            zone_id: ZoneId::work(),
            k: 3,
            n: 5,
            scheme: SecretSharingScheme::ShamirGf256,
            wrapped_shares: std::collections::HashMap::new(),
            rotation: SecretRotationPolicy::default(),
            secret_type: SecretType::EncryptionKey,
            label: Some("test-threshold".into()),
            created_at: 1_700_000_000,
            expires_at: Some(1_700_001_000),
            generation: 1,
        };

        assert!(!secret.is_expired(1_700_000_500));
        assert!(!secret.is_expired(1_700_000_999));
        assert!(secret.is_expired(1_700_001_000));
        assert!(secret.is_expired(1_700_002_000));
    }

    #[test]
    fn threshold_secret_no_expiry() {
        let secret = ThresholdSecretObject {
            header: test_header(),
            secret_id: SecretId::new(),
            zone_id: ZoneId::work(),
            k: 2,
            n: 3,
            scheme: SecretSharingScheme::ShamirGf256,
            wrapped_shares: std::collections::HashMap::new(),
            rotation: SecretRotationPolicy::default(),
            secret_type: SecretType::ApiKey,
            label: None,
            created_at: 1_700_000_000,
            expires_at: None,
            generation: 0,
        };

        assert!(!secret.is_expired(u64::MAX));
    }

    #[test]
    fn threshold_secret_needs_rotation() {
        let policy = SecretRotationPolicy::new(3600, 300); // 1 hour rotation
        let secret = ThresholdSecretObject {
            header: test_header(),
            secret_id: SecretId::new(),
            zone_id: ZoneId::work(),
            k: 3,
            n: 5,
            scheme: SecretSharingScheme::ShamirGf256,
            wrapped_shares: std::collections::HashMap::new(),
            rotation: policy,
            secret_type: SecretType::EncryptionKey,
            label: None,
            created_at: 1_700_000_000,
            expires_at: None,
            generation: 1,
        };

        // At creation time
        assert!(!secret.needs_rotation(1_700_000_000));
        // Before rotation
        assert!(!secret.needs_rotation(1_700_003_599));
        // At rotation time
        assert!(secret.needs_rotation(1_700_003_600));
        // After rotation time
        assert!(secret.needs_rotation(1_700_007_200));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // WrappedShare Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn wrapped_share_serialization_roundtrip() {
        let share = WrappedShare {
            index: 1,
            sealed_data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            recipient_key_id: "node-123-x25519".into(),
        };

        let json = serde_json::to_string(&share).unwrap();
        let deserialized: WrappedShare = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.index, 1);
        assert_eq!(deserialized.sealed_data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(deserialized.recipient_key_id, "node-123-x25519");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecretId – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_id_hash_consistency() {
        use std::collections::HashSet;
        let id = SecretId::test_id([0x42; 16]);
        let mut set = HashSet::new();
        set.insert(id);
        set.insert(id);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn secret_id_ordering() {
        let a = SecretId::test_id([0x00; 16]);
        let b = SecretId::test_id([0xFF; 16]);
        assert!(a < b || b < a); // Deterministic ordering exists
        assert_eq!(a.cmp(&a), std::cmp::Ordering::Equal);
    }

    #[test]
    fn secret_id_clone() {
        let id = SecretId::new();
        #[allow(clippy::clone_on_copy)]
        let cloned = id.clone();
        assert_eq!(id, cloned);
    }

    #[test]
    fn secret_id_copy() {
        let a = SecretId::test_id([0x11; 16]);
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn secret_id_default_is_unique() {
        let a = SecretId::default();
        let b = SecretId::default();
        assert_ne!(a, b);
    }

    #[test]
    fn secret_id_as_uuid() {
        let uuid = Uuid::from_bytes([0xAA; 16]);
        let id = SecretId::from_uuid(uuid);
        assert_eq!(*id.as_uuid(), uuid);
    }

    #[test]
    fn secret_id_parse_invalid() {
        let result = SecretId::parse("not-a-uuid");
        assert!(result.is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecretType – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_type_serializes_remaining_variants() {
        assert_eq!(
            serde_json::to_string(&SecretType::SshKey).unwrap(),
            "\"ssh_key\""
        );
        assert_eq!(
            serde_json::to_string(&SecretType::Generic).unwrap(),
            "\"generic\""
        );
        assert_eq!(
            serde_json::to_string(&SecretType::HmacKey).unwrap(),
            "\"hmac_key\""
        );
        assert_eq!(
            serde_json::to_string(&SecretType::EncryptionKey).unwrap(),
            "\"encryption_key\""
        );
    }

    #[test]
    fn secret_type_serde_roundtrip_all_variants() {
        let variants = [
            SecretType::ApiKey,
            SecretType::OAuthToken,
            SecretType::WebhookSecret,
            SecretType::DatabasePassword,
            SecretType::ClientCertificate,
            SecretType::SshKey,
            SecretType::Generic,
            SecretType::HmacKey,
            SecretType::EncryptionKey,
        ];
        for variant in &variants {
            let json = serde_json::to_string(variant).unwrap();
            let decoded: SecretType = serde_json::from_str(&json).unwrap();
            assert_eq!(*variant, decoded, "roundtrip failed for {variant:?}");
        }
    }

    #[test]
    fn secret_type_copy() {
        let a = SecretType::SshKey;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn secret_type_equality() {
        assert_eq!(SecretType::ApiKey, SecretType::ApiKey);
        assert_ne!(SecretType::ApiKey, SecretType::SshKey);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecretFormat – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_format_raw_serde() {
        let format = SecretFormat::Raw;
        let json = serde_json::to_string(&format).unwrap();
        assert_eq!(json, "\"raw\"");
        let decoded: SecretFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, SecretFormat::Raw);
    }

    #[test]
    fn secret_format_wrapped_key_serde() {
        let format = SecretFormat::WrappedKey;
        let json = serde_json::to_string(&format).unwrap();
        assert_eq!(json, "\"wrapped_key\"");
        let decoded: SecretFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, SecretFormat::WrappedKey);
    }

    #[test]
    fn secret_format_threshold_share_serde_roundtrip() {
        let format = SecretFormat::ThresholdShare {
            index: 2,
            threshold: 3,
            total: 5,
        };
        let json = serde_json::to_string(&format).unwrap();
        let decoded: SecretFormat = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, format);
    }

    #[test]
    fn secret_format_copy() {
        let a = SecretFormat::Raw;
        let b = a;
        assert_eq!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecretObject – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    fn test_secret_object() -> SecretObject {
        SecretObject {
            header: test_header(),
            secret_id: SecretId::test_id([0x42; 16]),
            secret_type: SecretType::ApiKey,
            format: SecretFormat::Raw,
            label: Some("test-secret".into()),
            encrypted_payload: vec![0xDE, 0xAD],
            key_derivation_info: None,
            expires_at: Some(1_700_000_100),
            max_access_count: Some(10),
            access_count: 0,
            revoked_by: None,
        }
    }

    #[test]
    fn secret_object_zone_id() {
        let secret = test_secret_object();
        assert_eq!(*secret.zone_id(), ZoneId::work());
    }

    #[test]
    fn secret_object_not_usable_when_revoked() {
        let mut secret = test_secret_object();
        secret.revoked_by = Some(ObjectId::from_bytes([0xFF; 32]));
        assert!(!secret.is_usable(1_700_000_000));
    }

    #[test]
    fn secret_object_not_usable_when_exhausted() {
        let mut secret = test_secret_object();
        secret.access_count = 10;
        assert!(!secret.is_usable(1_700_000_000));
    }

    #[test]
    fn secret_object_clone() {
        let secret = test_secret_object();
        let cloned = secret.clone();
        assert_eq!(cloned.secret_id, secret.secret_id);
        assert_eq!(cloned.secret_type, secret.secret_type);
        assert_eq!(cloned.format, secret.format);
        assert_eq!(cloned.label, secret.label);
        assert_eq!(cloned.encrypted_payload, secret.encrypted_payload);
    }

    #[test]
    fn secret_object_serde_omits_none_fields() {
        let mut secret = test_secret_object();
        secret.label = None;
        secret.key_derivation_info = None;
        secret.expires_at = None;
        secret.max_access_count = None;
        secret.revoked_by = None;
        let json = serde_json::to_string(&secret).unwrap();
        assert!(!json.contains("label"));
        assert!(!json.contains("key_derivation_info"));
        assert!(!json.contains("expires_at"));
        assert!(!json.contains("max_access_count"));
        assert!(!json.contains("revoked_by"));
    }

    #[test]
    fn secret_object_no_max_access_never_exhausted() {
        let mut secret = test_secret_object();
        secret.max_access_count = None;
        secret.access_count = u32::MAX;
        assert!(!secret.is_access_exhausted());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecretAccessToken – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    fn test_token() -> SecretAccessToken {
        SecretAccessToken::new(
            SecretId::test_id([0x42; 16]),
            ZoneId::work(),
            test_principal(),
            "test-purpose".into(),
            1_700_000_000,
            1_700_000_300,
            5,
            vec![0xCA, 0xFE],
        )
    }

    #[test]
    fn secret_access_token_authorization_accessor() {
        let token = test_token();
        assert_eq!(token.authorization(), &[0xCA, 0xFE]);
    }

    #[test]
    fn secret_access_token_remaining_uses_saturating() {
        let mut token = test_token();
        token.use_count = 100; // Way over max_uses of 5
        assert_eq!(token.remaining_uses(), 0);
    }

    #[test]
    fn secret_access_token_is_valid_combines_checks() {
        let mut token = test_token();
        // Valid: not expired, not exhausted
        assert!(token.is_valid(1_700_000_100));
        // Expired
        assert!(!token.is_valid(1_700_000_300));
        // Exhausted but not expired
        token.use_count = 5;
        assert!(!token.is_valid(1_700_000_100));
    }

    #[test]
    fn secret_access_token_serde_roundtrip() {
        let token = test_token();
        let json = serde_json::to_string(&token).unwrap();
        let decoded: SecretAccessToken = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.secret_id, token.secret_id);
        assert_eq!(decoded.zone_id, token.zone_id);
        assert_eq!(decoded.purpose, token.purpose);
        assert_eq!(decoded.issued_at, token.issued_at);
        assert_eq!(decoded.expires_at, token.expires_at);
        assert_eq!(decoded.max_uses, token.max_uses);
        assert_eq!(decoded.use_count, token.use_count);
    }

    #[test]
    fn secret_access_token_record_use_until_exhaustion() {
        let mut token = SecretAccessToken::new(
            SecretId::new(),
            ZoneId::work(),
            test_principal(),
            "single-use".into(),
            1_700_000_000,
            1_700_000_300,
            1,
            vec![],
        );
        assert_eq!(token.remaining_uses(), 1);
        assert!(token.record_use());
        assert_eq!(token.remaining_uses(), 0);
        assert!(token.is_exhausted());
        assert!(!token.record_use());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // KeyDerivationInfo – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn key_derivation_info_serde_roundtrip() {
        let kdi = KeyDerivationInfo {
            algorithm: "HKDF-SHA256".into(),
            salt: vec![0x01, 0x02, 0x03],
            info: Some("context-string".into()),
        };
        let json = serde_json::to_string(&kdi).unwrap();
        let decoded: KeyDerivationInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.algorithm, "HKDF-SHA256");
        assert_eq!(decoded.salt, vec![0x01, 0x02, 0x03]);
        assert_eq!(decoded.info.as_deref(), Some("context-string"));
    }

    #[test]
    fn key_derivation_info_serde_omits_empty_fields() {
        let kdi = KeyDerivationInfo {
            algorithm: "HKDF-SHA256".into(),
            salt: vec![],
            info: None,
        };
        let json = serde_json::to_string(&kdi).unwrap();
        assert!(!json.contains("salt"));
        assert!(!json.contains("info"));
    }

    #[test]
    fn key_derivation_info_clone() {
        let kdi = KeyDerivationInfo {
            algorithm: "HKDF-SHA256".into(),
            salt: vec![0xFF],
            info: Some("test".into()),
        };
        let cloned = kdi.clone();
        assert_eq!(cloned.algorithm, kdi.algorithm);
        assert_eq!(cloned.salt, kdi.salt);
        assert_eq!(cloned.info, kdi.info);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecretSharingScheme – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_sharing_scheme_copy() {
        let a = SecretSharingScheme::ShamirGf256;
        let b = a;
        assert_eq!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecretRotationPolicy – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn rotation_policy_default_matches_default_policy() {
        let from_default = SecretRotationPolicy::default();
        let from_fn = SecretRotationPolicy::default_policy();
        assert_eq!(from_default.rotate_after_secs, from_fn.rotate_after_secs);
        assert_eq!(from_default.overlap_secs, from_fn.overlap_secs);
    }

    #[test]
    fn rotation_policy_clone() {
        let policy = SecretRotationPolicy::new(86400, 3600);
        let cloned = policy.clone();
        assert_eq!(cloned.rotate_after_secs, policy.rotate_after_secs);
        assert_eq!(cloned.overlap_secs, policy.overlap_secs);
    }

    #[test]
    fn rotation_policy_equality() {
        let a = SecretRotationPolicy::new(100, 10);
        let b = SecretRotationPolicy::new(100, 10);
        let c = SecretRotationPolicy::new(200, 10);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ThresholdSecretObject – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    fn test_threshold_secret() -> ThresholdSecretObject {
        ThresholdSecretObject {
            header: test_header(),
            secret_id: SecretId::test_id([0x55; 16]),
            zone_id: ZoneId::work(),
            k: 3,
            n: 5,
            scheme: SecretSharingScheme::ShamirGf256,
            wrapped_shares: std::collections::HashMap::new(),
            rotation: SecretRotationPolicy::new(3600, 300),
            secret_type: SecretType::EncryptionKey,
            label: Some("threshold-test".into()),
            created_at: 1_700_000_000,
            expires_at: Some(1_700_100_000),
            generation: 1,
        }
    }

    #[test]
    fn threshold_secret_zone_id() {
        let secret = test_threshold_secret();
        assert_eq!(*secret.zone_id(), ZoneId::work());
    }

    #[test]
    fn threshold_secret_clone() {
        let secret = test_threshold_secret();
        let cloned = secret.clone();
        assert_eq!(cloned.secret_id, secret.secret_id);
        assert_eq!(cloned.k, secret.k);
        assert_eq!(cloned.n, secret.n);
        assert_eq!(cloned.generation, secret.generation);
        assert_eq!(cloned.label, secret.label);
    }

    #[test]
    fn threshold_secret_serde_roundtrip() {
        let secret = test_threshold_secret();
        let json = serde_json::to_string(&secret).unwrap();
        let decoded: ThresholdSecretObject = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.secret_id, secret.secret_id);
        assert_eq!(decoded.k, 3);
        assert_eq!(decoded.n, 5);
        assert_eq!(decoded.generation, 1);
        assert_eq!(decoded.created_at, 1_700_000_000);
    }

    #[test]
    fn threshold_secret_needs_rotation_at_boundary() {
        let secret = test_threshold_secret();
        // rotation.rotate_after_secs = 3600
        // created_at = 1_700_000_000
        // rotation due at created_at + 3600 = 1_700_003_600
        assert!(!secret.needs_rotation(1_700_003_599));
        assert!(secret.needs_rotation(1_700_003_600));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SecretMaterial – Additional Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_material_large() {
        let material = SecretMaterial::new(vec![0xFF; 1024]);
        assert_eq!(material.len(), 1024);
        assert!(!material.is_empty());
        assert_eq!(material.as_bytes()[0], 0xFF);
        assert_eq!(material.as_bytes()[1023], 0xFF);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // New: SecretId edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_id_parse_empty_string() {
        let result = SecretId::parse("");
        assert!(result.is_err());
    }

    #[test]
    fn secret_id_parse_too_short() {
        let result = SecretId::parse("12345678");
        assert!(result.is_err());
    }

    #[test]
    fn secret_id_parse_valid_hyphenated() {
        let result = SecretId::parse("550e8400-e29b-41d4-a716-446655440000");
        assert!(result.is_ok());
    }

    #[test]
    fn secret_id_test_id_deterministic() {
        let a = SecretId::test_id([0xAB; 16]);
        let b = SecretId::test_id([0xAB; 16]);
        assert_eq!(a, b);
    }

    #[test]
    fn secret_id_test_id_different_bytes_differ() {
        let a = SecretId::test_id([0x00; 16]);
        let b = SecretId::test_id([0x01; 16]);
        assert_ne!(a, b);
    }

    #[test]
    fn secret_id_from_uuid_as_uuid_roundtrip() {
        let uuid = Uuid::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ]);
        let id = SecretId::from_uuid(uuid);
        let recovered = *id.as_uuid();
        assert_eq!(recovered, uuid);
    }

    #[test]
    fn secret_id_display_matches_uuid_display() {
        let bytes = [0x11; 16];
        let uuid = Uuid::from_bytes(bytes);
        let id = SecretId::test_id(bytes);
        assert_eq!(format!("{id}"), format!("{uuid}"));
    }

    #[test]
    fn secret_id_debug_contains_uuid_string() {
        let bytes = [0x42; 16];
        let uuid = Uuid::from_bytes(bytes);
        let id = SecretId::test_id(bytes);
        let debug = format!("{id:?}");
        assert!(debug.contains(&uuid.to_string()));
    }

    #[test]
    fn secret_id_serde_json_is_string() {
        let id = SecretId::test_id([0x77; 16]);
        let json = serde_json::to_string(&id).unwrap();
        // serde(transparent) means it's just a UUID string
        assert!(json.starts_with('"'));
        assert!(json.ends_with('"'));
    }

    #[test]
    fn secret_id_ordering_deterministic() {
        let a = SecretId::test_id([0x00; 16]);
        let b = SecretId::test_id([0xFF; 16]);
        // Compare in both directions to confirm consistent ordering
        assert!(a < b);
        assert!(b > a);
        assert_eq!(a.partial_cmp(&b), Some(std::cmp::Ordering::Less));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // New: SecretType edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_type_debug_all_variants() {
        let variants = [
            (SecretType::ApiKey, "ApiKey"),
            (SecretType::OAuthToken, "OAuthToken"),
            (SecretType::WebhookSecret, "WebhookSecret"),
            (SecretType::DatabasePassword, "DatabasePassword"),
            (SecretType::ClientCertificate, "ClientCertificate"),
            (SecretType::SshKey, "SshKey"),
            (SecretType::Generic, "Generic"),
            (SecretType::HmacKey, "HmacKey"),
            (SecretType::EncryptionKey, "EncryptionKey"),
        ];
        for (variant, name) in &variants {
            let debug = format!("{variant:?}");
            assert_eq!(&debug, name, "Debug mismatch for {name}");
        }
    }

    #[test]
    fn secret_type_clone_independence() {
        let a = SecretType::WebhookSecret;
        #[allow(clippy::clone_on_copy)]
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn secret_type_deserialize_invalid() {
        let result = serde_json::from_str::<SecretType>("\"not_a_type\"");
        assert!(result.is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // New: SecretFormat edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_format_threshold_share_debug() {
        let format = SecretFormat::ThresholdShare {
            index: 2,
            threshold: 3,
            total: 5,
        };
        let debug = format!("{format:?}");
        assert!(debug.contains("ThresholdShare"));
        assert!(debug.contains("index: 2"));
        assert!(debug.contains("threshold: 3"));
        assert!(debug.contains("total: 5"));
    }

    #[test]
    fn secret_format_equality_different_variants() {
        assert_ne!(SecretFormat::Raw, SecretFormat::WrappedKey);
        assert_ne!(
            SecretFormat::Raw,
            SecretFormat::ThresholdShare {
                index: 1,
                threshold: 2,
                total: 3
            }
        );
    }

    #[test]
    fn secret_format_threshold_share_different_params_differ() {
        let a = SecretFormat::ThresholdShare {
            index: 1,
            threshold: 2,
            total: 3,
        };
        let b = SecretFormat::ThresholdShare {
            index: 2,
            threshold: 2,
            total: 3,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn secret_format_deserialize_invalid() {
        let result = serde_json::from_str::<SecretFormat>("\"invalid_format\"");
        assert!(result.is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // New: SecretObject boundary & edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_object_usable_at_exact_expiry_boundary() {
        let mut secret = test_secret_object();
        secret.expires_at = Some(1_700_000_100);
        // One tick before expiry: usable
        assert!(secret.is_usable(1_700_000_099));
        // Exactly at expiry: not usable
        assert!(!secret.is_usable(1_700_000_100));
    }

    #[test]
    fn secret_object_usable_at_exact_access_boundary() {
        let mut secret = test_secret_object();
        secret.max_access_count = Some(3);
        secret.access_count = 2;
        assert!(secret.is_usable(1_700_000_000));
        secret.access_count = 3;
        assert!(!secret.is_usable(1_700_000_000));
    }

    #[test]
    fn secret_object_not_usable_all_three_conditions() {
        let mut secret = test_secret_object();
        secret.expires_at = Some(1_700_000_050);
        secret.max_access_count = Some(1);
        secret.access_count = 1;
        secret.revoked_by = Some(ObjectId::from_bytes([0xAA; 32]));
        // All three conditions are triggered
        assert!(!secret.is_usable(1_700_000_100));
        assert!(secret.is_expired(1_700_000_100));
        assert!(secret.is_revoked());
        assert!(secret.is_access_exhausted());
    }

    #[test]
    fn secret_object_access_count_defaults_to_zero_on_deserialize() {
        // access_count has `#[serde(default)]` — verify it defaults to 0
        // Serialize a secret with non-zero access_count, then strip the field
        let mut secret = test_secret_object();
        secret.access_count = 42;
        let json = serde_json::to_string(&secret).unwrap();
        // Remove the access_count field from the JSON
        let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
        value.as_object_mut().unwrap().remove("access_count");
        let modified_json = serde_json::to_string(&value).unwrap();
        let decoded: SecretObject = serde_json::from_str(&modified_json).unwrap();
        assert_eq!(decoded.access_count, 0);
    }

    #[test]
    fn secret_object_with_key_derivation_info_roundtrip() {
        let mut secret = test_secret_object();
        secret.key_derivation_info = Some(KeyDerivationInfo {
            algorithm: "HKDF-SHA512".into(),
            salt: vec![0xAA, 0xBB, 0xCC],
            info: Some("v2-key".into()),
        });
        let json = serde_json::to_string(&secret).unwrap();
        let decoded: SecretObject = serde_json::from_str(&json).unwrap();
        let kdi = decoded.key_derivation_info.unwrap();
        assert_eq!(kdi.algorithm, "HKDF-SHA512");
        assert_eq!(kdi.salt, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(kdi.info.as_deref(), Some("v2-key"));
    }

    #[test]
    fn secret_object_debug_format() {
        let secret = test_secret_object();
        let debug = format!("{secret:?}");
        assert!(debug.contains("SecretObject"));
        assert!(debug.contains("secret_id"));
    }

    #[test]
    fn secret_object_is_expired_at_exact_time() {
        let mut secret = test_secret_object();
        secret.expires_at = Some(1_700_000_000);
        // Exactly at expiry time
        assert!(secret.is_expired(1_700_000_000));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // New: SecretAccessToken edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_access_token_new_has_zero_use_count() {
        let token = test_token();
        assert_eq!(token.use_count, 0);
    }

    #[test]
    fn secret_access_token_new_has_unique_token_id() {
        let t1 = test_token();
        let t2 = test_token();
        assert_ne!(t1.token_id, t2.token_id);
    }

    #[test]
    fn secret_access_token_expired_at_exact_boundary() {
        let token = test_token();
        // expires_at is 1_700_000_300
        assert!(!token.is_expired(1_700_000_299));
        assert!(token.is_expired(1_700_000_300));
    }

    #[test]
    fn secret_access_token_zero_max_uses_always_exhausted() {
        let token = SecretAccessToken::new(
            SecretId::new(),
            ZoneId::work(),
            test_principal(),
            "zero-max".into(),
            1_700_000_000,
            1_700_000_300,
            0,
            vec![],
        );
        assert!(token.is_exhausted());
        assert_eq!(token.remaining_uses(), 0);
        assert!(!token.is_valid(1_700_000_100));
    }

    #[test]
    fn secret_access_token_zero_max_uses_record_use_fails() {
        let mut token = SecretAccessToken::new(
            SecretId::new(),
            ZoneId::work(),
            test_principal(),
            "zero-max".into(),
            1_700_000_000,
            1_700_000_300,
            0,
            vec![],
        );
        assert!(!token.record_use());
    }

    #[test]
    fn secret_access_token_debug_contains_fields() {
        let token = test_token();
        let debug = format!("{token:?}");
        assert!(debug.contains("SecretAccessToken"));
        assert!(debug.contains("token_id"));
        assert!(debug.contains("secret_id"));
        assert!(debug.contains("zone_id"));
        assert!(debug.contains("requester"));
        assert!(debug.contains("purpose"));
        assert!(debug.contains("issued_at"));
        assert!(debug.contains("expires_at"));
        assert!(debug.contains("max_uses"));
        assert!(debug.contains("use_count"));
        assert!(debug.contains("[redacted]"));
    }

    #[test]
    fn secret_access_token_debug_redacts_any_authorization_bytes() {
        let token = SecretAccessToken::new(
            SecretId::new(),
            ZoneId::work(),
            test_principal(),
            "test".into(),
            0,
            100,
            1,
            vec![0x41, 0x42, 0x43, 0x44], // "ABCD"
        );
        let debug = format!("{token:?}");
        // The authorization bytes should not appear as hex in the debug output
        assert!(!debug.contains("41424344"));
        assert!(!debug.contains("ABCD"));
    }

    #[test]
    fn secret_access_token_clone() {
        let token = test_token();
        let cloned = token.clone();
        assert_eq!(cloned.secret_id, token.secret_id);
        assert_eq!(cloned.zone_id, token.zone_id);
        assert_eq!(cloned.purpose, token.purpose);
        assert_eq!(cloned.issued_at, token.issued_at);
        assert_eq!(cloned.expires_at, token.expires_at);
        assert_eq!(cloned.max_uses, token.max_uses);
        assert_eq!(cloned.use_count, token.use_count);
        assert_eq!(cloned.authorization(), token.authorization());
    }

    #[test]
    fn secret_access_token_record_use_increments_count() {
        let mut token = test_token();
        assert_eq!(token.use_count, 0);
        token.record_use();
        assert_eq!(token.use_count, 1);
        token.record_use();
        assert_eq!(token.use_count, 2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // New: SecretMaterial edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_material_debug_includes_len_value() {
        let material = SecretMaterial::new(vec![0; 42]);
        let debug = format!("{material:?}");
        assert!(debug.contains("42"));
        assert!(debug.contains("[redacted]"));
    }

    #[test]
    fn secret_material_empty_debug() {
        let material = SecretMaterial::new(vec![]);
        let debug = format!("{material:?}");
        assert!(debug.contains("len: 0"));
    }

    #[test]
    fn secret_material_single_byte() {
        let material = SecretMaterial::new(vec![0x99]);
        assert_eq!(material.len(), 1);
        assert!(!material.is_empty());
        assert_eq!(material.as_bytes(), &[0x99]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // New: SecretRotationPolicy edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn rotation_policy_zero_rotate_always_due() {
        let policy = SecretRotationPolicy::new(0, 0);
        assert!(policy.is_rotation_due(0));
        assert!(policy.is_rotation_due(1));
    }

    #[test]
    fn rotation_policy_zero_overlap_never_in_window() {
        let policy = SecretRotationPolicy::new(3600, 0);
        assert!(!policy.in_overlap_window(0));
        assert!(!policy.in_overlap_window(1));
    }

    #[test]
    fn rotation_policy_debug_format() {
        let policy = SecretRotationPolicy::new(100, 10);
        let debug = format!("{policy:?}");
        assert!(debug.contains("SecretRotationPolicy"));
        assert!(debug.contains("rotate_after_secs"));
        assert!(debug.contains("overlap_secs"));
    }

    #[test]
    fn rotation_policy_serde_all_fields_present() {
        let policy = SecretRotationPolicy::new(7200, 600);
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains("\"rotate_after_secs\":7200"));
        assert!(json.contains("\"overlap_secs\":600"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // New: ThresholdSecretObject edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn threshold_secret_with_wrapped_shares_serde() {
        let mut secret = test_threshold_secret();
        secret.wrapped_shares.insert(
            "node-alpha".into(),
            WrappedShare {
                index: 1,
                sealed_data: vec![0xAA, 0xBB],
                recipient_key_id: "key-alpha".into(),
            },
        );
        secret.wrapped_shares.insert(
            "node-beta".into(),
            WrappedShare {
                index: 2,
                sealed_data: vec![0xCC, 0xDD],
                recipient_key_id: "key-beta".into(),
            },
        );
        let json = serde_json::to_string(&secret).unwrap();
        let decoded: ThresholdSecretObject = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.wrapped_shares.len(), 2);
        assert!(decoded.wrapped_shares.contains_key("node-alpha"));
        assert!(decoded.wrapped_shares.contains_key("node-beta"));
        let alpha = &decoded.wrapped_shares["node-alpha"];
        assert_eq!(alpha.index, 1);
        assert_eq!(alpha.sealed_data, vec![0xAA, 0xBB]);
    }

    #[test]
    fn threshold_secret_needs_rotation_before_created_at_saturates() {
        let secret = test_threshold_secret();
        // now_unix < created_at: saturating_sub should give 0
        assert!(!secret.needs_rotation(1_699_999_000));
    }

    #[test]
    fn threshold_secret_serde_label_none() {
        let mut secret = test_threshold_secret();
        secret.label = None;
        let json = serde_json::to_string(&secret).unwrap();
        assert!(!json.contains("label"));
        let decoded: ThresholdSecretObject = serde_json::from_str(&json).unwrap();
        assert!(decoded.label.is_none());
    }

    #[test]
    fn threshold_secret_serde_expires_at_none() {
        let mut secret = test_threshold_secret();
        secret.expires_at = None;
        let json = serde_json::to_string(&secret).unwrap();
        assert!(!json.contains("expires_at"));
    }

    #[test]
    fn threshold_secret_debug_format() {
        let secret = test_threshold_secret();
        let debug = format!("{secret:?}");
        assert!(debug.contains("ThresholdSecretObject"));
        assert!(debug.contains("secret_id"));
        assert!(debug.contains("zone_id"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // New: WrappedShare edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn wrapped_share_debug_format() {
        let share = WrappedShare {
            index: 3,
            sealed_data: vec![0x01, 0x02],
            recipient_key_id: "test-key".into(),
        };
        let debug = format!("{share:?}");
        assert!(debug.contains("WrappedShare"));
        assert!(debug.contains("index: 3"));
        assert!(debug.contains("test-key"));
    }

    #[test]
    fn wrapped_share_clone() {
        let share = WrappedShare {
            index: 5,
            sealed_data: vec![0xEE, 0xFF],
            recipient_key_id: "node-key-x".into(),
        };
        let cloned = share.clone();
        assert_eq!(cloned.index, share.index);
        assert_eq!(cloned.sealed_data, share.sealed_data);
        assert_eq!(cloned.recipient_key_id, share.recipient_key_id);
    }

    #[test]
    fn wrapped_share_empty_sealed_data() {
        let share = WrappedShare {
            index: 1,
            sealed_data: vec![],
            recipient_key_id: "empty-key".into(),
        };
        let json = serde_json::to_string(&share).unwrap();
        let decoded: WrappedShare = serde_json::from_str(&json).unwrap();
        assert!(decoded.sealed_data.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // New: KeyDerivationInfo edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn key_derivation_info_debug_format() {
        let kdi = KeyDerivationInfo {
            algorithm: "HKDF-SHA256".into(),
            salt: vec![0x01],
            info: Some("ctx".into()),
        };
        let debug = format!("{kdi:?}");
        assert!(debug.contains("KeyDerivationInfo"));
        assert!(debug.contains("HKDF-SHA256"));
    }

    #[test]
    fn key_derivation_info_deserialize_missing_optional_fields() {
        let json = r#"{"algorithm":"HKDF-SHA256"}"#;
        let decoded: KeyDerivationInfo = serde_json::from_str(json).unwrap();
        assert_eq!(decoded.algorithm, "HKDF-SHA256");
        assert!(decoded.salt.is_empty());
        assert!(decoded.info.is_none());
    }

    #[test]
    fn key_derivation_info_large_salt() {
        let kdi = KeyDerivationInfo {
            algorithm: "HKDF-SHA512".into(),
            salt: vec![0xAB; 256],
            info: None,
        };
        let json = serde_json::to_string(&kdi).unwrap();
        let decoded: KeyDerivationInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.salt.len(), 256);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // New: SecretSharingScheme edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn secret_sharing_scheme_debug() {
        let scheme = SecretSharingScheme::ShamirGf256;
        let debug = format!("{scheme:?}");
        assert_eq!(debug, "ShamirGf256");
    }

    #[test]
    fn secret_sharing_scheme_equality() {
        let a = SecretSharingScheme::ShamirGf256;
        let b = SecretSharingScheme::ShamirGf256;
        assert_eq!(a, b);
    }

    #[test]
    fn secret_sharing_scheme_deserialize_invalid() {
        let result = serde_json::from_str::<SecretSharingScheme>("\"aes_sharing\"");
        assert!(result.is_err());
    }
}
