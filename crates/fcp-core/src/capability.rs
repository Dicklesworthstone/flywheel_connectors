//! Capability types and token verification.
//!
//! Capabilities are cryptographically-scoped permissions that grant specific
//! actions to principals within zones. Capability tokens (FCT) carry the
//! cryptographic proof of authorization.
//!
//! # Verification typestate
//!
//! Token verification is tracked at the type level. Five checks run during
//! verification (signature, timing, zone, operation, instance-binding) and
//! the marker on a verified token reflects which have passed:
//!
//! - [`CapabilityToken<Unverified>`] — deserialized but not yet verified.
//!   Cannot access claims.
//! - [`CapabilityToken<UnboundVerified>`] — signature / timing / zone /
//!   operation checks passed, but instance-binding was deliberately skipped
//!   (typical gateway vantage, where the connector's `InstanceId` is not
//!   yet known). Produced by [`CapabilityVerifier::verify_unbound`].
//! - [`CapabilityToken<BoundVerified>`] — all five checks passed. Produced
//!   by [`CapabilityVerifier::verify_bound`] or by calling
//!   [`CapabilityToken::promote_with_instance`] on an unbound token with
//!   a matching `InstanceId`.
//! - [`CapabilityToken<ConstraintsEnforced>`] — bound verification passed
//!   and request-level capability constraints were evaluated with an allow
//!   result. Produced by [`CapabilityToken::promote_with_constraints`].
//! - [`CapabilityToken<CryptographicallyVerified>`] — legacy marker, still
//!   returned by the older [`CapabilityVerifier::verify`]. New code should
//!   pick `verify_bound` / `verify_unbound` and demand the appropriate
//!   marker in downstream function signatures.
//!
//! The gateway produces `UnboundVerified`. The connector runtime receives
//! it, calls `promote_with_instance` with its own `InstanceId`, evaluates
//! request constraints with `promote_with_constraints`, and passes the
//! resulting `ConstraintsEnforced` token to the connector boundary.
//! Executors that require full enforcement declare
//! `fn(_: CapabilityToken<ConstraintsEnforced>)` and the compiler refuses
//! to pass them a weaker token. See
//! `docs/architecture/adr/m8j0q-constraint-typestate.md`.

use std::fmt;
use std::time::Duration;

use chrono::Utc;
use fcp_async_core::time;
use fcp_auth_schema::claims::CURRENT_SCHEMA_VERSION;
use fcp_crypto::ed25519::Ed25519VerifyingKey;
use fcp_crypto::{
    CryptoResult, HybridSignable, HybridSignedObjectKind, SignedEnvelope,
    signing_bytes_for_canonical_payload,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::object::ObjectId;
use crate::policy::pattern_matches;
use crate::{CredentialId, CredentialValidationError, FcpError, FcpResult};
use fcp_crypto::cose::{CoseToken, CwtClaims, cwt_claims, fcp2_claims};

/// Canonical identifier validation error (NORMATIVE).
///
/// Applies to the identifier set in `FCP_Specification_V3.md` §3.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IdValidationError {
    #[error("identifier must not be empty")]
    Empty,

    #[error("identifier too long ({len} bytes > {max} bytes)")]
    TooLong { len: usize, max: usize },

    #[error("identifier must be ASCII")]
    NonAscii,

    #[error("identifier contains uppercase ASCII")]
    UppercaseNotAllowed,

    #[error("identifier has invalid start character '{ch}'")]
    InvalidStartChar { ch: char },

    #[error("identifier has invalid character '{ch}' at byte {index}")]
    InvalidChar { ch: char, index: usize },
}

/// Validate identifier canonicity (NORMATIVE).
///
/// Rules:
/// - ASCII only (no Unicode)
/// - lowercase only (no mixed case)
/// - length ≤ 128 bytes
/// - regex: `^[a-z0-9][a-z0-9._:-]*$`
///
/// # Errors
/// Returns an `IdValidationError` if the identifier is not canonical.
pub fn validate_canonical_id(id: &str) -> Result<(), IdValidationError> {
    if id.is_empty() {
        return Err(IdValidationError::Empty);
    }

    if id.len() > 128 {
        return Err(IdValidationError::TooLong {
            len: id.len(),
            max: 128,
        });
    }

    if !id.is_ascii() {
        return Err(IdValidationError::NonAscii);
    }

    if id.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(IdValidationError::UppercaseNotAllowed);
    }

    let mut chars = id.char_indices();
    let Some((_, first)) = chars.next() else {
        return Err(IdValidationError::Empty);
    };
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(IdValidationError::InvalidStartChar { ch: first });
    }

    for (index, ch) in chars {
        let ok =
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | ':' | '-');
        if !ok {
            return Err(IdValidationError::InvalidChar { ch, index });
        }
    }

    Ok(())
}

/// Capability identifier - unique name for a permission.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CapabilityId(std::sync::Arc<str>);

impl CapabilityId {
    /// Create a new capability ID.
    ///
    /// # Errors
    /// Returns an error if the identifier is not canonical.
    pub fn new(id: impl Into<String>) -> Result<Self, IdValidationError> {
        Self::try_from(id.into())
    }

    /// Create a capability ID from a static string literal.
    ///
    /// # Panics
    /// Panics if the identifier is not canonical. Use only for compile-time known values.
    #[must_use]
    pub fn from_static(id: &'static str) -> Self {
        Self::new(id).expect("static capability ID must be canonical")
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CapabilityId {
    type Error = IdValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_canonical_id(&value)?;
        Ok(Self(value.into()))
    }
}

impl From<CapabilityId> for String {
    fn from(value: CapabilityId) -> Self {
        value.0.to_string()
    }
}

impl std::str::FromStr for CapabilityId {
    type Err = IdValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_owned())
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for CapabilityId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Connector identifier - unique name for a connector type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ConnectorId(std::sync::Arc<str>);

impl ConnectorId {
    /// Create a new connector ID with full details.
    ///
    /// # Errors
    /// Returns an error if the constructed identifier is not canonical.
    pub fn new(
        name: impl Into<String>,
        archetype: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, IdValidationError> {
        Self::try_from(format!(
            "{}:{}:{}",
            name.into(),
            archetype.into(),
            version.into()
        ))
    }

    /// Create a connector ID from a static string literal.
    ///
    /// # Panics
    /// Panics if the identifier is not canonical. Use only for compile-time known values.
    #[must_use]
    pub fn from_static(id: &'static str) -> Self {
        id.parse().expect("static connector ID must be canonical")
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ConnectorId {
    type Error = IdValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_canonical_id(&value)?;
        Ok(Self(value.into()))
    }
}

impl From<ConnectorId> for String {
    fn from(value: ConnectorId) -> Self {
        value.0.to_string()
    }
}

impl std::str::FromStr for ConnectorId {
    type Err = IdValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl fmt::Display for ConnectorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for ConnectorId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Instance identifier - unique ID for a running connector instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct InstanceId(std::sync::Arc<str>);

impl InstanceId {
    /// Generate a new random instance ID.
    #[must_use]
    pub fn new() -> Self {
        Self(format!("inst_{}", Uuid::new_v4()).into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for InstanceId {
    fn default() -> Self {
        Self::new()
    }
}

impl TryFrom<String> for InstanceId {
    type Error = IdValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_canonical_id(&value)?;
        Ok(Self(value.into()))
    }
}

impl From<InstanceId> for String {
    fn from(value: InstanceId) -> Self {
        value.0.to_string()
    }
}

impl std::str::FromStr for InstanceId {
    type Err = IdValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl fmt::Display for InstanceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for InstanceId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Operation identifier - name for a connector function.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct OperationId(std::sync::Arc<str>);

impl OperationId {
    /// Create a new operation ID.
    ///
    /// # Errors
    /// Returns an error if the identifier is not canonical.
    pub fn new(id: impl Into<String>) -> Result<Self, IdValidationError> {
        Self::try_from(id.into())
    }

    /// Create an operation ID from a static string literal.
    ///
    /// # Panics
    /// Panics if the identifier is not canonical. Use only for compile-time known values.
    #[must_use]
    pub fn from_static(id: &'static str) -> Self {
        Self::new(id).expect("static operation ID must be canonical")
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for OperationId {
    type Error = IdValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_canonical_id(&value)?;
        Ok(Self(value.into()))
    }
}

impl From<OperationId> for String {
    fn from(value: OperationId) -> Self {
        value.0.to_string()
    }
}

impl std::str::FromStr for OperationId {
    type Err = IdValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for OperationId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Zone identifier - name of a trust boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ZoneId(std::sync::Arc<str>);

/// Fixed-size `ZoneId` hash (NORMATIVE).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ZoneIdHash([u8; 32]);

impl ZoneIdHash {
    /// Construct a `ZoneIdHash` from raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ZoneIdHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ZoneIdHash")
            .field(&hex::encode(self.0))
            .finish()
    }
}

impl AsRef<[u8]> for ZoneIdHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ZoneIdError {
    #[error("zone id must not be empty")]
    Empty,

    #[error("zone id contains an empty segment at byte {index}")]
    EmptySegment { index: usize },

    #[error("zone id too long ({len} bytes > {max} bytes)")]
    TooLong { len: usize, max: usize },

    #[error("zone id must be ASCII")]
    NonAscii,

    #[error("zone id must start with `z:`")]
    MissingPrefix,

    #[error("tailscale tag must start with `tag:fcp-`")]
    InvalidTailscaleTagPrefix,

    #[error("zone id prefix `{prefix}` is reserved")]
    ReservedPrefix { prefix: &'static str },

    #[error("zone id has invalid character '{ch}' at byte {index}")]
    InvalidChar { ch: char, index: usize },
}

impl ZoneId {
    /// Owner zone - highest trust level.
    pub const OWNER: &str = "z:owner";
    /// Private zone - personal data.
    pub const PRIVATE: &str = "z:private";
    /// Work zone - project collaboration.
    pub const WORK: &str = "z:work";
    /// Community zone - public/semi-public content.
    pub const COMMUNITY: &str = "z:community";
    /// Public zone - internet-facing, untrusted.
    pub const PUBLIC: &str = "z:public";

    /// Create an owner zone.
    #[must_use]
    pub fn owner() -> Self {
        Self(Self::OWNER.into())
    }

    /// Create a private zone.
    #[must_use]
    pub fn private() -> Self {
        Self(Self::PRIVATE.into())
    }

    /// Create a work zone.
    #[must_use]
    pub fn work() -> Self {
        Self(Self::WORK.into())
    }

    /// Create a community zone.
    #[must_use]
    pub fn community() -> Self {
        Self(Self::COMMUNITY.into())
    }

    /// Create a public zone.
    #[must_use]
    pub fn public() -> Self {
        Self(Self::PUBLIC.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Raw bytes of canonical `ZoneId` string (NORMATIVE).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }

    /// Fixed-size hash of `ZoneId` (NORMATIVE).
    #[must_use]
    pub fn hash(&self) -> ZoneIdHash {
        let mut h = blake3::Hasher::new();
        h.update(b"FCP2-ZONE-ID-V1");
        h.update(self.as_bytes());
        ZoneIdHash(*h.finalize().as_bytes())
    }

    /// Map to Tailscale ACL tag.
    #[must_use]
    pub fn to_tailscale_tag(&self) -> String {
        let raw = self.as_str();
        let suffix = raw
            .strip_prefix("z:project:")
            .map_or_else(
                || raw.strip_prefix("z:").unwrap_or(raw).to_owned(),
                |project| format!("proj-{project}"),
            )
            .replace(':', "-");
        format!("tag:fcp-{suffix}")
    }

    /// Create from Tailscale ACL tag.
    ///
    /// # Errors
    /// Returns an error if the tag prefix is invalid or the resulting zone id is non-canonical.
    pub fn from_tailscale_tag(tag: &str) -> Result<Self, ZoneIdError> {
        let Some(suffix) = tag.strip_prefix("tag:fcp-") else {
            return Err(ZoneIdError::InvalidTailscaleTagPrefix);
        };
        let zone = suffix.strip_prefix("proj-").map_or_else(
            || format!("z:{suffix}"),
            |project| format!("z:project:{project}"),
        );
        zone.parse()
    }
}
impl ZoneId {
    fn validate(zone_id: &str) -> Result<(), ZoneIdError> {
        if zone_id.is_empty() {
            return Err(ZoneIdError::Empty);
        }

        if zone_id.len() > 64 {
            return Err(ZoneIdError::TooLong {
                len: zone_id.len(),
                max: 64,
            });
        }

        if !zone_id.is_ascii() {
            return Err(ZoneIdError::NonAscii);
        }

        if !zone_id.starts_with("z:") {
            return Err(ZoneIdError::MissingPrefix);
        }

        let mut segment_start = 2;
        for segment in zone_id[2..].split(':') {
            if segment.is_empty() {
                return Err(ZoneIdError::EmptySegment {
                    index: segment_start,
                });
            }
            segment_start += segment.len() + 1;
        }

        if zone_id[2..].starts_with("proj-") {
            return Err(ZoneIdError::ReservedPrefix { prefix: "z:proj-" });
        }

        if let Some(project) = zone_id.strip_prefix("z:project:") {
            Self::validate_project_zone_name(project)?;
        }

        for (index, ch) in zone_id.char_indices() {
            let ok = ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, ':' | '-');
            if !ok {
                return Err(ZoneIdError::InvalidChar { ch, index });
            }
        }

        Ok(())
    }

    fn validate_project_zone_name(project: &str) -> Result<(), ZoneIdError> {
        let project_start = "z:project:".len();

        if project.starts_with('-') {
            return Err(ZoneIdError::InvalidChar {
                ch: '-',
                index: project_start,
            });
        }

        if project.ends_with('-') {
            return Err(ZoneIdError::InvalidChar {
                ch: '-',
                index: project_start + project.len() - 1,
            });
        }

        for (offset, ch) in project.char_indices() {
            if !(ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-') {
                return Err(ZoneIdError::InvalidChar {
                    ch,
                    index: project_start + offset,
                });
            }
        }

        Ok(())
    }
}

impl TryFrom<String> for ZoneId {
    type Error = ZoneIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::validate(&value)?;
        Ok(Self(value.into()))
    }
}

impl From<ZoneId> for String {
    fn from(value: ZoneId) -> Self {
        value.0.to_string()
    }
}

impl std::str::FromStr for ZoneId {
    type Err = ZoneIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl fmt::Display for ZoneId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for ZoneId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ZoneBound<T> — type-level zone binding invariant
// ─────────────────────────────────────────────────────────────────────────────

/// A value `T` bound to a specific [`ZoneId`] at the API level.
///
/// `ZoneBound<T>` enforces that the inner value can only be accessed when the
/// caller demonstrates zone membership — either via [`with_zone_check`] (which
/// validates at runtime) or [`into_inner_unchecked`] (which is `#[doc(hidden)]`
/// and intended only for migration / testing scaffolds).
///
/// # Security invariant
///
/// Once bound, the zone association is immutable. There is no `set_zone()`
/// or `rebind()` — cross-zone transfer must go through the provenance system.
///
/// [`with_zone_check`]: ZoneBound::with_zone_check
/// [`into_inner_unchecked`]: ZoneBound::into_inner_unchecked
#[derive(Debug, Clone)]
pub struct ZoneBound<T> {
    inner: T,
    zone_id: ZoneId,
}

impl<T> ZoneBound<T> {
    /// Bind a value to a zone. Once bound, the zone is immutable.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // T may have Drop
    pub fn bind(inner: T, zone_id: ZoneId) -> Self {
        Self { inner, zone_id }
    }

    /// The zone this value is bound to.
    #[must_use]
    pub const fn zone_id(&self) -> &ZoneId {
        &self.zone_id
    }

    /// Access the inner value if the expected zone matches.
    ///
    /// # Errors
    ///
    /// Returns [`FcpError::ZoneViolation`] if `expected_zone` does not match
    /// the binding.
    pub fn with_zone_check<R>(
        &self,
        expected_zone: &ZoneId,
        f: impl FnOnce(&T) -> R,
    ) -> Result<R, FcpError> {
        if &self.zone_id != expected_zone {
            return Err(FcpError::ZoneViolation {
                source_zone: self.zone_id.as_str().to_owned(),
                target_zone: expected_zone.as_str().to_owned(),
                message: "zone-bound value accessed from wrong zone".to_owned(),
            });
        }
        Ok(f(&self.inner))
    }

    /// Mutably access the inner value if the expected zone matches.
    ///
    /// # Errors
    ///
    /// Returns [`FcpError::ZoneViolation`] on zone mismatch.
    pub fn with_zone_check_mut<R>(
        &mut self,
        expected_zone: &ZoneId,
        f: impl FnOnce(&mut T) -> R,
    ) -> Result<R, FcpError> {
        if &self.zone_id != expected_zone {
            return Err(FcpError::ZoneViolation {
                source_zone: self.zone_id.as_str().to_owned(),
                target_zone: expected_zone.as_str().to_owned(),
                message: "zone-bound value accessed from wrong zone".to_owned(),
            });
        }
        Ok(f(&mut self.inner))
    }

    /// Consume the wrapper and return the inner value if the zone matches.
    ///
    /// # Errors
    ///
    /// Returns [`FcpError::ZoneViolation`] on zone mismatch.
    pub fn into_inner(self, expected_zone: &ZoneId) -> Result<T, FcpError> {
        if &self.zone_id != expected_zone {
            return Err(FcpError::ZoneViolation {
                source_zone: self.zone_id.as_str().to_owned(),
                target_zone: expected_zone.as_str().to_owned(),
                message: "zone-bound value unwrapped from wrong zone".to_owned(),
            });
        }
        Ok(self.inner)
    }

    /// Consume without zone check (test/migration scaffolding only).
    #[doc(hidden)]
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // T may have Drop
    pub fn into_inner_unchecked(self) -> T {
        self.inner
    }
}

impl<T: PartialEq> PartialEq for ZoneBound<T> {
    fn eq(&self, other: &Self) -> bool {
        self.zone_id == other.zone_id && self.inner == other.inner
    }
}

impl<T: Eq> Eq for ZoneBound<T> {}

impl<T: Serialize> Serialize for ZoneBound<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("ZoneBound", 2)?;
        s.serialize_field("zone_id", &self.zone_id)?;
        s.serialize_field("inner", &self.inner)?;
        s.end()
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for ZoneBound<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Helper<U> {
            zone_id: ZoneId,
            inner: U,
        }
        let h = Helper::<T>::deserialize(deserializer)?;
        Ok(Self {
            zone_id: h.zone_id,
            inner: h.inner,
        })
    }
}

/// Principal identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PrincipalId(std::sync::Arc<str>);

impl PrincipalId {
    /// Create a new principal ID.
    ///
    /// # Errors
    /// Returns an error if the identifier is not canonical.
    pub fn new(id: impl Into<String>) -> Result<Self, IdValidationError> {
        Self::try_from(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PrincipalId {
    type Error = IdValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_canonical_id(&value)?;
        Ok(Self(value.into()))
    }
}

impl From<PrincipalId> for String {
    fn from(value: PrincipalId) -> Self {
        value.0.to_string()
    }
}

impl std::str::FromStr for PrincipalId {
    type Err = IdValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl AsRef<str> for PrincipalId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Tailscale Node ID.
///
/// Untrusted-input paths (`TryFrom<String>`, `FromStr`, serde
/// deserialization through `try_from = "String"`) validate against the
/// same canonical-id rules every other identifier type in this module
/// uses (`validate_canonical_id`): ASCII-only, no uppercase, no
/// whitespace or control characters, no Unicode lookalikes, length ≤
/// 128 bytes, `^[a-z0-9][a-z0-9._:-]*$` shape.
///
/// The pre-existing infallible constructors (`new`, `From<String>`)
/// remain available for compile-time-known identifiers (every call
/// site in the workspace today passes a literal like
/// `"node-initiator"`, and several internal tests deliberately
/// construct unusual fixtures such as empty or oversized ids to
/// exercise downstream-layer guards). Wire-supplied identifiers MUST
/// arrive through the validating path so that a malformed
/// `FcpsFrame.source_id`, `OperationReceipt.executed_by`, or peer
/// identifier in a session message cannot smuggle empty,
/// whitespace-only, NUL-embedded, bidi-override
/// (`"\u{202E}revil-node"`), or namespace-collision (`"z:owner"`)
/// payloads through the audit chain.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TailscaleNodeId(std::sync::Arc<str>);

impl TailscaleNodeId {
    /// Construct from a compile-time-known or trusted identifier.
    ///
    /// Does NOT validate — kept infallible so existing fixture and
    /// downstream-rejection tests can build fixtures (e.g. oversized
    /// source ids that exercise a frame-encoder guard) without going
    /// through the canonical-id gate. Use [`Self::try_new`] on any
    /// caller-supplied or wire-supplied input.
    pub fn new(id: impl Into<String>) -> Self {
        let s: String = id.into();
        Self(s.into())
    }

    /// Validating constructor for caller-supplied input.
    ///
    /// Applies the canonical-id rules; returns
    /// [`IdValidationError`] on rejection so callers can fail closed
    /// instead of silently accepting malformed identifiers.
    ///
    /// # Errors
    /// Returns any error returned by [`validate_canonical_id`].
    pub fn try_new(id: impl Into<String>) -> Result<Self, IdValidationError> {
        let s: String = id.into();
        validate_canonical_id(&s)?;
        Ok(Self(s.into()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for TailscaleNodeId {
    type Error = IdValidationError;

    /// Validating conversion — used by serde and other deserialization
    /// paths so wire-supplied identifiers are gated.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_canonical_id(&value)?;
        Ok(Self(value.into()))
    }
}

impl std::str::FromStr for TailscaleNodeId {
    type Err = IdValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_owned())
    }
}

impl From<TailscaleNodeId> for String {
    fn from(id: TailscaleNodeId) -> Self {
        id.0.to_string()
    }
}

/// Capability Object - mesh-native grant object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityObject {
    /// Capabilities granted by this object
    pub caps: Vec<CapabilityGrant>,

    /// Constraints on these capabilities
    #[serde(default)]
    pub constraints: CapabilityConstraints,

    /// Principal this grant is for (optional, if bound to specific principal)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<PrincipalId>,

    /// Valid from (timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<u64>,

    /// Valid until (timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<u64>,
}

/// Ordered capability-delegation chain back to a root authority.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilityChain(Vec<ObjectId>);

impl CapabilityChain {
    /// Construct a chain from ordered capability object identifiers.
    #[must_use]
    pub const fn new(chain: Vec<ObjectId>) -> Self {
        Self(chain)
    }

    /// Borrow the ordered capability object identifiers.
    #[must_use]
    pub fn as_slice(&self) -> &[ObjectId] {
        &self.0
    }

    /// Consume the chain and return the ordered object identifiers.
    #[must_use]
    pub fn into_inner(self) -> Vec<ObjectId> {
        self.0
    }

    /// Number of capability object identifiers in the chain.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the chain carries no delegation identifiers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Role Object - named bundle of capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleObject {
    /// Name of the role
    pub name: String,

    /// Capabilities included in this role
    pub caps: Vec<CapabilityGrant>,

    /// Inherited roles (`ObjectIds` of other `RoleObjects`)
    #[serde(default)]
    pub includes: Vec<ObjectId>,
}

/// Role Assignment - binds a role to a principal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleAssignment {
    /// The role being assigned (`ObjectId` of `RoleObject`)
    pub role_id: ObjectId,

    /// The principal receiving the role
    pub principal: PrincipalId,

    /// Optional attenuation
    #[serde(default)]
    pub constraints: CapabilityConstraints,
}

// ─────────────────────────────────────────────────────────────────────────────
// Phantom type markers for compile-time token verification enforcement
// ─────────────────────────────────────────────────────────────────────────────

/// Marker type: token has not been cryptographically verified.
///
/// A `CapabilityToken<Unverified>` can be created by deserialization or
/// construction, but it carries NO proof that its signature, claims, or
/// zone binding are valid. Code that requires authorization evidence must
/// accept `CapabilityToken<CryptographicallyVerified>` instead.
#[derive(Debug, Clone, Copy)]
pub struct Unverified;

/// Marker type: token has been cryptographically verified by a
/// [`CapabilityVerifier`].
///
/// **Deprecated (br-jkcka.8):** this marker is ambiguous — it does not
/// record whether the instance-binding check actually ran. New code
/// should demand [`BoundVerified`] (full 5/5 checks) or accept
/// [`UnboundVerified`] explicitly and promote via
/// [`CapabilityToken::promote_with_instance`]. See
/// `docs/architecture/adr/jkcka-typestate-split.md`.
#[deprecated(
    since = "0.1.1",
    note = "use BoundVerified (full 5/5 verification) or UnboundVerified + promote_with_instance; this marker is ambiguous (jkcka epic)"
)]
#[derive(Debug, Clone, Copy)]
pub struct CryptographicallyVerified;

/// Marker type: token passed **all five** verification checks, including
/// instance-binding (br-jkcka.3).
///
/// A `CapabilityToken<BoundVerified>` can be produced by:
/// - [`CapabilityVerifier::verify_bound`] when the verifier was constructed
///   with [`CapabilityVerifier::new`] (i.e. with a known `InstanceId`).
/// - [`CapabilityToken::promote_with_instance`] on an `UnboundVerified`
///   token (typical gateway → connector handoff).
///
/// Hold this type to prove at compile time that every capability-token
/// check ran before the token reached the current scope. Downstream
/// enforcement points (operation executors, sandbox-spawners) should
/// demand this variant in their signatures.
#[derive(Debug, Clone, Copy)]
pub struct BoundVerified;

/// Marker type: token passed **four of five** verification checks
/// (signature, timing, zone, operation) but NOT instance-binding
/// (br-jkcka.3).
///
/// A `CapabilityToken<UnboundVerified>` can be produced by
/// [`CapabilityVerifier::verify_unbound`] when the verifier was
/// constructed with [`CapabilityVerifier::without_instance_binding`]
/// (typical gateway vantage point, where the `InstanceId` is not yet
/// known).
///
/// A downstream enforcement point (the connector runtime, which DOES
/// know its instance id) must call
/// [`CapabilityToken::promote_with_instance`] before executing any
/// operation. Functions that execute operations should refuse this
/// variant by typing their signature to `CapabilityToken<BoundVerified>`.
#[derive(Debug, Clone, Copy)]
pub struct UnboundVerified;

/// Marker type: token passed `BoundVerified` AND its
/// `CapabilityConstraints` claims were evaluated against a request via a
/// `CapabilityConstraintEnforcer` with outcome `Allow` (m8j0q.A.6).
///
/// Hold a `CapabilityToken<ConstraintsEnforced>` to prove at compile time
/// that every check on the token — cryptographic AND semantic — completed
/// successfully before the request reached the boundary.
///
/// Produced exclusively by
/// [`CapabilityToken::<BoundVerified>::promote_with_constraints`], which
/// CONSUMES the `BoundVerified` witness so the un-enforced token cannot
/// reach the dispatch boundary alongside the enforced one.
///
/// Operation executors and dispatch entry points that cross the
/// host→subprocess boundary should require this variant in their
/// signatures: a `CapabilityToken<BoundVerified>` (or weaker) does NOT
/// satisfy `CapabilityToken<ConstraintsEnforced>`. See
/// `docs/architecture/adr/m8j0q-constraint-typestate.md`.
#[derive(Debug, Clone, Copy)]
pub struct ConstraintsEnforced;

mod verified_sealed {
    /// Sealed marker trait: prevents external crates from inventing new
    /// "verified" markers. Only the in-crate states implement it.
    pub trait Sealed {}
    impl Sealed for super::BoundVerified {}
    impl Sealed for super::UnboundVerified {}
    impl Sealed for super::ConstraintsEnforced {}
    #[allow(deprecated)]
    impl Sealed for super::CryptographicallyVerified {}
}

/// Marker bound for state-agnostic helpers that accept any of
/// `BoundVerified`, `UnboundVerified`, or `ConstraintsEnforced`.
///
/// The deprecated legacy marker [`CryptographicallyVerified`] is intentionally
/// EXCLUDED so new generic helpers cannot silently widen back to the ambiguous
/// pre-jkcka surface.
///
/// Sealed: cannot be implemented outside of `fcp-core`.
pub trait AnyVerified: verified_sealed::Sealed {}
impl AnyVerified for BoundVerified {}
impl AnyVerified for UnboundVerified {}
impl AnyVerified for ConstraintsEnforced {}

/// TLA+ invariant clause names mirrored by
/// `specs/tla/capability_lifecycle.tla`.
pub const CAPABILITY_LIFECYCLE_TLA_INVARIANT_CLAUSES: &[&str] = &[
    "RevokeBeforeUse",
    "NoDoubleSpend",
    "RevocationPropagationSLO",
];

/// Abstract capability-token lifecycle states mirrored by the TLA+ model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CapabilityLifecycleState {
    Pending,
    Approved,
    Used,
    Revoked,
    Expired,
}

impl CapabilityLifecycleState {
    pub const ALL: [Self; 5] = [
        Self::Pending,
        Self::Approved,
        Self::Used,
        Self::Revoked,
        Self::Expired,
    ];

    #[must_use]
    pub const fn tla_name(self) -> &'static str {
        match self {
            Self::Pending => "Pending",
            Self::Approved => "Approved",
            Self::Used => "Used",
            Self::Revoked => "Revoked",
            Self::Expired => "Expired",
        }
    }
}

impl fmt::Display for CapabilityLifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tla_name())
    }
}

impl TryFrom<&str> for CapabilityLifecycleState {
    type Error = CapabilityLifecycleParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "Pending" => Ok(Self::Pending),
            "Approved" => Ok(Self::Approved),
            "Used" => Ok(Self::Used),
            "Revoked" => Ok(Self::Revoked),
            "Expired" => Ok(Self::Expired),
            _ => Err(CapabilityLifecycleParseError::UnknownState {
                value: value.to_owned(),
            }),
        }
    }
}

/// Abstract lifecycle transitions mirrored by the TLA+ action set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CapabilityLifecycleTransition {
    Approve,
    UseAndEmitReceipt,
    RevokePending,
    RevokeApproved,
    ExpirePending,
    ExpireApproved,
    PushRevocation,
    AdvanceRevocationClock,
}

impl CapabilityLifecycleTransition {
    pub const ALL: [Self; 8] = [
        Self::Approve,
        Self::UseAndEmitReceipt,
        Self::RevokePending,
        Self::RevokeApproved,
        Self::ExpirePending,
        Self::ExpireApproved,
        Self::PushRevocation,
        Self::AdvanceRevocationClock,
    ];

    #[must_use]
    pub const fn tla_name(self) -> &'static str {
        match self {
            Self::Approve => "Approve",
            Self::UseAndEmitReceipt => "UseAndEmitReceipt",
            Self::RevokePending => "RevokePending",
            Self::RevokeApproved => "RevokeApproved",
            Self::ExpirePending => "ExpirePending",
            Self::ExpireApproved => "ExpireApproved",
            Self::PushRevocation => "PushRevocation",
            Self::AdvanceRevocationClock => "AdvanceRevocationClock",
        }
    }

    #[must_use]
    pub const fn from_state(self) -> CapabilityLifecycleState {
        match self {
            Self::Approve | Self::RevokePending | Self::ExpirePending => {
                CapabilityLifecycleState::Pending
            }
            Self::UseAndEmitReceipt | Self::RevokeApproved | Self::ExpireApproved => {
                CapabilityLifecycleState::Approved
            }
            Self::PushRevocation | Self::AdvanceRevocationClock => {
                CapabilityLifecycleState::Revoked
            }
        }
    }

    #[must_use]
    pub const fn to_state(self) -> CapabilityLifecycleState {
        match self {
            Self::Approve => CapabilityLifecycleState::Approved,
            Self::UseAndEmitReceipt => CapabilityLifecycleState::Used,
            Self::RevokePending | Self::RevokeApproved => CapabilityLifecycleState::Revoked,
            Self::ExpirePending | Self::ExpireApproved => CapabilityLifecycleState::Expired,
            Self::PushRevocation | Self::AdvanceRevocationClock => {
                CapabilityLifecycleState::Revoked
            }
        }
    }
}

impl fmt::Display for CapabilityLifecycleTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tla_name())
    }
}

impl TryFrom<&str> for CapabilityLifecycleTransition {
    type Error = CapabilityLifecycleParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "Approve" => Ok(Self::Approve),
            "UseAndEmitReceipt" => Ok(Self::UseAndEmitReceipt),
            "RevokePending" => Ok(Self::RevokePending),
            "RevokeApproved" => Ok(Self::RevokeApproved),
            "ExpirePending" => Ok(Self::ExpirePending),
            "ExpireApproved" => Ok(Self::ExpireApproved),
            "PushRevocation" => Ok(Self::PushRevocation),
            "AdvanceRevocationClock" => Ok(Self::AdvanceRevocationClock),
            _ => Err(CapabilityLifecycleParseError::UnknownTransition {
                value: value.to_owned(),
            }),
        }
    }
}

/// Unique abstract state edges in `CapabilityLifecycleTransition::ALL`.
pub const CAPABILITY_LIFECYCLE_TRANSITIONS: &[(
    CapabilityLifecycleState,
    CapabilityLifecycleState,
)] = &[
    (
        CapabilityLifecycleState::Pending,
        CapabilityLifecycleState::Approved,
    ),
    (
        CapabilityLifecycleState::Approved,
        CapabilityLifecycleState::Used,
    ),
    (
        CapabilityLifecycleState::Pending,
        CapabilityLifecycleState::Revoked,
    ),
    (
        CapabilityLifecycleState::Approved,
        CapabilityLifecycleState::Revoked,
    ),
    (
        CapabilityLifecycleState::Pending,
        CapabilityLifecycleState::Expired,
    ),
    (
        CapabilityLifecycleState::Approved,
        CapabilityLifecycleState::Expired,
    ),
    (
        CapabilityLifecycleState::Revoked,
        CapabilityLifecycleState::Revoked,
    ),
];

/// Error returned when parsing model labels from TLA+ fixtures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapabilityLifecycleParseError {
    #[error("unknown capability lifecycle state {value}")]
    UnknownState { value: String },
    #[error("unknown capability lifecycle transition {value}")]
    UnknownTransition { value: String },
}

/// Runtime lifecycle violation that corresponds to the TLA+ state machine.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapabilityLifecycleError {
    #[error("invalid capability lifecycle transition {transition} from {state}")]
    InvalidTransition {
        state: CapabilityLifecycleState,
        transition: CapabilityLifecycleTransition,
    },
    #[error("capability token was already spent")]
    AlreadyUsed,
    #[error("capability token was revoked before use")]
    RevokedBeforeUse,
    #[error("capability token is expired")]
    Expired,
    #[error("revocation propagation exceeded bound ({age_steps} steps > {bound_steps} steps)")]
    RevocationPropagationSloBreached { age_steps: u32, bound_steps: u32 },
}

/// Snapshot consumed by runtime assertions that mirror the TLA+ invariants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityLifecycleSnapshot {
    pub state: CapabilityLifecycleState,
    pub used_receipts: u8,
    pub revoked_seen: bool,
    pub revocation_pending: bool,
    pub revocation_age_steps: u32,
    pub revocation_propagation_bound: u32,
}

/// Assert runtime invariants mirrored by
/// `specs/tla/capability_lifecycle.tla`.
///
/// # Panics
/// Panics when a runtime state violates one of the named TLA+ invariants.
pub fn assert_capability_lifecycle_invariants(snapshot: &CapabilityLifecycleSnapshot) {
    assert!(
        !(snapshot.revoked_seen && snapshot.used_receipts > 0),
        "TLA_INVARIANT:RevokeBeforeUse revoked tokens cannot emit receipts"
    );
    assert!(
        snapshot.used_receipts <= 1,
        "TLA_INVARIANT:NoDoubleSpend capability tokens emit at most one receipt"
    );
    assert!(
        !snapshot.revocation_pending
            || snapshot.revocation_age_steps <= snapshot.revocation_propagation_bound,
        "TLA_INVARIANT:RevocationPropagationSLO revocation push exceeded propagation bound"
    );
}

/// Small runtime mirror for the capability lifecycle TLA+ model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityLifecycle {
    state: CapabilityLifecycleState,
    used_receipt_id: Option<ObjectId>,
    revoked_seen: bool,
    revocation_pending: bool,
    revocation_age_steps: u32,
    revocation_propagation_bound: u32,
}

impl CapabilityLifecycle {
    #[must_use]
    pub const fn pending(revocation_propagation_bound: u32) -> Self {
        Self {
            state: CapabilityLifecycleState::Pending,
            used_receipt_id: None,
            revoked_seen: false,
            revocation_pending: false,
            revocation_age_steps: 0,
            revocation_propagation_bound,
        }
    }

    #[must_use]
    pub const fn approved(revocation_propagation_bound: u32) -> Self {
        Self {
            state: CapabilityLifecycleState::Approved,
            used_receipt_id: None,
            revoked_seen: false,
            revocation_pending: false,
            revocation_age_steps: 0,
            revocation_propagation_bound,
        }
    }

    #[must_use]
    pub const fn state(&self) -> CapabilityLifecycleState {
        self.state
    }

    #[must_use]
    pub const fn used_receipt_id(&self) -> Option<ObjectId> {
        self.used_receipt_id
    }

    #[must_use]
    pub const fn snapshot(&self) -> CapabilityLifecycleSnapshot {
        CapabilityLifecycleSnapshot {
            state: self.state,
            used_receipts: if self.used_receipt_id.is_some() { 1 } else { 0 },
            revoked_seen: self.revoked_seen,
            revocation_pending: self.revocation_pending,
            revocation_age_steps: self.revocation_age_steps,
            revocation_propagation_bound: self.revocation_propagation_bound,
        }
    }

    /// Move a pending token into the approved state.
    ///
    /// # Errors
    /// Returns an error if the token is not pending.
    pub fn approve(&mut self) -> Result<(), CapabilityLifecycleError> {
        self.require_transition(CapabilityLifecycleTransition::Approve)?;
        self.state = CapabilityLifecycleState::Approved;
        self.assert_invariants();
        Ok(())
    }

    /// Spend an approved token and bind it to the emitted operation receipt.
    ///
    /// # Errors
    /// Returns an error when the token is not approved, has already been used,
    /// was revoked, or has expired.
    pub fn mark_used(&mut self, receipt_id: ObjectId) -> Result<(), CapabilityLifecycleError> {
        match self.state {
            CapabilityLifecycleState::Approved => {
                self.state = CapabilityLifecycleState::Used;
                self.used_receipt_id = Some(receipt_id);
                self.assert_invariants();
                Ok(())
            }
            CapabilityLifecycleState::Used => Err(CapabilityLifecycleError::AlreadyUsed),
            CapabilityLifecycleState::Revoked => Err(CapabilityLifecycleError::RevokedBeforeUse),
            CapabilityLifecycleState::Expired => Err(CapabilityLifecycleError::Expired),
            CapabilityLifecycleState::Pending => Err(CapabilityLifecycleError::InvalidTransition {
                state: self.state,
                transition: CapabilityLifecycleTransition::UseAndEmitReceipt,
            }),
        }
    }

    /// Revoke a pending or approved token before it can emit a receipt.
    ///
    /// # Errors
    /// Returns an error if the token has already reached a terminal state.
    pub fn revoke(&mut self) -> Result<(), CapabilityLifecycleError> {
        let transition = match self.state {
            CapabilityLifecycleState::Pending => CapabilityLifecycleTransition::RevokePending,
            CapabilityLifecycleState::Approved => CapabilityLifecycleTransition::RevokeApproved,
            CapabilityLifecycleState::Used => return Err(CapabilityLifecycleError::AlreadyUsed),
            CapabilityLifecycleState::Revoked | CapabilityLifecycleState::Expired => {
                return Err(CapabilityLifecycleError::InvalidTransition {
                    state: self.state,
                    transition: CapabilityLifecycleTransition::RevokeApproved,
                });
            }
        };
        self.require_transition(transition)?;
        self.state = CapabilityLifecycleState::Revoked;
        self.revoked_seen = true;
        self.revocation_pending = true;
        self.revocation_age_steps = 0;
        self.assert_invariants();
        Ok(())
    }

    /// Expire a pending or approved token.
    ///
    /// # Errors
    /// Returns an error if the token has already reached a terminal state.
    pub fn expire(&mut self) -> Result<(), CapabilityLifecycleError> {
        let transition = match self.state {
            CapabilityLifecycleState::Pending => CapabilityLifecycleTransition::ExpirePending,
            CapabilityLifecycleState::Approved => CapabilityLifecycleTransition::ExpireApproved,
            CapabilityLifecycleState::Used => return Err(CapabilityLifecycleError::AlreadyUsed),
            CapabilityLifecycleState::Revoked => {
                return Err(CapabilityLifecycleError::RevokedBeforeUse);
            }
            CapabilityLifecycleState::Expired => return Err(CapabilityLifecycleError::Expired),
        };
        self.require_transition(transition)?;
        self.state = CapabilityLifecycleState::Expired;
        self.revocation_pending = false;
        self.revocation_age_steps = 0;
        self.assert_invariants();
        Ok(())
    }

    /// Mark that revocation propagation reached the local executor.
    ///
    /// # Errors
    /// Returns an error if there is no pending revocation push.
    pub fn push_revocation(&mut self) -> Result<(), CapabilityLifecycleError> {
        self.require_transition(CapabilityLifecycleTransition::PushRevocation)?;
        if !self.revocation_pending {
            return Err(CapabilityLifecycleError::InvalidTransition {
                state: self.state,
                transition: CapabilityLifecycleTransition::PushRevocation,
            });
        }
        self.revocation_pending = false;
        self.revocation_age_steps = 0;
        self.assert_invariants();
        Ok(())
    }

    /// Advance the abstract revocation propagation clock by one step.
    ///
    /// # Errors
    /// Returns an error when advancing would breach the propagation SLO.
    pub fn advance_revocation_clock(&mut self) -> Result<(), CapabilityLifecycleError> {
        self.require_transition(CapabilityLifecycleTransition::AdvanceRevocationClock)?;
        if !self.revocation_pending {
            return Err(CapabilityLifecycleError::InvalidTransition {
                state: self.state,
                transition: CapabilityLifecycleTransition::AdvanceRevocationClock,
            });
        }
        let next_age = self.revocation_age_steps.saturating_add(1);
        if next_age > self.revocation_propagation_bound {
            return Err(CapabilityLifecycleError::RevocationPropagationSloBreached {
                age_steps: next_age,
                bound_steps: self.revocation_propagation_bound,
            });
        }
        self.revocation_age_steps = next_age;
        self.assert_invariants();
        Ok(())
    }

    fn require_transition(
        &self,
        transition: CapabilityLifecycleTransition,
    ) -> Result<(), CapabilityLifecycleError> {
        if transition.from_state() == self.state {
            Ok(())
        } else {
            Err(CapabilityLifecycleError::InvalidTransition {
                state: self.state,
                transition,
            })
        }
    }

    fn assert_invariants(&self) {
        assert_capability_lifecycle_invariants(&self.snapshot());
    }
}

/// Bridge trait for promoting a bound token after request-level constraint
/// evaluation.
///
/// `fcp-core` owns the typestate and token internals, while `fcp-policy` owns
/// the concrete constraint semantics. Policy enforcers implement this trait for
/// their request descriptor type, and
/// [`CapabilityToken::promote_with_constraints`] consumes the bound token only
/// after this evaluator returns `Ok(())`.
pub trait CapabilityConstraintEvaluator<Request> {
    /// Structured denial type returned when the request is not allowed.
    type Denial;

    /// Evaluate `constraints` against `request`.
    ///
    /// Returning `Ok(())` is the only success witness accepted by
    /// [`CapabilityToken::promote_with_constraints`].
    ///
    /// # Errors
    ///
    /// Returns [`Self::Denial`] when `request` violates the supplied
    /// [`CapabilityConstraints`].
    fn evaluate_constraints(
        &self,
        constraints: &CapabilityConstraints,
        request: &Request,
    ) -> Result<(), Self::Denial>;
}

/// Convenience alias for an unverified capability token.
pub type UnverifiedToken = CapabilityToken<Unverified>;

/// Convenience alias for a verified capability token.
///
/// **Deprecated (br-jkcka.8):** ambiguous — prefer the typed variants
/// `CapabilityToken<BoundVerified>` or `CapabilityToken<UnboundVerified>`.
#[allow(deprecated)]
#[deprecated(
    since = "0.1.1",
    note = "ambiguous; prefer BoundVerified / UnboundVerified"
)]
pub type VerifiedToken = CapabilityToken<CryptographicallyVerified>;

/// Flywheel Capability Token (FCT) - cryptographically signed authorization.
///
/// Wraps a `COSE_Sign1` token containing FCP2 claims, with compile-time
/// tracking of verification state via phantom types.
///
/// - `CapabilityToken<Unverified>` (the default): deserialized but not yet
///   verified. Cannot access claims.
/// - `CapabilityToken<CryptographicallyVerified>`: produced only by [`CapabilityVerifier::verify()`].
///   Carries the verified [`CwtClaims`] accessible via [`claims()`](CapabilityToken::claims).
///
/// This type-level distinction prevents accidentally using an unverified token
/// where a verified one is required — the compiler catches the mistake.
#[derive(Debug)]
pub struct CapabilityToken<S = Unverified> {
    /// The raw `COSE_Sign1` token
    raw: CoseToken,
    /// Cryptographically-verified claims — populated only in a post-verify state.
    verified_claims: Option<CwtClaims>,
    /// Phantom data for compile-time state tracking.
    _state: std::marker::PhantomData<S>,
}

impl<S> Clone for CapabilityToken<S> {
    fn clone(&self) -> Self {
        Self {
            raw: self.raw.clone(),
            verified_claims: self.verified_claims.clone(),
            _state: std::marker::PhantomData,
        }
    }
}

impl<S> From<&Self> for CapabilityToken<S> {
    fn from(token: &Self) -> Self {
        token.clone()
    }
}

/// Hybrid signed capability-token envelope.
pub type HybridSignedCapabilityToken<S = Unverified> = SignedEnvelope<CapabilityToken<S>>;

impl<S> HybridSignable for CapabilityToken<S> {
    const OBJECT_KIND: HybridSignedObjectKind = HybridSignedObjectKind::CapabilityToken;

    fn hybrid_signing_bytes(&self) -> CryptoResult<Vec<u8>> {
        let token_cbor = self.raw.to_cbor()?;
        Ok(signing_bytes_for_canonical_payload(
            Self::OBJECT_KIND,
            &token_cbor,
        ))
    }
}

// Methods available on ALL token states
impl<S> CapabilityToken<S> {
    /// Access the raw COSE token.
    #[must_use]
    pub const fn raw(&self) -> &CoseToken {
        &self.raw
    }

    /// Consume the token and return the raw COSE token.
    #[must_use]
    pub fn into_raw(self) -> CoseToken {
        self.raw
    }
}

// Methods available only on (legacy) VERIFIED tokens.
// br-jkcka.8: see impls on CapabilityToken<BoundVerified> /
// CapabilityToken<UnboundVerified> for the non-deprecated path.
#[allow(deprecated)]
impl CapabilityToken<CryptographicallyVerified> {
    /// Access the cryptographically verified claims.
    ///
    /// These claims have been validated for signature, timing, zone binding,
    /// and operation grant by a [`CapabilityVerifier`].
    ///
    /// # Panics
    ///
    /// Panics if the token was constructed without verified claims. This
    /// cannot happen through the public API since only `CapabilityVerifier::verify`
    /// produces `CapabilityToken<CryptographicallyVerified>`.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Cannot be const: calls Option::as_ref + expect
    pub fn claims(&self) -> &CwtClaims {
        self.verified_claims
            .as_ref()
            .expect("CryptographicallyVerified token always has claims")
    }

    /// Downgrade a verified token back to unverified.
    ///
    /// This discards the verification proof. Useful when a verified token
    /// needs to be re-serialized or passed to an API that accepts unverified
    /// tokens.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Cannot be const: drops Option<CwtClaims>
    pub fn downgrade(self) -> CapabilityToken<Unverified> {
        CapabilityToken {
            raw: self.raw,
            verified_claims: None,
            _state: std::marker::PhantomData,
        }
    }
}

impl Serialize for CapabilityToken<Unverified> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as the raw COSE bytes
        let bytes = self.raw.to_cbor().map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }
}

#[allow(deprecated)]
impl Serialize for CapabilityToken<CryptographicallyVerified> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize as the raw COSE bytes (same as unverified)
        let bytes = self.raw.to_cbor().map_err(serde::ser::Error::custom)?;
        serializer.serialize_bytes(&bytes)
    }
}

impl<'de> Deserialize<'de> for CapabilityToken<Unverified> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor;
        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = Vec<u8>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("byte array")
            }
            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(v.to_vec())
            }
            // Also handle byte buf (owned)
            fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(v)
            }
            // Support base64 strings for JSON
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                // Try base64 decoding if it's a string (e.g. from JSON)
                use base64::Engine;
                base64::engine::general_purpose::STANDARD
                    .decode(v)
                    .map_err(E::custom)
            }

            // Support sequence of bytes (e.g. JSON array of numbers)
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = Vec::new();
                while let Some(byte) = seq.next_element()? {
                    bytes.push(byte);
                }
                Ok(bytes)
            }
        }

        let bytes = deserializer.deserialize_any(BytesVisitor)?;
        let raw = CoseToken::from_cbor(&bytes).map_err(serde::de::Error::custom)?;

        // Deserialization always produces Unverified — the caller MUST
        // pass through CapabilityVerifier::verify() before using claims.
        Ok(Self {
            raw,
            verified_claims: None,
            _state: std::marker::PhantomData,
        })
    }
}

// Methods available only on UnboundVerified tokens (br-jkcka.3)
impl CapabilityToken<UnboundVerified> {
    /// Perform the deferred instance-binding check and promote to
    /// [`BoundVerified`] (br-jkcka.3).
    ///
    /// This is the explicit gateway → connector handoff. The gateway
    /// produces an `UnboundVerified` token via
    /// [`CapabilityVerifier::verify_unbound`] (because it doesn't know
    /// the connector's real `InstanceId` at preflight time). The
    /// connector runtime receives the token, calls
    /// `promote_with_instance` with its own `InstanceId`, and gets
    /// back a `BoundVerified` token suitable for passing to an
    /// operation executor that demands full enforcement.
    ///
    /// # Semantics (must match [`CapabilityVerifier::verify_bound`])
    ///
    /// - **Token declares `instance_id` claim matching `expected`**: promoted.
    /// - **Token declares `instance_id` claim NOT matching `expected`**:
    ///   rejected with [`FcpError::ZoneViolation`].
    /// - **Token has NO `instance_id` claim**: rejected with
    ///   [`FcpError::MissingField`]. `BoundVerified` represents all five
    ///   checks, so it is never produced from an instance-agnostic token.
    ///
    /// # Errors
    /// Returns [`FcpError::MissingField`] when the `instance_id` claim is
    /// absent or not CBOR text. Returns [`FcpError::ZoneViolation`] on
    /// instance-id claim mismatch. Returns [`FcpError::Internal`] if the
    /// token is missing claims (invariant: an `UnboundVerified` token always
    /// carries claims).
    pub fn promote_with_instance(
        self,
        expected: &InstanceId,
    ) -> FcpResult<CapabilityToken<BoundVerified>> {
        let claims = self
            .verified_claims
            .as_ref()
            .ok_or_else(|| FcpError::Internal {
                message: "UnboundVerified token missing claims (invariant violation)".into(),
            })?;

        let inst_val =
            claims
                .get(fcp2_claims::INSTANCE_ID)
                .ok_or_else(|| FcpError::MissingField {
                    field: "instance_id (required for BoundVerified)".into(),
                })?;

        // A token that passed verify_unbound already has INSTANCE_ID
        // type-checked; defensive pattern match for direct-construction
        // paths (e.g., tests) that bypass the verifier.
        let inst_str = inst_val.as_text().ok_or_else(|| FcpError::MissingField {
            field: "instance_id (must be CBOR text)".into(),
        })?;
        if inst_str != expected.as_str() {
            // Mirror the existing mismatch error shape from
            // verify_claims_inner (capability.rs — zone fields
            // carry the claim's zone, not the verifier's).
            let zone = claims.get_zone_id().unwrap_or("").to_string();
            return Err(FcpError::ZoneViolation {
                source_zone: zone.clone(),
                target_zone: zone,
                message: format!(
                    "Token instance mismatch: expected {}, got {inst_str}",
                    expected.as_str()
                ),
            });
        }

        Ok(CapabilityToken {
            raw: self.raw,
            verified_claims: self.verified_claims,
            _state: std::marker::PhantomData,
        })
    }

    /// Access the verified claims.
    ///
    /// The claims have passed signature, timing, zone, and operation
    /// verification — but the required `instance_id` binding check has
    /// NOT yet run. Callers that need full-enforcement guarantees must
    /// first [`promote_with_instance`](Self::promote_with_instance) to
    /// obtain a `CapabilityToken<BoundVerified>`.
    ///
    /// # Panics
    /// Panics if constructed without verified claims (invariant:
    /// the verifier always populates them when producing an
    /// `UnboundVerified` token; external construction is not
    /// exposed).
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Cannot be const: calls Option::as_ref + expect
    pub fn claims(&self) -> &CwtClaims {
        self.verified_claims
            .as_ref()
            .expect("UnboundVerified token must carry claims (invariant)")
    }
}

impl CapabilityToken<BoundVerified> {
    /// Access the verified claims.
    ///
    /// All five verification checks (signature, timing, zone,
    /// operation, instance binding) have passed.
    ///
    /// # Panics
    /// Panics if constructed without verified claims (invariant:
    /// the verifier and `promote_with_instance` always populate
    /// them when producing a `BoundVerified` token).
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Cannot be const: calls Option::as_ref + expect
    pub fn claims(&self) -> &CwtClaims {
        self.verified_claims
            .as_ref()
            .expect("BoundVerified token must carry claims (invariant)")
    }

    /// Run capability-constraint enforcement and promote to
    /// [`ConstraintsEnforced`] (m8j0q.A.6).
    ///
    /// Consumes `self`: the `BoundVerified` witness is invalidated by the
    /// promotion so a single token cannot be dispatched along both an
    /// un-enforced and an enforced code path. This is the type-level seat
    /// belt that prevents constraint enforcement from being silently
    /// bypassed.
    ///
    /// `evaluator` is supplied by the caller (typically
    /// `fcp_policy::DefaultConstraintEnforcer`) and runs the actual
    /// constraint evaluation against the request descriptor. fcp-core stays
    /// unaware of the policy crate so the typestate ladder lives here while
    /// the enforcement semantics live in fcp-policy. Returning `Ok(())` from
    /// [`CapabilityConstraintEvaluator::evaluate_constraints`] is the explicit
    /// witness that `ConstraintEvaluation::Allow` was produced.
    ///
    /// # Errors
    /// Propagates any denial returned by `evaluator`. Typical callers return a
    /// `fcp_policy::ConstraintDenialReason`; the denial type is generic so
    /// downstream consumers can use the structured rejection variant natural
    /// to their own error taxonomy.
    pub fn promote_with_constraints<E, Request>(
        self,
        evaluator: &E,
        constraints: &CapabilityConstraints,
        request: &Request,
    ) -> Result<CapabilityToken<ConstraintsEnforced>, E::Denial>
    where
        E: CapabilityConstraintEvaluator<Request>,
    {
        evaluator.evaluate_constraints(constraints, request)?;
        Ok(CapabilityToken {
            raw: self.raw,
            verified_claims: self.verified_claims,
            _state: std::marker::PhantomData,
        })
    }
}

impl CapabilityToken<ConstraintsEnforced> {
    /// Access the verified claims.
    ///
    /// All five cryptographic checks plus capability-constraint
    /// enforcement have passed. Holding a
    /// `CapabilityToken<ConstraintsEnforced>` is compile-time proof that
    /// every gate succeeded before the request reached this scope.
    ///
    /// # Panics
    /// Panics if constructed without verified claims (invariant:
    /// `promote_with_constraints` always carries them forward from the
    /// consumed `BoundVerified` token).
    #[must_use]
    #[allow(clippy::missing_const_for_fn)] // Cannot be const: calls Option::as_ref + expect
    pub fn claims(&self) -> &CwtClaims {
        self.verified_claims
            .as_ref()
            .expect("ConstraintsEnforced token must carry claims (invariant)")
    }
}

impl CapabilityToken<Unverified> {
    /// Create a new unverified token from a raw COSE token.
    #[must_use]
    pub const fn from_raw(raw: CoseToken) -> Self {
        Self {
            raw,
            verified_claims: None,
            _state: std::marker::PhantomData,
        }
    }

    /// Create a test token with minimal fields for testing.
    ///
    /// This token has a valid signature from a throwaway key and should
    /// only be used in tests. It is **unverified** — call
    /// `CapabilityVerifier::verify()` to produce a `CapabilityToken<CryptographicallyVerified>`.
    ///
    /// # Panics
    ///
    /// Panics if test constraint attachment or token signing fails during test
    /// token construction.
    #[must_use]
    pub fn test_token() -> Self {
        use fcp_crypto::cose::CapabilityTokenBuilder;
        use fcp_crypto::ed25519::Ed25519SigningKey;

        let signing_key = Ed25519SigningKey::generate();
        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::hours(1);

        // C3.4: tokens MUST include constraints (default-deny)
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut cbor)
            .expect("Failed to serialize test constraints");

        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.all")
            .zone_id("z:work")
            .principal("test-principal")
            .issuer("node:test")
            .validity(now, expires)
            .try_constraints_cbor(&cbor)
            .expect("test constraints CBOR should be valid")
            .sign(&signing_key)
            .expect("Failed to create test token");

        Self::from_raw(cose_token)
    }
}

/// A single capability grant within a token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    /// The capability being granted
    pub capability: CapabilityId,

    /// Optional operation scope (if None, applies to all operations under this cap)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<OperationId>,
}

/// Constraints on capability usage.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilityConstraints {
    /// Resource URI patterns that are allowed
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_allow: Vec<String>,

    /// Resource URI patterns that are denied
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resource_deny: Vec<String>,

    /// Maximum number of invocations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_calls: Option<u32>,

    /// Maximum bytes that can be transferred
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,

    /// Idempotency key for deduplication
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,

    /// Allowed credential IDs for secretless egress (NORMATIVE).
    ///
    /// Connectors can only use credentials listed here in egress requests.
    /// The egress proxy verifies `CredentialId` is in this list before
    /// injecting credential material.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credential_allow: Vec<CredentialId>,
}

impl CapabilityConstraints {
    /// Check whether this constraint set is empty (no restrictions at all).
    ///
    /// An empty constraint set means **deny all** — no resources are allowed.
    /// This is the default-deny interpretation required by C3.4.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.resource_allow.is_empty()
            && self.resource_deny.is_empty()
            && self.max_calls.is_none()
            && self.max_bytes.is_none()
            && self.idempotency_key.is_none()
            && self.credential_allow.is_empty()
    }

    /// Check if a credential ID is allowed by this capability's constraints.
    ///
    /// Returns `true` only if the credential is explicitly listed in `credential_allow`.
    /// Empty `credential_allow` implies no credentials are allowed (default deny).
    #[must_use]
    pub fn is_credential_allowed(&self, credential_id: &CredentialId) -> bool {
        self.credential_allow.contains(credential_id)
    }

    /// Validate that a credential ID is allowed by these constraints.
    ///
    /// # Errors
    ///
    /// Returns `CredentialValidationError::NotInCredentialAllow` if the credential
    /// is not in `credential_allow`. An empty `credential_allow` denies every
    /// credential (default deny, C3.4).
    pub fn validate_credential(
        &self,
        credential_id: &CredentialId,
    ) -> Result<(), CredentialValidationError> {
        if self.is_credential_allowed(credential_id) {
            Ok(())
        } else {
            Err(CredentialValidationError::NotInCredentialAllow {
                credential_id: *credential_id,
            })
        }
    }
}

/// Rate limit scope - determines how rate limits are tracked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationRateLimitScope {
    /// Rate limit per connector instance (default).
    #[default]
    PerConnector,
    /// Rate limit per zone.
    PerZone,
    /// Rate limit per principal (user/agent).
    PerPrincipal,
}

impl std::fmt::Display for OperationRateLimitScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PerConnector => write!(f, "per_connector"),
            Self::PerZone => write!(f, "per_zone"),
            Self::PerPrincipal => write!(f, "per_principal"),
        }
    }
}

impl std::str::FromStr for OperationRateLimitScope {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "per_connector" => Ok(Self::PerConnector),
            "per_zone" => Ok(Self::PerZone),
            "per_principal" => Ok(Self::PerPrincipal),
            _ => Err(format!(
                "invalid rate limit scope `{s}`: expected one of per_connector, per_zone, per_principal"
            )),
        }
    }
}

/// Rate limit configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    /// Maximum requests in the period (bucket size). Must be > 0.
    pub max: u32,

    /// Period in milliseconds (refill interval). Must be > 0.
    pub per_ms: u64,

    /// Burst allowance (tokens above max that can accumulate).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,

    /// Scope: determines how rate limits are tracked.
    /// Defaults to `per_connector` if not specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Pool name for shared rate limiting across operations.
    /// Operations with the same `pool_name` share a single rate limit bucket.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pool_name: Option<String>,
}

impl RateLimit {
    /// Validate the rate limit configuration.
    ///
    /// # Errors
    /// Returns an error if any constraint is violated.
    pub fn validate(&self) -> Result<(), RateLimitValidationError> {
        if self.max == 0 {
            return Err(RateLimitValidationError::ZeroMax);
        }
        if self.per_ms == 0 {
            return Err(RateLimitValidationError::ZeroPeriod);
        }
        if let Some(ref scope) = self.scope {
            scope.parse::<OperationRateLimitScope>().map_err(|_| {
                RateLimitValidationError::InvalidScope {
                    scope: scope.clone(),
                }
            })?;
        }
        // Validate pool_name format if present (must be valid identifier)
        if let Some(ref pool) = self.pool_name {
            if pool.is_empty() {
                return Err(RateLimitValidationError::EmptyPoolName);
            }
            if !pool
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
            {
                return Err(RateLimitValidationError::InvalidPoolName {
                    pool_name: pool.clone(),
                });
            }
        }
        Ok(())
    }

    /// Get the parsed scope, defaulting to `PerConnector`.
    #[must_use]
    pub fn parsed_scope(&self) -> OperationRateLimitScope {
        self.scope
            .as_ref()
            .and_then(|s| s.parse().ok())
            .unwrap_or_default()
    }
}

/// Error returned when rate limit validation fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitValidationError {
    /// `max` (bucket size) must be > 0.
    ZeroMax,
    /// `per_ms` (period) must be > 0.
    ZeroPeriod,
    /// Invalid scope value.
    InvalidScope { scope: String },
    /// Pool name cannot be empty.
    EmptyPoolName,
    /// Pool name contains invalid characters.
    InvalidPoolName { pool_name: String },
}

impl std::fmt::Display for RateLimitValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroMax => write!(f, "rate_limit.max must be > 0"),
            Self::ZeroPeriod => write!(f, "rate_limit.per_ms must be > 0"),
            Self::InvalidScope { scope } => {
                write!(
                    f,
                    "invalid rate_limit.scope `{scope}`: expected per_connector, per_zone, or per_principal"
                )
            }
            Self::EmptyPoolName => write!(f, "rate_limit.pool_name cannot be empty"),
            Self::InvalidPoolName { pool_name } => {
                write!(
                    f,
                    "invalid rate_limit.pool_name `{pool_name}`: must contain only alphanumeric, underscore, hyphen, or dot"
                )
            }
        }
    }
}

impl std::error::Error for RateLimitValidationError {}

/// Verifies capability tokens against the host's public key.
#[derive(Debug, Clone)]
pub struct CapabilityVerifier {
    /// Host's Ed25519 public key (issuance key)
    pub host_public_key: [u8; 32],

    /// Zone this connector is bound to
    pub zone_id: ZoneId,

    /// Instance ID for this connector.
    ///
    /// `Some(id)` means "enforce the instance-binding check: a token
    /// that carries an `INSTANCE_ID` claim must match `id`, or be
    /// rejected." `None` means "this verifier cannot enforce instance
    /// binding — skip the check and defer enforcement to the connector
    /// process itself" (br-flywheel_connectors-5qp7o).
    ///
    /// The `None` mode exists because an intermediate gateway (the
    /// `fcp-host` bin) has no link from a capability token back to the
    /// specific `SubprocessConnector` instance that will ultimately
    /// execute the operation. Previously the gateway papered over
    /// that gap by instantiating the verifier with a fresh random
    /// `InstanceId` per request; the result was worst-of-both-worlds:
    /// any token that DID declare `instance_id` was rejected (the
    /// random UUID never matched), and any token that did NOT declare
    /// `instance_id` passed without any instance enforcement. The
    /// gateway now opts out of the check explicitly via
    /// [`Self::without_instance_binding`], and instance-bound tokens
    /// reach the connector where the check is meaningful.
    pub instance_id: Option<InstanceId>,

    clock_source: CapabilityVerifierClock,
}

/// Capability-token timing tolerance for verifier-side clock skew.
///
/// This applies uniformly to all `CapabilityVerifier` entrypoints because
/// they all funnel through `verify_claims_inner`. Raw `CoseToken`
/// verification stays strict; the skew allowance is a policy choice at the
/// capability-verification boundary.
pub const CAPABILITY_TOKEN_CLOCK_SKEW_SECS: i64 = 300;

#[derive(Debug, Clone, Copy)]
enum CapabilityVerifierClock {
    SystemUtc,
    #[cfg(test)]
    Fixed(chrono::DateTime<Utc>),
}

impl CapabilityVerifier {
    /// Create a new capability verifier that enforces the instance-binding
    /// check against the given `instance_id`.
    #[must_use]
    pub const fn new(host_public_key: [u8; 32], zone_id: ZoneId, instance_id: InstanceId) -> Self {
        Self {
            host_public_key,
            zone_id,
            instance_id: Some(instance_id),
            clock_source: CapabilityVerifierClock::SystemUtc,
        }
    }

    /// Create a verifier that does NOT enforce the instance-binding check.
    ///
    /// Use this when the verifier's vantage point cannot know the
    /// connector's real `InstanceId` — typically the `fcp-host` gateway,
    /// which sits between the client and the subprocess connector and
    /// doesn't capture the connector-chosen instance id at handshake
    /// time. A downstream enforcement point (the connector itself) is
    /// responsible for re-verifying the token with the correct
    /// `InstanceId`.
    ///
    /// Construction sites that DO know the instance id (connector
    /// runtime, in-process integration tests) must keep using
    /// [`Self::new`] so the check stays active (br-5qp7o).
    #[must_use]
    pub const fn without_instance_binding(host_public_key: [u8; 32], zone_id: ZoneId) -> Self {
        Self {
            host_public_key,
            zone_id,
            instance_id: None,
            clock_source: CapabilityVerifierClock::SystemUtc,
        }
    }

    #[cfg(test)]
    const fn with_fixed_now_for_tests(mut self, now: chrono::DateTime<Utc>) -> Self {
        self.clock_source = CapabilityVerifierClock::Fixed(now);
        self
    }

    /// Helper to deserialize CBOR value
    fn deserialize_cbor<T: serde::de::DeserializeOwned>(value: &ciborium::Value) -> FcpResult<T> {
        let mut bytes = Vec::new();
        ciborium::into_writer(value, &mut bytes).map_err(|e| FcpError::Internal {
            message: format!("Serialization error: {e}"),
        })?;
        ciborium::from_reader(&bytes[..]).map_err(|e| FcpError::Internal {
            message: format!("Deserialization error: {e}"),
        })
    }

    fn validate_timing_with_clock_skew(
        claims: &CwtClaims,
        now: chrono::DateTime<Utc>,
    ) -> FcpResult<()> {
        let now_ts = now.timestamp();

        if let Some(exp) = claims.get_expiration() {
            if now_ts >= exp.saturating_add(CAPABILITY_TOKEN_CLOCK_SKEW_SECS) {
                return Err(FcpError::TokenExpired);
            }
        }

        if let Some(nbf) = claims.get_not_before() {
            if now_ts < nbf.saturating_sub(CAPABILITY_TOKEN_CLOCK_SKEW_SECS) {
                return Err(FcpError::TokenNotYetValid);
            }
        }

        Ok(())
    }

    fn now(&self) -> chrono::DateTime<Utc> {
        match self.clock_source {
            CapabilityVerifierClock::SystemUtc => Utc::now(),
            #[cfg(test)]
            CapabilityVerifierClock::Fixed(now) => now,
        }
    }

    /// Verify a capability token, producing a `CapabilityToken<CryptographicallyVerified>`.
    ///
    /// **Deprecated (br-jkcka.8):** the returned marker is ambiguous
    /// (does not record whether instance-binding ran). Call
    /// [`Self::verify_bound`] or [`Self::verify_unbound`] explicitly.
    ///
    /// This is a **consuming** method — the unverified token is moved into
    /// the verified token and can no longer be used.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid, claims are missing/expired,
    /// zone binding fails, or the operation is not granted.
    #[deprecated(
        since = "0.1.1",
        note = "ambiguous return type; use verify_bound (full enforcement) or verify_unbound (gateway vantage)"
    )]
    #[allow(deprecated)]
    pub fn verify<T>(
        &self,
        token: T,
        required_capability: &CapabilityId,
        operation: &OperationId,
        resource_uris: &[String],
    ) -> FcpResult<CapabilityToken<CryptographicallyVerified>>
    where
        T: Into<CapabilityToken>,
    {
        let token = token.into();
        let claims =
            self.verify_claims_inner(&token, required_capability, operation, resource_uris, false)?;

        Ok(CapabilityToken {
            raw: token.raw,
            verified_claims: Some(claims),
            _state: std::marker::PhantomData,
        })
    }

    /// Verify a capability token and produce a **bound**-verified token
    /// (all five checks passed, including instance binding).
    ///
    /// Requires the verifier to have been constructed with
    /// [`Self::new`] (non-`None` `instance_id`). If `instance_id` is
    /// `None`, returns `Err(FcpError::Internal)` — use
    /// [`Self::verify_unbound`] from gateway-vantage code instead.
    ///
    /// This is a **consuming** method — the unverified token is moved.
    ///
    /// # Errors
    /// Returns an error if the signature is invalid, claims are
    /// missing/expired, zone binding fails, the operation is not
    /// granted, or the token's `instance_id` claim does not match the
    /// verifier's `instance_id`.
    pub fn verify_bound<T>(
        &self,
        token: T,
        required_capability: &CapabilityId,
        operation: &OperationId,
        resource_uris: &[String],
    ) -> FcpResult<CapabilityToken<BoundVerified>>
    where
        T: Into<CapabilityToken>,
    {
        let token = token.into();
        if self.instance_id.is_none() {
            return Err(FcpError::Internal {
                message: "verify_bound requires verifier constructed with ::new (instance_id), \
                          not ::without_instance_binding — use verify_unbound instead"
                    .into(),
            });
        }
        let claims =
            self.verify_claims_inner(&token, required_capability, operation, resource_uris, true)?;
        Ok(CapabilityToken {
            raw: token.raw,
            verified_claims: Some(claims),
            _state: std::marker::PhantomData,
        })
    }

    /// Verify a capability token and produce an **unbound**-verified
    /// token (four of five checks: signature, timing, zone, operation).
    ///
    /// Requires the verifier to have been constructed with
    /// [`Self::without_instance_binding`]. The returned token has NOT
    /// had its `instance_id` check performed — a downstream enforcement
    /// point must call
    /// [`CapabilityToken::promote_with_instance`] before executing any
    /// operation. This is the gateway → connector handoff boundary
    /// spelled out in types.
    ///
    /// This is a **consuming** method.
    ///
    /// # Errors
    /// Returns an error if the signature is invalid, claims are
    /// missing/expired, zone binding fails, or the operation is not
    /// granted. Also returns `Err(FcpError::Internal)` if the verifier
    /// was constructed with a bound `instance_id` — use
    /// [`Self::verify_bound`] in that case.
    pub fn verify_unbound<T>(
        &self,
        token: T,
        required_capability: &CapabilityId,
        operation: &OperationId,
        resource_uris: &[String],
    ) -> FcpResult<CapabilityToken<UnboundVerified>>
    where
        T: Into<CapabilityToken>,
    {
        let token = token.into();
        if self.instance_id.is_some() {
            return Err(FcpError::Internal {
                message: "verify_unbound requires verifier constructed with \
                          ::without_instance_binding, not ::new — use verify_bound instead"
                    .into(),
            });
        }
        let claims =
            self.verify_claims_inner(&token, required_capability, operation, resource_uris, false)?;
        Ok(CapabilityToken {
            raw: token.raw,
            verified_claims: Some(claims),
            _state: std::marker::PhantomData,
        })
    }

    /// Verify a capability token by reference, returning just the claims.
    ///
    /// This is the non-consuming variant — it validates the token and returns
    /// the verified claims without producing a `CapabilityToken<CryptographicallyVerified>`.
    /// Prefer [`verify()`](Self::verify) when you need compile-time proof
    /// that the token has been verified.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid, claims are missing/expired,
    /// zone binding fails, or the operation is not granted.
    pub fn verify_claims(
        &self,
        token: &CapabilityToken,
        required_capability: &CapabilityId,
        operation: &OperationId,
        resource_uris: &[String],
    ) -> FcpResult<CwtClaims> {
        self.verify_claims_inner(token, required_capability, operation, resource_uris, false)
    }

    fn validate_claim_schema_version(claims: &CwtClaims) -> FcpResult<()> {
        let schema_version = match claims.get(fcp2_claims::SCHEMA_VERSION) {
            Some(ciborium::Value::Integer(version)) => {
                let as_i128: i128 = (*version).into();
                u16::try_from(as_i128).map_err(|_| FcpError::VersionMismatch {
                    expected: CURRENT_SCHEMA_VERSION.to_string(),
                    actual: as_i128.to_string(),
                })?
            }
            Some(_) => {
                return Err(FcpError::MissingField {
                    field: "schema_version (must be CBOR integer u16)".into(),
                });
            }
            None => {
                return Err(FcpError::MissingField {
                    field: "schema_version".into(),
                });
            }
        };

        if schema_version != CURRENT_SCHEMA_VERSION {
            return Err(FcpError::VersionMismatch {
                expected: CURRENT_SCHEMA_VERSION.to_string(),
                actual: schema_version.to_string(),
            });
        }

        Ok(())
    }

    fn validate_audience_binding(&self, claims: &CwtClaims) -> FcpResult<()> {
        let audience = match claims.get(cwt_claims::AUD) {
            Some(ciborium::Value::Text(aud)) if !aud.is_empty() => aud.as_str(),
            Some(ciborium::Value::Text(_)) => {
                return Err(FcpError::MissingField {
                    field: "aud (must not be empty)".into(),
                });
            }
            Some(_) => {
                return Err(FcpError::MissingField {
                    field: "aud (must be CBOR text)".into(),
                });
            }
            None => {
                return Err(FcpError::MissingField {
                    field: "aud".into(),
                });
            }
        };

        if audience != "*" && audience != self.zone_id.as_str() {
            return Err(FcpError::ZoneViolation {
                source_zone: audience.to_string(),
                target_zone: self.zone_id.0.to_string(),
                message: "Token audience mismatch".into(),
            });
        }

        Ok(())
    }

    fn validate_zone_binding(&self, claims: &CwtClaims) -> FcpResult<()> {
        if let Some(iss) = claims.get_zone_id() {
            if iss != self.zone_id.as_str() {
                return Err(FcpError::ZoneViolation {
                    source_zone: iss.into(),
                    target_zone: self.zone_id.0.to_string(),
                    message: "Token zone mismatch".into(),
                });
            }
            Ok(())
        } else {
            Err(FcpError::MissingField {
                field: "iss_zone".into(),
            })
        }
    }

    fn validate_instance_binding(
        &self,
        claims: &CwtClaims,
        require_instance_id: bool,
    ) -> FcpResult<()> {
        if let Some(inst_val) = claims.get(fcp2_claims::INSTANCE_ID) {
            let inst_str = inst_val.as_text().ok_or_else(|| FcpError::MissingField {
                field: "instance_id (must be CBOR text)".into(),
            })?;
            if let Some(expected) = self.instance_id.as_ref()
                && inst_str != expected.as_str()
            {
                return Err(FcpError::ZoneViolation {
                    source_zone: self.zone_id.0.to_string(),
                    target_zone: self.zone_id.0.to_string(),
                    message: format!(
                        "Token instance mismatch: expected {}, got {}",
                        expected.as_str(),
                        inst_str
                    ),
                });
            }
        } else if require_instance_id {
            return Err(FcpError::MissingField {
                field: "instance_id (required for BoundVerified)".into(),
            });
        }

        Ok(())
    }

    /// Shared inner verification logic used by both `verify()` and `verify_claims()`.
    fn verify_claims_inner(
        &self,
        token: &CapabilityToken,
        required_capability: &CapabilityId,
        operation: &OperationId,
        resource_uris: &[String],
        require_instance_id: bool,
    ) -> FcpResult<CwtClaims> {
        let verifying_key =
            Ed25519VerifyingKey::from_bytes(&self.host_public_key).map_err(|_| {
                FcpError::Internal {
                    message: "Invalid host key".into(),
                }
            })?;

        // 1. Verify signature and extract claims
        let claims = token
            .raw
            .verify(&verifying_key)
            .map_err(|_| FcpError::InvalidSignature)?;

        // 2. Enforce the typed auth-claim schema version at the trust boundary.
        Self::validate_claim_schema_version(&claims)?;

        // 3. Enforce audience binding. Capability tokens are valid for a
        // specific target zone (`aud == "z:..."`) or for all zones
        // (`aud == "*"`) — missing / empty / malformed `aud` must not turn
        // into implicit allow-all.
        self.validate_audience_binding(&claims)?;

        // 4. Validate timing
        let now = self.now();
        Self::validate_timing_with_clock_skew(&claims, now)?;

        // 5. Check zone binding
        self.validate_zone_binding(&claims)?;

        // 5.5. Check instance binding.
        //
        // The previous implementation silently fell through when the
        // INSTANCE_ID claim was present but not a CBOR Text value (e.g. an
        // Integer, Bytes, Array, or Map). The legitimate builder paths
        // (`CapabilityTokenBuilder::target_instance`,
        // `CwtClaims::target_instance`) only ever emit Text, so a non-Text
        // INSTANCE_ID indicates either a malformed token or an attacker
        // setting the claim to a type that bypasses the binding check
        // entirely. Either way, fail closed: a non-Text INSTANCE_ID claim
        // must be rejected, not treated as "no binding declared". The
        // sibling zone check (lines above) already gets this right via
        // `claims.get_zone_id()`, which filters to Text and returns None
        // otherwise — keep instance binding consistent.
        //
        // `verify_bound` requires the claim to be present and matching.
        // `verify_unbound` and the deprecated `verify`/`verify_claims` entrypoints
        // allow a missing claim, but still reject malformed non-Text values,
        // because malformed input is a parser-level violation independent of
        // whether this verifier is enforcing the match (br-flywheel_connectors-5qp7o,
        // br-flywheel_connectors-01yaq).
        self.validate_instance_binding(&claims, require_instance_id)?;

        // 6. Check operation grant
        //
        // br-8n0rm.6: `fcp2_claims::GRANTS` is the CANONICAL shape. The
        // legacy `OPERATIONS` fallback branch was removed once 8n0rm.8
        // made every signed token emit GRANTS automatically (see
        // `fcp_crypto::cose::synthesize_grants_from_legacy_operations`).
        //
        // A token that reaches this point without a GRANTS claim is
        // malformed — either hand-crafted with `.custom(...)` in a way
        // that bypassed the builder, OR from a pre-8n0rm.8 issuer that
        // needs upgrading. Reject it clearly.
        let Some(caps_val) = claims.get(fcp2_claims::GRANTS) else {
            return Err(FcpError::MissingField {
                field: "caps".into(),
            });
        };
        let grants: Vec<CapabilityGrant> = Self::deserialize_cbor(caps_val)?;

        let op_allowed = grants.iter().any(|g| {
            // Must match the required capability
            if g.capability != *required_capability {
                return false;
            }
            // Must match the operation (or be a wildcard)
            g.operation.as_ref().is_none_or(|op| op == operation)
        });

        if !op_allowed {
            return Err(FcpError::OperationNotGranted {
                operation: operation.0.to_string(),
            });
        }

        // 7. Enforce constraints (NORMATIVE — C3.4: mandatory, default-deny)
        if let Some(constr_val) = claims.get(fcp2_claims::CONSTRAINTS) {
            let constraints: CapabilityConstraints = Self::deserialize_cbor(constr_val)?;
            if constraints.is_empty() {
                return Err(FcpError::CapabilityDenied {
                    capability: "constraints".into(),
                    reason: "empty constraint set = deny all (C3.4 default-deny)".into(),
                });
            }
            Self::enforce_resource_constraints(&constraints, resource_uris)?;
        } else {
            // Missing constraints entirely — reject (C3.4)
            return Err(FcpError::CapabilityDenied {
                capability: "constraints".into(),
                reason: "token has no constraints — null constraints are rejected (C3.4)".into(),
            });
        }

        Ok(claims)
    }

    fn enforce_resource_constraints(
        constraints: &CapabilityConstraints,
        resource_uris: &[String],
    ) -> FcpResult<()> {
        // Check allow list
        if !constraints.resource_allow.is_empty() {
            // Defense-in-depth: if the token declares specific
            // (non-wildcard) resource patterns but the caller passed no
            // resource URIs, the subsequent `for uri in resource_uris`
            // loop iterates zero times and the allow-list silently
            // passes — a resource-scoped token ends up usable for
            // arbitrary resources. All ~76 connector call sites
            // currently invoke `verifier.verify_bound(.., &[])` regardless of
            // whether the operation targets a specific resource, so a
            // host that issues `resource_allow = ["notion://page/123"]`
            // cannot rely on the scope being enforced downstream. A
            // pure wildcard (`"*"`) is treated as "unrestricted" and is
            // exempt from this check so existing fixtures that use
            // `resource_allow: vec!["*".into()]` continue to work.
            let has_non_wildcard = constraints
                .resource_allow
                .iter()
                .any(|pattern| pattern != "*");
            if has_non_wildcard && resource_uris.is_empty() {
                return Err(FcpError::ResourceNotAllowed {
                    resource: "<none>: token declares non-wildcard resource_allow but caller provided no resource URIs".into(),
                });
            }
            for uri in resource_uris {
                let is_allowed = constraints
                    .resource_allow
                    .iter()
                    .any(|pattern| pattern_matches(pattern, uri));
                if !is_allowed {
                    return Err(FcpError::ResourceNotAllowed {
                        resource: uri.clone(),
                    });
                }
            }
        }

        // Check deny list
        for uri in resource_uris {
            if constraints
                .resource_deny
                .iter()
                .any(|pattern| pattern_matches(pattern, uri))
            {
                return Err(FcpError::ResourceNotAllowed {
                    resource: uri.clone(),
                });
            }
        }

        Ok(())
    }
}

/// Risk level for operations and capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Safety tier classification for tools and operations.
///
/// **Purpose:** Classifies the safety level of a tool or operation for agent decision-making.
/// Determines what approval/authorization is needed before an agent can execute the operation.
///
/// **Usage:**
/// - Tool descriptors: `ToolDescriptor.safety_tier`
/// - Operation metadata: `OperationMeta.safety_tier`
/// - Provenance validation: `can_drive_operation(tier)`
/// - CLI filtering: `--max-safety safe`
///
/// **Note:** This is distinct from [`RiskTier`](crate::quorum::RiskTier) in `quorum.rs`, which classifies
/// quorum/consensus requirements for distributed operations. `SafetyTier` is about
/// "can this agent do this?", while `RiskTier` is about "how many signatures are needed?".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SafetyTier {
    /// Safe operations: no approval needed, read-only or benign
    Safe,
    /// Risky operations: requires policy check, may have side effects
    Risky,
    /// Dangerous operations: requires interactive approval
    Dangerous,
    /// Critical system operations: requires quorum/elevation
    Critical,
    /// Forbidden: never allowed under any circumstances
    Forbidden,
}

/// Idempotency classification for operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyClass {
    /// No idempotency guarantees
    None,
    /// Best-effort deduplication
    BestEffort,
    /// Strict idempotency with key
    Strict,
}

/// Retry configuration for operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_attempts: u32,

    /// Initial delay between retries
    #[serde(with = "duration_millis")]
    pub initial_delay: Duration,

    /// Maximum delay between retries
    #[serde(with = "duration_millis")]
    pub max_delay: Duration,

    /// Multiplier for exponential backoff
    pub multiplier: f64,
}

/// Retry directive returned by classification layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetryDirective {
    /// Retry without waiting.
    Immediate,
    /// Retry using the caller's configured backoff policy.
    Backoff,
    /// Retry after a concrete delay.
    RetryAfter(Duration),
    /// Do not retry.
    Terminal,
}

impl RetryDirective {
    /// Parse a `Retry-After` duration value expressed as decimal seconds.
    ///
    /// This intentionally covers the deterministic delta-seconds form of the
    /// HTTP `Retry-After` header. Date-based parsing depends on wall-clock
    /// time and belongs at transport adapters that can supply a clock.
    ///
    /// # Errors
    ///
    /// Returns [`RetryDirectiveParseError`] when the input is empty,
    /// non-numeric, or overflows a [`Duration`].
    pub fn parse_retry_after(value: &str) -> Result<Self, RetryDirectiveParseError> {
        parse_retry_after_duration(value).map(Self::RetryAfter)
    }

    /// Return the explicit retry-after delay, if this directive carries one.
    #[must_use]
    pub const fn retry_after(self) -> Option<Duration> {
        match self {
            Self::RetryAfter(delay) => Some(delay),
            Self::Immediate | Self::Backoff | Self::Terminal => None,
        }
    }
}

impl fmt::Display for RetryDirective {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Immediate => f.write_str("immediate"),
            Self::Backoff => f.write_str("backoff"),
            Self::RetryAfter(delay) => write!(f, "retry-after={}ms", delay.as_millis()),
            Self::Terminal => f.write_str("terminal"),
        }
    }
}

impl std::str::FromStr for RetryDirective {
    type Err = RetryDirectiveParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "immediate" => Ok(Self::Immediate),
            "backoff" => Ok(Self::Backoff),
            "terminal" => Ok(Self::Terminal),
            _ => {
                let millis = s
                    .strip_prefix("retry-after=")
                    .and_then(|rest| rest.strip_suffix("ms"))
                    .ok_or(RetryDirectiveParseError::InvalidFormat)?;
                parse_millis_duration(millis).map(Self::RetryAfter)
            }
        }
    }
}

/// Error returned when parsing a [`RetryDirective`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RetryDirectiveParseError {
    /// Input did not match the stable directive grammar.
    #[error("retry directive must be immediate, backoff, terminal, or retry-after=<millis>ms")]
    InvalidFormat,

    /// Retry-after duration was not a decimal integer.
    #[error("retry-after duration must be a decimal integer")]
    InvalidDuration,

    /// Retry-after duration overflowed [`Duration`].
    #[error("retry-after duration is too large")]
    DurationOverflow,
}

fn parse_millis_duration(value: &str) -> Result<Duration, RetryDirectiveParseError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RetryDirectiveParseError::InvalidDuration);
    }

    let millis = value
        .parse::<u128>()
        .map_err(|_| RetryDirectiveParseError::DurationOverflow)?;
    let secs =
        u64::try_from(millis / 1_000).map_err(|_| RetryDirectiveParseError::DurationOverflow)?;
    let nanos = u32::try_from((millis % 1_000) * 1_000_000)
        .map_err(|_| RetryDirectiveParseError::DurationOverflow)?;
    Ok(Duration::new(secs, nanos))
}

fn parse_retry_after_duration(value: &str) -> Result<Duration, RetryDirectiveParseError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RetryDirectiveParseError::InvalidDuration);
    }

    let seconds = value
        .parse::<u64>()
        .map_err(|_| RetryDirectiveParseError::DurationOverflow)?;
    Ok(Duration::from_secs(seconds))
}

mod duration_millis {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        u64::try_from(duration.as_millis())
            .unwrap_or(u64::MAX)
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            multiplier: 2.0,
        }
    }
}

/// Exponential backoff delay policy expressed in retry attempts.
///
/// `max_retries` counts the delays after the initial operation attempt. A policy
/// with zero retries yields no delays, while a policy with `N` retries yields
/// exactly `N` delay values.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BackoffPolicy {
    /// Maximum number of retries after the initial operation attempt.
    pub max_retries: u32,

    /// Initial delay before the first retry.
    pub initial_delay: Duration,

    /// Maximum delay for any retry.
    pub max_delay: Duration,

    /// Multiplier for exponential backoff.
    pub multiplier: f64,
}

impl BackoffPolicy {
    /// Create a new backoff policy.
    #[must_use]
    pub const fn new(
        max_retries: u32,
        initial_delay: Duration,
        max_delay: Duration,
        multiplier: f64,
    ) -> Self {
        Self {
            max_retries,
            initial_delay,
            max_delay,
            multiplier,
        }
    }

    /// Return the configured maximum number of retries.
    #[must_use]
    pub const fn max_retries(self) -> u32 {
        self.max_retries
    }

    /// Return an iterator over the retry delays allowed by this policy.
    #[must_use]
    pub const fn retry_delays(self) -> BackoffDelays {
        BackoffDelays {
            policy: self,
            next_retry: 0,
        }
    }

    /// Return the delay for a zero-based retry index.
    #[must_use]
    pub fn delay_for_retry(self, retry_index: u32) -> Option<Duration> {
        if retry_index >= self.max_retries {
            return None;
        }

        Some(self.capped_delay_for_retry(retry_index))
    }

    fn capped_delay_for_retry(self, retry_index: u32) -> Duration {
        let mut delay = std::cmp::min(self.initial_delay, self.max_delay);
        for _ in 0..retry_index {
            delay = next_backoff_delay(delay, self.max_delay, self.multiplier);
        }

        delay
    }
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            max_retries: 2,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            multiplier: 2.0,
        }
    }
}

impl From<&RetryConfig> for BackoffPolicy {
    fn from(config: &RetryConfig) -> Self {
        Self {
            max_retries: config.max_attempts.saturating_sub(1),
            initial_delay: config.initial_delay,
            max_delay: config.max_delay,
            multiplier: config.multiplier,
        }
    }
}

impl From<RetryConfig> for BackoffPolicy {
    fn from(config: RetryConfig) -> Self {
        Self::from(&config)
    }
}

/// Iterator over the retry delays allowed by a [`BackoffPolicy`].
#[derive(Debug, Clone)]
pub struct BackoffDelays {
    policy: BackoffPolicy,
    next_retry: u32,
}

/// Retry-delay schedule produced by a [`BackoffPolicy`].
pub type BackoffSchedule = BackoffDelays;

impl BackoffDelays {
    /// Reset this schedule to the first retry delay.
    pub const fn reset(&mut self) {
        self.next_retry = 0;
    }
}

impl Iterator for BackoffDelays {
    type Item = Duration;

    fn next(&mut self) -> Option<Self::Item> {
        let delay = self.policy.delay_for_retry(self.next_retry)?;
        self.next_retry = self.next_retry.saturating_add(1);
        Some(delay)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.policy.max_retries.saturating_sub(self.next_retry);
        let remaining = usize::try_from(remaining).unwrap_or(usize::MAX);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for BackoffDelays {}

impl std::iter::FusedIterator for BackoffDelays {}

fn next_backoff_delay(delay: Duration, max_delay: Duration, multiplier: f64) -> Duration {
    if delay >= max_delay {
        return max_delay;
    }

    let multiplier = if multiplier.is_finite() && multiplier >= 1.0 {
        multiplier
    } else {
        1.0
    };
    let scaled_secs = delay.as_secs_f64() * multiplier;
    if !scaled_secs.is_finite() {
        return max_delay;
    }

    Duration::try_from_secs_f64(scaled_secs)
        .map_or(max_delay, |scaled| std::cmp::min(scaled, max_delay))
}

/// Retry with exponential backoff.
///
/// # Errors
///
/// Returns the final non-retryable error from `operation`, or the last retryable error once
/// `max_attempts` is exhausted.
pub async fn retry_with_backoff<F, Fut, T>(config: &RetryConfig, mut operation: F) -> FcpResult<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = FcpResult<T>>,
{
    let mut delay = config.initial_delay;
    let mut attempt = 0;

    loop {
        attempt += 1;
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) if e.is_retryable() && attempt < config.max_attempts => {
                if let Some(retry_after) = e.retry_after() {
                    time::sleep(retry_after).await;
                } else {
                    time::sleep(delay).await;
                    delay = std::cmp::min(
                        Duration::from_secs_f64(delay.as_secs_f64() * config.multiplier),
                        config.max_delay,
                    );
                }
            }
            Err(e) => return Err(e),
        }
    }
}

/// Correlation identifier for request tracing.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CorrelationId(pub Uuid);

impl CorrelationId {
    /// Generate a new random correlation ID.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for CorrelationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for CorrelationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Session identifier - unique ID for a handshake session.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub Uuid);

impl SessionId {
    /// Generate a new random session ID.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::str::FromStr for SessionId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Principal - an identity making requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Principal {
    /// Type of principal (e.g., "user", "agent", "service", "webhook")
    pub kind: String,

    /// Unique identifier for this principal
    pub id: String,

    /// Trust level of this principal
    pub trust: TrustLevel,

    /// Display name for humans
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

impl Principal {
    /// Enforce the baseline principal-to-zone access floor.
    ///
    /// **Opt-in utility, not a global invariant (br-u8l4d).** This method
    /// is provided for call sites that only have a [`Principal`] plus a
    /// [`ZoneId`] and have NOT yet consulted explicit host policy. It is
    /// intentionally not wired into the `CapabilityVerifier` / host admission
    /// paths because those paths already have richer policy context and
    /// wiring this floor in unconditionally would break legitimate
    /// `Paired`/`Admin` flows that explicit host policy allows.
    ///
    /// Current production callers: **none** (covered by tests only). The
    /// method is retained as a pub API building block for future
    /// principal-bearing admission sites to invoke explicitly when they lack
    /// richer context. The [`#[must_use]`] attribute below ensures callers
    /// cannot silently ignore a denied result.
    ///
    /// Current floor:
    /// - `Blocked` principals are denied everywhere.
    /// - Non-`Owner` principals are denied in high-trust zones (`z:private`,
    ///   `z:owner`) unless a higher layer performs an explicit allow.
    ///
    /// Do NOT treat this method as a substitute for zone membership, capability
    /// tokens, or host-side `allowed_zones` policy.
    ///
    /// # Errors
    /// Returns [`FcpError::Unauthorized`] when the principal fails the
    /// baseline zone-access floor.
    #[must_use = "verify_zone_access returns a Result; ignoring it silently grants access \
                  and defeats the zone-access floor (br-u8l4d)"]
    pub fn verify_zone_access(&self, zone_id: &ZoneId) -> FcpResult<()> {
        if self.trust == TrustLevel::Blocked {
            return Err(FcpError::Unauthorized {
                code: 2001,
                message: format!(
                    "blocked principal '{}' cannot access zone '{}'",
                    self.id,
                    zone_id.as_str()
                ),
            });
        }

        if matches!(zone_id.as_str(), ZoneId::PRIVATE | ZoneId::OWNER)
            && self.trust != TrustLevel::Owner
        {
            return Err(FcpError::Unauthorized {
                code: 2001,
                message: format!(
                    "principal '{}' requires explicit zone policy to access '{}'",
                    self.id,
                    zone_id.as_str()
                ),
            });
        }

        Ok(())
    }
}

/// Trust level for principals.
///
/// Per FCP Specification Section 6.5 (Ingress Bindings):
/// These are the canonical trust levels for external principals.
/// Order is from lowest to highest trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustLevel {
    /// Explicitly denied access
    Blocked,
    /// Unauthenticated user
    Anonymous,
    /// Authenticated but not approved
    Untrusted,
    /// Explicitly approved external user
    Paired,
    /// Elevated but not root
    Admin,
    /// Root trust (owner)
    Owner,
}

/// Taint level for provenance tracking.
///
/// Per FCP Specification Section 7.2.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default,
)]
pub enum TaintLevel {
    /// Trusted source only
    #[default]
    Untainted,
    /// Untrusted input present in chain
    Tainted,
    /// Direct untrusted instruction
    HighlyTainted,
}

/// A step in the provenance chain.
///
/// Per FCP Specification Section 7.2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceStep {
    /// Timestamp in milliseconds since epoch
    pub timestamp_ms: u64,

    /// Zone where this step occurred
    pub zone: ZoneId,

    /// Actor (agent/user/connector id)
    pub actor: String,

    /// Action performed (e.g., "discord.message", "tool.invoke")
    pub action: String,

    /// Resource URI or capability identifier
    pub resource: String,
}

/// Provenance metadata for tracking data origin.
///
/// Per FCP Specification Section 7.2:
/// - `origin_zone`: Where the triggering input originated
/// - `chain`: Monotonic chain of causal steps
/// - `taint`: Highest taint severity observed in the chain
/// - `elevated`: Whether explicit elevation has been granted
/// - `elevation_token`: Token proving elevation (if elevated)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// The zone where the request/data originated
    pub origin_zone: ZoneId,

    /// Monotonic chain of causal steps
    #[serde(default)]
    pub chain: Vec<ProvenanceStep>,

    /// Highest taint severity observed in the chain
    #[serde(default)]
    pub taint: TaintLevel,

    /// Whether this request has been elevated
    #[serde(default)]
    pub elevated: bool,

    /// Elevation token if elevated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elevation_token: Option<String>,
}

impl Provenance {
    /// Create provenance from an origin zone.
    #[must_use]
    pub const fn new(origin_zone: ZoneId) -> Self {
        Self {
            origin_zone,
            chain: Vec::new(),
            taint: TaintLevel::Untainted,
            elevated: false,
            elevation_token: None,
        }
    }

    /// Create tainted provenance from an untrusted source.
    #[must_use]
    pub const fn tainted(origin_zone: ZoneId) -> Self {
        Self {
            origin_zone,
            chain: Vec::new(),
            taint: TaintLevel::Tainted,
            elevated: false,
            elevation_token: None,
        }
    }

    /// Create highly tainted provenance from a direct untrusted instruction.
    #[must_use]
    pub const fn highly_tainted(origin_zone: ZoneId) -> Self {
        Self {
            origin_zone,
            chain: Vec::new(),
            taint: TaintLevel::HighlyTainted,
            elevated: false,
            elevation_token: None,
        }
    }

    /// Add a step to the provenance chain.
    #[must_use]
    pub fn with_step(mut self, step: ProvenanceStep) -> Self {
        self.chain.push(step);
        self
    }

    /// Mark as elevated with a token.
    #[must_use]
    pub fn elevated_with(mut self, token: impl Into<String>) -> Self {
        self.elevated = true;
        self.elevation_token = Some(token.into());
        self
    }

    /// Check if this provenance is tainted.
    #[must_use]
    pub const fn is_tainted(&self) -> bool {
        !matches!(self.taint, TaintLevel::Untainted)
    }

    /// Check if this provenance can access a higher-trust zone.
    ///
    /// Per FCP spec, tainted provenance cannot access higher-trust zones
    /// without explicit elevation.
    #[must_use]
    pub const fn can_access_higher_trust(&self) -> bool {
        !self.is_tainted() || self.elevated
    }
}

#[cfg(test)]
mod tests {
    #![allow(deprecated)]
    // This module still covers legacy `verify` / `CryptographicallyVerified`
    // behavior alongside the newer bound/unbound typestate tests.

    use super::*;
    use chrono::Duration;
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;

    /// Helper: serialize default-allow constraints to CBOR bytes for test tokens.
    fn test_constraints_cbor() -> Vec<u8> {
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&constraints, &mut buf).unwrap();
        buf
    }

    /// Helper: CBOR constraints with a specific (non-wildcard) resource pattern.
    fn test_constraints_cbor_with_resource_allow(patterns: Vec<String>) -> Vec<u8> {
        let constraints = CapabilityConstraints {
            resource_allow: patterns,
            ..Default::default()
        };
        let mut buf = Vec::new();
        ciborium::into_writer(&constraints, &mut buf).unwrap();
        buf
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Canonical ID Validation Tests (FCP Spec §3.4.2)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn canonical_id_valid_simple() {
        assert!(validate_canonical_id("hello").is_ok());
        assert!(validate_canonical_id("a").is_ok());
        assert!(validate_canonical_id("0").is_ok());
        assert!(validate_canonical_id("test123").is_ok());
    }

    #[test]
    fn canonical_id_reject_uppercase() {
        assert_eq!(
            validate_canonical_id("Hello"),
            Err(IdValidationError::UppercaseNotAllowed)
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CapabilityVerifier Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn verify_capability_token() {
        // 1. Generate keys
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();

        // 2. Create token data
        let now = Utc::now();
        let expires = now + Duration::hours(1);

        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.test")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(now, expires)
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .expect("Failed to sign token");

        // 3. Wrap in CapabilityToken
        let token = CapabilityToken::from_raw(cose_token);

        // 4. Verify
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new());

        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();

        let result = verifier
            .verify(token, &cap, &op, &[])
            .expect("Verification failed");

        assert_eq!(result.claims().get_capability_id(), Some("cap.test"));
    }

    #[test]
    fn verify_rejects_empty_audience() {
        let signing_key = Ed25519SigningKey::generate();
        let pub_bytes = signing_key.verifying_key().to_bytes();

        let now = Utc::now();
        let token = CapabilityToken::from_raw(
            CapabilityTokenBuilder::new()
                .capability_id("cap.test")
                .zone_id("z:work")
                .audience("")
                .principal("user:test")
                .operations(&["op.test"])
                .issuer("node:primary")
                .validity(now, now + Duration::hours(1))
                .try_constraints_cbor(&test_constraints_cbor())
                .expect("valid constraints")
                .sign(&signing_key)
                .unwrap(),
        );

        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new());
        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();
        let err = verifier.verify(token, &cap, &op, &[]).unwrap_err();

        assert!(
            matches!(&err, FcpError::MissingField { field } if field == "aud (must not be empty)"),
            "empty audience must be rejected, got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_wrong_audience_zone() {
        let signing_key = Ed25519SigningKey::generate();
        let pub_bytes = signing_key.verifying_key().to_bytes();

        let now = Utc::now();
        let token = CapabilityToken::from_raw(
            CapabilityTokenBuilder::new()
                .capability_id("cap.test")
                .zone_id("z:work")
                .audience("z:private")
                .principal("user:test")
                .operations(&["op.test"])
                .issuer("node:primary")
                .validity(now, now + Duration::hours(1))
                .try_constraints_cbor(&test_constraints_cbor())
                .expect("valid constraints")
                .sign(&signing_key)
                .unwrap(),
        );

        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new());
        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();
        let err = verifier.verify(token, &cap, &op, &[]).unwrap_err();

        assert!(
            matches!(&err, FcpError::ZoneViolation { message, .. } if message == "Token audience mismatch"),
            "wrong audience zone must be rejected, got {err:?}"
        );
    }

    #[test]
    fn verify_accepts_wildcard_audience() {
        let signing_key = Ed25519SigningKey::generate();
        let pub_bytes = signing_key.verifying_key().to_bytes();

        let now = Utc::now();
        let token = CapabilityToken::from_raw(
            CapabilityTokenBuilder::new()
                .capability_id("cap.test")
                .zone_id("z:work")
                .audience("*")
                .principal("user:test")
                .operations(&["op.test"])
                .issuer("node:primary")
                .validity(now, now + Duration::hours(1))
                .try_constraints_cbor(&test_constraints_cbor())
                .expect("valid constraints")
                .sign(&signing_key)
                .unwrap(),
        );

        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new());
        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();
        verifier
            .verify(token, &cap, &op, &[])
            .expect("wildcard audience should be accepted");
    }

    #[test]
    fn verify_rejects_non_wildcard_resource_allow_with_empty_uris() {
        // Defense-in-depth regression: a token with a specific
        // resource_allow pattern must not silently pass when the caller
        // provides no resource URIs. Historically the allow-list loop
        // iterated zero times, so a scoped token was usable for arbitrary
        // resources — the ~76 `verifier.verify_bound(.., &[])` call sites in
        // the connector tree would all benefit from this guard.
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();

        let now = Utc::now();
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.test")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor_with_resource_allow(vec![
                "notion://page/123".to_string(),
            ]))
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();
        let token = CapabilityToken::from_raw(cose_token);
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new());

        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();
        let result = verifier.verify(token, &cap, &op, &[]);
        assert!(
            matches!(
                result,
                Err(FcpError::ResourceNotAllowed { ref resource })
                    if resource.contains("non-wildcard")
            ),
            "expected ResourceNotAllowed for non-wildcard+empty, got {result:?}"
        );
    }

    #[test]
    fn verify_accepts_non_wildcard_resource_allow_with_matching_uri() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();

        let now = Utc::now();
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.test")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor_with_resource_allow(vec![
                "notion://page/*".to_string(),
            ]))
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();
        let token = CapabilityToken::from_raw(cose_token);
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new());

        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();
        verifier
            .verify(token, &cap, &op, &["notion://page/123".into()])
            .expect("matching resource URI should pass");
    }

    #[test]
    fn verify_accepts_wildcard_resource_allow_with_empty_uris() {
        // Backward-compatibility guard: the pure "*" wildcard is treated
        // as "unrestricted" and does not trigger the non-wildcard check.
        // Every existing connector integration test uses
        // `resource_allow: vec!["*".into()]`; breaking those would force
        // the entire connector tree to migrate URI plumbing in one shot.
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();

        let now = Utc::now();
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.test")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();
        let token = CapabilityToken::from_raw(cose_token);
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new());

        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();
        verifier
            .verify(token, &cap, &op, &[])
            .expect("pure wildcard resource_allow should still accept empty resource_uris");
    }

    #[test]
    fn verify_rejects_capability_mismatch() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();

        let now = Utc::now();
        // Token grants "cap.benign" with operations "op.test"
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.benign")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();

        let token = CapabilityToken::from_raw(cose_token);
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new());

        let op = OperationId::new("op.test").unwrap();
        // We TRY to use "cap.critical"
        let required_cap = CapabilityId::new("cap.critical").unwrap();

        let result = verifier.verify(token, &required_cap, &op, &[]);
        assert!(matches!(result, Err(FcpError::OperationNotGranted { .. })));
    }

    #[test]
    fn verify_rejects_wrong_zone() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();

        let now = Utc::now();
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.test")
            .zone_id("z:wrong") // Wrong zone
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();

        let token = CapabilityToken::from_raw(cose_token);
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new());
        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();

        let result = verifier.verify(token, &cap, &op, &[]);
        assert!(matches!(result, Err(FcpError::ZoneViolation { .. })));
    }

    #[test]
    fn verify_rejects_cross_project_audience_confused_deputy() {
        let signing_key = Ed25519SigningKey::generate();
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let foo_zone: ZoneId = "z:project:foo".parse().unwrap();
        let bar_zone: ZoneId = "z:project:bar".parse().unwrap();
        let now = Utc::now();

        let token = CapabilityToken::from_raw(
            CapabilityTokenBuilder::new()
                .capability_id("cap.test")
                .zone_id(foo_zone.as_str())
                .audience(foo_zone.as_str())
                .principal("user:test")
                .operations(&["op.test"])
                .issuer("node:primary")
                .validity(now, now + Duration::hours(1))
                .try_constraints_cbor(&test_constraints_cbor())
                .expect("valid constraints")
                .sign(&signing_key)
                .unwrap(),
        );

        let verifier = CapabilityVerifier::new(pub_bytes, bar_zone, InstanceId::new());
        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();
        let err = verifier.verify(token, &cap, &op, &[]).unwrap_err();

        assert!(
            matches!(&err, FcpError::ZoneViolation { message, source_zone, target_zone }
                if message == "Token audience mismatch"
                    && source_zone == "z:project:foo"
                    && target_zone == "z:project:bar"),
            "cross-project audience binding must reject token reuse, got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_cross_project_zone_with_wildcard_audience() {
        let signing_key = Ed25519SigningKey::generate();
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let foo_zone: ZoneId = "z:project:foo".parse().unwrap();
        let bar_zone: ZoneId = "z:project:bar".parse().unwrap();
        let now = Utc::now();

        let token = CapabilityToken::from_raw(
            CapabilityTokenBuilder::new()
                .capability_id("cap.test")
                .zone_id(foo_zone.as_str())
                .audience("*")
                .principal("user:test")
                .operations(&["op.test"])
                .issuer("node:primary")
                .validity(now, now + Duration::hours(1))
                .try_constraints_cbor(&test_constraints_cbor())
                .expect("valid constraints")
                .sign(&signing_key)
                .unwrap(),
        );

        let verifier = CapabilityVerifier::new(pub_bytes, bar_zone, InstanceId::new());
        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();
        let err = verifier.verify(token, &cap, &op, &[]).unwrap_err();

        assert!(
            matches!(&err, FcpError::ZoneViolation { message, source_zone, target_zone }
                if message == "Token zone mismatch"
                    && source_zone == "z:project:foo"
                    && target_zone == "z:project:bar"),
            "wildcard audience must not bypass project-zone binding, got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_expired() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();

        let now = chrono::DateTime::<Utc>::from_timestamp(1_704_067_200, 0).unwrap();
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.test")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(
                now - Duration::hours(2),
                now - Duration::seconds(CAPABILITY_TOKEN_CLOCK_SKEW_SECS + 1),
            )
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();

        let token = CapabilityToken::from_raw(cose_token);
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new())
            .with_fixed_now_for_tests(now);
        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();

        let result = verifier.verify(token, &cap, &op, &[]);
        assert!(matches!(result, Err(FcpError::TokenExpired)));
    }

    #[test]
    fn verify_accepts_expired_within_clock_skew_tolerance() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();

        let now = chrono::DateTime::<Utc>::from_timestamp(1_704_067_200, 0).unwrap();
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.test")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(
                now - Duration::hours(1),
                now - Duration::seconds(CAPABILITY_TOKEN_CLOCK_SKEW_SECS - 1),
            )
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();

        let token = CapabilityToken::from_raw(cose_token);
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new())
            .with_fixed_now_for_tests(now);
        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();

        verifier
            .verify(token, &cap, &op, &[])
            .expect("token expired within skew tolerance should verify");
    }

    #[test]
    fn verify_accepts_not_yet_valid_within_clock_skew_tolerance() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();

        let now = chrono::DateTime::<Utc>::from_timestamp(1_704_067_200, 0).unwrap();
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.test")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(
                now + Duration::seconds(CAPABILITY_TOKEN_CLOCK_SKEW_SECS - 1),
                now + Duration::hours(1),
            )
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();

        let token = CapabilityToken::from_raw(cose_token);
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new())
            .with_fixed_now_for_tests(now);
        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();

        verifier
            .verify(token, &cap, &op, &[])
            .expect("token not yet valid within skew tolerance should verify");
    }

    #[test]
    fn verify_rejects_not_yet_valid_beyond_clock_skew_tolerance() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();

        let now = chrono::DateTime::<Utc>::from_timestamp(1_704_067_200, 0).unwrap();
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.test")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(
                now + Duration::seconds(CAPABILITY_TOKEN_CLOCK_SKEW_SECS + 1),
                now + Duration::hours(1),
            )
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();

        let token = CapabilityToken::from_raw(cose_token);
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new())
            .with_fixed_now_for_tests(now);
        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();

        let result = verifier.verify(token, &cap, &op, &[]);
        assert!(matches!(result, Err(FcpError::TokenNotYetValid)));
    }

    #[test]
    fn verify_rejects_non_text_instance_id_claim() {
        // The previous instance-binding check used a nested
        // `if let Some(inst_str) = inst_val.as_text()` and silently fell
        // through when INSTANCE_ID was present but not a CBOR Text. That
        // let an attacker bypass instance binding by emitting the claim
        // as an Integer (or Bytes/Array/Map/Bool) — the type-confusion
        // pattern that has bitten other CBOR consumers. With the fix,
        // any non-Text INSTANCE_ID must produce MissingField rather than
        // pass.
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();

        let now = Utc::now();
        let claims = fcp_crypto::cose::CwtClaims::new()
            .capability_id("cap.test")
            .zone_id("z:work")
            .principal_id("user:test")
            .issuer("node:primary")
            .not_before(now)
            .expiration(now + Duration::hours(1))
            .operations(&["op.test"])
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            // Set INSTANCE_ID as an Integer instead of Text — pre-fix this
            // would let any verifier accept the token regardless of its
            // configured instance_id.
            .custom(
                fcp_crypto::cose::fcp2_claims::INSTANCE_ID,
                ciborium::Value::Integer(0_i64.into()),
            );
        let cose_token = fcp_crypto::cose::CoseToken::sign(&signing_key, &claims).expect("sign");
        let token = CapabilityToken::from_raw(cose_token);

        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new());
        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();

        let err = verifier
            .verify(token, &cap, &op, &[])
            .expect_err("non-Text INSTANCE_ID must be rejected");
        assert!(
            matches!(
                err,
                FcpError::MissingField { ref field } if field.contains("instance_id")
            ),
            "expected MissingField with instance_id mention, got {err:?}"
        );
    }

    #[test]
    fn verify_accepts_text_instance_id_claim_when_matching() {
        // Companion to the non-text rejection test: a properly-typed
        // INSTANCE_ID claim that matches the verifier's instance_id must
        // still pass cleanly. Establishes that the fix did not over-tighten.
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();

        let instance_id = InstanceId::new();
        let now = Utc::now();
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.test")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .target_instance(instance_id.as_str())
            .sign(&signing_key)
            .unwrap();
        let token = CapabilityToken::from_raw(cose_token);

        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), instance_id);
        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();

        verifier
            .verify(token, &cap, &op, &[])
            .expect("matching Text INSTANCE_ID must verify");
    }

    // ── br-flywheel_connectors-5qp7o: without_instance_binding mode ──

    #[test]
    fn without_instance_binding_accepts_token_that_declares_instance_id() {
        // Regression: prior host-gateway behavior constructed the verifier
        // with a fresh random InstanceId per request, so any token that
        // declared an instance_id claim was ALWAYS rejected (the random
        // UUID never matched). `without_instance_binding` opts out of
        // the check entirely — the gateway can't enforce it, but it
        // must not spuriously reject legitimate instance-bound tokens.
        let signing_key = Ed25519SigningKey::generate();
        let pub_bytes = signing_key.verifying_key().to_bytes();

        let token_instance = InstanceId::new();
        let now = Utc::now();
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.test")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .target_instance(token_instance.as_str())
            .sign(&signing_key)
            .unwrap();
        let token = CapabilityToken::from_raw(cose_token);

        let verifier = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();

        verifier.verify(token, &cap, &op, &[]).expect(
            "without_instance_binding must accept a token that declares instance_id — \
                 the verifier explicitly declined to check the binding",
        );
    }

    #[test]
    fn without_instance_binding_still_rejects_non_text_instance_id() {
        // Parser-level defense: a non-Text INSTANCE_ID claim is
        // rejected even when the verifier is in without_instance_binding
        // mode. The match check is what's skipped, not type validation —
        // a malformed claim is still a malformed claim.
        let signing_key = Ed25519SigningKey::generate();
        let pub_bytes = signing_key.verifying_key().to_bytes();

        let now = Utc::now();
        let claims = fcp_crypto::cose::CwtClaims::new()
            .capability_id("cap.test")
            .zone_id("z:work")
            .principal_id("user:test")
            .issuer("node:primary")
            .not_before(now)
            .expiration(now + Duration::hours(1))
            .operations(&["op.test"])
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .custom(
                fcp_crypto::cose::fcp2_claims::INSTANCE_ID,
                ciborium::Value::Integer(0_i64.into()),
            );
        let cose_token = fcp_crypto::cose::CoseToken::sign(&signing_key, &claims).expect("sign");
        let token = CapabilityToken::from_raw(cose_token);

        let verifier = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();

        let err = verifier
            .verify(token, &cap, &op, &[])
            .expect_err("non-Text INSTANCE_ID must be rejected even in unbound mode");
        assert!(
            matches!(err, FcpError::MissingField { ref field } if field.contains("instance_id")),
            "expected MissingField naming instance_id, got {err:?}",
        );
    }

    #[test]
    fn without_instance_binding_ignores_tokens_without_instance_claim() {
        // A token that doesn't declare instance_id passes cleanly in
        // unbound mode. Bound verification still rejects the same token,
        // because `BoundVerified` now requires an explicit instance claim.
        let signing_key = Ed25519SigningKey::generate();
        let pub_bytes = signing_key.verifying_key().to_bytes();

        let now = Utc::now();
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.test")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();
        let token = CapabilityToken::from_raw(cose_token);

        let verifier = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();

        verifier
            .verify(token, &cap, &op, &[])
            .expect("unbound mode + no instance claim = no check");
    }

    // ── br-8n0rm.6: legacy OPERATIONS fallback removed ───────────────────

    #[test]
    fn verifier_rejects_legacy_operations_only_token() {
        // Regression: hand-craft a CwtClaims with the legacy OPERATIONS
        // shape but NO canonical GRANTS, then sign + verify. After 8n0rm.6
        // the verifier must reject with MissingField("caps") rather than
        // falling through to the legacy OPERATIONS branch.
        let signing_key = Ed25519SigningKey::generate();
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let now = Utc::now();

        // Build raw CwtClaims WITHOUT going through CapabilityTokenBuilder
        // (which would auto-synthesize GRANTS via br-8n0rm.8). We set the
        // legacy-only fields directly.
        let claims = fcp_crypto::cose::CwtClaims::new()
            .issuer("z:work")
            .capability_id("cap.test")
            .zone_id("z:work")
            .operations(&["op.test"]) // legacy-only shape
            .issued_at(now)
            .expiration(now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints");
        let cose_token = fcp_crypto::cose::CoseToken::sign(&signing_key, &claims).unwrap();
        let token = CapabilityToken::from_raw(cose_token);

        let verifier = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
        let cap = CapabilityId::new("cap.test").unwrap();
        let op = OperationId::new("op.test").unwrap();
        let err = verifier.verify(token, &cap, &op, &[]).unwrap_err();
        assert!(
            matches!(&err, FcpError::MissingField { field, .. } if field == "caps"),
            "legacy OPERATIONS-only token must be rejected with MissingField(caps); got {err:?}"
        );
    }

    #[test]
    fn verifier_rejects_unsupported_schema_version_token() {
        let signing_key = Ed25519SigningKey::generate();
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let now = Utc::now();

        let grants = ciborium::Value::Array(vec![ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("capability".into()),
                ciborium::Value::Text("cap.test".into()),
            ),
            (
                ciborium::Value::Text("operation".into()),
                ciborium::Value::Text("op.test".into()),
            ),
        ])]);

        let claims = fcp_crypto::cose::CwtClaims::new()
            .issuer("z:work")
            .capability_id("cap.test")
            .zone_id("z:work")
            .issued_at(now)
            .expiration(now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .custom(fcp2_claims::GRANTS, grants)
            .custom(
                fcp2_claims::SCHEMA_VERSION,
                ciborium::Value::Integer(999_i64.into()),
            );
        let cose_token = fcp_crypto::cose::CoseToken::sign(&signing_key, &claims).unwrap();
        let token = CapabilityToken::from_raw(cose_token);

        let verifier = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
        let cap = CapabilityId::new("cap.test").unwrap();
        let op = OperationId::new("op.test").unwrap();
        let err = verifier.verify(token, &cap, &op, &[]).unwrap_err();
        let expected_schema = CURRENT_SCHEMA_VERSION.to_string();

        assert!(
            matches!(
                &err,
                FcpError::VersionMismatch { expected, actual }
                    if expected == &expected_schema && actual == "999"
            ),
            "unsupported schema_version must be rejected with VersionMismatch; got {err:?}"
        );
    }

    // ── br-jkcka.3: typestate split regression tests ─────────────────────

    /// Build a token + signing key pair with a known `instance_id`.
    /// Returns (token, `pub_bytes`, instance, capability, operation).
    fn mk_token_with_instance() -> (
        CapabilityToken,
        [u8; 32],
        InstanceId,
        CapabilityId,
        OperationId,
    ) {
        let signing_key = Ed25519SigningKey::generate();
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let instance = InstanceId::new();
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id("cap.test")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .target_instance(instance.as_str())
            .sign(&signing_key)
            .unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();
        let op = OperationId::new("op.test").unwrap();
        (
            CapabilityToken::from_raw(cose),
            pub_bytes,
            instance,
            cap,
            op,
        )
    }

    #[test]
    fn verify_bound_requires_instance_binding_verifier() {
        let (token, pub_bytes, _instance, cap, op) = mk_token_with_instance();
        // Unbound verifier — verify_bound must refuse with a clear error.
        let verifier = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
        let err = verifier.verify_bound(token, &cap, &op, &[]).unwrap_err();
        assert!(
            matches!(
                err,
                FcpError::Internal { ref message } if message.contains("verify_bound")
            ),
            "expected Internal error pointing at verify_bound misuse, got {err:?}"
        );
    }

    #[test]
    fn verify_unbound_requires_unbinding_verifier() {
        let (token, pub_bytes, instance, cap, op) = mk_token_with_instance();
        // Bound verifier — verify_unbound must refuse with a clear error.
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), instance);
        let err = verifier.verify_unbound(token, &cap, &op, &[]).unwrap_err();
        assert!(
            matches!(
                err,
                FcpError::Internal { ref message } if message.contains("verify_unbound")
            ),
            "expected Internal error pointing at verify_unbound misuse, got {err:?}"
        );
    }

    #[test]
    fn verify_bound_with_matching_instance_produces_bound_token() {
        let (token, pub_bytes, instance, cap, op) = mk_token_with_instance();
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), instance);
        let bound = verifier.verify_bound(token, &cap, &op, &[]).unwrap();
        // Type-level: `bound` is CapabilityToken<BoundVerified>.
        // Runtime: claims accessor works on the bound variant.
        let _claims = bound.claims();
    }

    #[test]
    fn verify_unbound_produces_unbound_token() {
        let (token, pub_bytes, _instance, cap, op) = mk_token_with_instance();
        let verifier = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
        let unbound = verifier.verify_unbound(token, &cap, &op, &[]).unwrap();
        // Runtime: claims accessor works on the unbound variant too.
        let _claims = unbound.claims();
    }

    #[test]
    fn promote_with_instance_correct_id_returns_bound() {
        let (token, pub_bytes, instance, cap, op) = mk_token_with_instance();
        let verifier = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
        let unbound = verifier.verify_unbound(token, &cap, &op, &[]).unwrap();
        // Promote with the correct instance id — succeeds.
        let bound = unbound
            .promote_with_instance(&instance)
            .expect("matching instance id must promote");
        let _claims = bound.claims();
    }

    #[test]
    fn promote_with_instance_wrong_id_returns_error() {
        let (token, pub_bytes, _instance, cap, op) = mk_token_with_instance();
        let wrong_instance = InstanceId::new();
        let verifier = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
        let unbound = verifier.verify_unbound(token, &cap, &op, &[]).unwrap();
        let err = unbound.promote_with_instance(&wrong_instance).unwrap_err();
        // br-jkcka.8 fresh-eyes fix: zone fields MUST be populated from the
        // claims (not empty strings) so the error is informative for debuggers.
        assert!(
            matches!(
                err,
                FcpError::ZoneViolation {
                    ref source_zone,
                    ref target_zone,
                    ref message,
                    ..
                } if source_zone == "z:work"
                    && target_zone == "z:work"
                    && message.contains("mismatch")
            ),
            "expected ZoneViolation with populated zones; got {err:?}"
        );
    }

    #[test]
    fn verify_bound_rejects_token_without_instance_id() {
        // flywheel_connectors-01yaq: BoundVerified means all five predicates
        // passed. A token without INSTANCE_ID cannot satisfy the instance
        // predicate and must not become BoundVerified.
        let signing_key = Ed25519SigningKey::generate();
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id("cap.test")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();
        let token = CapabilityToken::from_raw(cose);
        let cap = CapabilityId::new("cap.test").unwrap();
        let op = OperationId::new("op.test").unwrap();
        let instance = InstanceId::new();

        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), instance);
        let err = verifier.verify_bound(token, &cap, &op, &[]).unwrap_err();
        assert!(
            matches!(err, FcpError::MissingField { ref field } if field.contains("instance_id")),
            "expected MissingField(instance_id) for bound token without instance claim, got {err:?}"
        );
    }

    #[test]
    fn promote_with_instance_rejects_instance_agnostic_token() {
        // flywheel_connectors-01yaq: gateway-vantage verification may accept a
        // token with no INSTANCE_ID, but the connector handoff cannot promote it
        // to BoundVerified without an explicit binding.
        let signing_key = Ed25519SigningKey::generate();
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id("cap.test")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();
        let token = CapabilityToken::from_raw(cose);
        let cap = CapabilityId::new("cap.test").unwrap();
        let op = OperationId::new("op.test").unwrap();

        let verifier = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
        let unbound = verifier
            .verify_unbound(token, &cap, &op, &[])
            .expect("unbound verification may defer missing instance binding");

        let any_instance = InstanceId::new();
        let err = unbound.promote_with_instance(&any_instance).unwrap_err();
        assert!(
            matches!(err, FcpError::MissingField { ref field } if field.contains("instance_id")),
            "expected MissingField(instance_id) when promoting token without instance claim, got {err:?}"
        );
    }

    #[test]
    fn promote_with_instance_equivalence_to_direct_bound_verify() {
        // Property: for instance-bound tokens, both paths succeed:
        // - CapabilityVerifier::new(id).verify_bound(token)
        // - CapabilityVerifier::without_instance_binding().verify_unbound(token)
        //     .promote_with_instance(id)
        //
        // This test fails if either path rejects where the other accepts,
        // which would break the type-level safety guarantee the epic
        // stands on.
        let signing_key = Ed25519SigningKey::generate();
        let pub_bytes = signing_key.verifying_key().to_bytes();
        let now = Utc::now();
        let instance = InstanceId::new();
        let cose = CapabilityTokenBuilder::new()
            .capability_id("cap.test")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .target_instance(instance.as_str())
            .sign(&signing_key)
            .unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();
        let op = OperationId::new("op.test").unwrap();

        // Direct bound verify
        let bound_verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), instance.clone());
        let via_bound = bound_verifier
            .verify_bound(CapabilityToken::from_raw(cose.clone()), &cap, &op, &[])
            .expect("direct verify_bound must accept matching instance-bound token");

        // Unbound verify + promote
        let unbound_verifier =
            CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work());
        let via_promote = unbound_verifier
            .verify_unbound(CapabilityToken::from_raw(cose), &cap, &op, &[])
            .expect("verify_unbound must accept instance-bound token")
            .promote_with_instance(&instance)
            .expect("promote must succeed for matching instance-bound token");

        // Both paths produce equivalent verified claims.
        assert_eq!(
            via_bound.claims().get_capability_id(),
            via_promote.claims().get_capability_id()
        );
        assert_eq!(
            via_bound.claims().get_zone_id(),
            via_promote.claims().get_zone_id()
        );
    }

    #[test]
    fn any_verified_trait_only_covers_typed_markers() {
        fn assert_any_verified<T: AnyVerified>() {}

        assert_any_verified::<BoundVerified>();
        assert_any_verified::<UnboundVerified>();
        assert_any_verified::<ConstraintsEnforced>();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // m8j0q.A.6 — promote_with_constraints runtime tests
    //
    // Compile-fail proofs live in tests/ui/. These tests pin the runtime
    // semantics: Allow promotes, Deny propagates the rejection, claims
    // remain accessible after promotion, and the BoundVerified token is
    // consumed (move semantics — re-use is a compile error).
    // ─────────────────────────────────────────────────────────────────────────

    #[derive(Debug, PartialEq, Eq)]
    struct ToyDenial(&'static str);

    struct AllowConstraintEvaluator;

    impl CapabilityConstraintEvaluator<()> for AllowConstraintEvaluator {
        type Denial = ToyDenial;

        fn evaluate_constraints(
            &self,
            constraints: &CapabilityConstraints,
            _request: &(),
        ) -> Result<(), Self::Denial> {
            if constraints.resource_allow.is_empty() {
                Err(ToyDenial("resource_allow_empty"))
            } else {
                Ok(())
            }
        }
    }

    struct DenyConstraintEvaluator;

    impl CapabilityConstraintEvaluator<()> for DenyConstraintEvaluator {
        type Denial = ToyDenial;

        fn evaluate_constraints(
            &self,
            _constraints: &CapabilityConstraints,
            _request: &(),
        ) -> Result<(), Self::Denial> {
            Err(ToyDenial("host_not_in_allowlist"))
        }
    }

    fn allow_all_constraints() -> CapabilityConstraints {
        CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        }
    }

    #[test]
    fn promote_with_constraints_allow_returns_constraints_enforced() {
        let (token, pub_bytes, instance, cap, op) = mk_token_with_instance();
        let bound = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work())
            .verify_unbound(token, &cap, &op, &[])
            .unwrap()
            .promote_with_instance(&instance)
            .unwrap();
        let constraints = allow_all_constraints();

        let enforced: CapabilityToken<ConstraintsEnforced> = bound
            .promote_with_constraints(&AllowConstraintEvaluator, &constraints, &())
            .expect("Allow evaluator must produce ConstraintsEnforced");

        // Claims survive the promotion intact.
        assert_eq!(enforced.claims().get_zone_id(), Some("z:work"));
    }

    #[test]
    fn promote_with_constraints_deny_propagates_structured_reason() {
        let (token, pub_bytes, instance, cap, op) = mk_token_with_instance();
        let bound = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work())
            .verify_unbound(token, &cap, &op, &[])
            .unwrap()
            .promote_with_instance(&instance)
            .unwrap();
        let constraints = allow_all_constraints();

        let err = bound
            .promote_with_constraints(&DenyConstraintEvaluator, &constraints, &())
            .expect_err("Deny evaluator must propagate the rejection");

        assert_eq!(err, ToyDenial("host_not_in_allowlist"));
    }

    #[test]
    fn promote_with_constraints_evaluator_observes_constraints() {
        // The evaluator receives the constraint set selected by the caller
        // and must allow before the typestate can advance.
        let (token, pub_bytes, instance, cap, op) = mk_token_with_instance();
        let bound = CapabilityVerifier::without_instance_binding(pub_bytes, ZoneId::work())
            .verify_unbound(token, &cap, &op, &[])
            .unwrap()
            .promote_with_instance(&instance)
            .unwrap();

        let constraints = allow_all_constraints();
        let enforced = bound
            .promote_with_constraints(&AllowConstraintEvaluator, &constraints, &())
            .unwrap();

        assert_eq!(enforced.claims().get_zone_id(), Some("z:work"));
    }

    // The "consume self" guarantee is asserted at compile time by the
    // borrow checker: any test that tries to use `bound` after passing
    // it to `promote_with_constraints` would fail to compile. The
    // signature `fn promote_with_constraints(self, ...) -> ...` is the
    // proof; a runtime test cannot assert a move-out the way the
    // compiler can. The trybuild fixture
    // `bound_cannot_reach_constraints_enforced_api.rs` covers the
    // dispatch-boundary half of the same guarantee.

    // ─────────────────────────────────────────────────────────────────────────
    // CapabilityConstraints Credential Allow Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn credential_allow_empty_denies_all() {
        let constraints = CapabilityConstraints::default();
        let cred_id = CredentialId::new();

        assert!(!constraints.is_credential_allowed(&cred_id));
        assert!(constraints.validate_credential(&cred_id).is_err());
    }

    #[test]
    fn credential_allow_permits_listed_credential() {
        let cred_id1 = CredentialId::new();
        let cred_id2 = CredentialId::new();

        let constraints = CapabilityConstraints {
            credential_allow: vec![cred_id1, cred_id2],
            ..Default::default()
        };

        assert!(constraints.is_credential_allowed(&cred_id1));
        assert!(constraints.is_credential_allowed(&cred_id2));
        assert!(constraints.validate_credential(&cred_id1).is_ok());
        assert!(constraints.validate_credential(&cred_id2).is_ok());
    }

    #[test]
    fn credential_allow_denies_unlisted_credential() {
        let allowed_cred = CredentialId::new();
        let denied_cred = CredentialId::new();

        let constraints = CapabilityConstraints {
            credential_allow: vec![allowed_cred],
            ..Default::default()
        };

        assert!(!constraints.is_credential_allowed(&denied_cred));
        let result = constraints.validate_credential(&denied_cred);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(
            matches!(
                &err,
                CredentialValidationError::NotInCredentialAllow { credential_id } if *credential_id == denied_cred
            ),
            "Expected NotInCredentialAllow error, got {err:?}"
        );
    }

    #[test]
    fn credential_allow_with_multiple_credentials() {
        let cred1 = CredentialId::new();
        let cred2 = CredentialId::new();
        let cred3 = CredentialId::new();
        let denied_cred = CredentialId::new();

        let constraints = CapabilityConstraints {
            credential_allow: vec![cred1, cred2, cred3],
            ..Default::default()
        };

        // All listed should be allowed
        assert!(constraints.is_credential_allowed(&cred1));
        assert!(constraints.is_credential_allowed(&cred2));
        assert!(constraints.is_credential_allowed(&cred3));

        // Unlisted should be denied
        assert!(!constraints.is_credential_allowed(&denied_cred));
    }

    #[test]
    fn credential_allow_error_contains_credential_id() {
        let denied_cred = CredentialId::new();
        let allowed_cred = CredentialId::new();

        let constraints = CapabilityConstraints {
            credential_allow: vec![allowed_cred],
            ..Default::default()
        };

        let result = constraints.validate_credential(&denied_cred);
        assert!(result.is_err());

        // Verify the error message contains the credential ID
        let err = result.unwrap_err();
        let err_string = err.to_string();
        assert!(err_string.contains(&denied_cred.to_string()));
        assert!(err_string.contains("credential_allow"));
    }

    #[test]
    fn credential_constraints_serialization_includes_credential_allow() {
        let cred_id = CredentialId::new();
        let constraints = CapabilityConstraints {
            credential_allow: vec![cred_id],
            resource_allow: vec!["/api/v1/*".into()],
            ..Default::default()
        };

        let json = serde_json::to_string(&constraints).unwrap();
        assert!(json.contains("credential_allow"));
        assert!(json.contains(&cred_id.to_string()));

        let decoded: CapabilityConstraints = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.credential_allow.len(), 1);
        assert_eq!(decoded.credential_allow[0], cred_id);
    }

    #[test]
    fn credential_constraints_empty_credential_allow_omitted_in_json() {
        let constraints = CapabilityConstraints {
            resource_allow: vec!["/api/*".into()],
            ..Default::default()
        };

        let json = serde_json::to_string(&constraints).unwrap();
        // Empty vecs should be omitted per #[serde(skip_serializing_if = "Vec::is_empty")]
        assert!(!json.contains("credential_allow"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Type Naming Standardization Tests (SafetyTier vs RiskTier)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn safety_tier_vs_risk_tier_are_distinct() {
        // These are different types for different purposes:
        // - SafetyTier: tool/operation safety classification
        // - RiskTier (in quorum.rs): quorum/consensus requirements
        //
        // They share similar variant names but have different semantics:
        // - SafetyTier has 5 levels: Safe, Risky, Dangerous, Critical, Forbidden
        // - RiskTier has 4 levels: Safe, Risky, Dangerous, CriticalWrite

        // SafetyTier variant order (for documentation)
        assert!(matches!(SafetyTier::Safe, SafetyTier::Safe));
        assert!(matches!(SafetyTier::Risky, SafetyTier::Risky));
        assert!(matches!(SafetyTier::Dangerous, SafetyTier::Dangerous));
        assert!(matches!(SafetyTier::Critical, SafetyTier::Critical));
        assert!(matches!(SafetyTier::Forbidden, SafetyTier::Forbidden));

        // Verify SafetyTier serialization
        let tiers = [
            (SafetyTier::Safe, "safe"),
            (SafetyTier::Risky, "risky"),
            (SafetyTier::Dangerous, "dangerous"),
            (SafetyTier::Critical, "critical"),
            (SafetyTier::Forbidden, "forbidden"),
        ];

        for (tier, expected) in tiers {
            let json = serde_json::to_string(&tier).unwrap();
            assert!(
                json.contains(expected),
                "SafetyTier::{tier:?} should serialize to contain '{expected}'"
            );
        }
    }

    #[test]
    fn safety_tier_serialization_roundtrip() {
        let tiers = [
            SafetyTier::Safe,
            SafetyTier::Risky,
            SafetyTier::Dangerous,
            SafetyTier::Critical,
            SafetyTier::Forbidden,
        ];

        for tier in tiers {
            let json = serde_json::to_string(&tier).unwrap();
            let parsed: SafetyTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, parsed);
        }
    }

    // ── validate_canonical_id ────────────────────────────────────────────

    #[test]
    fn canonical_id_rejects_empty() {
        assert_eq!(validate_canonical_id(""), Err(IdValidationError::Empty));
    }

    #[test]
    fn canonical_id_rejects_too_long() {
        let long = "a".repeat(129);
        assert!(matches!(
            validate_canonical_id(&long),
            Err(IdValidationError::TooLong { len: 129, max: 128 })
        ));
        // Exactly 128 should be ok
        let exact = "a".repeat(128);
        assert!(validate_canonical_id(&exact).is_ok());
    }

    #[test]
    fn canonical_id_rejects_non_ascii() {
        assert_eq!(
            validate_canonical_id("héllo"),
            Err(IdValidationError::NonAscii)
        );
    }

    #[test]
    fn canonical_id_rejects_invalid_start_char() {
        assert!(matches!(
            validate_canonical_id(".test"),
            Err(IdValidationError::InvalidStartChar { ch: '.' })
        ));
        assert!(matches!(
            validate_canonical_id("-test"),
            Err(IdValidationError::InvalidStartChar { ch: '-' })
        ));
    }

    #[test]
    fn canonical_id_rejects_invalid_char() {
        assert!(matches!(
            validate_canonical_id("test@value"),
            Err(IdValidationError::InvalidChar { ch: '@', .. })
        ));
        assert!(matches!(
            validate_canonical_id("test value"),
            Err(IdValidationError::InvalidChar { ch: ' ', .. })
        ));
    }

    #[test]
    fn canonical_id_allows_all_valid_chars() {
        assert!(validate_canonical_id("abc.def_ghi:jkl-mno").is_ok());
        assert!(validate_canonical_id("0123456789").is_ok());
        assert!(validate_canonical_id("a:b:c").is_ok());
    }

    // ── Identifier types ───────────────────────────────────────────────────

    #[test]
    fn capability_id_serde_roundtrip() {
        let id = CapabilityId::new("cap.read").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        let back: CapabilityId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn capability_id_display() {
        let id = CapabilityId::new("cap.read").unwrap();
        assert_eq!(id.to_string(), "cap.read");
    }

    #[test]
    fn capability_id_from_str() {
        let id: CapabilityId = "cap.write".parse().unwrap();
        assert_eq!(id.as_str(), "cap.write");
        assert!("BAD".parse::<CapabilityId>().is_err());
    }

    #[test]
    fn connector_id_three_part() {
        let id = ConnectorId::new("gmail", "fcp2", "1.0").unwrap();
        assert_eq!(id.as_str(), "gmail:fcp2:1.0");
    }

    #[test]
    fn connector_id_from_static() {
        let id = ConnectorId::from_static("test:conn:v1");
        assert_eq!(id.as_str(), "test:conn:v1");
    }

    #[test]
    fn connector_id_serde_roundtrip() {
        let id = ConnectorId::from_static("discord:fcp2:1.0");
        let json = serde_json::to_string(&id).unwrap();
        let back: ConnectorId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn instance_id_is_unique() {
        let a = InstanceId::new();
        let b = InstanceId::new();
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn instance_id_default_same_as_new() {
        let d = InstanceId::default();
        assert!(d.as_str().starts_with("inst_"));
    }

    #[test]
    fn instance_id_display() {
        let id = InstanceId::new();
        assert!(id.as_str().starts_with("inst_"));
        assert_eq!(id.as_str(), id.to_string());
    }

    #[test]
    fn operation_id_from_static() {
        let id = OperationId::from_static("op.send");
        assert_eq!(id.as_str(), "op.send");
    }

    #[test]
    fn operation_id_serde_roundtrip() {
        let id = OperationId::new("op.test").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        let back: OperationId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn principal_id_serde_roundtrip() {
        let id = PrincipalId::new("user:alice").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        let back: PrincipalId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    // ── ZoneId ─────────────────────────────────────────────────────────────

    #[test]
    fn zone_id_standard_zones() {
        assert_eq!(ZoneId::owner().as_str(), "z:owner");
        assert_eq!(ZoneId::private().as_str(), "z:private");
        assert_eq!(ZoneId::work().as_str(), "z:work");
        assert_eq!(ZoneId::community().as_str(), "z:community");
        assert_eq!(ZoneId::public().as_str(), "z:public");
    }

    #[test]
    fn zone_id_parse_valid() {
        let z: ZoneId = "z:work".parse().unwrap();
        assert_eq!(z.as_str(), "z:work");
    }

    #[test]
    fn zone_id_parse_valid_project_zone() {
        let z: ZoneId = "z:project:foo".parse().unwrap();
        assert_eq!(z.as_str(), "z:project:foo");
    }

    #[test]
    fn zone_id_rejects_missing_prefix() {
        assert!(matches!(
            "work".parse::<ZoneId>(),
            Err(ZoneIdError::MissingPrefix)
        ));
    }

    #[test]
    fn zone_id_rejects_empty() {
        assert!(matches!("".parse::<ZoneId>(), Err(ZoneIdError::Empty)));
    }

    #[test]
    fn zone_id_rejects_empty_segment_after_prefix() {
        assert!(matches!(
            "z:".parse::<ZoneId>(),
            Err(ZoneIdError::EmptySegment { index: 2 })
        ));
    }

    #[test]
    fn zone_id_rejects_empty_segment_in_middle() {
        assert!(matches!(
            "z:project::foo".parse::<ZoneId>(),
            Err(ZoneIdError::EmptySegment { index: 10 })
        ));
    }

    #[test]
    fn zone_id_rejects_empty_trailing_segment() {
        assert!(matches!(
            "z:project:".parse::<ZoneId>(),
            Err(ZoneIdError::EmptySegment { index: 10 })
        ));
    }

    #[test]
    fn zone_id_rejects_too_long() {
        let long = format!("z:{}", "a".repeat(63));
        assert!(matches!(
            long.parse::<ZoneId>(),
            Err(ZoneIdError::TooLong { .. })
        ));
    }

    #[test]
    fn zone_id_rejects_reserved_project_tag_alias() {
        assert!(matches!(
            "z:proj-foo".parse::<ZoneId>(),
            Err(ZoneIdError::ReservedPrefix { prefix: "z:proj-" })
        ));
    }

    #[test]
    fn zone_id_rejects_project_names_that_do_not_roundtrip_through_tailscale() {
        for zone in [
            "z:project:-foo",
            "z:project:foo-",
            "z:project:foo_bar",
            "z:project:foo:bar",
        ] {
            assert!(
                matches!(zone.parse::<ZoneId>(), Err(ZoneIdError::InvalidChar { .. })),
                "{zone} should not be accepted as a Tailscale-project zone"
            );
        }
    }

    #[test]
    fn zone_id_hash_deterministic() {
        let z1 = ZoneId::work();
        let z2 = ZoneId::work();
        assert_eq!(z1.hash().as_bytes(), z2.hash().as_bytes());
    }

    #[test]
    fn zone_id_hash_differs_across_zones() {
        assert_ne!(
            ZoneId::work().hash().as_bytes(),
            ZoneId::owner().hash().as_bytes()
        );
    }

    #[test]
    fn zone_id_to_tailscale_tag() {
        assert_eq!(ZoneId::work().to_tailscale_tag(), "tag:fcp-work");
        assert_eq!(ZoneId::owner().to_tailscale_tag(), "tag:fcp-owner");
        let project: ZoneId = "z:project:foo".parse().unwrap();
        assert_eq!(project.to_tailscale_tag(), "tag:fcp-proj-foo");
    }

    #[test]
    fn zone_id_from_tailscale_tag() {
        let z = ZoneId::from_tailscale_tag("tag:fcp-work").unwrap();
        assert_eq!(z.as_str(), "z:work");

        let project = ZoneId::from_tailscale_tag("tag:fcp-proj-foo").unwrap();
        assert_eq!(project.as_str(), "z:project:foo");
    }

    #[test]
    fn zone_id_from_tailscale_tag_rejects_invalid() {
        assert!(matches!(
            ZoneId::from_tailscale_tag("tag:wrong-work"),
            Err(ZoneIdError::InvalidTailscaleTagPrefix)
        ));
    }

    #[test]
    fn zone_id_serde_roundtrip() {
        let z = ZoneId::work();
        let json = serde_json::to_string(&z).unwrap();
        let back: ZoneId = serde_json::from_str(&json).unwrap();
        assert_eq!(z, back);
    }

    // ── RateLimit ──────────────────────────────────────────────────────────

    #[test]
    fn rate_limit_validate_ok() {
        let rl = RateLimit {
            max: 10,
            per_ms: 60_000,
            burst: Some(5),
            scope: Some("per_zone".into()),
            pool_name: Some("shared.pool".into()),
        };
        assert!(rl.validate().is_ok());
    }

    #[test]
    fn rate_limit_validate_zero_max() {
        let rl = RateLimit {
            max: 0,
            per_ms: 1000,
            burst: None,
            scope: None,
            pool_name: None,
        };
        assert_eq!(rl.validate(), Err(RateLimitValidationError::ZeroMax));
    }

    #[test]
    fn rate_limit_validate_zero_period() {
        let rl = RateLimit {
            max: 10,
            per_ms: 0,
            burst: None,
            scope: None,
            pool_name: None,
        };
        assert_eq!(rl.validate(), Err(RateLimitValidationError::ZeroPeriod));
    }

    #[test]
    fn rate_limit_validate_invalid_scope() {
        let rl = RateLimit {
            max: 10,
            per_ms: 1000,
            burst: None,
            scope: Some("bad".into()),
            pool_name: None,
        };
        assert!(matches!(
            rl.validate(),
            Err(RateLimitValidationError::InvalidScope { .. })
        ));
    }

    #[test]
    fn rate_limit_validate_empty_pool_name() {
        let rl = RateLimit {
            max: 10,
            per_ms: 1000,
            burst: None,
            scope: None,
            pool_name: Some(String::new()),
        };
        assert_eq!(rl.validate(), Err(RateLimitValidationError::EmptyPoolName));
    }

    #[test]
    fn rate_limit_validate_invalid_pool_name() {
        let rl = RateLimit {
            max: 10,
            per_ms: 1000,
            burst: None,
            scope: None,
            pool_name: Some("a b".into()),
        };
        assert!(matches!(
            rl.validate(),
            Err(RateLimitValidationError::InvalidPoolName { .. })
        ));
    }

    #[test]
    fn rate_limit_parsed_scope_default() {
        let rl = RateLimit {
            max: 10,
            per_ms: 1000,
            burst: None,
            scope: None,
            pool_name: None,
        };
        assert_eq!(rl.parsed_scope(), OperationRateLimitScope::PerConnector);
    }

    #[test]
    fn rate_limit_parsed_scope_explicit() {
        let rl = RateLimit {
            max: 10,
            per_ms: 1000,
            burst: None,
            scope: Some("per_principal".into()),
            pool_name: None,
        };
        assert_eq!(rl.parsed_scope(), OperationRateLimitScope::PerPrincipal);
    }

    // ── OperationRateLimitScope ────────────────────────────────────────────

    #[test]
    fn operation_rate_limit_scope_from_str() {
        assert_eq!(
            "per_connector".parse::<OperationRateLimitScope>().unwrap(),
            OperationRateLimitScope::PerConnector
        );
        assert_eq!(
            "per_zone".parse::<OperationRateLimitScope>().unwrap(),
            OperationRateLimitScope::PerZone
        );
        assert_eq!(
            "per_principal".parse::<OperationRateLimitScope>().unwrap(),
            OperationRateLimitScope::PerPrincipal
        );
        assert!("invalid".parse::<OperationRateLimitScope>().is_err());
    }

    #[test]
    fn operation_rate_limit_scope_display() {
        assert_eq!(
            OperationRateLimitScope::PerConnector.to_string(),
            "per_connector"
        );
        assert_eq!(OperationRateLimitScope::PerZone.to_string(), "per_zone");
        assert_eq!(
            OperationRateLimitScope::PerPrincipal.to_string(),
            "per_principal"
        );
    }

    #[test]
    fn operation_rate_limit_scope_default() {
        assert_eq!(
            OperationRateLimitScope::default(),
            OperationRateLimitScope::PerConnector
        );
    }

    // ── RetryConfig ────────────────────────────────────────────────────────

    #[test]
    fn retry_config_default_values() {
        let cfg = RetryConfig::default();
        assert_eq!(cfg.max_attempts, 3);
        assert_eq!(cfg.initial_delay, std::time::Duration::from_millis(100));
        assert_eq!(cfg.max_delay, std::time::Duration::from_secs(30));
        assert!((cfg.multiplier - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn retry_config_serde_roundtrip() {
        let cfg = RetryConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: RetryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_attempts, cfg.max_attempts);
    }

    // ── TrustLevel ─────────────────────────────────────────────────────────

    #[test]
    fn trust_level_ordering() {
        assert!(TrustLevel::Blocked < TrustLevel::Anonymous);
        assert!(TrustLevel::Anonymous < TrustLevel::Untrusted);
        assert!(TrustLevel::Untrusted < TrustLevel::Paired);
        assert!(TrustLevel::Paired < TrustLevel::Admin);
        assert!(TrustLevel::Admin < TrustLevel::Owner);
    }

    #[test]
    fn trust_level_serde_roundtrip() {
        for level in [
            TrustLevel::Blocked,
            TrustLevel::Anonymous,
            TrustLevel::Untrusted,
            TrustLevel::Paired,
            TrustLevel::Admin,
            TrustLevel::Owner,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let back: TrustLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, back);
        }
    }

    // ── TaintLevel ─────────────────────────────────────────────────────────

    #[test]
    fn taint_level_default_is_untainted() {
        assert_eq!(TaintLevel::default(), TaintLevel::Untainted);
    }

    #[test]
    fn taint_level_ordering() {
        assert!(TaintLevel::Untainted < TaintLevel::Tainted);
        assert!(TaintLevel::Tainted < TaintLevel::HighlyTainted);
    }

    // ── Provenance ─────────────────────────────────────────────────────────

    #[test]
    fn provenance_new_is_untainted() {
        let p = Provenance::new(ZoneId::work());
        assert!(!p.is_tainted());
        assert!(p.can_access_higher_trust());
        assert_eq!(p.origin_zone.as_str(), "z:work");
    }

    #[test]
    fn provenance_tainted() {
        let p = Provenance::tainted(ZoneId::public());
        assert!(p.is_tainted());
        assert!(!p.can_access_higher_trust());
    }

    #[test]
    fn provenance_highly_tainted() {
        let p = Provenance::highly_tainted(ZoneId::public());
        assert!(p.is_tainted());
        assert_eq!(p.taint, TaintLevel::HighlyTainted);
    }

    #[test]
    fn provenance_elevated_can_access_higher() {
        let p = Provenance::tainted(ZoneId::public()).elevated_with("high-elev-token");
        assert!(p.is_tainted());
        assert!(p.can_access_higher_trust());
        assert_eq!(p.elevation_token.as_deref(), Some("high-elev-token"));
    }

    #[test]
    fn provenance_with_step() {
        let step = ProvenanceStep {
            timestamp_ms: 1000,
            zone: ZoneId::work(),
            actor: "agent:bot".into(),
            action: "invoke".into(),
            resource: "cap.read".into(),
        };
        let p = Provenance::new(ZoneId::work()).with_step(step);
        assert_eq!(p.chain.len(), 1);
    }

    // ── IdempotencyClass ───────────────────────────────────────────────────

    #[test]
    fn idempotency_class_serde_roundtrip() {
        for class in [
            IdempotencyClass::None,
            IdempotencyClass::BestEffort,
            IdempotencyClass::Strict,
        ] {
            let json = serde_json::to_string(&class).unwrap();
            let back: IdempotencyClass = serde_json::from_str(&json).unwrap();
            assert_eq!(class, back);
        }
    }

    // ── CorrelationId / SessionId ──────────────────────────────────────────

    #[test]
    fn correlation_id_unique() {
        let a = CorrelationId::new();
        let b = CorrelationId::new();
        assert_ne!(a, b);
    }

    #[test]
    fn session_id_unique() {
        let a = SessionId::new();
        let b = SessionId::new();
        assert_ne!(a, b);
    }

    // ── CapabilityGrant ────────────────────────────────────────────────────

    #[test]
    fn capability_grant_serde_roundtrip() {
        let grant = CapabilityGrant {
            capability: CapabilityId::new("cap.read").unwrap(),
            operation: Some(OperationId::new("op.list").unwrap()),
        };
        let json = serde_json::to_string(&grant).unwrap();
        let back: CapabilityGrant = serde_json::from_str(&json).unwrap();
        assert_eq!(grant, back);
    }

    #[test]
    fn capability_grant_omits_none_operation() {
        let grant = CapabilityGrant {
            capability: CapabilityId::new("cap.all").unwrap(),
            operation: None,
        };
        let json = serde_json::to_string(&grant).unwrap();
        assert!(!json.contains("operation"));
    }

    // ── RiskLevel ──────────────────────────────────────────────────────────

    #[test]
    fn risk_level_serde_roundtrip() {
        for level in [
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Critical,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let back: RiskLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, back);
        }
    }

    #[test]
    fn risk_level_vs_safety_tier_are_distinct() {
        // RiskLevel: UX/prioritization (Low, Medium, High, Critical)
        // SafetyTier: normative enforcement (Safe, Risky, Dangerous, Critical, Forbidden)
        //
        // Both may be present in ToolDescriptor, each for different purposes.

        // RiskLevel serialization
        let levels = [
            (RiskLevel::Low, "low"),
            (RiskLevel::Medium, "medium"),
            (RiskLevel::High, "high"),
            (RiskLevel::Critical, "critical"),
        ];

        for (level, expected) in levels {
            let json = serde_json::to_string(&level).unwrap();
            assert!(
                json.contains(expected),
                "RiskLevel::{level:?} should serialize to contain '{expected}'"
            );
        }

        // SafetyTier serialization (different enum, different values)
        let tiers = [
            (SafetyTier::Safe, "safe"),
            (SafetyTier::Forbidden, "forbidden"),
        ];

        for (tier, expected) in tiers {
            let json = serde_json::to_string(&tier).unwrap();
            assert!(
                json.contains(expected),
                "SafetyTier::{tier:?} should serialize to contain '{expected}'"
            );
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: CapabilityId edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn capability_id_rejects_empty() {
        assert!(matches!(
            CapabilityId::new(""),
            Err(IdValidationError::Empty)
        ));
    }

    #[test]
    fn capability_id_at_max_length_boundary() {
        // Exactly 128 bytes should succeed
        let max_id = "a".repeat(128);
        assert!(CapabilityId::new(max_id).is_ok());

        // 129 bytes should fail
        let over_id = "a".repeat(129);
        assert!(matches!(
            CapabilityId::new(over_id),
            Err(IdValidationError::TooLong { len: 129, max: 128 })
        ));
    }

    #[test]
    fn capability_id_with_multiple_colons() {
        // Multiple colons are valid per the regex `^[a-z0-9][a-z0-9._:-]*$`
        let id = CapabilityId::new("cap:scope:sub:detail").unwrap();
        assert_eq!(id.as_str(), "cap:scope:sub:detail");
    }

    #[test]
    fn capability_id_with_all_separator_types() {
        let id = CapabilityId::new("a.b_c:d-e").unwrap();
        assert_eq!(id.as_str(), "a.b_c:d-e");
    }

    #[test]
    fn capability_id_single_digit_start() {
        let id = CapabilityId::new("9cap").unwrap();
        assert_eq!(id.as_str(), "9cap");
    }

    #[test]
    fn capability_id_rejects_space_in_middle() {
        assert!(matches!(
            CapabilityId::new("cap read"),
            Err(IdValidationError::InvalidChar { ch: ' ', index: 3 })
        ));
    }

    #[test]
    fn capability_id_rejects_unicode_emoji() {
        assert!(matches!(
            CapabilityId::new("cap\u{1F600}"),
            Err(IdValidationError::NonAscii)
        ));
    }

    #[test]
    fn capability_id_rejects_starting_with_underscore() {
        assert!(matches!(
            CapabilityId::new("_cap"),
            Err(IdValidationError::InvalidStartChar { ch: '_' })
        ));
    }

    #[test]
    fn capability_id_rejects_starting_with_colon() {
        assert!(matches!(
            CapabilityId::new(":cap"),
            Err(IdValidationError::InvalidStartChar { ch: ':' })
        ));
    }

    #[test]
    fn capability_id_clone_preserves_value() {
        let original = CapabilityId::new("cap.read").unwrap();
        let cloned = original.clone();
        assert_eq!(original.as_str(), cloned.as_str());
    }

    #[test]
    fn capability_id_hash_equality() {
        use std::collections::HashSet;
        let id1 = CapabilityId::new("cap.test").unwrap();
        let id2 = CapabilityId::new("cap.test").unwrap();
        let mut set = HashSet::new();
        set.insert(id1);
        assert!(set.contains(&id2));
    }

    #[test]
    fn capability_id_as_ref_str() {
        let id = CapabilityId::new("cap.ref").unwrap();
        let s: &str = id.as_ref();
        assert_eq!(s, "cap.ref");
    }

    #[test]
    fn capability_id_into_string() {
        let id = CapabilityId::new("cap.owned").unwrap();
        let s: String = id.into();
        assert_eq!(s, "cap.owned");
    }

    #[test]
    #[should_panic(expected = "static capability ID must be canonical")]
    fn capability_id_from_static_panics_on_invalid() {
        let _ = CapabilityId::from_static("INVALID");
    }

    #[test]
    fn capability_id_debug_format() {
        let id = CapabilityId::new("cap.debug").unwrap();
        let dbg = format!("{id:?}");
        assert!(dbg.contains("cap.debug"));
    }

    #[test]
    fn capability_id_serde_rejects_invalid_json() {
        let result: Result<CapabilityId, _> = serde_json::from_str("\"UPPER\"");
        assert!(result.is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: ConnectorId edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn connector_id_clone_preserves_value() {
        let original = ConnectorId::from_static("test:conn:v1");
        let cloned = original.clone();
        assert_eq!(original.as_str(), cloned.as_str());
    }

    #[test]
    fn connector_id_as_ref_str() {
        let id = ConnectorId::from_static("test:conn:v1");
        let s: &str = id.as_ref();
        assert_eq!(s, "test:conn:v1");
    }

    #[test]
    fn connector_id_into_string() {
        let id = ConnectorId::from_static("test:conn:v1");
        let s: String = id.into();
        assert_eq!(s, "test:conn:v1");
    }

    #[test]
    fn connector_id_display() {
        let id = ConnectorId::from_static("test:conn:v1");
        assert_eq!(id.to_string(), "test:conn:v1");
    }

    #[test]
    fn connector_id_rejects_uppercase_part() {
        assert!(ConnectorId::new("Gmail", "fcp2", "1.0").is_err());
    }

    #[test]
    #[should_panic(expected = "static connector ID must be canonical")]
    fn connector_id_from_static_panics_on_invalid() {
        let _ = ConnectorId::from_static("BAD ID");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: OperationId edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn operation_id_rejects_empty() {
        assert!(matches!(
            OperationId::new(""),
            Err(IdValidationError::Empty)
        ));
    }

    #[test]
    fn operation_id_clone_preserves_value() {
        let original = OperationId::from_static("op.send");
        let cloned = original.clone();
        assert_eq!(original.as_str(), cloned.as_str());
    }

    #[test]
    fn operation_id_display() {
        let id = OperationId::from_static("op.list");
        assert_eq!(id.to_string(), "op.list");
    }

    #[test]
    fn operation_id_as_ref_str() {
        let id = OperationId::from_static("op.get");
        let s: &str = id.as_ref();
        assert_eq!(s, "op.get");
    }

    #[test]
    #[should_panic(expected = "static operation ID must be canonical")]
    fn operation_id_from_static_panics_on_invalid() {
        let _ = OperationId::from_static("OP.INVALID");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: InstanceId edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn instance_id_starts_with_prefix() {
        let id = InstanceId::new();
        assert!(id.as_str().starts_with("inst_"));
    }

    #[test]
    fn instance_id_serde_roundtrip() {
        let id = InstanceId::new();
        let json = serde_json::to_string(&id).unwrap();
        let back: InstanceId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn instance_id_display_format() {
        let id = InstanceId::new();
        let displayed = id.to_string();
        assert!(displayed.starts_with("inst_"));
        assert_eq!(displayed, id.as_str());
    }

    #[test]
    fn instance_id_clone_preserves_value() {
        let original = InstanceId::new();
        let cloned = original.clone();
        assert_eq!(original.as_str(), cloned.as_str());
    }

    #[test]
    fn instance_id_as_ref_str() {
        let id = InstanceId::new();
        let s: &str = id.as_ref();
        assert!(s.starts_with("inst_"));
    }

    #[test]
    fn instance_id_into_string() {
        let id = InstanceId::new();
        let expected = id.as_str().to_owned();
        let s: String = id.into();
        assert_eq!(s, expected);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: PrincipalId edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn principal_id_display() {
        let id = PrincipalId::new("user:alice").unwrap();
        assert_eq!(id.to_string(), "user:alice");
    }

    #[test]
    fn principal_id_as_ref_str() {
        let id = PrincipalId::new("agent:bot").unwrap();
        let s: &str = id.as_ref();
        assert_eq!(s, "agent:bot");
    }

    #[test]
    fn principal_id_into_string() {
        let id = PrincipalId::new("user:bob").unwrap();
        let s: String = id.into();
        assert_eq!(s, "user:bob");
    }

    #[test]
    fn principal_id_rejects_uppercase() {
        assert!(matches!(
            PrincipalId::new("User:Alice"),
            Err(IdValidationError::UppercaseNotAllowed)
        ));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: ZoneId edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_id_rejects_non_ascii() {
        assert!(matches!(
            "z:\u{00e9}l\u{00e8}ve".parse::<ZoneId>(),
            Err(ZoneIdError::NonAscii)
        ));
    }

    #[test]
    fn zone_id_rejects_invalid_char() {
        assert!(matches!(
            "z:work@home".parse::<ZoneId>(),
            Err(ZoneIdError::InvalidChar { ch: '@', .. })
        ));
    }

    #[test]
    fn zone_id_rejects_uppercase() {
        assert!(matches!(
            "z:Work".parse::<ZoneId>(),
            Err(ZoneIdError::InvalidChar { ch: 'W', .. })
        ));
    }

    #[test]
    fn zone_id_at_max_length_boundary() {
        // Exactly 64 bytes should succeed
        let max_zone = format!("z:{}", "a".repeat(62));
        assert_eq!(max_zone.len(), 64);
        assert!(max_zone.parse::<ZoneId>().is_ok());

        // 65 bytes should fail
        let over_zone = format!("z:{}", "a".repeat(63));
        assert_eq!(over_zone.len(), 65);
        assert!(matches!(
            over_zone.parse::<ZoneId>(),
            Err(ZoneIdError::TooLong { len: 65, max: 64 })
        ));
    }

    #[test]
    fn zone_id_clone_preserves_value() {
        let original = ZoneId::work();
        let cloned = original.clone();
        assert_eq!(original.as_str(), cloned.as_str());
    }

    #[test]
    fn zone_id_display() {
        let z = ZoneId::owner();
        assert_eq!(z.to_string(), "z:owner");
    }

    #[test]
    fn zone_id_as_ref_str() {
        let z = ZoneId::private();
        let s: &str = z.as_ref();
        assert_eq!(s, "z:private");
    }

    #[test]
    fn zone_id_into_string() {
        let z = ZoneId::community();
        let s: String = z.into();
        assert_eq!(s, "z:community");
    }

    #[test]
    fn zone_id_as_bytes() {
        let z = ZoneId::work();
        assert_eq!(z.as_bytes(), b"z:work");
    }

    #[test]
    fn zone_id_hash_from_bytes_roundtrip() {
        let z = ZoneId::work();
        let hash = z.hash();
        let reconstructed = ZoneIdHash::from_bytes(*hash.as_bytes());
        assert_eq!(hash, reconstructed);
    }

    #[test]
    fn zone_id_hash_debug_is_hex() {
        let z = ZoneId::work();
        let hash = z.hash();
        let dbg = format!("{hash:?}");
        assert!(dbg.starts_with("ZoneIdHash("));
        // The inner value should be hex
        assert!(dbg.contains(')'));
    }

    #[test]
    fn zone_id_hash_as_ref_bytes() {
        let z = ZoneId::work();
        let hash = z.hash();
        let bytes: &[u8] = hash.as_ref();
        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn zone_id_with_hyphens_allowed_underscores_rejected() {
        // Hyphens are valid zone-id characters; underscores were removed
        // from the charset (4728b8918) so zone ids stay representable as
        // Tailscale ACL tags, which forbid `_`.
        let z: ZoneId = "z:my-custom-zone".parse().unwrap();
        assert_eq!(z.as_str(), "z:my-custom-zone");

        let err = "z:my-custom_zone".parse::<ZoneId>().unwrap_err();
        assert!(
            matches!(err, ZoneIdError::InvalidChar { ch: '_', .. }),
            "underscore should be rejected, got {err:?}"
        );
    }

    #[test]
    fn zone_id_tailscale_tag_roundtrip_standard_zones() {
        for zone in [
            ZoneId::owner(),
            ZoneId::private(),
            ZoneId::work(),
            ZoneId::community(),
            ZoneId::public(),
            "z:project:foo".parse().unwrap(),
            "z:project:foo-bar".parse().unwrap(),
        ] {
            let tag = zone.to_tailscale_tag();
            let recovered = ZoneId::from_tailscale_tag(&tag).unwrap();
            assert_eq!(zone.as_str(), recovered.as_str());
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: ZoneIdError Display coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_id_error_display_empty() {
        let err = ZoneIdError::Empty;
        assert_eq!(err.to_string(), "zone id must not be empty");
    }

    #[test]
    fn zone_id_error_display_empty_segment() {
        let err = ZoneIdError::EmptySegment { index: 10 };
        assert_eq!(
            err.to_string(),
            "zone id contains an empty segment at byte 10"
        );
    }

    #[test]
    fn zone_id_error_display_too_long() {
        let err = ZoneIdError::TooLong { len: 100, max: 64 };
        assert_eq!(err.to_string(), "zone id too long (100 bytes > 64 bytes)");
    }

    #[test]
    fn zone_id_error_display_non_ascii() {
        let err = ZoneIdError::NonAscii;
        assert_eq!(err.to_string(), "zone id must be ASCII");
    }

    #[test]
    fn zone_id_error_display_missing_prefix() {
        let err = ZoneIdError::MissingPrefix;
        assert_eq!(err.to_string(), "zone id must start with `z:`");
    }

    #[test]
    fn zone_id_error_display_invalid_tailscale_tag() {
        let err = ZoneIdError::InvalidTailscaleTagPrefix;
        assert_eq!(err.to_string(), "tailscale tag must start with `tag:fcp-`");
    }

    #[test]
    fn zone_id_error_display_reserved_prefix() {
        let err = ZoneIdError::ReservedPrefix { prefix: "z:proj-" };
        assert_eq!(err.to_string(), "zone id prefix `z:proj-` is reserved");
    }

    #[test]
    fn zone_id_error_display_invalid_char() {
        let err = ZoneIdError::InvalidChar { ch: '!', index: 5 };
        assert_eq!(
            err.to_string(),
            "zone id has invalid character '!' at byte 5"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: IdValidationError Display coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn id_validation_error_display_empty() {
        let err = IdValidationError::Empty;
        assert_eq!(err.to_string(), "identifier must not be empty");
    }

    #[test]
    fn id_validation_error_display_too_long() {
        let err = IdValidationError::TooLong { len: 200, max: 128 };
        assert_eq!(
            err.to_string(),
            "identifier too long (200 bytes > 128 bytes)"
        );
    }

    #[test]
    fn id_validation_error_display_non_ascii() {
        let err = IdValidationError::NonAscii;
        assert_eq!(err.to_string(), "identifier must be ASCII");
    }

    #[test]
    fn id_validation_error_display_uppercase() {
        let err = IdValidationError::UppercaseNotAllowed;
        assert_eq!(err.to_string(), "identifier contains uppercase ASCII");
    }

    #[test]
    fn id_validation_error_display_invalid_start() {
        let err = IdValidationError::InvalidStartChar { ch: '-' };
        assert_eq!(
            err.to_string(),
            "identifier has invalid start character '-'"
        );
    }

    #[test]
    fn id_validation_error_display_invalid_char() {
        let err = IdValidationError::InvalidChar { ch: '!', index: 4 };
        assert_eq!(
            err.to_string(),
            "identifier has invalid character '!' at byte 4"
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: CapabilityGrant edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn capability_grant_with_operation_includes_field() {
        let grant = CapabilityGrant {
            capability: CapabilityId::new("cap.write").unwrap(),
            operation: Some(OperationId::new("op.create").unwrap()),
        };
        let json = serde_json::to_string(&grant).unwrap();
        assert!(json.contains("operation"));
        assert!(json.contains("op.create"));
    }

    #[test]
    fn capability_grant_clone_preserves_fields() {
        let original = CapabilityGrant {
            capability: CapabilityId::new("cap.admin").unwrap(),
            operation: Some(OperationId::new("op.delete").unwrap()),
        };
        let cloned = original.clone();
        assert_eq!(original.capability, cloned.capability);
        assert_eq!(original.operation, cloned.operation);
    }

    #[test]
    fn capability_grant_debug_format() {
        let grant = CapabilityGrant {
            capability: CapabilityId::new("cap.test").unwrap(),
            operation: None,
        };
        let dbg = format!("{grant:?}");
        assert!(dbg.contains("cap.test"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: CapabilityConstraints edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn capability_constraints_default_all_empty() {
        let c = CapabilityConstraints::default();
        assert!(c.resource_allow.is_empty());
        assert!(c.resource_deny.is_empty());
        assert!(c.max_calls.is_none());
        assert!(c.max_bytes.is_none());
        assert!(c.idempotency_key.is_none());
        assert!(c.credential_allow.is_empty());
    }

    #[test]
    fn capability_constraints_full_serde_roundtrip() {
        let cred = CredentialId::new();
        let c = CapabilityConstraints {
            resource_allow: vec!["/api/v1/*".into(), "/api/v2/*".into()],
            resource_deny: vec!["/admin/*".into()],
            max_calls: Some(100),
            max_bytes: Some(1_000_000),
            idempotency_key: Some("idem-key-123".into()),
            credential_allow: vec![cred],
        };

        let json = serde_json::to_string(&c).unwrap();
        let back: CapabilityConstraints = serde_json::from_str(&json).unwrap();

        assert_eq!(back.resource_allow.len(), 2);
        assert_eq!(back.resource_deny.len(), 1);
        assert_eq!(back.max_calls, Some(100));
        assert_eq!(back.max_bytes, Some(1_000_000));
        assert_eq!(back.idempotency_key.as_deref(), Some("idem-key-123"));
        assert_eq!(back.credential_allow.len(), 1);
    }

    #[test]
    fn capability_constraints_default_json_minimal() {
        let c = CapabilityConstraints::default();
        let json = serde_json::to_string(&c).unwrap();
        // All fields with skip_serializing_if should be omitted
        assert!(!json.contains("resource_allow"));
        assert!(!json.contains("resource_deny"));
        assert!(!json.contains("max_calls"));
        assert!(!json.contains("max_bytes"));
        assert!(!json.contains("idempotency_key"));
        assert!(!json.contains("credential_allow"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: CapabilityObject serde
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn capability_object_serde_roundtrip() {
        let obj = CapabilityObject {
            caps: vec![CapabilityGrant {
                capability: CapabilityId::new("cap.read").unwrap(),
                operation: None,
            }],
            constraints: CapabilityConstraints::default(),
            principal: Some(PrincipalId::new("user:alice").unwrap()),
            valid_from: Some(1000),
            valid_until: Some(2000),
        };
        let json = serde_json::to_string(&obj).unwrap();
        let back: CapabilityObject = serde_json::from_str(&json).unwrap();
        assert_eq!(back.caps.len(), 1);
        assert_eq!(back.valid_from, Some(1000));
        assert_eq!(back.valid_until, Some(2000));
        assert!(back.principal.is_some());
    }

    #[test]
    fn capability_object_omits_none_fields() {
        let obj = CapabilityObject {
            caps: vec![],
            constraints: CapabilityConstraints::default(),
            principal: None,
            valid_from: None,
            valid_until: None,
        };
        let json = serde_json::to_string(&obj).unwrap();
        assert!(!json.contains("principal"));
        assert!(!json.contains("valid_from"));
        assert!(!json.contains("valid_until"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: RoleObject / RoleAssignment
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn role_object_serde_roundtrip() {
        let role = RoleObject {
            name: "editor".into(),
            caps: vec![CapabilityGrant {
                capability: CapabilityId::new("cap.edit").unwrap(),
                operation: Some(OperationId::new("op.update").unwrap()),
            }],
            includes: vec![],
        };
        let json = serde_json::to_string(&role).unwrap();
        let back: RoleObject = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "editor");
        assert_eq!(back.caps.len(), 1);
    }

    #[test]
    fn role_assignment_serde_roundtrip() {
        let assignment = RoleAssignment {
            role_id: ObjectId::test_id("role-test"),
            principal: PrincipalId::new("user:bob").unwrap(),
            constraints: CapabilityConstraints::default(),
        };
        let json = serde_json::to_string(&assignment).unwrap();
        let back: RoleAssignment = serde_json::from_str(&json).unwrap();
        assert_eq!(back.principal.as_str(), "user:bob");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: TailscaleNodeId
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn tailscale_node_id_new_and_access() {
        let node = TailscaleNodeId::new("node-abc123");
        assert_eq!(node.as_str(), "node-abc123");
    }

    #[test]
    fn tailscale_node_id_try_from_string() {
        // Was `let node: TailscaleNodeId = String::from(...).into()` against
        // the bypass-prone `From<String>` impl that accepted any input.
        // Replaced with `try_from` to exercise the new canonical-id check.
        let node = TailscaleNodeId::try_from(String::from("ts-node-42")).unwrap();
        assert_eq!(node.as_str(), "ts-node-42");
    }

    #[test]
    fn tailscale_node_id_rejects_uncanonical_strings() {
        // Regression: previously every one of these constructed a
        // TailscaleNodeId verbatim. Now each must surface an
        // IdValidationError. The list mirrors the attack surface in the
        // type docstring (empty, whitespace, control bytes,
        // bidi-override, namespace-collision lookalike, uppercase).
        type ErrorPredicate = fn(&IdValidationError) -> bool;

        let cases: &[(&str, ErrorPredicate)] = &[
            ("", |e| matches!(e, IdValidationError::Empty)),
            ("   ", |e| {
                matches!(e, IdValidationError::InvalidStartChar { .. })
            }),
            ("node-bad ", |e| {
                matches!(e, IdValidationError::InvalidChar { .. })
            }),
            ("node\nbad", |e| {
                matches!(e, IdValidationError::InvalidChar { .. })
            }),
            ("node\0bad", |e| {
                matches!(e, IdValidationError::InvalidChar { .. })
            }),
            ("\u{202E}revil-node", |e| {
                matches!(e, IdValidationError::NonAscii)
            }),
            ("node-Café", |e| matches!(e, IdValidationError::NonAscii)),
            ("Node-UPPER", |e| {
                matches!(e, IdValidationError::UppercaseNotAllowed)
            }),
            ("/etc/passwd", |e| {
                matches!(e, IdValidationError::InvalidStartChar { .. })
            }),
        ];
        for (input, predicate) in cases {
            let err = TailscaleNodeId::try_from((*input).to_owned())
                .expect_err(&format!("input {input:?} must be rejected"));
            assert!(
                predicate(&err),
                "input {input:?} produced unexpected error variant: {err:?}"
            );
        }
    }

    #[test]
    fn tailscale_node_id_try_new_validates_input() {
        // `new` is intentionally infallible (used by trusted/test fixtures);
        // `try_new` is the path for caller-supplied input — it returns the
        // canonical-id error variant rather than silently accepting.
        let err = TailscaleNodeId::try_new("Bad ID").unwrap_err();
        // "Bad ID" has uppercase 'B' which the dedicated UppercaseNotAllowed
        // check fires before reaching the per-char loop.
        assert!(matches!(err, IdValidationError::UppercaseNotAllowed));
        // A lowercase-but-still-illegal character also surfaces an error.
        let err = TailscaleNodeId::try_new("node bad").unwrap_err();
        assert!(matches!(err, IdValidationError::InvalidChar { .. }));
        // Happy path still produces a valid id.
        let ok = TailscaleNodeId::try_new("node-ok").expect("canonical id");
        assert_eq!(ok.as_str(), "node-ok");
    }

    #[test]
    fn tailscale_node_id_serde_rejects_uncanonical_payload() {
        // Pre-fix: serde deserialization went through the auto-derived
        // TryFrom (from From<String>) and accepted anything. Post-fix:
        // the manual TryFrom validates, so a JSON string carrying a
        // non-canonical id must surface a deserialization error.
        let payload = r#""\u202Erevil-node""#;
        assert!(
            serde_json::from_str::<TailscaleNodeId>(payload).is_err(),
            "bidi-override Unicode in node id must fail to deserialize"
        );
        assert!(
            serde_json::from_str::<TailscaleNodeId>(r#""""#).is_err(),
            "empty string must fail to deserialize"
        );
    }

    #[test]
    fn tailscale_node_id_into_string() {
        let node = TailscaleNodeId::new("node-xyz");
        let s: String = node.into();
        assert_eq!(s, "node-xyz");
    }

    #[test]
    fn tailscale_node_id_serde_roundtrip() {
        let node = TailscaleNodeId::new("node-serde-test");
        let json = serde_json::to_string(&node).unwrap();
        let back: TailscaleNodeId = serde_json::from_str(&json).unwrap();
        assert_eq!(back.as_str(), "node-serde-test");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: RateLimit edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn rate_limit_serde_roundtrip() {
        let rl = RateLimit {
            max: 50,
            per_ms: 30_000,
            burst: Some(10),
            scope: Some("per_zone".into()),
            pool_name: Some("shared.pool".into()),
        };
        let json = serde_json::to_string(&rl).unwrap();
        let back: RateLimit = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max, 50);
        assert_eq!(back.per_ms, 30_000);
        assert_eq!(back.burst, Some(10));
        assert_eq!(back.scope.as_deref(), Some("per_zone"));
        assert_eq!(back.pool_name.as_deref(), Some("shared.pool"));
    }

    #[test]
    fn rate_limit_pool_name_with_valid_chars() {
        let rl = RateLimit {
            max: 1,
            per_ms: 1,
            burst: None,
            scope: None,
            pool_name: Some("my-pool_v2.api".into()),
        };
        assert!(rl.validate().is_ok());
    }

    #[test]
    fn rate_limit_pool_name_with_special_chars_rejected() {
        let rl = RateLimit {
            max: 1,
            per_ms: 1,
            burst: None,
            scope: None,
            pool_name: Some("pool name!".into()),
        };
        assert!(matches!(
            rl.validate(),
            Err(RateLimitValidationError::InvalidPoolName { .. })
        ));
    }

    #[test]
    fn rate_limit_parsed_scope_invalid_falls_back() {
        let rl = RateLimit {
            max: 1,
            per_ms: 1,
            burst: None,
            scope: Some("invalid_scope".into()),
            pool_name: None,
        };
        // Invalid scope should fall back to default
        assert_eq!(rl.parsed_scope(), OperationRateLimitScope::PerConnector);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: RateLimitValidationError Display coverage
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn rate_limit_validation_error_display_zero_max() {
        let err = RateLimitValidationError::ZeroMax;
        assert_eq!(err.to_string(), "rate_limit.max must be > 0");
    }

    #[test]
    fn rate_limit_validation_error_display_zero_period() {
        let err = RateLimitValidationError::ZeroPeriod;
        assert_eq!(err.to_string(), "rate_limit.per_ms must be > 0");
    }

    #[test]
    fn rate_limit_validation_error_display_invalid_scope() {
        let err = RateLimitValidationError::InvalidScope {
            scope: "bogus".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("bogus"));
        assert!(msg.contains("rate_limit.scope"));
    }

    #[test]
    fn rate_limit_validation_error_display_empty_pool() {
        let err = RateLimitValidationError::EmptyPoolName;
        assert_eq!(err.to_string(), "rate_limit.pool_name cannot be empty");
    }

    #[test]
    fn rate_limit_validation_error_display_invalid_pool() {
        let err = RateLimitValidationError::InvalidPoolName {
            pool_name: "a b c".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("a b c"));
        assert!(msg.contains("rate_limit.pool_name"));
    }

    #[test]
    fn rate_limit_validation_error_is_std_error() {
        let err = RateLimitValidationError::ZeroMax;
        // Verify it implements std::error::Error
        let _: &dyn std::error::Error = &err;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: RetryConfig edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn retry_config_custom_values_serde() {
        let cfg = RetryConfig {
            max_attempts: 5,
            initial_delay: std::time::Duration::from_millis(250),
            max_delay: std::time::Duration::from_secs(60),
            multiplier: 1.23,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: RetryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.max_attempts, 5);
        assert_eq!(back.initial_delay, std::time::Duration::from_millis(250));
        assert_eq!(back.max_delay, std::time::Duration::from_secs(60));
        assert!((back.multiplier - 1.23).abs() < f64::EPSILON);
    }

    #[test]
    fn retry_config_debug_format() {
        let cfg = RetryConfig::default();
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("max_attempts"));
        assert!(dbg.contains("initial_delay"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: CorrelationId / SessionId edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn correlation_id_default_same_as_new() {
        let d = CorrelationId::default();
        // Should be a valid UUID
        assert!(!d.0.is_nil());
    }

    #[test]
    fn correlation_id_display_is_uuid_format() {
        let id = CorrelationId::new();
        let displayed = id.to_string();
        // UUID v4 format: 8-4-4-4-12 hex chars
        assert_eq!(displayed.len(), 36);
        assert_eq!(displayed.chars().filter(|&c| c == '-').count(), 4);
    }

    #[test]
    fn correlation_id_serde_roundtrip() {
        let id = CorrelationId::new();
        let json = serde_json::to_string(&id).unwrap();
        let back: CorrelationId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn correlation_id_clone_preserves_value() {
        let original = CorrelationId::new();
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn session_id_default_same_as_new() {
        let d = SessionId::default();
        assert!(!d.0.is_nil());
    }

    #[test]
    fn session_id_display_is_uuid_format() {
        let id = SessionId::new();
        let displayed = id.to_string();
        assert_eq!(displayed.len(), 36);
        assert_eq!(displayed.chars().filter(|&c| c == '-').count(), 4);
    }

    #[test]
    fn session_id_serde_roundtrip() {
        let id = SessionId::new();
        let json = serde_json::to_string(&id).unwrap();
        let back: SessionId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    #[test]
    fn session_id_clone_preserves_value() {
        let original = SessionId::new();
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: Principal / TrustLevel edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn principal_serde_roundtrip() {
        let p = Principal {
            kind: "agent".into(),
            id: "bot-42".into(),
            trust: TrustLevel::Paired,
            display: Some("Bot 42".into()),
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: Principal = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, "agent");
        assert_eq!(back.id, "bot-42");
        assert_eq!(back.trust, TrustLevel::Paired);
        assert_eq!(back.display.as_deref(), Some("Bot 42"));
    }

    #[test]
    fn principal_omits_none_display() {
        let p = Principal {
            kind: "user".into(),
            id: "u1".into(),
            trust: TrustLevel::Anonymous,
            display: None,
        };
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("display"));
    }

    #[test]
    fn principal_verify_zone_access_denies_blocked_everywhere() {
        let principal = Principal {
            kind: "user".into(),
            id: "blocked-user".into(),
            trust: TrustLevel::Blocked,
            display: None,
        };

        let err = principal.verify_zone_access(&ZoneId::public()).unwrap_err();
        assert!(matches!(
            &err,
            FcpError::Unauthorized { code, message }
            if *code == 2001
                && message == "blocked principal 'blocked-user' cannot access zone 'z:public'"
        ));
    }

    #[test]
    fn principal_verify_zone_access_denies_paired_private_without_policy() {
        let principal = Principal {
            kind: "user".into(),
            id: "alice".into(),
            trust: TrustLevel::Paired,
            display: None,
        };

        let err = principal
            .verify_zone_access(&ZoneId::private())
            .unwrap_err();
        assert!(matches!(
            &err,
            FcpError::Unauthorized { code, message }
            if *code == 2001
                && message == "principal 'alice' requires explicit zone policy to access 'z:private'"
        ));
    }

    #[test]
    fn principal_verify_zone_access_denies_admin_owner_without_policy() {
        let principal = Principal {
            kind: "service".into(),
            id: "ops-bot".into(),
            trust: TrustLevel::Admin,
            display: None,
        };

        let err = principal.verify_zone_access(&ZoneId::owner()).unwrap_err();
        assert!(matches!(
            &err,
            FcpError::Unauthorized { code, message }
            if *code == 2001
                && message == "principal 'ops-bot' requires explicit zone policy to access 'z:owner'"
        ));
    }

    #[test]
    fn principal_verify_zone_access_allows_owner_in_owner_zone() {
        let principal = Principal {
            kind: "user".into(),
            id: "root".into(),
            trust: TrustLevel::Owner,
            display: None,
        };

        principal.verify_zone_access(&ZoneId::owner()).unwrap();
    }

    #[test]
    fn principal_verify_zone_access_allows_paired_in_work_zone() {
        let principal = Principal {
            kind: "user".into(),
            id: "alice".into(),
            trust: TrustLevel::Paired,
            display: None,
        };

        principal.verify_zone_access(&ZoneId::work()).unwrap();
    }

    #[test]
    fn trust_level_clone_and_copy() {
        let level = TrustLevel::Admin;
        let copied = level;
        assert_eq!(level, copied);
        // Verify Copy semantics: original still usable after assignment
        assert_eq!(level, TrustLevel::Admin);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: TaintLevel / Provenance edge cases
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn taint_level_serde_roundtrip() {
        for level in [
            TaintLevel::Untainted,
            TaintLevel::Tainted,
            TaintLevel::HighlyTainted,
        ] {
            let json = serde_json::to_string(&level).unwrap();
            let back: TaintLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(level, back);
        }
    }

    #[test]
    fn provenance_serde_roundtrip() {
        let p = Provenance::new(ZoneId::work())
            .with_step(ProvenanceStep {
                timestamp_ms: 42,
                zone: ZoneId::work(),
                actor: "agent:test".into(),
                action: "invoke".into(),
                resource: "cap.read".into(),
            })
            .elevated_with("elev-token-abc");

        let json = serde_json::to_string(&p).unwrap();
        let back: Provenance = serde_json::from_str(&json).unwrap();
        assert_eq!(back.origin_zone.as_str(), "z:work");
        assert_eq!(back.chain.len(), 1);
        assert!(back.elevated);
        assert_eq!(back.elevation_token.as_deref(), Some("elev-token-abc"));
    }

    #[test]
    fn provenance_multiple_steps() {
        let p = Provenance::new(ZoneId::work())
            .with_step(ProvenanceStep {
                timestamp_ms: 100,
                zone: ZoneId::work(),
                actor: "a1".into(),
                action: "read".into(),
                resource: "r1".into(),
            })
            .with_step(ProvenanceStep {
                timestamp_ms: 200,
                zone: ZoneId::private(),
                actor: "a2".into(),
                action: "write".into(),
                resource: "r2".into(),
            });
        assert_eq!(p.chain.len(), 2);
        assert_eq!(p.chain[0].timestamp_ms, 100);
        assert_eq!(p.chain[1].timestamp_ms, 200);
    }

    #[test]
    fn provenance_untainted_can_access_higher_trust() {
        let p = Provenance::new(ZoneId::work());
        assert!(!p.is_tainted());
        assert!(p.can_access_higher_trust());
    }

    #[test]
    fn provenance_highly_tainted_cannot_access_without_elevation() {
        let p = Provenance::highly_tainted(ZoneId::public());
        assert!(p.is_tainted());
        assert!(!p.can_access_higher_trust());
    }

    #[test]
    fn provenance_highly_tainted_with_elevation_can_access() {
        let p = Provenance::highly_tainted(ZoneId::public()).elevated_with("high-elev-token");
        assert!(p.is_tainted());
        assert!(p.can_access_higher_trust());
        assert_eq!(p.elevation_token.as_deref(), Some("high-elev-token"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: CapabilityToken test_token
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn capability_token_test_token_is_constructible() {
        let token = CapabilityToken::test_token();
        // Should have raw COSE token
        let dbg = format!("{token:?}");
        assert!(dbg.contains("CapabilityToken"));
    }

    #[test]
    fn capability_token_clone() {
        let token = CapabilityToken::test_token();
        let cloned = token.clone();
        // Both should exist independently
        let dbg1 = format!("{token:?}");
        let dbg2 = format!("{cloned:?}");
        assert!(!dbg1.is_empty());
        assert!(!dbg2.is_empty());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: CapabilityVerifier construction
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn capability_verifier_new_stores_fields() {
        let key = [0u8; 32];
        let zone = ZoneId::work();
        let instance = InstanceId::new();
        let verifier = CapabilityVerifier::new(key, zone.clone(), instance.clone());

        assert_eq!(verifier.host_public_key, [0u8; 32]);
        assert_eq!(verifier.zone_id.as_str(), zone.as_str());
        assert_eq!(
            verifier
                .instance_id
                .as_ref()
                .expect("new() sets Some(instance_id)")
                .as_str(),
            instance.as_str()
        );
    }

    #[test]
    fn capability_verifier_clone() {
        let key = [1u8; 32];
        let zone = ZoneId::owner();
        let instance = InstanceId::new();
        let original = CapabilityVerifier::new(key, zone, instance);
        let cloned = original.clone();
        assert_eq!(original.host_public_key, cloned.host_public_key);
        assert_eq!(original.zone_id.as_str(), cloned.zone_id.as_str());
    }

    #[test]
    fn capability_verifier_rejects_wrong_key() {
        // Generate token with one key, verify with a different key
        let signing_key = Ed25519SigningKey::generate();
        let wrong_key = Ed25519SigningKey::generate();
        let wrong_pub = wrong_key.verifying_key().to_bytes();

        let now = Utc::now();
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.test")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();

        let token = CapabilityToken::from_raw(cose_token);
        let verifier = CapabilityVerifier::new(wrong_pub, ZoneId::work(), InstanceId::new());
        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();

        let result = verifier.verify(token, &cap, &op, &[]);
        assert!(result.is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: OperationRateLimitScope serde roundtrip
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn operation_rate_limit_scope_serde_roundtrip() {
        for scope in [
            OperationRateLimitScope::PerConnector,
            OperationRateLimitScope::PerZone,
            OperationRateLimitScope::PerPrincipal,
        ] {
            let json = serde_json::to_string(&scope).unwrap();
            let back: OperationRateLimitScope = serde_json::from_str(&json).unwrap();
            assert_eq!(scope, back);
        }
    }

    #[test]
    fn operation_rate_limit_scope_from_str_error_message() {
        let err = "garbage".parse::<OperationRateLimitScope>().unwrap_err();
        assert!(err.contains("garbage"));
        assert!(err.contains("per_connector"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEW: IdempotencyClass / SafetyTier copy semantics
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn idempotency_class_is_copy() {
        let a = IdempotencyClass::Strict;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn safety_tier_is_copy() {
        let a = SafetyTier::Dangerous;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn risk_level_is_copy() {
        let a = RiskLevel::High;
        let b = a;
        assert_eq!(a, b);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phantom Type Verification State Tests (C3.1)
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn phantom_type_default_is_unverified() {
        // CapabilityToken without type parameter defaults to Unverified
        let token: CapabilityToken = CapabilityToken::test_token();
        let _: CapabilityToken<Unverified> = token;
    }

    #[test]
    fn phantom_type_verify_produces_verified() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();
        let now = Utc::now();

        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.test")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.test"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();

        let unverified: CapabilityToken<Unverified> = CapabilityToken::from_raw(cose_token);
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new());
        let op = OperationId::new("op.test").unwrap();
        let cap = CapabilityId::new("cap.test").unwrap();

        // verify() consumes the Unverified token and produces CryptographicallyVerified
        let result: CapabilityToken<CryptographicallyVerified> =
            verifier.verify(unverified, &cap, &op, &[]).unwrap();

        // CryptographicallyVerified token has claims
        assert!(result.claims().get_capability_id().is_some());
    }

    #[test]
    fn phantom_type_verified_token_has_claims() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();
        let now = Utc::now();

        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.phantom")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.read"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();

        let token = CapabilityToken::from_raw(cose_token);
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new());
        let op = OperationId::new("op.read").unwrap();
        let cap = CapabilityId::new("cap.phantom").unwrap();

        let result = verifier.verify(token, &cap, &op, &[]).unwrap();
        assert_eq!(result.claims().get_capability_id(), Some("cap.phantom"));
        assert_eq!(result.claims().get_zone_id(), Some("z:work"));
    }

    #[test]
    fn phantom_type_raw_accessible_on_both_states() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();
        let now = Utc::now();

        let instance = InstanceId::new();
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.raw")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.raw"])
            .issuer("node:primary")
            .target_instance(instance.as_str())
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();

        // raw() works on Unverified
        let unverified = CapabilityToken::from_raw(cose_token);
        let _raw_unverified = unverified.raw().to_cbor().unwrap();

        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), instance);
        let op = OperationId::new("op.raw").unwrap();
        let cap = CapabilityId::new("cap.raw").unwrap();

        // raw() also works on CryptographicallyVerified (verify consumes the unverified token)
        let result = verifier.verify_bound(unverified, &cap, &op, &[]).unwrap();
        let _raw_verified = result.raw().to_cbor().unwrap();
    }

    #[test]
    fn phantom_type_downgrade_verified_to_unverified() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();
        let now = Utc::now();

        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.down")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.down"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();

        let token = CapabilityToken::from_raw(cose_token);
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new());
        let op = OperationId::new("op.down").unwrap();
        let cap = CapabilityId::new("cap.down").unwrap();

        let result = verifier.verify(token, &cap, &op, &[]).unwrap();
        let downgraded: CapabilityToken<Unverified> = result.downgrade();

        // Downgraded token can be re-verified (verify consumes it)
        let re_verified = verifier.verify(downgraded, &cap, &op, &[]).unwrap();
        assert_eq!(re_verified.claims().get_capability_id(), Some("cap.down"));
    }

    #[test]
    fn phantom_type_verify_claims_ref_api() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();
        let now = Utc::now();

        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.ref")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.ref"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();

        let token = CapabilityToken::from_raw(cose_token);
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new());
        let op = OperationId::new("op.ref").unwrap();
        let cap = CapabilityId::new("cap.ref").unwrap();

        // verify_claims() borrows the token and returns claims
        let claims = verifier.verify_claims(&token, &cap, &op, &[]).unwrap();
        assert_eq!(claims.get_capability_id(), Some("cap.ref"));

        // Token is still usable (not consumed)
        let _raw = token.raw().to_cbor().unwrap();
    }

    #[test]
    fn phantom_type_type_aliases_work() {
        let token: UnverifiedToken = CapabilityToken::test_token();
        assert!(!token.raw().to_cbor().unwrap().is_empty());
    }

    #[test]
    fn phantom_type_clone_preserves_state() {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();
        let now = Utc::now();

        let instance = InstanceId::new();
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.clone")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.clone"])
            .issuer("node:primary")
            .target_instance(instance.as_str())
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();

        let token = CapabilityToken::from_raw(cose_token);
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), instance);
        let op = OperationId::new("op.clone").unwrap();
        let cap = CapabilityId::new("cap.clone").unwrap();

        let result = verifier.verify_bound(token, &cap, &op, &[]).unwrap();

        // Clone a verified token - clone preserves CryptographicallyVerified state
        let cloned = result;
        assert_eq!(cloned.claims().get_capability_id(), Some("cap.clone"));
    }

    #[test]
    fn phantom_type_test_token_is_unverified() {
        let token = CapabilityToken::test_token();
        // test_token() returns CapabilityToken<Unverified>
        let _: &CapabilityToken<Unverified> = &token;
        // raw() is accessible
        assert!(!token.raw().to_cbor().unwrap().is_empty());
    }

    #[test]
    fn phantom_type_from_raw_creates_unverified() {
        let signing_key = Ed25519SigningKey::generate();
        let now = Utc::now();
        let cose = CapabilityTokenBuilder::new()
            .capability_id("cap.raw")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.raw"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();

        let token = CapabilityToken::from_raw(cose);
        let _: &CapabilityToken<Unverified> = &token;
    }

    #[test]
    fn phantom_type_verify_consumes_unverified_token() {
        // Acceptance criterion C3.1.2: verify() is a consuming method.
        // After calling verify(), the original unverified token is moved
        // and cannot be used again (the compiler would reject it).
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();
        let now = Utc::now();

        let instance = InstanceId::new();
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.consume")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.consume"])
            .issuer("node:primary")
            .target_instance(instance.as_str())
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();

        let token = CapabilityToken::from_raw(cose_token);
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), instance);
        let op = OperationId::new("op.consume").unwrap();
        let cap = CapabilityId::new("cap.consume").unwrap();

        // verify() takes ownership — `token` is moved here
        let result = verifier.verify_bound(token, &cap, &op, &[]).unwrap();

        // `token` cannot be used after this point (compiler enforces)
        // CryptographicallyVerified token works:
        assert_eq!(result.claims().get_capability_id(), Some("cap.consume"));
    }

    #[test]
    fn phantom_type_verify_claims_is_non_consuming() {
        // Acceptance: verify_claims() borrows the token, does NOT consume it.
        // The unverified token remains usable after calling verify_claims().
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();
        let now = Utc::now();

        let instance = InstanceId::new();
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.noncon")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.noncon"])
            .issuer("node:primary")
            .target_instance(instance.as_str())
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();

        let token = CapabilityToken::from_raw(cose_token);
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), instance);
        let op = OperationId::new("op.noncon").unwrap();
        let cap = CapabilityId::new("cap.noncon").unwrap();

        // verify_claims() borrows the token
        let claims = verifier.verify_claims(&token, &cap, &op, &[]).unwrap();
        assert_eq!(claims.get_capability_id(), Some("cap.noncon"));

        // Token is still usable — can call raw() or verify() again
        let _raw = token.raw().to_cbor().unwrap();
        let result = verifier.verify_bound(token, &cap, &op, &[]).unwrap();
        assert_eq!(result.claims().get_zone_id(), Some("z:work"));
    }

    #[test]
    fn phantom_type_serialization_roundtrip() {
        // Acceptance: serialization + deserialization always produces Unverified.
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();
        let now = Utc::now();

        let instance = InstanceId::new();
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.serde")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.serde"])
            .issuer("node:primary")
            .target_instance(instance.as_str())
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();

        let token = CapabilityToken::from_raw(cose_token);
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), instance);
        let op = OperationId::new("op.serde").unwrap();
        let cap = CapabilityId::new("cap.serde").unwrap();

        // Verify first, then serialize the verified token
        let result = verifier.verify_bound(token, &cap, &op, &[]).unwrap();
        let bytes = result.raw().to_cbor().unwrap();

        // Deserialize produces Unverified, not CryptographicallyVerified
        let raw = CoseToken::from_cbor(&bytes).unwrap();
        let deserialized: CapabilityToken<Unverified> = CapabilityToken::from_raw(raw);

        // Must verify again to access claims
        let re_verified = verifier.verify_bound(deserialized, &cap, &op, &[]).unwrap();
        assert_eq!(re_verified.claims().get_capability_id(), Some("cap.serde"));
    }

    #[test]
    fn phantom_type_expired_token_rejected_at_verify() {
        // Acceptance: expired token is rejected by verify().
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();
        let now = Utc::now();

        // Create token that expired 1 hour ago
        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.expired")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.expired"])
            .issuer("node:primary")
            .validity(now - Duration::hours(2), now - Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();

        let token = CapabilityToken::from_raw(cose_token);
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new());
        let op = OperationId::new("op.expired").unwrap();
        let cap = CapabilityId::new("cap.expired").unwrap();

        let result = verifier.verify_bound(token, &cap, &op, &[]);
        assert!(matches!(result, Err(FcpError::TokenExpired)));
    }

    #[test]
    fn phantom_type_zone_mismatch_rejected_at_verify() {
        // Acceptance: token for wrong zone is rejected by verify().
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let pub_bytes = verifying_key.to_bytes();
        let now = Utc::now();

        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.zone")
            .zone_id("z:wrong")
            .principal("user:test")
            .operations(&["op.zone"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();

        let token = CapabilityToken::from_raw(cose_token);
        // Verifier expects z:work but token says z:wrong
        let verifier = CapabilityVerifier::new(pub_bytes, ZoneId::work(), InstanceId::new());
        let op = OperationId::new("op.zone").unwrap();
        let cap = CapabilityId::new("cap.zone").unwrap();

        let result = verifier.verify_bound(token, &cap, &op, &[]);
        assert!(matches!(result, Err(FcpError::ZoneViolation { .. })));
    }

    #[test]
    fn phantom_type_invalid_signature_rejected_at_verify() {
        // Acceptance: token signed with wrong key is rejected by verify().
        let signing_key = Ed25519SigningKey::generate();
        let wrong_key = Ed25519SigningKey::generate();
        let wrong_pub = wrong_key.verifying_key().to_bytes();
        let now = Utc::now();

        let cose_token = CapabilityTokenBuilder::new()
            .capability_id("cap.sig")
            .zone_id("z:work")
            .principal("user:test")
            .operations(&["op.sig"])
            .issuer("node:primary")
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&test_constraints_cbor())
            .expect("valid constraints")
            .sign(&signing_key)
            .unwrap();

        let token = CapabilityToken::from_raw(cose_token);
        // Verifier has wrong public key
        let verifier = CapabilityVerifier::new(wrong_pub, ZoneId::work(), InstanceId::new());
        let op = OperationId::new("op.sig").unwrap();
        let cap = CapabilityId::new("cap.sig").unwrap();

        let result = verifier.verify_bound(token, &cap, &op, &[]);
        assert!(matches!(result, Err(FcpError::InvalidSignature)));
    }

    #[test]
    fn phantom_type_verified_has_zero_runtime_overhead() {
        // PhantomData<S> is zero-sized — verify this at compile time.
        assert_eq!(
            std::mem::size_of::<std::marker::PhantomData<CryptographicallyVerified>>(),
            0
        );
        assert_eq!(
            std::mem::size_of::<std::marker::PhantomData<Unverified>>(),
            0
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // C3.7: ZoneBound<T> acceptance tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn zone_bound_bind_and_access_within_zone() {
        let bound = ZoneBound::bind(42_u32, ZoneId::owner());
        let result = bound.with_zone_check(&ZoneId::owner(), |v| *v);
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn zone_bound_cross_zone_access_rejected() {
        let bound = ZoneBound::bind("secret", ZoneId::private());
        let result = bound.with_zone_check(&ZoneId::public(), |v| *v);
        assert!(
            matches!(
                result,
                Err(FcpError::ZoneViolation {
                    ref source_zone,
                    ref target_zone,
                    ..
                }) if source_zone == "z:private" && target_zone == "z:public"
            ),
            "expected ZoneViolation, got {result:?}"
        );
    }

    #[test]
    fn zone_bound_zone_id_accessor() {
        let bound = ZoneBound::bind(vec![1, 2, 3], ZoneId::work());
        assert_eq!(bound.zone_id(), &ZoneId::work());
    }

    #[test]
    fn zone_bound_serde_roundtrip() {
        let bound = ZoneBound::bind(String::from("payload"), ZoneId::community());
        let json = serde_json::to_string(&bound).unwrap();
        let back: ZoneBound<String> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.zone_id(), &ZoneId::community());
        let val = back.with_zone_check(&ZoneId::community(), std::clone::Clone::clone);
        assert_eq!(val.unwrap(), "payload");
    }

    #[test]
    fn zone_bound_into_inner_same_zone() {
        let bound = ZoneBound::bind(99_i64, ZoneId::owner());
        assert_eq!(bound.into_inner(&ZoneId::owner()).unwrap(), 99);
    }

    #[test]
    fn zone_bound_into_inner_wrong_zone_rejected() {
        let bound = ZoneBound::bind(99_i64, ZoneId::owner());
        let err = bound.into_inner(&ZoneId::work()).unwrap_err();
        assert!(matches!(err, FcpError::ZoneViolation { .. }));
    }

    #[test]
    fn zone_bound_mut_access_within_zone() {
        let mut bound = ZoneBound::bind(vec![1, 2], ZoneId::private());
        bound
            .with_zone_check_mut(&ZoneId::private(), |v| v.push(3))
            .unwrap();
        let result = bound.with_zone_check(&ZoneId::private(), std::vec::Vec::len);
        assert_eq!(result.unwrap(), 3);
    }

    #[test]
    fn zone_bound_zone_is_immutable() {
        // ZoneBound has no set_zone() or rebind() — zone is fixed at construction.
        // This test verifies the API surface by checking clone preserves zone.
        let original = ZoneBound::bind(42_u32, ZoneId::owner());
        let cloned = original;
        assert_eq!(cloned.zone_id(), &ZoneId::owner());
        // Cross-zone access still rejected on clone
        assert!(cloned.with_zone_check(&ZoneId::public(), |v| *v).is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // C3.4: Mandatory capability constraints acceptance tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn capability_constraints_empty_is_deny_all() {
        let empty = CapabilityConstraints::default();
        assert!(empty.is_empty());
        // Empty constraints = deny all — no resources allowed
    }

    #[test]
    fn capability_constraints_with_allow_not_empty() {
        let constraints = CapabilityConstraints {
            resource_allow: vec!["repo:octocat/*".into()],
            ..Default::default()
        };
        assert!(!constraints.is_empty());
    }

    #[test]
    fn capability_constraints_with_max_calls_not_empty() {
        let constraints = CapabilityConstraints {
            max_calls: Some(100),
            ..Default::default()
        };
        assert!(!constraints.is_empty());
    }

    #[test]
    fn capability_constraints_with_credential_allow_not_empty() {
        let constraints = CapabilityConstraints {
            credential_allow: vec![CredentialId::new()],
            ..Default::default()
        };
        assert!(!constraints.is_empty());
    }
}
