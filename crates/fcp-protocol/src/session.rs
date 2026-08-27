//! FCP mesh session primitives (handshake, key derivation, and FCPS datagram MACs).
//!
//! Implements the normative session handshake defined in `FCP_Specification_V3.md`
//! §9.7.1 (Handshake and Session Establishment) and §9.7.2 (Mesh Session Authentication).
use fcp_cbor::{
    MAX_CANONICALIZATION_DEPTH, MAX_DESERIALIZATION_RECURSION_LIMIT, SerializationError,
    to_canonical_cbor,
};
use fcp_crypto::{
    CryptoError, Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey, HkdfSha256,
    X25519PublicKey, X25519SharedSecret,
};
use fcp_prelude::TailscaleNodeId;
use fcp_tailscale::{MeshIdentity, TailscaleError};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashSet, VecDeque};
use std::io::Cursor;
use subtle::ConstantTimeEq;
use thiserror::Error;

/// Size of the session identifier in bytes.
pub const SESSION_ID_SIZE: usize = 16;

/// Size of the hello/ack nonces in bytes.
pub const SESSION_NONCE_SIZE: usize = 16;

/// Size of the stateless cookie in bytes.
pub const SESSION_COOKIE_SIZE: usize = 32;

/// Size of the truncated session MAC tag in bytes.
pub const SESSION_MAC_SIZE: usize = 16;

/// Length of the FCPS datagram header (`session_id` + seq + mac).
pub const FCPS_DATAGRAM_HEADER_LEN: usize = 40;

/// Default max datagram bytes (MTU-safe).
pub const DEFAULT_MAX_DATAGRAM_BYTES: u16 = 1200;

/// Maximum handshake payload size in bytes (defensive limit).
pub const MAX_HANDSHAKE_BYTES: usize = 16 * 1024;

/// Default number of accepted hello nonces to retain for replay rejection.
pub const DEFAULT_HELLO_REPLAY_WINDOW_SIZE: usize = 1024;

/// Errors for session handshake and FCPS datagram handling.
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("invalid session crypto suite id {0}")]
    InvalidSuiteId(u8),

    #[error("no mutually supported session crypto suite")]
    NoMutualSuite,

    #[error("missing signature")]
    MissingSignature,

    #[error("signature verification failed")]
    InvalidSignature,

    #[error("invalid stateless cookie")]
    InvalidCookie,

    #[error("invalid stateless cookie length (len {len})")]
    InvalidCookieLength { len: usize },

    #[error("attestation missing or invalid")]
    InvalidAttestation,

    #[error("attestation expired")]
    AttestationExpired,

    #[error("attested node id does not match handshake")]
    AttestationNodeMismatch,

    #[error("session ack does not reflect the initiating hello endpoints")]
    AckHelloMismatch,

    #[error("session ack selected a suite not offered by the hello")]
    AckSuiteNotOffered,

    #[error("session ack selected suite {actual:?} below minimum {minimum:?}")]
    AckSuiteBelowMinimum {
        actual: SessionCryptoSuite,
        minimum: SessionCryptoSuite,
    },

    #[error("attestation verification failed: {reason}")]
    AttestationVerifyFailed { reason: String },

    #[error("FCPS datagram too short (len {len})")]
    DatagramTooShort { len: usize },

    #[error("FCPS datagram too large (len {len} > max {max})")]
    DatagramTooLarge { len: usize, max: usize },

    #[error("MAC key length invalid")]
    InvalidMacKeyLength,

    #[error("timestamp skew too large (delta {delta} > max {max})")]
    TimestampSkew { delta: u64, max: u64 },

    #[error("duplicate hello nonce still tracked by the active replay window")]
    DuplicateHelloNonce,

    #[error(transparent)]
    Cbor(#[from] fcp_cbor::SerializationError),

    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// Session crypto suite negotiation (NORMATIVE).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionCryptoSuite {
    /// X25519 + HKDF-SHA256 + HMAC-SHA256 (tag truncated to 16 bytes).
    Suite1 = 1,
    /// X25519 + HKDF-SHA256 + BLAKE3-keyed (tag truncated to 16 bytes).
    Suite2 = 2,
}

impl SessionCryptoSuite {
    /// Return the numeric suite identifier.
    #[must_use]
    pub const fn id(self) -> u8 {
        self as u8
    }

    /// Convert from a numeric suite identifier.
    ///
    /// # Errors
    /// Returns `SessionError::InvalidSuiteId` for unknown values.
    pub const fn try_from_id(id: u8) -> Result<Self, SessionError> {
        match id {
            1 => Ok(Self::Suite1),
            2 => Ok(Self::Suite2),
            other => Err(SessionError::InvalidSuiteId(other)),
        }
    }

    /// Human-readable suite label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Suite1 => "suite1-hmacsha256",
            Self::Suite2 => "suite2-blake3",
        }
    }
}

impl Serialize for SessionCryptoSuite {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(self.id())
    }
}

impl<'de> Deserialize<'de> for SessionCryptoSuite {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let id = u8::deserialize(deserializer)?;
        Self::try_from_id(id).map_err(serde::de::Error::custom)
    }
}

/// Mesh session identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MeshSessionId(#[serde(with = "bytes16_serde")] pub [u8; SESSION_ID_SIZE]);

impl MeshSessionId {
    /// Generate a new random session id.
    #[must_use]
    pub fn new() -> Self {
        let mut bytes = [0u8; SESSION_ID_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Borrow the raw session id bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SESSION_ID_SIZE] {
        &self.0
    }
}

impl Default for MeshSessionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Fixed-size session nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionNonce(#[serde(with = "bytes16_serde")] pub [u8; SESSION_NONCE_SIZE]);

impl SessionNonce {
    /// Generate a new random nonce.
    #[must_use]
    pub fn new() -> Self {
        let mut bytes = [0u8; SESSION_NONCE_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Borrow the raw nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SESSION_NONCE_SIZE] {
        &self.0
    }
}

impl Default for SessionNonce {
    fn default() -> Self {
        Self::new()
    }
}

/// Stateless cookie for `HelloRetry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionCookie(#[serde(with = "bytes32_serde")] pub [u8; SESSION_COOKIE_SIZE]);

impl SessionCookie {
    /// Borrow the raw cookie bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SESSION_COOKIE_SIZE] {
        &self.0
    }

    /// Parse a cookie from raw bytes.
    ///
    /// # Errors
    /// Returns `SessionError::InvalidCookieLength` if length is incorrect.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, SessionError> {
        if slice.len() != SESSION_COOKIE_SIZE {
            return Err(SessionError::InvalidCookieLength { len: slice.len() });
        }
        let mut bytes = [0u8; SESSION_COOKIE_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }
}

mod bytes16_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 16], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 16], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 16 {
            return Err(serde::de::Error::custom(format!(
                "invalid length: expected 16, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

mod bytes32_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "invalid length: expected 32, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

/// Negotiated transport limits (NORMATIVE when used).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TransportLimits {
    /// Maximum UDP payload bytes the sender will transmit for FCPS frames.
    pub max_datagram_bytes: u16,
}

impl TransportLimits {
    /// Validate `max_datagram_bytes` and return the effective limit.
    #[must_use]
    pub const fn effective_max(self) -> u16 {
        if self.max_datagram_bytes == 0 {
            DEFAULT_MAX_DATAGRAM_BYTES
        } else {
            self.max_datagram_bytes
        }
    }
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            max_datagram_bytes: DEFAULT_MAX_DATAGRAM_BYTES,
        }
    }
}

/// Session handshake: initiator → responder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshSessionHello {
    pub from: TailscaleNodeId,
    pub to: TailscaleNodeId,
    pub eph_pubkey: X25519PublicKey,
    pub nonce: SessionNonce,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookie: Option<SessionCookie>,
    pub timestamp: u64,
    pub suites: Vec<SessionCryptoSuite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport_limits: Option<TransportLimits>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Ed25519Signature>,
}

impl MeshSessionHello {
    /// Compute the handshake transcript bytes (signature excluded).
    ///
    /// Uses canonical CBOR for each field to keep encoding deterministic.
    ///
    /// # Errors
    /// Returns `SessionError::Cbor` if canonical encoding fails.
    pub fn transcript_bytes(&self) -> Result<Vec<u8>, SessionError> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"FCP2-HELLO-V1");
        append_cbor(&mut buf, &self.from)?;
        append_cbor(&mut buf, &self.to)?;
        append_cbor(&mut buf, &self.eph_pubkey)?;
        append_cbor(&mut buf, &self.nonce)?;
        append_cbor(&mut buf, &self.cookie)?;
        append_cbor(&mut buf, &self.timestamp)?;
        append_cbor(&mut buf, &self.suites)?;
        append_cbor(&mut buf, &self.transport_limits)?;
        Ok(buf)
    }

    /// Sign the hello transcript in-place.
    ///
    /// # Errors
    /// Returns `SessionError::Cbor` if canonical encoding fails.
    pub fn sign(&mut self, signing_key: &Ed25519SigningKey) -> Result<(), SessionError> {
        let transcript = self.transcript_bytes()?;
        self.signature = Some(signing_key.sign(&transcript));
        Ok(())
    }

    /// Verify the hello signature.
    ///
    /// # Errors
    /// Returns `SessionError::MissingSignature` or `SessionError::InvalidSignature`.
    pub fn verify(&self, verifying_key: &Ed25519VerifyingKey) -> Result<(), SessionError> {
        let signature = self.signature.ok_or(SessionError::MissingSignature)?;
        let transcript = self.transcript_bytes()?;
        verifying_key
            .verify(&transcript, &signature)
            .map_err(|_| SessionError::InvalidSignature)
    }
}

/// Session handshake: responder → initiator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshSessionAck {
    pub from: TailscaleNodeId,
    pub to: TailscaleNodeId,
    pub eph_pubkey: X25519PublicKey,
    pub nonce: SessionNonce,
    pub session_id: MeshSessionId,
    pub suite: SessionCryptoSuite,
    pub timestamp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<Ed25519Signature>,
}

impl MeshSessionAck {
    /// Compute the handshake transcript bytes (signature excluded).
    ///
    /// # Errors
    /// Returns `SessionError::Cbor` if canonical encoding fails.
    pub fn transcript_bytes(&self, hello: &MeshSessionHello) -> Result<Vec<u8>, SessionError> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"FCP2-ACK-V1");
        append_cbor(&mut buf, &self.from)?;
        append_cbor(&mut buf, &self.to)?;
        append_cbor(&mut buf, &self.eph_pubkey)?;
        append_cbor(&mut buf, &self.nonce)?;
        append_cbor(&mut buf, &self.session_id)?;
        append_cbor(&mut buf, &self.suite)?;
        append_cbor(&mut buf, &self.timestamp)?;
        append_cbor(&mut buf, &hello.eph_pubkey)?;
        append_cbor(&mut buf, &hello.nonce)?;
        Ok(buf)
    }

    /// Sign the ack transcript in-place.
    ///
    /// # Errors
    /// Returns `SessionError::Cbor` if canonical encoding fails.
    pub fn sign(
        &mut self,
        hello: &MeshSessionHello,
        signing_key: &Ed25519SigningKey,
    ) -> Result<(), SessionError> {
        let transcript = self.transcript_bytes(hello)?;
        self.signature = Some(signing_key.sign(&transcript));
        Ok(())
    }

    /// Verify the ack signature.
    ///
    /// # Errors
    /// Returns `SessionError::MissingSignature` or `SessionError::InvalidSignature`.
    pub fn verify(
        &self,
        hello: &MeshSessionHello,
        verifying_key: &Ed25519VerifyingKey,
    ) -> Result<(), SessionError> {
        if self.from.as_str() != hello.to.as_str() || self.to.as_str() != hello.from.as_str() {
            return Err(SessionError::AckHelloMismatch);
        }
        verify_ack_suite_against_floor(self.suite, &hello.suites, MINIMUM_SUITE)?;
        let signature = self.signature.ok_or(SessionError::MissingSignature)?;
        let transcript = self.transcript_bytes(hello)?;
        verifying_key
            .verify(&transcript, &signature)
            .map_err(|_| SessionError::InvalidSignature)
    }
}

/// Decode canonical CBOR and reject non-canonical encodings.
fn decode_canonical_cbor<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, SessionError> {
    if bytes.len() > MAX_HANDSHAKE_BYTES {
        return Err(SessionError::Cbor(SerializationError::PayloadTooLarge {
            len: bytes.len(),
            max: MAX_HANDSHAKE_BYTES,
        }));
    }

    let mut cursor = Cursor::new(bytes);
    let value: T = ciborium::de::from_reader_with_recursion_limit(
        &mut cursor,
        MAX_DESERIALIZATION_RECURSION_LIMIT,
    )
    .map_err(map_handshake_cbor_deserialize_error)?;
    #[allow(clippy::cast_possible_truncation)] // cursor position always <= bytes.len()
    if cursor.position() as usize != bytes.len() {
        return Err(SessionError::Cbor(SerializationError::TrailingBytes));
    }

    let canonical = to_canonical_cbor(&value)?;
    if canonical != bytes {
        return Err(SessionError::Cbor(SerializationError::NonCanonicalEncoding));
    }

    Ok(value)
}

fn map_handshake_cbor_deserialize_error(
    err: ciborium::de::Error<std::io::Error>,
) -> SerializationError {
    match err {
        ciborium::de::Error::RecursionLimitExceeded => SerializationError::DepthExceeded {
            depth: MAX_DESERIALIZATION_RECURSION_LIMIT + 1,
            max: MAX_CANONICALIZATION_DEPTH,
        },
        other => SerializationError::CborDeserialize(other),
    }
}

/// Decode a canonical CBOR-encoded `MeshSessionHello`.
///
/// # Errors
/// Returns `SessionError::Cbor` if decoding fails or encoding is non-canonical.
pub fn decode_hello_cbor(bytes: &[u8]) -> Result<MeshSessionHello, SessionError> {
    decode_canonical_cbor(bytes)
}

/// Decode a canonical CBOR-encoded `MeshSessionAck`.
///
/// # Errors
/// Returns `SessionError::Cbor` if decoding fails or encoding is non-canonical.
pub fn decode_ack_cbor(bytes: &[u8]) -> Result<MeshSessionAck, SessionError> {
    decode_canonical_cbor(bytes)
}

/// Decode a raw cookie from bytes.
///
/// # Errors
/// Returns `SessionError::InvalidCookieLength` if length is incorrect.
pub fn decode_cookie_bytes(bytes: &[u8]) -> Result<SessionCookie, SessionError> {
    SessionCookie::try_from_slice(bytes)
}

/// Stateless cookie challenge (`HelloRetry`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshSessionHelloRetry {
    pub from: TailscaleNodeId,
    pub to: TailscaleNodeId,
    pub cookie: SessionCookie,
    pub timestamp: u64,
}

fn map_attestation_error(err: TailscaleError) -> SessionError {
    match err {
        TailscaleError::InvalidAttestation => SessionError::InvalidAttestation,
        TailscaleError::AttestationExpired => SessionError::AttestationExpired,
        other => SessionError::AttestationVerifyFailed {
            reason: other.to_string(),
        },
    }
}

/// Get current Unix timestamp in seconds.
///
/// Returns the current Unix timestamp in seconds.
///
/// Returns 0 if the system clock is before the Unix epoch (e.g.,
/// misconfigured containers or embedded devices), rather than panicking.
#[must_use]
pub fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HelloReplayKey {
    from: TailscaleNodeId,
    nonce: SessionNonce,
}

/// Responder-side tracker for accepted hello nonces inside the active replay window.
#[derive(Debug, Clone)]
pub struct HelloReplayWindow {
    capacity: usize,
    order: VecDeque<HelloReplayKey>,
    seen: HashSet<HelloReplayKey>,
}

impl HelloReplayWindow {
    /// Create a new hello replay window with bounded FIFO retention.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            capacity,
            order: VecDeque::with_capacity(capacity),
            seen: HashSet::with_capacity(capacity),
        }
    }

    fn key_for(hello: &MeshSessionHello) -> HelloReplayKey {
        HelloReplayKey {
            from: hello.from.clone(),
            nonce: hello.nonce,
        }
    }

    /// Return whether this hello would be accepted without mutating the window.
    #[must_use]
    pub fn check(&self, hello: &MeshSessionHello) -> bool {
        !self.seen.contains(&Self::key_for(hello))
    }

    /// Record a verified hello and reject duplicates that remain inside the active window.
    pub fn check_and_update(&mut self, hello: &MeshSessionHello) -> bool {
        let key = Self::key_for(hello);
        if !self.seen.insert(key.clone()) {
            return false;
        }

        self.order.push_back(key);
        while self.order.len() > self.capacity {
            if let Some(evicted) = self.order.pop_front() {
                self.seen.remove(&evicted);
            }
        }
        true
    }
}

impl Default for HelloReplayWindow {
    fn default() -> Self {
        Self::new(DEFAULT_HELLO_REPLAY_WINDOW_SIZE)
    }
}

/// Verify a hello signature against a peer identity and attestation.
///
/// # Errors
/// Returns `SessionError::AttestationNodeMismatch` if the node id differs,
/// `SessionError::TimestampSkew` if timestamp is outside policy window,
/// or the relevant `SessionError` if attestation/signature verification fails.
///
/// This helper intentionally does not track accepted nonces. Responder call sites that
/// admit new hellos should use [`verify_hello_attested_with_replay`] so duplicate hello
/// nonces are rejected while they remain inside the active replay window.
pub fn verify_hello_attested(
    hello: &MeshSessionHello,
    identity: &MeshIdentity,
    time_policy: &TimePolicy,
) -> Result<(), SessionError> {
    if identity.node_id.as_str() != hello.from.as_str() {
        return Err(SessionError::AttestationNodeMismatch);
    }

    // Verify timestamp freshness
    let now = current_timestamp();
    let skew = hello.timestamp.abs_diff(now);

    if skew > time_policy.max_skew_secs {
        return Err(SessionError::TimestampSkew {
            delta: skew,
            max: time_policy.max_skew_secs,
        });
    }

    identity
        .verify_attestation()
        .map_err(map_attestation_error)?;
    hello.verify(&identity.node_keys.signing_key)?;
    Ok(())
}

/// Verify a hello and reject duplicate nonces still retained by the active replay window.
///
/// # Errors
/// Returns any error from [`verify_hello_attested`] or [`SessionError::DuplicateHelloNonce`]
/// when the responder has already accepted the same `(from, nonce)` tuple within the
/// currently retained active window.
pub fn verify_hello_attested_with_replay(
    hello: &MeshSessionHello,
    identity: &MeshIdentity,
    time_policy: &TimePolicy,
    replay_window: &mut HelloReplayWindow,
) -> Result<(), SessionError> {
    verify_hello_attested(hello, identity, time_policy)?;
    if replay_window.check_and_update(hello) {
        Ok(())
    } else {
        Err(SessionError::DuplicateHelloNonce)
    }
}

/// Verify an ack signature against a peer identity and attestation.
///
/// # Errors
/// Returns `SessionError::AttestationNodeMismatch` if the node id differs,
/// `SessionError::TimestampSkew` if timestamp is outside policy window,
/// or the relevant `SessionError` if attestation/signature verification fails.
pub fn verify_ack_attested(
    ack: &MeshSessionAck,
    hello: &MeshSessionHello,
    identity: &MeshIdentity,
    time_policy: &TimePolicy,
) -> Result<(), SessionError> {
    if identity.node_id.as_str() != ack.from.as_str() {
        return Err(SessionError::AttestationNodeMismatch);
    }

    // Verify timestamp freshness
    let now = current_timestamp();
    let skew = ack.timestamp.abs_diff(now);

    if skew > time_policy.max_skew_secs {
        return Err(SessionError::TimestampSkew {
            delta: skew,
            max: time_policy.max_skew_secs,
        });
    }

    identity
        .verify_attestation()
        .map_err(map_attestation_error)?;
    ack.verify(hello, &identity.node_keys.signing_key)?;
    Ok(())
}

/// Direction for session MAC computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionDirection {
    InitiatorToResponder,
    ResponderToInitiator,
}

impl SessionDirection {
    /// Return the direction byte used in MAC input.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::InitiatorToResponder => 0x00,
            Self::ResponderToInitiator => 0x01,
        }
    }
}

/// Replay window tracker for a session.
///
/// Uses a sliding bitmap to track received sequence numbers and detect replays.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    highest_seq: u64,
    bitmap: u128,
    window_size: u64,
}

impl ReplayWindow {
    /// Create a new replay window with the given size.
    #[must_use]
    pub fn new(window_size: u64) -> Self {
        let window_size = window_size.max(1);
        Self {
            highest_seq: 0,
            bitmap: 0,
            window_size,
        }
    }

    /// Check if sequence is valid (not a replay) without updating the window.
    ///
    /// This should be called before expensive MAC verification to prevent
    /// CPU exhaustion attacks from replayed packets.
    #[must_use]
    pub const fn check(&self, seq: u64) -> bool {
        if seq == 0 {
            return false;
        }

        if seq > self.highest_seq {
            true
        } else {
            let diff = self.highest_seq - seq;
            if diff >= self.window_size || diff >= 128 {
                return false;
            }
            let bit = 1u128 << diff;
            (self.bitmap & bit) == 0
        }
    }

    /// Check if sequence is valid (not a replay) and update window.
    ///
    /// Returns `true` if accepted, `false` if replayed or too old.
    #[allow(clippy::branches_sharing_code)] // both branches intentionally return true at end
    pub fn check_and_update(&mut self, seq: u64) -> bool {
        if seq == 0 {
            return false;
        }

        if seq > self.highest_seq {
            let shift = (seq - self.highest_seq).min(128);
            self.bitmap = self
                .bitmap
                .checked_shl(u32::try_from(shift).unwrap_or(u32::MAX))
                .unwrap_or(0);
            self.bitmap |= 1;
            self.highest_seq = seq;
            true
        } else {
            let diff = self.highest_seq - seq;
            if diff >= self.window_size || diff >= 128 {
                return false;
            }
            let bit = 1u128 << diff;
            if self.bitmap & bit != 0 {
                return false;
            }
            self.bitmap |= bit;
            true
        }
    }

    /// Return the highest sequence number observed.
    #[must_use]
    pub const fn highest_seq(&self) -> u64 {
        self.highest_seq
    }
}

/// Replay protection policy (NORMATIVE defaults).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionReplayPolicy {
    pub max_reorder_window: u64,
    pub rekey_after_frames: u64,
    pub rekey_after_seconds: u64,
    pub rekey_after_bytes: u64,
}

impl Default for SessionReplayPolicy {
    fn default() -> Self {
        Self {
            max_reorder_window: 128,
            rekey_after_frames: 1_000_000_000,
            rekey_after_seconds: 86_400,
            rekey_after_bytes: 1_099_511_627_776,
        }
    }
}

/// Time skew handling policy (NORMATIVE defaults).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimePolicy {
    pub max_skew_secs: u64,
    pub log_skew_events: bool,
}

impl Default for TimePolicy {
    fn default() -> Self {
        Self {
            max_skew_secs: 120,
            log_skew_events: true,
        }
    }
}

/// Derived session key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionKeys {
    pub k_mac_i2r: [u8; 32],
    pub k_mac_r2i: [u8; 32],
    pub k_ctx: [u8; 32],
}

impl SessionKeys {
    /// Return the MAC key for a given direction.
    #[must_use]
    pub const fn mac_key(&self, direction: SessionDirection) -> &[u8; 32] {
        match direction {
            SessionDirection::InitiatorToResponder => &self.k_mac_i2r,
            SessionDirection::ResponderToInitiator => &self.k_mac_r2i,
        }
    }
}

/// Derive session keys from the ECDH shared secret, selected suite, and
/// handshake transcript data.
///
/// # Errors
/// Returns `SessionError::Crypto` if HKDF expansion fails.
pub fn derive_session_keys(
    shared_secret: &X25519SharedSecret,
    suite: SessionCryptoSuite,
    session_id: &MeshSessionId,
    initiator_node_id: &TailscaleNodeId,
    responder_node_id: &TailscaleNodeId,
    hello_nonce: &SessionNonce,
    ack_nonce: &SessionNonce,
) -> Result<SessionKeys, SessionError> {
    let mut info = Vec::new();
    info.extend_from_slice(b"FCP2-SESSION-V1");
    info.push(suite.id());

    let init_bytes = initiator_node_id.as_str().as_bytes();
    info.extend_from_slice(
        &u32::try_from(init_bytes.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    info.extend_from_slice(init_bytes);

    let resp_bytes = responder_node_id.as_str().as_bytes();
    info.extend_from_slice(
        &u32::try_from(resp_bytes.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    info.extend_from_slice(resp_bytes);

    info.extend_from_slice(hello_nonce.as_bytes());
    info.extend_from_slice(ack_nonce.as_bytes());

    let hkdf = HkdfSha256::new(Some(session_id.as_bytes()), shared_secret.as_bytes());
    let okm = hkdf.expand_to_array::<96>(&info)?;

    let mut k_mac_i2r = [0u8; 32];
    let mut k_mac_r2i = [0u8; 32];
    let mut k_ctx = [0u8; 32];
    k_mac_i2r.copy_from_slice(&okm[0..32]);
    k_mac_r2i.copy_from_slice(&okm[32..64]);
    k_ctx.copy_from_slice(&okm[64..96]);

    Ok(SessionKeys {
        k_mac_i2r,
        k_mac_r2i,
        k_ctx,
    })
}

/// The minimum crypto suite FCP will negotiate. Any suite weaker than
/// this floor is refused at negotiation time even if the responder's
/// preference list still contains it.
///
/// Versioning rule: bumping `MINIMUM_SUITE` is a deployment-breaking
/// change. Stage it by (a) adding support for the replacement suite in
/// every peer's offered+supported lists, (b) waiting one full release
/// cycle, (c) bumping the floor. See
/// `docs/protocol/session-handshake.md` for the full suite-deprecation
/// policy.
pub const MINIMUM_SUITE: SessionCryptoSuite = SessionCryptoSuite::Suite1;

/// Internal strength ordering of suites. Higher rank = stronger suite.
/// Used ONLY for [`MINIMUM_SUITE`] enforcement in [`negotiate_suite`];
/// not part of the public API.
///
/// When adding a new variant to [`SessionCryptoSuite`], assign a rank
/// that reflects its cryptographic strength relative to existing
/// suites. This is the single site that knows the strength ordering.
#[must_use]
const fn suite_rank(s: SessionCryptoSuite) -> u8 {
    match s {
        SessionCryptoSuite::Suite1 => 1,
        SessionCryptoSuite::Suite2 => 2,
    }
}

/// Negotiate the session crypto suite using **responder** preference ordering,
/// with a [`MINIMUM_SUITE`] floor.
///
/// The responder picks the first suite in its own preference list that the
/// initiator also supports AND that is at or above [`MINIMUM_SUITE`] in
/// strength. Suites weaker than the floor are refused even if both peers
/// still list them.
///
/// This is the modern-crypto default (TLS 1.3, Noise, `WireGuard`) and
/// defends against downgrade via a malicious or coerced initiator that
/// deliberately orders its offers worst-first. The `MINIMUM_SUITE` floor
/// is the belt-and-braces defense against a responder with a stale or
/// misconfigured preference list.
///
/// Transcript binding at [`MeshSessionHello::transcript_bytes`] protects
/// against in-transit rewriting of the offered-suites list; this function
/// protects against an initiator that honestly offers a bad list. The
/// defenses are complementary and address different threat models.
///
/// Returns `None` if there is no intersection at or above
/// [`MINIMUM_SUITE`] between initiator and responder suite sets.
///
/// See `docs/protocol/session-handshake.md` for the responder-picks
/// invariant and suite-deprecation policy.
#[must_use]
pub fn negotiate_suite(
    initiator_suites: &[SessionCryptoSuite],
    responder_suites: &[SessionCryptoSuite],
) -> Option<SessionCryptoSuite> {
    let floor = suite_rank(MINIMUM_SUITE);
    responder_suites
        .iter()
        .copied()
        .find(|suite| initiator_suites.contains(suite) && suite_rank(*suite) >= floor)
}

fn verify_ack_suite_against_floor(
    ack_suite: SessionCryptoSuite,
    hello_suites: &[SessionCryptoSuite],
    minimum_suite: SessionCryptoSuite,
) -> Result<(), SessionError> {
    if suite_rank(ack_suite) < suite_rank(minimum_suite) {
        return Err(SessionError::AckSuiteBelowMinimum {
            actual: ack_suite,
            minimum: minimum_suite,
        });
    }
    if !hello_suites.contains(&ack_suite) {
        return Err(SessionError::AckSuiteNotOffered);
    }
    Ok(())
}

/// Compute the stateless cookie for a hello message.
///
/// # Errors
/// Returns `SessionError::InvalidMacKeyLength` on key init failure.
pub fn compute_cookie(
    cookie_key: &[u8; 32],
    hello: &MeshSessionHello,
) -> Result<SessionCookie, SessionError> {
    let mut data = Vec::new();
    append_cbor(&mut data, &hello.from)?;
    append_cbor(&mut data, &hello.to)?;
    append_cbor(&mut data, &hello.eph_pubkey)?;
    append_cbor(&mut data, &hello.nonce)?;
    append_cbor(&mut data, &hello.timestamp)?;
    append_cbor(&mut data, &hello.suites)?;
    append_cbor(&mut data, &hello.transport_limits)?;

    let mut mac = Hmac::<Sha256>::new_from_slice(cookie_key)
        .map_err(|_| SessionError::InvalidMacKeyLength)?;
    mac.update(&data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; SESSION_COOKIE_SIZE];
    out.copy_from_slice(&result[..SESSION_COOKIE_SIZE]);
    Ok(SessionCookie(out))
}

/// Verify a stateless cookie against a hello message.
///
/// # Errors
/// Returns `SessionError::InvalidCookie` if the cookie does not match.
pub fn verify_cookie(
    cookie_key: &[u8; 32],
    hello: &MeshSessionHello,
    cookie: &SessionCookie,
) -> Result<(), SessionError> {
    let expected = compute_cookie(cookie_key, hello)?;
    if expected.as_bytes().ct_eq(cookie.as_bytes()).into() {
        Ok(())
    } else {
        Err(SessionError::InvalidCookie)
    }
}

/// Compute the session MAC for an FCPS frame.
///
/// # Errors
/// Returns `SessionError::InvalidMacKeyLength` on key init failure.
pub fn compute_session_mac(
    suite: SessionCryptoSuite,
    mac_key: &[u8; 32],
    session_id: &MeshSessionId,
    direction: SessionDirection,
    seq: u64,
    frame_bytes: &[u8],
) -> Result<[u8; SESSION_MAC_SIZE], SessionError> {
    let direction = [direction.as_u8()];
    let seq = seq.to_le_bytes();
    match suite {
        SessionCryptoSuite::Suite1 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(mac_key)
                .map_err(|_| SessionError::InvalidMacKeyLength)?;
            mac.update(session_id.as_bytes());
            mac.update(&direction);
            mac.update(&seq);
            mac.update(frame_bytes);
            let full = mac.finalize().into_bytes();
            let mut out = [0u8; SESSION_MAC_SIZE];
            out.copy_from_slice(&full[..SESSION_MAC_SIZE]);
            Ok(out)
        }
        SessionCryptoSuite::Suite2 => {
            let mut hasher = blake3::Hasher::new_keyed(mac_key);
            hasher.update(session_id.as_bytes());
            hasher.update(&direction);
            hasher.update(&seq);
            hasher.update(frame_bytes);
            let hash = hasher.finalize();
            let mut out = [0u8; SESSION_MAC_SIZE];
            out.copy_from_slice(&hash.as_bytes()[..SESSION_MAC_SIZE]);
            Ok(out)
        }
    }
}

/// Verify the session MAC for an FCPS frame.
///
/// # Errors
/// Returns `SessionError::InvalidSignature` on MAC mismatch.
pub fn verify_session_mac(
    suite: SessionCryptoSuite,
    mac_key: &[u8; 32],
    session_id: &MeshSessionId,
    direction: SessionDirection,
    seq: u64,
    frame_bytes: &[u8],
    expected: &[u8; SESSION_MAC_SIZE],
) -> Result<(), SessionError> {
    let computed = compute_session_mac(suite, mac_key, session_id, direction, seq, frame_bytes)?;
    if computed.ct_eq(expected).into() {
        Ok(())
    } else {
        Err(SessionError::InvalidSignature)
    }
}

/// FCPS datagram wrapper (on-wire format).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FcpsDatagram {
    pub session_id: MeshSessionId,
    pub seq: u64,
    pub mac: [u8; SESSION_MAC_SIZE],
    pub frame_bytes: Vec<u8>,
}

impl FcpsDatagram {
    /// Encode the datagram to bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FCPS_DATAGRAM_HEADER_LEN + self.frame_bytes.len());
        out.extend_from_slice(self.session_id.as_bytes());
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&self.mac);
        out.extend_from_slice(&self.frame_bytes);
        out
    }

    /// Decode a datagram from bytes, enforcing length limits.
    ///
    /// # Errors
    /// Returns `SessionError::DatagramTooShort` or `SessionError::DatagramTooLarge`.
    pub fn decode(bytes: &[u8], max_datagram_bytes: u16) -> Result<Self, SessionError> {
        if bytes.len() < FCPS_DATAGRAM_HEADER_LEN {
            return Err(SessionError::DatagramTooShort { len: bytes.len() });
        }

        let max = max_datagram_bytes as usize;
        if bytes.len() > max {
            return Err(SessionError::DatagramTooLarge {
                len: bytes.len(),
                max,
            });
        }

        // Direct byte access — bounds guaranteed by length check above.
        let mut session_id = [0u8; SESSION_ID_SIZE];
        session_id.copy_from_slice(&bytes[0..16]);

        let seq = u64::from_le_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);

        let mut mac = [0u8; SESSION_MAC_SIZE];
        mac.copy_from_slice(&bytes[24..40]);

        let frame_bytes = bytes[40..].to_vec();

        Ok(Self {
            session_id: MeshSessionId(session_id),
            seq,
            mac,
            frame_bytes,
        })
    }
}

fn append_cbor<T: Serialize>(buf: &mut Vec<u8>, value: &T) -> Result<(), SessionError> {
    let bytes = to_canonical_cbor(value)?;
    buf.extend_from_slice(&bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use fcp_crypto::X25519SecretKey;
    use fcp_tailscale::{MeshIdentity, NodeId, NodeKeyAttestation, NodeKeys, TailscaleTag};
    use serde_json::json;
    use std::panic::AssertUnwindSafe;
    use std::time::Instant;
    use uuid::Uuid;

    struct LogContext<'a> {
        phase: &'a str,
        operation: &'a str,
        suite: Option<SessionCryptoSuite>,
        session_id: Option<&'a MeshSessionId>,
        peer_node_id: Option<&'a TailscaleNodeId>,
        reason_code: Option<&'a str>,
        details: Option<serde_json::Value>,
    }

    impl<'a> LogContext<'a> {
        fn new(phase: &'a str, operation: &'a str) -> Self {
            Self {
                phase,
                operation,
                suite: None,
                session_id: None,
                peer_node_id: None,
                reason_code: None,
                details: None,
            }
        }

        fn with_suite(mut self, suite: SessionCryptoSuite) -> Self {
            self.suite = Some(suite);
            self
        }

        fn with_session(mut self, session_id: &'a MeshSessionId) -> Self {
            self.session_id = Some(session_id);
            self
        }

        fn with_peer(mut self, peer: &'a TailscaleNodeId) -> Self {
            self.peer_node_id = Some(peer);
            self
        }

        fn with_reason(mut self, reason_code: &'a str) -> Self {
            self.reason_code = Some(reason_code);
            self
        }

        fn with_details(mut self, details: serde_json::Value) -> Self {
            self.details = Some(details);
            self
        }
    }

    fn run_logged_test<F>(test_name: &str, assertions: u32, context: &LogContext<'_>, f: F)
    where
        F: FnOnce(),
    {
        let start = Instant::now();
        let result = std::panic::catch_unwind(AssertUnwindSafe(f));
        let duration_ms = start.elapsed().as_millis();

        let (passed, failed, outcome) = match result {
            Ok(()) => (assertions, 0, "pass"),
            Err(_) => (0, assertions, "fail"),
        };

        let log = json!({
            "timestamp": Utc::now().to_rfc3339(),
            "level": "info",
            "test_name": test_name,
            "module": "fcp-session",
            "phase": context.phase,
            "correlation_id": Uuid::new_v4().to_string(),
            "session_id": context.session_id.map(|id| hex::encode(id.as_bytes())),
            "peer_node_id": context.peer_node_id.map(TailscaleNodeId::as_str),
            "suite": context.suite.map(SessionCryptoSuite::as_str),
            "operation": context.operation,
            "result": outcome,
            "reason_code": context.reason_code,
            "details": context.details,
            "duration_ms": duration_ms,
            "assertions": {
                "passed": passed,
                "failed": failed
            }
        });
        println!("{log}");

        if let Err(payload) = result {
            std::panic::resume_unwind(payload);
        }
    }

    /// Responder-picks regression with structured logging.
    ///
    /// Same inputs as the post-crkft.2 flip at
    /// `negotiate_suite_ignores_initiator_order_preference`
    /// (initiator `[Suite2, Suite1]`, responder `[Suite1, Suite2]`) but
    /// wrapped in `run_logged_test` so the responder-picks invariant is
    /// exercised through the logging harness as well.
    ///
    /// Renamed from `suite_negotiation_prefers_initiator_order` (br-abezh):
    /// the old name + assertion asserted initiator-picks semantics, which
    /// directly contradicted `docs/protocol/session-handshake.md` after
    /// crkft.2 flipped the public API to responder-picks.
    #[test]
    fn suite_negotiation_prefers_responder_order() {
        let context = LogContext::new("handshake", "suite_negotiate");
        run_logged_test(
            "suite_negotiation_prefers_responder_order",
            2,
            &context,
            || {
                let initiator = [SessionCryptoSuite::Suite2, SessionCryptoSuite::Suite1];
                let responder = [SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2];
                let chosen = negotiate_suite(&initiator, &responder).expect("suite chosen");
                assert_eq!(chosen, SessionCryptoSuite::Suite1);
                assert_eq!(chosen.id(), 1);
            },
        );
    }

    #[test]
    fn session_mac_round_trip() {
        let session_id = MeshSessionId([0x22_u8; 16]);
        let context = LogContext::new("established", "mac_round_trip")
            .with_session(&session_id)
            .with_suite(SessionCryptoSuite::Suite2);
        run_logged_test("session_mac_round_trip", 2, &context, || {
            let key = [0x11_u8; 32];
            let frame = b"frame-bytes";
            let mac = compute_session_mac(
                SessionCryptoSuite::Suite2,
                &key,
                &session_id,
                SessionDirection::InitiatorToResponder,
                7,
                frame,
            )
            .expect("mac computed");
            verify_session_mac(
                SessionCryptoSuite::Suite2,
                &key,
                &session_id,
                SessionDirection::InitiatorToResponder,
                7,
                frame,
                &mac,
            )
            .expect("mac verified");
        });
    }

    #[test]
    fn fcps_datagram_encode_decode() {
        let session_id = MeshSessionId([0x33_u8; 16]);
        let context = LogContext::new("datagram", "encode_decode").with_session(&session_id);
        run_logged_test("fcps_datagram_encode_decode", 3, &context, || {
            let datagram = FcpsDatagram {
                session_id,
                seq: 42,
                mac: [0x44_u8; 16],
                frame_bytes: vec![0xAA, 0xBB, 0xCC],
            };
            let encoded = datagram.encode();
            let decoded =
                FcpsDatagram::decode(&encoded, DEFAULT_MAX_DATAGRAM_BYTES).expect("decode ok");
            assert_eq!(decoded.session_id, datagram.session_id);
            assert_eq!(decoded.seq, datagram.seq);
            assert_eq!(decoded.frame_bytes, datagram.frame_bytes);
        });
    }

    #[test]
    fn suite_negotiation_returns_none_when_no_overlap() {
        let context = LogContext::new("handshake", "suite_negotiate").with_reason("FCP-3001");
        run_logged_test(
            "suite_negotiation_returns_none_when_no_overlap",
            1,
            &context,
            || {
                let initiator = [SessionCryptoSuite::Suite1];
                let responder = [SessionCryptoSuite::Suite2];
                assert!(negotiate_suite(&initiator, &responder).is_none());
            },
        );
    }

    #[test]
    fn hello_signature_round_trip() {
        let initiator = TailscaleNodeId::new("node-initiator");
        let responder = TailscaleNodeId::new("node-responder");
        let context = LogContext::new("handshake", "hello_verify").with_peer(&responder);
        run_logged_test("hello_signature_round_trip", 3, &context, || {
            let signing_key = Ed25519SigningKey::generate();
            let mut hello = MeshSessionHello {
                from: initiator.clone(),
                to: responder.clone(),
                eph_pubkey: X25519SecretKey::generate().public_key(),
                nonce: SessionNonce([0x10_u8; 16]),
                cookie: None,
                timestamp: 1_704_067_200,
                suites: vec![SessionCryptoSuite::Suite1],
                transport_limits: Some(TransportLimits {
                    max_datagram_bytes: 1200,
                }),
                signature: None,
            };
            let transcript_before = hello.transcript_bytes().expect("transcript");
            hello.sign(&signing_key).expect("sign");
            let transcript_after = hello.transcript_bytes().expect("transcript");
            assert_eq!(transcript_before, transcript_after);
            hello.verify(&signing_key.verifying_key()).expect("verify");
        });
    }

    #[test]
    fn ack_signature_rejects_mismatched_hello() {
        let initiator = TailscaleNodeId::new("node-initiator");
        let responder = TailscaleNodeId::new("node-responder");
        let session_id = MeshSessionId([0x42_u8; 16]);
        let context = LogContext::new("handshake", "ack_verify")
            .with_session(&session_id)
            .with_peer(&initiator)
            .with_reason("FCP-3002");
        run_logged_test(
            "ack_signature_rejects_mismatched_hello",
            2,
            &context,
            || {
                let signing_key = Ed25519SigningKey::generate();
                let hello = MeshSessionHello {
                    from: initiator.clone(),
                    to: responder.clone(),
                    eph_pubkey: X25519SecretKey::generate().public_key(),
                    nonce: SessionNonce([0x11_u8; 16]),
                    cookie: None,
                    timestamp: 1_704_067_200,
                    suites: vec![SessionCryptoSuite::Suite1],
                    transport_limits: None,
                    signature: None,
                };
                let mut ack = MeshSessionAck {
                    from: responder.clone(),
                    to: initiator.clone(),
                    eph_pubkey: X25519SecretKey::generate().public_key(),
                    nonce: SessionNonce([0x22_u8; 16]),
                    session_id,
                    suite: SessionCryptoSuite::Suite1,
                    timestamp: 1_704_067_205,
                    signature: None,
                };
                ack.sign(&hello, &signing_key).expect("sign");
                ack.verify(&hello, &signing_key.verifying_key())
                    .expect("verify");

                let mut tampered = hello;
                tampered.nonce = SessionNonce([0x99_u8; 16]);
                assert!(matches!(
                    ack.verify(&tampered, &signing_key.verifying_key()),
                    Err(SessionError::InvalidSignature)
                ));
            },
        );
    }

    #[test]
    fn hello_signature_rejects_tampered_suite_offers() {
        let initiator = TailscaleNodeId::new("node-initiator");
        let responder = TailscaleNodeId::new("node-responder");
        let context = LogContext::new("handshake", "hello_verify")
            .with_peer(&initiator)
            .with_reason("suite_offer_tamper");
        run_logged_test(
            "hello_signature_rejects_tampered_suite_offers",
            2,
            &context,
            || {
                let signing_key = Ed25519SigningKey::generate();
                let mut hello = MeshSessionHello {
                    from: initiator.clone(),
                    to: responder.clone(),
                    eph_pubkey: X25519SecretKey::generate().public_key(),
                    nonce: SessionNonce([0x12_u8; 16]),
                    cookie: None,
                    timestamp: 1_704_067_200,
                    suites: vec![SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2],
                    transport_limits: None,
                    signature: None,
                };
                hello.sign(&signing_key).expect("sign");
                hello.verify(&signing_key.verifying_key()).expect("verify");

                let mut tampered = hello;
                tampered.suites = vec![SessionCryptoSuite::Suite1];
                assert!(matches!(
                    tampered.verify(&signing_key.verifying_key()),
                    Err(SessionError::InvalidSignature)
                ));
            },
        );
    }

    #[test]
    fn ack_verify_rejects_tampered_suite_offers_after_responder_selects_stronger_suite() {
        let initiator = TailscaleNodeId::new("node-initiator");
        let responder = TailscaleNodeId::new("node-responder");
        let session_id = MeshSessionId([0x43_u8; 16]);
        let context = LogContext::new("handshake", "ack_verify")
            .with_session(&session_id)
            .with_peer(&responder)
            .with_reason("suite_offer_downgrade");
        run_logged_test(
            "ack_verify_rejects_tampered_suite_offers_after_responder_selects_stronger_suite",
            3,
            &context,
            || {
                let initiator_signing_key = Ed25519SigningKey::generate();
                let responder_signing_key = Ed25519SigningKey::generate();
                let mut hello = MeshSessionHello {
                    from: initiator.clone(),
                    to: responder.clone(),
                    eph_pubkey: X25519SecretKey::generate().public_key(),
                    nonce: SessionNonce([0x13_u8; 16]),
                    cookie: None,
                    timestamp: 1_704_067_200,
                    suites: vec![SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2],
                    transport_limits: None,
                    signature: None,
                };
                hello.sign(&initiator_signing_key).expect("sign hello");
                hello
                    .verify(&initiator_signing_key.verifying_key())
                    .expect("verify hello");

                let mut ack = MeshSessionAck {
                    from: responder.clone(),
                    to: initiator.clone(),
                    eph_pubkey: X25519SecretKey::generate().public_key(),
                    nonce: SessionNonce([0x23_u8; 16]),
                    session_id,
                    suite: SessionCryptoSuite::Suite2,
                    timestamp: 1_704_067_205,
                    signature: None,
                };
                ack.sign(&hello, &responder_signing_key).expect("sign ack");
                ack.verify(&hello, &responder_signing_key.verifying_key())
                    .expect("verify ack");

                let mut tampered = hello;
                tampered.suites = vec![SessionCryptoSuite::Suite1];
                assert!(matches!(
                    ack.verify(&tampered, &responder_signing_key.verifying_key()),
                    Err(SessionError::AckSuiteNotOffered)
                ));
            },
        );
    }

    #[test]
    fn cookie_verification_detects_tampering() {
        let initiator = TailscaleNodeId::new("node-initiator");
        let responder = TailscaleNodeId::new("node-responder");
        let context = LogContext::new("handshake", "cookie_verify").with_peer(&responder);
        run_logged_test("cookie_verification_detects_tampering", 2, &context, || {
            let cookie_key = [0x55_u8; 32];
            let hello = MeshSessionHello {
                from: initiator.clone(),
                to: responder.clone(),
                eph_pubkey: X25519SecretKey::generate().public_key(),
                nonce: SessionNonce([0x22_u8; 16]),
                cookie: None,
                timestamp: 1_704_067_200,
                suites: vec![SessionCryptoSuite::Suite2],
                transport_limits: None,
                signature: None,
            };
            let cookie = compute_cookie(&cookie_key, &hello).expect("cookie");
            verify_cookie(&cookie_key, &hello, &cookie).expect("verify");

            let mut tampered = hello;
            tampered.timestamp += 1;
            assert!(matches!(
                verify_cookie(&cookie_key, &tampered, &cookie),
                Err(SessionError::InvalidCookie)
            ));
        });
    }

    #[test]
    fn derive_session_keys_is_deterministic_and_separated() {
        let initiator = TailscaleNodeId::new("node-initiator");
        let responder = TailscaleNodeId::new("node-responder");
        let session_id = MeshSessionId([0x77_u8; 16]);
        let context = LogContext::new("handshake", "key_derive").with_session(&session_id);
        run_logged_test(
            "derive_session_keys_is_deterministic_and_separated",
            4,
            &context,
            || {
                let sk_i = X25519SecretKey::from_bytes([0x12_u8; 32]);
                let sk_r = X25519SecretKey::from_bytes([0x34_u8; 32]);
                let shared = sk_i.diffie_hellman(&sk_r.public_key()).unwrap();
                let hello_nonce = SessionNonce([0x01_u8; 16]);
                let ack_nonce = SessionNonce([0x02_u8; 16]);
                let keys1 = derive_session_keys(
                    &shared,
                    SessionCryptoSuite::Suite1,
                    &session_id,
                    &initiator,
                    &responder,
                    &hello_nonce,
                    &ack_nonce,
                )
                .expect("keys");
                let keys2 = derive_session_keys(
                    &shared,
                    SessionCryptoSuite::Suite1,
                    &session_id,
                    &initiator,
                    &responder,
                    &hello_nonce,
                    &ack_nonce,
                )
                .expect("keys");
                assert_eq!(keys1, keys2);
                assert_ne!(keys1.k_mac_i2r, keys1.k_mac_r2i);
                assert_ne!(keys1.k_mac_i2r, keys1.k_ctx);
                assert_ne!(keys1.k_mac_r2i, keys1.k_ctx);
            },
        );
    }

    #[test]
    fn derive_session_keys_bind_selected_suite() {
        let initiator = TailscaleNodeId::new("node-initiator");
        let responder = TailscaleNodeId::new("node-responder");
        let session_id = MeshSessionId([0x78_u8; 16]);
        let context = LogContext::new("handshake", "key_derive")
            .with_session(&session_id)
            .with_reason("selected_suite_binding");
        run_logged_test(
            "derive_session_keys_bind_selected_suite",
            1,
            &context,
            || {
                let sk_i = X25519SecretKey::from_bytes([0x12_u8; 32]);
                let sk_r = X25519SecretKey::from_bytes([0x34_u8; 32]);
                let shared = sk_i.diffie_hellman(&sk_r.public_key()).unwrap();
                let hello_nonce = SessionNonce([0x01_u8; 16]);
                let ack_nonce = SessionNonce([0x02_u8; 16]);
                let suite1_keys = derive_session_keys(
                    &shared,
                    SessionCryptoSuite::Suite1,
                    &session_id,
                    &initiator,
                    &responder,
                    &hello_nonce,
                    &ack_nonce,
                )
                .expect("suite1 keys");
                let suite2_keys = derive_session_keys(
                    &shared,
                    SessionCryptoSuite::Suite2,
                    &session_id,
                    &initiator,
                    &responder,
                    &hello_nonce,
                    &ack_nonce,
                )
                .expect("suite2 keys");
                assert_ne!(suite1_keys, suite2_keys);
            },
        );
    }

    #[test]
    fn datagram_decode_rejects_invalid_lengths() {
        let session_id = MeshSessionId([0x99_u8; 16]);
        let context = LogContext::new("datagram", "decode_bounds")
            .with_session(&session_id)
            .with_reason("FCP-3003");
        run_logged_test(
            "datagram_decode_rejects_invalid_lengths",
            2,
            &context,
            || {
                let too_short = vec![0u8; FCPS_DATAGRAM_HEADER_LEN - 1];
                assert!(matches!(
                    FcpsDatagram::decode(&too_short, DEFAULT_MAX_DATAGRAM_BYTES),
                    Err(SessionError::DatagramTooShort { .. })
                ));

                let mut too_large = vec![0u8; FCPS_DATAGRAM_HEADER_LEN + 1];
                too_large.resize((DEFAULT_MAX_DATAGRAM_BYTES as usize) + 1, 0u8);
                assert!(matches!(
                    FcpsDatagram::decode(&too_large, DEFAULT_MAX_DATAGRAM_BYTES),
                    Err(SessionError::DatagramTooLarge { .. })
                ));
            },
        );
    }

    #[test]
    fn datagram_decode_accepts_empty_frame() {
        let session_id = MeshSessionId([0x9A_u8; 16]);
        let context = LogContext::new("datagram", "decode_bounds").with_session(&session_id);
        run_logged_test("datagram_decode_accepts_empty_frame", 2, &context, || {
            let mut bytes = Vec::with_capacity(FCPS_DATAGRAM_HEADER_LEN);
            bytes.extend_from_slice(session_id.as_bytes());
            bytes.extend_from_slice(&0u64.to_le_bytes());
            bytes.extend_from_slice(&[0u8; SESSION_MAC_SIZE]);

            let decoded =
                FcpsDatagram::decode(&bytes, DEFAULT_MAX_DATAGRAM_BYTES).expect("decode ok");
            assert_eq!(decoded.session_id, session_id);
            assert_eq!(decoded.frame_bytes, [] as [u8; 0]);
        });
    }

    #[test]
    fn datagram_decode_accepts_max_boundary() {
        let session_id = MeshSessionId([0x9B_u8; 16]);
        let context = LogContext::new("datagram", "decode_bounds").with_session(&session_id);
        run_logged_test("datagram_decode_accepts_max_boundary", 1, &context, || {
            let max = DEFAULT_MAX_DATAGRAM_BYTES as usize;
            let payload_len = max.saturating_sub(FCPS_DATAGRAM_HEADER_LEN);
            let mut bytes = Vec::with_capacity(max);
            bytes.extend_from_slice(session_id.as_bytes());
            bytes.extend_from_slice(&1u64.to_le_bytes());
            bytes.extend_from_slice(&[0u8; SESSION_MAC_SIZE]);
            bytes.extend(std::iter::repeat_n(0xAAu8, payload_len));

            let decoded =
                FcpsDatagram::decode(&bytes, DEFAULT_MAX_DATAGRAM_BYTES).expect("decode ok");
            assert_eq!(decoded.frame_bytes.len(), payload_len);
        });
    }

    #[test]
    fn session_mac_rejects_tampered_frame() {
        let session_id = MeshSessionId([0x55_u8; 16]);
        let context = LogContext::new("established", "mac_verify")
            .with_session(&session_id)
            .with_suite(SessionCryptoSuite::Suite1)
            .with_reason("FCP-3004");
        run_logged_test("session_mac_rejects_tampered_frame", 1, &context, || {
            let key = [0x44_u8; 32];
            let frame = b"frame-bytes";
            let mac = compute_session_mac(
                SessionCryptoSuite::Suite1,
                &key,
                &session_id,
                SessionDirection::ResponderToInitiator,
                9,
                frame,
            )
            .expect("mac");
            let mut tampered = frame.to_vec();
            tampered[0] ^= 0xFF;
            assert!(matches!(
                verify_session_mac(
                    SessionCryptoSuite::Suite1,
                    &key,
                    &session_id,
                    SessionDirection::ResponderToInitiator,
                    9,
                    &tampered,
                    &mac,
                ),
                Err(SessionError::InvalidSignature)
            ));
        });
    }

    #[test]
    fn session_mac_rejects_wrong_session_id() {
        let session_id = MeshSessionId([0x59_u8; 16]);
        let other_session_id = MeshSessionId([0x5A_u8; 16]);
        let context = LogContext::new("established", "mac_verify")
            .with_session(&session_id)
            .with_suite(SessionCryptoSuite::Suite2)
            .with_reason("FCP-3004");
        run_logged_test("session_mac_rejects_wrong_session_id", 1, &context, || {
            let key = [0x55_u8; 32];
            let frame = b"frame-bytes";
            let mac = compute_session_mac(
                SessionCryptoSuite::Suite2,
                &key,
                &session_id,
                SessionDirection::InitiatorToResponder,
                15,
                frame,
            )
            .expect("mac");
            assert!(matches!(
                verify_session_mac(
                    SessionCryptoSuite::Suite2,
                    &key,
                    &other_session_id,
                    SessionDirection::InitiatorToResponder,
                    15,
                    frame,
                    &mac,
                ),
                Err(SessionError::InvalidSignature)
            ));
        });
    }

    #[test]
    fn session_mac_rejects_wrong_key() {
        let session_id = MeshSessionId([0x56_u8; 16]);
        let context = LogContext::new("established", "mac_verify")
            .with_session(&session_id)
            .with_suite(SessionCryptoSuite::Suite2)
            .with_reason("FCP-3004");
        run_logged_test("session_mac_rejects_wrong_key", 1, &context, || {
            let key = [0x11_u8; 32];
            let wrong_key = [0x22_u8; 32];
            let frame = b"frame-bytes";
            let mac = compute_session_mac(
                SessionCryptoSuite::Suite2,
                &key,
                &session_id,
                SessionDirection::InitiatorToResponder,
                11,
                frame,
            )
            .expect("mac");
            assert!(matches!(
                verify_session_mac(
                    SessionCryptoSuite::Suite2,
                    &wrong_key,
                    &session_id,
                    SessionDirection::InitiatorToResponder,
                    11,
                    frame,
                    &mac,
                ),
                Err(SessionError::InvalidSignature)
            ));
        });
    }

    #[test]
    fn session_mac_rejects_wrong_direction() {
        let session_id = MeshSessionId([0x57_u8; 16]);
        let context = LogContext::new("established", "mac_verify")
            .with_session(&session_id)
            .with_suite(SessionCryptoSuite::Suite1)
            .with_reason("FCP-3004");
        run_logged_test("session_mac_rejects_wrong_direction", 1, &context, || {
            let key = [0x33_u8; 32];
            let frame = b"frame-bytes";
            let mac = compute_session_mac(
                SessionCryptoSuite::Suite1,
                &key,
                &session_id,
                SessionDirection::InitiatorToResponder,
                12,
                frame,
            )
            .expect("mac");
            assert!(matches!(
                verify_session_mac(
                    SessionCryptoSuite::Suite1,
                    &key,
                    &session_id,
                    SessionDirection::ResponderToInitiator,
                    12,
                    frame,
                    &mac,
                ),
                Err(SessionError::InvalidSignature)
            ));
        });
    }

    #[test]
    fn session_mac_rejects_wrong_sequence() {
        let session_id = MeshSessionId([0x58_u8; 16]);
        let context = LogContext::new("established", "mac_verify")
            .with_session(&session_id)
            .with_suite(SessionCryptoSuite::Suite1)
            .with_reason("FCP-3004");
        run_logged_test("session_mac_rejects_wrong_sequence", 1, &context, || {
            let key = [0x44_u8; 32];
            let frame = b"frame-bytes";
            let mac = compute_session_mac(
                SessionCryptoSuite::Suite1,
                &key,
                &session_id,
                SessionDirection::ResponderToInitiator,
                13,
                frame,
            )
            .expect("mac");
            assert!(matches!(
                verify_session_mac(
                    SessionCryptoSuite::Suite1,
                    &key,
                    &session_id,
                    SessionDirection::ResponderToInitiator,
                    14,
                    frame,
                    &mac,
                ),
                Err(SessionError::InvalidSignature)
            ));
        });
    }

    #[test]
    fn session_mac_rejects_wrong_suite() {
        let session_id = MeshSessionId([0x5B_u8; 16]);
        let context = LogContext::new("established", "mac_verify")
            .with_session(&session_id)
            .with_suite(SessionCryptoSuite::Suite1)
            .with_reason("FCP-3004");
        run_logged_test("session_mac_rejects_wrong_suite", 1, &context, || {
            let key = [0x66_u8; 32];
            let frame = b"frame-bytes";
            let mac = compute_session_mac(
                SessionCryptoSuite::Suite1,
                &key,
                &session_id,
                SessionDirection::InitiatorToResponder,
                16,
                frame,
            )
            .expect("mac");
            assert!(matches!(
                verify_session_mac(
                    SessionCryptoSuite::Suite2,
                    &key,
                    &session_id,
                    SessionDirection::InitiatorToResponder,
                    16,
                    frame,
                    &mac,
                ),
                Err(SessionError::InvalidSignature)
            ));
        });
    }

    #[test]
    fn datagram_mac_verification_round_trip() {
        let session_id = MeshSessionId([0x77_u8; 16]);
        let context = LogContext::new("datagram", "mac_verify")
            .with_session(&session_id)
            .with_suite(SessionCryptoSuite::Suite2)
            .with_reason("FCP-3004");
        run_logged_test("datagram_mac_verification_round_trip", 2, &context, || {
            let key = [0x55_u8; 32];
            let frame_bytes = vec![0xAB, 0xCD, 0xEF];
            let seq = 21;
            let mac = compute_session_mac(
                SessionCryptoSuite::Suite2,
                &key,
                &session_id,
                SessionDirection::InitiatorToResponder,
                seq,
                &frame_bytes,
            )
            .expect("mac");

            let datagram = FcpsDatagram {
                session_id,
                seq,
                mac,
                frame_bytes,
            };
            let encoded = datagram.encode();
            let decoded =
                FcpsDatagram::decode(&encoded, DEFAULT_MAX_DATAGRAM_BYTES).expect("decode ok");
            verify_session_mac(
                SessionCryptoSuite::Suite2,
                &key,
                &decoded.session_id,
                SessionDirection::InitiatorToResponder,
                decoded.seq,
                &decoded.frame_bytes,
                &decoded.mac,
            )
            .expect("mac verified");

            let mut tampered = decoded.mac;
            tampered[0] ^= 0xFF;
            assert!(matches!(
                verify_session_mac(
                    SessionCryptoSuite::Suite2,
                    &key,
                    &decoded.session_id,
                    SessionDirection::InitiatorToResponder,
                    decoded.seq,
                    &decoded.frame_bytes,
                    &tampered,
                ),
                Err(SessionError::InvalidSignature)
            ));
        });
    }

    #[test]
    fn replay_window_accepts_in_order_and_rejects_replay() {
        let mut window = ReplayWindow::new(128);
        let context = LogContext::new("established", "replay_check").with_details(json!({
            "sequence_received": 1,
            "decision": "accept"
        }));
        run_logged_test(
            "replay_window_accepts_in_order_and_rejects_replay",
            3,
            &context,
            || {
                assert!(!window.check_and_update(0));
                assert!(window.check_and_update(1));
                assert!(!window.check_and_update(1));
            },
        );
    }

    #[test]
    fn replay_window_allows_reordering_within_window() {
        let mut window = ReplayWindow::new(128);
        let context = LogContext::new("established", "replay_check").with_details(json!({
            "sequence_received": [100, 99, 95, 50],
            "decision": "accept",
            "reason": "IN_WINDOW"
        }));
        run_logged_test(
            "replay_window_allows_reordering_within_window",
            4,
            &context,
            || {
                assert!(window.check_and_update(100));
                assert!(window.check_and_update(99));
                assert!(window.check_and_update(95));
                assert!(window.check_and_update(50));
            },
        );
    }

    #[test]
    fn replay_window_rejects_old_sequences() {
        let mut window = ReplayWindow::new(128);
        let context = LogContext::new("established", "replay_check").with_details(json!({
            "sequence_received": 50,
            "decision": "reject",
            "reason": "STALE"
        }));
        run_logged_test("replay_window_rejects_old_sequences", 3, &context, || {
            assert!(window.check_and_update(200));
            assert!(!window.check_and_update(50));
            assert!(window.check_and_update(73));
        });
    }

    fn make_attested_hello_identity(
        from: &str,
        nonce: [u8; 16],
    ) -> (MeshSessionHello, MeshIdentity) {
        let owner_key = Ed25519SigningKey::generate();
        let node_signing = Ed25519SigningKey::generate();
        let node_issuance = Ed25519SigningKey::generate();
        let node_encryption = X25519SecretKey::generate();
        let node_id = NodeId::new(from);
        let tags = vec![TailscaleTag::fcp_tag("work")];

        let node_keys = NodeKeys::new(
            node_signing.verifying_key(),
            node_encryption.public_key(),
            node_issuance.verifying_key(),
        );

        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).expect("attest");

        let identity = MeshIdentity::new(
            node_id,
            "host".to_string(),
            Vec::new(),
            tags,
            owner_key.verifying_key(),
            node_keys,
        )
        .with_attestation(attestation);

        let mut hello = MeshSessionHello {
            from: TailscaleNodeId::new(from),
            to: TailscaleNodeId::new("node-responder"),
            eph_pubkey: node_encryption.public_key(),
            nonce: SessionNonce(nonce),
            cookie: None,
            timestamp: current_timestamp(),
            suites: vec![SessionCryptoSuite::Suite1],
            transport_limits: None,
            signature: None,
        };
        hello.sign(&node_signing).expect("sign hello");
        (hello, identity)
    }

    #[test]
    fn hello_attestation_verifies_and_expired_fails() {
        let owner_key = Ed25519SigningKey::generate();
        let node_signing = Ed25519SigningKey::generate();
        let node_issuance = Ed25519SigningKey::generate();
        let node_encryption = X25519SecretKey::generate();
        let node_id = NodeId::new("node-initiator");
        let tags = vec![TailscaleTag::fcp_tag("work")];

        let node_keys = NodeKeys::new(
            node_signing.verifying_key(),
            node_encryption.public_key(),
            node_issuance.verifying_key(),
        );

        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).expect("attest");

        let identity = MeshIdentity::new(
            node_id,
            "host".to_string(),
            Vec::new(),
            tags,
            owner_key.verifying_key(),
            node_keys,
        )
        .with_attestation(attestation);

        let mut hello = MeshSessionHello {
            from: TailscaleNodeId::new("node-initiator"),
            to: TailscaleNodeId::new("node-responder"),
            eph_pubkey: node_encryption.public_key(),
            nonce: SessionNonce([0xAB_u8; 16]),
            cookie: None,
            timestamp: current_timestamp(),
            suites: vec![SessionCryptoSuite::Suite1],
            transport_limits: None,
            signature: None,
        };
        hello.sign(&node_signing).expect("sign hello");

        let context = LogContext::new("handshake", "attestation_verify");
        run_logged_test(
            "hello_attestation_verifies_and_expired_fails",
            2,
            &context,
            || {
                verify_hello_attested(&hello, &identity, &TimePolicy::default())
                    .expect("attestation ok");

                let mut expired = identity.clone();
                if let Some(att) = expired.attestation.as_mut() {
                    att.expires_at = Utc::now() - Duration::hours(1);
                }
                assert!(matches!(
                    verify_hello_attested(&hello, &expired, &TimePolicy::default()),
                    Err(SessionError::AttestationExpired)
                ));
            },
        );
    }

    #[test]
    fn ack_attestation_detects_node_mismatch() {
        let owner_key = Ed25519SigningKey::generate();
        let node_signing = Ed25519SigningKey::generate();
        let node_issuance = Ed25519SigningKey::generate();
        let node_encryption = X25519SecretKey::generate();
        let node_id = NodeId::new("node-responder");
        let tags = vec![TailscaleTag::fcp_tag("work")];

        let node_keys = NodeKeys::new(
            node_signing.verifying_key(),
            node_encryption.public_key(),
            node_issuance.verifying_key(),
        );

        let attestation =
            NodeKeyAttestation::sign(&owner_key, &node_id, &node_keys, &tags, 24).expect("attest");

        let identity = MeshIdentity::new(
            node_id,
            "host".to_string(),
            Vec::new(),
            tags,
            owner_key.verifying_key(),
            node_keys,
        )
        .with_attestation(attestation);

        let ts = current_timestamp();
        let mut hello = MeshSessionHello {
            from: TailscaleNodeId::new("node-initiator"),
            to: TailscaleNodeId::new("node-responder"),
            eph_pubkey: X25519SecretKey::generate().public_key(),
            nonce: SessionNonce([0x11_u8; 16]),
            cookie: None,
            timestamp: ts,
            suites: vec![SessionCryptoSuite::Suite1],
            transport_limits: None,
            signature: None,
        };
        hello.sign(&node_signing).expect("sign hello");

        let mut ack = MeshSessionAck {
            from: TailscaleNodeId::new("node-responder"),
            to: TailscaleNodeId::new("node-initiator"),
            eph_pubkey: node_encryption.public_key(),
            nonce: SessionNonce([0x22_u8; 16]),
            session_id: MeshSessionId([0x10_u8; 16]),
            suite: SessionCryptoSuite::Suite1,
            timestamp: ts + 5,
            signature: None,
        };
        ack.sign(&hello, &node_signing).expect("sign ack");

        let mut mismatched = identity;
        mismatched.node_id = NodeId::new("node-other");
        let context = LogContext::new("handshake", "attestation_verify").with_reason("FCP-3006");
        run_logged_test("ack_attestation_detects_node_mismatch", 1, &context, || {
            assert!(matches!(
                verify_ack_attested(&ack, &hello, &mismatched, &TimePolicy::default()),
                Err(SessionError::AttestationNodeMismatch)
            ));
        });
    }

    #[test]
    fn hello_replay_window_rejects_duplicate_nonce_from_same_peer() {
        let (hello, identity) = make_attested_hello_identity("node-initiator", [0x55; 16]);
        let replayed_hello = hello.clone();
        let mut replay_window = HelloReplayWindow::new(8);

        verify_hello_attested_with_replay(
            &hello,
            &identity,
            &TimePolicy::default(),
            &mut replay_window,
        )
        .expect("first hello accepted");

        assert!(matches!(
            verify_hello_attested_with_replay(
                &replayed_hello,
                &identity,
                &TimePolicy::default(),
                &mut replay_window,
            ),
            Err(SessionError::DuplicateHelloNonce)
        ));
    }

    #[test]
    fn hello_replay_window_allows_same_nonce_from_distinct_peers() {
        let (hello_a, identity_a) = make_attested_hello_identity("node-a", [0x66; 16]);
        let (hello_b, identity_b) = make_attested_hello_identity("node-b", [0x66; 16]);
        let mut replay_window = HelloReplayWindow::new(8);

        verify_hello_attested_with_replay(
            &hello_a,
            &identity_a,
            &TimePolicy::default(),
            &mut replay_window,
        )
        .expect("first peer accepted");

        verify_hello_attested_with_replay(
            &hello_b,
            &identity_b,
            &TimePolicy::default(),
            &mut replay_window,
        )
        .expect("same nonce from a different peer should remain distinct");
    }

    // ── Batch 2: SunnyMoose test expansion ──

    #[test]
    fn suite_from_id_roundtrip() {
        assert_eq!(
            SessionCryptoSuite::try_from_id(1).expect("valid"),
            SessionCryptoSuite::Suite1
        );
        assert_eq!(
            SessionCryptoSuite::try_from_id(2).expect("valid"),
            SessionCryptoSuite::Suite2
        );
        assert!(SessionCryptoSuite::try_from_id(0).is_err());
        assert!(SessionCryptoSuite::try_from_id(3).is_err());
        assert!(SessionCryptoSuite::try_from_id(255).is_err());
    }

    #[test]
    fn suite_as_str() {
        assert_eq!(SessionCryptoSuite::Suite1.as_str(), "suite1-hmacsha256");
        assert_eq!(SessionCryptoSuite::Suite2.as_str(), "suite2-blake3");
    }

    #[test]
    fn mesh_session_id_new_is_random() {
        let a = MeshSessionId::new();
        let b = MeshSessionId::new();
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_eq!(a.as_bytes().len(), SESSION_ID_SIZE);
    }

    #[test]
    fn session_nonce_new_is_random() {
        let a = SessionNonce::new();
        let b = SessionNonce::new();
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_eq!(a.as_bytes().len(), SESSION_NONCE_SIZE);
    }

    #[test]
    fn session_cookie_try_from_slice() {
        let bytes = [0xCC; SESSION_COOKIE_SIZE];
        let cookie = SessionCookie::try_from_slice(&bytes).expect("valid");
        assert_eq!(cookie.as_bytes(), &bytes);
        // Wrong length should fail
        assert!(SessionCookie::try_from_slice(&[0; 10]).is_err());
    }

    #[test]
    fn replay_window_highest_seq_advances() {
        let mut window = ReplayWindow::new(128);
        assert_eq!(window.highest_seq(), 0);
        assert!(window.check_and_update(5));
        assert!(window.check_and_update(10));
        assert_eq!(window.highest_seq(), 10);
        // Going backwards within window doesn't change highest
        assert!(window.check_and_update(8));
        assert_eq!(window.highest_seq(), 10);
    }

    #[test]
    fn replay_window_boundary_at_window_edge() {
        let mut window = ReplayWindow::new(128);
        // Accept seq 200, then try seq at the boundary
        assert!(window.check_and_update(200));
        // seq 73 is 200 - 127 = still just inside window
        assert!(window.check_and_update(73));
        // seq 72 is outside the window
        assert!(!window.check_and_update(72));
    }

    #[test]
    fn datagram_decode_too_short() {
        let short = vec![0u8; 10];
        let err = FcpsDatagram::decode(&short, DEFAULT_MAX_DATAGRAM_BYTES).expect_err("too short");
        assert!(matches!(err, SessionError::DatagramTooShort { .. }));
    }

    #[test]
    fn datagram_decode_too_large() {
        let datagram = FcpsDatagram {
            session_id: MeshSessionId([0xAA; 16]),
            seq: 1,
            mac: [0xBB; SESSION_MAC_SIZE],
            frame_bytes: vec![0xCC; 2000],
        };
        let encoded = datagram.encode();
        let err = FcpsDatagram::decode(&encoded, 100).expect_err("too large");
        assert!(matches!(err, SessionError::DatagramTooLarge { .. }));
    }

    #[test]
    fn session_keys_different_per_direction() {
        let sk = X25519SecretKey::generate();
        let pk = X25519SecretKey::generate().public_key();
        let shared_secret = sk.diffie_hellman(&pk).unwrap();
        let session_id = MeshSessionId([0xAA; 16]);
        let initiator = TailscaleNodeId::new("node-init");
        let responder = TailscaleNodeId::new("node-resp");
        let hello_nonce = SessionNonce([0x11; 16]);
        let ack_nonce = SessionNonce([0x22; 16]);
        let keys = derive_session_keys(
            &shared_secret,
            SessionCryptoSuite::Suite1,
            &session_id,
            &initiator,
            &responder,
            &hello_nonce,
            &ack_nonce,
        )
        .expect("derive keys");
        // i2r and r2i keys must differ
        assert_ne!(keys.k_mac_i2r, keys.k_mac_r2i);
        // k_ctx must be independent
        assert_ne!(keys.k_ctx, keys.k_mac_i2r);
        assert_ne!(keys.k_ctx, keys.k_mac_r2i);
    }

    #[test]
    fn session_keys_deterministic() {
        let sk = X25519SecretKey::from_bytes([0xBB; 32]);
        let pk = X25519SecretKey::from_bytes([0xCC; 32]).public_key();
        let shared_secret = sk.diffie_hellman(&pk).unwrap();
        let session_id = MeshSessionId([0xDD; 16]);
        let initiator = TailscaleNodeId::new("node-a");
        let responder = TailscaleNodeId::new("node-b");
        let hello_nonce = SessionNonce([0x33; 16]);
        let ack_nonce = SessionNonce([0x44; 16]);
        let keys_a = derive_session_keys(
            &shared_secret,
            SessionCryptoSuite::Suite1,
            &session_id,
            &initiator,
            &responder,
            &hello_nonce,
            &ack_nonce,
        )
        .expect("derive keys a");
        let keys_b = derive_session_keys(
            &shared_secret,
            SessionCryptoSuite::Suite1,
            &session_id,
            &initiator,
            &responder,
            &hello_nonce,
            &ack_nonce,
        )
        .expect("derive keys b");
        assert_eq!(keys_a.k_mac_i2r, keys_b.k_mac_i2r);
        assert_eq!(keys_a.k_mac_r2i, keys_b.k_mac_r2i);
        assert_eq!(keys_a.k_ctx, keys_b.k_ctx);
    }

    #[test]
    fn session_direction_as_u8() {
        assert_eq!(SessionDirection::InitiatorToResponder.as_u8(), 0x00);
        assert_eq!(SessionDirection::ResponderToInitiator.as_u8(), 0x01);
    }

    #[test]
    fn time_policy_default_values() {
        let policy = TimePolicy::default();
        assert_eq!(policy.max_skew_secs, 120);
    }

    #[test]
    fn session_replay_policy_default() {
        let policy = SessionReplayPolicy::default();
        assert!(policy.max_reorder_window > 0);
    }

    #[test]
    fn error_display_messages() {
        assert_eq!(
            SessionError::InvalidSuiteId(99).to_string(),
            "invalid session crypto suite id 99"
        );
        assert_eq!(
            SessionError::NoMutualSuite.to_string(),
            "no mutually supported session crypto suite"
        );
        assert_eq!(
            SessionError::InvalidCookie.to_string(),
            "invalid stateless cookie"
        );
        assert_eq!(
            SessionError::DatagramTooShort { len: 5 }.to_string(),
            "FCPS datagram too short (len 5)"
        );
        assert_eq!(
            SessionError::DatagramTooLarge {
                len: 2000,
                max: 1200
            }
            .to_string(),
            "FCPS datagram too large (len 2000 > max 1200)"
        );
        assert_eq!(
            SessionError::TimestampSkew {
                delta: 500,
                max: 120
            }
            .to_string(),
            "timestamp skew too large (delta 500 > max 120)"
        );
    }

    // ── Security regression: current_timestamp pre-epoch safety (1fcd949) ──

    #[test]
    fn test_current_timestamp_returns_nonzero() {
        // On a normal system, current_timestamp should return a reasonable value
        let ts = current_timestamp();
        // Should be after 2025-01-01 (Unix timestamp 1735689600)
        assert!(ts > 1_735_689_600, "Timestamp {ts} seems too low for 2025+");
    }

    #[test]
    fn test_current_timestamp_does_not_panic() {
        // The fix ensures this never panics, even on edge-case systems.
        // We can't easily mock SystemTime::now(), but we verify the function
        // signature guarantees a u64 return (no Result/Option) and that
        // unwrap_or_default produces 0 on pre-epoch clocks.
        use std::time::UNIX_EPOCH;

        // Simulate what the function does: duration_since returns Err for
        // pre-epoch clocks, and unwrap_or_default yields Duration::ZERO (0 secs).
        let pre_epoch_result = UNIX_EPOCH
            .checked_sub(std::time::Duration::from_secs(100))
            .map(|pre_epoch| {
                pre_epoch
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            });
        // If checked_sub succeeds (it should), the result is 0
        if let Some(ts) = pre_epoch_result {
            assert_eq!(ts, 0, "Pre-epoch clock should produce timestamp 0");
        }
    }

    // ── SessionCryptoSuite serde roundtrip ─────────────────────────────

    #[test]
    fn test_session_crypto_suite_serde_roundtrip() {
        for suite in [SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2] {
            let json = serde_json::to_string(&suite).unwrap();
            let deserialized: SessionCryptoSuite = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, suite);
        }
    }

    #[test]
    fn test_session_crypto_suite_as_str() {
        assert_eq!(SessionCryptoSuite::Suite1.as_str(), "suite1-hmacsha256");
        assert_eq!(SessionCryptoSuite::Suite2.as_str(), "suite2-blake3");
    }

    #[test]
    fn test_session_crypto_suite_invalid_id() {
        let err = SessionCryptoSuite::try_from_id(0);
        assert!(err.is_err());
        let err = SessionCryptoSuite::try_from_id(3);
        assert!(err.is_err());
        let err = SessionCryptoSuite::try_from_id(255);
        assert!(err.is_err());
    }

    #[test]
    fn test_session_crypto_suite_serde_invalid() {
        let result = serde_json::from_str::<SessionCryptoSuite>("0");
        assert!(result.is_err());
        let result = serde_json::from_str::<SessionCryptoSuite>("99");
        assert!(result.is_err());
    }

    // ── SessionNonce / MeshSessionId defaults ──────────────────────────

    #[test]
    fn test_session_nonce_default_is_random() {
        let n1 = SessionNonce::default();
        let n2 = SessionNonce::default();
        // Extremely unlikely to be equal
        assert_ne!(n1.as_bytes(), n2.as_bytes());
    }

    #[test]
    fn test_mesh_session_id_default_is_random() {
        let id1 = MeshSessionId::default();
        let id2 = MeshSessionId::default();
        assert_ne!(id1.as_bytes(), id2.as_bytes());
    }

    // ── SessionCookie ──────────────────────────────────────────────────

    #[test]
    fn test_session_cookie_try_from_slice_valid() {
        let bytes = [42u8; SESSION_COOKIE_SIZE];
        let cookie = SessionCookie::try_from_slice(&bytes).unwrap();
        assert_eq!(cookie.as_bytes(), &bytes);
    }

    #[test]
    fn test_session_cookie_try_from_slice_wrong_length() {
        let err = SessionCookie::try_from_slice(&[0u8; 16]).unwrap_err();
        assert!(matches!(err, SessionError::InvalidCookieLength { len: 16 }));
    }

    // ── TransportLimits ────────────────────────────────────────────────

    #[test]
    fn test_transport_limits_effective_max_zero() {
        let tl = TransportLimits {
            max_datagram_bytes: 0,
        };
        assert_eq!(tl.effective_max(), DEFAULT_MAX_DATAGRAM_BYTES);
    }

    #[test]
    fn test_transport_limits_effective_max_nonzero() {
        let tl = TransportLimits {
            max_datagram_bytes: 2000,
        };
        assert_eq!(tl.effective_max(), 2000);
    }

    #[test]
    fn test_transport_limits_default() {
        let tl = TransportLimits::default();
        assert_eq!(tl.max_datagram_bytes, DEFAULT_MAX_DATAGRAM_BYTES);
    }

    // ── ReplayWindow edge cases ────────────────────────────────────────

    #[test]
    fn test_replay_window_seq_zero_rejected() {
        let mut rw = ReplayWindow::new(128);
        assert!(!rw.check_and_update(0));
    }

    #[test]
    fn test_replay_window_small_window() {
        let mut rw = ReplayWindow::new(1);
        assert!(rw.check_and_update(1));
        assert!(!rw.check_and_update(1)); // replay
        assert!(rw.check_and_update(2));
        // seq 1 is now too old for window of 1
    }

    #[test]
    fn test_replay_window_window_size_zero_becomes_one() {
        let rw = ReplayWindow::new(0);
        // Constructor forces window_size = max(0, 1) = 1
        assert_eq!(rw.highest_seq(), 0);
    }

    #[test]
    fn test_replay_window_large_jump() {
        let mut rw = ReplayWindow::new(128);
        assert!(rw.check_and_update(1));
        assert!(rw.check_and_update(1000));
        // After a jump of 999, seq 1 is too old
        assert!(!rw.check_and_update(1));
        assert_eq!(rw.highest_seq(), 1000);
    }

    #[test]
    fn test_replay_window_out_of_order_within_window() {
        let mut rw = ReplayWindow::new(128);
        assert!(rw.check_and_update(5));
        assert!(rw.check_and_update(3)); // out of order, within window
        assert!(rw.check_and_update(4)); // out of order, within window
        assert!(!rw.check_and_update(3)); // replay
        assert!(!rw.check_and_update(4)); // replay
    }

    // ── SessionReplayPolicy / TimePolicy defaults ──────────────────────

    #[test]
    fn test_session_replay_policy_defaults() {
        let policy = SessionReplayPolicy::default();
        assert_eq!(policy.max_reorder_window, 128);
        assert_eq!(policy.rekey_after_frames, 1_000_000_000);
        assert_eq!(policy.rekey_after_seconds, 86_400);
        assert_eq!(policy.rekey_after_bytes, 1_099_511_627_776);
    }

    #[test]
    fn test_time_policy_defaults() {
        let policy = TimePolicy::default();
        assert_eq!(policy.max_skew_secs, 120);
        assert!(policy.log_skew_events);
    }

    // ── SessionDirection ───────────────────────────────────────────────

    #[test]
    fn test_session_direction_as_u8() {
        assert_eq!(SessionDirection::InitiatorToResponder.as_u8(), 0x00);
        assert_eq!(SessionDirection::ResponderToInitiator.as_u8(), 0x01);
    }

    // ── SessionKeys mac_key ────────────────────────────────────────────

    #[test]
    fn test_session_keys_mac_key_direction() {
        let keys = SessionKeys {
            k_mac_i2r: [1u8; 32],
            k_mac_r2i: [2u8; 32],
            k_ctx: [3u8; 32],
        };
        assert_eq!(
            keys.mac_key(SessionDirection::InitiatorToResponder),
            &[1u8; 32]
        );
        assert_eq!(
            keys.mac_key(SessionDirection::ResponderToInitiator),
            &[2u8; 32]
        );
    }

    // ── negotiate_suite edge cases ─────────────────────────────────────

    #[test]
    fn test_negotiate_suite_empty_initiator() {
        assert!(negotiate_suite(&[], &[SessionCryptoSuite::Suite1]).is_none());
    }

    #[test]
    fn test_negotiate_suite_empty_responder() {
        assert!(negotiate_suite(&[SessionCryptoSuite::Suite1], &[]).is_none());
    }

    #[test]
    fn test_negotiate_suite_both_empty() {
        assert!(negotiate_suite(&[], &[]).is_none());
    }

    #[test]
    fn test_negotiate_suite_responder_preference() {
        // Initiator offers [Suite2, Suite1]; responder prefers Suite1 (listed first).
        // Responder-picks semantics → Suite1 wins even though initiator listed Suite2 first.
        let result = negotiate_suite(
            &[SessionCryptoSuite::Suite2, SessionCryptoSuite::Suite1],
            &[SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2],
        );
        assert_eq!(result, Some(SessionCryptoSuite::Suite1));
    }

    // ── compute_cookie determinism ─────────────────────────────────────

    #[test]
    fn test_compute_cookie_deterministic() {
        let key = [0xABu8; 32];
        let hello = make_hello();
        let cookie1 = compute_cookie(&key, &hello).unwrap();
        let cookie2 = compute_cookie(&key, &hello).unwrap();
        assert_eq!(cookie1.as_bytes(), cookie2.as_bytes());
    }

    #[test]
    fn test_compute_cookie_different_keys() {
        let key1 = [0xABu8; 32];
        let key2 = [0xCDu8; 32];
        let hello = make_hello();
        let cookie1 = compute_cookie(&key1, &hello).unwrap();
        let cookie2 = compute_cookie(&key2, &hello).unwrap();
        assert_ne!(cookie1.as_bytes(), cookie2.as_bytes());
    }

    fn make_hello() -> MeshSessionHello {
        use fcp_crypto::X25519SecretKey;
        let secret = X25519SecretKey::generate();
        MeshSessionHello {
            from: TailscaleNodeId::new("node-init"),
            to: TailscaleNodeId::new("node-resp"),
            eph_pubkey: secret.public_key(),
            nonce: SessionNonce([0u8; 16]),
            cookie: None,
            timestamp: 1_700_000_000,
            suites: vec![SessionCryptoSuite::Suite1],
            transport_limits: None,
            signature: None,
        }
    }

    fn make_ack() -> MeshSessionAck {
        use fcp_crypto::X25519SecretKey;
        let secret = X25519SecretKey::generate();
        MeshSessionAck {
            from: TailscaleNodeId::new("node-resp"),
            to: TailscaleNodeId::new("node-init"),
            eph_pubkey: secret.public_key(),
            nonce: SessionNonce([1u8; 16]),
            session_id: MeshSessionId([0xAA; 16]),
            suite: SessionCryptoSuite::Suite1,
            timestamp: 1_700_000_001,
            signature: None,
        }
    }

    // ── decode_hello_cbor tests ─────────────────────────────────────

    #[test]
    fn decode_hello_cbor_valid_round_trip() {
        let context = LogContext::new("handshake", "decode_hello_cbor");
        run_logged_test("decode_hello_cbor_valid_round_trip", 2, &context, || {
            let hello = make_hello();
            let encoded = to_canonical_cbor(&hello).expect("encode hello");
            let decoded = decode_hello_cbor(&encoded).expect("decode hello");
            assert_eq!(decoded.from.as_str(), hello.from.as_str());
            assert_eq!(decoded.timestamp, hello.timestamp);
        });
    }

    #[test]
    fn decode_hello_cbor_rejects_empty() {
        let context = LogContext::new("handshake", "decode_hello_cbor").with_reason("empty_input");
        run_logged_test("decode_hello_cbor_rejects_empty", 1, &context, || {
            let err = decode_hello_cbor(&[]).expect_err("empty should fail");
            assert!(matches!(err, SessionError::Cbor(_)));
        });
    }

    #[test]
    fn decode_hello_cbor_rejects_garbage() {
        let context =
            LogContext::new("handshake", "decode_hello_cbor").with_reason("garbage_input");
        run_logged_test("decode_hello_cbor_rejects_garbage", 1, &context, || {
            let err = decode_hello_cbor(&[0xFF, 0xFE, 0xFD]).expect_err("garbage");
            assert!(matches!(err, SessionError::Cbor(_)));
        });
    }

    #[test]
    fn decode_hello_cbor_rejects_oversized() {
        let context = LogContext::new("handshake", "decode_hello_cbor").with_reason("oversized");
        run_logged_test("decode_hello_cbor_rejects_oversized", 1, &context, || {
            let oversized = vec![0u8; MAX_HANDSHAKE_BYTES + 1];
            let err = decode_hello_cbor(&oversized).expect_err("oversized");
            assert!(matches!(err, SessionError::Cbor(_)));
        });
    }

    #[test]
    fn decode_canonical_cbor_uses_canonical_depth_limit() {
        let context =
            LogContext::new("handshake", "decode_canonical_cbor").with_reason("depth_limit");
        run_logged_test(
            "decode_canonical_cbor_uses_canonical_depth_limit",
            2,
            &context,
            || {
                let mut at_limit = vec![0x81; MAX_CANONICALIZATION_DEPTH];
                at_limit.push(0x00);
                decode_canonical_cbor::<ciborium::Value>(&at_limit)
                    .expect("canonical depth limit must decode");

                let mut over_limit = vec![0x81; MAX_CANONICALIZATION_DEPTH + 1];
                over_limit.push(0x00);
                let err = decode_canonical_cbor::<ciborium::Value>(&over_limit)
                    .expect_err("over-depth handshake CBOR must fail before canonical re-encode");

                assert!(
                    matches!(
                        err,
                        SessionError::Cbor(SerializationError::DepthExceeded { .. })
                    ),
                    "expected depth-exceeded CBOR error, got {err:?}"
                );
            },
        );
    }

    // ── decode_ack_cbor tests ───────────────────────────────────────

    #[test]
    fn decode_ack_cbor_valid_round_trip() {
        let context = LogContext::new("handshake", "decode_ack_cbor");
        run_logged_test("decode_ack_cbor_valid_round_trip", 2, &context, || {
            let ack = make_ack();
            let encoded = to_canonical_cbor(&ack).expect("encode ack");
            let decoded = decode_ack_cbor(&encoded).expect("decode ack");
            assert_eq!(decoded.from.as_str(), ack.from.as_str());
            assert_eq!(decoded.session_id, ack.session_id);
        });
    }

    #[test]
    fn decode_ack_cbor_rejects_invalid() {
        let context = LogContext::new("handshake", "decode_ack_cbor").with_reason("invalid_cbor");
        run_logged_test("decode_ack_cbor_rejects_invalid", 1, &context, || {
            let err = decode_ack_cbor(&[0xAA, 0xBB]).expect_err("invalid");
            assert!(matches!(err, SessionError::Cbor(_)));
        });
    }

    // ── decode_cookie_bytes tests ───────────────────────────────────

    #[test]
    fn decode_cookie_bytes_valid() {
        let context = LogContext::new("handshake", "decode_cookie");
        run_logged_test("decode_cookie_bytes_valid", 1, &context, || {
            let bytes = [0xCC; SESSION_COOKIE_SIZE];
            let cookie = decode_cookie_bytes(&bytes).expect("valid cookie");
            assert_eq!(cookie.as_bytes(), &bytes);
        });
    }

    #[test]
    fn decode_cookie_bytes_invalid_length() {
        let context = LogContext::new("handshake", "decode_cookie").with_reason("invalid_length");
        run_logged_test("decode_cookie_bytes_invalid_length", 1, &context, || {
            let err = decode_cookie_bytes(&[0u8; 16]).expect_err("too short");
            assert!(matches!(err, SessionError::InvalidCookieLength { len: 16 }));
        });
    }

    #[test]
    fn decode_cookie_bytes_empty() {
        let context = LogContext::new("handshake", "decode_cookie").with_reason("empty");
        run_logged_test("decode_cookie_bytes_empty", 1, &context, || {
            let err = decode_cookie_bytes(&[]).expect_err("empty");
            assert!(matches!(err, SessionError::InvalidCookieLength { len: 0 }));
        });
    }

    // ── hello verify missing signature ──────────────────────────────

    #[test]
    fn hello_verify_missing_signature() {
        let context = LogContext::new("handshake", "verify").with_reason("missing_signature");
        run_logged_test("hello_verify_missing_signature", 1, &context, || {
            let hello = make_hello(); // signature is None
            let key = Ed25519SigningKey::generate();
            let err = hello.verify(&key.verifying_key()).expect_err("missing sig");
            assert!(matches!(err, SessionError::MissingSignature));
        });
    }

    #[test]
    fn ack_verify_missing_signature() {
        let context = LogContext::new("handshake", "verify").with_reason("missing_signature");
        run_logged_test("ack_verify_missing_signature", 1, &context, || {
            let ack = make_ack(); // signature is None
            let hello = make_hello();
            let key = Ed25519SigningKey::generate();
            let err = ack
                .verify(&hello, &key.verifying_key())
                .expect_err("missing sig");
            assert!(matches!(err, SessionError::MissingSignature));
        });
    }

    #[test]
    fn ack_verify_rejects_endpoint_mismatch() {
        let context = LogContext::new("handshake", "verify").with_reason("ack_hello_mismatch");
        run_logged_test("ack_verify_rejects_endpoint_mismatch", 1, &context, || {
            let signing_key = Ed25519SigningKey::generate();
            let hello = make_hello();
            let mut ack = make_ack();
            ack.to = TailscaleNodeId::new("node-someone-else");
            ack.sign(&hello, &signing_key).expect("sign ack");

            let err = ack
                .verify(&hello, &signing_key.verifying_key())
                .expect_err("ack endpoint mismatch should fail");
            assert!(matches!(err, SessionError::AckHelloMismatch));
        });
    }

    #[test]
    fn ack_verify_rejects_suite_not_offered_by_hello() {
        let context = LogContext::new("handshake", "verify").with_reason("suite_not_offered");
        run_logged_test(
            "ack_verify_rejects_suite_not_offered_by_hello",
            1,
            &context,
            || {
                let signing_key = Ed25519SigningKey::generate();
                let mut hello = make_hello();
                hello.suites = vec![SessionCryptoSuite::Suite1];

                let mut ack = make_ack();
                ack.suite = SessionCryptoSuite::Suite2;
                ack.sign(&hello, &signing_key).expect("sign ack");

                let err = ack
                    .verify(&hello, &signing_key.verifying_key())
                    .expect_err("suite not offered should fail");
                assert!(matches!(err, SessionError::AckSuiteNotOffered));
            },
        );
    }

    #[test]
    fn ack_suite_validation_rejects_suite_below_future_floor() {
        let context = LogContext::new("handshake", "verify").with_reason("suite_below_floor");
        run_logged_test(
            "ack_suite_validation_rejects_suite_below_future_floor",
            1,
            &context,
            || {
                let err = verify_ack_suite_against_floor(
                    SessionCryptoSuite::Suite1,
                    &[SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2],
                    SessionCryptoSuite::Suite2,
                )
                .expect_err("suite below a future floor must fail");
                assert!(matches!(
                    err,
                    SessionError::AckSuiteBelowMinimum {
                        actual: SessionCryptoSuite::Suite1,
                        minimum: SessionCryptoSuite::Suite2,
                    }
                ));
            },
        );
    }

    // ── suite id roundtrip ──────────────────────────────────────────

    #[test]
    fn suite_id_roundtrip_both_variants() {
        let context = LogContext::new("handshake", "suite_id");
        run_logged_test("suite_id_roundtrip_both_variants", 4, &context, || {
            assert_eq!(SessionCryptoSuite::Suite1.id(), 1);
            assert_eq!(SessionCryptoSuite::Suite2.id(), 2);
            assert_eq!(
                SessionCryptoSuite::try_from_id(1).unwrap(),
                SessionCryptoSuite::Suite1
            );
            assert_eq!(
                SessionCryptoSuite::try_from_id(2).unwrap(),
                SessionCryptoSuite::Suite2
            );
        });
    }

    #[test]
    fn suite_try_from_id_invalid() {
        let context = LogContext::new("handshake", "suite_id").with_reason("invalid_id");
        run_logged_test("suite_try_from_id_invalid", 3, &context, || {
            assert!(matches!(
                SessionCryptoSuite::try_from_id(0),
                Err(SessionError::InvalidSuiteId(0))
            ));
            assert!(matches!(
                SessionCryptoSuite::try_from_id(3),
                Err(SessionError::InvalidSuiteId(3))
            ));
            assert!(matches!(
                SessionCryptoSuite::try_from_id(255),
                Err(SessionError::InvalidSuiteId(255))
            ));
        });
    }

    #[test]
    fn suite_as_str_values() {
        let context = LogContext::new("handshake", "suite_label");
        run_logged_test("suite_as_str_values", 2, &context, || {
            assert_eq!(SessionCryptoSuite::Suite1.as_str(), "suite1-hmacsha256");
            assert_eq!(SessionCryptoSuite::Suite2.as_str(), "suite2-blake3");
        });
    }

    // ── as_bytes direct assertions ──────────────────────────────────

    #[test]
    fn mesh_session_id_as_bytes() {
        let context = LogContext::new("types", "as_bytes");
        run_logged_test("mesh_session_id_as_bytes", 2, &context, || {
            let id = MeshSessionId([0xAB; 16]);
            assert_eq!(id.as_bytes().len(), SESSION_ID_SIZE);
            assert_eq!(id.as_bytes(), &[0xAB; 16]);
        });
    }

    #[test]
    fn session_nonce_as_bytes() {
        let context = LogContext::new("types", "as_bytes");
        run_logged_test("session_nonce_as_bytes", 2, &context, || {
            let nonce = SessionNonce([0xCD; 16]);
            assert_eq!(nonce.as_bytes().len(), SESSION_NONCE_SIZE);
            assert_eq!(nonce.as_bytes(), &[0xCD; 16]);
        });
    }

    #[test]
    fn session_cookie_as_bytes() {
        let context = LogContext::new("types", "as_bytes");
        run_logged_test("session_cookie_as_bytes", 2, &context, || {
            let cookie = SessionCookie([0xEF; 32]);
            assert_eq!(cookie.as_bytes().len(), SESSION_COOKIE_SIZE);
            assert_eq!(cookie.as_bytes(), &[0xEF; 32]);
        });
    }

    // ── transport limits edge cases ─────────────────────────────────

    #[test]
    fn transport_limits_zero_uses_default() {
        let context = LogContext::new("types", "transport_limits");
        run_logged_test("transport_limits_zero_uses_default", 1, &context, || {
            let limits = TransportLimits {
                max_datagram_bytes: 0,
            };
            assert_eq!(limits.effective_max(), DEFAULT_MAX_DATAGRAM_BYTES);
        });
    }

    #[test]
    fn transport_limits_nonzero_preserved() {
        let context = LogContext::new("types", "transport_limits");
        run_logged_test("transport_limits_nonzero_preserved", 1, &context, || {
            let limits = TransportLimits {
                max_datagram_bytes: 500,
            };
            assert_eq!(limits.effective_max(), 500);
        });
    }

    // ── session error display ───────────────────────────────────────

    #[test]
    fn session_error_display_variants() {
        let context = LogContext::new("types", "error_display");
        run_logged_test("session_error_display_variants", 5, &context, || {
            assert!(
                SessionError::MissingSignature
                    .to_string()
                    .contains("missing signature")
            );
            assert!(
                SessionError::InvalidSignature
                    .to_string()
                    .contains("signature verification")
            );
            assert!(
                SessionError::InvalidCookie
                    .to_string()
                    .contains("invalid stateless cookie")
            );
            assert!(
                SessionError::InvalidAttestation
                    .to_string()
                    .contains("attestation")
            );
            assert!(
                SessionError::AckHelloMismatch
                    .to_string()
                    .contains("does not reflect")
            );
            assert!(
                SessionError::AckSuiteNotOffered
                    .to_string()
                    .contains("suite not offered")
            );
            assert!(
                SessionError::AckSuiteBelowMinimum {
                    actual: SessionCryptoSuite::Suite1,
                    minimum: SessionCryptoSuite::Suite2,
                }
                .to_string()
                .contains("below minimum")
            );
            assert!(
                SessionError::InvalidMacKeyLength
                    .to_string()
                    .contains("MAC key")
            );
        });
    }

    // ── hello_retry serde ───────────────────────────────────────────

    #[test]
    fn hello_retry_serde_roundtrip() {
        let context = LogContext::new("handshake", "hello_retry");
        run_logged_test("hello_retry_serde_roundtrip", 3, &context, || {
            let retry = MeshSessionHelloRetry {
                from: TailscaleNodeId::new("node-a"),
                to: TailscaleNodeId::new("node-b"),
                cookie: SessionCookie([0x77; 32]),
                timestamp: 1_700_000_000,
            };
            let json = serde_json::to_string(&retry).expect("serialize");
            let decoded: MeshSessionHelloRetry = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(decoded.from.as_str(), "node-a");
            assert_eq!(decoded.to.as_str(), "node-b");
            assert_eq!(decoded.timestamp, 1_700_000_000);
        });
    }

    // ── Batch 4: SunnyMoose deep-coverage expansion ──

    #[test]
    fn session_constants_values() {
        assert_eq!(SESSION_ID_SIZE, 16);
        assert_eq!(SESSION_NONCE_SIZE, 16);
        assert_eq!(SESSION_COOKIE_SIZE, 32);
        assert_eq!(SESSION_MAC_SIZE, 16);
        assert_eq!(FCPS_DATAGRAM_HEADER_LEN, 40);
        assert_eq!(DEFAULT_MAX_DATAGRAM_BYTES, 1200);
        assert_eq!(MAX_HANDSHAKE_BYTES, 16 * 1024);
    }

    #[test]
    fn session_direction_debug_clone_eq() {
        let dir = SessionDirection::InitiatorToResponder;
        let cloned = dir;
        assert_eq!(dir, cloned);
        let dbg = format!("{dir:?}");
        assert!(dbg.contains("InitiatorToResponder"));

        let dir2 = SessionDirection::ResponderToInitiator;
        assert_ne!(dir, dir2);
    }

    #[test]
    fn session_crypto_suite_debug_format() {
        let s1 = SessionCryptoSuite::Suite1;
        let dbg = format!("{s1:?}");
        assert!(dbg.contains("Suite1"));
    }

    #[test]
    fn session_crypto_suite_clone_copy_eq_hash() {
        use std::collections::HashSet;
        let s = SessionCryptoSuite::Suite2;
        let copy = s;
        assert_eq!(s, copy);

        let mut set = HashSet::new();
        set.insert(SessionCryptoSuite::Suite1);
        set.insert(SessionCryptoSuite::Suite2);
        set.insert(SessionCryptoSuite::Suite1);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn mesh_session_id_hash_in_set() {
        use std::collections::HashSet;
        let id1 = MeshSessionId([0xAA; 16]);
        let id2 = MeshSessionId([0xBB; 16]);
        let mut set = HashSet::new();
        set.insert(id1);
        set.insert(id2);
        set.insert(id1);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn session_nonce_hash_in_set() {
        use std::collections::HashSet;
        let n1 = SessionNonce([0x11; 16]);
        let n2 = SessionNonce([0x22; 16]);
        let mut set = HashSet::new();
        set.insert(n1);
        set.insert(n2);
        set.insert(n1);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn session_cookie_hash_in_set() {
        use std::collections::HashSet;
        let c1 = SessionCookie([0xAA; 32]);
        let c2 = SessionCookie([0xBB; 32]);
        let mut set = HashSet::new();
        set.insert(c1);
        set.insert(c2);
        set.insert(c1);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn replay_window_clone() {
        let mut window = ReplayWindow::new(128);
        assert!(window.check_and_update(5));
        assert!(window.check_and_update(10));
        let cloned = window.clone();
        assert_eq!(cloned.highest_seq(), 10);
    }

    #[test]
    fn session_replay_policy_clone_eq() {
        let policy = SessionReplayPolicy::default();
        let cloned = policy;
        assert_eq!(policy, cloned);
    }

    #[test]
    fn time_policy_clone_eq() {
        let policy = TimePolicy::default();
        let cloned = policy;
        assert_eq!(policy, cloned);
    }

    #[test]
    fn session_keys_clone_eq() {
        let keys = SessionKeys {
            k_mac_i2r: [0x11; 32],
            k_mac_r2i: [0x22; 32],
            k_ctx: [0x33; 32],
        };
        let cloned = keys;
        assert_eq!(keys, cloned);
    }

    #[test]
    fn session_keys_debug() {
        let keys = SessionKeys {
            k_mac_i2r: [0; 32],
            k_mac_r2i: [0; 32],
            k_ctx: [0; 32],
        };
        let dbg = format!("{keys:?}");
        assert!(dbg.contains("SessionKeys"));
    }

    #[test]
    fn datagram_clone_eq() {
        let dg = FcpsDatagram {
            session_id: MeshSessionId([0x11; 16]),
            seq: 42,
            mac: [0x22; SESSION_MAC_SIZE],
            frame_bytes: vec![0x33, 0x44],
        };
        let cloned = dg.clone();
        assert_eq!(dg, cloned);
    }

    #[test]
    fn datagram_debug_format() {
        let dg = FcpsDatagram {
            session_id: MeshSessionId([0; 16]),
            seq: 0,
            mac: [0; SESSION_MAC_SIZE],
            frame_bytes: vec![],
        };
        let dbg = format!("{dg:?}");
        assert!(dbg.contains("FcpsDatagram"));
    }

    #[test]
    fn session_mac_suite1_roundtrip() {
        let session_id = MeshSessionId([0x11; 16]);
        let key = [0x22; 32];
        let frame = b"suite1 mac test";
        let mac = compute_session_mac(
            SessionCryptoSuite::Suite1,
            &key,
            &session_id,
            SessionDirection::InitiatorToResponder,
            1,
            frame,
        )
        .expect("mac");
        verify_session_mac(
            SessionCryptoSuite::Suite1,
            &key,
            &session_id,
            SessionDirection::InitiatorToResponder,
            1,
            frame,
            &mac,
        )
        .expect("verify");
    }

    #[test]
    fn session_mac_suite2_roundtrip() {
        let session_id = MeshSessionId([0x33; 16]);
        let key = [0x44; 32];
        let frame = b"suite2 mac test";
        let mac = compute_session_mac(
            SessionCryptoSuite::Suite2,
            &key,
            &session_id,
            SessionDirection::ResponderToInitiator,
            99,
            frame,
        )
        .expect("mac");
        verify_session_mac(
            SessionCryptoSuite::Suite2,
            &key,
            &session_id,
            SessionDirection::ResponderToInitiator,
            99,
            frame,
            &mac,
        )
        .expect("verify");
    }

    #[test]
    fn session_error_attestation_verify_failed_display() {
        let err = SessionError::AttestationVerifyFailed {
            reason: "test reason".to_string(),
        };
        let display = err.to_string();
        assert!(display.contains("test reason"));
    }

    #[test]
    fn session_error_attestation_node_mismatch_display() {
        let err = SessionError::AttestationNodeMismatch;
        let display = err.to_string();
        assert!(display.contains("node id"));
    }

    #[test]
    fn session_error_attestation_expired_display() {
        let err = SessionError::AttestationExpired;
        let display = err.to_string();
        assert!(display.contains("expired"));
    }

    #[test]
    fn session_error_no_mutual_suite_display() {
        let err = SessionError::NoMutualSuite;
        let display = err.to_string();
        assert!(display.contains("mutual"));
    }

    #[test]
    fn session_error_invalid_cookie_length_display() {
        let err = SessionError::InvalidCookieLength { len: 10 };
        let display = err.to_string();
        assert!(display.contains("10"));
    }

    #[test]
    fn hello_retry_debug_clone() {
        let retry = MeshSessionHelloRetry {
            from: TailscaleNodeId::new("node-a"),
            to: TailscaleNodeId::new("node-b"),
            cookie: SessionCookie([0; 32]),
            timestamp: 0,
        };
        let cloned = retry.clone();
        assert_eq!(cloned.from.as_str(), "node-a");
        let dbg = format!("{retry:?}");
        assert!(dbg.contains("MeshSessionHelloRetry"));
    }

    #[test]
    fn transport_limits_serde_roundtrip() {
        let limits = TransportLimits {
            max_datagram_bytes: 1400,
        };
        let json = serde_json::to_string(&limits).expect("serialize");
        let back: TransportLimits = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.max_datagram_bytes, 1400);
    }

    #[test]
    fn transport_limits_effective_max_u16_max() {
        let limits = TransportLimits {
            max_datagram_bytes: u16::MAX,
        };
        assert_eq!(limits.effective_max(), u16::MAX);
    }

    #[test]
    fn transport_limits_effective_max_one() {
        let limits = TransportLimits {
            max_datagram_bytes: 1,
        };
        assert_eq!(limits.effective_max(), 1);
    }

    #[test]
    fn replay_window_debug_format() {
        let window = ReplayWindow::new(64);
        let dbg = format!("{window:?}");
        assert!(dbg.contains("ReplayWindow"));
    }

    #[test]
    fn replay_window_accepts_consecutive_then_rejects_all_replays() {
        let mut window = ReplayWindow::new(128);
        for seq in 1..=10u64 {
            assert!(window.check_and_update(seq), "seq {seq} should be accepted");
        }
        for seq in 1..=10u64 {
            assert!(
                !window.check_and_update(seq),
                "replay of seq {seq} should be rejected"
            );
        }
    }

    // ── Batch 5: SunnyMoose edge-case and integration tests ──

    #[test]
    fn derive_session_keys_different_nonces_produce_different_keys() {
        let sk = X25519SecretKey::from_bytes([0x12; 32]);
        let pk = X25519SecretKey::from_bytes([0x34; 32]).public_key();
        let shared = sk.diffie_hellman(&pk).unwrap();
        let session_id = MeshSessionId([0xAA; 16]);
        let initiator = TailscaleNodeId::new("node-i");
        let responder = TailscaleNodeId::new("node-r");
        let hello_nonce_a = SessionNonce([0x01; 16]);
        let hello_nonce_b = SessionNonce([0x02; 16]);
        let ack_nonce = SessionNonce([0x03; 16]);

        let keys_a = derive_session_keys(
            &shared,
            SessionCryptoSuite::Suite1,
            &session_id,
            &initiator,
            &responder,
            &hello_nonce_a,
            &ack_nonce,
        )
        .expect("keys a");
        let keys_b = derive_session_keys(
            &shared,
            SessionCryptoSuite::Suite1,
            &session_id,
            &initiator,
            &responder,
            &hello_nonce_b,
            &ack_nonce,
        )
        .expect("keys b");
        assert_ne!(keys_a.k_mac_i2r, keys_b.k_mac_i2r);
        assert_ne!(keys_a.k_ctx, keys_b.k_ctx);
    }

    #[test]
    fn derive_session_keys_swapped_roles_produce_different_keys() {
        let sk = X25519SecretKey::from_bytes([0x12; 32]);
        let pk = X25519SecretKey::from_bytes([0x34; 32]).public_key();
        let shared = sk.diffie_hellman(&pk).unwrap();
        let session_id = MeshSessionId([0xBB; 16]);
        let node_a = TailscaleNodeId::new("node-a");
        let node_b = TailscaleNodeId::new("node-b");
        let hello_nonce = SessionNonce([0x01; 16]);
        let ack_nonce = SessionNonce([0x02; 16]);

        let keys_ab = derive_session_keys(
            &shared,
            SessionCryptoSuite::Suite1,
            &session_id,
            &node_a,
            &node_b,
            &hello_nonce,
            &ack_nonce,
        )
        .expect("keys ab");
        let keys_ba = derive_session_keys(
            &shared,
            SessionCryptoSuite::Suite1,
            &session_id,
            &node_b,
            &node_a,
            &hello_nonce,
            &ack_nonce,
        )
        .expect("keys ba");
        assert_ne!(keys_ab.k_mac_i2r, keys_ba.k_mac_i2r);
    }

    #[test]
    fn nonce_reuse_with_same_keypair_does_not_allow_cross_session_replay() {
        let sk = X25519SecretKey::from_bytes([0x21; 32]);
        let pk = X25519SecretKey::from_bytes([0x43; 32]).public_key();
        let shared = sk.diffie_hellman(&pk).unwrap();
        let initiator = TailscaleNodeId::new("node-i");
        let responder = TailscaleNodeId::new("node-r");
        let hello_nonce = SessionNonce([0x11; 16]);
        let ack_nonce = SessionNonce([0x22; 16]);
        let session_a = MeshSessionId([0xA1; 16]);
        let session_b = MeshSessionId([0xB2; 16]);

        let keys_a = derive_session_keys(
            &shared,
            SessionCryptoSuite::Suite1,
            &session_a,
            &initiator,
            &responder,
            &hello_nonce,
            &ack_nonce,
        )
        .expect("keys a");
        let keys_b = derive_session_keys(
            &shared,
            SessionCryptoSuite::Suite1,
            &session_b,
            &initiator,
            &responder,
            &hello_nonce,
            &ack_nonce,
        )
        .expect("keys b");

        assert_ne!(
            keys_a.k_mac_i2r, keys_b.k_mac_i2r,
            "fresh session_id must domain-separate MAC keys even if nonces are reused"
        );
        assert_ne!(
            keys_a.k_ctx, keys_b.k_ctx,
            "context key must also change across sessions with reused nonces"
        );

        let frame_bytes = b"replayed frame";
        let seq = 7;
        let mac_a = compute_session_mac(
            SessionCryptoSuite::Suite1,
            keys_a.mac_key(SessionDirection::InitiatorToResponder),
            &session_a,
            SessionDirection::InitiatorToResponder,
            seq,
            frame_bytes,
        )
        .expect("compute old-session mac");

        assert!(
            matches!(
                verify_session_mac(
                    SessionCryptoSuite::Suite1,
                    keys_b.mac_key(SessionDirection::InitiatorToResponder),
                    &session_b,
                    SessionDirection::InitiatorToResponder,
                    seq,
                    frame_bytes,
                    &mac_a,
                ),
                Err(SessionError::InvalidSignature)
            ),
            "replaying a frame from session A into session B must fail even if both handshake nonces were reused"
        );
    }

    #[test]
    fn captured_ack_from_old_session_cannot_complete_fresh_handshake() {
        let initiator = TailscaleNodeId::new("node-i");
        let responder = TailscaleNodeId::new("node-r");
        let initiator_signing_key = Ed25519SigningKey::generate();
        let responder_signing_key = Ed25519SigningKey::generate();

        let mut old_hello = MeshSessionHello {
            from: initiator.clone(),
            to: responder.clone(),
            eph_pubkey: X25519SecretKey::generate().public_key(),
            nonce: SessionNonce([0x31; 16]),
            cookie: None,
            timestamp: 1_704_067_200,
            suites: vec![SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2],
            transport_limits: None,
            signature: None,
        };
        old_hello
            .sign(&initiator_signing_key)
            .expect("sign old hello");

        let mut captured_ack = MeshSessionAck {
            from: responder.clone(),
            to: initiator.clone(),
            eph_pubkey: X25519SecretKey::generate().public_key(),
            nonce: SessionNonce([0x41; 16]),
            session_id: MeshSessionId([0xC1; 16]),
            suite: SessionCryptoSuite::Suite2,
            timestamp: 1_704_067_205,
            signature: None,
        };
        captured_ack
            .sign(&old_hello, &responder_signing_key)
            .expect("sign captured ack");
        captured_ack
            .verify(&old_hello, &responder_signing_key.verifying_key())
            .expect("captured ack must verify against the original hello");

        let mut fresh_hello = MeshSessionHello {
            from: initiator,
            to: responder,
            eph_pubkey: X25519SecretKey::generate().public_key(),
            nonce: SessionNonce([0x32; 16]),
            cookie: None,
            timestamp: 1_704_067_260,
            suites: vec![SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2],
            transport_limits: None,
            signature: None,
        };
        fresh_hello
            .sign(&initiator_signing_key)
            .expect("sign fresh hello");
        fresh_hello
            .verify(&initiator_signing_key.verifying_key())
            .expect("fresh hello must verify");

        assert!(
            matches!(
                captured_ack.verify(&fresh_hello, &responder_signing_key.verifying_key()),
                Err(SessionError::InvalidSignature)
            ),
            "a captured ack from an old session must not verify against a fresh hello from the same peers"
        );
    }

    #[test]
    fn negotiate_suite_single_overlap() {
        let result = negotiate_suite(&[SessionCryptoSuite::Suite1], &[SessionCryptoSuite::Suite1]);
        assert_eq!(result, Some(SessionCryptoSuite::Suite1));
    }

    #[test]
    fn negotiate_suite_duplicate_entries() {
        let result = negotiate_suite(
            &[
                SessionCryptoSuite::Suite2,
                SessionCryptoSuite::Suite2,
                SessionCryptoSuite::Suite1,
            ],
            &[SessionCryptoSuite::Suite1],
        );
        // First match found is Suite1 (Suite2 is not in responder)
        assert_eq!(result, Some(SessionCryptoSuite::Suite1));
    }

    // ── crkft.3: responder-picks regression tests ────────────────────────
    // These tests lock in the responder-picks invariant. Do NOT rewrite
    // them to match a future change without first updating
    // docs/protocol/session-handshake.md.

    #[test]
    fn negotiate_suite_responder_wins_on_multi_suite_overlap() {
        // Both peers support both suites; responder lists Suite2 first.
        // Responder-picks semantics → Suite2 wins.
        let initiator = [SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2];
        let responder = [SessionCryptoSuite::Suite2, SessionCryptoSuite::Suite1];
        assert_eq!(
            negotiate_suite(&initiator, &responder),
            Some(SessionCryptoSuite::Suite2),
            "responder's first-preferred mutual suite must win"
        );
    }

    #[test]
    fn negotiate_suite_no_overlap_returns_none() {
        let initiator = [SessionCryptoSuite::Suite1];
        let responder = [SessionCryptoSuite::Suite2];
        assert_eq!(negotiate_suite(&initiator, &responder), None);
    }

    #[test]
    fn negotiate_suite_ignores_initiator_order_preference() {
        // Initiator lists Suite2 first; responder prefers Suite1.
        // Responder-picks → Suite1 wins.
        let initiator = [SessionCryptoSuite::Suite2, SessionCryptoSuite::Suite1];
        let responder = [SessionCryptoSuite::Suite1, SessionCryptoSuite::Suite2];
        assert_eq!(
            negotiate_suite(&initiator, &responder),
            Some(SessionCryptoSuite::Suite1),
        );
    }

    // ── crkft.4: MINIMUM_SUITE floor regression tests ────────────────────

    #[test]
    fn negotiate_suite_accepts_at_or_above_floor() {
        // MINIMUM_SUITE is itself the floor; negotiating it must succeed
        // when both peers offer/support it.
        assert_eq!(
            negotiate_suite(&[MINIMUM_SUITE], &[MINIMUM_SUITE]),
            Some(MINIMUM_SUITE),
        );
    }

    #[test]
    fn minimum_suite_equals_current_weakest() {
        // When a new stronger suite lands and Suite1 is deprecated,
        // update MINIMUM_SUITE to the new weakest and delete this
        // assertion (or bump it to the new floor). This test is the
        // mechanical checkpoint enforcing the versioning policy in
        // docs/protocol/session-handshake.md.
        assert_eq!(
            suite_rank(MINIMUM_SUITE),
            suite_rank(SessionCryptoSuite::Suite1),
            "MINIMUM_SUITE must track the weakest currently-supported suite"
        );
    }

    #[test]
    fn suite_rank_is_monotonic() {
        // Ranks must be strictly ordered by strength. If this fails,
        // the ordering logic in `suite_rank` is broken and the floor
        // check cannot be trusted.
        assert!(suite_rank(SessionCryptoSuite::Suite2) > suite_rank(SessionCryptoSuite::Suite1));
    }

    #[test]
    fn negotiate_suite_malicious_initiator_cannot_downgrade() {
        // Threat model: initiator is attacker-positioned and orders its
        // own list worst-first. Responder-picks semantics prevents the
        // initiator from dictating the outcome.
        //
        // Today both Suite1 and Suite2 are cryptographically sound so
        // "weaker" is fictional — this test documents INTENT, not an
        // exploitable condition. When a future suite deprecates one of
        // these, this test is what catches a regression that would make
        // the downgrade exploitable again.
        let initiator_ordered_worst_first = [
            SessionCryptoSuite::Suite1, // pretend this is "weaker"
            SessionCryptoSuite::Suite2,
        ];
        let responder_prefers_strong = [
            SessionCryptoSuite::Suite2, // strong
            SessionCryptoSuite::Suite1,
        ];
        assert_eq!(
            negotiate_suite(&initiator_ordered_worst_first, &responder_prefers_strong),
            Some(SessionCryptoSuite::Suite2),
            "initiator ordering must not dictate outcome"
        );
    }

    #[test]
    fn session_mac_empty_frame_bytes() {
        let session_id = MeshSessionId([0x11; 16]);
        let key = [0x22; 32];
        let frame: &[u8] = b"";
        let mac = compute_session_mac(
            SessionCryptoSuite::Suite1,
            &key,
            &session_id,
            SessionDirection::InitiatorToResponder,
            1,
            frame,
        )
        .expect("mac empty");
        verify_session_mac(
            SessionCryptoSuite::Suite1,
            &key,
            &session_id,
            SessionDirection::InitiatorToResponder,
            1,
            frame,
            &mac,
        )
        .expect("verify empty");
    }

    #[test]
    fn session_mac_large_frame_bytes() {
        let session_id = MeshSessionId([0x33; 16]);
        let key = [0x44; 32];
        let frame = vec![0xAB; 8192];
        let mac = compute_session_mac(
            SessionCryptoSuite::Suite2,
            &key,
            &session_id,
            SessionDirection::ResponderToInitiator,
            999,
            &frame,
        )
        .expect("mac large");
        verify_session_mac(
            SessionCryptoSuite::Suite2,
            &key,
            &session_id,
            SessionDirection::ResponderToInitiator,
            999,
            &frame,
            &mac,
        )
        .expect("verify large");
    }

    #[test]
    fn datagram_encode_decode_max_seq() {
        let datagram = FcpsDatagram {
            session_id: MeshSessionId([0xEE; 16]),
            seq: u64::MAX,
            mac: [0xFF; SESSION_MAC_SIZE],
            frame_bytes: vec![0x01, 0x02],
        };
        let encoded = datagram.encode();
        let decoded =
            FcpsDatagram::decode(&encoded, DEFAULT_MAX_DATAGRAM_BYTES).expect("decode ok");
        assert_eq!(decoded.seq, u64::MAX);
        assert_eq!(decoded.mac, [0xFF; SESSION_MAC_SIZE]);
    }

    #[test]
    fn cookie_try_from_slice_zero_length() {
        let err = SessionCookie::try_from_slice(&[]).expect_err("empty");
        assert!(matches!(err, SessionError::InvalidCookieLength { len: 0 }));
    }

    #[test]
    fn cookie_try_from_slice_one_too_long() {
        let bytes = [0u8; SESSION_COOKIE_SIZE + 1];
        let err = SessionCookie::try_from_slice(&bytes).expect_err("too long");
        assert!(matches!(err, SessionError::InvalidCookieLength { len: 33 }));
    }

    #[test]
    fn mesh_session_id_serde_json_roundtrip() {
        let id = MeshSessionId([0xAB; 16]);
        let json = serde_json::to_string(&id).expect("serialize");
        let back: MeshSessionId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, id);
    }

    #[test]
    fn session_nonce_serde_json_roundtrip() {
        let nonce = SessionNonce([0xCD; 16]);
        let json = serde_json::to_string(&nonce).expect("serialize");
        let back: SessionNonce = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, nonce);
    }

    #[test]
    fn session_cookie_serde_json_roundtrip() {
        let cookie = SessionCookie([0xEF; 32]);
        let json = serde_json::to_string(&cookie).expect("serialize");
        let back: SessionCookie = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, cookie);
    }

    #[test]
    fn session_mac_size_is_16() {
        assert_eq!(SESSION_MAC_SIZE, 16);
    }

    #[test]
    fn replay_window_u64_max_seq() {
        let mut window = ReplayWindow::new(128);
        assert!(window.check_and_update(u64::MAX));
        assert!(!window.check_and_update(u64::MAX)); // replay
        assert_eq!(window.highest_seq(), u64::MAX);
    }

    #[test]
    fn replay_window_large_window_size() {
        let mut window = ReplayWindow::new(1000);
        assert!(window.check_and_update(500));
        assert!(window.check_and_update(400)); // within window
        assert!(!window.check_and_update(400)); // replay
    }

    #[test]
    fn hello_transcript_with_cookie_differs_from_without() {
        let _signing_key = Ed25519SigningKey::generate();
        let hello_no_cookie = MeshSessionHello {
            from: TailscaleNodeId::new("node-a"),
            to: TailscaleNodeId::new("node-b"),
            eph_pubkey: X25519SecretKey::from_bytes([0x11; 32]).public_key(),
            nonce: SessionNonce([0; 16]),
            cookie: None,
            timestamp: 1_700_000_000,
            suites: vec![SessionCryptoSuite::Suite1],
            transport_limits: None,
            signature: None,
        };
        let hello_with_cookie = MeshSessionHello {
            cookie: Some(SessionCookie([0xCC; 32])),
            ..hello_no_cookie.clone()
        };
        let t1 = hello_no_cookie.transcript_bytes().expect("transcript");
        let t2 = hello_with_cookie.transcript_bytes().expect("transcript");
        assert_ne!(t1, t2);
    }

    #[test]
    fn hello_transcript_with_transport_limits_differs() {
        let hello_no_limits = MeshSessionHello {
            from: TailscaleNodeId::new("node-a"),
            to: TailscaleNodeId::new("node-b"),
            eph_pubkey: X25519SecretKey::from_bytes([0x11; 32]).public_key(),
            nonce: SessionNonce([0; 16]),
            cookie: None,
            timestamp: 1_700_000_000,
            suites: vec![SessionCryptoSuite::Suite1],
            transport_limits: None,
            signature: None,
        };
        let hello_with_limits = MeshSessionHello {
            transport_limits: Some(TransportLimits {
                max_datagram_bytes: 1400,
            }),
            ..hello_no_limits.clone()
        };
        let t1 = hello_no_limits.transcript_bytes().expect("transcript");
        let t2 = hello_with_limits.transcript_bytes().expect("transcript");
        assert_ne!(t1, t2);
    }

    #[test]
    fn verify_cookie_with_wrong_key_fails() {
        let key_a = [0xAA; 32];
        let key_b = [0xBB; 32];
        let hello = make_hello();
        let cookie = compute_cookie(&key_a, &hello).expect("cookie");
        let err = verify_cookie(&key_b, &hello, &cookie).expect_err("wrong key");
        assert!(matches!(err, SessionError::InvalidCookie));
    }

    #[test]
    fn decode_hello_cbor_rejects_trailing_bytes() {
        let hello = make_hello();
        let mut encoded = to_canonical_cbor(&hello).expect("encode");
        encoded.push(0xFF); // trailing byte
        let err = decode_hello_cbor(&encoded).expect_err("trailing bytes");
        assert!(matches!(err, SessionError::Cbor(_)));
    }

    #[test]
    fn transport_limits_serde_transparent() {
        // TransportLimits is serde(transparent), so it should serialize as just the u16
        let limits = TransportLimits {
            max_datagram_bytes: 1400,
        };
        let json = serde_json::to_string(&limits).expect("serialize");
        assert_eq!(json, "1400");
        let back: TransportLimits = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.max_datagram_bytes, 1400);
    }
}
