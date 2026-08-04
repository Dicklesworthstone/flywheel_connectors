//! AWS Signature Version 4 signing for FCP connectors.
//!
//! Implements the AWS SigV4 signing process as documented in the
//! [AWS Signature Version 4 documentation](https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html).
//!
//! This module provides a shared, correct SigV4 implementation that
//! AWS-family connectors (aws, s3, dynamodb, etc.) can use instead of
//! rolling their own partial signing logic.
//!
//! # Features
//!
//! - Canonical request assembly (sorted headers, encoded URI/query)
//! - HMAC-SHA256 signing key derivation
//! - Authorization header generation
//! - Query string presigning for temporary URLs
//! - Clock injection for deterministic testing
//! - Redaction-safe debug output (credentials never logged)

use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

// ── Credentials ─────────────────────────────────────────────────────────

/// AWS credentials for SigV4 signing.
///
/// Debug output redacts secret_access_key and session_token.
#[derive(Clone)]
pub struct AwsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

impl fmt::Debug for AwsCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AwsCredentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

// ── Signing Scope ───────────────────────────────────────────────────────

/// Scope for SigV4 signing (date/region/service).
#[derive(Debug, Clone)]
pub struct SigningScope {
    /// AWS region (e.g., "us-east-1").
    pub region: String,
    /// AWS service (e.g., "s3", "ec2", "execute-api").
    pub service: String,
}

impl SigningScope {
    /// How many times this service's canonical URI path is encoded.
    ///
    /// SigV4 requires each path segment to be URI-encoded **twice** for every
    /// service except Amazon S3, which requires exactly **once**. Signing S3
    /// with the double-encoded form (or anything else with the single-encoded
    /// form) produces a canonical request the service will not reproduce, and
    /// the request is rejected with `SignatureDoesNotMatch`.
    ///
    /// The comparison is case-insensitive because `service` is a public field
    /// with no normalizing constructor, so `SigningScope { service: "S3", .. }`
    /// is constructible. Matches `fcp_provider_auth::SigV4Auth`.
    #[must_use]
    pub fn canonical_path_encoding(&self) -> CanonicalPathEncoding {
        if self.service.eq_ignore_ascii_case("s3") {
            CanonicalPathEncoding::Single
        } else {
            CanonicalPathEncoding::Double
        }
    }

    /// Whether this service's canonical URI has dot segments resolved.
    ///
    /// Same S3-vs-everything-else split as [`Self::canonical_path_encoding`],
    /// and case-insensitive for the same reason: `service` is a public field
    /// with no normalising constructor.
    #[must_use]
    pub fn canonical_path_normalization(&self) -> CanonicalPathNormalization {
        if self.service.eq_ignore_ascii_case("s3") {
            CanonicalPathNormalization::Preserve
        } else {
            CanonicalPathNormalization::RemoveDotSegments
        }
    }
}

/// Number of URI-encoding passes applied to the canonical request's path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalPathEncoding {
    /// Encode each path segment once — Amazon S3.
    Single,
    /// Encode each path segment twice — every other AWS service.
    Double,
}

/// Whether the canonical URI path has RFC 3986 dot segments resolved.
///
/// A second, independent axis from [`CanonicalPathEncoding`]. S3 treats the path
/// as an opaque object key, so `/a/../b` names a literal key containing `..` and
/// must be signed as written; every other service resolves it to `/b` before
/// signing. Getting this wrong yields `SignatureDoesNotMatch` for any caller
/// that builds a path by joining segments and lands a `//`, `.` or `..`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalPathNormalization {
    /// Resolve `.` / `..` and collapse duplicate slashes — every service but S3.
    RemoveDotSegments,
    /// Sign the path exactly as supplied — Amazon S3.
    Preserve,
}

// ── Request to Sign ─────────────────────────────────────────────────────

/// HTTP request components needed for SigV4 signing.
#[derive(Debug, Clone)]
pub struct SignableRequest {
    /// HTTP method (GET, PUT, POST, DELETE, etc.).
    pub method: String,
    /// **Wire** URI path — the absolute path exactly as it will appear in the
    /// request line, percent-encoded (e.g. `url::Url::path()` gives this
    /// directly, as `/bucket/my%20key`).
    ///
    /// The signer percent-DECODES this back to the raw path before building
    /// the canonical URI, because that is what the service does with what it
    /// receives. Passing an already-decoded path here signs a different
    /// resource than the one the request targets whenever the path contains
    /// anything needing an escape.
    pub uri: String,
    /// Query string parameters (key → value).
    pub query_params: BTreeMap<String, String>,
    /// HTTP headers (lowercase key → value).
    pub headers: BTreeMap<String, String>,
    /// SHA-256 hash of the request body (hex-encoded).
    /// Use `UNSIGNED_PAYLOAD` for unsigned payloads (e.g., S3 streaming).
    pub payload_hash: String,
}

/// Sentinel value for unsigned payloads.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// Sentinel value for empty body.
pub const EMPTY_PAYLOAD_HASH: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

impl SignableRequest {
    /// Compute the SHA-256 hash of a payload.
    #[must_use]
    pub fn hash_payload(payload: &[u8]) -> String {
        hex::encode(Sha256::digest(payload))
    }
}

// ── Signed Output ───────────────────────────────────────────────────────

/// Result of SigV4 signing — the Authorization header value and
/// signed headers list.
#[derive(Clone)]
pub struct SignedRequest {
    /// The full Authorization header value.
    pub authorization: String,
    /// ISO 8601 timestamp used for signing.
    pub x_amz_date: String,
    /// Security token header (if session credentials).
    pub x_amz_security_token: Option<String>,
    /// SHA-256 content hash header.
    pub x_amz_content_sha256: String,
}

impl fmt::Debug for SignedRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `authorization` embeds `Credential=<ACCESS_KEY_ID>/<scope>` plus the
        // request signature. This type derived `Debug` and so printed the access
        // key id through any `format!("{signed:?}")` — even though `AwsCredentials`
        // right above it hand-writes `Debug` specifically to keep credential
        // material out of log lines, and `fcp_provider_auth::SigV4SignedAuth`
        // redacts this same string for this same reason. An access key id is an
        // identifier rather than a secret, but the workspace has already decided
        // to treat it as log-sensitive, and two implementations of one rule
        // disagreeing is how the stricter one eventually gets "simplified" away.
        //
        // The session token is redacted for the stronger reason: it IS secret.
        f.debug_struct("SignedRequest")
            .field("authorization", &"[REDACTED]")
            .field("x_amz_date", &self.x_amz_date)
            .field(
                "x_amz_security_token",
                &self.x_amz_security_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("x_amz_content_sha256", &self.x_amz_content_sha256)
            .finish()
    }
}

/// Intermediate artifacts produced by one SigV4 signing pass.
///
/// SigV4 is a pipeline — canonical request, then string-to-sign, then
/// signature — and each stage feeds a hash into the next. Comparing only the
/// final signature against a reference therefore tells you *that* a signer
/// diverged but not *where*, and every stage hashes into an opaque hex digest
/// that carries no diagnostic information on its own.
///
/// `Debug` is derived here DELIBERATELY, unlike on [`SignedRequest`]: this type
/// exists to be printed. It carries no credential material — the canonical
/// request and string-to-sign contain the access key id only inside the
/// credential scope, and the signature is per-request and useless without the
/// secret key. Redacting a diagnostic type would defeat its only purpose.
///
/// Exposing the intermediates is what makes the published AWS test vectors
/// usable as more than a pass/fail bit: the vectors ship the expected canonical
/// request and string-to-sign alongside the expected signature precisely so a
/// mismatch can be localised to one stage.
#[derive(Debug, Clone)]
pub struct SigV4Trace {
    /// Canonical request (AWS "Task 1").
    pub canonical_request: String,
    /// String to sign (AWS "Task 2").
    pub string_to_sign: String,
    /// Hex-encoded signature (AWS "Task 3").
    pub signature: String,
    /// Semicolon-joined lowercase signed header names.
    pub signed_headers: String,
    /// `<date>/<region>/<service>/aws4_request`.
    pub credential_scope: String,
}

/// Result of query string presigning.
#[derive(Debug, Clone)]
pub struct PresignedUrl {
    /// The presigned URL with SigV4 query parameters.
    pub url: String,
    /// When the presigned URL expires.
    pub expires_in_secs: u64,
}

// ── Signer ──────────────────────────────────────────────────────────────

/// AWS SigV4 signer with deterministic clock injection.
#[derive(Debug, Clone)]
pub struct SigV4Signer {
    credentials: AwsCredentials,
    scope: SigningScope,
    /// Fixed timestamp for deterministic testing. If None, uses Utc::now().
    fixed_time: Option<DateTime<Utc>>,
    /// Whether to add `x-amz-content-sha256` to the signed header set when the
    /// caller did not supply it. Defaults to `true`.
    sign_content_sha256_header: bool,
    /// Overrides the scope-derived path-normalisation profile when set.
    path_normalization: Option<CanonicalPathNormalization>,
    /// When true, `x-amz-security-token` is left out of the signed header set
    /// even though the credentials carry one. Defaults to `false`.
    omit_session_token: bool,
}

impl SigV4Signer {
    /// Create a new signer.
    #[must_use]
    pub fn new(credentials: AwsCredentials, scope: SigningScope) -> Self {
        Self {
            credentials,
            scope,
            fixed_time: None,
            sign_content_sha256_header: true,
            path_normalization: None,
            omit_session_token: false,
        }
    }

    /// Create a signer with a fixed timestamp (for deterministic tests).
    #[must_use]
    pub fn with_fixed_time(mut self, time: DateTime<Utc>) -> Self {
        self.fixed_time = Some(time);
        self
    }

    /// Override the scope-derived path-normalisation profile.
    ///
    /// Production callers should not need this — [`SigningScope`] derives the
    /// profile from the service name. It exists so the signer can be driven per
    /// case against AWS's published vectors, which carry the profile in each
    /// case's `context.normalize` while every case names the same service.
    #[must_use]
    pub const fn with_path_normalization(
        mut self,
        normalization: CanonicalPathNormalization,
    ) -> Self {
        self.path_normalization = Some(normalization);
        self
    }

    /// Control whether `x-amz-content-sha256` is added to the signed header
    /// set when the caller did not supply it. Default `true`.
    ///
    /// S3 requires the header, and signing it is only safe because callers
    /// forward `SignedRequest::x_amz_content_sha256` onto the wire — a signed
    /// header that is not actually sent produces `SignatureDoesNotMatch`.
    ///
    /// Set `false` to sign exactly the headers supplied. This exists so the
    /// signer can be driven in the shape AWS's published test vectors describe:
    /// those vectors sign a service that does not carry the header, so leaving
    /// it in would make every vector mismatch for a reason that has nothing to
    /// do with the canonical-URI and query-encoding rules they exist to pin.
    #[must_use]
    pub const fn with_content_sha256_header(mut self, enabled: bool) -> Self {
        self.sign_content_sha256_header = enabled;
        self
    }

    /// Sign without `x-amz-security-token`, leaving the caller to add the token
    /// to the request *after* signing.
    ///
    /// This is AWS's own `omit_session_token` signing flag
    /// (`aws_signing_config_aws.flags.omit_session_token`). The default —
    /// signing the token — is correct for ordinary requests made with session
    /// credentials, and is what the published vector
    /// `post-sts-header-before` pins.
    ///
    /// Some flows need the other shape: the token must travel on the wire but
    /// must not be part of the signed header set, because the receiving service
    /// re-derives the signature over a header set that does not include it.
    /// `post-sts-header-after` is exactly that case, and it carries
    /// `"omit_session_token": true` in its `context.json`.
    ///
    /// [`SignedRequest::x_amz_security_token`] is still populated when this is
    /// set — the token is omitted from the *signature*, not from the request.
    /// Dropping it from the wire as well would break any service that requires
    /// it.
    #[must_use]
    pub const fn with_omit_session_token(mut self, omit: bool) -> Self {
        self.omit_session_token = omit;
        self
    }

    /// Sign a request and return the Authorization header components.
    #[must_use]
    pub fn sign(&self, request: &SignableRequest) -> SignedRequest {
        self.sign_traced(request).0
    }

    /// Sign a request, additionally returning every intermediate artifact.
    ///
    /// Same computation as [`Self::sign`]; see [`SigV4Trace`] for why the
    /// intermediates are worth surfacing.
    #[must_use]
    pub fn sign_traced(&self, request: &SignableRequest) -> (SignedRequest, SigV4Trace) {
        let now = self.now();
        let date_stamp = now.format("%Y%m%d").to_string();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

        let credential_scope = format!(
            "{date_stamp}/{}/{}/aws4_request",
            self.scope.region, self.scope.service
        );

        // Step 1: Canonical request
        let (canonical_request, signed_headers) = self.build_canonical_request(request, &amz_date);

        // Step 2: String to sign
        let canonical_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
        let string_to_sign =
            format!("AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{canonical_hash}");

        // Step 3: Signing key
        let signing_key = self.derive_signing_key(&date_stamp);

        // Step 4: Signature
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        // Step 5: Authorization header
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.credentials.access_key_id,
        );

        (
            SignedRequest {
                authorization,
                x_amz_date: amz_date,
                x_amz_security_token: self.credentials.session_token.clone(),
                // The NORMALISED hash, i.e. the one that was actually signed.
                // Returning `request.payload_hash` verbatim would hand the caller
                // an uppercase value to put on the wire while the signature
                // covered the lowercase one.
                x_amz_content_sha256: canonical_payload_hash(&request.payload_hash),
            },
            SigV4Trace {
                canonical_request,
                string_to_sign,
                signature,
                signed_headers,
                credential_scope,
            },
        )
    }

    /// Generate a presigned URL with SigV4 query string signing.
    #[must_use]
    pub fn presign(&self, request: &SignableRequest, expires_in_secs: u64) -> PresignedUrl {
        let now = self.now();
        let date_stamp = now.format("%Y%m%d").to_string();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

        let credential_scope = format!(
            "{date_stamp}/{}/{}/aws4_request",
            self.scope.region, self.scope.service
        );
        let credential = format!("{}/{credential_scope}", self.credentials.access_key_id);

        // Build query params for presigning
        let mut query = request.query_params.clone();
        query.insert("X-Amz-Algorithm".into(), "AWS4-HMAC-SHA256".into());
        query.insert("X-Amz-Credential".into(), credential);
        query.insert("X-Amz-Date".into(), amz_date.clone());
        query.insert("X-Amz-Expires".into(), expires_in_secs.to_string());
        query.insert("X-Amz-SignedHeaders".into(), "host".into());
        if let Some(token) = &self.credentials.session_token {
            query.insert("X-Amz-Security-Token".into(), token.clone());
        }

        // Canonical request with UNSIGNED-PAYLOAD
        let canonical_query = build_canonical_query(&query);
        let canonical_headers = request
            .headers
            .iter()
            .filter(|(k, _)| k.as_str() == "host")
            .map(|(k, v)| format!("{k}:{v}\n"))
            .collect::<String>();

        // Same canonical-URI rule as `sign`; using `request.uri` verbatim here
        // meant presigned URLs were signed against a different path than
        // signed requests for the identical resource.
        let canonical_uri = canonical_uri_path(
            &request.uri,
            self.scope.canonical_path_encoding(),
            self.path_normalization
                .unwrap_or_else(|| self.scope.canonical_path_normalization()),
        );
        let canonical_request = format!(
            "{}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\nhost\n{UNSIGNED_PAYLOAD}",
            request.method,
        );

        let canonical_hash = hex::encode(Sha256::digest(canonical_request.as_bytes()));
        let string_to_sign =
            format!("AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{canonical_hash}");

        let signing_key = self.derive_signing_key(&date_stamp);
        let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

        query.insert("X-Amz-Signature".into(), signature);

        let final_query = build_canonical_query(&query);
        // Build an ABSOLUTE url. This previously returned bare
        // `{path}?{query}`, so `PresignedUrl.url` — documented as "The
        // presigned URL" and handed straight back to callers — was an
        // un-dereferenceable relative path. The `host` header is already
        // required for the signature, so it is always available here.
        let url = request.headers.get("host").map_or_else(
            || format!("{}?{final_query}", request.uri),
            |host| format!("https://{host}{}?{final_query}", request.uri),
        );

        PresignedUrl {
            url,
            expires_in_secs,
        }
    }

    // ── Internal ────────────────────────────────────────────────────

    fn now(&self) -> DateTime<Utc> {
        self.fixed_time.unwrap_or_else(Utc::now)
    }

    /// Build the canonical request string and return (canonical_request, signed_headers).
    fn build_canonical_request(
        &self,
        request: &SignableRequest,
        amz_date: &str,
    ) -> (String, String) {
        // Canonical URI — single-encoded for S3, double-encoded elsewhere.
        let canonical_uri = canonical_uri_path(
            &request.uri,
            self.scope.canonical_path_encoding(),
            self.path_normalization
                .unwrap_or_else(|| self.scope.canonical_path_normalization()),
        );

        // Canonical query string (sorted by key)
        let canonical_query = build_canonical_query(&request.query_params);

        // Normalise the two remaining inputs the service canonicalises for us.
        // Both were previously used verbatim, which meant `fcp-sdk` and
        // `fcp_provider_auth` signed the same logical request differently
        // (br-rt4q4): that crate uppercases the method and lowercases the hash at
        // construction time.
        let method = canonical_method(&request.method);
        let payload_hash = canonical_payload_hash(&request.payload_hash);

        // Canonical headers (sorted, lowercase, trimmed).
        //
        // The signer OWNS these three values, so it overwrites rather than
        // deferring to the caller. Previously these used `entry().or_insert_with`,
        // i.e. caller-wins, which desynchronised the signature from the returned
        // headers: a caller-supplied `x-amz-date` was SIGNED, but `SignedRequest`
        // still reported the signer's own computed date, so writing the returned
        // value onto the wire sent a date that was not the one signed. Since the
        // signer is the component that decides the timestamp (via `fixed_time` or
        // `now`), computes the payload hash header from `payload_hash`, and holds
        // the session token, signer-wins is the only self-consistent contract —
        // and it matches `fcp_provider_auth`, which always overwrote.
        let mut headers = request.headers.clone();
        headers.insert("x-amz-date".into(), amz_date.into());
        if self.sign_content_sha256_header {
            headers.insert("x-amz-content-sha256".into(), payload_hash.clone());
        }
        if let Some(token) = &self.credentials.session_token {
            if !self.omit_session_token {
                headers.insert("x-amz-security-token".into(), token.clone());
            }
        }

        // Re-key by the LOWERCASED name before ordering. AWS orders canonical
        // headers by the lowercased name, but `headers` is keyed by whatever
        // case the caller used — so `{"Host": .., "content-type": ..}` emitted
        // `host;content-type`, which is mis-sorted and fails verification, and
        // two case variants of one header produced a duplicated entry in both
        // lists. Collecting into a fresh BTreeMap fixes the order and collapses
        // the duplicate.
        let lowercased: BTreeMap<String, String> = headers
            .iter()
            .map(|(k, v)| (k.to_lowercase(), canonical_header_value(v)))
            .collect();

        let canonical_headers: String = lowercased
            .iter()
            .map(|(k, v)| format!("{k}:{v}\n"))
            .collect();

        let signed_headers: String = lowercased.keys().cloned().collect::<Vec<_>>().join(";");

        let canonical_request = format!(
            "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}",
        );

        (canonical_request, signed_headers)
    }

    /// Derive the SigV4 signing key via successive HMAC rounds.
    fn derive_signing_key(&self, date_stamp: &str) -> Vec<u8> {
        let k_date = hmac_sha256(
            format!("AWS4{}", self.credentials.secret_access_key).as_bytes(),
            date_stamp.as_bytes(),
        );
        let k_region = hmac_sha256(&k_date, self.scope.region.as_bytes());
        let k_service = hmac_sha256(&k_region, self.scope.service.as_bytes());
        hmac_sha256(&k_service, b"aws4_request")
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// URI-encode a single component per AWS SigV4 rules.
/// Unreserved chars (A-Z, a-z, 0-9, '-', '_', '.', '~') are not encoded.
fn uri_encode(s: &str) -> String {
    let mut encoded = String::with_capacity(s.len() * 2);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    encoded
}

fn uri_encode_path(path: &str) -> String {
    if path.is_empty() {
        return "/".into();
    }
    path.split('/')
        .map(|segment| uri_encode(segment))
        .collect::<Vec<_>>()
        .join("/")
}

/// Percent-decode a wire path back to the raw bytes the service will see.
///
/// Invalid UTF-8 is replaced rather than rejected: the canonical URI is only
/// ever compared against the service's own rendering, and a request whose path
/// is not valid UTF-8 will fail on its own merits rather than here.
fn percent_decode_path(path: &str) -> String {
    percent_encoding::percent_decode_str(path)
        .decode_utf8_lossy()
        .into_owned()
}

/// Build the canonical URI for a request.
///
/// The service percent-decodes the path it receives and then re-encodes it to
/// canonicalize, so the signer has to do the same thing: decode the wire path,
/// then apply the service's required number of encoding passes. Encoding the
/// wire path directly (the previous behaviour) is only equivalent when the
/// path contains nothing that needed escaping in the first place — which is
/// why plain ASCII keys signed correctly while a key with a space, a literal
/// `%`, or any non-ASCII character produced `SignatureDoesNotMatch`.
fn canonical_uri_path(
    wire_path: &str,
    encoding: CanonicalPathEncoding,
    normalization: CanonicalPathNormalization,
) -> String {
    // An absolute path is what the canonical request needs, and a relative one is
    // malformed input rather than a different resource. `RemoveDotSegments` always
    // returns a rooted path, so without this the two profiles disagreed on the
    // same input: `Preserve` signed `bucket/key` unrooted while the other rooted
    // it. `fcp_provider_auth` always rooted. (br-rt4q4)
    let rooted: String = if wire_path.starts_with('/') {
        wire_path.to_string()
    } else {
        format!("/{wire_path}")
    };
    // Normalise the WIRE path, before decoding. Order matters: decoding first
    // would turn an encoded `%2F` inside a segment into a real separator, and
    // normalisation would then treat it as one — silently signing a different
    // resource than the request targets. Dot segments are unreserved and so are
    // never percent-encoded on the wire, which is why normalising first loses
    // nothing.
    let normalized = match normalization {
        CanonicalPathNormalization::RemoveDotSegments => remove_dot_segments(&rooted),
        CanonicalPathNormalization::Preserve => rooted,
    };
    let raw = percent_decode_path(&normalized);
    let once = uri_encode_path(&raw);
    match encoding {
        CanonicalPathEncoding::Single => once,
        CanonicalPathEncoding::Double => uri_encode_path(&once),
    }
}

/// Canonicalise the HTTP method: trim and uppercase.
///
/// Line 1 of the canonical request must match what the service sees, and the
/// service sees a method that is uppercase — every registered HTTP method
/// (RFC 9110) is, and every caller in the workspace builds one from a `Method`
/// constant. Signing `get` verbatim produced a canonical request no service would
/// reproduce.
///
/// Matches `fcp_provider_auth`, which normalises at `SigV4SigningContext::new`.
/// NOTE for callers: this normalises what is SIGNED, so the request you send must
/// also use the uppercase form.
fn canonical_method(method: &str) -> String {
    method.trim().to_ascii_uppercase()
}

/// Canonicalise the payload hash: lowercase hex, leaving the sentinels alone.
///
/// AWS emits and expects lowercase hex. `SignableRequest::hash_payload` already
/// produces lowercase, so this only matters for a hand-built hash — but a
/// hand-built uppercase hash previously signed differently here than in
/// `fcp_provider_auth`, which lowercases at construction.
///
/// `UNSIGNED-PAYLOAD` is a literal sentinel, not hex, and must survive uppercase.
fn canonical_payload_hash(payload_hash: &str) -> String {
    if payload_hash.eq_ignore_ascii_case(UNSIGNED_PAYLOAD) {
        UNSIGNED_PAYLOAD.to_string()
    } else {
        payload_hash.to_ascii_lowercase()
    }
}

/// Canonicalise a header value: trim the ends and collapse every run of
/// internal whitespace to a single space.
///
/// AWS requires the collapse, not just the trim. Confirmed by the published
/// vector `get-header-value-trim`, whose expected canonical request carries
/// `my-header2:"a b c"` for an input of `"a   b   c"` — note it collapses inside
/// the quotes too, so this is unconditional rather than quote-aware.
fn canonical_header_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Resolve `.` and `..` segments and collapse duplicate slashes, per RFC 3986
/// §6.2.2.3 plus AWS's additional empty-segment collapsing.
///
/// Verified against AWS's published vectors: `/example/..` and `//` and `/./`
/// all canonicalise to `/`; `/./example` to `/example`; `//example//` to
/// `/example/`. A trailing slash on the input is preserved when any segment
/// survives.
fn remove_dot_segments(path: &str) -> String {
    let mut resolved: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            // An empty segment is a duplicate (or leading/trailing) slash.
            "" | "." => {}
            ".." => {
                resolved.pop();
            }
            other => resolved.push(other),
        }
    }
    if resolved.is_empty() {
        return "/".into();
    }
    let trailing = if path.ends_with('/') { "/" } else { "" };
    format!("/{}{trailing}", resolved.join("/"))
}

/// Build the canonical query string: percent-encode every pair, THEN order by
/// the encoded bytes.
///
/// The order of those two steps is the whole content of this function. AWS sorts
/// canonical query parameters by their **encoded** key, so a key that encodes to
/// a percent escape sorts by `%` (0x25) rather than by the first byte of its raw
/// form. Confirmed against AWS's own signer (`aws-c-auth`
/// `source/aws_signing.c`), which runs `s_transform_query_params` with
/// `aws_byte_buf_append_encoding_uri_param` and only then `qsort`s with
/// `s_canonical_query_param_comparator` — a lexical compare on the encoded key
/// with the encoded value as tiebreak. Pinned by the published vector
/// `get-vanilla-query-order-encoded`, where `%E1%88%B4` must sort FIRST.
///
/// Iterating the `BTreeMap` directly (the previous behaviour) ordered by the
/// DECODED key, which is a different order for every key containing a byte
/// outside the unreserved set: `ᐴ` sorts after `Param` by its UTF-8 bytes
/// (0xE1 > 0x50) but before it once encoded (0x25 < 0x50). The map's key order
/// is not the signing order and must not be reused as one.
///
/// The decoded-to-encoded map is total, so nothing is lost by the map being
/// keyed on decoded values: the encoded form is a pure function of the decoded
/// key, so the ordering AWS needs is always recoverable here.
fn build_canonical_query(params: &BTreeMap<String, String>) -> String {
    let mut encoded: Vec<(String, String)> = params
        .iter()
        .map(|(k, v)| (uri_encode(k), uri_encode(v)))
        .collect();
    // Key first, then value — matching AWS's comparator. The value tiebreak is
    // unreachable through a BTreeMap (keys are unique) but is kept so this
    // matches the reference rule rather than the current input type.
    encoded.sort();
    encoded
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_credentials() -> AwsCredentials {
        AwsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: None,
        }
    }

    fn test_scope() -> SigningScope {
        SigningScope {
            region: "us-east-1".into(),
            service: "s3".into(),
        }
    }

    fn fixed_time() -> DateTime<Utc> {
        "2013-05-24T00:00:00Z".parse().unwrap()
    }

    fn test_signer() -> SigV4Signer {
        SigV4Signer::new(test_credentials(), test_scope()).with_fixed_time(fixed_time())
    }

    // ── Canonical URI encoding (br-1nqg7) ────────────────────────

    /// S3 requires exactly ONE encoding pass; every other service requires two.
    /// The signer previously encoded the wire path once regardless of service,
    /// which is correct only for a path that needed no escaping to begin with.
    #[test]
    fn canonical_uri_encodes_once_for_s3_and_twice_for_other_services() {
        // `%20` on the wire decodes to a space, which S3 canonicalizes back to
        // `%20` — not `%2520`.
        assert_eq!(
            canonical_uri_path(
                "/bucket/my%20report.pdf",
                CanonicalPathEncoding::Single,
                CanonicalPathNormalization::Preserve,
            ),
            "/bucket/my%20report.pdf"
        );
        assert_eq!(
            canonical_uri_path(
                "/bucket/my%20report.pdf",
                CanonicalPathEncoding::Double,
                CanonicalPathNormalization::RemoveDotSegments,
            ),
            "/bucket/my%2520report.pdf"
        );
    }

    /// A path containing only unreserved characters must canonicalize
    /// identically under the old and new rules — the fix must not disturb the
    /// requests that already signed correctly.
    /// Expectations taken from AWS's published v4 vectors (see
    /// crates/fcp-conformance/tests/vectors/aws-sigv4), not from this
    /// implementation.
    #[test]
    fn dot_segments_resolve_the_way_aws_signs_them() {
        for (input, expected) in [
            ("/example/..", "/"),
            ("/example1/example2/../..", "/"),
            ("/./", "/"),
            ("//", "/"),
            ("/./example", "/example"),
            ("//example//", "/example/"),
            ("/", "/"),
            ("/example", "/example"),
            // `..` cannot escape the root.
            ("/../../etc/passwd", "/etc/passwd"),
        ] {
            assert_eq!(
                remove_dot_segments(input),
                expected,
                "remove_dot_segments({input:?})"
            );
        }
    }

    /// S3 signs the path as written because an object key may legitimately
    /// contain `..` or a double slash; every other service resolves first.
    /// Signing the wrong one of these yields SignatureDoesNotMatch.
    #[test]
    fn s3_preserves_dot_segments_and_other_services_resolve_them() {
        assert_eq!(
            SigningScope {
                region: "us-east-1".into(),
                service: "s3".into(),
            }
            .canonical_path_normalization(),
            CanonicalPathNormalization::Preserve
        );
        assert_eq!(
            SigningScope {
                region: "us-east-1".into(),
                service: "execute-api".into(),
            }
            .canonical_path_normalization(),
            CanonicalPathNormalization::RemoveDotSegments
        );

        // Same input, two profiles, two different canonical URIs.
        assert_eq!(
            canonical_uri_path(
                "/bucket/a/../b",
                CanonicalPathEncoding::Single,
                CanonicalPathNormalization::Preserve,
            ),
            "/bucket/a/../b"
        );
        assert_eq!(
            canonical_uri_path(
                "/bucket/a/../b",
                CanonicalPathEncoding::Single,
                CanonicalPathNormalization::RemoveDotSegments,
            ),
            "/bucket/b"
        );
    }

    #[test]
    fn header_values_collapse_internal_whitespace_the_way_aws_signs_them() {
        // Expectation from AWS's get-header-value-trim vector.
        assert_eq!(canonical_header_value("\"a   b   c\""), "\"a b c\"");
        assert_eq!(canonical_header_value("  value  "), "value");
        assert_eq!(canonical_header_value("a\tb"), "a b");
        assert_eq!(canonical_header_value("value"), "value");
        assert_eq!(canonical_header_value(""), "");
    }

    /// PINS CURRENT BEHAVIOUR — deliberately not a correctness claim.
    ///
    /// AWS's published vectors contain no case with a percent-encoded slash, so
    /// nothing authoritative constrains this path. What the pipeline does today:
    /// dot-segment resolution runs on the WIRE path (RFC 3986 §6.2.2.3 operates
    /// on the still-encoded path, where `%2F` is not a separator), then the
    /// decode step turns `%2F` into a real `/`, and `uri_encode_path` treats
    /// that as a separator and leaves it unencoded. Net effect: a `..` that only
    /// becomes a segment AFTER decoding is not resolved.
    ///
    /// Recorded so the behaviour cannot drift unnoticed. Resolving whether it
    /// matches live AWS needs a measurement against a real endpoint, not a
    /// closer reading of the spec — see br-f57c6.
    #[test]
    fn encoded_slash_behaviour_is_pinned_pending_measurement() {
        assert_eq!(
            canonical_uri_path(
                "/bucket/a%2F..%2Fb",
                CanonicalPathEncoding::Single,
                CanonicalPathNormalization::RemoveDotSegments,
            ),
            "/bucket/a/../b"
        );
        // S3 preserves, so the encoded slash still decodes but nothing resolves.
        assert_eq!(
            canonical_uri_path(
                "/bucket/a%2F..%2Fb",
                CanonicalPathEncoding::Single,
                CanonicalPathNormalization::Preserve,
            ),
            "/bucket/a/../b"
        );
    }

    #[test]
    fn canonical_uri_is_unchanged_for_paths_needing_no_escape() {
        for path in ["/bucket/plain.pdf", "/bucket/path/to/file.txt", "/"] {
            assert_eq!(
                canonical_uri_path(
                    path,
                    CanonicalPathEncoding::Single,
                    CanonicalPathNormalization::Preserve,
                ),
                uri_encode_path(path),
                "single-pass encoding must be a no-op change for {path}"
            );
        }
    }

    /// Characters the URL parser leaves unescaped (`&`, `+`, `:`) still get
    /// encoded by the canonicalizer, matching what S3 computes after decoding.
    #[test]
    fn canonical_uri_encodes_aws_reserved_characters_left_raw_by_the_url_parser() {
        assert_eq!(
            canonical_uri_path(
                "/bucket/Q&A.pdf",
                CanonicalPathEncoding::Single,
                CanonicalPathNormalization::Preserve,
            ),
            "/bucket/Q%26A.pdf"
        );
        assert_eq!(
            canonical_uri_path(
                "/bucket/a+b.pdf",
                CanonicalPathEncoding::Single,
                CanonicalPathNormalization::Preserve,
            ),
            "/bucket/a%2Bb.pdf"
        );
    }

    /// A literal `%` in the key arrives as `%25` and must survive the
    /// decode/re-encode round trip rather than becoming `%2525`.
    #[test]
    fn canonical_uri_round_trips_a_literal_percent() {
        assert_eq!(
            canonical_uri_path(
                "/bucket/50%25.pdf",
                CanonicalPathEncoding::Single,
                CanonicalPathNormalization::Preserve,
            ),
            "/bucket/50%25.pdf"
        );
    }

    /// Non-ASCII keys are the most common real-world trigger — any accented or
    /// CJK filename arrives percent-encoded and was double-encoded before.
    #[test]
    fn canonical_uri_handles_non_ascii_keys() {
        assert_eq!(
            canonical_uri_path(
                "/bucket/e%C3%B1e.pdf",
                CanonicalPathEncoding::Single,
                CanonicalPathNormalization::Preserve,
            ),
            "/bucket/e%C3%B1e.pdf"
        );
    }

    /// Signing the same resource under S3 and a non-S3 scope must produce
    /// different signatures, proving the mode is actually threaded through.
    #[test]
    fn s3_and_non_s3_scopes_sign_the_same_path_differently() {
        let request = SignableRequest {
            method: "GET".into(),
            uri: "/bucket/my%20report.pdf".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([("host".to_string(), "s3.amazonaws.com".to_string())]),
            payload_hash: EMPTY_PAYLOAD_HASH.into(),
        };

        let s3 = SigV4Signer::new(test_credentials(), test_scope()).with_fixed_time(fixed_time());
        let other = SigV4Signer::new(
            test_credentials(),
            SigningScope {
                region: "us-east-1".into(),
                service: "bedrock".into(),
            },
        )
        .with_fixed_time(fixed_time());

        assert_ne!(
            s3.sign(&request).authorization,
            other.sign(&request).authorization,
            "the canonical path encoding must differ between S3 and other services"
        );
    }

    /// Canonical headers are ordered by the LOWERCASED name, and two case
    /// variants of one header collapse to a single entry.
    #[test]
    fn canonical_headers_sort_by_lowercased_name() {
        let request = SignableRequest {
            method: "GET".into(),
            uri: "/bucket/key".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([
                ("Host".to_string(), "s3.amazonaws.com".to_string()),
                ("content-type".to_string(), "text/plain".to_string()),
            ]),
            payload_hash: EMPTY_PAYLOAD_HASH.into(),
        };
        let (_, signed_headers) =
            test_signer().build_canonical_request(&request, "20130524T000000Z");
        let names: Vec<&str> = signed_headers.split(';').collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(
            names, sorted,
            "signed headers must be sorted: {signed_headers}"
        );
        assert!(names.contains(&"content-type"), "{signed_headers}");
        assert!(names.contains(&"host"), "{signed_headers}");
        assert_eq!(
            names.iter().filter(|n| **n == "host").count(),
            1,
            "case variants must collapse: {signed_headers}"
        );
    }

    /// The presigned URL must be absolute — it is handed straight to callers.
    #[test]
    fn presigned_url_is_absolute() {
        let request = SignableRequest {
            method: "GET".into(),
            uri: "/bucket/report.pdf".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([("host".to_string(), "s3.amazonaws.com".to_string())]),
            payload_hash: UNSIGNED_PAYLOAD.into(),
        };
        let presigned = test_signer().presign(&request, 900);
        assert!(
            presigned
                .url
                .starts_with("https://s3.amazonaws.com/bucket/report.pdf?"),
            "presigned url must be dereferenceable, got {}",
            presigned.url
        );
        assert!(
            presigned.url.contains("X-Amz-Signature="),
            "{}",
            presigned.url
        );
    }

    // ── Signing Key Derivation ───────────────────────────────────

    #[test]
    fn signing_key_derivation_is_deterministic() {
        let signer = test_signer();
        let key1 = signer.derive_signing_key("20130524");
        let key2 = signer.derive_signing_key("20130524");
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32); // HMAC-SHA256 output
    }

    #[test]
    fn signing_key_differs_by_date() {
        let signer = test_signer();
        let key1 = signer.derive_signing_key("20130524");
        let key2 = signer.derive_signing_key("20130525");
        assert_ne!(key1, key2);
    }

    #[test]
    fn signing_key_differs_by_region() {
        let signer1 = SigV4Signer::new(
            test_credentials(),
            SigningScope {
                region: "us-east-1".into(),
                service: "s3".into(),
            },
        );
        let signer2 = SigV4Signer::new(
            test_credentials(),
            SigningScope {
                region: "eu-west-1".into(),
                service: "s3".into(),
            },
        );
        assert_ne!(
            signer1.derive_signing_key("20130524"),
            signer2.derive_signing_key("20130524"),
        );
    }

    #[test]
    fn signing_key_differs_by_service() {
        let signer1 = SigV4Signer::new(
            test_credentials(),
            SigningScope {
                region: "us-east-1".into(),
                service: "s3".into(),
            },
        );
        let signer2 = SigV4Signer::new(
            test_credentials(),
            SigningScope {
                region: "us-east-1".into(),
                service: "ec2".into(),
            },
        );
        assert_ne!(
            signer1.derive_signing_key("20130524"),
            signer2.derive_signing_key("20130524"),
        );
    }

    // ── Canonical Request ────────────────────────────────────────

    #[test]
    fn canonical_request_sorts_headers() {
        let signer = test_signer();
        let request = SignableRequest {
            method: "GET".into(),
            uri: "/".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([
                ("host".into(), "example.amazonaws.com".into()),
                ("x-amz-date".into(), "20130524T000000Z".into()),
            ]),
            payload_hash: EMPTY_PAYLOAD_HASH.into(),
        };

        let (canonical, signed_headers) =
            signer.build_canonical_request(&request, "20130524T000000Z");

        assert!(canonical.contains("host:example.amazonaws.com"));
        assert!(signed_headers.contains("host"));
        assert!(signed_headers.contains("x-amz-date"));
    }

    #[test]
    fn canonical_query_string_sorted_by_key() {
        let params = BTreeMap::from([
            ("z-param".into(), "value2".into()),
            ("a-param".into(), "value1".into()),
        ]);
        let result = build_canonical_query(&params);
        // All-unreserved keys: encoded and decoded order agree here, so this
        // case cannot discriminate the two. See the test below for one that can.
        assert!(result.starts_with("a-param"), "got: {result}");
    }

    /// AWS orders canonical query parameters by the ENCODED key, so a key whose
    /// raw bytes sort late can sort first once encoded.
    ///
    /// Pinned by the published vector `get-vanilla-query-order-encoded` and
    /// confirmed against AWS's own signer, which percent-encodes every pair and
    /// only then sorts (`aws-c-auth` `source/aws_signing.c`:
    /// `s_transform_query_params` → `qsort` with
    /// `s_canonical_query_param_comparator`).
    ///
    /// This is the regression test for reusing the `BTreeMap`'s own key order as
    /// the signing order: `ᐴ` is 0xE1.. raw so it sorted AFTER `Param` (0x50),
    /// but encodes to `%E1%88%B4` which sorts BEFORE it (0x25 < 0x50).
    #[test]
    fn canonical_query_orders_by_encoded_key_not_by_decoded_key() {
        let params = BTreeMap::from([
            ("Param-3".to_string(), "Value3".to_string()),
            ("Param".to_string(), "Value2".to_string()),
            // The decoded form of `%E1%88%B4`.
            ("\u{1234}".to_string(), "Value1".to_string()),
        ]);

        assert_eq!(
            build_canonical_query(&params),
            "%E1%88%B4=Value1&Param=Value2&Param-3=Value3"
        );

        // Guard the premise: the map's own iteration order is the WRONG order,
        // so this test would not detect a regression if that ever stopped being
        // true.
        let map_order: Vec<&str> = params.keys().map(String::as_str).collect();
        assert_eq!(
            map_order,
            vec!["Param", "Param-3", "\u{1234}"],
            "BTreeMap order is by decoded key; if this changes the test above \
             no longer discriminates encoded-vs-decoded ordering"
        );
    }

    /// `omit_session_token` keeps the token off the SIGNATURE, not off the wire.
    ///
    /// Pinned by the published vector pair `post-sts-header-before` (token
    /// signed, the default) and `post-sts-header-after` (token added after
    /// signing, `"omit_session_token": true`).
    #[test]
    fn omit_session_token_drops_the_token_from_the_signed_set_only() {
        let creds = AwsCredentials {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            session_token: Some("AQoDYXdzEXAMPLETOKEN".into()),
        };
        let request = SignableRequest {
            method: "POST".into(),
            uri: "/".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([("host".into(), "example.amazonaws.com".into())]),
            payload_hash: EMPTY_PAYLOAD_HASH.into(),
        };

        let signed = SigV4Signer::new(creds.clone(), test_scope())
            .with_fixed_time(fixed_time())
            .with_content_sha256_header(false)
            .with_omit_session_token(true);
        let (out, trace) = signed.sign_traced(&request);

        assert_eq!(
            trace.signed_headers, "host;x-amz-date",
            "the token must not appear in the signed header set"
        );
        assert!(
            !trace.canonical_request.contains("x-amz-security-token"),
            "canonical request must not carry the token: {}",
            trace.canonical_request
        );
        assert_eq!(
            out.x_amz_security_token.as_deref(),
            Some("AQoDYXdzEXAMPLETOKEN"),
            "the token is omitted from the signature, NOT from the request — \
             dropping it from the wire too would break the service call"
        );

        // Default (omit = false) signs it, and the two shapes must differ.
        let default_signer = SigV4Signer::new(creds, test_scope())
            .with_fixed_time(fixed_time())
            .with_content_sha256_header(false);
        let (_, default_trace) = default_signer.sign_traced(&request);
        assert_eq!(
            default_trace.signed_headers,
            "host;x-amz-date;x-amz-security-token"
        );
        assert_ne!(
            trace.signature, default_trace.signature,
            "omitting the token must change the signature, or the flag is inert"
        );
    }

    /// The signer normalises the method, so a caller's casing cannot change what
    /// is signed. (br-rt4q4)
    #[test]
    fn method_is_uppercased_before_signing() {
        assert_eq!(canonical_method("get"), "GET");
        assert_eq!(canonical_method("  put  "), "PUT");
        assert_eq!(canonical_method("POST"), "POST");

        let signer = test_signer();
        let request = |method: &str| SignableRequest {
            method: method.into(),
            uri: "/".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([("host".into(), "example.amazonaws.com".into())]),
            payload_hash: EMPTY_PAYLOAD_HASH.into(),
        };
        let (_, lower) = signer.sign_traced(&request("get"));
        let (_, upper) = signer.sign_traced(&request("GET"));
        assert_eq!(
            lower.canonical_request, upper.canonical_request,
            "method casing must not reach the canonical request"
        );
        assert!(lower.canonical_request.starts_with("GET\n"));
    }

    /// The payload hash is lowercased, and the sentinel survives. (br-rt4q4)
    #[test]
    fn payload_hash_is_lowercased_but_the_sentinel_is_preserved() {
        assert_eq!(
            canonical_payload_hash(&EMPTY_PAYLOAD_HASH.to_uppercase()),
            EMPTY_PAYLOAD_HASH
        );
        assert_eq!(canonical_payload_hash(UNSIGNED_PAYLOAD), UNSIGNED_PAYLOAD);
        assert_eq!(
            canonical_payload_hash("unsigned-payload"),
            UNSIGNED_PAYLOAD,
            "the sentinel is a literal, not hex — it must not be lowercased"
        );

        // And the value the caller is told to send matches the one signed.
        let out = test_signer().sign(&SignableRequest {
            method: "GET".into(),
            uri: "/".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([("host".into(), "example.amazonaws.com".into())]),
            payload_hash: EMPTY_PAYLOAD_HASH.to_uppercase(),
        });
        assert_eq!(out.x_amz_content_sha256, EMPTY_PAYLOAD_HASH);
    }

    /// The signer owns `x-amz-date`, so what it returns is what it signed.
    ///
    /// The regression this guards is subtle and was the real hazard in br-rt4q4:
    /// under the old caller-wins behaviour the caller's date was SIGNED while the
    /// signer's computed date was RETURNED, so a caller who dutifully wrote the
    /// returned header onto the wire sent a date the signature did not cover.
    #[test]
    fn signer_owned_headers_win_over_caller_supplied_ones() {
        let (out, trace) = test_signer().sign_traced(&SignableRequest {
            method: "GET".into(),
            uri: "/".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([
                ("host".into(), "example.amazonaws.com".into()),
                ("x-amz-date".into(), "19990101T000000Z".into()),
            ]),
            payload_hash: EMPTY_PAYLOAD_HASH.into(),
        });

        assert!(
            trace
                .canonical_request
                .contains(&format!("x-amz-date:{}", out.x_amz_date)),
            "the signed date must be the returned date; canonical request was:\n{}",
            trace.canonical_request
        );
        assert!(
            !trace.canonical_request.contains("19990101T000000Z"),
            "the caller's stale date must not be signed"
        );
    }

    /// A relative path is rooted before signing, in BOTH profiles. (br-rt4q4)
    #[test]
    fn relative_paths_are_rooted_in_both_profiles() {
        for normalization in [
            CanonicalPathNormalization::Preserve,
            CanonicalPathNormalization::RemoveDotSegments,
        ] {
            assert_eq!(
                canonical_uri_path("bucket/key", CanonicalPathEncoding::Single, normalization),
                "/bucket/key",
                "a relative path must be rooted under {normalization:?}"
            );
        }
    }

    /// `SignedRequest` must not print credential material. (br-qyxkb)
    #[test]
    fn signed_request_debug_redacts_authorization_and_token() {
        let creds = AwsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: Some("FwoGZXIvYXdzEBYaDHqa0AF".into()),
        };
        let signed = SigV4Signer::new(creds, test_scope())
            .with_fixed_time(fixed_time())
            .sign(&SignableRequest {
                method: "GET".into(),
                uri: "/".into(),
                query_params: BTreeMap::new(),
                headers: BTreeMap::from([("host".into(), "example.amazonaws.com".into())]),
                payload_hash: EMPTY_PAYLOAD_HASH.into(),
            });

        let rendered = format!("{signed:?}");
        assert!(
            !rendered.contains("AKIAIOSFODNN7EXAMPLE"),
            "the access key id reached Debug output: {rendered}"
        );
        assert!(
            !rendered.contains("FwoGZXIvYXdzEBYaDHqa0AF"),
            "the session token reached Debug output: {rendered}"
        );
        assert!(rendered.contains("[REDACTED]"));
        // The non-sensitive fields stay legible, or the type is useless to debug.
        assert!(rendered.contains(&signed.x_amz_date));
    }

    /// Pins the input-convention boundary between this signer and AWS's own.
    ///
    /// `aws-c-auth` NEVER percent-decodes the path: with `use_double_uri_encode`
    /// it applies exactly ONE encoding pass to the path string it was handed, and
    /// with the flag off it emits that string verbatim (`source/aws_signing.c`,
    /// `s_append_canonical_path`). This signer instead decodes the wire path and
    /// then applies its profile's number of passes.
    ///
    /// Those two algorithms are IDENTICAL for a canonically-encoded wire path,
    /// which is what [`SignableRequest::uri`] is documented to carry — that
    /// equivalence is what this test measures, in both profiles. They differ only
    /// when the input is a RAW (un-encoded) path, which is not a legal
    /// request-target and not what this API accepts.
    ///
    /// That difference is the entire explanation for the three published vectors
    /// (`get-space-normalized`, `get-space-unnormalized`, `get-utf8`) whose
    /// fixtures supply raw paths: it is an input-convention boundary, not a
    /// signing defect. Recorded here as measurement so it cannot decay back into
    /// a suspected bug.
    #[test]
    fn wire_path_input_reproduces_aws_own_canonical_path_algorithm() {
        for wire in ["/example%20space/", "/%E1%88%B4", "/bucket/plain.txt", "/"] {
            // Non-S3 profile: AWS applies one encode pass to the wire path.
            assert_eq!(
                canonical_uri_path(
                    wire,
                    CanonicalPathEncoding::Double,
                    CanonicalPathNormalization::RemoveDotSegments,
                ),
                uri_encode_path(wire),
                "double-encoding profile must equal one encode pass over the \
                 wire path for {wire}"
            );
            // S3 profile: AWS emits the wire path verbatim.
            assert_eq!(
                canonical_uri_path(
                    wire,
                    CanonicalPathEncoding::Single,
                    CanonicalPathNormalization::Preserve,
                ),
                wire,
                "single-encoding profile must equal the wire path verbatim for {wire}"
            );
        }

        // And the boundary itself: handed the RAW path the fixtures use, this
        // signer emits one pass MORE than AWS does, because its decode step is a
        // no-op on a string with no escapes. Measured, not desired.
        assert_eq!(
            canonical_uri_path(
                "/example space/",
                CanonicalPathEncoding::Double,
                CanonicalPathNormalization::RemoveDotSegments,
            ),
            "/example%2520space/",
        );
    }

    // ── Full Signing ─────────────────────────────────────────────

    #[test]
    fn sign_produces_valid_authorization_header() {
        let signer = test_signer();
        let request = SignableRequest {
            method: "GET".into(),
            uri: "/test.txt".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([("host".into(), "examplebucket.s3.amazonaws.com".into())]),
            payload_hash: EMPTY_PAYLOAD_HASH.into(),
        };

        let signed_request = signer.sign(&request);

        assert!(
            signed_request
                .authorization
                .starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/")
        );
        assert!(signed_request.authorization.contains("SignedHeaders="));
        assert!(signed_request.authorization.contains("Signature="));
        assert_eq!(signed_request.x_amz_date, "20130524T000000Z");
        assert_eq!(signed_request.x_amz_content_sha256, EMPTY_PAYLOAD_HASH);
        assert!(signed_request.x_amz_security_token.is_none());
    }

    #[test]
    fn sign_is_deterministic_with_fixed_time() {
        let signer = test_signer();
        let request = SignableRequest {
            method: "GET".into(),
            uri: "/".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([("host".into(), "example.amazonaws.com".into())]),
            payload_hash: EMPTY_PAYLOAD_HASH.into(),
        };

        let signed1 = signer.sign(&request);
        let signed2 = signer.sign(&request);
        assert_eq!(signed1.authorization, signed2.authorization);
    }

    #[test]
    fn sign_includes_session_token_when_present() {
        let creds = AwsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: Some("FwoGZXIvYXdzEBYaDHqa0AF".into()),
        };
        let signer = SigV4Signer::new(creds, test_scope()).with_fixed_time(fixed_time());

        let request = SignableRequest {
            method: "GET".into(),
            uri: "/".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([("host".into(), "example.amazonaws.com".into())]),
            payload_hash: EMPTY_PAYLOAD_HASH.into(),
        };

        let signed_request = signer.sign(&request);
        assert!(signed_request.x_amz_security_token.is_some());
        assert!(
            signed_request
                .authorization
                .contains("x-amz-security-token")
        );
    }

    // ── Presigning ───────────────────────────────────────────────

    #[test]
    fn presign_produces_url_with_sigv4_params() {
        let signer = test_signer();
        let request = SignableRequest {
            method: "GET".into(),
            uri: "/test-bucket/test-key.txt".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([("host".into(), "s3.amazonaws.com".into())]),
            payload_hash: UNSIGNED_PAYLOAD.into(),
        };

        let presigned = signer.presign(&request, 3600);

        assert!(presigned.url.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
        assert!(presigned.url.contains("X-Amz-Credential="));
        assert!(presigned.url.contains("X-Amz-Date="));
        assert!(presigned.url.contains("X-Amz-Expires=3600"));
        assert!(presigned.url.contains("X-Amz-Signature="));
        assert!(presigned.url.contains("X-Amz-SignedHeaders=host"));
        assert_eq!(presigned.expires_in_secs, 3600);
    }

    #[test]
    fn presign_is_deterministic() {
        let signer = test_signer();
        let request = SignableRequest {
            method: "GET".into(),
            uri: "/bucket/key".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([("host".into(), "s3.amazonaws.com".into())]),
            payload_hash: UNSIGNED_PAYLOAD.into(),
        };

        let url1 = signer.presign(&request, 900);
        let url2 = signer.presign(&request, 900);
        assert_eq!(url1.url, url2.url);
    }

    // ── Payload Hashing ──────────────────────────────────────────

    #[test]
    fn empty_payload_hash_matches_constant() {
        assert_eq!(SignableRequest::hash_payload(b""), EMPTY_PAYLOAD_HASH);
    }

    #[test]
    fn payload_hash_is_deterministic() {
        let hash1 = SignableRequest::hash_payload(b"hello world");
        let hash2 = SignableRequest::hash_payload(b"hello world");
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, EMPTY_PAYLOAD_HASH);
    }

    // ── Credential Redaction ─────────────────────────────────────

    #[test]
    fn debug_output_redacts_secrets() {
        let creds = AwsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: Some("token123".into()),
        };
        let debug = format!("{creds:?}");
        assert!(debug.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!debug.contains("wJalrXUtnFEMI"));
        assert!(!debug.contains("token123"));
        assert!(debug.contains("[REDACTED]"));
    }

    // ── URI Encoding ─────────────────────────────────────────────

    #[test]
    fn uri_encode_empty_path_becomes_slash() {
        assert_eq!(uri_encode_path(""), "/");
    }

    #[test]
    fn uri_encode_preserves_slashes() {
        let encoded = uri_encode_path("/bucket/key/with/slashes");
        assert!(encoded.starts_with('/'));
        assert!(encoded.contains('/'));
    }

    // ── Cross-Cloud Auth Regression: SigV4 ──────────────────────

    #[test]
    fn presign_with_session_token_includes_security_token() {
        let creds = AwsCredentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
            session_token: Some("FwoGZXIvYXdzEBYaDHqa0AF".into()),
        };
        let signer = SigV4Signer::new(creds, test_scope()).with_fixed_time(fixed_time());
        let request = SignableRequest {
            method: "GET".into(),
            uri: "/bucket/key".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([("host".into(), "s3.amazonaws.com".into())]),
            payload_hash: UNSIGNED_PAYLOAD.into(),
        };
        let presigned = signer.presign(&request, 3600);
        assert!(
            presigned.url.contains("X-Amz-Security-Token="),
            "presigned URL must include session token: {}",
            presigned.url
        );
    }

    #[test]
    fn presign_expiry_boundary_zero_produces_valid_url() {
        let signer = test_signer();
        let request = SignableRequest {
            method: "GET".into(),
            uri: "/bucket/key".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([("host".into(), "s3.amazonaws.com".into())]),
            payload_hash: UNSIGNED_PAYLOAD.into(),
        };
        let presigned = signer.presign(&request, 0);
        assert!(presigned.url.contains("X-Amz-Expires=0"));
        assert_eq!(presigned.expires_in_secs, 0);
    }

    #[test]
    fn presign_max_expiry_604800_produces_valid_url() {
        let signer = test_signer();
        let request = SignableRequest {
            method: "GET".into(),
            uri: "/bucket/key".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([("host".into(), "s3.amazonaws.com".into())]),
            payload_hash: UNSIGNED_PAYLOAD.into(),
        };
        let presigned = signer.presign(&request, 604_800);
        assert!(presigned.url.contains("X-Amz-Expires=604800"));
        assert_eq!(presigned.expires_in_secs, 604_800);
    }

    #[test]
    fn sign_different_payloads_produce_different_signatures() {
        let signer = test_signer();
        let make_request = |payload: &[u8]| SignableRequest {
            method: "PUT".into(),
            uri: "/bucket/key".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([("host".into(), "s3.amazonaws.com".into())]),
            payload_hash: SignableRequest::hash_payload(payload),
        };

        let signed_empty = signer.sign(&make_request(b""));
        let signed_body = signer.sign(&make_request(b"hello world"));
        assert_ne!(
            signed_empty.authorization, signed_body.authorization,
            "different payloads must produce different signatures"
        );
    }

    #[test]
    fn sign_different_methods_produce_different_signatures() {
        let signer = test_signer();
        let make_request = |method: &str| SignableRequest {
            method: method.into(),
            uri: "/bucket/key".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([("host".into(), "s3.amazonaws.com".into())]),
            payload_hash: EMPTY_PAYLOAD_HASH.into(),
        };

        let signed_get = signer.sign(&make_request("GET"));
        let signed_put = signer.sign(&make_request("PUT"));
        assert_ne!(signed_get.authorization, signed_put.authorization);
    }

    #[test]
    fn presign_with_existing_query_params_preserves_them() {
        let signer = test_signer();
        let request = SignableRequest {
            method: "GET".into(),
            uri: "/bucket/key".into(),
            query_params: BTreeMap::from([(
                "response-content-type".into(),
                "application/json".into(),
            )]),
            headers: BTreeMap::from([("host".into(), "s3.amazonaws.com".into())]),
            payload_hash: UNSIGNED_PAYLOAD.into(),
        };
        let presigned = signer.presign(&request, 3600);
        assert!(
            presigned
                .url
                .contains("response-content-type=application%2Fjson")
                || presigned
                    .url
                    .contains("response-content-type=application/json"),
            "existing query params must be preserved: {}",
            presigned.url
        );
    }

    #[test]
    fn sign_credential_string_includes_scope_components() {
        let signer = test_signer();
        let request = SignableRequest {
            method: "GET".into(),
            uri: "/".into(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::from([("host".into(), "example.amazonaws.com".into())]),
            payload_hash: EMPTY_PAYLOAD_HASH.into(),
        };
        let sign_result = signer.sign(&request);
        // Credential should contain: access_key/date/region/service/aws4_request
        assert!(
            sign_result
                .authorization
                .contains("20130524/us-east-1/s3/aws4_request"),
            "credential scope must include date/region/service: {}",
            sign_result.authorization
        );
    }

    #[test]
    fn uri_encode_special_characters() {
        let encoded = uri_encode_path("/bucket/key with spaces/file@name.txt");
        assert!(!encoded.contains(' '), "spaces must be percent-encoded");
        assert!(
            encoded.contains("%40") || encoded.contains('@'),
            "@ should be handled: {encoded}"
        );
    }

    #[test]
    fn signing_key_is_exactly_32_bytes() {
        let signer = test_signer();
        for date in ["20130524", "20261231", "20000101"] {
            let key = signer.derive_signing_key(date);
            assert_eq!(
                key.len(),
                32,
                "HMAC-SHA256 output must be 32 bytes for date {date}"
            );
        }
    }
}
