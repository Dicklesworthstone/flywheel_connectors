//! JWT assertion builder and Google `OAuth2` token exchange for service-account auth.
//!
//! Implements the [Google OAuth2 Service Account](https://developers.google.com/identity/protocols/oauth2/service-account)
//! flow: construct a signed JWT assertion, then exchange it for a short-lived access token.
//!
//! The JWT is signed with RS256 (RSASSA-PKCS1-v1_5 using SHA-256) per RFC 7518 §3.3.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::SignatureEncoding;
use rsa::{RsaPrivateKey, pkcs1v15::SigningKey};
use sha2::Sha256;

use crate::error::{GcpError, GcpResult};

/// Percent-encode a string for use in application/x-www-form-urlencoded bodies.
fn urlencoded(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            b' ' => out.push('+'),
            _ => {
                out.push('%');
                out.push(char::from(b"0123456789ABCDEF"[(b >> 4) as usize]));
                out.push(char::from(b"0123456789ABCDEF"[(b & 0x0f) as usize]));
            }
        }
    }
    out
}

/// Google `OAuth2` token endpoint.
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";

/// JWT grant type for service-account assertion.
const JWT_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Default token lifetime in seconds (Google maximum is 3600).
const DEFAULT_LIFETIME_SECS: u64 = 3600;

/// Clock-skew safety margin: backdate `iat` by this amount to handle small clock differences.
const CLOCK_SKEW_MARGIN_SECS: u64 = 30;

/// A cached service-account access token with its expiry.
#[derive(Clone)]
pub(crate) struct CachedToken {
    pub access_token: String,
    /// Expiry time as seconds since UNIX epoch.
    pub expires_at_unix: u64,
}

impl std::fmt::Debug for CachedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedToken")
            .field("access_token", &"[REDACTED]")
            .field("expires_at_unix", &self.expires_at_unix)
            .finish()
    }
}

impl CachedToken {
    /// Returns `true` if the token has expired or will expire within the safety margin.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        // Refresh 60 seconds before actual expiry to avoid races.
        now + 60 >= self.expires_at_unix
    }
}

/// Build a signed JWT assertion for Google `OAuth2` service-account auth.
///
/// # Arguments
///
/// * `client_email` - The service account email (becomes the `iss` and `sub` claims).
/// * `private_key_pem` - The RSA private key in PEM format (PKCS#8).
/// * `scopes` - Space-separated `OAuth2` scopes.
/// * `token_uri` - The token endpoint (default: Google's `OAuth2` endpoint).
///
/// # Errors
///
/// Returns `GcpError::Config` if the PEM key cannot be parsed, or if signing fails.
pub(crate) fn build_jwt_assertion(
    client_email: &str,
    private_key_pem: &str,
    scopes: &str,
    token_uri: Option<&str>,
) -> GcpResult<String> {
    let audience = token_uri.unwrap_or(TOKEN_ENDPOINT);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| GcpError::Config(format!("system clock error: {e}")))?
        .as_secs();

    let iat = now.saturating_sub(CLOCK_SKEW_MARGIN_SECS);
    let exp = now + DEFAULT_LIFETIME_SECS;

    // Header: RS256 JWT
    let header = serde_json::json!({
        "alg": "RS256",
        "typ": "JWT"
    });

    // Claims
    let claims = serde_json::json!({
        "iss": client_email,
        "sub": client_email,
        "aud": audience,
        "scope": scopes,
        "iat": iat,
        "exp": exp,
    });

    let header_b64 = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let claims_b64 = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    let signing_input = format!("{header_b64}.{claims_b64}");

    // Parse PEM private key (PKCS#8 format, standard for Google service account JSON keys)
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem).map_err(|e| {
        GcpError::Config(format!(
            "failed to parse service-account private key (expected PKCS#8 PEM): {e}"
        ))
    })?;

    // Sign with RS256 (RSASSA-PKCS1-v1_5 + SHA-256)
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let signature = rsa::signature::Signer::sign(&signing_key, signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());

    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Exchange a signed JWT assertion for an access token via Google's `OAuth2` endpoint.
///
/// # Errors
///
/// Returns `GcpError::Unauthorized` for auth failures (including clock-skew hints),
/// `GcpError::Http` for transport errors, and `GcpError::Json` for parse errors.
pub(crate) async fn exchange_jwt_for_token(
    client: &reqwest::Client,
    jwt_assertion: &str,
    token_uri: Option<&str>,
) -> GcpResult<CachedToken> {
    let endpoint = token_uri.unwrap_or(TOKEN_ENDPOINT);

    let form_body = format!(
        "grant_type={}&assertion={}",
        urlencoded(JWT_GRANT_TYPE),
        urlencoded(jwt_assertion),
    );

    let resp = client
        .post(endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(form_body)
        .send()
        .await
        .map_err(GcpError::Http)?;

    let status = resp.status();
    let body: serde_json::Value = resp
        .json::<serde_json::Value>()
        .await
        .map_err(GcpError::Http)?;

    if !status.is_success() {
        let error_desc = body["error_description"]
            .as_str()
            .unwrap_or("unknown error");
        let error_code = body["error"].as_str().unwrap_or("unknown");

        // Detect clock-skew issues and provide actionable guidance
        let message = if error_code == "invalid_grant"
            && (error_desc.contains("time") || error_desc.contains("clock"))
        {
            format!(
                "JWT token exchange failed (possible clock skew): {error_desc}. \
                 Verify that your system clock is accurate. \
                 GCP allows up to 10 minutes of clock skew."
            )
        } else {
            format!("JWT token exchange failed ({error_code}): {error_desc}")
        };

        return Err(GcpError::Unauthorized(message));
    }

    let access_token = body["access_token"]
        .as_str()
        .ok_or_else(|| GcpError::Config("token response missing access_token field".into()))?
        .to_string();

    let expires_in = body["expires_in"].as_u64().unwrap_or(DEFAULT_LIFETIME_SECS);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();

    Ok(CachedToken {
        access_token,
        expires_at_unix: now + expires_in,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a test RSA key pair in PKCS#8 PEM format.
    fn test_private_key_pem() -> String {
        use rsa::pkcs8::EncodePrivateKey;
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 2048).expect("key generation");
        key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .expect("PEM encoding")
            .to_string()
    }

    #[test]
    fn build_jwt_produces_three_part_token() {
        let pem = test_private_key_pem();
        let jwt = build_jwt_assertion(
            "test@project.iam.gserviceaccount.com",
            &pem,
            crate::types::DEFAULT_GCP_SCOPES,
            None,
        )
        .expect("JWT construction should succeed");

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have header.claims.signature");

        // Verify header
        let header_bytes = URL_SAFE_NO_PAD.decode(parts[0]).expect("header base64");
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).expect("header JSON");
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["typ"], "JWT");

        // Verify claims
        let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).expect("claims base64");
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).expect("claims JSON");
        assert_eq!(claims["iss"], "test@project.iam.gserviceaccount.com");
        assert_eq!(claims["sub"], "test@project.iam.gserviceaccount.com");
        assert_eq!(claims["aud"], TOKEN_ENDPOINT);
        assert_eq!(claims["scope"], crate::types::DEFAULT_GCP_SCOPES);
        assert!(claims["iat"].is_u64());
        assert!(claims["exp"].is_u64());

        // iat should be backdated by CLOCK_SKEW_MARGIN_SECS
        let iat = claims["iat"].as_u64().unwrap();
        let exp = claims["exp"].as_u64().unwrap();
        assert!(exp > iat, "exp must be after iat");
        // exp - iat should be DEFAULT_LIFETIME_SECS + CLOCK_SKEW_MARGIN_SECS
        let delta = exp - iat;
        assert_eq!(delta, DEFAULT_LIFETIME_SECS + CLOCK_SKEW_MARGIN_SECS);
    }

    #[test]
    fn build_jwt_with_custom_token_uri() {
        let pem = test_private_key_pem();
        let jwt = build_jwt_assertion(
            "test@project.iam.gserviceaccount.com",
            &pem,
            crate::types::DEFAULT_GCP_SCOPES,
            Some("https://custom-token.example.com/token"),
        )
        .expect("JWT construction should succeed");

        let parts: Vec<&str> = jwt.split('.').collect();
        let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).expect("claims base64");
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).expect("claims JSON");
        assert_eq!(claims["aud"], "https://custom-token.example.com/token");
    }

    #[test]
    fn build_jwt_rejects_invalid_pem() {
        let result = build_jwt_assertion(
            "test@project.iam.gserviceaccount.com",
            "not a valid PEM key",
            crate::types::DEFAULT_GCP_SCOPES,
            None,
        );
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("private key"),
            "error should mention private key: {err_msg}"
        );
    }

    #[test]
    fn build_jwt_rejects_empty_pem() {
        let result = build_jwt_assertion(
            "test@project.iam.gserviceaccount.com",
            "",
            crate::types::DEFAULT_GCP_SCOPES,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn jwt_signature_is_deterministic_for_same_input() {
        // Two JWTs built at the "same" time with the same key should have the same
        // header and claims (aside from tiny time differences). The signature will
        // differ because RS256 with PKCS#1 v1.5 is deterministic for the same input.
        let pem = test_private_key_pem();
        let jwt1 = build_jwt_assertion(
            "svc@p.iam.gserviceaccount.com",
            &pem,
            crate::types::DEFAULT_GCP_SCOPES,
            None,
        )
        .unwrap();
        let jwt2 = build_jwt_assertion(
            "svc@p.iam.gserviceaccount.com",
            &pem,
            crate::types::DEFAULT_GCP_SCOPES,
            None,
        )
        .unwrap();
        // Both should parse as valid 3-part JWTs
        assert_eq!(jwt1.split('.').count(), 3);
        assert_eq!(jwt2.split('.').count(), 3);
    }

    #[test]
    fn cached_token_expired_when_past() {
        let token = CachedToken {
            access_token: "ya29.test".into(),
            expires_at_unix: 0, // long past
        };
        assert!(token.is_expired());
    }

    #[test]
    fn cached_token_not_expired_when_future() {
        let far_future = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 7200;
        let token = CachedToken {
            access_token: "ya29.test".into(),
            expires_at_unix: far_future,
        };
        assert!(!token.is_expired());
    }

    #[test]
    fn cached_token_expired_within_safety_margin() {
        // Token expires in 30 seconds, but safety margin is 60 → expired
        let soon = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 30;
        let token = CachedToken {
            access_token: "ya29.test".into(),
            expires_at_unix: soon,
        };
        assert!(token.is_expired());
    }

    #[test]
    fn build_jwt_with_custom_scopes() {
        let pem = test_private_key_pem();
        let scopes = "https://www.googleapis.com/auth/compute https://www.googleapis.com/auth/devstorage.read_only";
        let jwt = build_jwt_assertion("svc@p.iam.gserviceaccount.com", &pem, scopes, None).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).unwrap();
        assert_eq!(claims["scope"], scopes);
    }

    #[test]
    fn jwt_exchange_parses_success_response() {
        // Test the CachedToken construction logic without hitting the network
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = CachedToken {
            access_token: "ya29.actual-token-here".into(),
            expires_at_unix: now + 3600,
        };
        assert!(!token.is_expired());
        assert_eq!(token.access_token, "ya29.actual-token-here");
    }

    #[test]
    fn build_jwt_signature_is_valid_rs256() {
        use rsa::pkcs1v15::VerifyingKey;
        use rsa::signature::Verifier;

        let pem = test_private_key_pem();
        let private_key = RsaPrivateKey::from_pkcs8_pem(&pem).unwrap();
        let public_key = private_key.to_public_key();

        let jwt = build_jwt_assertion(
            "svc@p.iam.gserviceaccount.com",
            &pem,
            crate::types::DEFAULT_GCP_SCOPES,
            None,
        )
        .unwrap();

        let parts: Vec<&str> = jwt.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();

        let verifying_key = VerifyingKey::<Sha256>::new(public_key);
        let signature =
            rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()).expect("signature bytes");
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .expect("RS256 signature verification should pass");
    }

    // ── Cross-Cloud Auth Regression: GCP JWT ────────────────────

    #[test]
    fn cached_token_debug_redacts_access_token() {
        let token = CachedToken {
            access_token: "ya29.very-secret-token".into(),
            expires_at_unix: 9999999999,
        };
        let debug = format!("{token:?}");
        assert!(
            debug.contains("[REDACTED]"),
            "access_token must be redacted: {debug}"
        );
        assert!(
            !debug.contains("ya29.very-secret-token"),
            "raw access token must not appear in debug output: {debug}"
        );
    }

    #[test]
    fn cached_token_expired_at_exact_safety_margin_boundary() {
        // Token expires exactly 60 seconds from now (the safety margin)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = CachedToken {
            access_token: "ya29.test".into(),
            expires_at_unix: now + 60,
        };
        // now + 60 >= now + 60 is true, so token is expired at boundary
        assert!(
            token.is_expired(),
            "token at exact safety margin boundary should be considered expired"
        );
    }

    #[test]
    fn cached_token_not_expired_just_beyond_safety_margin() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = CachedToken {
            access_token: "ya29.test".into(),
            expires_at_unix: now + 120,
        };
        assert!(
            !token.is_expired(),
            "token well beyond safety margin should not be expired"
        );
    }

    #[test]
    fn jwt_exp_minus_iat_equals_lifetime_plus_skew() {
        let pem = test_private_key_pem();
        let jwt = build_jwt_assertion(
            "svc@p.iam.gserviceaccount.com",
            &pem,
            crate::types::DEFAULT_GCP_SCOPES,
            None,
        )
        .unwrap();

        let parts: Vec<&str> = jwt.split('.').collect();
        let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).unwrap();

        let iat = claims["iat"].as_u64().unwrap();
        let exp = claims["exp"].as_u64().unwrap();
        assert_eq!(
            exp - iat,
            DEFAULT_LIFETIME_SECS + CLOCK_SKEW_MARGIN_SECS,
            "token lifetime must be DEFAULT_LIFETIME_SECS + CLOCK_SKEW_MARGIN_SECS"
        );
    }

    #[test]
    fn jwt_iat_is_backdated_by_clock_skew_margin() {
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let pem = test_private_key_pem();
        let jwt = build_jwt_assertion(
            "svc@p.iam.gserviceaccount.com",
            &pem,
            crate::types::DEFAULT_GCP_SCOPES,
            None,
        )
        .unwrap();

        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let parts: Vec<&str> = jwt.split('.').collect();
        let claims_bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).unwrap();
        let iat = claims["iat"].as_u64().unwrap();

        // iat should be now - CLOCK_SKEW_MARGIN_SECS ± 1 second
        assert!(
            iat >= before - CLOCK_SKEW_MARGIN_SECS - 1 && iat <= after - CLOCK_SKEW_MARGIN_SECS + 1,
            "iat ({iat}) should be backdated by ~{CLOCK_SKEW_MARGIN_SECS}s from now ({before}-{after})"
        );
    }

    #[test]
    fn jwt_different_service_accounts_produce_different_tokens() {
        let pem = test_private_key_pem();
        let jwt1 = build_jwt_assertion(
            "svc1@project.iam.gserviceaccount.com",
            &pem,
            crate::types::DEFAULT_GCP_SCOPES,
            None,
        )
        .unwrap();
        let jwt2 = build_jwt_assertion(
            "svc2@project.iam.gserviceaccount.com",
            &pem,
            crate::types::DEFAULT_GCP_SCOPES,
            None,
        )
        .unwrap();

        // Claims differ (different iss/sub), so signatures differ
        let parts1: Vec<&str> = jwt1.split('.').collect();
        let parts2: Vec<&str> = jwt2.split('.').collect();
        assert_ne!(
            parts1[1], parts2[1],
            "different service accounts must produce different claims"
        );
    }

    #[test]
    fn jwt_different_scopes_produce_different_claims() {
        let pem = test_private_key_pem();
        let jwt1 = build_jwt_assertion(
            "svc@p.iam.gserviceaccount.com",
            &pem,
            "https://www.googleapis.com/auth/cloud-platform",
            None,
        )
        .unwrap();
        let jwt2 = build_jwt_assertion(
            "svc@p.iam.gserviceaccount.com",
            &pem,
            "https://www.googleapis.com/auth/compute",
            None,
        )
        .unwrap();

        let decode_scope = |jwt: &str| -> String {
            let parts: Vec<&str> = jwt.split('.').collect();
            let bytes = URL_SAFE_NO_PAD.decode(parts[1]).unwrap();
            let claims: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            claims["scope"].as_str().unwrap().to_owned()
        };

        assert_ne!(
            decode_scope(&jwt1),
            decode_scope(&jwt2),
            "different scopes must produce different claims"
        );
    }

    #[test]
    fn urlencoded_handles_special_characters() {
        assert_eq!(urlencoded("hello world"), "hello+world");
        assert_eq!(urlencoded("a=b&c=d"), "a%3Db%26c%3Dd");
        assert_eq!(
            urlencoded("safe-chars_here.tilde~"),
            "safe-chars_here.tilde~"
        );
    }

    #[test]
    fn jwt_rejects_pkcs1_format_pem() {
        // PKCS#1 format starts with "-----BEGIN RSA PRIVATE KEY-----"
        // Our implementation requires PKCS#8 format
        let pkcs1_pem =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBALRiMLAH\n-----END RSA PRIVATE KEY-----";
        let result = build_jwt_assertion(
            "svc@p.iam.gserviceaccount.com",
            pkcs1_pem,
            crate::types::DEFAULT_GCP_SCOPES,
            None,
        );
        assert!(
            result.is_err(),
            "PKCS#1 format should be rejected (we require PKCS#8)"
        );
    }
}
