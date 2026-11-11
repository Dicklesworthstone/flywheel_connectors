//! Request-bound authentication at the host's secretless egress boundary.
//!
//! The egress guard calls this only after capability and destination admission.
//! The host repeats it with the current credential incarnation after DNS and
//! authority refresh, inside the original request deadline. Only headers change:
//! URL, method and body remain the same values the guard authorized and the
//! transport will send. Signatures and credential material never enter errors.

use std::collections::BTreeMap;

use fcp_provider_auth::{SigV4Auth, SigV4SigningContext};
use fcp_sandbox::{EgressError, EgressHttpRequest, HttpHeader};
use sha2::{Digest, Sha256};

fn invalid(message: &str) -> EgressError {
    EgressError::CredentialError(message.to_owned())
}

fn owned_signing_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "x-fcp-credential-id"
            | "x-amz-date"
            | "x-amz-content-sha256"
            | "x-amz-security-token"
    )
}

fn query_auth_parameter(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "x-amz-algorithm"
            | "x-amz-credential"
            | "x-amz-date"
            | "x-amz-expires"
            | "x-amz-security-token"
            | "x-amz-signedheaders"
            | "x-amz-signature"
            | "awsaccesskeyid"
            | "signature"
    )
}

fn validate_percent_escapes(raw: &str) -> Result<(), EgressError> {
    // Reject escapes which a forgiving decoder would silently retain.
    let bytes = raw.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'%'
            && (index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit())
        {
            return Err(invalid("SigV4 URL contains an invalid percent escape"));
        }
    }
    Ok(())
}

fn decode_uri_field(raw: &str) -> Result<String, EgressError> {
    validate_percent_escapes(raw)?;
    // Query values are represented as UTF-8 by the shared signer. Reject
    // invalid bytes instead of signing Unicode replacement characters.
    percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .map(std::borrow::Cow::into_owned)
        .map_err(|_| invalid("SigV4 URL must decode to UTF-8"))
}

fn signing_context(
    request: &EgressHttpRequest,
    url: &url::Url,
) -> Result<SigV4SigningContext, EgressError> {
    // Paths remain in wire form, including escapes for opaque non-UTF-8 bytes.
    // Only query fields are decoded into the shared signer's string map.
    validate_percent_escapes(url.path())?;
    let mut context = SigV4SigningContext::new(
        &request.method,
        url.path(),
        hex::encode(Sha256::digest(request.body.as_deref().unwrap_or_default())),
    )
    .map_err(|_| invalid("SigV4 request method, path or payload is invalid"))?;
    if context.method != request.method {
        return Err(invalid("SigV4 requires an uppercase HTTP method"));
    }
    reqwest::Method::from_bytes(request.method.as_bytes())
        .map_err(|_| invalid("SigV4 HTTP method is invalid"))?;

    if let Some(query) = url.query().filter(|query| !query.is_empty()) {
        for part in query.split('&') {
            let (name, value) = part.split_once('=').unwrap_or((part, ""));
            // Match the AWS Rust signer's form-query decoding: a raw '+'
            // represents a space; a literal plus is encoded as '%2B'. Paths
            // deliberately do not use this query-specific normalization.
            let name = decode_uri_field(&name.replace('+', " "))?;
            let value = decode_uri_field(&value.replace('+', " "))?;
            if query_auth_parameter(&name) {
                return Err(invalid(
                    "SigV4 host credentials cannot be combined with query authentication",
                ));
            }
            // The shared signer models one value per decoded query name. Do
            // not silently collapse repeated names or percent-encoded aliases.
            if context.query_params.contains_key(&name) {
                return Err(invalid("SigV4 duplicate query names are unsupported"));
            }
            context = context
                .with_query_param(name, value)
                .map_err(|_| invalid("SigV4 query parameter is invalid"))?;
        }
    }
    Ok(context)
}

/// Sign the exact request using the shared provider-auth implementation.
///
/// The signature is assembled off to the side. Invalid requests leave the
/// original request unchanged; successful calls replace caller auth headers.
pub(super) fn inject_sigv4(
    method: &SigV4Auth,
    request: &EgressHttpRequest,
) -> Result<Vec<HttpHeader>, EgressError> {
    let url = url::Url::parse(&request.url)
        .map_err(|_| invalid("SigV4 requires a valid absolute HTTP URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(invalid(
            "SigV4 requires an HTTP URL without user information or a fragment",
        ));
    }
    let context = signing_context(request, &url)?;
    let mut headers = Vec::with_capacity(request.headers.len() + 4);
    let mut canonical = BTreeMap::new();
    for header in &request.headers {
        if owned_signing_header(&header.name)
            || super::forbidden_egress_request_header(&header.name)
        {
            continue;
        }
        let name = reqwest::header::HeaderName::from_bytes(header.name.as_bytes())
            .map_err(|_| invalid("SigV4 request contains an invalid header name"))?;
        reqwest::header::HeaderValue::from_str(&header.value)
            .map_err(|_| invalid("SigV4 request contains an invalid header value"))?;
        if canonical
            .insert(name.as_str().to_owned(), header.value.clone())
            .is_some()
        {
            return Err(invalid("SigV4 duplicate request headers are unsupported"));
        }
        headers.push(header.clone());
    }
    // reqwest owns Host and framing. Sign the same normalized authority,
    // including a non-default port, instead of a caller's spoofed Host header.
    canonical.insert(
        "host".to_owned(),
        url[url::Position::BeforeHost..url::Position::AfterPort].to_owned(),
    );
    // AWS explicitly excludes these volatile headers from signatures. They
    // may be rewritten by intermediaries without changing request authority.
    canonical.remove("user-agent");
    canonical.remove("x-amzn-trace-id");
    let signed = method
        .sign(&context, &canonical)
        .map_err(|_| invalid("SigV4 could not sign the authorized request"))?;
    headers.extend([
        HttpHeader {
            name: "Authorization".to_owned(),
            value: signed.authorization,
        },
        HttpHeader {
            name: "x-amz-date".to_owned(),
            value: signed.x_amz_date,
        },
        HttpHeader {
            name: "x-amz-content-sha256".to_owned(),
            value: signed.x_amz_content_sha256,
        },
    ]);
    if let Some(token) = signed.x_amz_security_token {
        headers.push(HttpHeader {
            name: "x-amz-security-token".to_owned(),
            value: token,
        });
    }
    Ok(headers)
}

/// Request-bound credentials must never be reused on an automatic redirect.
pub(super) fn requires_original_target(request: &EgressHttpRequest) -> bool {
    request.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("authorization")
            && header.value.starts_with("AWS4-HMAC-SHA256 ")
    })
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use hmac::{Hmac, Mac};

    const ACCESS_KEY: &str = "AKIAEXAMPLEHOSTTEST";
    const SECRET_KEY: &str = "host-signing-fixture-secret";
    const SESSION_TOKEN: &str = "host-signing-fixture-session";

    pub(crate) fn method() -> SigV4Auth {
        SigV4Auth::new(
            ACCESS_KEY,
            SECRET_KEY,
            Some(SESSION_TOKEN.to_owned()),
            "us-east-1",
            "s3",
        )
        .unwrap()
    }

    pub(crate) fn request(url: String) -> EgressHttpRequest {
        EgressHttpRequest {
            url,
            method: "PUT".to_owned(),
            headers: vec![
                HttpHeader {
                    name: "Content-Type".to_owned(),
                    value: "application/octet-stream".to_owned(),
                },
                HttpHeader {
                    name: "Host".to_owned(),
                    value: "untrusted.invalid".to_owned(),
                },
                HttpHeader {
                    name: "AUTHORIZATION".to_owned(),
                    value: "Bearer caller-supplied-secret".to_owned(),
                },
                HttpHeader {
                    name: "X-Amz-Date".to_owned(),
                    value: "20000101T000000Z".to_owned(),
                },
                HttpHeader {
                    name: "X-Amz-Security-Token".to_owned(),
                    value: "caller-supplied-session".to_owned(),
                },
                HttpHeader {
                    name: "X-Amz-Content-Sha256".to_owned(),
                    value: "UNSIGNED-PAYLOAD".to_owned(),
                },
            ],
            body: Some(vec![0, 1, 0xff, b'\n', b'+']),
            credential_id: Some("host-signing-fixture-id".to_owned()),
        }
    }

    fn header<'a>(request: &'a EgressHttpRequest, name: &str) -> &'a str {
        let values = request
            .headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case(name))
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 1, "one authoritative {name} header");
        &values[0].value
    }

    fn mac(key: &[u8], bytes: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(bytes);
        mac.finalize().into_bytes().to_vec()
    }

    /// Independent AWS canonical-request/HMAC check, also used on bytes read
    /// by the loopback HTTP provider. It does not call the production signer.
    pub(crate) fn assert_example_signature(request: &EgressHttpRequest, host: &str) {
        let timestamp = header(request, "x-amz-date");
        let payload_hash = hex::encode(Sha256::digest([0, 1, 0xff, b'\n', b'+']));
        assert_eq!(header(request, "x-amz-content-sha256"), payload_hash);
        assert_eq!(header(request, "x-amz-security-token"), SESSION_TOKEN);
        let signed_headers =
            "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token";
        let canonical_request = format!(
            "PUT\n/bucket/a%20b%2B\nother=a%20b&tag=a%2Bb\n\
             content-type:application/octet-stream\nhost:{host}\n\
             x-amz-content-sha256:{payload_hash}\nx-amz-date:{timestamp}\n\
             x-amz-security-token:{SESSION_TOKEN}\n\n{signed_headers}\n{payload_hash}"
        );
        let date = &timestamp[..8];
        let scope = format!("{date}/us-east-1/s3/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );
        let date_key = mac(format!("AWS4{SECRET_KEY}").as_bytes(), date.as_bytes());
        let region_key = mac(&date_key, b"us-east-1");
        let service_key = mac(&region_key, b"s3");
        let signing_key = mac(&service_key, b"aws4_request");
        let signature = hex::encode(mac(&signing_key, string_to_sign.as_bytes()));
        assert_eq!(
            header(request, "authorization"),
            format!(
                "AWS4-HMAC-SHA256 Credential={ACCESS_KEY}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
            )
        );
    }

    #[test]
    fn signs_binary_payload_and_exact_path_query_host_with_shared_signer() {
        let mut request = request(
            "https://examplebucket.s3.amazonaws.com:8443/bucket/a%20b%2B?tag=a%2Bb&other=a+b"
                .to_owned(),
        );
        let original = request.clone();
        request.headers = inject_sigv4(&method(), &request).unwrap();
        assert_example_signature(&request, "examplebucket.s3.amazonaws.com:8443");
        assert_eq!(request.method, original.method);
        assert_eq!(request.url, original.url);
        assert_eq!(request.body, original.body);
        assert_eq!(request.credential_id, original.credential_id);
        assert!(requires_original_target(&request));
        assert!(!request.headers.iter().any(|header| {
            header.value.contains("caller-supplied")
                || header.value.contains("UNSIGNED-PAYLOAD")
                || header.name.eq_ignore_ascii_case("host")
        }));
    }

    #[test]
    fn refuses_ambiguous_or_pre_authenticated_urls_without_changing_request() {
        for url in [
            "https://example.com/?key=first&key=second",
            "https://example.com/?key=first&%6bey=second",
            "https://example.com/?key=%ff",
            "https://example.com/?key=%0z",
            "https://example.com/%0z",
            "https://example.com/?=value",
            "https://example.com/?key=value&&next=value",
            "https://example.com/?X-Amz-Signature=untrusted",
            "https://example.com/?%58-Amz-Credential=untrusted",
            "https://example.com/?AWSAccessKeyId=untrusted",
            "https://user:untrusted@example.com/",
            "https://example.com/#untrusted",
            "ftp://example.com/file",
        ] {
            let request = request(url.to_owned());
            let before = serde_json::to_value(&request).unwrap();
            let error = inject_sigv4(&method(), &request).unwrap_err();
            assert_eq!(serde_json::to_value(&request).unwrap(), before);
            assert!(!error.to_string().contains("untrusted"));
            assert!(!error.to_string().contains(SECRET_KEY));
            assert!(!error.to_string().contains(SESSION_TOKEN));
        }
    }

    #[test]
    fn rejects_header_aliases_and_noncanonical_methods_before_signing() {
        let mut request = request("https://example.com/".to_owned());
        request.headers.push(HttpHeader {
            name: "content-TYPE".to_owned(),
            value: "application/json".to_owned(),
        });
        assert!(inject_sigv4(&method(), &request).is_err());
        request.headers.pop();
        for invalid_method in ["get", " PUT", "GET\r\nX-Injected: yes", "GE T"] {
            request.method = invalid_method.to_owned();
            assert!(inject_sigv4(&method(), &request).is_err());
        }
    }

    #[test]
    fn preserves_opaque_wire_paths_and_excludes_transport_owned_headers() {
        let mut request = request("https://example.com/a%2Fb/%ff/%252F".to_owned());
        for name in [
            "Connection",
            "Content-Length",
            "Transfer-Encoding",
            "Keep-Alive",
            "Proxy-Connection",
            "Proxy-Authorization",
            "Proxy-Authenticate",
            "TE",
            "Trailer",
            "Upgrade",
        ] {
            request.headers.push(HttpHeader {
                name: name.to_owned(),
                value: "caller-transport-value".to_owned(),
            });
        }
        let context = signing_context(&request, &url::Url::parse(&request.url).unwrap()).unwrap();
        assert_eq!(context.uri_path, "/a%2Fb/%ff/%252F");
        request.headers = inject_sigv4(&method(), &request).unwrap();
        assert!(!request.headers.iter().any(|header| {
            super::super::forbidden_egress_request_header(&header.name)
                || header.value == "caller-transport-value"
        }));
    }

    #[test]
    fn query_parser_distinguishes_plus_space_and_literal_percent() {
        let request = request(
            "https://example.com/?plus=%2B&space=%20&form=+&percent=%25&flag&utf8=%E2%9C%93"
                .to_owned(),
        );
        let context = signing_context(&request, &url::Url::parse(&request.url).unwrap()).unwrap();
        assert_eq!(context.query_params["plus"], "+");
        assert_eq!(context.query_params["space"], " ");
        assert_eq!(context.query_params["form"], " ");
        assert_eq!(context.query_params["percent"], "%");
        assert_eq!(context.query_params["flag"], "");
        assert_eq!(context.query_params["utf8"], "✓");
    }
}
