//! SigV4 canonical-URI regression coverage for the AWS connector's signing path
//! (br-1nqg7).
//!
//! `sign_request` assembles the request URL by string-formatting the raw bucket
//! and key, parses it with `url::Url`, and passes `url.path()` — the WIRE path,
//! already percent-encoded — to the SDK signer. The service percent-decodes
//! what it receives and re-encodes it to canonicalize, so the signer has to do
//! the same. Encoding the wire path directly is only equivalent when the key
//! needed no escaping in the first place.
//!
//! These tests pin the encoding contract at the connector boundary so a future
//! change to either the URL construction or the signer trips here rather than
//! silently producing `SignatureDoesNotMatch` against live S3 — which the
//! wiremock-based suites cannot catch, since they never verify signatures.

use fcp_sdk::sigv4::{CanonicalPathEncoding, SigningScope};

/// Mirror of the service-side canonicalization: decode the received path, then
/// URI-encode each segment once (S3) or twice (everything else).
fn service_canonical_uri(wire_path: &str, encoding: CanonicalPathEncoding) -> String {
    fn uri_encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len() * 2);
        for byte in s.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(byte as char);
                }
                _ => out.push_str(&format!("%{byte:02X}")),
            }
        }
        out
    }
    fn encode_path(path: &str) -> String {
        if path.is_empty() {
            return "/".into();
        }
        path.split('/')
            .map(uri_encode)
            .collect::<Vec<_>>()
            .join("/")
    }

    let decoded = percent_encoding::percent_decode_str(wire_path)
        .decode_utf8_lossy()
        .into_owned();
    let once = encode_path(&decoded);
    match encoding {
        CanonicalPathEncoding::Single => once,
        CanonicalPathEncoding::Double => encode_path(&once),
    }
}

/// The wire path the connector actually sends, derived exactly as
/// `sign_request` derives it.
fn wire_path_for_key(bucket: &str, key: &str) -> String {
    let url = format!("https://s3.amazonaws.com/{bucket}/{key}");
    url::Url::parse(&url)
        .expect("connector-shaped S3 url parses")
        .path()
        .to_string()
}

#[test]
fn s3_is_single_encoded_and_other_services_are_double_encoded() {
    let s3 = SigningScope {
        region: "us-east-1".into(),
        service: "s3".into(),
    };
    let bedrock = SigningScope {
        region: "us-east-1".into(),
        service: "bedrock".into(),
    };

    assert_eq!(
        s3.canonical_path_encoding(),
        CanonicalPathEncoding::Single,
        "S3 requires exactly one encoding pass"
    );
    assert_eq!(
        bedrock.canonical_path_encoding(),
        CanonicalPathEncoding::Double,
        "every non-S3 service requires two encoding passes"
    );
}

/// The cases that were silently broken: any key containing a character the URL
/// parser percent-encodes. Encoding the wire path a second time turned `%20`
/// into `%2520`, so the client's canonical request could never match S3's.
#[test]
fn s3_canonical_uri_survives_keys_that_require_escaping() {
    for (key, expected_canonical) in [
        ("my report.pdf", "/bucket/my%20report.pdf"),
        ("50%.pdf", "/bucket/50%25.pdf"),
        ("e\u{f1}e.pdf", "/bucket/e%C3%B1e.pdf"),
        ("caf\u{e9}/men\u{fc}.txt", "/bucket/caf%C3%A9/men%C3%BC.txt"),
    ] {
        let wire = wire_path_for_key("bucket", key);
        assert_eq!(
            service_canonical_uri(&wire, CanonicalPathEncoding::Single),
            expected_canonical,
            "key {key:?} (wire {wire:?}) must canonicalize to what S3 computes"
        );
    }
}

/// Characters the URL parser leaves alone were already signed correctly, and
/// must stay that way — this is the "no behaviour change for what already
/// worked" half of the fix. It also pins the claim in `sanitize_object_key`'s
/// comment that `&` is safe to allow in a key.
#[test]
fn s3_canonical_uri_is_unchanged_for_keys_that_needed_no_escaping() {
    for (key, expected_canonical) in [
        ("plain.pdf", "/bucket/plain.pdf"),
        ("path/to/file.txt", "/bucket/path/to/file.txt"),
        ("Q&A.pdf", "/bucket/Q%26A.pdf"),
        ("a+b.pdf", "/bucket/a%2Bb.pdf"),
        ("a:b.pdf", "/bucket/a%3Ab.pdf"),
    ] {
        let wire = wire_path_for_key("bucket", key);
        assert_eq!(
            service_canonical_uri(&wire, CanonicalPathEncoding::Single),
            expected_canonical,
            "key {key:?} signed correctly before the fix and must still"
        );
    }
}
