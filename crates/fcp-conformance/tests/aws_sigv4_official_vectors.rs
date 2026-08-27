//! Differential `SigV4` harness against AWS's published signing test suite.
//!
//! br-3wt77. The workspace has two independent `SigV4` signers —
//! `fcp_sdk::sigv4` and `fcp_provider_auth` — and before this harness neither was
//! checked against AWS's own vectors. Each pinned exactly one real vector
//! (`GetBucketLifecycle`), whose path is `/`: the single path for which a correct
//! canonical-URI implementation and a broken one agree. That is precisely why
//! the canonical-URI defect behind br-1nqg7 / br-0lsi3 survived in both crates
//! while every test passed.
//!
//! BOTH signers are now driven over the same corpus, and additionally compared
//! against **each other** byte for byte. Matching AWS is not sufficient on its
//! own: two signers can each match on the cases they are checked against and
//! still disagree elsewhere, in which case a request verifies or not depending on
//! which crate happened to be on the call path.
//!
//! Vectors are vendored verbatim under `tests/vectors/aws-sigv4/`; see the
//! README there for provenance. They are never fetched at test time.
//!
//! Each case is asserted stage by stage — canonical request, then
//! string-to-sign, then signature — because every `SigV4` stage hashes into the
//! next. Comparing only the final signature would say *that* a signer diverged
//! but never *where*, and the whole value of these fixtures is that they ship
//! the intermediates.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use fcp_provider_auth::{
    CanonicalPathNormalization as PaNormalization, SigV4Auth, SigV4SigningContext,
    SigV4SigningOptions,
};
use fcp_sdk::sigv4::{
    AwsCredentials, CanonicalPathEncoding, CanonicalPathNormalization, SigV4Signer,
    SignableRequest, SigningScope,
};

/// One vendored case.
struct Vector {
    name: String,
    request: ParsedRequest,
    context: Context,
    expected_canonical_request: String,
    expected_string_to_sign: String,
    expected_signature: String,
}

struct Context {
    access_key_id: String,
    secret_access_key: String,
    token: Option<String>,
    region: String,
    service: String,
    timestamp: String,
    /// When true the case expects `x-amz-content-sha256` in the signed set.
    sign_body: bool,
    /// RFC 3986 dot-segment removal, and ONLY that.
    ///
    /// This flag does not select the encoding profile. Upstream maps it to
    /// `should_normalize_uri_path` alone, while `use_double_uri_encode` is
    /// hardcoded `true` for every case in the suite
    /// (`aws-c-auth` `tests/sigv4_signing_tests.c`,
    /// `s_v4_test_context_init_signing_config`). Normalisation and encoding are
    /// two independent axes upstream, exactly as they are here.
    normalize: bool,
    /// When true the case adds `x-amz-security-token` to the request AFTER
    /// signing, so the token must be absent from the signed header set.
    ///
    /// Upstream this is `flags.omit_session_token`; absent means `false`.
    omit_session_token: bool,
}

struct ParsedRequest {
    method: String,
    path: String,
    query: BTreeMap<String, String>,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
    /// Sign this payload hash verbatim instead of hashing `body`.
    ///
    /// Always `None` for vendored cases — the corpus's expectations are computed
    /// from the body, so overriding it there would compare against the wrong
    /// answer. Synthetic cross-signer cases set it, because two of the axes worth
    /// checking (uppercase hex, and the `UNSIGNED-PAYLOAD` sentinel) are
    /// properties OF the hash string and are unreachable by hashing a body.
    payload_hash_override: Option<String>,
}

impl ParsedRequest {
    /// The payload hash the signers should be handed.
    fn payload_hash(&self) -> String {
        self.payload_hash_override
            .clone()
            .unwrap_or_else(|| SignableRequest::hash_payload(&self.body))
    }
}

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/aws-sigv4")
}

/// Parse the suite's `request.txt`: an HTTP/1.1 request line, then headers as
/// `Name:value` (no space after the colon), then a blank line, then the body.
///
/// Continuation lines (a header value folded across lines) appear in
/// `get-header-value-multiline` and are joined per RFC 7230 obsolete folding.
fn parse_request(raw: &str) -> ParsedRequest {
    let mut lines = raw.split('\n');
    let request_line = lines.next().unwrap_or_default().trim_end_matches('\r');
    // The target may itself contain a literal space (`get-space-*`), so split
    // on the FIRST and LAST space rather than tokenising: `GET /a b/ HTTP/1.1`.
    let (method, rest) = request_line.split_once(' ').unwrap_or((request_line, ""));
    let method = method.to_string();
    let target = rest
        .rsplit_once(' ')
        .map_or_else(|| rest.to_string(), |(t, _version)| t.to_string());

    let (path, query_str) = target.split_once('?').map_or_else(
        || (target.clone(), String::new()),
        |(p, q)| (p.to_string(), q.to_string()),
    );

    let mut query = BTreeMap::new();
    if !query_str.is_empty() {
        for pair in query_str.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            query.insert(decode(k), decode(v));
        }
    }

    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    let mut last_key: Option<String> = None;
    let mut body_lines: Vec<String> = Vec::new();
    let mut in_body = false;

    for line in lines {
        let line = line.trim_end_matches('\r');
        if in_body {
            body_lines.push(line.to_string());
            continue;
        }
        if line.is_empty() {
            in_body = true;
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Obsolete line folding (RFC 7230 §3.2.4). AWS replaces the fold
            // with a single SPACE, not a comma — comma-joining is the rule for
            // a REPEATED header name, which is a different case. Measured
            // against get-header-value-multiline, whose expected canonical
            // request is `my-header1:value1 value2 value3`.
            if let Some(key) = &last_key {
                let existing = headers.get(key).cloned().unwrap_or_default();
                headers.insert(key.clone(), format!("{existing} {}", line.trim()));
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            let key = name.trim().to_lowercase();
            // A repeated header name is comma-joined, per the canonical-request
            // rules the `get-header-key-duplicate` case exercises.
            headers
                .entry(key.clone())
                .and_modify(|existing| {
                    *existing = format!("{existing},{}", value.trim());
                })
                .or_insert_with(|| value.trim().to_string());
            last_key = Some(key);
        }
    }

    ParsedRequest {
        method,
        path,
        query,
        headers,
        body: body_lines.join("\n").into_bytes(),
        payload_hash_override: None,
    }
}

fn decode(s: &str) -> String {
    percent_decode(s)
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn parse_context(raw: &str) -> Context {
    let v: serde_json::Value = serde_json::from_str(raw).expect("context.json");
    let creds = &v["credentials"];
    Context {
        access_key_id: creds["access_key_id"].as_str().unwrap_or_default().into(),
        secret_access_key: creds["secret_access_key"]
            .as_str()
            .unwrap_or_default()
            .into(),
        token: creds
            .get("token")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        region: v["region"].as_str().unwrap_or_default().into(),
        service: v["service"].as_str().unwrap_or_default().into(),
        timestamp: v["timestamp"].as_str().unwrap_or_default().into(),
        sign_body: v["sign_body"].as_bool().unwrap_or(false),
        normalize: v["normalize"].as_bool().unwrap_or(true),
        omit_session_token: v["omit_session_token"].as_bool().unwrap_or(false),
    }
}

fn load_vectors() -> Vec<Vector> {
    let dir = vectors_dir();
    let mut out = Vec::new();
    let mut entries: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .filter_map(Result::ok)
        .filter(|e| e.path().is_dir())
        .collect();
    entries.sort_by_key(std::fs::DirEntry::path);

    for entry in entries {
        let p = entry.path();
        let name = p
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        let read = |f: &str| {
            std::fs::read_to_string(p.join(f)).unwrap_or_else(|e| panic!("{name}/{f}: {e}"))
        };
        out.push(Vector {
            request: parse_request(&read("request.txt")),
            context: parse_context(&read("context.json")),
            expected_canonical_request: read("header-canonical-request.txt"),
            expected_string_to_sign: read("header-string-to-sign.txt"),
            expected_signature: read("header-signature.txt").trim().to_string(),
            name,
        });
    }
    assert!(!out.is_empty(), "no vendored vectors found");
    out
}

/// The suite's fixtures are the authority on what a correct signer emits. This
/// checks the *parser* first, on a case whose shape is hand-verifiable, so a
/// parser bug cannot silently weaken every downstream assertion.
#[test]
fn request_parser_matches_a_hand_checked_case() {
    let dir = vectors_dir().join("get-vanilla-query-order-key-case");
    let parsed = parse_request(&std::fs::read_to_string(dir.join("request.txt")).unwrap());
    assert_eq!(parsed.method, "GET");
    assert_eq!(parsed.path, "/");
    assert_eq!(
        parsed.headers.get("host").map(String::as_str),
        Some("example.amazonaws.com")
    );
    assert_eq!(parsed.body, [] as [u8; 0]);

    let ctx = parse_context(&std::fs::read_to_string(dir.join("context.json")).unwrap());
    assert_eq!(ctx.access_key_id, "AKIDEXAMPLE");
    assert_eq!(ctx.region, "us-east-1");
    assert_eq!(ctx.service, "service");
    assert_eq!(ctx.timestamp, "2015-08-30T12:36:00Z");

    assert!(
        !ctx.omit_session_token,
        "absent omit_session_token must default to false"
    );

    // The sts pair is the only place this flag appears, and it appears on BOTH
    // sides. A parser that silently dropped it would make `-after` look like a
    // signer defect, which is exactly what happened before it was read.
    for (case, expected) in [
        ("post-sts-header-after", true),
        ("post-sts-header-before", false),
    ] {
        let sts = parse_context(
            &std::fs::read_to_string(vectors_dir().join(case).join("context.json")).unwrap(),
        );
        assert_eq!(
            sts.omit_session_token, expected,
            "{case}: omit_session_token must be read from context.json"
        );
        assert!(sts.token.is_some(), "{case} must carry a session token");
    }

    let multiline = parse_request(
        &std::fs::read_to_string(vectors_dir().join("get-header-value-multiline/request.txt"))
            .unwrap(),
    );
    assert!(
        multiline
            .headers
            .get("my-header1")
            .is_some_and(|v| v == "value1 value2 value3"),
        "folded header values must be space-joined per RFC 7230 unfolding, got {:?}",
        multiline.headers.get("my-header1")
    );
}

/// The suite's `normalize` flag selects dot-segment removal, and nothing else.
///
/// It is NOT the S3-vs-everything-else encoding selector — an earlier version of
/// this comment claimed it was. Upstream maps `normalize` to
/// `should_normalize_uri_path` while hardcoding `use_double_uri_encode = true`
/// for all 38 cases, so the corpus exercises both normalisation profiles but
/// only the double-encoding profile. This pins that the normalisation split is
/// still represented on both sides.
#[test]
fn vendored_corpus_covers_both_normalization_profiles() {
    let vectors = load_vectors();
    let normalized = vectors.iter().filter(|v| v.context.normalize).count();
    let unnormalized = vectors.len() - normalized;
    eprintln!("vectors: {normalized} normalize=true, {unnormalized} normalize=false");
    assert!(normalized > 0, "corpus lost its normalize=true cases");
    assert!(
        unnormalized > 0,
        "corpus lost its normalize=false cases — the S3-side path profile would be untested"
    );
}

fn sign_with_sdk(v: &Vector) -> (String, String, String) {
    let ts = chrono::DateTime::parse_from_rfc3339(&v.context.timestamp)
        .expect("timestamp")
        .with_timezone(&chrono::Utc);

    let creds = AwsCredentials {
        access_key_id: v.context.access_key_id.clone(),
        secret_access_key: v.context.secret_access_key.clone(),
        session_token: v.context.token.clone(),
    };
    let scope = SigningScope {
        region: v.context.region.clone(),
        service: v.context.service.clone(),
    };
    // AWS's vectors sign a service that does not carry x-amz-content-sha256, so
    // the signer is driven in exactly that shape. Leaving the header on would
    // make every case mismatch for a reason unrelated to the canonical-URI and
    // query-encoding rules these fixtures exist to pin. Verified by measurement:
    // with the header enabled, the sole difference on get-header-key-duplicate
    // was that one header line — every other byte, including the duplicate-key
    // comma join, already matched.
    let signer = SigV4Signer::new(creds, scope)
        .with_fixed_time(ts)
        .with_content_sha256_header(v.context.sign_body)
        // Every vendored case uses service `service`, so the scope-derived
        // profile would normalise all 38. The corpus instead carries the profile
        // per case in `context.normalize`, which is the axis these fixtures
        // exist to exercise, so it is driven explicitly here.
        .with_path_normalization(if v.context.normalize {
            CanonicalPathNormalization::RemoveDotSegments
        } else {
            CanonicalPathNormalization::Preserve
        })
        // `post-sts-header-after` carries `"omit_session_token": true`: the
        // token travels on the wire but must not be in the signed header set.
        // Ignoring this field made that case look like a signer defect when it
        // is a documented AWS signing mode.
        .with_omit_session_token(v.context.omit_session_token);

    let req = SignableRequest {
        method: v.request.method.clone(),
        uri: v.request.path.clone(),
        query_params: v.request.query.clone(),
        headers: v.request.headers.clone(),
        payload_hash: v.request.payload_hash(),
    };
    let (_, trace) = signer.sign_traced(&req);
    (
        trace.canonical_request,
        trace.string_to_sign,
        trace.signature,
    )
}

/// Drive `fcp-provider-auth`'s independent signer over the same vector.
///
/// This is the second half of br-3wt77: one corpus, one parser, one set of
/// expectations, two signers. A vector suite that only ever ran against one of
/// two implementations leaves the other exactly as unverified as it was before —
/// and it was this crate, not `fcp-sdk`, that still had no path normalisation at
/// all.
///
/// Returns `None` when the signer refuses the case rather than signing it.
/// Refusals are surfaced, never swallowed: this signer validates header names
/// and values and requires `host`, which `fcp-sdk` does not, so a refusal is a
/// real behavioural difference that belongs in the report.
fn sign_with_provider_auth(v: &Vector) -> Option<(String, String, String)> {
    let auth = SigV4Auth::new(
        v.context.access_key_id.clone(),
        v.context.secret_access_key.clone(),
        v.context.token.clone(),
        v.context.region.clone(),
        v.context.service.clone(),
    )
    .expect("vector credentials are well-formed");

    let ts = chrono::DateTime::parse_from_rfc3339(&v.context.timestamp)
        .expect("timestamp")
        .with_timezone(&chrono::Utc);

    let mut context =
        SigV4SigningContext::new(&v.request.method, &v.request.path, v.request.payload_hash())
            .expect("vector request is well-formed")
            .with_signing_time(ts);
    for (k, val) in &v.request.query {
        context = context
            .with_query_param(k.clone(), val.clone())
            .expect("vector query param is well-formed");
    }

    let options = SigV4SigningOptions {
        path_normalization: Some(if v.context.normalize {
            PaNormalization::RemoveDotSegments
        } else {
            PaNormalization::Preserve
        }),
        sign_content_sha256_header: v.context.sign_body,
        omit_session_token: v.context.omit_session_token,
    };

    let (_, trace) = auth
        .sign_traced(&context, &v.request.headers, options)
        .ok()?;
    Some((
        trace.canonical_request,
        trace.string_to_sign,
        trace.signature,
    ))
}

/// Cases `fcp-provider-auth` REFUSES to sign, with the reason.
///
/// A refusal is not a divergence — this signer deliberately validates more than
/// `fcp-sdk` does — but it is also not coverage, so it is enumerated rather than
/// silently skipped. Listing it keeps the two signers' verified surface honest:
/// these are the cases where only one of them is actually checked.
///
/// MEASURED EMPTY: the stricter validation refuses none of the 38 cases. Every
/// vector carries `host`, header names stay inside the ASCII-alnum-plus-hyphen
/// charset, and no value is empty after trimming — `get-header-value-multiline`
/// unfolds to a value this signer accepts. The list stays here, asserted against,
/// so that a future validation change cannot quietly convert coverage into a
/// skip.
const PROVIDER_AUTH_REFUSED: &[&str] = &[];

/// Cases where this harness cannot compare the two signers on equal terms.
///
/// This list is a RATCHET, not a suppression: the test asserts the divergent
/// set is EXACTLY this, so a new divergence fails, and a case that starts
/// matching also fails until the name is removed here.
///
/// Only ONE category remains, and it is a documented input-convention boundary
/// rather than a signing defect. Resolved history, kept because it explains why
/// the list is the shape it is (br-f57c6):
///
/// * Path normalisation (was 6 cases) — FIXED: `CanonicalPathNormalization` is
///   now a second profile axis and `remove_dot_segments` resolves `.` / `..`
///   and collapses duplicate slashes. Independently confirmed as the right
///   shape by upstream, which also treats `should_normalize_uri_path` and
///   `use_double_uri_encode` as independent flags.
/// * Header-value whitespace (was 1) — FIXED: `canonical_header_value` collapses
///   internal runs, not just the ends.
/// * Canonical query ordering (was 1) — FIXED: pairs are percent-encoded and
///   only THEN sorted, matching `s_transform_query_params` → `qsort` with
///   `s_canonical_query_param_comparator`. The earlier note that this needed an
///   API change was wrong: the encoded key is a pure function of the decoded
///   key, so the ordering is always recoverable from a decoded-keyed map.
/// * Session token always signed (was 1) — NOT A DEFECT: `context.json` carries
///   `omit_session_token`, which this harness previously ignored. It is now
///   parsed and threaded through `with_omit_session_token`.
///
/// REMAINING — raw-vs-wire input convention (3 cases):
/// `get-space-normalized`, `get-space-unnormalized`, `get-utf8`.
///
/// These fixtures put a LITERAL space or a literal `U+1234` in the request
/// target (`GET /example space/ HTTP/1.1`), which is not a legal
/// request-target. AWS's own signer never percent-decodes the path: with
/// `use_double_uri_encode` it applies exactly ONE encoding pass to whatever
/// string it was handed, and with the flag off it emits that string verbatim
/// (`aws-c-auth` `source/aws_signing.c`, `s_append_canonical_path`). So on a raw
/// path it produces `%20`. `SignableRequest::uri` is documented to carry the
/// WIRE path, and this signer decodes it before re-encoding, so on the same raw
/// string its decode is a no-op and it emits one pass more: `%2520`.
///
/// For a canonically-encoded wire path the two algorithms are IDENTICAL in both
/// profiles. That equivalence is measured directly, not asserted in prose, by
/// `fcp_sdk::sigv4` test `wire_path_input_reproduces_aws_own_canonical_path_algorithm`
/// and by [`wire_form_of_the_raw_fixture_paths_matches_aws`] below.
///
/// The encoding contract itself was settled by measurement against live AWS in
/// br-1nqg7 / br-0lsi3 and is NOT re-derived from these files. The earlier
/// hypothesis — that the corpus was generated with double-encoding disabled —
/// was checked against the generator and REFUTED: `use_double_uri_encode` is
/// hardcoded `true` for all 38 cases.
const KNOWN_DIVERGENT: &[&str] = &[
    // Raw (non-wire) fixture paths; see above.
    "get-space-normalized",
    "get-space-unnormalized",
    "get-utf8",
];

/// Every case is checked stage by stage. Divergences are reported all at once,
/// per stage, because a signer bug shows up as a FAMILY of related failures and
/// the family is the diagnosis.
#[test]
fn sdk_signer_against_official_vectors() {
    let vectors = load_vectors();
    let mut diverged: Vec<String> = Vec::new();
    let mut stage_detail: Vec<String> = Vec::new();

    for v in &vectors {
        let (canonical, sts, sig) = sign_with_sdk(v);
        let canonical_ok = canonical.trim_end() == v.expected_canonical_request.trim_end();
        let sts_ok = sts.trim_end() == v.expected_string_to_sign.trim_end();
        let sig_ok = sig == v.expected_signature;

        if canonical_ok && sts_ok && sig_ok {
            continue;
        }
        diverged.push(v.name.clone());

        // A canonical-request match with a downstream mismatch would mean the
        // hashing or key-derivation stage is broken, which is a different and
        // much more serious class than a canonicalisation difference.
        assert!(
            !(canonical_ok && (!sts_ok || !sig_ok)),
            "{}: canonical request matches AWS but a later stage does not — \
             string_to_sign_ok={sts_ok} signature_ok={sig_ok}. That implicates \
             hashing or signing-key derivation, not canonicalisation.",
            v.name
        );
        stage_detail.push(format!("{} (canonical request)", v.name));
    }

    diverged.sort();
    let mut expected: Vec<String> = KNOWN_DIVERGENT.iter().map(|s| (*s).to_string()).collect();
    expected.sort();

    let matched = vectors.len() - diverged.len();
    eprintln!(
        "aws-sigv4 official vectors: {matched}/{} cases reproduce AWS exactly at all three \
         stages; {} known divergences",
        vectors.len(),
        diverged.len()
    );
    if !stage_detail.is_empty() {
        eprintln!("divergent stages: {stage_detail:?}");
    }

    let newly_broken: Vec<_> = diverged.iter().filter(|n| !expected.contains(n)).collect();
    let newly_fixed: Vec<_> = expected.iter().filter(|n| !diverged.contains(n)).collect();

    assert!(
        newly_broken.is_empty(),
        "NEW SigV4 divergence from AWS's published vectors: {newly_broken:?}. \
         This is a regression — the signer changed behaviour on a case that used to match."
    );
    assert!(
        newly_fixed.is_empty(),
        "These cases now match AWS: {newly_fixed:?}. Remove them from KNOWN_DIVERGENT \
         so the ratchet holds them from here on."
    );
}

/// The same corpus, the same stage-by-stage assertions, against the OTHER
/// signer.
///
/// `fcp-provider-auth` is expected to reproduce AWS on exactly the cases
/// `fcp-sdk` does: both crates now implement the same two path profiles, the same
/// encode-then-sort query rule, the same header-whitespace collapse, and the same
/// `omit_session_token` mode. The shared `KNOWN_DIVERGENT` ratchet therefore
/// applies unchanged — if the two signers ever need different lists, they have
/// drifted, and that is the bug this test exists to catch.
#[test]
fn provider_auth_signer_against_official_vectors() {
    let vectors = load_vectors();
    let mut diverged: Vec<String> = Vec::new();
    let mut refused: Vec<String> = Vec::new();

    for v in &vectors {
        let Some((canonical, sts, sig)) = sign_with_provider_auth(v) else {
            refused.push(v.name.clone());
            continue;
        };
        let canonical_ok = canonical.trim_end() == v.expected_canonical_request.trim_end();
        let sts_ok = sts.trim_end() == v.expected_string_to_sign.trim_end();
        let sig_ok = sig == v.expected_signature;

        if canonical_ok && sts_ok && sig_ok {
            continue;
        }
        diverged.push(v.name.clone());

        assert!(
            !(canonical_ok && (!sts_ok || !sig_ok)),
            "{}: canonical request matches AWS but a later stage does not — \
             string_to_sign_ok={sts_ok} signature_ok={sig_ok}. That implicates \
             hashing or signing-key derivation, not canonicalisation.",
            v.name
        );
    }

    diverged.sort();
    refused.sort();
    let mut expected_divergent: Vec<String> =
        KNOWN_DIVERGENT.iter().map(|s| (*s).to_string()).collect();
    expected_divergent.sort();
    let mut expected_refused: Vec<String> = PROVIDER_AUTH_REFUSED
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    expected_refused.sort();

    eprintln!(
        "aws-sigv4 official vectors (fcp-provider-auth): {}/{} reproduce AWS exactly; \
         {} known divergences; {} refused",
        vectors.len() - diverged.len() - refused.len(),
        vectors.len(),
        diverged.len(),
        refused.len(),
    );

    assert_eq!(
        refused, expected_refused,
        "the set of cases fcp-provider-auth refuses to sign changed. A refusal is \
         not coverage — if this grew, a case silently stopped being checked."
    );
    assert_eq!(
        diverged, expected_divergent,
        "fcp-provider-auth's divergence set must equal fcp-sdk's. A difference \
         here means the two signers no longer agree on canonicalisation, so the \
         same request signs two ways depending on which crate runs."
    );
}

/// The two signers must produce byte-identical canonical requests.
///
/// This is the assertion that actually protects callers. Both crates matching AWS
/// on 35 of 38 cases would still permit them to differ on the other 3, and a
/// request signed by whichever crate happened to be on the call path would then
/// verify or not depending on that accident. Comparing them to each other
/// directly closes that gap — including on the cases where NEITHER matches AWS.
#[test]
fn both_signers_agree_byte_for_byte_on_every_vector() {
    let mut compared = 0_usize;
    for v in &load_vectors() {
        let Some((pa_canonical, pa_sts, pa_sig)) = sign_with_provider_auth(v) else {
            continue;
        };
        let (sdk_canonical, sdk_sts, sdk_sig) = sign_with_sdk(v);

        assert_eq!(
            sdk_canonical.trim_end(),
            pa_canonical.trim_end(),
            "{}: the two signers built different canonical requests",
            v.name
        );
        assert_eq!(sdk_sts.trim_end(), pa_sts.trim_end(), "{}", v.name);
        assert_eq!(sdk_sig, pa_sig, "{}", v.name);
        compared += 1;
    }
    assert!(
        compared >= 30,
        "only {compared} vectors were comparable across both signers; the \
         cross-signer check has lost its coverage"
    );
}

/// Build a synthetic vector for cross-signer comparison only.
///
/// The expectations are placeholders and are never asserted against: these cases
/// exist to compare the two signers to EACH OTHER on inputs the official corpus
/// cannot express, so there is no AWS-published answer to compare to.
fn synthetic_vector(
    name: &str,
    method: &str,
    path: &str,
    query: &[(&str, &str)],
    headers: &[(&str, &str)],
    payload_hash: &str,
) -> Vector {
    Vector {
        name: name.to_string(),
        request: ParsedRequest {
            method: method.to_string(),
            path: path.to_string(),
            query: query
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
            body: Vec::new(),
            // Verbatim, NOT hashed from the empty body. Without this the
            // uppercase-hex and `UNSIGNED-PAYLOAD` cases were inert: both signers
            // recomputed the same lowercase hash from the same empty body, so they
            // agreed for a reason that had nothing to do with the axis under test.
            // Caught by running the negative control, which failed to name them.
            payload_hash_override: Some(payload_hash.to_string()),
        },
        context: Context {
            access_key_id: "AKIDEXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_string(),
            token: None,
            region: "us-east-1".to_string(),
            service: "service".to_string(),
            timestamp: "2015-08-30T12:36:00Z".to_string(),
            sign_body: false,
            normalize: true,
            omit_session_token: false,
        },
        expected_canonical_request: String::new(),
        expected_string_to_sign: String::new(),
        expected_signature: String::new(),
    }
}

/// Cross-signer parity on the axes the official corpus CANNOT exercise.
///
/// `both_signers_agree_byte_for_byte_on_every_vector` is necessary but not
/// sufficient: every vendored case uses an uppercase method, a lowercase hex
/// payload hash, an absolute path, and supplies no `x-amz-*` header of its own. So
/// a green corpus says nothing about how the two signers treat those inputs, and
/// they genuinely disagreed on all four (br-rt4q4) — `fcp-provider-auth`
/// normalised the method and hash at construction while `fcp-sdk` used both
/// verbatim, and the two took opposite sides on caller-supplied `x-amz-*` headers.
///
/// A parity test whose inputs all come from a uniform corpus is exactly how those
/// survived a suite that looked comprehensive.
#[test]
fn both_signers_agree_on_inputs_the_corpus_cannot_express() {
    let host = [("host", "example.amazonaws.com")];
    let empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    let cases = vec![
        // Method casing.
        synthetic_vector("lowercase-method", "get", "/", &[], &host, empty_hash),
        synthetic_vector("padded-method", " POST ", "/", &[], &host, empty_hash),
        // Payload-hash casing, and the sentinel.
        synthetic_vector(
            "uppercase-payload-hash",
            "GET",
            "/",
            &[],
            &host,
            &empty_hash.to_uppercase(),
        ),
        synthetic_vector(
            "unsigned-payload-sentinel",
            "PUT",
            "/object.txt",
            &[],
            &host,
            "UNSIGNED-PAYLOAD",
        ),
        // A relative path. This one MUST run under the Preserve profile:
        // `remove_dot_segments` roots its output anyway, so under
        // RemoveDotSegments both signers agree no matter what either does about
        // rooting, and the case proves nothing. Another axis the negative control
        // caught as inert.
        {
            let mut v =
                synthetic_vector("relative-path", "GET", "bucket/key", &[], &host, empty_hash);
            v.context.normalize = false;
            v
        },
        // Caller-supplied signer-owned headers.
        synthetic_vector(
            "caller-supplied-amz-date",
            "GET",
            "/",
            &[],
            &[
                ("host", "example.amazonaws.com"),
                ("x-amz-date", "19990101T000000Z"),
            ],
            empty_hash,
        ),
        // A query key that only differs in order once encoded.
        synthetic_vector(
            "encoded-order-query",
            "GET",
            "/",
            &[("\u{1234}", "Value1"), ("Param", "Value2")],
            &host,
            empty_hash,
        ),
        // Mixed-case header names, which each crate lowercases differently.
        synthetic_vector(
            "mixed-case-header-names",
            "GET",
            "/",
            &[],
            &[("Host", "example.amazonaws.com"), ("X-Custom", "  a   b  ")],
            empty_hash,
        ),
    ];

    // Collected rather than asserted case by case: a normalisation regression
    // usually breaks a FAMILY of these axes at once, and seeing only the first is
    // how you fix one and re-run four times.
    let mut mismatches: Vec<String> = Vec::new();

    for v in &cases {
        let (sdk_canonical, sdk_sts, sdk_sig) = sign_with_sdk(v);
        let (pa_canonical, pa_sts, pa_sig) = sign_with_provider_auth(v).unwrap_or_else(|| {
            panic!(
                "{}: fcp-provider-auth refused to sign a synthetic parity case; if that \
                 refusal is intended, assert it explicitly rather than dropping the case",
                v.name
            )
        });

        if sdk_canonical.trim_end() != pa_canonical.trim_end() {
            mismatches.push(format!(
                "{}: canonical requests differ\n  fcp-sdk:           {:?}\n  fcp-provider-auth: {:?}",
                v.name,
                sdk_canonical.trim_end(),
                pa_canonical.trim_end()
            ));
        } else if sdk_sts.trim_end() != pa_sts.trim_end() || sdk_sig != pa_sig {
            mismatches.push(format!(
                "{}: canonical requests MATCH but a later stage does not \
                 (string_to_sign_eq={}, signature_eq={}) — that implicates hashing or \
                 key derivation, not canonicalisation",
                v.name,
                sdk_sts.trim_end() == pa_sts.trim_end(),
                sdk_sig == pa_sig
            ));
        }
    }

    assert!(
        mismatches.is_empty(),
        "the two SigV4 signers disagree on {} of {} inputs the official corpus cannot \
         express. The same request would then verify or not depending on which crate is \
         on the call path:\n\n{}",
        mismatches.len(),
        cases.len(),
        mismatches.join("\n\n")
    );
}

/// AWS's URI-path encoder: percent-encode every byte outside the unreserved
/// set, preserving `/` as the segment separator.
///
/// Harness-local on purpose. It exists to CHARACTERISE the remaining divergence,
/// never to construct an expectation a signer is then checked against, so it
/// must not be imported from the crate under test.
fn aws_uri_encode_path_once(path: &str) -> String {
    path.split('/')
        .map(|segment| {
            segment
                .bytes()
                .map(|b| match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                        (b as char).to_string()
                    }
                    other => format!("%{other:02X}"),
                })
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Characterises the three remaining divergences EXACTLY, so the ratchet records
/// a bounded, understood difference rather than an open question.
///
/// For each case the claim is: our canonical request differs from AWS's in the
/// canonical-URI line ONLY, and that line is precisely one additional
/// URI-encoding pass over AWS's. Both halves matter. The second half says the
/// difference is the input-convention boundary (see [`KNOWN_DIVERGENT`]); the
/// first says no OTHER defect is hiding inside these three cases, which is the
/// part a bare "known divergence" entry cannot tell you.
#[test]
fn remaining_divergences_are_exactly_one_extra_encoding_pass() {
    let raw_path_cases = ["get-space-normalized", "get-space-unnormalized", "get-utf8"];
    assert_eq!(
        raw_path_cases.len(),
        KNOWN_DIVERGENT.len(),
        "every known divergence must be characterised here, not just listed"
    );

    for v in load_vectors()
        .iter()
        .filter(|v| raw_path_cases.contains(&v.name.as_str()))
    {
        let (canonical, _, _) = sign_with_sdk(v);
        let ours: Vec<&str> = canonical.trim_end().split('\n').collect();
        let theirs: Vec<&str> = v
            .expected_canonical_request
            .trim_end()
            .split('\n')
            .collect();

        assert_eq!(
            ours.len(),
            theirs.len(),
            "{}: canonical request line count differs, so this is not a \
             canonical-URI-only difference",
            v.name
        );

        // Line 1 is the method; line 2 is the canonical URI.
        assert_eq!(
            ours[1],
            aws_uri_encode_path_once(theirs[1]),
            "{}: our canonical URI must be exactly one encoding pass over AWS's",
            v.name
        );

        for (i, (a, b)) in ours.iter().zip(theirs.iter()).enumerate() {
            if i == 1 {
                continue;
            }
            assert_eq!(
                a, b,
                "{}: line {i} of the canonical request differs too — the \
                 divergence is NOT confined to the canonical URI, so something \
                 else is wrong in this case",
                v.name
            );
        }
    }
}

/// Guards the thing the single-vector era could not: that the corpus actually
/// exercises paths where a canonical-URI bug is observable. 26 of the 38 cases
/// have paths needing no escaping and would pass under a broken encoder too.
#[test]
fn corpus_contains_paths_that_discriminate_canonical_uri_bugs() {
    let vectors = load_vectors();
    let discriminating = vectors
        .iter()
        .filter(|v| {
            v.request.path.contains(' ')
                || v.request.path.contains("..")
                || v.request.path.contains("//")
                || !v.request.path.is_ascii()
                || v.request.path.contains("/./")
        })
        .count();
    assert!(
        discriminating >= 8,
        "corpus lost its discriminating paths ({discriminating}); a canonical-URI \
         regression would go unnoticed again"
    );
}

/// Keeps `CanonicalPathEncoding` honest about which profile each service gets.
#[test]
fn s3_and_non_s3_select_different_canonical_path_encodings() {
    let s3 = SigningScope {
        region: "us-east-1".into(),
        service: "s3".into(),
    };
    let other = SigningScope {
        region: "us-east-1".into(),
        service: "service".into(),
    };
    assert_eq!(s3.canonical_path_encoding(), CanonicalPathEncoding::Single);
    assert_eq!(
        other.canonical_path_encoding(),
        CanonicalPathEncoding::Double
    );
}
