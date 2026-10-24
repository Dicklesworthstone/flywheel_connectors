//! Workspace-level regression: capability-token typestate at connector
//! invoke boundaries (br-dja9u, [REALITY][P1]).
//!
//! The capability-token typestate ladder
//! (`Unverified → UnboundVerified → BoundVerified → ConstraintsEnforced`)
//! is documented as **mechanical enforcement** at the gateway →
//! connector handoff: gateway emits `UnboundVerified` via
//! `CapabilityVerifier::without_instance_binding().verify_unbound(...)`,
//! and the connector runtime promotes to `BoundVerified` /
//! `ConstraintsEnforced` via
//! `verify_bound` / `promote_with_instance` / `promote_with_constraints`
//! before executing.
//!
//! Live tree adoption (per the dja9u bead's evidence scan):
//!
#![allow(clippy::manual_let_else)]
//!
//! - 79 connectors `USE_TYPESTATE` (`verify_bound` / `promote_with`_* /
//!   shared `StandaloneSession` bounded admission).
//! - 0 connectors `USE_LEGACY_VERIFY` (deprecated `verifier.verify(...)`
//!   alias — the `#[deprecated]` `CapabilityVerifier::verify` entrypoint with
//!   an ambiguous return type, which discards the structural-verification
//!   typestate so the connector can no longer prove to downstream code that
//!   the token was bound-verified).
//! - The remaining files in `connectors/*/src/connector.rs` either
//!   delegate verification to a shared helper or are scaffolds that
//!   do not yet wire a verifier at all.
//!
//! This test is a **forward-only ratchet**:
//!
//! 1. It enumerates every file under `connectors/*/src/connector.rs`
//!    in the live tree.
//! 2. It classifies each as `USES_TYPESTATE` / `USES_LEGACY_VERIFY` /
//!    `NO_VERIFIER` based on substring scan of the source.
//! 3. It asserts the legacy-`.verify(...)` set is a subset of the
//!    pinned `LEGACY_VERIFY` allowlist below — adding a new
//!    `.verify(...)` call site fails the test, removing one always
//!    passes.
//! 4. It asserts the typestate-using set is a superset of the pinned
//!    `TYPESTATE_ENFORCED` allowlist — removing typestate enforcement
//!    from a connector that already had it fails the test.
//!
//! When a future bead migrates a connector from `LEGACY_VERIFY` to
//! `USES_TYPESTATE`, the migration shrinks `LEGACY_VERIFY_ALLOWLIST`
//! and grows `TYPESTATE_ENFORCED_ALLOWLIST`. The ratchet means the
//! typestate adoption number can only ever increase from this
//! commit forward.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Marker substrings that indicate a connector is using the typestate
/// ladder correctly (any one of them is sufficient evidence).
const TYPESTATE_MARKERS: &[&str] = &[
    "verify_bound(",
    "promote_with_instance(",
    "promote_with_constraints(",
];

/// Marker for the deprecated `verifier.verify(...)` alias — the
/// `#[deprecated]` `CapabilityVerifier::verify` method ("ambiguous return
/// type; use `verify_bound` (full enforcement) or `verify_unbound` (gateway
/// vantage)"). We look for the exact substring `verifier.verify(` rather than
/// `.verify(` alone so we don't false-flag e.g. `signing_key.verify(...)` or a
/// webhook `verifier.verify(headers, payload, ...)` signature check (neither is
/// a capability gate).
///
/// This MUST stay disjoint from `TYPESTATE_MARKERS`: `verify_bound` is the
/// GOOD typestate method, so the legacy marker keys off the bare `verify(`
/// method name, which is not a substring of `verify_bound(`. `classify`
/// additionally checks the typestate markers first, so a connector that uses
/// both a capability `verify_bound` and an unrelated webhook `verify(` is
/// correctly classified as typestate-enforcing.
const LEGACY_VERIFY_MARKER: &str = "verifier.verify(";

/// Connectors known to currently use the legacy `.verify(...)` alias
/// at the invoke/simulate boundary as of this commit. Any addition
/// fails this test (regression: new connector takes a worse path);
/// any removal silently passes (forward-only migration).
///
/// Captured by:
/// `grep -lE "verifier\\.verify\\(" connectors/*/src/connector.rs`
/// at the time the dja9u commit landed.
const LEGACY_VERIFY_ALLOWLIST: &[&str] = &[];

/// Connectors known to currently use the typestate ladder correctly
/// (`verify_bound` / `promote_with_instance` / `promote_with_constraints`).
/// Removing any of these fails this test (regression: connector
/// dropped its typestate enforcement). Adding a new one always
/// passes.
///
/// Captured by:
/// `grep -lE "verify_bound|promote_with_instance|promote_with_constraints" \
///         connectors/*/src/connector.rs`
/// at the time the dja9u commit landed.
const TYPESTATE_ENFORCED_ALLOWLIST: &[&str] = &[
    "airtable",
    "anthropic",
    "apple-notes",
    "apple-reminders",
    "aws",
    "azure",
    "bitbucket",
    "browser",
    "calendly",
    "circleci",
    "cloudflare",
    "coda",
    "confluence",
    "dingtalk",
    "discord",
    "dockerhub",
    "email-generic",
    "feishu",
    "figma",
    "gcp",
    "github",
    "gitlab",
    "gmail",
    "google-admin-reports",
    "google-ai",
    "google-calendar",
    "google-docs",
    "google-drive",
    "google-people",
    "google-places",
    "google-sheets",
    "hackernews",
    "hue",
    "imessage",
    "irc",
    "jira",
    "line",
    "linear",
    "llm-router",
    "mastodon",
    "matrix",
    "mattermost",
    "microsoft365",
    "netlify",
    "nextcloud-talk",
    "nostr",
    "notion",
    "obsidian",
    "openai",
    "outlook",
    "package-registry",
    "paypal",
    "perplexity-search",
    "pinecone",
    "plaid",
    "qdrant",
    "qq",
    "s3",
    "shopify",
    "signal",
    "slack",
    "sonos",
    "square",
    "stripe",
    "supabase",
    "synology-chat",
    "teams",
    "telegram",
    "twilio",
    "twitch",
    "twitter",
    "vercel",
    "wecom",
    "webhook-receiver",
    "whatsapp",
    "wolfram",
    "youtube",
    "zendesk",
    "zoom",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundaryStyle {
    UsesTypestate,
    UsesLegacyVerify,
    NoVerifier,
}

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at crates/fcp-conformance; pop two
    // levels to reach the workspace root.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .expect("crates/ parent")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn connector_name_from_path(path: &Path) -> String {
    // .../connectors/<name>/src/connector.rs
    path.parent()
        .and_then(Path::parent)
        .and_then(Path::file_name)
        .map(|n| n.to_string_lossy().to_string())
        .expect("connector path has the expected shape")
}

fn collect_connector_files(root: &Path) -> Vec<PathBuf> {
    let connectors_dir = root.join("connectors");
    let mut files = Vec::new();
    let read_dir = match fs::read_dir(&connectors_dir) {
        Ok(rd) => rd,
        Err(_) => return files,
    };
    for entry in read_dir.flatten() {
        let connector_rs = entry.path().join("src").join("connector.rs");
        if connector_rs.is_file() {
            files.push(connector_rs);
        }
    }
    files.sort();
    files
}

fn classify(source: &str) -> BoundaryStyle {
    // StandaloneSession::admit_bounded returns a non-forgeable admission
    // witness after verify_bound and signed usage accounting. A construction
    // alone does not count: the connector must also admit at dispatch.
    let uses_session_authority =
        source.contains("StandaloneSession::new(") && source.contains("authority.admit_bounded(");
    let uses_typestate =
        uses_session_authority || TYPESTATE_MARKERS.iter().any(|m| source.contains(m));
    let uses_legacy = source.contains(LEGACY_VERIFY_MARKER);
    if uses_typestate {
        BoundaryStyle::UsesTypestate
    } else if uses_legacy {
        BoundaryStyle::UsesLegacyVerify
    } else {
        BoundaryStyle::NoVerifier
    }
}

#[test]
fn standalone_session_requires_construction_and_admission_for_ratchet() {
    assert_eq!(
        classify("StandaloneSession::new(MANIFEST)"),
        BoundaryStyle::NoVerifier
    );
    assert_eq!(
        classify("authority.admit_bounded(&request, &[], LIMIT)"),
        BoundaryStyle::NoVerifier
    );
    assert_eq!(
        classify("StandaloneSession::new(MANIFEST); authority.admit_bounded(&request, &[], LIMIT)"),
        BoundaryStyle::UsesTypestate
    );
}

#[test]
fn dja9u_no_new_connectors_use_legacy_verify_alias_at_invoke_boundary() {
    let root = workspace_root();
    let files = collect_connector_files(&root);
    assert!(
        !files.is_empty(),
        "expected to find connector source files under {}/connectors",
        root.display()
    );

    let allowlist: BTreeSet<&str> = LEGACY_VERIFY_ALLOWLIST.iter().copied().collect();
    let mut violations: Vec<(String, BoundaryStyle)> = Vec::new();
    for path in &files {
        let source = fs::read_to_string(path).expect("read connector source");
        if classify(&source) != BoundaryStyle::UsesLegacyVerify {
            continue;
        }
        let name = connector_name_from_path(path);
        if !allowlist.contains(name.as_str()) {
            violations.push((name, BoundaryStyle::UsesLegacyVerify));
        }
    }
    assert!(
        violations.is_empty(),
        "br-dja9u regression: new connectors must use verify_bound (or \
         promote_with_instance / promote_with_constraints), not the \
         deprecated `verifier.verify_bound(...)` alias. New violators: {:#?}. \
         If migrating a connector ON TO the typestate path, also remove it \
         from LEGACY_VERIFY_ALLOWLIST in {}",
        violations,
        file!()
    );
}

#[test]
fn dja9u_no_typestate_regressions_in_already_enforced_connectors() {
    let root = workspace_root();
    let files = collect_connector_files(&root);

    let want_typestate: BTreeSet<&str> = TYPESTATE_ENFORCED_ALLOWLIST.iter().copied().collect();
    let mut have_typestate: BTreeSet<String> = BTreeSet::new();
    for path in &files {
        let source = fs::read_to_string(path).expect("read connector source");
        if classify(&source) == BoundaryStyle::UsesTypestate {
            have_typestate.insert(connector_name_from_path(path));
        }
    }
    let mut regressed: Vec<String> = Vec::new();
    for name in &want_typestate {
        if !have_typestate.contains(*name) {
            regressed.push((*name).to_owned());
        }
    }
    assert!(
        regressed.is_empty(),
        "br-dja9u regression: connectors that previously enforced the \
         capability-token typestate (verify_bound / promote_with_*) no \
         longer do. Regressed: {regressed:#?}. If a connector was deleted \
         on purpose, also drop it from TYPESTATE_ENFORCED_ALLOWLIST in {}",
        file!()
    );
}

#[test]
fn dja9u_allowlists_match_pinned_baseline_counts() {
    // Sanity: keep the allowlist sizes obvious in the source so reviewers
    // can spot drift. If you migrate a connector from LEGACY_VERIFY ->
    // USES_TYPESTATE, decrement the legacy size and increment the
    // typestate size in this assertion.
    assert_eq!(
        LEGACY_VERIFY_ALLOWLIST.len(),
        0,
        "LEGACY_VERIFY_ALLOWLIST size drifted; update this assertion to \
         match"
    );
    assert_eq!(
        TYPESTATE_ENFORCED_ALLOWLIST.len(),
        79,
        "TYPESTATE_ENFORCED_ALLOWLIST size drifted; update this assertion \
         to match"
    );
    let legacy_set: BTreeSet<&str> = LEGACY_VERIFY_ALLOWLIST.iter().copied().collect();
    let typestate_set: BTreeSet<&str> = TYPESTATE_ENFORCED_ALLOWLIST.iter().copied().collect();
    let intersect: Vec<_> = legacy_set.intersection(&typestate_set).copied().collect();
    assert!(
        intersect.is_empty(),
        "br-dja9u: a connector cannot appear in both allowlists \
         simultaneously (a typestate-using connector by definition does \
         not need the legacy alias). Intersection: {intersect:?}"
    );
}

#[test]
fn dja9u_classification_function_is_self_consistent() {
    // Pin the classifier behaviour against fixed example sources so a
    // future refactor of TYPESTATE_MARKERS / LEGACY_VERIFY_MARKER cannot
    // silently invert the categorisation.
    let typestate_src = "let bound = verifier.verify_bound(token, &cap, &op, &uris)?;";
    assert_eq!(classify(typestate_src), BoundaryStyle::UsesTypestate);

    let legacy_src = "verifier.verify(token, &cap, &op, &[])?;";
    assert_eq!(classify(legacy_src), BoundaryStyle::UsesLegacyVerify);

    // Ed25519 / signature `.verify(...)` calls MUST NOT trip the legacy
    // marker — that's the whole reason the marker requires the
    // `verifier.` prefix.
    let unrelated = "signing_key.verify(message, &signature)?;";
    assert_eq!(classify(unrelated), BoundaryStyle::NoVerifier);

    let promote_with_instance_src =
        "let bound = unbound.promote_with_instance(&InstanceId::new())?;";
    assert_eq!(
        classify(promote_with_instance_src),
        BoundaryStyle::UsesTypestate
    );

    let promote_with_constraints_src =
        "let enforced = bound.promote_with_constraints(&enforcer, &request)?;";
    assert_eq!(
        classify(promote_with_constraints_src),
        BoundaryStyle::UsesTypestate
    );
}
