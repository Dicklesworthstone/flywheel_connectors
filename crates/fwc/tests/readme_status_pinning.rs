//! README status table ↔ production-path drift defence (br-lvz4t).
//!
//! `VioletPine`'s audit (br-lvz4t) found that README.md labelled
//! "Mesh-Native Architecture" as `IMPLEMENTED` even though every
//! production invoke still flows through the host-first
//! `fwc → fcp-host → connector subprocess` path. The README's own
//! Operational Model Versions section (V2 Mesh-Native = "Target, NOT
//! YET OPERATIONAL, zero production evidence") contradicted the feature
//! table.
//!
//! This file is the machine-checkable counterpart to the README fix.
//! It pins three invariants:
//!
//! 1. The Mesh-Native row in the feature table does NOT claim
//!    `IMPLEMENTED` (it must say `STEADY-STATE TARGET` /
//!    `NOT YET OPERATIONAL`).
//! 2. The V2 row in the Operational Model Versions table still says
//!    `NOT YET OPERATIONAL`.
//! 3. The production `fwc` invoke route still posts to `/rpc/invoke`
//!    on the host (i.e. has not been silently rewired to a mesh route
//!    without a corresponding README update).
//!
//! If any of these three drift, the README's claim and the production
//! path are out of sync and this test fails loudly. The intended fix
//! is to update both together.

const README: &str = include_str!("../../../README.md");
const FCP3_TRANSITION_SCORECARD: &str = include_str!("../../../docs/FCP3_Transition_Scorecard.md");
const FWC_MAIN: &str = include_str!("../src/main.rs");
const FWC_TRUTH: &str = include_str!("../src/truth.rs");
const FWC_COMMAND_SCHEMAS: &str =
    include_str!("../../fcp-conformance/tests/fwc_command_schemas.rs");
const SECRET_FETCH: &str = include_str!("../../fcp-crypto/src/secret_fetch.rs");
const SECRETLESS_CONNECTOR_E2E: &str =
    include_str!("../../fcp-e2e/tests/secretless_connector_e2e.rs");
const SECRETLESS_GITHUB_E2E: &str = include_str!("../../fcp-e2e/tests/secretless_github_e2e.rs");
const SECRETLESS_SLACK_E2E: &str = include_str!("../../fcp-e2e/tests/secretless_slack_e2e.rs");
const SECRETLESS_GMAIL_E2E: &str = include_str!("../../fcp-e2e/tests/secretless_gmail_e2e.rs");

fn feature_table_row_for(feature_name: &str) -> Option<&'static str> {
    // Locate the line in the feature table whose first non-pipe cell
    // contains `feature_name`. The feature table uses pipe-delimited
    // markdown rows starting with `| **<name>** |`.
    let needle = format!("| **{feature_name}** |");
    README.lines().find(|line| line.starts_with(&needle))
}

#[test]
fn readme_mesh_native_row_is_not_marked_implemented() {
    // br-lvz4t Invariant 1: the Mesh-Native Architecture row MUST NOT
    // be labelled IMPLEMENTED while the production path is host-first.
    // Match the literal status cell `| \`IMPLEMENTED\` |` so a row
    // whose description happens to mention the word "implemented" in
    // prose still passes.
    let row = feature_table_row_for("Mesh-Native Architecture").expect(
        "feature table row for Mesh-Native Architecture must exist; if you renamed the row, \
         update this test so the README/production drift defence keeps working",
    );
    assert!(
        !row.contains("| `IMPLEMENTED` |"),
        "br-lvz4t: Mesh-Native Architecture row claims `IMPLEMENTED` but the production \
         invoke path is still host-first (HostClient::invoke posts to /rpc/invoke on \
         fcp-host, not to a mesh route). Either downgrade the status cell to \
         `STEADY-STATE TARGET (NOT YET OPERATIONAL)` (or similar) or wire a real mesh-backed \
         invoke path and add an end-to-end fixture proving normal operator invokes flow \
         through it. Row was: {row}"
    );
    assert!(
        row.contains("STEADY-STATE TARGET") || row.contains("NOT YET OPERATIONAL"),
        "br-lvz4t: Mesh-Native row must explicitly say `STEADY-STATE TARGET` or \
         `NOT YET OPERATIONAL` so the casual reader does not mistake the building blocks \
         (gossip, IBLT, etc.) for operational cutover. Row was: {row}"
    );
}

#[test]
fn readme_operational_model_v2_row_says_not_yet_operational() {
    // br-lvz4t Invariant 2: the operational-model-versions table's V2
    // row must keep its honest status. This is the table at
    // README.md "## Operational Model Versions" — V2 row begins with
    // `| **V2** |`.
    let row = README
        .lines()
        .find(|line| line.starts_with("| **V2** |"))
        .expect("Operational Model Versions table must contain a V2 row");
    assert!(
        row.contains("NOT YET OPERATIONAL"),
        "br-lvz4t: V2 (Mesh-Native) row in the Operational Model Versions table must say \
         `NOT YET OPERATIONAL` until a production mesh-backed invoke path lands. Row: {row}"
    );
    assert!(
        row.to_lowercase().contains("zero production evidence")
            || row.to_lowercase().contains("no production"),
        "br-lvz4t: V2 row should also explicitly say `Zero production evidence` so the \
         status cell's NOT YET OPERATIONAL claim is grounded. Row: {row}"
    );
}

#[test]
fn readme_audit_status_paragraph_still_present() {
    // br-lvz4t: defence against the "drop the audit-status note"
    // failure mode — without this paragraph, the table is just
    // marketing. The reconciliation date should be visible.
    assert!(
        README.contains("**Audit status**:"),
        "br-lvz4t: README feature table must keep the **Audit status** paragraph that \
         records the last reconciliation date and links to the claims-vs-reality audit doc"
    );
    assert!(
        README.contains("br-lvz4t"),
        "br-lvz4t: audit-status paragraph should reference br-lvz4t so the rationale for \
         the Mesh-Native downgrade is discoverable"
    );
}

#[test]
fn readme_secretless_connectors_row_is_pinned_to_proven() {
    let row = feature_table_row_for("Secretless Connectors")
        .expect("feature table row for Secretless Connectors must exist");
    assert!(
        row.contains("| `PROVEN` |"),
        "flywheel_connectors-e99o6.1.6: Secretless Connectors row must stay `PROVEN` \
         while the evidence files remain present. Row: {row}"
    );
    for required_text in [
        "SecretFetchHook",
        "credential_id",
        "GitHub",
        "Slack",
        "Gmail",
        "does not claim every connector has migrated",
    ] {
        assert!(
            row.contains(required_text),
            "flywheel_connectors-e99o6.1.6: Secretless row must keep precision phrase \
             `{required_text}` so PROVEN covers the pattern, not every connector. Row: {row}"
        );
    }
}

#[test]
fn readme_secretless_proven_status_has_evidence_files() {
    assert!(
        SECRET_FETCH.contains("pub trait SecretFetchHook"),
        "Secretless PROVEN requires the production SecretFetchHook trait"
    );
    assert!(
        SECRETLESS_CONNECTOR_E2E.contains("SecretFetchHook"),
        "Secretless PROVEN requires the production trait migration/redaction E2E"
    );
    for (name, contents) in [
        ("github", SECRETLESS_GITHUB_E2E),
        ("slack", SECRETLESS_SLACK_E2E),
        ("gmail", SECRETLESS_GMAIL_E2E),
    ] {
        assert!(
            contents.contains("RedactedReplayBundle")
                && contents.contains("cross_connector_bleed")
                && contents.contains("wire_and_rotation")
                && contents.contains("tracing_and_audit"),
            "Secretless PROVEN requires {name} connector-family redaction gauntlet evidence"
        );
    }
}

#[test]
fn readme_mesh_native_status_is_backed_by_cutover_gate_contract() {
    let row = feature_table_row_for("Mesh-Native Architecture")
        .expect("feature table row for Mesh-Native Architecture must exist");
    assert!(
        row.contains("STEADY-STATE TARGET") && row.contains("NOT YET OPERATIONAL"),
        "Mesh-Native Architecture must remain a target while any cutover gate is not green. Row: {row}"
    );
    for gate_id in [
        "mesh-inventory-placement",
        "mesh-lifecycle-state-replication",
        "mesh-audit-chain-quorum",
        "mesh-policy-object-distribution",
    ] {
        assert!(
            FCP3_TRANSITION_SCORECARD.contains(gate_id),
            "FCP3 transition scorecard must document cutover gate `{gate_id}` before the README mesh-native status can change"
        );
    }
    assert!(
        FWC_MAIN.contains("CutoverGates(MeshCutoverGatesArgs)"),
        "`fwc mesh cutover-gates --json` must stay wired while the README references cutover gating"
    );
}

#[test]
fn fwc_production_invoke_still_routes_through_host_rpc_invoke() {
    // br-lvz4t Invariant 3: the production invoke entry point in
    // fwc/src/main.rs's HostClient::invoke MUST still post to
    // /rpc/invoke on the host. If anyone rewires this to a mesh
    // endpoint without coordinating with the README status table,
    // this test fires.
    //
    // Match the literal call pattern fwc currently uses:
    //   fn invoke(&self, request: &InvokeRequest) -> Result<InvokeResponse> {
    //       self.post_json("/rpc/invoke", request)
    //   }
    //
    // Reduced to the substring that uniquely identifies the route.
    assert!(
        FWC_MAIN.contains(r#"self.post_json("/rpc/invoke", request)"#),
        "br-lvz4t: HostClient::invoke in crates/fwc/src/main.rs no longer posts to \
         /rpc/invoke. If you have wired a real mesh-native invoke route, update the \
         Mesh-Native Architecture row in README.md (and remove the `STEADY-STATE TARGET` / \
         `NOT YET OPERATIONAL` qualifier) so the status table reflects the new reality."
    );
}

#[test]
fn fwc_invoke_fn_signature_is_unchanged() {
    // Defensive: the test above is text-grep based, so a casual rename
    // of the route string would silently mask the drift. Pin the
    // function signature too — both must change together.
    assert!(
        FWC_MAIN.contains("fn invoke(&self, request: &InvokeRequest) -> Result<InvokeResponse>"),
        "br-lvz4t: HostClient::invoke signature has changed. If this is intentional \
         (e.g. mesh-native cutover), update both the README status row and this test in \
         the same PR so the README ↔ production-path drift defence stays meaningful."
    );
}

/// A.5 (`flywheel_connectors-hr0rr.2.5`) coordinated update path: when the
/// A-series cutover beads are closed AND the four scorecard gates report
/// green, graduating the README Mesh-Native label must be a single-file,
/// test-visible act — this test file is that file. The assertions below pin
/// the A.5 operator-surface wiring that makes a one-file graduation honest:
/// every read-only answer is truth-classified, the resolver gate decides
/// when mesh-backed answers may be served, and simulate is explicitly
/// non-authoritative. If any of these disappear, graduating the label would
/// require new code, and this test must keep failing until that code exists.
#[test]
fn readme_mesh_native_graduation_requires_only_this_file() {
    // 1. Read-only commands route through LiveTruthResolver so every operator
    //    answer carries a resolver decision trace, not a post-hoc stamp.
    assert!(
        FWC_MAIN.contains("resolve_with_partials"),
        "A.5 graduation path: read-only fwc commands must route through \
         LiveTruthResolver::resolve_with_partials before the Mesh-Native label can move"
    );
    // 2. The mesh-backed rung is gated on healthy mesh peers (A.6) so the
    //    label cannot graduate while no mesh is provisioned.
    assert!(
        FWC_TRUTH.contains("mesh_backed_enabled")
            && FWC_TRUTH.contains("MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE"),
        "A.5 graduation path: the resolver's mesh_backed gate (default off until \
         MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE is met) must stay wired"
    );
    // 3. The conformance suite pins `_truth_source` on every read-only command
    //    envelope, so the graduated label's evidence surface is machine-checked.
    assert!(
        FWC_COMMAND_SCHEMAS.contains("_truth_source") && FWC_COMMAND_SCHEMAS.contains("simulated"),
        "A.5 graduation path: the command-schema conformance suite must keep pinning \
         _truth_source (including the non-authoritative `simulated` marker) for every \
         read-only command"
    );
    // 4. simulate is marked non-authoritative end-to-end.
    assert!(
        FWC_MAIN.contains("inject_simulated_truth_source_metadata"),
        "A.5 graduation path: `fwc simulate` must keep stamping `_truth_source: \"simulated\"` \
         so non-authoritative answers are never mistaken for runtime truth"
    );
}
