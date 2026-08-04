use std::{fs, process::Command};

#[test]
fn external_callers_cannot_forge_supply_chain_success_results() {
    let registry_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let crate_dir = tempfile::tempdir().expect("create external compile test crate");
    let src_dir = crate_dir.path().join("src");
    fs::create_dir(&src_dir).expect("create external crate src dir");

    fs::write(
        crate_dir.path().join("Cargo.toml"),
        format!(
            // `[workspace]` opts this throwaway crate OUT of any enclosing
            // workspace. Without it, a tempdir that resolves under the project
            // tree (which is what happens on an rch worker, where the checkout
            // and the temp root share a filesystem root) makes cargo refuse
            // with "current package believes it's in a workspace when it's
            // not" — a DIFFERENT compile error than the private-field one this
            // test asserts on, so the test failed remotely while passing
            // locally (br-g2b1r).
            r#"[package]
name = "fcp-registry-forge-check"
version = "0.0.0"
edition = "2024"

[workspace]

[dependencies]
fcp-registry = {{ path = "{}" }}
"#,
            registry_root.display()
        ),
    )
    .expect("write external crate manifest");

    let private_result_source = r#"
use fcp_registry::{
    SigstoreVerificationResult, TransparencyVerificationResult, TufVerificationResult,
};

fn main() {
    let _tuf = TufVerificationResult {
        verified: true,
        root_version: 1,
        target: None,
    };
    let _sigstore = SigstoreVerificationResult {
        verified: true,
        identity: None,
        issuer: None,
        rekor_log_index: None,
    };
    let _transparency = TransparencyVerificationResult {
        verified: true,
        log_index: Some(1),
        logged_at: Some(2),
    };
}
"#;
    let stderr = rejected_external_source(
        &registry_root,
        crate_dir.path(),
        &src_dir,
        private_result_source,
    );
    assert!(
        stderr.contains("TufVerificationResult") && stderr.contains("private"),
        "expected private-field error for TUF result, got:\n{stderr}"
    );
    assert!(
        stderr.contains("SigstoreVerificationResult") && stderr.contains("private"),
        "expected private-field error for Sigstore result, got:\n{stderr}"
    );
    assert!(
        stderr.contains("TransparencyVerificationResult") && stderr.contains("private"),
        "expected private-field error for transparency result, got:\n{stderr}"
    );

    let removed_setter_source = r#"
use fcp_registry::SupplyChainEvidence;

fn main() {
    let _setter = SupplyChainEvidence::new().with_transparency_log_present(true);
}
"#;
    let stderr = rejected_external_source(
        &registry_root,
        crate_dir.path(),
        &src_dir,
        removed_setter_source,
    );
    assert!(
        stderr.contains("with_transparency_log_present"),
        "expected removed transparency setter to fail, got:\n{stderr}"
    );
}

fn rejected_external_source(
    registry_root: &std::path::Path,
    crate_dir: &std::path::Path,
    src_dir: &std::path::Path,
    source: &str,
) -> String {
    fs::write(src_dir.join("main.rs"), source).expect("write external crate source");

    let target_dir = crate_dir.join("target");
    let output = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .arg("check")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(crate_dir.join("Cargo.toml"))
        .env("CARGO_TARGET_DIR", &target_dir)
        .current_dir(registry_root)
        .output()
        .expect("run external cargo check");

    assert!(
        !output.status.success(),
        "forged external supply-chain evidence unexpectedly compiled\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stderr).into_owned()
}
