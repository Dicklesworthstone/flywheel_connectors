//! End-to-end verification of `LiveTruthResolver` internal error handling
//! (`_truth_source: "unavailable"`, `error.type: "truth-resolver-internal-error"`,
//! `fcp.truth_resolver.internal_error` log event, correlation ID, and redaction)
//! for `flywheel_connectors-hr0rr.2.5`.

use std::path::Path;
use std::process::{Command, Output};

use fwc::truth::{FORCE_RESOLVER_INTERNAL_ERROR_ENV, TRUTH_SOURCE_SCHEMA_VERSION};
use serde_json::Value;

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
}

fn run_fwc_forced_internal_error(args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fwc"));
    command
        .current_dir(repo_root())
        .env_remove("FWC_HOST")
        .env_remove("FCP_HOST_ENDPOINT")
        .env_remove("FCP_HOST_BIND")
        .env(FORCE_RESOLVER_INTERNAL_ERROR_ENV, "1")
        .args(args);
    command.output().expect("fwc process should launch")
}

fn stdout_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout should be JSON: {error}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn forced_resolver_internal_error_emits_unavailable_truth_source_across_read_commands() {
    let cases: &[(&[&str], &str, Option<&str>)] = &[
        (&["--json", "list", "--offline"], "list", None),
        (&["--json", "show", "github", "--offline"], "show", None),
        (&["--json", "search", "github", "--offline"], "search", None),
        (&["--json", "schema", "github", "--offline"], "schema", None),
        (&["--json", "status"], "status", None),
        (&["--json", "doctor", "--zone", "z:work"], "doctor", None),
        (
            &["--json", "context", "current"],
            "context",
            Some("current"),
        ),
        (&["--json", "history"], "history", None),
        (
            &["--json", "mesh", "explain-availability", "github"],
            "mesh",
            Some("explain-availability"),
        ),
        (
            &[
                "--json",
                "connector",
                "state",
                "explain",
                "--connector",
                "github",
                "--offline",
            ],
            "connector",
            Some("state explain"),
        ),
        (
            &[
                "--json",
                "connector",
                "lease",
                "status",
                "--connector",
                "github",
                "--offline",
            ],
            "connector",
            Some("lease status"),
        ),
        (
            &["--json", "audit", "chain", "status", "--zone", "z:work"],
            "audit",
            Some("chain status"),
        ),
    ];

    for &(args, expected_command, expected_subcommand) in cases {
        let output = run_fwc_forced_internal_error(args);
        assert!(
            !output.status.success(),
            "internal resolver failure must exit non-zero for {args:?}"
        );

        let payload = stdout_json(&output);
        assert_eq!(payload["status"], "error", "failed for {args:?}");
        assert_eq!(
            payload["command"], expected_command,
            "command mismatch for {args:?}"
        );
        if let Some(sub) = expected_subcommand {
            assert_eq!(
                payload["subcommand"].as_str(),
                Some(sub),
                "subcommand mismatch for {args:?}"
            );
        }
        assert_eq!(
            payload["schema_version"], TRUTH_SOURCE_SCHEMA_VERSION,
            "schema_version mismatch for {args:?}"
        );
        assert_eq!(
            payload["_truth_source"], "unavailable",
            "_truth_source must be `unavailable` (never `offline` or `unknown`) for {args:?}"
        );
        assert_eq!(
            payload["error"]["type"], "truth-resolver-internal-error",
            "error.type mismatch for {args:?}"
        );
        assert_eq!(
            payload["error"]["recoverable"], false,
            "error.recoverable must be false for {args:?}"
        );
        assert_eq!(
            payload["error"]["log_event"], "fcp.truth_resolver.internal_error",
            "error.log_event mismatch for {args:?}"
        );
        assert_eq!(
            payload["error"]["bead_reference"], "flywheel_connectors-hr0rr.2.5",
            "error.bead_reference mismatch for {args:?}"
        );
        let correlation_id = payload["error"]["correlation_id"]
            .as_str()
            .expect("correlation_id must be a string");
        assert!(
            uuid::Uuid::parse_str(correlation_id).is_ok(),
            "correlation_id must be a valid UUID, got: {correlation_id}"
        );
        let redacted_cause = payload["error"]["redacted_cause"]
            .as_str()
            .expect("redacted_cause must be a string");
        assert!(
            redacted_cause.contains("strategy failed before querying sources"),
            "unexpected redacted_cause: {redacted_cause}"
        );
        // Verify internal reason strings are not leaked in the operator payload.
        let raw_json = payload.to_string();
        assert!(
            !raw_json.contains("FWC_TEST_FORCE_RESOLVER_INTERNAL_ERROR"),
            "redacted payload must not leak internal reason details: {raw_json}"
        );
    }
}
