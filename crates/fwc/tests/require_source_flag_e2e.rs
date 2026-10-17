//! End-to-end verification of `--require-source {mesh,mesh-or-host,any-live}`
//! across all 4 `KnowledgeState` truth sources (`MeshBacked`, `HostBacked`,
//! `NodeLocal`, `Offline`) and CLI commands for `flywheel_connectors-hr0rr.2.5`.

use std::path::Path;
use std::process::{Command, Output};

use fwc::truth::{KnowledgeState, RequiredTruthSource, TRUTH_SOURCE_SCHEMA_VERSION};
use serde_json::Value;

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
}

fn run_fwc(args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fwc"));
    command
        .current_dir(repo_root())
        .env_remove("FWC_HOST")
        .env_remove("FCP_HOST_ENDPOINT")
        .env_remove("FCP_HOST_BIND")
        .env_remove("FWC_TEST_FORCE_RESOLVER_INTERNAL_ERROR")
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
fn require_source_3x4_knowledge_state_acceptance_matrix() {
    // 3 RequiredTruthSource levels x 4 primary KnowledgeState tiers = 12 cases.
    let matrix: &[(RequiredTruthSource, KnowledgeState, bool)] = &[
        // --require-source mesh: only MeshBacked is accepted
        (RequiredTruthSource::Mesh, KnowledgeState::MeshBacked, true),
        (RequiredTruthSource::Mesh, KnowledgeState::HostBacked, false),
        (RequiredTruthSource::Mesh, KnowledgeState::NodeLocal, false),
        (RequiredTruthSource::Mesh, KnowledgeState::Offline, false),
        // --require-source mesh-or-host: MeshBacked and HostBacked are accepted
        (
            RequiredTruthSource::MeshOrHost,
            KnowledgeState::MeshBacked,
            true,
        ),
        (
            RequiredTruthSource::MeshOrHost,
            KnowledgeState::HostBacked,
            true,
        ),
        (
            RequiredTruthSource::MeshOrHost,
            KnowledgeState::NodeLocal,
            false,
        ),
        (
            RequiredTruthSource::MeshOrHost,
            KnowledgeState::Offline,
            false,
        ),
        // --require-source any-live: MeshBacked and HostBacked are accepted
        (
            RequiredTruthSource::AnyLive,
            KnowledgeState::MeshBacked,
            true,
        ),
        (
            RequiredTruthSource::AnyLive,
            KnowledgeState::HostBacked,
            true,
        ),
        (
            RequiredTruthSource::AnyLive,
            KnowledgeState::NodeLocal,
            false,
        ),
        (RequiredTruthSource::AnyLive, KnowledgeState::Offline, false),
    ];

    assert_eq!(matrix.len(), 12);

    for &(required, actual, expected_accepts) in matrix {
        assert_eq!(
            required.accepts(actual),
            expected_accepts,
            "mismatch for required={required}, actual={actual}"
        );
        let validation = required.validate(actual);
        if expected_accepts {
            assert!(
                validation.is_ok(),
                "expected validate Ok for required={required}, actual={actual}"
            );
        } else {
            let err = validation.expect_err("expected TruthSourceUnavailable");
            assert_eq!(err.required, required);
            assert_eq!(err.actual, actual);
        }
    }
}

#[test]
fn cli_require_source_refuses_weaker_truth_sources_with_structured_error() {
    let cli_refusal_cases: &[(&[&str], &str, &str)] = &[
        (
            &[
                "--json",
                "list",
                "--offline",
                "--require-source",
                "any-live",
            ],
            "any-live",
            "offline",
        ),
        (
            &[
                "--json",
                "show",
                "github",
                "--offline",
                "--require-source",
                "mesh-or-host",
            ],
            "mesh-or-host",
            "offline",
        ),
        (
            &[
                "--json",
                "search",
                "github",
                "--offline",
                "--require-source",
                "mesh",
            ],
            "mesh",
            "offline",
        ),
        (
            &[
                "--json",
                "schema",
                "github",
                "--offline",
                "--require-source",
                "any-live",
            ],
            "any-live",
            "offline",
        ),
        (
            &[
                "--json",
                "context",
                "current",
                "--require-source",
                "any-live",
            ],
            "any-live",
            "node-local",
        ),
        (
            &[
                "--json",
                "context",
                "current",
                "--require-source",
                "mesh-or-host",
            ],
            "mesh-or-host",
            "node-local",
        ),
        (
            &["--json", "context", "current", "--require-source", "mesh"],
            "mesh",
            "node-local",
        ),
        (
            &["--json", "history", "--require-source", "any-live"],
            "any-live",
            "offline",
        ),
        (
            &[
                "--json",
                "mesh",
                "explain-availability",
                "github",
                "--require-source",
                "any-live",
            ],
            "any-live",
            "offline",
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
                "--require-source",
                "mesh-or-host",
            ],
            "mesh-or-host",
            "offline",
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
                "--require-source",
                "mesh",
            ],
            "mesh",
            "offline",
        ),
        (
            &["--json", "status", "--require-source", "any-live"],
            "any-live",
            "offline",
        ),
        (
            &[
                "--json",
                "doctor",
                "--zone",
                "z:work",
                "--require-source",
                "mesh-or-host",
            ],
            "mesh-or-host",
            "offline",
        ),
    ];

    for &(args, expected_required, expected_actual) in cli_refusal_cases {
        let output = run_fwc(args);
        assert!(
            !output.status.success(),
            "expected non-zero exit code for {args:?}"
        );
        let payload = stdout_json(&output);
        assert_eq!(payload["status"], "error", "failed for {args:?}");
        assert_eq!(
            payload["schema_version"], TRUTH_SOURCE_SCHEMA_VERSION,
            "failed for {args:?}"
        );
        assert_eq!(
            payload["_truth_source"], expected_actual,
            "failed for {args:?}"
        );
        assert_eq!(
            payload["error"]["type"], "truth-source-unavailable",
            "failed for {args:?}"
        );
        assert_eq!(
            payload["error"]["required"], expected_required,
            "failed for {args:?}"
        );
        assert_eq!(
            payload["error"]["actual"], expected_actual,
            "failed for {args:?}"
        );
    }
}
