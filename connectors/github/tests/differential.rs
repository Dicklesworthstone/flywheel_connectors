//! Differential loopback-vs-live coverage for the GitHub connector.

use chrono::{Duration, Utc};
use fcp_crypto::cose::CapabilityTokenBuilder;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_github::connector::GitHubConnector;
use fcp_prelude::{CapabilityConstraints, CapabilityToken};
use fcp_testkit::{DifferentialHarness, DifferentialResult};
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

const LIVE_GATE_ENV: &str = "FCP_LIVE_READ";
const TEST_CREDENTIAL_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const OP_GET_REPO: &str = "github.get_repo";
const CAP_READ: &str = "github.read";
const OWNER: &str = "rust-lang";
const REPO: &str = "rust";

fn live_gate_enabled() -> bool {
    std::env::var(LIVE_GATE_ENV)
        .is_ok_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn generate_read_token(
    signing_key: &Ed25519SigningKey,
    connector: &GitHubConnector,
) -> CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec![format!("github://{OWNER}/{REPO}")],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(CAP_READ)
        .zone_id("z:work")
        .principal("user:differential-test")
        .operations(&[OP_GET_REPO])
        .issuer("node:differential-test")
        .token_id(b"github-differential")
        .target_instance(connector.instance_id().as_str())
        .validity(now, now + Duration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("test constraints CBOR should be valid")
        .sign(signing_key)
        .expect("capability token");
    CapabilityToken::from_raw(cose)
}

async fn setup_connector(base_url: &str) -> (GitHubConnector, Ed25519SigningKey) {
    let mut connector = GitHubConnector::new();
    connector
        .handle_configure(json!({
            "credential_id": TEST_CREDENTIAL_ID,
            "base_url": base_url,
        }))
        .await
        .expect("configure connector");

    let signing_key = Ed25519SigningKey::generate();
    let verifying_key = signing_key.verifying_key();
    connector
        .handle_handshake(json!({
            "protocol_version": "2.0.0",
            "zone": "z:work",
            "host_public_key": verifying_key.to_bytes(),
            "nonce": vec![0u8; 32],
            "capabilities_requested": [CAP_READ],
        }))
        .await
        .expect("handshake connector");

    (connector, signing_key)
}

async fn invoke_get_repo(connector: &GitHubConnector, signing_key: &Ed25519SigningKey) -> Value {
    let token = generate_read_token(signing_key, connector);
    connector
        .handle_invoke(json!({
            "operation": OP_GET_REPO,
            "input": {
                "owner": OWNER,
                "repo": REPO,
            },
            "capability_token": token,
        }))
        .await
        .expect("get_repo should succeed")
}

fn static_repo_payload(id: u64, updated_at: &str) -> Value {
    json!({
        "id": id,
        "name": REPO,
        "full_name": format!("{OWNER}/{REPO}"),
        "owner": {
            "login": OWNER,
            "id": id + 1,
            "avatar_url": "https://avatars.githubusercontent.com/u/5430905?v=4",
            "type": "Organization"
        },
        "description": "Empowering everyone to build reliable and efficient software.",
        "private": false,
        "fork": false,
        "html_url": format!("https://github.com/{OWNER}/{REPO}"),
        "default_branch": "main",
        "language": "Rust",
        "stargazers_count": 42,
        "forks_count": 10,
        "open_issues_count": 5,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": updated_at
    })
}

#[test]
fn github_get_repo_fixture_diff_smoke() {
    let loopback = json!({ "repository": static_repo_payload(1_296_269, "2026-05-13T18:42:31Z") });
    let live = json!({ "repository": static_repo_payload(9_999_999, "2026-05-13T19:00:00Z") });
    let loopback_bytes = serde_json::to_vec(&loopback).expect("serialize loopback fixture");
    let live_bytes = serde_json::to_vec(&live).expect("serialize live fixture");

    assert_eq!(
        DifferentialHarness::new().compare(&loopback_bytes, &live_bytes),
        DifferentialResult::Equivalent
    );
}

#[fcp_async_core::runtime::test]
async fn github_get_repo_loopback_vs_live() {
    if !live_gate_enabled() {
        eprintln!(
            "SKIP: {LIVE_GATE_ENV} is not enabled; set {LIVE_GATE_ENV}=1 to run GitHub differential live verification."
        );
        return;
    }

    let (live_connector, live_signing_key) = setup_connector("https://api.github.com").await;
    let live_response = invoke_get_repo(&live_connector, &live_signing_key).await;
    let live_repository = live_response
        .get("repository")
        .cloned()
        .expect("live response contains repository");

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/repos/{OWNER}/{REPO}")))
        .and(header("x-fcp-credential-id", TEST_CREDENTIAL_ID))
        .respond_with(ResponseTemplate::new(200).set_body_json(live_repository))
        .mount(&server)
        .await;

    let (loopback_connector, loopback_signing_key) = setup_connector(&server.uri()).await;
    let loopback_response = invoke_get_repo(&loopback_connector, &loopback_signing_key).await;
    let loopback_bytes = serde_json::to_vec(&loopback_response).expect("serialize loopback");
    let live_bytes = serde_json::to_vec(&live_response).expect("serialize live");

    match DifferentialHarness::new().compare(&loopback_bytes, &live_bytes) {
        DifferentialResult::Equivalent => {}
        other => panic!("github get_repo loopback vs live diverged: {other:?}"),
    }
}
