//! Release-blocker #59: production routing and native cancellation regressions.

use std::time::Duration;

use fcp_core::TailscaleNodeId;
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_host::mesh_routing::{MeshRouter, MeshRoutingSettings};
use serde_json::json;

/// Check the actual public future, including the production HTTP fetch closure.
/// A synthetic PeerDiscovery fetch alone does not check this composition.
#[test]
fn production_mesh_advertisement_future_is_send() {
    fn assert_send<T: Send>(_: T) {}

    let local_key = Ed25519SigningKey::generate();
    let peer_key = Ed25519SigningKey::generate();
    let router = MeshRouter::new(MeshRoutingSettings {
        node_id: TailscaleNodeId::new("issue-59-local"),
        signing_key: local_key,
        peers_json: json!([{
            "node_id": "issue-59-peer",
            "endpoint": "http://127.0.0.1:1",
            "public_key_hex": hex::encode(peer_key.verifying_key().to_bytes()),
        }])
        .to_string(),
        forward_timeout: Duration::from_secs(1),
    })
    .expect("valid mesh routing settings");

    // Construct but never poll: this compile-time contract needs no peer server.
    assert_send(router.peer_advertisements());
}
