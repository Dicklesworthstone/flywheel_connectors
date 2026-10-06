//! Multi-process proof of the mesh-backed invoke path (bridge plan A.2).
//!
//! Every test runs real `fcp-host` processes that know each other through a
//! signed peer directory. An operator invoke sent to a node that does not run
//! the connector is relayed over a signed `/rpc/mesh/forward` envelope to the
//! advertising peer, executed there by the real `fcp-test-connector`
//! subprocess, and returned with `response_metadata.route` naming the
//! executor (`mesh-backed`). The executor re-runs every capability, zone, and
//! policy gate, rejects forged and replayed envelopes, and a forward that
//! cannot be delivered moves to the next HRW-ranked advertiser.

mod lease_e2e_support;

use std::net::SocketAddr;
use std::path::PathBuf;

use fcp_core::{TailscaleNodeId, ZoneId};
use fcp_crypto::ed25519::Ed25519SigningKey;
use fcp_kernel::{ConnectorId, InvokeResponse, InvokeStatus, InvokeTruthSource};
use fcp_mesh::invoke_route::{
    MeshForwardBody, MeshForwardEnvelope, MeshForwardReply, advertised_connector_route_subject,
};
use lease_e2e_support::{
    HttpHostProcess, build_invoke_request, capability_public_key_hex, host_e2e_lock, http_get_json,
    http_post_json, plain_test_connector_config, reserve_local_bind_addr,
};
use serde_json::{Value, json};

const REMOTE_CONNECTOR: &str = "fcp.test.mesh-remote:utility:1.0.0";

struct MeshNode {
    id: &'static str,
    key: Ed25519SigningKey,
    bind: SocketAddr,
    key_file: PathBuf,
}

struct MeshFixture {
    _dir: tempfile::TempDir,
    nodes: Vec<MeshNode>,
    peers_json: String,
    capability_key: Ed25519SigningKey,
}

impl MeshFixture {
    fn new(ids: &[&'static str]) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let mut nodes = Vec::new();
        for id in ids {
            let key = Ed25519SigningKey::generate();
            let key_file = dir.path().join(format!("{id}.mesh.key"));
            std::fs::write(&key_file, hex::encode(key.to_bytes()))?;
            nodes.push(MeshNode {
                id,
                key,
                bind: reserve_local_bind_addr()?,
                key_file,
            });
        }
        let peers_json = serde_json::to_string(
            &nodes
                .iter()
                .map(|node| {
                    json!({
                        "node_id": node.id,
                        "endpoint": format!("http://{}", node.bind),
                        "public_key_hex": hex::encode(node.key.verifying_key().to_bytes()),
                    })
                })
                .collect::<Vec<_>>(),
        )?;
        Ok(Self {
            _dir: dir,
            nodes,
            peers_json,
            capability_key: Ed25519SigningKey::generate(),
        })
    }

    fn node(&self, id: &str) -> &MeshNode {
        self.nodes
            .iter()
            .find(|node| node.id == id)
            .expect("fixture node")
    }

    async fn spawn(
        &self,
        id: &str,
        connector_configs: Vec<Value>,
    ) -> Result<HttpHostProcess, Box<dyn std::error::Error>> {
        let node = self.node(id);
        let key_file = node.key_file.display().to_string();
        let capability_public_key = capability_public_key_hex(&self.capability_key);
        HttpHostProcess::spawn_at_with_env(
            node.bind,
            connector_configs,
            &[
                ("FCP_HOST_MESH_NODE_ID", node.id),
                ("FCP_HOST_MESH_SIGNING_KEY_FILE", key_file.as_str()),
                ("FCP_HOST_MESH_PEERS", self.peers_json.as_str()),
                ("FCP_HOST_MESH_FORWARD_TIMEOUT_MS", "15000"),
                (
                    "FCP_HOST_CAPABILITY_PUBLIC_KEY",
                    capability_public_key.as_str(),
                ),
            ],
        )
        .await
    }
}

fn remote_connector() -> ConnectorId {
    ConnectorId::from_static(REMOTE_CONNECTOR)
}

fn route_of(response: &InvokeResponse) -> &fcp_kernel::InvokeRouteProvenance {
    response
        .response_metadata
        .as_ref()
        .and_then(|metadata| metadata.route.as_ref())
        .expect("mesh-aware host must stamp route provenance")
}

async fn post_raw(
    host: &HttpHostProcess,
    path: &str,
    body: &impl serde::Serialize,
) -> Result<(reqwest::StatusCode, String), Box<dyn std::error::Error>> {
    let response = host
        .client
        .post(format!("{}{path}", host.base_url))
        .json(body)
        .send()
        .await?;
    let status = response.status();
    Ok((status, response.text().await?))
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn entry_node_forwards_invoke_to_advertising_peer_and_labels_answer_mesh_backed()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let mesh = MeshFixture::new(&["node-a", "node-b"])?;
    let connector_id = remote_connector();
    let executor = mesh
        .spawn(
            "node-b",
            vec![plain_test_connector_config(&connector_id, "Mesh Remote")],
        )
        .await?;
    let entry = mesh.spawn("node-a", Vec::new()).await?;

    // The executor answers its own connector host-backed.
    let (direct_request, _) = build_invoke_request(connector_id.clone(), &mesh.capability_key);
    let direct: InvokeResponse = http_post_json(
        executor.client.clone(),
        format!("{}/rpc/invoke", executor.base_url),
        direct_request,
    )
    .await?;
    assert_eq!(direct.status, InvokeStatus::Ok);
    let direct_route = route_of(&direct);
    assert_eq!(direct_route.truth_source, InvokeTruthSource::HostBacked);
    assert_eq!(direct_route.served_by.as_deref(), Some("node-b"));
    assert_eq!(direct_route.decision, "local_connector");

    // The entry node does not run the connector, so it relays to node-b.
    let (request, _) = build_invoke_request(connector_id.clone(), &mesh.capability_key);
    let request_id = request.id.clone();
    let forwarded: InvokeResponse = http_post_json(
        entry.client.clone(),
        format!("{}/rpc/invoke", entry.base_url),
        request,
    )
    .await?;
    assert_eq!(forwarded.status, InvokeStatus::Ok, "{forwarded:?}");
    assert_eq!(forwarded.id, request_id);
    assert_eq!(
        forwarded
            .result
            .as_ref()
            .and_then(|result| result.get("echo")),
        Some(&json!({ "message": "hello" })),
        "the real connector subprocess on node-b must have executed the request"
    );
    let route = route_of(&forwarded);
    assert_eq!(route.truth_source, InvokeTruthSource::MeshBacked);
    assert_eq!(route.served_by.as_deref(), Some("node-b"));
    assert_eq!(route.entry_node.as_deref(), Some("node-a"));
    assert_eq!(route.hop_count, 1);
    assert_eq!(route.decision, "advertised_peer_forward");
    assert!(route.failed_attempts.is_empty());

    // Wire shape: the label is visible to any JSON client.
    let raw: Value = serde_json::to_value(&forwarded)?;
    assert_eq!(
        raw["response_metadata"]["route"]["truth_source"],
        "mesh-backed"
    );

    // Catalog and introspection on the entry node see the peer's connector.
    let discovery: Value = http_post_json(
        entry.client.clone(),
        format!("{}/rpc/discover", entry.base_url),
        json!({}),
    )
    .await?;
    let listed = discovery["connectors"]
        .as_array()
        .expect("discovery connectors")
        .iter()
        .any(|connector| connector["id"] == REMOTE_CONNECTOR);
    assert!(
        listed,
        "entry discovery must list the peer connector: {discovery}"
    );
    let introspection: Value = http_get_json(
        entry.client.clone(),
        format!("{}/rpc/introspect/{REMOTE_CONNECTOR}", entry.base_url),
    )
    .await?;
    assert!(
        introspection["tools"]
            .as_array()
            .is_some_and(|tools| tools.iter().any(|tool| tool["name"] == "test.echo")),
        "entry introspection must be served by the peer: {introspection}"
    );

    // Preflight is forwarded too, so `fwc invoke`'s preflight step works.
    let (preflight_source, _) = build_invoke_request(connector_id.clone(), &mesh.capability_key);
    let preflight: Value = http_post_json(
        entry.client.clone(),
        format!("{}/rpc/preflight", entry.base_url),
        json!({
            "request_id": preflight_source.id,
            "connector_id": REMOTE_CONNECTOR,
            "operation": "test.echo",
            "params": { "message": "hello" },
            "zone_id": "z:work",
            "capability_token": preflight_source.capability_token,
        }),
    )
    .await?;
    assert_eq!(
        preflight["allowed"], true,
        "forwarded preflight should pass on the executor: {preflight}"
    );
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn forwarded_invoke_is_still_authorized_by_the_executor()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let mesh = MeshFixture::new(&["node-a", "node-b"])?;
    let connector_id = remote_connector();
    let _executor = mesh
        .spawn(
            "node-b",
            vec![plain_test_connector_config(&connector_id, "Mesh Remote")],
        )
        .await?;
    let entry = mesh.spawn("node-a", Vec::new()).await?;

    // A token minted by a key the executor does not trust is relayed but
    // refused by node-b's own capability verification.
    let rogue_key = Ed25519SigningKey::generate();
    let (request, _) = build_invoke_request(connector_id, &rogue_key);
    let (status, body) = post_raw(&entry, "/rpc/invoke", &request).await?;
    assert_eq!(
        status,
        reqwest::StatusCode::FORBIDDEN,
        "executor must deny: {body}"
    );
    assert!(
        body.contains("mesh executor `node-b`") && body.contains("capability token"),
        "denial must name the executor and the failed gate: {body}"
    );

    // A connector nobody advertises fails the same way it does host-first.
    let (unknown, _) = build_invoke_request(
        ConnectorId::from_static("fcp.test.nobody:utility:1.0.0"),
        &mesh.capability_key,
    );
    let (status, _) = post_raw(&entry, "/rpc/invoke", &unknown).await?;
    assert_ne!(status, reqwest::StatusCode::OK);
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn peer_forward_endpoint_rejects_forged_misaddressed_and_replayed_envelopes()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let mesh = MeshFixture::new(&["node-a", "node-b"])?;
    let connector_id = remote_connector();
    let executor = mesh
        .spawn(
            "node-b",
            vec![plain_test_connector_config(&connector_id, "Mesh Remote")],
        )
        .await?;
    let (request, _) = build_invoke_request(connector_id, &mesh.capability_key);
    let body = || MeshForwardBody::Invoke {
        request_json: serde_json::to_string(&request).expect("request json"),
        asserted_principal: None,
    };
    let now_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?;

    // Forged: claims node-a but is signed by an outsider key.
    let forged = MeshForwardEnvelope::sign(
        &Ed25519SigningKey::generate(),
        TailscaleNodeId::new("node-a"),
        TailscaleNodeId::new("node-b"),
        now_ms,
        body(),
    )?;
    let (status, text) = post_raw(&executor, "/rpc/mesh/forward", &forged).await?;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED, "{text}");

    // Misaddressed: validly signed by node-a, but for another node.
    let misaddressed = MeshForwardEnvelope::sign(
        &mesh.node("node-a").key,
        TailscaleNodeId::new("node-a"),
        TailscaleNodeId::new("node-c"),
        now_ms,
        body(),
    )?;
    let (status, text) = post_raw(&executor, "/rpc/mesh/forward", &misaddressed).await?;
    assert_eq!(status, reqwest::StatusCode::MISDIRECTED_REQUEST, "{text}");

    // Valid once, then a replay of the identical envelope is refused.
    let genuine = MeshForwardEnvelope::sign(
        &mesh.node("node-a").key,
        TailscaleNodeId::new("node-a"),
        TailscaleNodeId::new("node-b"),
        now_ms,
        body(),
    )?;
    let (status, text) = post_raw(&executor, "/rpc/mesh/forward", &genuine).await?;
    assert_eq!(status, reqwest::StatusCode::OK, "{text}");
    let reply: MeshForwardReply = serde_json::from_str(&text)?;
    let origin_directory = fcp_mesh::invoke_route::MeshPeerDirectory::from_json(
        TailscaleNodeId::new("node-a"),
        &mesh.peers_json,
    )?;
    reply.verify_for(&genuine, &origin_directory)?;
    assert!(reply.is_success(), "genuine forward executes: {text}");
    let (status, text) = post_raw(&executor, "/rpc/mesh/forward", &genuine).await?;
    assert_eq!(status, reqwest::StatusCode::CONFLICT, "{text}");

    // Stale: outside the freshness window.
    let stale = MeshForwardEnvelope::sign(
        &mesh.node("node-a").key,
        TailscaleNodeId::new("node-a"),
        TailscaleNodeId::new("node-b"),
        now_ms - 10 * 60_000,
        body(),
    )?;
    let (status, text) = post_raw(&executor, "/rpc/mesh/forward", &stale).await?;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED, "{text}");
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn undeliverable_first_choice_moves_to_next_ranked_advertiser()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let mesh = MeshFixture::new(&["node-a", "node-b", "node-c"])?;
    let connector_id = remote_connector();
    let peer_b = mesh
        .spawn(
            "node-b",
            vec![plain_test_connector_config(&connector_id, "Mesh Remote")],
        )
        .await?;
    let peer_c = mesh
        .spawn(
            "node-c",
            vec![plain_test_connector_config(&connector_id, "Mesh Remote")],
        )
        .await?;
    let entry = mesh.spawn("node-a", Vec::new()).await?;

    // Prime the entry node's advertisement cache while both peers are up.
    let _: Value = http_post_json(
        entry.client.clone(),
        format!("{}/rpc/discover", entry.base_url),
        json!({}),
    )
    .await?;

    let zone = ZoneId::work();
    let ranked = fcp_mesh::planner::rank_lease_holders_by_hrw(
        &zone,
        &advertised_connector_route_subject(REMOTE_CONNECTOR, &zone),
        &[
            TailscaleNodeId::new("node-b"),
            TailscaleNodeId::new("node-c"),
        ],
    );
    let (first, second) = (ranked[0].as_str().to_owned(), ranked[1].as_str().to_owned());
    // Take the first choice down; its advertisement is still cached, so the
    // entry node attempts it, fails before delivery, and moves on.
    if first == "node-b" {
        drop(peer_b);
    } else {
        drop(peer_c);
    }

    let (request, _) = build_invoke_request(connector_id, &mesh.capability_key);
    let response: InvokeResponse = http_post_json(
        entry.client.clone(),
        format!("{}/rpc/invoke", entry.base_url),
        request,
    )
    .await?;
    assert_eq!(response.status, InvokeStatus::Ok);
    let route = route_of(&response);
    assert_eq!(route.truth_source, InvokeTruthSource::MeshBacked);
    assert_eq!(route.served_by.as_deref(), Some(second.as_str()));
    assert_eq!(route.failed_attempts.len(), 1, "{route:?}");
    assert!(
        route.failed_attempts[0].starts_with(&first),
        "failed attempt names the unreachable peer: {route:?}"
    );
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn every_advertiser_unreachable_fails_closed_with_attempts()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let mesh = MeshFixture::new(&["node-a", "node-b"])?;
    let connector_id = remote_connector();
    let peer_b = mesh
        .spawn(
            "node-b",
            vec![plain_test_connector_config(&connector_id, "Mesh Remote")],
        )
        .await?;
    let entry = mesh.spawn("node-a", Vec::new()).await?;
    let _: Value = http_post_json(
        entry.client.clone(),
        format!("{}/rpc/discover", entry.base_url),
        json!({}),
    )
    .await?;
    drop(peer_b);

    let (request, _) = build_invoke_request(connector_id, &mesh.capability_key);
    let (status, body) = post_raw(&entry, "/rpc/invoke", &request).await?;
    assert_eq!(status, reqwest::StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(
        body.contains("node-b") && body.contains("not delivered"),
        "the refusal lists the undeliverable attempt: {body}"
    );
    Ok(())
}
