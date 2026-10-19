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
use fcp_host::{BatchInvokeResponse, BatchStatus, OperationResultStatus};
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
    let discovery_response = entry
        .client
        .post(format!("{}/rpc/discover", entry.base_url))
        .json(&json!({}))
        .send()
        .await?
        .error_for_status()?;
    assert_eq!(
        discovery_response.headers()["x-fcp-truth-source"],
        "mesh-backed"
    );
    assert_eq!(
        discovery_response.headers()["x-fcp-truth-local-connectors"],
        "0"
    );
    assert_eq!(
        discovery_response.headers()["x-fcp-truth-mesh-connectors"],
        "1"
    );
    let discovery: Value = discovery_response.json().await?;
    let listed = discovery["connectors"]
        .as_array()
        .expect("discovery connectors")
        .iter()
        .any(|connector| connector["id"] == REMOTE_CONNECTOR);
    assert!(
        listed,
        "entry discovery must list the peer connector: {discovery}"
    );
    let introspection_response = entry
        .client
        .get(format!(
            "{}/rpc/introspect/{REMOTE_CONNECTOR}",
            entry.base_url
        ))
        .send()
        .await?
        .error_for_status()?;
    let introspection: Value = introspection_response.json().await?;
    assert_eq!(introspection["read_route"]["truth_source"], "mesh-backed");
    assert_eq!(introspection["read_route"]["entry_node"], "node-a");
    assert_eq!(introspection["read_route"]["served_by"], "node-b");
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
async fn live_http_batch_forwards_remote_members_and_binds_verified_results()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let mesh = MeshFixture::new(&["node-a", "node-b"])?;
    let _executor = mesh
        .spawn(
            "node-b",
            vec![plain_test_connector_config(
                &remote_connector(),
                "Batch Remote",
            )],
        )
        .await?;
    let entry = mesh.spawn("node-a", Vec::new()).await?;
    let (mut source, _) = build_invoke_request(remote_connector(), &mesh.capability_key);
    source.input = json!({"message": "remote batch value"});
    let source_id = source.id.clone();
    let (mut consumer, _) = build_invoke_request(remote_connector(), &mesh.capability_key);
    consumer.input = json!({
        "message": {
            "$fcp_batch_ref": {"operation": "source", "pointer": "/result/echo/message"}
        }
    });
    let consumer_id = consumer.id.clone();

    // Exercise the alternate public route and reverse submission order: the
    // dependency determines dispatch order, while results keep caller order.
    let response: BatchInvokeResponse = http_post_json(
        entry.client.clone(),
        format!("{}/rpc/batch-invoke", entry.base_url),
        json!({
            "operations": [
                {"id": "consumer", "request": consumer, "depends_on": ["source"]},
                {"id": "source", "request": source, "depends_on": []}
            ],
            "options": {"max_parallelism": 2, "timeout_ms": 30_000}
        }),
    )
    .await?;
    assert_eq!(response.status, BatchStatus::Success, "{response:?}");
    assert_eq!(
        (response.completed, response.failed, response.skipped),
        (2, 0, 0)
    );
    assert_eq!(response.results[0].id, "consumer");
    assert_eq!(response.results[1].id, "source");
    for (result, request_id) in response.results.iter().zip([consumer_id, source_id]) {
        assert_eq!(result.status, OperationResultStatus::Success);
        let invoke: InvokeResponse = serde_json::from_value(result.output.clone().unwrap())?;
        assert_eq!(invoke.id, request_id);
        assert_eq!(invoke.status, InvokeStatus::Ok);
        assert_eq!(
            invoke.result.as_ref().unwrap()["echo"]["message"],
            "remote batch value"
        );
        assert_eq!(
            route_of(&invoke).truth_source,
            InvokeTruthSource::MeshBacked
        );
        assert_eq!(route_of(&invoke).served_by.as_deref(), Some("node-b"));
    }
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn live_http_batch_remote_principal_denial_blocks_dependent_dispatch()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let mesh = MeshFixture::new(&["node-a", "node-b"])?;
    let _executor = mesh
        .spawn(
            "node-b",
            vec![plain_test_connector_config(
                &remote_connector(),
                "Batch Authority",
            )],
        )
        .await?;
    let entry = mesh.spawn("node-a", Vec::new()).await?;
    let (source, _) = build_invoke_request(remote_connector(), &mesh.capability_key);
    let (mut consumer, _) = build_invoke_request(remote_connector(), &mesh.capability_key);
    consumer.input = json!({
        "message": {
            "$fcp_batch_ref": {"operation": "source", "pointer": "/result/echo/message"}
        }
    });
    let response: BatchInvokeResponse = entry
        .client
        .post(format!("{}/rpc/batch", entry.base_url))
        .header("X-Principal", "user:other")
        .json(&json!({
            "operations": [
                {"id": "source", "request": source, "depends_on": []},
                {"id": "consumer", "request": consumer, "depends_on": ["source"]}
            ],
            "options": {"max_parallelism": 2, "timeout_ms": 30_000}
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(
        (response.completed, response.failed, response.skipped),
        (0, 1, 1)
    );
    assert_eq!(response.results[0].status, OperationResultStatus::Error);
    assert!(response.results[0].output.is_none());
    let denial = response.results[0].error.as_ref().unwrap();
    assert!(
        denial.message.contains("request principal `user:other`"),
        "{denial:?}"
    );
    assert!(denial.retry_after_ms.is_none());
    assert_eq!(response.results[1].status, OperationResultStatus::Skipped);
    assert_eq!(
        response.results[1].error.as_ref().unwrap().code,
        "DEP_FAILED"
    );
    assert!(response.results[1].output.is_none());
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn remote_connector_inventory_and_status_are_available_without_admin_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let mesh = MeshFixture::new(&["node-a", "node-b"])?;
    let executor = mesh
        .spawn(
            "node-b",
            vec![plain_test_connector_config(
                &remote_connector(),
                "Remote Inventory",
            )],
        )
        .await?;
    let entry = mesh.spawn("node-a", Vec::new()).await?;

    // These are public read endpoints. The entry's admin credential must not
    // be needed or forwarded to the executor to inspect a remote connector.
    for suffix in ["", "/status"] {
        let path = format!("/rpc/connectors/{REMOTE_CONNECTOR}{suffix}");
        let direct_response = executor
            .client
            .get(format!("{}{path}", executor.base_url))
            .header("x-fcp-truth-source", "mesh-backed")
            .send()
            .await?
            .error_for_status()?;
        let direct: Value = direct_response.json().await?;
        assert!(direct.get("read_route").is_none());
        let forwarded_response = entry
            .client
            .get(format!("{}{path}", entry.base_url))
            .send()
            .await?
            .error_for_status()?;
        let forwarded: Value = forwarded_response.json().await?;
        assert_eq!(forwarded["read_route"]["truth_source"], "mesh-backed");
        assert_eq!(forwarded["read_route"]["entry_node"], "node-a");
        assert_eq!(forwarded["read_route"]["served_by"], "node-b");
        assert_eq!(forwarded["read_route"]["hop_count"], 1);
        if suffix.is_empty() {
            assert_eq!(forwarded["connector"]["id"], REMOTE_CONNECTOR);
            assert_eq!(forwarded["connector"]["name"], "Remote Inventory");
            for field in ["id", "name", "version", "enabled", "tool_count"] {
                assert_eq!(forwarded["connector"][field], direct["connector"][field]);
            }
            assert_eq!(forwarded["registry_version"], direct["registry_version"]);
        } else {
            assert_eq!(forwarded["connector_id"], REMOTE_CONNECTOR);
            for field in [
                "desired_state",
                "observed_state",
                "lifecycle",
                "pinned_version",
            ] {
                assert_eq!(
                    forwarded[field], direct[field],
                    "remote status field {field}"
                );
            }
        }
    }

    // Protected admin reads retain their original authorization boundary.
    for path in [
        format!("/rpc/rollout/pin/{REMOTE_CONNECTOR}"),
        format!("/rpc/rollout/{REMOTE_CONNECTOR}"),
    ] {
        let response = entry
            .client
            .get(format!("{}{path}", entry.base_url))
            .send()
            .await?;
        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
    }
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn mesh_discovery_does_not_promote_local_records_to_mesh_truth()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let mesh = MeshFixture::new(&["node-a", "node-b"])?;
    let _executor = mesh
        .spawn(
            "node-b",
            vec![plain_test_connector_config(&remote_connector(), "Remote")],
        )
        .await?;
    let local = ConnectorId::from_static("fcp.test.mesh-local:utility:1.0.0");
    let entry = mesh
        .spawn("node-a", vec![plain_test_connector_config(&local, "Local")])
        .await?;

    let response = entry
        .client
        .post(format!("{}/rpc/discover", entry.base_url))
        .header("x-fcp-truth-source", "mesh-backed")
        .json(&json!({}))
        .send()
        .await?
        .error_for_status()?;
    assert_eq!(response.headers()["x-fcp-truth-source"], "host-backed");
    assert_eq!(response.headers()["x-fcp-truth-local-connectors"], "1");
    assert_eq!(response.headers()["x-fcp-truth-mesh-connectors"], "1");
    let discovery: Value = response.json().await?;
    assert_eq!(discovery["connectors"].as_array().unwrap().len(), 2);

    let response = entry
        .client
        .get(format!("{}/rpc/introspect/{local}", entry.base_url))
        .header("x-fcp-truth-source", "mesh-backed")
        .send()
        .await?
        .error_for_status()?;
    let introspection: Value = response.json().await?;
    assert!(introspection.get("read_route").is_none());
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn forwarded_connector_reads_are_authenticated_replay_guarded_and_local_only()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let mesh = MeshFixture::new(&["node-a", "node-b"])?;
    let executor = mesh
        .spawn(
            "node-b",
            vec![plain_test_connector_config(
                &remote_connector(),
                "Remote Inventory",
            )],
        )
        .await?;
    let entry = mesh.spawn("node-a", Vec::new()).await?;
    let origin_directory = fcp_mesh::invoke_route::MeshPeerDirectory::from_json(
        TailscaleNodeId::new("node-a"),
        &mesh.peers_json,
    )?;
    let bodies = [
        MeshForwardBody::Inventory {
            connector_id: REMOTE_CONNECTOR.to_owned(),
        },
        MeshForwardBody::Status {
            connector_id: REMOTE_CONNECTOR.to_owned(),
        },
    ];
    for body in bodies {
        let envelope = MeshForwardEnvelope::sign(
            &mesh.node("node-a").key,
            TailscaleNodeId::new("node-a"),
            TailscaleNodeId::new("node-b"),
            fcp_host::mesh_routing::unix_now_ms(),
            body.clone(),
        )?;
        let mut tampered = envelope.clone();
        tampered.body = MeshForwardBody::Introspect {
            connector_id: REMOTE_CONNECTOR.to_owned(),
        };
        let (status, text) = post_raw(&executor, "/rpc/mesh/forward", &tampered).await?;
        assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED, "{text}");

        let (status, text) = post_raw(&executor, "/rpc/mesh/forward", &envelope).await?;
        assert_eq!(status, reqwest::StatusCode::OK, "{text}");
        let reply: MeshForwardReply = serde_json::from_str(&text)?;
        reply.verify_for(&envelope, &origin_directory)?;
        assert!(reply.is_success(), "{text}");
        let (status, text) = post_raw(&executor, "/rpc/mesh/forward", &envelope).await?;
        assert_eq!(status, reqwest::StatusCode::CONFLICT, "{text}");

        // node-a can discover the connector on node-b, but a signed forward
        // addressed to node-a must never recurse back through peer routing.
        let wrong_executor = MeshForwardEnvelope::sign(
            &mesh.node("node-b").key,
            TailscaleNodeId::new("node-b"),
            TailscaleNodeId::new("node-a"),
            fcp_host::mesh_routing::unix_now_ms(),
            body,
        )?;
        let (status, text) = post_raw(&entry, "/rpc/mesh/forward", &wrong_executor).await?;
        assert_eq!(status, reqwest::StatusCode::OK, "{text}");
        let reply: MeshForwardReply = serde_json::from_str(&text)?;
        let directory = fcp_mesh::invoke_route::MeshPeerDirectory::from_json(
            TailscaleNodeId::new("node-b"),
            &mesh.peers_json,
        )?;
        reply.verify_for(&wrong_executor, &directory)?;
        assert_eq!(
            reply.status,
            reqwest::StatusCode::NOT_FOUND.as_u16(),
            "{text}"
        );
    }
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn connector_inventory_prefers_local_registration_over_peer_advertisements()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let mesh = MeshFixture::new(&["node-a", "node-b"])?;
    let _peer = mesh
        .spawn(
            "node-b",
            vec![plain_test_connector_config(
                &remote_connector(),
                "Peer Copy",
            )],
        )
        .await?;
    let entry = mesh
        .spawn(
            "node-a",
            vec![plain_test_connector_config(
                &remote_connector(),
                "Local Copy",
            )],
        )
        .await?;
    let inventory: Value = http_get_json(
        entry.client.clone(),
        format!("{}/rpc/connectors/{REMOTE_CONNECTOR}", entry.base_url),
    )
    .await?;
    assert_eq!(inventory["connector"]["name"], "Local Copy");
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
        origin_attempt_id: None,
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

// A real signed mesh peer whose reply can be changed between requests. The
// entry node remains a real host process; only failing replica behavior is
// controlled here.
struct SignedReadPeer {
    bind: SocketAddr,
    reply: std::sync::Arc<std::sync::Mutex<Option<(u16, String)>>>,
    forwards: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl SignedReadPeer {
    fn spawn(
        mesh: &MeshFixture,
        id: &str,
        status: u16,
        body: String,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        use fcp_mesh::invoke_route::{
            AdvertisedConnector, MeshForwardReplayGuard, MeshPeerAdvertisement, MeshPeerDirectory,
        };
        use std::io::Write;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        use std::time::Duration;

        let node = mesh.node(id);
        let bind = node.bind;
        let key = Ed25519SigningKey::from_bytes(&node.key.to_bytes())?;
        let node_id = TailscaleNodeId::new(node.id);
        let directory = MeshPeerDirectory::from_json(node_id.clone(), &mesh.peers_json)?;
        let listener = std::net::TcpListener::bind(bind)?;
        let reply = Arc::new(std::sync::Mutex::new(Some((status, body))));
        let forwards = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let thread_reply = Arc::clone(&reply);
        let thread_forwards = Arc::clone(&forwards);
        let thread_stop = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            let mut replay = MeshForwardReplayGuard::new(60_000, 128);
            for stream in listener.incoming() {
                let mut stream = stream.expect("accept signed peer connection");
                if thread_stop.load(Ordering::SeqCst) {
                    break;
                }
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("peer read timeout");
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .expect("peer write timeout");
                let (path, body) = read_signed_peer_request(&mut stream);
                let response = match path.as_str() {
                    "/rpc/mesh/advertisement" => {
                        let advertisement = MeshPeerAdvertisement::sign(
                            &key,
                            node_id.clone(),
                            fcp_host::mesh_routing::unix_now_ms(),
                            vec![AdvertisedConnector {
                                connector_id: REMOTE_CONNECTOR.to_owned(),
                                zones: vec!["z:work".to_owned(), "z:owner".to_owned()],
                                singleton_writer: false,
                                summary_json: None,
                            }],
                        );
                        serde_json::to_vec(&advertisement).expect("serialize advertisement")
                    }
                    "/rpc/mesh/forward" => {
                        let envelope: MeshForwardEnvelope =
                            serde_json::from_slice(&body).expect("decode signed forward");
                        let now = fcp_host::mesh_routing::unix_now_ms();
                        envelope
                            .verify(&directory, now, 60_000)
                            .expect("entry forward must authenticate");
                        replay
                            .check_and_record(&envelope, now)
                            .expect("entry must use a fresh nonce for each attempt");
                        thread_forwards.fetch_add(1, Ordering::SeqCst);
                        let selected = thread_reply.lock().expect("reply lock").clone();
                        let Some((status, body)) = selected else {
                            // Received and authenticated, then disconnected before a reply.
                            continue;
                        };
                        let reply = MeshForwardReply::sign(
                            &key,
                            node_id.clone(),
                            &envelope,
                            status,
                            body,
                        );
                        serde_json::to_vec(&reply).expect("serialize signed reply")
                    }
                    unexpected => panic!("unexpected peer request: {unexpected}"),
                };
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                )
                .expect("write peer response headers");
                stream.write_all(&response).expect("write peer response");
            }
        });
        Ok(Self {
            bind,
            reply,
            forwards,
            stop,
            worker: Some(worker),
        })
    }

    fn set_reply(&self, status: u16, body: String) {
        *self.reply.lock().expect("reply lock") = Some((status, body));
    }

    fn disconnect_after_receipt(&self) {
        *self.reply.lock().expect("reply lock") = None;
    }

    fn forwards(&self) -> usize {
        self.forwards.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Drop for SignedReadPeer {
    fn drop(&mut self) {
        self.stop
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = std::net::TcpStream::connect(self.bind);
        if let Some(worker) = self.worker.take() {
            let joined = worker.join();
            if !std::thread::panicking() {
                joined.expect("signed read peer should finish without panicking");
            }
        }
    }
}

fn read_signed_peer_request(stream: &mut std::net::TcpStream) -> (String, Vec<u8>) {
    use std::io::{BufRead, Read};
    let mut reader = std::io::BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read request line");
    let path = line
        .split_whitespace()
        .nth(1)
        .expect("request path")
        .to_owned();
    let mut header_bytes = line.len();
    let mut content_length = 0;
    loop {
        line.clear();
        assert!(reader.read_line(&mut line).expect("read header") > 0);
        header_bytes += line.len();
        assert!(header_bytes <= 16_384, "bounded peer request headers");
        if line == "\r\n" {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse::<usize>().expect("content length");
        }
    }
    assert!(content_length <= 2 * 1024 * 1024, "bounded peer request body");
    let mut body = vec![0; content_length];
    reader.read_exact(&mut body).expect("read request body");
    (path, body)
}

fn ranked_read_nodes(zone: &ZoneId) -> Vec<TailscaleNodeId> {
    fcp_mesh::planner::rank_lease_holders_by_hrw(
        zone,
        &advertised_connector_route_subject(REMOTE_CONNECTOR, zone),
        &[
            TailscaleNodeId::new("node-b"),
            TailscaleNodeId::new("node-c"),
        ],
    )
}

async fn valid_mesh_read_responses() -> Result<(Value, Value), Box<dyn std::error::Error>> {
    let connector = fcp_host::ConnectorSummary {
        id: remote_connector(),
        name: "Valid Read Replica".to_owned(),
        description: None,
        version: semver::Version::new(1, 0, 0),
        categories: Vec::new(),
        tool_count: 0,
        max_safety_tier: fcp_core::SafetyTier::Safe,
        enabled: true,
        health: fcp_kernel::ConnectorHealth::Healthy,
        last_health_check: None,
    };
    let state = fcp_host::HostAdminStateStore::new();
    state
        .reconcile_registered_connectors(std::slice::from_ref(&connector))
        .await?;
    let status = state.connector_status(&connector.id).await?;
    let inventory = fcp_host::ConnectorInventoryResponse {
        connector,
        registry_version: 1,
        cache: None,
        meta: None,
    };
    Ok((serde_json::to_value(inventory)?, serde_json::to_value(status)?))
}

fn live_simulate_request(mesh: &MeshFixture, request_id: &str) -> Value {
    let (source, _) = build_invoke_request(remote_connector(), &mesh.capability_key);
    json!({
        "request_id": request_id,
        "connector_id": REMOTE_CONNECTOR,
        "operation": "test.echo",
        "zone_id": "z:work",
        "principal": "agent:test",
        "input": {"message": "read-only simulation"},
        "capability_token": source.capability_token,
        "estimate_cost": false,
        "check_availability": false,
        "deadline_ms": 5000,
    })
}

async fn simulate_receipts(
    host: &HttpHostProcess,
) -> Result<Value, Box<dyn std::error::Error>> {
    http_post_json(
        host.client.clone(),
        format!("{}/rpc/admin/simulate-receipts", host.base_url),
        json!({"connector_id": REMOTE_CONNECTOR, "limit": 100}),
    )
    .await
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn read_queries_fail_over_unavailable_malformed_and_wrong_identity_replicas()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let mesh = MeshFixture::new(&["node-a", "node-b", "node-c"])?;
    let ranked = ranked_read_nodes(&ZoneId::owner());
    let (inventory, status_response) = valid_mesh_read_responses().await?;
    let first = SignedReadPeer::spawn(&mesh, ranked[0].as_str(), 503, "\"busy\"".to_owned())?;
    let second = SignedReadPeer::spawn(&mesh, ranked[1].as_str(), 200, inventory.to_string())?;
    let entry = mesh.spawn("node-a", Vec::new()).await?;
    let mut wrong_inventory = inventory.clone();
    wrong_inventory["connector"]["id"] = json!("fcp.test.wrong:utility:1.0.0");
    let cases = [
        (404, "\"advertisement is stale\"".to_owned()),
        (503, "\"replica unavailable\"".to_owned()),
        (200, "{".to_owned()),
        (200, json!({"connector": {"id": REMOTE_CONNECTOR}}).to_string()),
        (200, wrong_inventory.to_string()),
    ];
    for (status, body) in cases {
        first.set_reply(status, body);
        let previous_first = first.forwards();
        let previous_second = second.forwards();
        let response: Value = http_get_json(
            entry.client.clone(),
            format!("{}/rpc/connectors/{REMOTE_CONNECTOR}", entry.base_url),
        )
        .await?;
        assert_eq!(response["connector"]["id"], REMOTE_CONNECTOR);
        assert_eq!(response["connector"]["name"], "Valid Read Replica");
        assert_eq!(first.forwards(), previous_first + 1);
        assert_eq!(second.forwards(), previous_second + 1);
    }

    first.disconnect_after_receipt();
    let previous_second = second.forwards();
    let response: Value = http_get_json(
        entry.client.clone(),
        format!("{}/rpc/connectors/{REMOTE_CONNECTOR}", entry.base_url),
    )
    .await?;
    assert_eq!(response["connector"]["id"], REMOTE_CONNECTOR);
    assert_eq!(second.forwards(), previous_second + 1);

    let mut wrong_status = status_response.clone();
    wrong_status["connector_id"] = json!("fcp.test.wrong:utility:1.0.0");
    first.set_reply(200, wrong_status.to_string());
    second.set_reply(200, status_response.to_string());
    let previous_second = second.forwards();
    let status: Value = http_get_json(
        entry.client.clone(),
        format!("{}/rpc/connectors/{REMOTE_CONNECTOR}/status", entry.base_url),
    )
    .await?;
    assert_eq!(status["connector_id"], REMOTE_CONNECTOR);
    assert_eq!(second.forwards(), previous_second + 1);

    // Exhaustion still rejects wrong identities and never reflects peer data.
    wrong_inventory["connector"]["description"] = json!("private-replica-payload");
    first.set_reply(200, wrong_inventory.to_string());
    second.set_reply(200, wrong_inventory.to_string());
    let response = entry
        .client
        .get(format!("{}/rpc/connectors/{REMOTE_CONNECTOR}", entry.base_url))
        .send()
        .await?;
    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    let body = response.text().await?;
    assert!(body.contains(ranked[0].as_str()) && body.contains(ranked[1].as_str()), "{body}");
    assert!(body.contains("different connector"), "{body}");
    assert!(!body.contains("private-replica-payload"), "{body}");
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn read_query_denials_do_not_probe_a_more_permissive_replica()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let mesh = MeshFixture::new(&["node-a", "node-b", "node-c"])?;
    let ranked = ranked_read_nodes(&ZoneId::owner());
    let (inventory, _) = valid_mesh_read_responses().await?;
    let first = SignedReadPeer::spawn(&mesh, ranked[0].as_str(), 403, "\"denied\"".to_owned())?;
    let second = SignedReadPeer::spawn(&mesh, ranked[1].as_str(), 200, inventory.to_string())?;
    let entry = mesh.spawn("node-a", Vec::new()).await?;
    for status in [400, 401, 403, 409, 422] {
        first.set_reply(status, "\"private-policy-denial-details\"".to_owned());
        let response = entry
            .client
            .get(format!("{}/rpc/connectors/{REMOTE_CONNECTOR}", entry.base_url))
            .send()
            .await?;
        assert_eq!(response.status().as_u16(), status);
        let body = response.text().await?;
        assert!(body.contains(ranked[0].as_str()), "{body}");
        assert!(!body.contains("private-policy-denial-details"), "{body}");
        assert_eq!(second.forwards(), 0, "a denial must not search another executor");
    }

    first.set_reply(
        200,
        serde_json::to_string(&fcp_host::PreflightResponse::denied("policy denied"))?,
    );
    second.set_reply(
        200,
        serde_json::to_string(&fcp_host::PreflightResponse::allowed())?,
    );
    let response: Value = http_post_json(
        entry.client.clone(),
        format!("{}/rpc/preflight", entry.base_url),
        json!({
            "request_id": "authoritative-preflight-denial",
            "connector_id": REMOTE_CONNECTOR,
            "operation": "test.echo",
            "zone_id": "z:owner",
        }),
    )
    .await?;
    assert_eq!(response["allowed"], false);
    assert_eq!(response["reason"], "policy denied");
    assert_eq!(second.forwards(), 0);
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn doctor_retries_self_check_replies_for_the_wrong_connector_or_zone()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let mesh = MeshFixture::new(&["node-a", "node-b", "node-c"])?;
    let ranked = ranked_read_nodes(&ZoneId::work());
    let valid = json!({
        "connector_id": REMOTE_CONNECTOR,
        "zone_id": "z:work",
        "report": fcp_kernel::SelfCheckReport::ok(),
    });
    let first = SignedReadPeer::spawn(&mesh, ranked[0].as_str(), 200, valid.to_string())?;
    let second = SignedReadPeer::spawn(&mesh, ranked[1].as_str(), 200, valid.to_string())?;
    let entry = mesh.spawn("node-a", Vec::new()).await?;
    for (field, wrong) in [
        ("connector_id", "fcp.test.wrong:utility:1.0.0"),
        ("zone_id", "z:private"),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = json!(wrong);
        first.set_reply(200, invalid.to_string());
        let previous_second = second.forwards();
        let response: Value = http_post_json(
            entry.client.clone(),
            format!("{}/doctor", entry.base_url),
            json!({
                "zone_id": "z:work",
                "connectors": [REMOTE_CONNECTOR],
                "self_check": true,
            }),
        )
        .await?;
        assert_eq!(response["overall_status"], "OK", "{response}");
        assert_eq!(response["connector_self_checks"].as_array().unwrap().len(), 1);
        assert_eq!(response["connector_self_checks"][0]["connector_id"], REMOTE_CONNECTOR);
        assert_eq!(response["connector_self_checks"][0]["report"]["status"], "ok");
        assert_eq!(second.forwards(), previous_second + 1);
    }
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn simulations_fail_over_wrong_request_receipts_but_preserve_negative_verdicts()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let mesh = MeshFixture::new(&["node-a", "node-b", "node-c"])?;
    let ranked = ranked_read_nodes(&ZoneId::work());
    let request = live_simulate_request(&mesh, "bound-mesh-simulation");
    let input_cbor = fcp_crypto::canonicalize::to_deterministic_cbor(&request["input"])?;
    let valid = json!({
        "request_id": request["request_id"],
        "would_succeed": true,
        "phase": "connector_reached",
        "preflight_allowed": true,
        "duration_ms": 1,
        "receipt": {
            "receipt_id": "executor-simulation-receipt",
            "connector_id": REMOTE_CONNECTOR,
            "operation": "test.echo",
            "phase": "connector_reached",
            "would_succeed": true,
            "input_digest": hex::encode(blake3::hash(&input_cbor).as_bytes()),
            "duration_ms": 1,
            "simulated_at": chrono::Utc::now(),
        },
    });
    let first = SignedReadPeer::spawn(&mesh, ranked[0].as_str(), 200, valid.to_string())?;
    let second = SignedReadPeer::spawn(&mesh, ranked[1].as_str(), 200, valid.to_string())?;
    let entry = mesh.spawn("node-a", Vec::new()).await?;
    for (pointer, wrong) in [
        ("/request_id", json!("different-request")),
        ("/receipt/connector_id", json!("fcp.test.wrong:utility:1.0.0")),
        ("/receipt/operation", json!("test.other")),
        ("/receipt/input_digest", json!("wrong-input-digest")),
        ("/receipt/phase", json!("preflight_only")),
        ("/receipt/would_succeed", json!(false)),
        ("/receipt/duration_ms", json!(99)),
        ("/preflight_allowed", json!(false)),
    ] {
        let mut invalid = valid.clone();
        *invalid.pointer_mut(pointer).expect("known simulation field") = wrong;
        first.set_reply(200, invalid.to_string());
        let previous_second = second.forwards();
        let response: Value = http_post_json(
            entry.client.clone(),
            format!("{}/rpc/simulate", entry.base_url),
            request.clone(),
        )
        .await?;
        let typed: fcp_host::HostSimulateResponse = serde_json::from_value(response)?;
        assert_eq!(typed.request_id, "bound-mesh-simulation");
        assert!(typed.would_succeed);
        assert_eq!(typed.receipt.receipt_id, "executor-simulation-receipt");
        assert_eq!(second.forwards(), previous_second + 1);
    }

    let mut denied = valid;
    denied["would_succeed"] = json!(false);
    denied["preflight_allowed"] = json!(false);
    denied["phase"] = json!("preflight_only");
    denied["failure_reason"] = json!("authoritative executor policy denial");
    denied["receipt"]["would_succeed"] = json!(false);
    denied["receipt"]["phase"] = json!("preflight_only");
    first.set_reply(200, denied.to_string());
    let previous_second = second.forwards();
    let response: Value = http_post_json(
        entry.client.clone(),
        format!("{}/rpc/simulate", entry.base_url),
        request,
    )
    .await?;
    assert_eq!(response["would_succeed"], false);
    assert_eq!(response["preflight_allowed"], false);
    assert_eq!(response["failure_reason"], "authoritative executor policy denial");
    assert_eq!(second.forwards(), previous_second);
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn remote_simulate_returns_connector_details_and_keeps_receipts_on_the_executor()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let mesh = MeshFixture::new(&["node-a", "node-b"])?;
    let executor = mesh
        .spawn(
            "node-b",
            vec![plain_test_connector_config(&remote_connector(), "Remote simulation")],
        )
        .await?;
    let entry = mesh.spawn("node-a", Vec::new()).await?;
    let mut request = live_simulate_request(&mesh, "remote-simulate-basic");
    let basic: Value = http_post_json(
        entry.client.clone(),
        format!("{}/rpc/simulate", entry.base_url),
        request.clone(),
    )
    .await?;
    assert_eq!(basic["request_id"], request["request_id"]);
    assert_eq!(basic["phase"], "connector_reached", "{basic}");
    assert_eq!(basic["preflight_allowed"], true);
    assert_eq!(basic["would_succeed"], true);
    assert!(basic.get("cost_estimate").is_none());
    assert!(basic.get("availability").is_none());

    request["request_id"] = json!("remote-simulate-details");
    request["estimate_cost"] = json!(true);
    request["check_availability"] = json!(true);
    let detailed: Value = http_post_json(
        entry.client.clone(),
        format!("{}/rpc/simulate", entry.base_url),
        request.clone(),
    )
    .await?;
    assert_eq!(detailed["request_id"], request["request_id"]);
    assert_eq!(detailed["phase"], "connector_reached", "{detailed}");
    assert_eq!(detailed["preflight_allowed"], true);
    assert_eq!(detailed["would_succeed"], true);
    assert_eq!(detailed["cost_estimate"]["api_credits"], 7);
    assert_eq!(detailed["cost_estimate"]["estimated_duration_ms"], 25);
    assert_eq!(detailed["cost_estimate"]["estimated_bytes"], 128);
    assert_eq!(detailed["cost_estimate"]["confidence"], "high");
    assert_eq!(detailed["availability"]["available"], true);
    assert_eq!(detailed["availability"]["rate_limit_remaining"], 42);
    let input_cbor = fcp_crypto::canonicalize::to_deterministic_cbor(&request["input"])?;
    assert_eq!(
        detailed["receipt"]["input_digest"],
        hex::encode(blake3::hash(&input_cbor).as_bytes())
    );
    assert_eq!(detailed["receipt"]["connector_id"], REMOTE_CONNECTOR);
    assert_eq!(detailed["receipt"]["operation"], "test.echo");
    assert_eq!(detailed["receipt"]["phase"], detailed["phase"]);
    assert_eq!(detailed["receipt"]["would_succeed"], detailed["would_succeed"]);
    assert_eq!(detailed["receipt"]["duration_ms"], detailed["duration_ms"]);

    let receipts = simulate_receipts(&executor).await?;
    assert_eq!(receipts["total_receipts"], 2, "{receipts}");
    let records = receipts["receipts"].as_array().expect("executor simulation receipts");
    assert!(records.iter().any(|receipt| receipt == &basic["receipt"]));
    assert!(records.iter().any(|receipt| receipt == &detailed["receipt"]));
    assert_eq!(
        simulate_receipts(&entry).await?["total_receipts"],
        0,
        "the origin must return the executor's receipt without inventing a local simulation"
    );
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn remote_simulate_distinguishes_connector_denial_unsupported_and_timeout()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let mesh = MeshFixture::new(&["node-a", "node-b"])?;
    let unsupported_id = ConnectorId::from_static("fcp.test.sim-unsupported:utility:1.0.0");
    let slow_id = ConnectorId::from_static("fcp.test.sim-slow:utility:1.0.0");
    let mut denied_config = plain_test_connector_config(&remote_connector(), "Denied simulation");
    denied_config["env"]["FCP_TEST_CONNECTOR_SIMULATE_MODE"] = json!("denied");
    let mut unsupported_config = plain_test_connector_config(&unsupported_id, "Unsupported simulation");
    unsupported_config["env"]["FCP_TEST_CONNECTOR_SIMULATE_MODE"] = json!("unsupported");
    let executor = mesh
        .spawn(
            "node-b",
            vec![
                denied_config,
                unsupported_config,
                plain_test_connector_config(&slow_id, "Slow simulation"),
            ],
        )
        .await?;
    let entry = mesh.spawn("node-a", Vec::new()).await?;

    let denied: Value = http_post_json(
        entry.client.clone(),
        format!("{}/rpc/simulate", entry.base_url),
        live_simulate_request(&mesh, "connector-predicts-failure"),
    )
    .await?;
    assert_eq!(denied["preflight_allowed"], true, "{denied}");
    assert_eq!(denied["phase"], "connector_reached");
    assert_eq!(denied["would_succeed"], false);
    assert_eq!(denied["denial_code"], "FCP-TEST-SIMULATE");
    assert_eq!(denied["receipt"]["would_succeed"], false);

    let mut unsupported_request = live_simulate_request(&mesh, "connector-cannot-simulate");
    unsupported_request["connector_id"] = json!(unsupported_id.as_str());
    let unsupported: Value = http_post_json(
        entry.client.clone(),
        format!("{}/rpc/simulate", entry.base_url),
        unsupported_request,
    )
    .await?;
    assert_eq!(unsupported["preflight_allowed"], true, "{unsupported}");
    assert_eq!(unsupported["phase"], "connector_unsupported");
    assert_eq!(unsupported["would_succeed"], false);
    assert!(unsupported["failure_reason"].as_str().is_some_and(|reason| !reason.is_empty()));

    // Warm the real connector and signed advertisement cache before exercising
    // its execution deadline, so startup latency is not the property tested.
    let mut slow_request = live_simulate_request(&mesh, "warm-slow-connector");
    slow_request["connector_id"] = json!(slow_id.as_str());
    let warmed: Value = http_post_json(
        entry.client.clone(),
        format!("{}/rpc/simulate", entry.base_url),
        slow_request.clone(),
    )
    .await?;
    assert_eq!(warmed["would_succeed"], true, "{warmed}");
    slow_request["request_id"] = json!("bounded-remote-simulation");
    slow_request["input"]["delay_ms"] = json!(300);
    slow_request["deadline_ms"] = json!(50);
    let timed_out: Value = http_post_json(
        entry.client.clone(),
        format!("{}/rpc/simulate", entry.base_url),
        slow_request,
    )
    .await?;
    assert_eq!(timed_out["preflight_allowed"], true, "{timed_out}");
    assert_eq!(timed_out["phase"], "timed_out");
    assert_eq!(timed_out["would_succeed"], false);
    assert_eq!(timed_out["receipt"]["phase"], "timed_out");

    for response in [&denied, &unsupported, &timed_out] {
        let query = json!({"connector_id": response["receipt"]["connector_id"], "limit": 100});
        let executor_receipts: Value = http_post_json(
            executor.client.clone(),
            format!("{}/rpc/admin/simulate-receipts", executor.base_url),
            query.clone(),
        )
        .await?;
        assert!(
            executor_receipts["receipts"]
                .as_array()
                .expect("executor receipts")
                .iter()
                .any(|receipt| receipt == &response["receipt"]),
            "the executor must journal the exact terminal simulation outcome"
        );
        let entry_receipts: Value = http_post_json(
            entry.client.clone(),
            format!("{}/rpc/admin/simulate-receipts", entry.base_url),
            query,
        )
        .await?;
        assert_eq!(entry_receipts["total_receipts"], 0);
    }
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn remote_simulate_rechecks_capability_principal_and_signed_zone_on_the_executor()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let mesh = MeshFixture::new(&["node-a", "node-b"])?;
    let executor = mesh
        .spawn(
            "node-b",
            vec![plain_test_connector_config(&remote_connector(), "Authorized simulation")],
        )
        .await?;
    let entry = mesh.spawn("node-a", Vec::new()).await?;

    let mut invalid_token_request = live_simulate_request(&mesh, "wrong-simulation-key");
    let (untrusted, _) = build_invoke_request(remote_connector(), &Ed25519SigningKey::generate());
    invalid_token_request["capability_token"] = serde_json::to_value(untrusted.capability_token)?;
    let bad_token: Value = http_post_json(
        entry.client.clone(),
        format!("{}/rpc/simulate", entry.base_url),
        invalid_token_request,
    )
    .await?;
    assert_eq!(bad_token["phase"], "preflight_only", "{bad_token}");
    assert_eq!(bad_token["preflight_allowed"], false);
    assert_eq!(bad_token["would_succeed"], false);

    let principal_response = entry
        .client
        .post(format!("{}/rpc/simulate", entry.base_url))
        .header("x-principal", "agent:other")
        .json(&live_simulate_request(&mesh, "wrong-simulation-principal"))
        .send()
        .await?;
    assert!(principal_response.status().is_success());
    let bad_principal: Value = principal_response.json().await?;
    assert_eq!(bad_principal["phase"], "preflight_only", "{bad_principal}");
    assert_eq!(bad_principal["preflight_allowed"], false);
    assert_eq!(bad_principal["would_succeed"], false);
    assert!(
        bad_principal["failure_reason"]
            .as_str()
            .is_some_and(|reason| reason.to_lowercase().contains("principal")),
        "{bad_principal}"
    );

    // Bypass advertisement filtering with an authenticated peer request: the
    // executor itself must reject a connector outside its configured zone.
    let mut wrong_zone = live_simulate_request(&mesh, "wrong-simulation-zone");
    wrong_zone["zone_id"] = json!("z:private");
    let envelope = MeshForwardEnvelope::sign(
        &mesh.node("node-a").key,
        TailscaleNodeId::new("node-a"),
        TailscaleNodeId::new("node-b"),
        fcp_host::mesh_routing::unix_now_ms(),
        MeshForwardBody::Simulate {
            request_json: serde_json::to_string(&wrong_zone)?,
            asserted_principal: Some("agent:test".to_owned()),
        },
    )?;
    let mut tampered = envelope.clone();
    wrong_zone["zone_id"] = json!("z:work");
    tampered.body = MeshForwardBody::Simulate {
        request_json: serde_json::to_string(&wrong_zone)?,
        asserted_principal: Some("agent:test".to_owned()),
    };
    let (status, body) = post_raw(&executor, "/rpc/mesh/forward", &tampered).await?;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED, "{body}");

    let (status, body) = post_raw(&executor, "/rpc/mesh/forward", &envelope).await?;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    let reply: MeshForwardReply = serde_json::from_str(&body)?;
    let directory = fcp_mesh::invoke_route::MeshPeerDirectory::from_json(
        TailscaleNodeId::new("node-a"),
        &mesh.peers_json,
    )?;
    reply.verify_for(&envelope, &directory)?;
    assert!(reply.is_success(), "{body}");
    let bad_zone: Value = serde_json::from_str(&reply.body_json)?;
    assert_eq!(bad_zone["phase"], "preflight_only", "{bad_zone}");
    assert_eq!(bad_zone["preflight_allowed"], false);
    assert_eq!(bad_zone["would_succeed"], false);
    let (status, body) = post_raw(&executor, "/rpc/mesh/forward", &envelope).await?;
    assert_eq!(status, reqwest::StatusCode::CONFLICT, "{body}");

    let receipts = simulate_receipts(&executor).await?;
    assert_eq!(receipts["total_receipts"], 3, "{receipts}");
    let records = receipts["receipts"].as_array().expect("executor denial receipts");
    for response in [&bad_token, &bad_principal, &bad_zone] {
        assert!(records.iter().any(|receipt| receipt == &response["receipt"]));
    }
    assert_eq!(simulate_receipts(&entry).await?["total_receipts"], 0);
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn simulation_prefers_the_local_connector_verdict_over_a_healthy_peer()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let mesh = MeshFixture::new(&["node-a", "node-b"])?;
    let peer = mesh
        .spawn(
            "node-b",
            vec![plain_test_connector_config(&remote_connector(), "Permissive remote")],
        )
        .await?;
    let mut local_config = plain_test_connector_config(&remote_connector(), "Authoritative local");
    local_config["env"]["FCP_TEST_CONNECTOR_SIMULATE_MODE"] = json!("denied");
    let entry = mesh.spawn("node-a", vec![local_config]).await?;
    let response: Value = http_post_json(
        entry.client.clone(),
        format!("{}/rpc/simulate", entry.base_url),
        live_simulate_request(&mesh, "prefer-local-simulation"),
    )
    .await?;
    assert_eq!(response["preflight_allowed"], true, "{response}");
    assert_eq!(response["phase"], "connector_reached");
    assert_eq!(response["would_succeed"], false);
    assert_eq!(response["denial_code"], "FCP-TEST-SIMULATE");
    let local_receipts = simulate_receipts(&entry).await?;
    assert_eq!(local_receipts["total_receipts"], 1);
    assert_eq!(local_receipts["receipts"][0], response["receipt"]);
    assert_eq!(simulate_receipts(&peer).await?["total_receipts"], 0);
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn doctor_aggregates_real_local_and_remote_connector_self_checks()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let mesh = MeshFixture::new(&["node-a", "node-b"])?;
    let local_id = ConnectorId::from_static("fcp.test.mesh-local:utility:1.0.0");
    let mut remote_config = plain_test_connector_config(&remote_connector(), "Degraded remote");
    remote_config["env"]["FCP_TEST_CONNECTOR_HEALTH"] = json!("degraded");
    let _executor = mesh.spawn("node-b", vec![remote_config]).await?;
    let entry = mesh
        .spawn(
            "node-a",
            vec![plain_test_connector_config(&local_id, "Healthy local")],
        )
        .await?;
    let baseline: Value = http_post_json(
        entry.client.clone(),
        format!("{}/doctor", entry.base_url),
        json!({"zone_id": "z:work", "self_check": false}),
    )
    .await?;
    let response: Value = http_post_json(
        entry.client.clone(),
        format!("{}/doctor", entry.base_url),
        json!({
            "zone_id": "z:work",
            "connectors": [local_id.as_str(), REMOTE_CONNECTOR],
            "self_check": true,
        }),
    )
    .await?;
    assert_eq!(response["overall_status"], "WARN", "{response}");
    for field in [
        "schema_version",
        "zone_id",
        "checkpoint",
        "revocation",
        "audit",
        "transport_policy",
        "store_coverage",
        "degraded_mode",
    ] {
        assert_eq!(
            response[field], baseline[field],
            "peer diagnostics must not replace the entry host's {field}"
        );
    }
    let checks = response["connector_self_checks"].as_array().expect("self-check results");
    assert_eq!(checks.len(), 2);
    let local = checks
        .iter()
        .find(|check| check["connector_id"] == local_id.as_str())
        .expect("local diagnostic");
    let remote = checks
        .iter()
        .find(|check| check["connector_id"] == REMOTE_CONNECTOR)
        .expect("remote diagnostic");
    assert_eq!(local["report"]["status"], "ok");
    assert_eq!(remote["report"]["status"], "degraded");
    assert_eq!(remote["report"]["reason_code"], "fixture_degraded");
    assert!(local["report"]["details"]["handshake_count"].is_u64());
    assert!(remote["report"]["details"]["handshake_count"].is_u64());
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn doctor_preserves_local_failures_and_denies_wrong_zone_before_runtime_diagnostics()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let mesh = MeshFixture::new(&["node-a", "node-b"])?;
    let _peer = mesh
        .spawn(
            "node-b",
            vec![plain_test_connector_config(&remote_connector(), "Healthy remote")],
        )
        .await?;
    let mut local_config = plain_test_connector_config(&remote_connector(), "Failing local");
    local_config["env"]["FCP_TEST_CONNECTOR_HEALTH"] = json!("error");
    let entry = mesh.spawn("node-a", vec![local_config]).await?;
    for (zone, expected_reason) in [
        ("z:work", "fixture_unavailable"),
        ("z:private", "self_check_zone_denied"),
    ] {
        let response: Value = http_post_json(
            entry.client.clone(),
            format!("{}/doctor", entry.base_url),
            json!({
                "zone_id": zone,
                "connectors": [REMOTE_CONNECTOR],
                "self_check": true,
            }),
        )
        .await?;
        assert_eq!(response["overall_status"], "FAIL", "{response}");
        let checks = response["connector_self_checks"].as_array().expect("self-check results");
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0]["connector_id"], REMOTE_CONNECTOR);
        assert_eq!(checks[0]["report"]["status"], "failed");
        assert_eq!(checks[0]["report"]["reason_code"], expected_reason);
    }
    Ok(())
}

#[fcp_async_core::runtime::test(flavor = "multi_thread")]
async fn forwarded_self_check_is_zone_bound_authenticated_replay_guarded_and_local_only()
-> Result<(), Box<dyn std::error::Error>> {
    let _guard = host_e2e_lock().await;
    let mesh = MeshFixture::new(&["node-a", "node-b"])?;
    let executor = mesh
        .spawn(
            "node-b",
            vec![plain_test_connector_config(&remote_connector(), "Remote diagnostics")],
        )
        .await?;
    let entry = mesh.spawn("node-a", Vec::new()).await?;
    let request = MeshForwardEnvelope::sign(
        &mesh.node("node-a").key,
        TailscaleNodeId::new("node-a"),
        TailscaleNodeId::new("node-b"),
        fcp_host::mesh_routing::unix_now_ms(),
        MeshForwardBody::SelfCheck {
            connector_id: REMOTE_CONNECTOR.to_owned(),
            zone_id: "z:work".to_owned(),
        },
    )?;
    let mut tampered = request.clone();
    tampered.body = MeshForwardBody::SelfCheck {
        connector_id: REMOTE_CONNECTOR.to_owned(),
        zone_id: "z:private".to_owned(),
    };
    let (status, body) = post_raw(&executor, "/rpc/mesh/forward", &tampered).await?;
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED, "{body}");

    let (status, body) = post_raw(&executor, "/rpc/mesh/forward", &request).await?;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    let reply: MeshForwardReply = serde_json::from_str(&body)?;
    let directory = fcp_mesh::invoke_route::MeshPeerDirectory::from_json(
        TailscaleNodeId::new("node-a"),
        &mesh.peers_json,
    )?;
    reply.verify_for(&request, &directory)?;
    assert!(reply.is_success(), "{body}");
    let report: Value = serde_json::from_str(&reply.body_json)?;
    assert_eq!(report["connector_id"], REMOTE_CONNECTOR);
    assert_eq!(report["zone_id"], "z:work");
    assert_eq!(report["report"]["status"], "ok");
    assert!(report["report"]["details"]["handshake_count"].is_u64());
    let (status, body) = post_raw(&executor, "/rpc/mesh/forward", &request).await?;
    assert_eq!(status, reqwest::StatusCode::CONFLICT, "{body}");

    let private_request = MeshForwardEnvelope::sign(
        &mesh.node("node-a").key,
        TailscaleNodeId::new("node-a"),
        TailscaleNodeId::new("node-b"),
        fcp_host::mesh_routing::unix_now_ms(),
        MeshForwardBody::SelfCheck {
            connector_id: REMOTE_CONNECTOR.to_owned(),
            zone_id: "z:private".to_owned(),
        },
    )?;
    let (status, body) = post_raw(&executor, "/rpc/mesh/forward", &private_request).await?;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    let denied: MeshForwardReply = serde_json::from_str(&body)?;
    denied.verify_for(&private_request, &directory)?;
    assert_eq!(denied.status, reqwest::StatusCode::FORBIDDEN.as_u16());

    // This node can discover the remote connector, but a signed executor
    // request must never bounce recursively to another peer.
    let missing_local = MeshForwardEnvelope::sign(
        &mesh.node("node-b").key,
        TailscaleNodeId::new("node-b"),
        TailscaleNodeId::new("node-a"),
        fcp_host::mesh_routing::unix_now_ms(),
        MeshForwardBody::SelfCheck {
            connector_id: REMOTE_CONNECTOR.to_owned(),
            zone_id: "z:work".to_owned(),
        },
    )?;
    let (status, body) = post_raw(&entry, "/rpc/mesh/forward", &missing_local).await?;
    assert_eq!(status, reqwest::StatusCode::OK, "{body}");
    let absent: MeshForwardReply = serde_json::from_str(&body)?;
    let peer_directory = fcp_mesh::invoke_route::MeshPeerDirectory::from_json(
        TailscaleNodeId::new("node-b"),
        &mesh.peers_json,
    )?;
    absent.verify_for(&missing_local, &peer_directory)?;
    assert_eq!(absent.status, reqwest::StatusCode::NOT_FOUND.as_u16());
    Ok(())
}
