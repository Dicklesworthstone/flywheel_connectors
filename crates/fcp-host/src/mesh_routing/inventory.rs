//! Operator inventory from current membership and authenticated advertisements.
//!
//! An advertisement proves what a configured peer recently advertised. It does
//! not prove health, current execution admission, replicated state, or quorum.
//! Missing evidence remains explicit instead of removing an unavailable peer
//! from the topology or promoting a configured target into a live connector.

use serde::{Deserialize, Serialize};

use super::{
    AdvertisedConnector, MeshPeerAdvertisement, MeshPeerDirectory, MeshRouter, unix_now_ms,
};

/// Admin-authenticated route exposing this host's current mesh inventory view.
pub const MESH_INVENTORY_ROUTE: &str = "/rpc/mesh/inventory";
/// Versioned operator inventory contract.
pub const MESH_INVENTORY_SCHEMA_VERSION: &str = "fcp.mesh.inventory.v1";

/// Authority available for the membership snapshot in this response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshInventoryMembershipStatus {
    /// This host has no configured mesh identity or peer directory.
    NotConfigured,
    /// Peer identities come from the operator's static configuration.
    Configured,
    /// Current membership is owner-signed and persistently checkpointed.
    OwnerSigned,
    /// Configured membership is expired, fenced, or changed during collection.
    Unavailable,
}

/// Evidence backing one node's connector inventory, independent of health.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshInventoryStatus {
    /// Direct local host configuration; no peer signature is implied.
    Local,
    /// Fresh advertisement authenticated against current peer membership.
    Verified,
    /// A configured peer supplied no currently usable signed inventory.
    Unavailable,
}

/// Minimal placement declaration without credentials, keys or runtime payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshInventoryConnector {
    /// Canonical connector identifier.
    pub connector_id: String,
    /// Declared allowed zones; an empty set grants no zone availability.
    pub zones: Vec<String>,
    /// Whether dispatch requires single-writer lease coordination.
    pub singleton_writer: bool,
}

/// One local or currently authorized peer node and its available evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshInventoryNode {
    /// Mesh identity, absent only for a local host without mesh configuration.
    pub node_id: Option<String>,
    /// Whether this entry is the selected host itself.
    pub is_local: bool,
    /// How the connector list was obtained; this is not a health classification.
    pub inventory_status: MeshInventoryStatus,
    /// Timestamp signed by the peer, absent for local or unavailable inventory.
    pub advertisement_issued_at_ms: Option<u64>,
    /// Age at collection; a permitted future timestamp has zero elapsed age.
    pub advertisement_age_ms: Option<u64>,
    /// Only direct local or authenticated peer connector declarations.
    pub connectors: Vec<MeshInventoryConnector>,
}

/// A bounded discovery snapshot served by the selected host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshInventoryResponse {
    /// Always [`MESH_INVENTORY_SCHEMA_VERSION`].
    pub schema_version: String,
    /// Host wall-clock time after discovery completed.
    pub generated_at_ms: u64,
    /// This host's configured mesh identity, if any.
    pub local_node_id: Option<String>,
    /// Whether mesh routing is configured, even when its authority is unusable.
    pub mesh_configured: bool,
    /// Membership authority used for this snapshot.
    pub membership_status: MeshInventoryMembershipStatus,
    /// Local entry first, then current peers in node-id order.
    pub nodes: Vec<MeshInventoryNode>,
    /// Bounded explanations of missing evidence and interpretation limits.
    pub warnings: Vec<String>,
}

impl MeshInventoryResponse {
    /// Report local configured connectors without inventing a mesh identity.
    #[must_use]
    pub fn local_only(connectors: Vec<AdvertisedConnector>) -> Self {
        Self::local_at(None, connectors, unix_now_ms())
    }

    fn local_at(
        node_id: Option<String>,
        connectors: Vec<AdvertisedConnector>,
        generated_at_ms: u64,
    ) -> Self {
        Self {
            schema_version: MESH_INVENTORY_SCHEMA_VERSION.to_owned(),
            generated_at_ms,
            mesh_configured: node_id.is_some(),
            local_node_id: node_id.clone(),
            membership_status: MeshInventoryMembershipStatus::NotConfigured,
            nodes: vec![MeshInventoryNode {
                node_id,
                is_local: true,
                inventory_status: MeshInventoryStatus::Local,
                advertisement_issued_at_ms: None,
                advertisement_age_ms: None,
                connectors: project_connectors(connectors),
            }],
            warnings: vec![
                "Connector inventories describe configuration and signed advertisements; they do not prove health, execution admission, state replication, or quorum."
                    .to_owned(),
            ],
        }
    }

    fn membership_unavailable(&mut self) {
        self.membership_status = MeshInventoryMembershipStatus::Unavailable;
        self.nodes.retain(|node| node.is_local);
        self.warnings.push(
            "Current mesh membership is unavailable or changed during discovery; peer inventory was withheld. Retry after membership is restored."
                .to_owned(),
        );
    }

    fn append_peers(
        &mut self,
        directory: &MeshPeerDirectory,
        advertisements: Vec<MeshPeerAdvertisement>,
    ) {
        let mut advertisements: std::collections::HashMap<_, _> = advertisements
            .into_iter()
            .map(|advertisement| (advertisement.node_id.clone(), advertisement))
            .collect();
        let mut unavailable = 0_usize;
        for peer in directory.peers() {
            let advertisement = advertisements
                .remove(&peer.node_id)
                .filter(|advertisement| {
                    advertisement
                        .verify(
                            &peer.node_id,
                            directory,
                            self.generated_at_ms,
                            fcp_mesh::invoke_route::DEFAULT_MESH_ADVERTISEMENT_MAX_AGE_MS,
                        )
                        .is_ok()
                });
            if advertisement.is_none() {
                unavailable += 1;
            }
            self.nodes.push(MeshInventoryNode {
                node_id: Some(peer.node_id.as_str().to_owned()),
                is_local: false,
                inventory_status: if advertisement.is_some() {
                    MeshInventoryStatus::Verified
                } else {
                    MeshInventoryStatus::Unavailable
                },
                advertisement_issued_at_ms: advertisement.as_ref().map(|value| value.issued_at_ms),
                advertisement_age_ms: advertisement
                    .as_ref()
                    .map(|value| self.generated_at_ms.saturating_sub(value.issued_at_ms)),
                connectors: advertisement
                    .map_or_else(Vec::new, |value| project_connectors(value.connectors)),
            });
        }
        if unavailable > 0 {
            self.warnings.push(format!(
                "{unavailable} configured peer(s) have no fresh authenticated inventory; their availability is unknown."
            ));
        }
    }
}

fn project_connectors(connectors: Vec<AdvertisedConnector>) -> Vec<MeshInventoryConnector> {
    let mut projected: Vec<_> = connectors
        .into_iter()
        .map(|connector| {
            let mut zones = connector.zones;
            zones.sort();
            zones.dedup();
            MeshInventoryConnector {
                connector_id: connector.connector_id,
                zones,
                singleton_writer: connector.singleton_writer,
            }
        })
        .collect();
    projected.sort_by(|left, right| left.connector_id.cmp(&right.connector_id));
    projected
}

impl MeshRouter {
    /// Collect current peer evidence with the same bounded discovery used by routing.
    ///
    /// Expired membership or a concurrent directory publication withholds the
    /// entire peer view. Local configuration remains visible. No caller-provided
    /// wall time, static target, or failed request can establish peer availability.
    pub async fn inventory(
        &self,
        local_connectors: Vec<AdvertisedConnector>,
    ) -> MeshInventoryResponse {
        let mut response = MeshInventoryResponse::local_at(
            Some(self.local_node().as_str().to_owned()),
            local_connectors,
            unix_now_ms(),
        );
        let Ok(snapshot) = self.trusted_directory() else {
            self.advertisements.invalidate();
            response.membership_unavailable();
            return response;
        };
        let advertisements = self
            .advertisements
            .collect(&snapshot, |peer| async move {
                self.fetch_advertisement(&peer.endpoint).await
            })
            .await;
        response.generated_at_ms = unix_now_ms();
        if self.ensure_current_directory(&snapshot).is_err() {
            self.advertisements.invalidate();
            response.membership_unavailable();
            return response;
        }
        response.membership_status = if self.has_owner_signed_membership() {
            MeshInventoryMembershipStatus::OwnerSigned
        } else {
            MeshInventoryMembershipStatus::Configured
        };
        response.append_peers(&snapshot, advertisements);
        // Signature projection can be nontrivial for large inventories. Do not
        // publish peers from a generation that expired or was replaced meanwhile.
        if self.ensure_current_directory(&snapshot).is_err() {
            response.membership_unavailable();
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use fcp_core::TailscaleNodeId;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_mesh::invoke_route::{DEFAULT_MESH_ADVERTISEMENT_MAX_AGE_MS, MeshPeerConfig};

    use super::*;

    fn connector(id: &str, zones: &[&str]) -> AdvertisedConnector {
        AdvertisedConnector {
            connector_id: id.to_owned(),
            zones: zones.iter().map(|zone| (*zone).to_owned()).collect(),
            singleton_writer: true,
            summary_json: Some("secret-summary-must-not-be-in-inventory".to_owned()),
        }
    }

    fn directory(key: &Ed25519SigningKey) -> MeshPeerDirectory {
        MeshPeerDirectory::from_configs(
            TailscaleNodeId::new("local"),
            &["peer-b", "peer-a"].map(|node| MeshPeerConfig {
                node_id: node.to_owned(),
                endpoint: "http://127.0.0.1:19001".to_owned(),
                public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            }),
        )
        .unwrap()
    }

    #[test]
    fn local_inventory_has_no_fabricated_mesh_identity_or_peer_proof() {
        let response = MeshInventoryResponse::local_only(vec![
            connector("slack", &["z:work", "z:work", "z:private"]),
            connector("github", &[]),
        ]);
        assert!(!response.mesh_configured);
        assert_eq!(response.local_node_id, None);
        assert_eq!(
            response.membership_status,
            MeshInventoryMembershipStatus::NotConfigured
        );
        assert_eq!(response.nodes.len(), 1);
        let local = &response.nodes[0];
        assert_eq!(local.inventory_status, MeshInventoryStatus::Local);
        assert!(local.advertisement_issued_at_ms.is_none());
        assert!(local.advertisement_age_ms.is_none());
        assert_eq!(local.connectors[0].connector_id, "github");
        assert!(local.connectors[0].zones.is_empty());
        assert_eq!(local.connectors[1].zones, ["z:private", "z:work"]);
        let encoded = serde_json::to_string(&response).unwrap();
        assert!(!encoded.contains("secret-summary"));
        assert!(!encoded.contains("public_key"));
        assert!(!encoded.contains("endpoint"));
        assert_eq!(
            serde_json::from_str::<MeshInventoryResponse>(&encoded).unwrap(),
            response
        );
    }

    #[test]
    fn signed_inventory_keeps_unavailable_peers_and_never_infers_health() {
        let key = Ed25519SigningKey::generate();
        let directory = directory(&key);
        let now = 1_000_000;
        let advertisement = MeshPeerAdvertisement::sign(
            &key,
            TailscaleNodeId::new("peer-b"),
            now - 125,
            vec![connector("github", &["z:work"])],
        );
        let mut response = MeshInventoryResponse::local_at(Some("local".into()), vec![], now);
        response.append_peers(&directory, vec![advertisement]);
        assert_eq!(response.nodes.len(), 3);
        assert_eq!(response.nodes[1].node_id.as_deref(), Some("peer-a"));
        assert_eq!(
            response.nodes[1].inventory_status,
            MeshInventoryStatus::Unavailable
        );
        assert!(response.nodes[1].connectors.is_empty());
        let verified = &response.nodes[2];
        assert_eq!(verified.node_id.as_deref(), Some("peer-b"));
        assert_eq!(verified.inventory_status, MeshInventoryStatus::Verified);
        assert_eq!(verified.advertisement_age_ms, Some(125));
        assert_eq!(verified.advertisement_issued_at_ms, Some(now - 125));
        assert_eq!(verified.connectors[0].connector_id, "github");
        assert!(
            response
                .warnings
                .iter()
                .any(|warning| warning.contains("1 configured peer"))
        );
        let node_json = serde_json::to_value(verified).unwrap();
        for absent in [
            "health",
            "is_available",
            "replica_count",
            "quorum",
            "summary_json",
        ] {
            assert!(node_json.get(absent).is_none(), "{absent}");
        }
    }

    #[test]
    fn forged_stale_future_and_nonmember_inventories_are_withheld() {
        let key = Ed25519SigningKey::generate();
        let other_key = Ed25519SigningKey::generate();
        let directory = directory(&key);
        let now = 1_000_000;
        for (signer, node, issued_at) in [
            (&other_key, "peer-a", now),
            (
                &key,
                "peer-a",
                now - DEFAULT_MESH_ADVERTISEMENT_MAX_AGE_MS - 1,
            ),
            (
                &key,
                "peer-a",
                now + DEFAULT_MESH_ADVERTISEMENT_MAX_AGE_MS + 1,
            ),
            (&key, "removed-node", now),
        ] {
            let advertisement = MeshPeerAdvertisement::sign(
                signer,
                TailscaleNodeId::new(node),
                issued_at,
                vec![connector("forged", &["z:owner"])],
            );
            let mut response = MeshInventoryResponse::local_at(Some("local".into()), vec![], now);
            response.append_peers(&directory, vec![advertisement]);
            assert_eq!(response.nodes.len(), 3);
            for peer in &response.nodes[1..] {
                assert_eq!(peer.inventory_status, MeshInventoryStatus::Unavailable);
                assert!(peer.connectors.is_empty());
                assert!(peer.advertisement_issued_at_ms.is_none());
            }
        }
    }

    #[test]
    fn membership_failure_withholds_all_remote_names_and_preserves_local_configuration() {
        let key = Ed25519SigningKey::generate();
        let mut response = MeshInventoryResponse::local_at(
            Some("local".into()),
            vec![connector("local-connector", &["z:work"])],
            1_000_000,
        );
        response.append_peers(&directory(&key), vec![]);
        response.membership_unavailable();
        assert_eq!(
            response.membership_status,
            MeshInventoryMembershipStatus::Unavailable
        );
        assert!(response.mesh_configured);
        assert_eq!(response.nodes.len(), 1);
        assert_eq!(
            response.nodes[0].connectors[0].connector_id,
            "local-connector"
        );
        assert!(!serde_json::to_string(&response).unwrap().contains("peer-a"));
    }

    #[fcp_async_core::runtime::test]
    async fn live_inventory_fetches_and_authenticates_loopback_advertisement() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let peer_key = Ed25519SigningKey::generate();
        let advertisement = MeshPeerAdvertisement::sign(
            &peer_key,
            TailscaleNodeId::new("peer"),
            unix_now_ms(),
            vec![connector("github", &["z:work"])],
        );
        let body = serde_json::to_string(&advertisement).unwrap();
        let server = std::thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            connection
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !bytes.windows(4).any(|part| part == b"\r\n\r\n") {
                let received = connection.read(&mut buffer).unwrap();
                assert!(received > 0);
                bytes.extend_from_slice(&buffer[..received]);
                assert!(bytes.len() <= 8192);
            }
            assert!(
                String::from_utf8(bytes)
                    .unwrap()
                    .starts_with("GET /rpc/mesh/advertisement HTTP/1.1\r\n")
            );
            write!(connection, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        });
        let router = MeshRouter::new(super::super::MeshRoutingSettings {
            node_id: TailscaleNodeId::new("local"),
            signing_key: Ed25519SigningKey::generate(),
            peers_json: serde_json::to_string(&[MeshPeerConfig {
                node_id: "peer".into(),
                endpoint,
                public_key_hex: hex::encode(peer_key.verifying_key().to_bytes()),
            }])
            .unwrap(),
            forward_timeout: Duration::from_secs(5),
        })
        .unwrap();
        let response = router
            .inventory(vec![connector("local-connector", &["z:private"])])
            .await;
        server.join().unwrap();
        assert_eq!(
            response.membership_status,
            MeshInventoryMembershipStatus::Configured
        );
        assert_eq!(response.nodes.len(), 2);
        assert_eq!(
            response.nodes[0].inventory_status,
            MeshInventoryStatus::Local
        );
        assert_eq!(
            response.nodes[1].inventory_status,
            MeshInventoryStatus::Verified
        );
        assert_eq!(response.nodes[1].connectors[0].connector_id, "github");
        assert_eq!(response.nodes[1].connectors[0].zones, ["z:work"]);
        // Shared discovery cache preserves authenticated evidence without
        // requiring the one-shot server to remain reachable on every read.
        let cached = router.inventory(vec![]).await;
        assert_eq!(
            cached.nodes[1].inventory_status,
            MeshInventoryStatus::Verified
        );
    }
}
