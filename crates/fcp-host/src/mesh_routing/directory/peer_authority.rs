//! Request-scoped authority that survives unrelated membership changes.
//!
//! A directory generation is a publication boundary, not the identity of every
//! member. Keep an opaque epoch for each continuously authorized (node, key,
//! endpoint) binding. Renewals and edits to other peers preserve that epoch;
//! removal or changing either the key or endpoint replaces it. Retaining the
//! old Arc prevents remove/re-add and rotate/restore ABA from reviving a call.
//!
//! This is process-local continuity, not a new trust root or lease election.
//! Callers must check the live publication's validity and failure state before
//! capturing or checking a snapshot. No checkpoint format or signing key changes.

use std::collections::BTreeMap;
use std::sync::Arc;

use fcp_core::TailscaleNodeId;
use fcp_mesh::invoke_route::{MeshForwardError, MeshPeer, MeshPeerDirectory};

#[derive(Debug)]
struct PeerEpoch;

#[derive(Debug)]
struct PeerEntry {
    peer: MeshPeer,
    epoch: Arc<PeerEpoch>,
}

/// A single peer's authority, captured atomically with its verification directory.
#[derive(Debug)]
pub(in crate::mesh_routing) struct PeerSnapshot {
    directory: Arc<MeshPeerDirectory>,
    node_id: TailscaleNodeId,
    // None is reserved for explicit static-directory routers. It never passes
    // a signed membership continuity check.
    epoch: Option<Arc<PeerEpoch>>,
}

impl PeerSnapshot {
    /// Static configurations cannot hot-reload and retain their directory fence.
    pub(in crate::mesh_routing) fn unversioned(
        directory: Arc<MeshPeerDirectory>,
        node_id: &TailscaleNodeId,
    ) -> Result<Self, MeshForwardError> {
        if directory.peer(node_id).is_none() {
            return Err(MeshForwardError::UnknownPeer(node_id.as_str().to_owned()));
        }
        Ok(Self {
            directory,
            node_id: node_id.clone(),
            epoch: None,
        })
    }

    /// Immutable keys and endpoint used when this particular call was admitted.
    pub(in crate::mesh_routing) fn directory(&self) -> &Arc<MeshPeerDirectory> {
        &self.directory
    }
}

/// Continuity markers published together with a complete verified directory.
#[derive(Debug)]
pub(super) struct PeerContinuity {
    entries: BTreeMap<String, PeerEntry>,
}

impl PeerContinuity {
    pub(super) fn new(directory: &MeshPeerDirectory) -> Self {
        Self {
            entries: BTreeMap::new(),
        }
        .successor(directory)
    }

    /// Build the next view without mutating snapshots held by in-flight calls.
    pub(super) fn successor(&self, directory: &MeshPeerDirectory) -> Self {
        let entries = directory
            .peers()
            .map(|peer| {
                let epoch = self
                    .entries
                    .get(peer.node_id.as_str())
                    .filter(|previous| &previous.peer == peer)
                    .map_or_else(|| Arc::new(PeerEpoch), |previous| Arc::clone(&previous.epoch));
                (
                    peer.node_id.as_str().to_owned(),
                    PeerEntry {
                        peer: peer.clone(),
                        epoch,
                    },
                )
            })
            .collect();
        Self { entries }
    }

    pub(super) fn snapshot(
        &self,
        directory: Arc<MeshPeerDirectory>,
        node_id: &TailscaleNodeId,
    ) -> Result<PeerSnapshot, MeshForwardError> {
        let entry = self
            .entries
            .get(node_id.as_str())
            .ok_or_else(|| MeshForwardError::UnknownPeer(node_id.as_str().to_owned()))?;
        // Never combine the epoch of one publication with another one's key.
        if directory.peer(node_id) != Some(&entry.peer) {
            return Err(authority_changed());
        }
        Ok(PeerSnapshot {
            directory,
            node_id: node_id.clone(),
            epoch: Some(Arc::clone(&entry.epoch)),
        })
    }

    pub(super) fn check(&self, snapshot: &PeerSnapshot) -> Result<(), MeshForwardError> {
        match (
            self.entries.get(snapshot.node_id.as_str()),
            snapshot.epoch.as_ref(),
        ) {
            (Some(current), Some(expected)) if Arc::ptr_eq(&current.epoch, expected) => Ok(()),
            _ => Err(authority_changed()),
        }
    }
}

fn authority_changed() -> MeshForwardError {
    MeshForwardError::Malformed {
        field: "peer_directory",
        detail: "peer authority changed while the request was in flight".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_mesh::invoke_route::MeshPeerConfig;

    use super::*;

    fn directory(peers: &[(&str, u8, u16)]) -> Arc<MeshPeerDirectory> {
        let configs: Vec<_> = peers
            .iter()
            .map(|(id, seed, port)| {
                let key = Ed25519SigningKey::from_bytes(&[*seed; 32]).unwrap();
                MeshPeerConfig {
                    node_id: (*id).to_owned(),
                    endpoint: format!("http://127.0.0.1:{port}"),
                    public_key_hex: hex::encode(key.verifying_key().to_bytes()),
                }
            })
            .collect();
        Arc::new(MeshPeerDirectory::from_configs(TailscaleNodeId::new("local"), &configs).unwrap())
    }

    fn peer() -> TailscaleNodeId {
        TailscaleNodeId::new("peer")
    }

    #[test]
    fn identical_peer_in_a_new_directory_preserves_in_flight_authority() {
        let first = directory(&[("peer", 41, 19001)]);
        let continuity = PeerContinuity::new(&first);
        let snapshot = continuity.snapshot(Arc::clone(&first), &peer()).unwrap();
        let next = directory(&[("peer", 41, 19001)]);
        assert!(!Arc::ptr_eq(&first, &next));
        continuity.successor(&next).check(&snapshot).unwrap();
    }

    #[test]
    fn other_peer_join_rotation_and_removal_preserve_the_target() {
        let first = directory(&[("peer", 41, 19001)]);
        let mut continuity = PeerContinuity::new(&first);
        let snapshot = continuity.snapshot(Arc::clone(&first), &peer()).unwrap();
        for peers in [
            vec![("peer", 41, 19001), ("other", 42, 19002)],
            vec![("peer", 41, 19001), ("other", 43, 19003)],
            vec![("peer", 41, 19001)],
        ] {
            continuity = continuity.successor(&directory(&peers));
            continuity.check(&snapshot).unwrap();
        }
        assert_eq!(snapshot.directory().len(), 1, "old directory is immutable");
    }

    #[test]
    fn changing_target_key_or_endpoint_revokes_old_authority() {
        let first = directory(&[("peer", 41, 19001)]);
        let continuity = PeerContinuity::new(&first);
        let snapshot = continuity.snapshot(Arc::clone(&first), &peer()).unwrap();
        for changed in [vec![("peer", 42, 19001)], vec![("peer", 41, 19002)]] {
            let next = directory(&changed);
            let successor = continuity.successor(&next);
            assert!(successor.check(&snapshot).is_err());
            let fresh = successor.snapshot(next, &peer()).unwrap();
            successor.check(&fresh).unwrap();
        }
    }

    #[test]
    fn removal_and_readdition_do_not_revive_the_old_epoch() {
        let first = directory(&[("peer", 41, 19001)]);
        let continuity = PeerContinuity::new(&first);
        let snapshot = continuity.snapshot(Arc::clone(&first), &peer()).unwrap();
        let removed = continuity.successor(&directory(&[]));
        assert!(removed.check(&snapshot).is_err());
        let restored = removed.successor(&first);
        assert!(restored.check(&snapshot).is_err());
        restored.check(&restored.snapshot(first, &peer()).unwrap()).unwrap();
    }

    #[test]
    fn key_and_endpoint_round_trips_do_not_revive_the_old_epoch() {
        let first = directory(&[("peer", 41, 19001)]);
        let continuity = PeerContinuity::new(&first);
        let snapshot = continuity.snapshot(Arc::clone(&first), &peer()).unwrap();
        for changed in [vec![("peer", 42, 19001)], vec![("peer", 41, 19002)]] {
            let restored = continuity.successor(&directory(&changed)).successor(&first);
            assert!(restored.check(&snapshot).is_err());
        }
    }

    #[test]
    fn static_snapshots_cannot_impersonate_signed_authority() {
        let view = directory(&[("peer", 41, 19001)]);
        let continuity = PeerContinuity::new(&view);
        let snapshot = PeerSnapshot::unversioned(Arc::clone(&view), &peer()).unwrap();
        assert!(continuity.check(&snapshot).is_err());
        assert!(matches!(
            PeerSnapshot::unversioned(view, &TailscaleNodeId::new("unknown")),
            Err(MeshForwardError::UnknownPeer(_)),
        ));
    }

    #[test]
    fn mismatched_directory_and_continuity_are_not_combined() {
        let first = directory(&[("peer", 41, 19001)]);
        let continuity = PeerContinuity::new(&first);
        let wrong_key = directory(&[("peer", 42, 19001)]);
        assert!(continuity.snapshot(wrong_key, &peer()).is_err());
        assert!(matches!(
            continuity.snapshot(first, &TailscaleNodeId::new("unknown")),
            Err(MeshForwardError::UnknownPeer(_)),
        ));
    }
}
