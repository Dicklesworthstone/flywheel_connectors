#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

use std::fs;
use std::path::Path;

use fcp_cbor::{CanonicalSerializer, SchemaId, SerializationError};
use semver::Version;
use thiserror::Error;

use crate::local_mesh::{
    LocalChaosMode, LocalFailoverInvariantReport, LocalMeshHarnessError, LocalNodeReplayTimeline,
    LocalNodeSnapshot, LocalNodeStateHash, LocalReplayBundle, LocalReplayBundlePaths,
    LocalReplayHashes, LocalReplayManifest, LocalRoleTransition,
};

const SNAPSHOT_STAGES: [&str; 4] = [
    "state_at_t0.cbor",
    "state_at_chaos.cbor",
    "state_at_heal.cbor",
    "state_at_end.cbor",
];

const FORBIDDEN_REPLAY_MARKERS: &[&str] = &[
    "mesh-harness-node-",
    "authorization",
    "bearer",
    "cookie",
    "password",
    "secret",
    "token",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedactedReplayBundleSummary {
    pub scenario_id: String,
    pub seed_index: u64,
    pub chaos_mode: LocalChaosMode,
    pub node_count: usize,
    pub event_count: usize,
    pub timeline_count: usize,
    pub snapshot_file_count: usize,
    pub final_state_hash: String,
    pub per_node_state_hash_count: usize,
    pub active_holder_hash: String,
    pub online_node_count: usize,
    pub all_nodes_online_at_end: bool,
    pub orphaned_active_lease_count: usize,
    pub orphaned_connector_state_count: usize,
    pub invalid_receipt_signature_count: usize,
}

#[derive(Debug, Error)]
pub enum RedactedReplayBundleError {
    #[error("replay artifact `{context}` contains forbidden marker `{marker}`")]
    RedactionLeak {
        context: String,
        marker: &'static str,
    },
    #[error("replay bundle failed in-memory redaction scan")]
    InMemoryRedaction,
    #[error("replay manifest result must be `pass`, got `{0}`")]
    ManifestResult(String),
    #[error("replay manifest node count {actual} did not match expected {expected}")]
    NodeCountMismatch { expected: usize, actual: usize },
    #[error("replay bundle had no transition events")]
    EmptyEvents,
    #[error("replay event {index} in `{artifact}` has an empty node_id_hash")]
    EmptyEventNodeHash { artifact: String, index: usize },
    #[error("replay artifact `{artifact}` field `{field}` had length {actual}; expected 64")]
    HashLengthMismatch {
        artifact: String,
        field: &'static str,
        actual: usize,
    },
    #[error("replay artifact `{artifact}` field `{field}` is not lowercase hex")]
    HashNotHex {
        artifact: String,
        field: &'static str,
    },
    #[error("replay bundle had {actual} node snapshots; expected {expected}")]
    NodeSnapshotCountMismatch { expected: usize, actual: usize },
    #[error("replay bundle had {actual} node timelines; expected {expected}")]
    NodeTimelineCountMismatch { expected: usize, actual: usize },
    #[error("replay timeline `{artifact}` has an empty node_id_hash")]
    EmptyTimelineNodeHash { artifact: String },
    #[error("replay snapshot `{artifact}` has an empty node_id_hash")]
    EmptySnapshotNodeHash { artifact: String },
    #[error("replay bundle had {actual} per-node state hashes; expected {expected}")]
    PerNodeStateHashCountMismatch { expected: usize, actual: usize },
    #[error("per-node state hash `{artifact}` has an empty node_id_hash")]
    EmptyPerNodeStateHash { artifact: String },
    #[error("replay invariants `{artifact}` has an empty active_holder_hash")]
    EmptyActiveHolderHash { artifact: String },
    #[error("replay invariants online node count {actual} did not match expected {expected}")]
    OnlineNodeCountMismatch { expected: usize, actual: usize },
    #[error("replay invariants did not report all nodes online at end")]
    NodesOfflineAtEnd,
    #[error("replay invariants orphaned active lease count {actual}; expected 0")]
    OrphanedActiveLeaseCount { actual: usize },
    #[error("replay invariants orphaned connector state count {actual}; expected 0")]
    OrphanedConnectorStateCount { actual: usize },
    #[error("replay invariants invalid receipt signature count {actual}; expected 0")]
    InvalidReceiptSignatureCount { actual: usize },
    #[error("replay artifact `{artifact}` I/O failed: {source}")]
    Io {
        artifact: String,
        source: std::io::Error,
    },
    #[error("failed to decode JSON replay artifact `{artifact}`: {source}")]
    Json {
        artifact: String,
        source: serde_json::Error,
    },
    #[error("failed to decode CBOR replay snapshot `{artifact}`: {source}")]
    Cbor {
        artifact: String,
        source: SerializationError,
    },
    #[error("local mesh replay bundle helper failed: {0}")]
    LocalMesh(#[from] LocalMeshHarnessError),
}

pub fn assert_redaction_safe_str(
    context: &str,
    body: &str,
) -> Result<(), RedactedReplayBundleError> {
    let normalized = body.to_ascii_lowercase();
    if let Some(marker) = FORBIDDEN_REPLAY_MARKERS
        .iter()
        .copied()
        .find(|marker| normalized.contains(marker))
    {
        return Err(RedactedReplayBundleError::RedactionLeak {
            context: context.to_string(),
            marker,
        });
    }
    Ok(())
}

pub fn verify_in_memory_replay_bundle(
    bundle: &LocalReplayBundle,
    expected_node_count: usize,
) -> Result<RedactedReplayBundleSummary, RedactedReplayBundleError> {
    let artifact = "in-memory LocalReplayBundle";
    let bundle_json =
        serde_json::to_string(bundle).map_err(|source| RedactedReplayBundleError::Json {
            artifact: artifact.to_string(),
            source,
        })?;
    ensure_text_redacted(artifact, &bundle_json)?;
    if !bundle.is_redaction_safe()? {
        return Err(RedactedReplayBundleError::InMemoryRedaction);
    }

    ensure_events_shape(artifact, &bundle.events)?;
    ensure_snapshots_shape(artifact, &bundle.node_snapshots, expected_node_count)?;
    ensure_timelines_shape(artifact, &bundle.node_timelines, expected_node_count)?;
    ensure_replay_shape(
        &bundle.manifest,
        bundle.events.len(),
        bundle.node_timelines.len(),
        bundle.node_timelines.len() * SNAPSHOT_STAGES.len(),
        &bundle.invariants,
        &bundle.hashes,
        expected_node_count,
    )
}

pub fn verify_written_replay_bundle(
    paths: &LocalReplayBundlePaths,
    expected_node_count: usize,
) -> Result<RedactedReplayBundleSummary, RedactedReplayBundleError> {
    let manifest_text = read_text_artifact(&paths.manifest)?;
    ensure_text_redacted(&artifact_name(&paths.manifest), &manifest_text)?;
    let manifest: LocalReplayManifest = decode_json_artifact(&paths.manifest, &manifest_text)?;

    let events_text = read_text_artifact(&paths.events)?;
    ensure_text_redacted(&artifact_name(&paths.events), &events_text)?;
    let events = decode_events_jsonl(&paths.events, &events_text)?;

    let hashes_text = read_text_artifact(&paths.hashes)?;
    ensure_text_redacted(&artifact_name(&paths.hashes), &hashes_text)?;
    let hashes: LocalReplayHashes = decode_json_artifact(&paths.hashes, &hashes_text)?;

    let invariants_text = read_text_artifact(&paths.invariants)?;
    ensure_text_redacted(&artifact_name(&paths.invariants), &invariants_text)?;
    let invariants: LocalFailoverInvariantReport =
        decode_json_artifact(&paths.invariants, &invariants_text)?;

    ensure_events_shape(&artifact_name(&paths.events), &events)?;
    let snapshot_file_count = verify_snapshot_tree(&paths.snapshot_root, expected_node_count)?;

    ensure_replay_shape(
        &manifest,
        events.len(),
        expected_node_count,
        snapshot_file_count,
        &invariants,
        &hashes,
        expected_node_count,
    )
}

fn ensure_replay_shape(
    manifest: &LocalReplayManifest,
    event_count: usize,
    timeline_count: usize,
    snapshot_file_count: usize,
    invariants: &LocalFailoverInvariantReport,
    hashes: &LocalReplayHashes,
    expected_node_count: usize,
) -> Result<RedactedReplayBundleSummary, RedactedReplayBundleError> {
    if manifest.result != "pass" {
        return Err(RedactedReplayBundleError::ManifestResult(
            manifest.result.clone(),
        ));
    }
    if manifest.node_count != expected_node_count {
        return Err(RedactedReplayBundleError::NodeCountMismatch {
            expected: expected_node_count,
            actual: manifest.node_count,
        });
    }
    if event_count == 0 {
        return Err(RedactedReplayBundleError::EmptyEvents);
    }
    if timeline_count != expected_node_count {
        return Err(RedactedReplayBundleError::NodeTimelineCountMismatch {
            expected: expected_node_count,
            actual: timeline_count,
        });
    }
    ensure_invariants_shape("replay invariants", invariants, expected_node_count)?;
    ensure_hashes_shape("replay hashes", hashes, expected_node_count)?;

    Ok(RedactedReplayBundleSummary {
        scenario_id: manifest.scenario_id.clone(),
        seed_index: manifest.seed_index,
        chaos_mode: manifest.chaos_mode,
        node_count: manifest.node_count,
        event_count,
        timeline_count,
        snapshot_file_count,
        final_state_hash: hashes.final_state_hash.clone(),
        per_node_state_hash_count: hashes.per_node_state_hashes.len(),
        active_holder_hash: invariants.active_holder_hash.clone(),
        online_node_count: invariants.online_node_count,
        all_nodes_online_at_end: invariants.all_nodes_online_at_end,
        orphaned_active_lease_count: invariants.orphaned_active_lease_count,
        orphaned_connector_state_count: invariants.orphaned_connector_state_count,
        invalid_receipt_signature_count: invariants.invalid_receipt_signature_count,
    })
}

fn ensure_events_shape(
    artifact: &str,
    events: &[LocalRoleTransition],
) -> Result<(), RedactedReplayBundleError> {
    if events.is_empty() {
        return Err(RedactedReplayBundleError::EmptyEvents);
    }

    for (index, event) in events.iter().enumerate() {
        if event.node_id_hash.is_empty() {
            return Err(RedactedReplayBundleError::EmptyEventNodeHash {
                artifact: artifact.to_string(),
                index,
            });
        }
        ensure_hash_field(artifact, "event.node_id_hash", &event.node_id_hash)?;
        if let Some(target_hash) = &event.lease_handoff_target_hash {
            ensure_hash_field(artifact, "event.lease_handoff_target_hash", target_hash)?;
        }
    }

    Ok(())
}

fn ensure_snapshots_shape(
    artifact: &str,
    snapshots: &[LocalNodeSnapshot],
    expected_node_count: usize,
) -> Result<(), RedactedReplayBundleError> {
    if snapshots.len() != expected_node_count {
        return Err(RedactedReplayBundleError::NodeSnapshotCountMismatch {
            expected: expected_node_count,
            actual: snapshots.len(),
        });
    }

    for snapshot in snapshots {
        ensure_snapshot_redacted(artifact, snapshot)?;
    }

    Ok(())
}

fn ensure_timelines_shape(
    artifact: &str,
    timelines: &[LocalNodeReplayTimeline],
    expected_node_count: usize,
) -> Result<(), RedactedReplayBundleError> {
    if timelines.len() != expected_node_count {
        return Err(RedactedReplayBundleError::NodeTimelineCountMismatch {
            expected: expected_node_count,
            actual: timelines.len(),
        });
    }

    for timeline in timelines {
        if timeline.node_id_hash.is_empty() {
            return Err(RedactedReplayBundleError::EmptyTimelineNodeHash {
                artifact: artifact.to_string(),
            });
        }
        ensure_hash_field(artifact, "timeline.node_id_hash", &timeline.node_id_hash)?;
        ensure_snapshot_redacted(artifact, &timeline.state_at_t0)?;
        ensure_snapshot_redacted(artifact, &timeline.state_at_chaos)?;
        ensure_snapshot_redacted(artifact, &timeline.state_at_heal)?;
        ensure_snapshot_redacted(artifact, &timeline.state_at_end)?;
    }

    Ok(())
}

fn ensure_hashes_shape(
    artifact: &str,
    hashes: &LocalReplayHashes,
    expected_node_count: usize,
) -> Result<(), RedactedReplayBundleError> {
    ensure_hash_field(artifact, "final_state_hash", &hashes.final_state_hash)?;
    ensure_hash_field(artifact, "receipt_hash", &hashes.receipt_hash)?;
    ensure_hash_field(artifact, "transition_hash", &hashes.transition_hash)?;
    if hashes.per_node_state_hashes.len() != expected_node_count {
        return Err(RedactedReplayBundleError::PerNodeStateHashCountMismatch {
            expected: expected_node_count,
            actual: hashes.per_node_state_hashes.len(),
        });
    }

    for state_hash in &hashes.per_node_state_hashes {
        ensure_state_hash_redacted(artifact, state_hash)?;
    }

    Ok(())
}

fn ensure_invariants_shape(
    artifact: &str,
    invariants: &LocalFailoverInvariantReport,
    expected_node_count: usize,
) -> Result<(), RedactedReplayBundleError> {
    if invariants.active_holder_hash.is_empty() {
        return Err(RedactedReplayBundleError::EmptyActiveHolderHash {
            artifact: artifact.to_string(),
        });
    }
    ensure_hash_field(
        artifact,
        "active_holder_hash",
        &invariants.active_holder_hash,
    )?;
    if invariants.online_node_count != expected_node_count {
        return Err(RedactedReplayBundleError::OnlineNodeCountMismatch {
            expected: expected_node_count,
            actual: invariants.online_node_count,
        });
    }
    if !invariants.all_nodes_online_at_end {
        return Err(RedactedReplayBundleError::NodesOfflineAtEnd);
    }
    if invariants.orphaned_active_lease_count != 0 {
        return Err(RedactedReplayBundleError::OrphanedActiveLeaseCount {
            actual: invariants.orphaned_active_lease_count,
        });
    }
    if invariants.orphaned_connector_state_count != 0 {
        return Err(RedactedReplayBundleError::OrphanedConnectorStateCount {
            actual: invariants.orphaned_connector_state_count,
        });
    }
    if invariants.invalid_receipt_signature_count != 0 {
        return Err(RedactedReplayBundleError::InvalidReceiptSignatureCount {
            actual: invariants.invalid_receipt_signature_count,
        });
    }
    Ok(())
}

fn ensure_state_hash_redacted(
    artifact: &str,
    state_hash: &LocalNodeStateHash,
) -> Result<(), RedactedReplayBundleError> {
    if state_hash.node_id_hash.is_empty() {
        return Err(RedactedReplayBundleError::EmptyPerNodeStateHash {
            artifact: artifact.to_string(),
        });
    }
    ensure_hash_field(
        artifact,
        "per_node_state_hash.node_id_hash",
        &state_hash.node_id_hash,
    )?;
    ensure_hash_field(
        artifact,
        "per_node_state_hash.state_hash",
        &state_hash.state_hash,
    )
}

fn verify_snapshot_tree(
    snapshot_root: &Path,
    expected_node_count: usize,
) -> Result<usize, RedactedReplayBundleError> {
    let mut node_dirs = fs::read_dir(snapshot_root)
        .map_err(|source| RedactedReplayBundleError::Io {
            artifact: artifact_name(snapshot_root),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| RedactedReplayBundleError::Io {
            artifact: artifact_name(snapshot_root),
            source,
        })?;
    node_dirs.sort_by_key(std::fs::DirEntry::file_name);

    if node_dirs.len() != expected_node_count {
        return Err(RedactedReplayBundleError::NodeTimelineCountMismatch {
            expected: expected_node_count,
            actual: node_dirs.len(),
        });
    }

    let mut snapshot_file_count = 0;
    for entry in node_dirs {
        let node_dir = entry.path();
        for stage in SNAPSHOT_STAGES {
            let snapshot_path = node_dir.join(stage);
            let bytes = read_binary_artifact(&snapshot_path)?;
            ensure_bytes_redacted(&artifact_name(&snapshot_path), &bytes)?;
            let snapshot = decode_snapshot(&snapshot_path, &bytes)?;
            ensure_snapshot_redacted(&artifact_name(&snapshot_path), &snapshot)?;
            snapshot_file_count += 1;
        }
    }

    Ok(snapshot_file_count)
}

fn decode_events_jsonl(
    path: &Path,
    text: &str,
) -> Result<Vec<LocalRoleTransition>, RedactedReplayBundleError> {
    let mut events = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let event =
            serde_json::from_str(line).map_err(|source| RedactedReplayBundleError::Json {
                artifact: artifact_name(path),
                source,
            })?;
        events.push(event);
    }
    Ok(events)
}

fn decode_snapshot(
    path: &Path,
    bytes: &[u8],
) -> Result<LocalNodeSnapshot, RedactedReplayBundleError> {
    let schema = SchemaId::new("fcp.testkit", "LocalNodeSnapshot", Version::new(1, 0, 0));
    CanonicalSerializer::deserialize(bytes, &schema).map_err(|source| {
        RedactedReplayBundleError::Cbor {
            artifact: artifact_name(path),
            source,
        }
    })
}

fn ensure_snapshot_redacted(
    artifact: &str,
    snapshot: &LocalNodeSnapshot,
) -> Result<(), RedactedReplayBundleError> {
    if snapshot.node_id_hash.is_empty() {
        return Err(RedactedReplayBundleError::EmptySnapshotNodeHash {
            artifact: artifact.to_string(),
        });
    }
    ensure_hash_field(artifact, "snapshot.node_id_hash", &snapshot.node_id_hash)
}

fn read_text_artifact(path: &Path) -> Result<String, RedactedReplayBundleError> {
    fs::read_to_string(path).map_err(|source| RedactedReplayBundleError::Io {
        artifact: artifact_name(path),
        source,
    })
}

fn read_binary_artifact(path: &Path) -> Result<Vec<u8>, RedactedReplayBundleError> {
    fs::read(path).map_err(|source| RedactedReplayBundleError::Io {
        artifact: artifact_name(path),
        source,
    })
}

fn decode_json_artifact<T: serde::de::DeserializeOwned>(
    path: &Path,
    text: &str,
) -> Result<T, RedactedReplayBundleError> {
    serde_json::from_str(text).map_err(|source| RedactedReplayBundleError::Json {
        artifact: artifact_name(path),
        source,
    })
}

fn ensure_text_redacted(artifact: &str, text: &str) -> Result<(), RedactedReplayBundleError> {
    assert_redaction_safe_str(artifact, text)
}

fn ensure_hash_field(
    artifact: &str,
    field: &'static str,
    value: &str,
) -> Result<(), RedactedReplayBundleError> {
    ensure_text_redacted(artifact, value)?;
    if value.len() != 64 {
        return Err(RedactedReplayBundleError::HashLengthMismatch {
            artifact: artifact.to_string(),
            field,
            actual: value.len(),
        });
    }
    if !value
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(RedactedReplayBundleError::HashNotHex {
            artifact: artifact.to_string(),
            field,
        });
    }
    Ok(())
}

fn ensure_bytes_redacted(artifact: &str, bytes: &[u8]) -> Result<(), RedactedReplayBundleError> {
    let lowercase = bytes.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>();
    for marker in FORBIDDEN_REPLAY_MARKERS {
        if lowercase
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
        {
            return Err(RedactedReplayBundleError::RedactionLeak {
                context: artifact.to_string(),
                marker,
            });
        }
    }
    Ok(())
}

fn artifact_name(path: &Path) -> String {
    path.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_mesh::{LocalChaosMode, LocalMeshHarness};

    fn replay_bundle() -> LocalReplayBundle {
        let mut harness = LocalMeshHarness::new_three_node(23).expect("harness should build");
        harness
            .run_failover_scenario(LocalChaosMode::KillLeaderMidWrite)
            .expect("scenario should complete")
            .replay_bundle
    }

    #[test]
    fn verifier_rejects_short_event_node_hash() {
        let mut bundle = replay_bundle();
        bundle
            .events
            .first_mut()
            .expect("scenario should emit replay events")
            .node_id_hash = "abc123".to_string();

        let error = verify_in_memory_replay_bundle(&bundle, 3)
            .expect_err("short event node hashes should fail the replay verifier");
        assert!(matches!(
            error,
            RedactedReplayBundleError::HashLengthMismatch {
                field: "event.node_id_hash",
                ..
            }
        ));
    }

    #[test]
    fn verifier_rejects_non_hex_snapshot_node_hash() {
        let mut bundle = replay_bundle();
        bundle
            .node_timelines
            .first_mut()
            .expect("scenario should emit node timelines")
            .state_at_end
            .node_id_hash = "g".repeat(64);

        let error = verify_in_memory_replay_bundle(&bundle, 3)
            .expect_err("non-hex snapshot node hashes should fail the replay verifier");
        assert!(matches!(
            error,
            RedactedReplayBundleError::HashNotHex {
                field: "snapshot.node_id_hash",
                ..
            }
        ));
    }

    #[test]
    fn verifier_rejects_non_hex_receipt_hash() {
        let mut bundle = replay_bundle();
        bundle.hashes.receipt_hash = "z".repeat(64);

        let error = verify_in_memory_replay_bundle(&bundle, 3)
            .expect_err("non-hex receipt hashes should fail the replay verifier");
        assert!(matches!(
            error,
            RedactedReplayBundleError::HashNotHex {
                field: "receipt_hash",
                ..
            }
        ));
    }
}
