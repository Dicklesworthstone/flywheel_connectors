//! Live deployment admission from independently pinned health observations.
//!
//! This bridge authenticates an external observer's evidence. It does not infer
//! quorum from a configured peer list or mint a healthy snapshot itself.

use std::io::Read;
use std::sync::Mutex as StdMutex;

use fcp_host::{
    DeploymentClassificationReason, DeploymentEvidenceChallenge, DeploymentEvidenceVerifier,
    DeploymentMode, SignedDeploymentEvidence,
};

use super::*;

const CONFIG_ENV: &str = "FCP_HOST_DEPLOYMENT_EVIDENCE_CONFIG_FILE";
const MAX_FILE_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    subject: String,
    zone_id: ZoneId,
    attester_public_key_hex: String,
    evidence_file: PathBuf,
}

fn invalid_config(message: &str) -> HostError {
    HostError::InvalidFilter(format!("deployment evidence: {message}"))
}

fn read_bounded(path: &StdPath) -> HostResult<Vec<u8>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    // Check both sides of open: the path may be atomically replaced by its
    // publisher, and a FIFO replacement must not block the Unix runtime.
    let metadata =
        std::fs::metadata(path).map_err(|_| invalid_config("cannot inspect configured file"))?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES as u64 {
        return Err(invalid_config("expected a bounded regular file"));
    }
    let file = options
        .open(path)
        .map_err(|_| invalid_config("cannot open configured file"))?;
    let metadata = file
        .metadata()
        .map_err(|_| invalid_config("cannot inspect opened file"))?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES as u64 {
        return Err(invalid_config("expected a bounded regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid_config("cannot read configured file"))?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(invalid_config("configured file exceeds its byte limit"));
    }
    Ok(bytes)
}

impl FileConfig {
    fn into_service(self, min_healthy_peers: u32) -> HostResult<DeploymentEvidenceService> {
        let bytes: [u8; 32] = hex::decode(&self.attester_public_key_hex)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| invalid_config("attester key must be 32 bytes of hexadecimal"))?;
        let key = Ed25519VerifyingKey::from_bytes(&bytes)
            .map_err(|_| invalid_config("attester public key is invalid"))?;
        DeploymentEvidenceService::new(
            self.subject,
            self.zone_id,
            key,
            self.evidence_file,
            min_healthy_peers,
        )
    }
}

pub(super) struct DeploymentEvidenceService {
    zone_id: ZoneId,
    challenge: DeploymentEvidenceChallenge,
    attester_public_key: [u8; 32],
    evidence_file: PathBuf,
    min_healthy_peers: u32,
    verifier: StdMutex<DeploymentEvidenceVerifier>,
}

impl DeploymentEvidenceService {
    pub(super) fn new(
        subject: String,
        zone_id: ZoneId,
        attester: Ed25519VerifyingKey,
        evidence_file: PathBuf,
        min_healthy_peers: u32,
    ) -> HostResult<Self> {
        if !evidence_file.is_absolute() {
            return Err(invalid_config("evidence_file must be absolute"));
        }
        if min_healthy_peers == 0 {
            return Err(invalid_config(
                "minimum healthy peer count must be positive",
            ));
        }
        let attester_public_key = attester.to_bytes();
        let verifier = DeploymentEvidenceVerifier::new(subject, zone_id.clone(), attester)
            .map_err(|_| invalid_config("invalid attested host binding"))?;
        Ok(Self {
            zone_id,
            challenge: verifier.challenge().clone(),
            attester_public_key,
            evidence_file,
            min_healthy_peers,
            verifier: StdMutex::new(verifier),
        })
    }

    pub(super) fn challenge(&self) -> &DeploymentEvidenceChallenge {
        &self.challenge
    }

    pub(super) fn validate_key_separation(
        &self,
        capability_key: Option<&Ed25519VerifyingKey>,
        approval_key: Option<&Ed25519VerifyingKey>,
    ) -> HostResult<()> {
        if capability_key
            .into_iter()
            .chain(approval_key)
            .any(|key| key.to_bytes() == self.attester_public_key)
        {
            return Err(invalid_config(
                "health attester must be independent of capability and approval signing keys",
            ));
        }
        Ok(())
    }

    pub(super) fn classification(&self, zone: &ZoneId) -> DeploymentClassification {
        if zone != &self.zone_id {
            return classify_deployment_mode(MeshQuorumSignals::single_host_evaluation());
        }
        self.classification_with_deadline(zone)
            .map(|(classification, _)| classification)
            .unwrap_or_else(|| DeploymentClassification {
                mode: DeploymentMode::Evaluation,
                signals: MeshQuorumSignals::single_host_evaluation(),
                reason: DeploymentClassificationReason::SignedSignalsRejected,
            })
    }

    fn classification_with_deadline(
        &self,
        zone: &ZoneId,
    ) -> Option<(DeploymentClassification, Instant)> {
        if zone != &self.zone_id {
            return None;
        }
        let bytes = read_bounded(&self.evidence_file).ok()?;
        let evidence: SignedDeploymentEvidence = serde_json::from_slice(&bytes).ok()?;
        let mut verifier = self.verifier.lock().ok()?;
        let now_ms = u64::try_from(Utc::now().timestamp_millis()).ok()?;
        let (authenticated, deadline) = verifier.evaluate_with_deadline(&evidence, now_ms).ok()?;
        // Only authenticated, fresh signals may reach this configurable
        // classifier. Pin the same operator threshold used at startup.
        Some((
            fcp_host::classify_deployment_mode_with_min_peers(
                authenticated.signals,
                self.min_healthy_peers,
            ),
            deadline,
        ))
    }
}

/// The deployment requirements of one admitted operation, retained across queue
/// and session waits. This retains a verifier, never an accepted observation.
#[derive(Clone)]
pub(super) struct DeploymentDispatchGuard {
    service: Option<Arc<DeploymentEvidenceService>>,
    zone: ZoneId,
    tier: SafetyTier,
}

impl DeploymentDispatchGuard {
    pub(super) fn new(
        service: Option<Arc<DeploymentEvidenceService>>,
        zone: ZoneId,
        tier: SafetyTier,
    ) -> Self {
        Self {
            service,
            zone,
            tier,
        }
    }

    /// Read and authenticate outside runtime ownership/map locks. The returned
    /// permit is only for the immediately following activation, not later RPCs.
    pub(super) fn refresh(&self) -> HostResult<DeploymentDispatchPermit> {
        let evaluation = classify_deployment_mode(MeshQuorumSignals::single_host_evaluation());
        if admit_safety_tier(&evaluation, self.tier).is_ok() {
            // Operations admitted in Evaluation do not borrow expiring health
            // authority merely because an observer happens to be configured.
            return Ok(DeploymentDispatchPermit { deadline: None });
        }
        let (classification, deadline) = self
            .service
            .as_ref()
            .and_then(|service| service.classification_with_deadline(&self.zone))
            .ok_or_else(dispatch_refused)?;
        admit_safety_tier(&classification, self.tier).map_err(|_| dispatch_refused())?;
        let permit = DeploymentDispatchPermit {
            deadline: Some(deadline),
        };
        permit.require_current()?;
        Ok(permit)
    }
}

fn dispatch_refused() -> HostError {
    HostError::PreflightFailed(
        "current deployment evidence does not permit the queued operation tier".to_owned(),
    )
}

/// A time bound from the just-authenticated observation. Keeping this small
/// permits the final expiry check while holding the runtime's selection lock.
pub(super) struct DeploymentDispatchPermit {
    deadline: Option<Instant>,
}

impl DeploymentDispatchPermit {
    pub(super) fn is_current(&self) -> bool {
        self.deadline
            .is_none_or(|deadline| Instant::now() < deadline)
    }

    pub(super) fn require_current(&self) -> HostResult<()> {
        if self.is_current() {
            Ok(())
        } else {
            Err(dispatch_refused())
        }
    }
}

pub(super) fn from_env() -> HostResult<Option<DeploymentEvidenceService>> {
    let Some(path) = read_optional_trimmed_env_string(CONFIG_ENV)? else {
        return Ok(None);
    };
    let bytes = read_bounded(StdPath::new(&path))?;
    let config: FileConfig = serde_json::from_slice(&bytes)
        .map_err(|_| invalid_config("configuration is malformed or contains unknown fields"))?;
    let min_peers = read_optional_trimmed_env_string(V2_MIN_HEALTHY_MESH_PEERS_ENV)?;
    let min_peers = fcp_host::parse_v2_min_healthy_mesh_peers(min_peers.as_deref())
        .map_err(|_| invalid_config("configured minimum healthy peer count is invalid"))?;
    config.into_service(min_peers).map(Some)
}

pub(super) async fn challenge_handler(
    State(state): State<Arc<AppState>>,
) -> Result<(HeaderMap, Json<DeploymentEvidenceChallenge>), (StatusCode, String)> {
    state
        .deployment_evidence
        .as_ref()
        .map(|evidence| {
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::CACHE_CONTROL,
                HeaderValue::from_static("no-store"),
            );
            (headers, Json(evidence.challenge().clone()))
        })
        .ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "deployment evidence is not configured".to_owned(),
            )
        })
}

#[cfg(test)]
mod tests {
    use fcp_crypto::ed25519::Ed25519SigningKey;

    use super::*;

    fn service(path: PathBuf, key: &Ed25519SigningKey) -> DeploymentEvidenceService {
        DeploymentEvidenceService::new(
            "host-evidence-test".to_owned(),
            ZoneId::work(),
            key.verifying_key(),
            path,
            fcp_host::MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE,
        )
        .expect("validated host binding")
    }

    fn publish(
        service: &DeploymentEvidenceService,
        key: &Ed25519SigningKey,
        generation: u64,
        signals: MeshQuorumSignals,
    ) -> Vec<u8> {
        let now = u64::try_from(Utc::now().timestamp_millis()).expect("current time");
        let evidence = SignedDeploymentEvidence::sign(
            service.challenge(),
            signals,
            generation,
            now,
            now + 30_000,
            key,
        )
        .expect("signed health observation");
        let bytes = serde_json::to_vec(&evidence).expect("evidence JSON");
        std::fs::write(&service.evidence_file, &bytes).expect("publish health evidence");
        bytes
    }

    #[test]
    fn deployment_evidence_runtime_never_reuses_missing_or_malformed_authority() {
        let directory = tempfile::tempdir().expect("temp directory");
        let key = Ed25519SigningKey::generate();
        let service = service(directory.path().join("evidence.json"), &key);
        assert_eq!(
            service.classification(&ZoneId::work()).mode,
            DeploymentMode::Evaluation
        );
        let first = publish(&service, &key, 1, MeshQuorumSignals::fully_active(2));
        assert_eq!(
            service.classification(&ZoneId::work()).mode,
            DeploymentMode::MeshActive
        );
        assert_eq!(
            service.classification(&ZoneId::owner()).mode,
            DeploymentMode::Evaluation
        );
        for invalid in [
            b"private-invalid-evidence".to_vec(),
            vec![b'X'; MAX_FILE_BYTES + 1],
        ] {
            std::fs::write(&service.evidence_file, invalid).expect("replace evidence");
            assert_eq!(
                service.classification(&ZoneId::work()).mode,
                DeploymentMode::Evaluation
            );
        }
        publish(
            &service,
            &key,
            2,
            MeshQuorumSignals::single_host_evaluation(),
        );
        assert_eq!(
            service.classification(&ZoneId::work()).mode,
            DeploymentMode::Evaluation
        );
        std::fs::write(&service.evidence_file, first).expect("attempt old active snapshot");
        assert_eq!(
            service.classification(&ZoneId::work()).mode,
            DeploymentMode::Evaluation
        );
        publish(&service, &key, 3, MeshQuorumSignals::fully_active(2));
        assert_eq!(
            service.classification(&ZoneId::work()).mode,
            DeploymentMode::MeshActive
        );
    }

    #[test]
    fn deployment_evidence_runtime_requires_independent_key_and_absolute_file() {
        let directory = tempfile::tempdir().expect("temp directory");
        let key = Ed25519SigningKey::generate();
        let service = service(directory.path().join("evidence.json"), &key);
        let health = key.verifying_key();
        let other = Ed25519SigningKey::generate().verifying_key();
        assert!(
            service
                .validate_key_separation(Some(&health), None)
                .is_err()
        );
        assert!(
            service
                .validate_key_separation(None, Some(&health))
                .is_err()
        );
        service
            .validate_key_separation(Some(&other), Some(&other))
            .expect("independent health key");
        assert!(
            DeploymentEvidenceService::new(
                "host".to_owned(),
                ZoneId::work(),
                health,
                PathBuf::from("relative.json"),
                fcp_host::MIN_HEALTHY_MESH_PEERS_FOR_ACTIVE,
            )
            .is_err()
        );
        assert!(read_bounded(directory.path()).is_err());
    }

    #[test]
    fn deployment_evidence_runtime_honors_the_pinned_operator_peer_threshold() {
        let directory = tempfile::tempdir().expect("temp directory");
        let key = Ed25519SigningKey::generate();
        let service = DeploymentEvidenceService::new(
            "host-three-peer-minimum".to_owned(),
            ZoneId::work(),
            key.verifying_key(),
            directory.path().join("evidence.json"),
            3,
        )
        .expect("pin stronger operator threshold");
        publish(&service, &key, 1, MeshQuorumSignals::fully_active(2));
        assert_eq!(
            service.classification(&ZoneId::work()).mode,
            DeploymentMode::Evaluation
        );
        publish(&service, &key, 2, MeshQuorumSignals::fully_active(3));
        assert_eq!(
            service.classification(&ZoneId::work()).mode,
            DeploymentMode::MeshActive
        );
    }

    #[test]
    fn dispatch_guard_observes_withdrawal_replacement_and_generation_rollback() {
        let directory = tempfile::tempdir().expect("temp directory");
        let key = Ed25519SigningKey::generate();
        let service = Arc::new(service(directory.path().join("evidence.json"), &key));
        let guard = DeploymentDispatchGuard::new(
            Some(Arc::clone(&service)),
            ZoneId::work(),
            SafetyTier::Risky,
        );
        assert!(guard.refresh().is_err());
        let first = publish(&service, &key, 1, MeshQuorumSignals::fully_active(2));
        guard.refresh().expect("fresh authenticated deployment");

        let withdrawn = directory.path().join("withdrawn-evidence.json");
        std::fs::rename(&service.evidence_file, &withdrawn).expect("withdraw evidence");
        assert!(guard.refresh().is_err(), "must reread the configured file");
        std::fs::write(&service.evidence_file, b"invalid replacement")
            .expect("replace evidence with malformed content");
        assert!(guard.refresh().is_err());
        publish(
            &service,
            &key,
            2,
            MeshQuorumSignals::single_host_evaluation(),
        );
        assert!(guard.refresh().is_err(), "authenticated downgrade must win");
        std::fs::write(&service.evidence_file, first).expect("restore stale active generation");
        assert!(
            guard.refresh().is_err(),
            "old active authority cannot return"
        );
        publish(&service, &key, 3, MeshQuorumSignals::fully_active(2));
        guard
            .refresh()
            .expect("fresh later generation restores authority");
    }

    #[test]
    fn dispatch_guard_preserves_zone_tier_and_operator_thresholds() {
        let directory = tempfile::tempdir().expect("temp directory");
        let key = Ed25519SigningKey::generate();
        let service = Arc::new(
            DeploymentEvidenceService::new(
                "host-dispatch-test".to_owned(),
                ZoneId::work(),
                key.verifying_key(),
                directory.path().join("evidence.json"),
                3,
            )
            .expect("three-peer policy"),
        );
        let risky = DeploymentDispatchGuard::new(
            Some(Arc::clone(&service)),
            ZoneId::work(),
            SafetyTier::Risky,
        );
        publish(&service, &key, 1, MeshQuorumSignals::fully_active(2));
        assert!(risky.refresh().is_err());
        publish(&service, &key, 2, MeshQuorumSignals::fully_active(3));
        risky.refresh().expect("operator threshold satisfied");
        for (zone, tier) in [
            (ZoneId::owner(), SafetyTier::Risky),
            (ZoneId::work(), SafetyTier::Forbidden),
        ] {
            assert!(
                DeploymentDispatchGuard::new(Some(Arc::clone(&service)), zone, tier)
                    .refresh()
                    .is_err()
            );
        }
        assert!(
            DeploymentDispatchGuard::new(None, ZoneId::work(), SafetyTier::Risky)
                .refresh()
                .is_err()
        );
        DeploymentDispatchGuard::new(None, ZoneId::work(), SafetyTier::Safe)
            .refresh()
            .expect("Evaluation still permits Safe operations")
            .require_current()
            .expect("Safe operations do not depend on a health lease");
    }

    #[test]
    fn dispatch_permit_expires_before_runtime_selection() {
        let permit = DeploymentDispatchPermit {
            deadline: Some(Instant::now()),
        };
        assert!(!permit.is_current());
        assert!(permit.require_current().is_err());
        let permanent = DeploymentDispatchPermit { deadline: None };
        assert!(permanent.require_current().is_ok());
    }
}
