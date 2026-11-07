//! Live deployment admission from independently pinned health observations.
//!
//! This bridge authenticates an external observer's evidence. It does not infer
//! quorum from a configured peer list or mint a healthy snapshot itself.

use std::io::Read;
#[cfg(unix)]
use std::io::Write;
use std::sync::Mutex as StdMutex;

use fcp_host::{
    DeploymentClassificationReason, DeploymentEvidenceChallenge, DeploymentEvidenceVerifier,
    DeploymentMode, SignedDeploymentEvidence,
};

use super::*;

const CONFIG_ENV: &str = "FCP_HOST_DEPLOYMENT_EVIDENCE_CONFIG_FILE";
const MAX_FILE_BYTES: usize = 64 * 1024;
const MAX_STARTUP_TIMEOUT_MS: u64 = 60_000;
const STARTUP_POLL_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    subject: String,
    zone_id: ZoneId,
    attester_public_key_hex: String,
    evidence_file: PathBuf,
    startup_challenge_file: Option<PathBuf>,
    startup_timeout_ms: Option<u64>,
}

/// An explicit, bounded rendezvous with an independent local health observer.
/// The publication path must be new for every launch; this host never removes
/// or replaces a previous process's descriptor.
struct StartupBootstrap {
    challenge_file: PathBuf,
    timeout: Duration,
}

impl StartupBootstrap {
    fn from_fields(
        challenge_file: Option<PathBuf>,
        timeout_ms: Option<u64>,
        evidence_file: &StdPath,
    ) -> HostResult<Option<Self>> {
        let (challenge_file, timeout_ms) = match (challenge_file, timeout_ms) {
            (None, None) => return Ok(None),
            (Some(path), Some(timeout)) => (path, timeout),
            _ => {
                return Err(invalid_config(
                    "startup_challenge_file and startup_timeout_ms must be configured together",
                ));
            }
        };
        if !cfg!(unix) {
            return Err(invalid_config(
                "protected startup challenge publication requires Unix file permissions",
            ));
        }
        if !challenge_file.is_absolute()
            || challenge_file.file_name().is_none()
            || challenge_file
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err(invalid_config(
                "startup_challenge_file must be an absolute file path without parent traversal",
            ));
        }
        if challenge_file == evidence_file {
            return Err(invalid_config(
                "startup challenge and signed evidence require different files",
            ));
        }
        if !(1..=MAX_STARTUP_TIMEOUT_MS).contains(&timeout_ms) {
            return Err(invalid_config(
                "startup_timeout_ms must be between 1 and 60000",
            ));
        }
        Ok(Some(Self {
            challenge_file,
            timeout: Duration::from_millis(timeout_ms),
        }))
    }
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
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    // Check both sides of open: the path may be atomically replaced by its
    // publisher, and a FIFO replacement must not block the Unix runtime.
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| invalid_config("cannot inspect configured file"))?;
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

/// The observer must run as the host's Unix user (or a trusted local root).
/// Validate every ancestor, require a private final directory, and never open
/// an existing destination. Inode checks fence path replacement before any
/// challenge bytes are written. Same-UID and root mutation of these protected
/// directories remains inside the local operator trust boundary.
#[cfg(unix)]
fn publish_startup_challenge(
    path: &StdPath,
    challenge: &DeploymentEvidenceChallenge,
) -> HostResult<()> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let parent = path
        .parent()
        .ok_or_else(|| invalid_config("startup challenge requires a parent directory"))?;
    let mut ancestors = parent.ancestors().collect::<Vec<_>>();
    ancestors.reverse();
    let mut inspected = Vec::with_capacity(ancestors.len());
    for ancestor in ancestors {
        let metadata = std::fs::symlink_metadata(ancestor)
            .map_err(|_| invalid_config("cannot inspect startup challenge directory"))?;
        if !metadata.is_dir() {
            return Err(invalid_config(
                "startup challenge ancestors must be directories, never symlinks",
            ));
        }
        // A root-owned sticky ancestor such as /tmp cannot replace another
        // user's private child. Other shared writable ancestors are rejected.
        if metadata.mode() & 0o022 != 0 && !(metadata.uid() == 0 && metadata.mode() & 0o1000 != 0) {
            return Err(invalid_config(
                "startup challenge ancestors must not be writable by other users",
            ));
        }
        inspected.push((ancestor, metadata));
    }
    let (_, parent_metadata) = inspected
        .last()
        .ok_or_else(|| invalid_config("startup challenge requires a private directory"))?;
    if parent_metadata.mode() & 0o077 != 0 {
        return Err(invalid_config(
            "startup challenge parent must be a private owner-only directory",
        ));
    }
    let parent_file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(parent)
        .map_err(|_| invalid_config("cannot open startup challenge directory"))?;
    let opened_parent = parent_file
        .metadata()
        .map_err(|_| invalid_config("cannot inspect opened startup challenge directory"))?;
    if opened_parent.dev() != parent_metadata.dev() || opened_parent.ino() != parent_metadata.ino()
    {
        return Err(invalid_config("startup challenge directory changed"));
    }
    let bytes = serde_json::to_vec(challenge)
        .map_err(|_| invalid_config("cannot encode startup challenge"))?;
    if bytes.len() > MAX_FILE_BYTES {
        return Err(invalid_config("startup challenge exceeds its byte limit"));
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| {
            invalid_config("cannot create startup challenge; use a new nonexisting file per launch")
        })?;
    let created = file
        .metadata()
        .map_err(|_| invalid_config("cannot inspect created startup challenge"))?;
    // A newly created file's owner is the filesystem identity of this host.
    // Read it from the handle instead of trusting an environment-provided UID.
    if !created.is_file()
        || created.nlink() != 1
        || created.mode() & 0o777 != 0o600
        || parent_metadata.uid() != created.uid()
    {
        return Err(invalid_config(
            "startup challenge requires an owner-only regular file in a host-owned directory",
        ));
    }
    for (ancestor, before) in &inspected {
        if before.uid() != 0 && before.uid() != created.uid() {
            return Err(invalid_config(
                "startup challenge ancestors must be owned by this host user or root",
            ));
        }
        let after = std::fs::symlink_metadata(ancestor)
            .map_err(|_| invalid_config("startup challenge directory disappeared"))?;
        if !after.is_dir()
            || before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.uid() != after.uid()
            || before.mode() != after.mode()
        {
            return Err(invalid_config("startup challenge directory changed"));
        }
    }
    validate_startup_file_identity(path, &created)?;
    file.write_all(&bytes)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .and_then(|()| parent_file.sync_all())
        .map_err(|_| invalid_config("cannot durably publish startup challenge"))?;
    Ok(())
}

#[cfg(unix)]
fn validate_startup_file_identity(path: &StdPath, created: &std::fs::Metadata) -> HostResult<()> {
    use std::os::unix::fs::MetadataExt;

    let published = std::fs::symlink_metadata(path)
        .map_err(|_| invalid_config("startup challenge path disappeared"))?;
    if !published.is_file()
        || published.dev() != created.dev()
        || published.ino() != created.ino()
        || published.uid() != created.uid()
        || published.nlink() != 1
        || published.mode() & 0o777 != 0o600
    {
        return Err(invalid_config("startup challenge path changed"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn publish_startup_challenge(
    _path: &StdPath,
    _challenge: &DeploymentEvidenceChallenge,
) -> HostResult<()> {
    Err(invalid_config(
        "protected startup challenge publication requires Unix file permissions",
    ))
}

impl FileConfig {
    fn into_service(self, min_healthy_peers: u32) -> HostResult<DeploymentEvidenceService> {
        let startup = StartupBootstrap::from_fields(
            self.startup_challenge_file,
            self.startup_timeout_ms,
            &self.evidence_file,
        )?;
        let bytes: [u8; 32] = hex::decode(&self.attester_public_key_hex)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| invalid_config("attester key must be 32 bytes of hexadecimal"))?;
        let key = Ed25519VerifyingKey::from_bytes(&bytes)
            .map_err(|_| invalid_config("attester public key is invalid"))?;
        let mut service = DeploymentEvidenceService::new(
            self.subject,
            self.zone_id,
            key,
            self.evidence_file,
            min_healthy_peers,
        )?;
        service.startup = startup;
        Ok(service)
    }
}

pub(super) struct DeploymentEvidenceService {
    zone_id: ZoneId,
    challenge: DeploymentEvidenceChallenge,
    attester_public_key: [u8; 32],
    evidence_file: PathBuf,
    min_healthy_peers: u32,
    verifier: StdMutex<DeploymentEvidenceVerifier>,
    startup: Option<StartupBootstrap>,
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
            startup: None,
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

    /// Publish only after validating the independent trust root, then obtain
    /// current-process evidence before the ordinary HTTP listener is bound.
    /// With no opt-in, preserve the historical single-host startup behavior.
    pub(super) async fn startup_signals(
        &self,
        capability_key: Option<&Ed25519VerifyingKey>,
        approval_key: Option<&Ed25519VerifyingKey>,
    ) -> HostResult<MeshQuorumSignals> {
        self.validate_key_separation(capability_key, approval_key)?;
        let Some(startup) = &self.startup else {
            return Ok(MeshQuorumSignals::single_host_evaluation());
        };
        publish_startup_challenge(&startup.challenge_file, self.challenge())?;
        tracing::info!(
            event = "deployment_evidence_startup_challenge_published",
            timeout_ms = startup.timeout.as_millis(),
            min_healthy_peers = self.min_healthy_peers,
            "published protected process challenge; waiting for independent signed evidence"
        );
        let deadline = Instant::now() + startup.timeout;
        loop {
            if let Some((classification, evidence_deadline)) =
                self.classification_with_deadline(&self.zone_id)
            {
                if classification.mode.is_mesh_active()
                    && Instant::now() < evidence_deadline
                    && Instant::now() < deadline
                {
                    tracing::info!(
                        event = "deployment_evidence_startup_verified",
                        healthy_peers = classification.signals.healthy_peer_count,
                        "fresh process-bound deployment evidence is ready for boot policy"
                    );
                    return Ok(classification.signals);
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                // Never reuse a previously observed snapshot after a wait or
                // malformed replacement. The existing boot policy decides
                // whether these Evaluation signals mean degrade or refuse.
                tracing::warn!(
                    event = "deployment_evidence_startup_timeout",
                    "startup evidence deadline expired; applying boot policy with Evaluation signals"
                );
                return Ok(MeshQuorumSignals::single_host_evaluation());
            }
            fcp_async_core::time::sleep(remaining.min(STARTUP_POLL_INTERVAL)).await;
        }
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

    fn file_config(directory: &StdPath, key: &Ed25519SigningKey) -> FileConfig {
        FileConfig {
            subject: "host-evidence-test".to_owned(),
            zone_id: ZoneId::work(),
            attester_public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            evidence_file: directory.join("evidence.json"),
            startup_challenge_file: None,
            startup_timeout_ms: None,
        }
    }

    #[cfg(unix)]
    fn bootstrap_service(
        directory: &StdPath,
        key: &Ed25519SigningKey,
        timeout_ms: u64,
        min_peers: u32,
    ) -> DeploymentEvidenceService {
        // On macOS, the system temporary directory can begin with a symlink
        // such as /var. The protected path explicitly uses its real ancestry.
        let directory = directory.canonicalize().expect("real temporary directory");
        let mut config = file_config(&directory, key);
        config.startup_challenge_file = Some(directory.join("challenge.json"));
        config.startup_timeout_ms = Some(timeout_ms);
        config.into_service(min_peers).expect("bootstrap config")
    }

    #[test]
    fn startup_configuration_requires_paired_bounded_distinct_absolute_paths() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let key = Ed25519SigningKey::generate();
        let base = serde_json::json!({
            "subject": "host-evidence-test",
            "zone_id": "z:work",
            "attester_public_key_hex": hex::encode(key.verifying_key().to_bytes()),
            "evidence_file": directory.path().join("evidence.json"),
        });
        let default: FileConfig = serde_json::from_value(base.clone()).expect("old config shape");
        assert!(
            default
                .into_service(2)
                .expect("default service")
                .startup
                .is_none()
        );
        let challenge =
            serde_json::to_value(directory.path().join("challenge.json")).expect("challenge path");
        for (path, timeout) in [
            (challenge.clone(), serde_json::Value::Null),
            (serde_json::Value::Null, serde_json::json!(100)),
            (challenge.clone(), serde_json::json!(0)),
            (
                challenge.clone(),
                serde_json::json!(MAX_STARTUP_TIMEOUT_MS + 1),
            ),
            (serde_json::json!("relative.json"), serde_json::json!(100)),
            (base["evidence_file"].clone(), serde_json::json!(100)),
            (
                serde_json::to_value(directory.path().join("..").join("challenge.json"))
                    .expect("parent traversal path"),
                serde_json::json!(100),
            ),
        ] {
            let mut candidate = base.clone();
            candidate["startup_challenge_file"] = path;
            candidate["startup_timeout_ms"] = timeout;
            let config: FileConfig = serde_json::from_value(candidate).expect("config shape");
            assert!(config.into_service(2).is_err());
        }
        let mut valid = base;
        valid["startup_challenge_file"] = challenge;
        valid["startup_timeout_ms"] = serde_json::json!(MAX_STARTUP_TIMEOUT_MS);
        let config: FileConfig = serde_json::from_value(valid).expect("config shape");
        assert_eq!(config.into_service(2).is_ok(), cfg!(unix));
    }

    #[fcp_async_core::runtime::test]
    async fn startup_without_opt_in_preserves_evaluation_even_with_valid_evidence() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let key = Ed25519SigningKey::generate();
        let service = file_config(directory.path(), &key)
            .into_service(2)
            .expect("service");
        publish(&service, &key, 1, MeshQuorumSignals::fully_active(2));
        assert_eq!(
            service
                .startup_signals(None, None)
                .await
                .expect("default startup"),
            MeshQuorumSignals::single_host_evaluation(),
        );
        assert_eq!(
            service.classification(&ZoneId::work()).mode,
            DeploymentMode::MeshActive
        );
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test]
    async fn startup_authenticates_published_process_challenge_and_never_caches_authority() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temporary directory");
        let key = Ed25519SigningKey::generate();
        let service = Arc::new(bootstrap_service(directory.path(), &key, 5_000, 3));
        let capability = Ed25519SigningKey::generate().verifying_key();
        let approval = Ed25519SigningKey::generate().verifying_key();
        let challenge_file = service
            .startup
            .as_ref()
            .expect("bootstrap")
            .challenge_file
            .clone();
        let expected = service.challenge().clone();
        let evidence_file = service.evidence_file.clone();
        let observer = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let challenge: DeploymentEvidenceChallenge = loop {
                if let Ok(bytes) = read_bounded(&challenge_file) {
                    if let Ok(challenge) = serde_json::from_slice(&bytes) {
                        break challenge;
                    }
                }
                assert!(
                    Instant::now() < deadline,
                    "host did not publish its challenge"
                );
                std::thread::sleep(Duration::from_millis(1));
            };
            assert_eq!(
                challenge, expected,
                "publish the existing verifier's binding"
            );
            assert_eq!(
                std::fs::metadata(&challenge_file)
                    .expect("challenge metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            let now = u64::try_from(Utc::now().timestamp_millis()).expect("current time");
            let signed = SignedDeploymentEvidence::sign(
                &challenge,
                MeshQuorumSignals::fully_active(3),
                1,
                now,
                now + 30_000,
                &key,
            )
            .expect("independent observation");
            std::fs::write(
                evidence_file,
                serde_json::to_vec(&signed).expect("signed evidence"),
            )
            .expect("publish evidence");
        });
        let signals = service
            .startup_signals(Some(&capability), Some(&approval))
            .await
            .expect("bootstrap");
        observer.join().expect("independent observer");
        let resolution = select_host_truth_precedence_boot_from_env_values(
            signals,
            Some("v2"),
            Some("refuse-boot"),
            None,
            Some("3"),
        )
        .expect("verified V2 startup");
        assert_eq!(resolution.classification.mode, DeploymentMode::MeshActive);
        assert!(!resolution.selection.insufficient_peers);
        assert_eq!(
            resolution.selection.effective,
            fcp_policy::OperationalModelVersion::V2MeshNative
        );

        let guard = DeploymentDispatchGuard::new(
            Some(Arc::clone(&service)),
            ZoneId::work(),
            SafetyTier::Risky,
        );
        guard.refresh().expect("fresh authority at dispatch");
        std::fs::write(&service.evidence_file, b"withdrawn").expect("withdraw authority");
        assert!(
            guard.refresh().is_err(),
            "boot success must not authorize later execution"
        );
        assert_eq!(
            service.classification(&ZoneId::work()).mode,
            DeploymentMode::Evaluation
        );
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test]
    async fn startup_rejects_keys_before_creating_any_challenge_file() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let key = Ed25519SigningKey::generate();
        let service = bootstrap_service(directory.path(), &key, 1, 2);
        let challenge_file = &service.startup.as_ref().expect("bootstrap").challenge_file;
        let health = key.verifying_key();
        for (capability, approval) in [(Some(&health), None), (None, Some(&health))] {
            assert!(service.startup_signals(capability, approval).await.is_err());
            assert!(
                !challenge_file.exists(),
                "key rejection must precede publication"
            );
        }
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test]
    async fn startup_timeout_rejects_invalid_stale_wrong_zone_and_previous_process_evidence() {
        for invalid_kind in 0..8 {
            let directory = tempfile::tempdir().expect("temporary directory");
            let key = Ed25519SigningKey::generate();
            let service = bootstrap_service(directory.path(), &key, 1, 2);
            let mut descriptor = service.challenge().clone();
            if invalid_kind == 1 {
                descriptor.zone_id = ZoneId::owner();
            } else if invalid_kind == 2 {
                let previous = self::service(directory.path().join("previous.json"), &key);
                descriptor = previous.challenge().clone();
            }
            let now = u64::try_from(Utc::now().timestamp_millis()).expect("current time");
            let (issued, expires) = if invalid_kind == 3 {
                (now - 30_000, now - 1)
            } else {
                (now, now + 30_000)
            };
            let mut observed_signals = MeshQuorumSignals::fully_active(2);
            if invalid_kind == 6 {
                observed_signals.revocation_snapshot_fresh = false;
            } else if invalid_kind == 7 {
                observed_signals.lease_coordinator_reachable = Some(false);
            }
            let mut signed = SignedDeploymentEvidence::sign(
                &descriptor,
                observed_signals,
                1,
                issued,
                expires,
                &key,
            )
            .expect("signed observation");
            if invalid_kind == 4 {
                signed.quorum.signals.healthy_peer_count += 1;
            }
            let bytes = if invalid_kind == 0 {
                b"malformed evidence".to_vec()
            } else {
                serde_json::to_vec(&signed).expect("evidence JSON")
            };
            if invalid_kind != 5 {
                std::fs::write(&service.evidence_file, bytes).expect("invalid evidence");
            }
            let signals = service
                .startup_signals(None, None)
                .await
                .expect("bounded wait");
            assert_eq!(signals, MeshQuorumSignals::single_host_evaluation());
            assert!(
                select_host_truth_precedence_boot_from_env_values(
                    signals,
                    Some("v2"),
                    Some("refuse-boot"),
                    None,
                    None,
                )
                .is_err()
            );
        }
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test]
    async fn startup_timeout_honors_operator_threshold_and_existing_degrade_policy() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let key = Ed25519SigningKey::generate();
        let service = bootstrap_service(directory.path(), &key, 1, 3);
        publish(&service, &key, 1, MeshQuorumSignals::fully_active(2));
        let signals = service
            .startup_signals(None, None)
            .await
            .expect("bounded wait");
        assert_eq!(signals, MeshQuorumSignals::single_host_evaluation());
        assert!(
            select_host_truth_precedence_boot_from_env_values(
                signals,
                Some("v2"),
                Some("refuse-boot"),
                None,
                Some("3"),
            )
            .is_err()
        );
        let degraded = select_host_truth_precedence_boot_from_env_values(
            signals,
            Some("v2"),
            Some("degrade-to-v1"),
            None,
            Some("3"),
        )
        .expect("explicit degrade policy still applies");
        assert_eq!(
            degraded.selection.effective,
            fcp_policy::OperationalModelVersion::V1HostFirst
        );
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test]
    async fn startup_publication_never_overwrites_existing_files_or_follows_symlinks() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let key = Ed25519SigningKey::generate();
        let service = bootstrap_service(directory.path(), &key, 1, 2);
        let challenge_file = &service.startup.as_ref().expect("bootstrap").challenge_file;
        std::fs::write(challenge_file, b"unrelated operator file").expect("existing file");
        assert!(service.startup_signals(None, None).await.is_err());
        assert_eq!(
            std::fs::read(challenge_file).expect("preserved file"),
            b"unrelated operator file"
        );

        let linked_directory = tempfile::tempdir().expect("temporary directory");
        let linked = bootstrap_service(linked_directory.path(), &key, 1, 2);
        let linked_challenge = &linked.startup.as_ref().expect("bootstrap").challenge_file;
        std::os::unix::fs::symlink(challenge_file, linked_challenge).expect("symlink");
        assert!(linked.startup_signals(None, None).await.is_err());
        assert!(
            read_bounded(linked_challenge).is_err(),
            "evidence reads reject symlinks too"
        );
        assert_eq!(
            std::fs::read(challenge_file).expect("preserved target"),
            b"unrelated operator file"
        );
    }

    #[cfg(unix)]
    #[test]
    fn startup_publication_rejects_insecure_parents_symlink_ancestors_and_fifos() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().expect("temporary directory");
        let key = Ed25519SigningKey::generate();
        let service = bootstrap_service(directory.path(), &key, 1, 2);
        let challenge_file = &service.startup.as_ref().expect("bootstrap").challenge_file;
        let parent = challenge_file.parent().expect("parent");
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755))
            .expect("open permissions");
        assert!(publish_startup_challenge(challenge_file, service.challenge()).is_err());
        assert!(!challenge_file.exists());
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .expect("restore private directory");
        let alias_directory = tempfile::tempdir().expect("alias parent");
        let alias = alias_directory
            .path()
            .canonicalize()
            .expect("canonical alias parent")
            .join("linked");
        std::os::unix::fs::symlink(parent, &alias).expect("directory symlink");
        assert!(
            publish_startup_challenge(&alias.join("challenge.json"), service.challenge()).is_err()
        );
        assert!(!challenge_file.exists());
        let status = std::process::Command::new("mkfifo")
            .arg(challenge_file)
            .status()
            .expect("POSIX mkfifo");
        assert!(status.success());
        assert!(publish_startup_challenge(challenge_file, service.challenge()).is_err());
        assert!(
            read_bounded(challenge_file).is_err(),
            "FIFO intake must fail without blocking"
        );
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
