//! Owner-authorized, continuously refreshed revocation at live host admission.
//!
//! The signed snapshot supplies the existing bounded cascade walker's chain and
//! lookup tables. Its owner key and zone come from independent startup config,
//! never from a request or the snapshot itself. Every check reads the source;
//! missing, invalid or stale input never falls back to a previously valid feed.
//! Permanent revocations and generation floors survive restart on trusted local
//! storage. This is an opt-in local feed, not mesh discovery or gossip transport.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use fcp_crypto::{
    Ed25519SigningKey, Ed25519VerifyingKey, KeyId, PqSigningPolicy, SignedEnvelope,
    canonical_signing_bytes,
};
use fcp_evidence::{
    AttestationChain, CascadeConfig, CascadeHop, RevocationRecord, check_revocation_chain,
};
use fcp_prelude::{ObjectId, ZoneId};
use serde::{Deserialize, Serialize};

use crate::{HostError, HostResult};

mod storage;

/// Startup configuration file for independently pinned zone-owner feeds.
pub const RUNTIME_REVOCATION_CONFIG_ENV: &str = "FCP_HOST_REVOCATION_CONFIG_FILE";
/// Schema and signing domain for the complete snapshot payload.
pub const RUNTIME_REVOCATION_SCHEMA: &str = "fcp.host.revocation-snapshot.v1";
/// Hard freshness ceiling; the signer may choose a shorter lifetime.
pub const MAX_REVOCATION_SNAPSHOT_LIFETIME_MS: u64 = 300_000;
const MAX_BYTES: usize = 1024 * 1024;
const MAX_RECORDS: usize = 4096;
const MAX_FUTURE_SKEW_MS: u64 = 5000;
const INITIALIZED: &[u8] = b"FCP-HOST-REVOCATION-CHECKPOINT-V1\n";

/// A permanent, immediately effective token revocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeTokenRevocation {
    /// The same token object identity used by host capability admission.
    pub token_id: ObjectId,
    /// Unix milliseconds; cannot be later than snapshot issuance.
    pub revoked_at_ms: u64,
}

/// A permanent key revocation at an existing cascade hop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeKeyRevocation {
    /// Canonical key identifier, derived from the public key.
    pub kid: KeyId,
    /// Issuer, node or owner attestation scope.
    pub hop: CascadeHop,
    /// Unix milliseconds; cannot be later than snapshot issuance.
    pub revoked_at_ms: u64,
}

/// Full owner-signed state for one zone. Revocation sets are cumulative.
///
/// The owner is supplied by the pinned verifying key. Unknown issuers cannot
/// manufacture an implicit root: their configured chain must reach that owner.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRevocationSnapshot {
    /// Must equal [`RUNTIME_REVOCATION_SCHEMA`].
    pub schema: String,
    /// Exact execution zone authorized by this owner.
    pub zone_id: ZoneId,
    /// Positive monotonic generation; every renewal uses a new generation.
    pub generation: u64,
    /// Unix milliseconds when these observations were made.
    pub issued_at_ms: u64,
    /// Exclusive expiry, at most five minutes after issuance.
    pub expires_at_ms: u64,
    /// Existing cascade edges from issuance keys to node keys.
    pub issuance_to_node: Vec<(KeyId, KeyId)>,
    /// Existing cascade edges from node keys to the pinned owner key.
    pub node_to_owner: Vec<(KeyId, KeyId)>,
    /// Every permanent token revocation known to this feed.
    pub tokens: Vec<RuntimeTokenRevocation>,
    /// Every permanent scoped key revocation known to this feed.
    pub keys: Vec<RuntimeKeyRevocation>,
}

/// Uses FCP's existing signed-envelope implementation and classical host key mode.
pub type SignedRuntimeRevocations = SignedEnvelope<RuntimeRevocationSnapshot>;

impl RuntimeRevocationSnapshot {
    /// Sign a full snapshot with the independently provisioned zone owner.
    ///
    /// # Errors
    /// Returns an encoding or signing error; host admission also checks shape,
    /// monotonicity, zone binding and freshness against its own trusted config.
    pub fn sign(&self, owner: &Ed25519SigningKey) -> HostResult<SignedRuntimeRevocations> {
        SignedEnvelope::sign_with_policy(
            RUNTIME_REVOCATION_SCHEMA,
            self.clone(),
            &self.signing_bytes()?,
            PqSigningPolicy::ClassicalOnly,
            Some(owner),
            None,
        )
        .map_err(|_| invalid("snapshot signing failed"))
    }

    fn signing_bytes(&self) -> HostResult<Vec<u8>> {
        let cbor =
            fcp_cbor::to_canonical_cbor(self).map_err(|_| invalid("snapshot encoding failed"))?;
        Ok(canonical_signing_bytes(RUNTIME_REVOCATION_SCHEMA, &cbor))
    }
}

/// Startup-only trust and persistence selection. No private key is loaded.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRevocationZoneConfig {
    /// Only this exact request zone may use the source.
    pub zone_id: ZoneId,
    /// Independently pinned Ed25519 owner public key, 64 hexadecimal digits.
    pub owner_public_key_hex: String,
    /// Bounded regular JSON file, atomically replaced by the owner publisher.
    pub snapshot_file: PathBuf,
    /// Host-owned anti-rollback file; `.lock` and `.next` are reserved companions.
    pub checkpoint_file: PathBuf,
}

/// Explicitly configured feeds for every zone served by this host.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRevocationConfig {
    /// Between one and sixteen independently pinned zones, without duplicates.
    pub zones: Vec<RuntimeRevocationZoneConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    zone_id: ZoneId,
    owner_kid: KeyId,
    generation: u64,
    digest: [u8; 32],
    observed_at_ms: u64,
    equivocated: bool,
    capacity_exhausted: bool,
    issuance_to_node: Vec<(KeyId, KeyId)>,
    node_to_owner: Vec<(KeyId, KeyId)>,
    tokens: Vec<RuntimeTokenRevocation>,
    keys: Vec<RuntimeKeyRevocation>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredCheckpoint {
    checkpoint: Checkpoint,
    checksum: [u8; 32],
}

#[derive(Debug)]
struct Feed {
    config: RuntimeRevocationZoneConfig,
    owner: Ed25519VerifyingKey,
    checkpoint: Option<Checkpoint>,
    failed: bool,
    clock_ms: u64,
    clock_at: Instant,
    checkpoint_owner: u32,
    _lock: File,
}

/// Current-source enforcement plus durable per-zone rollback and revocation floors.
#[derive(Debug)]
pub struct RuntimeRevocationService {
    feeds: Vec<Mutex<Feed>>,
}

/// Freshness bound from one just-authenticated revocation observation.
///
/// This is only a permit for the immediately following dispatch. A later RPC
/// must refresh the source again. Both clocks constrain its lifetime so waiting
/// for runtime ownership cannot extend authority after clock adjustments.
#[derive(Debug)]
pub struct RuntimeRevocationPermit {
    deadline: Instant,
    expires_at_ms: u64,
}

impl RuntimeRevocationPermit {
    /// Check freshness without file access or signature verification.
    #[must_use]
    pub fn is_current(&self) -> bool {
        Instant::now() < self.deadline && now_ms().is_ok_and(|now| now < self.expires_at_ms)
    }

    /// # Errors
    /// Refuses an observation that expired while awaiting runtime ownership.
    pub fn require_current(&self) -> HostResult<()> {
        if self.is_current() {
            Ok(())
        } else {
            Err(invalid("dispatch observation expired"))
        }
    }
}

type TokenIndex = HashMap<ObjectId, u64>;
type KeyIndex = HashMap<(KeyId, CascadeHop), u64>;

fn invalid(reason: &str) -> HostError {
    HostError::PreflightFailed(format!("runtime revocation: {reason}"))
}

fn now_ms() -> HostResult<u64> {
    u64::try_from(chrono::Utc::now().timestamp_millis())
        .map_err(|_| invalid("host clock is invalid"))
}

impl RuntimeRevocationService {
    /// Read explicit startup configuration. An invalid configured path is an error.
    ///
    /// # Errors
    /// Refuses malformed config, missing/invalid initial snapshots, unavailable
    /// persistence, duplicate zones or overlapping source/checkpoint paths.
    pub fn from_env() -> HostResult<Option<Self>> {
        let path = match std::env::var(RUNTIME_REVOCATION_CONFIG_ENV) {
            Ok(path) if !path.trim().is_empty() => path,
            Err(std::env::VarError::NotPresent) => return Ok(None),
            _ => return Err(invalid("configuration path is empty or not Unicode")),
        };
        let bytes = read_bounded(Path::new(&path), 64 * 1024)?;
        let config =
            serde_json::from_slice(&bytes).map_err(|_| invalid("configuration is invalid"))?;
        Self::open(config).map(Some)
    }

    /// Open all feeds before accepting work; checkpoint ownership lasts until drop.
    ///
    /// # Errors
    /// Returns the same trust, source and durable-state errors as live verification.
    pub fn open(mut config: RuntimeRevocationConfig) -> HostResult<Self> {
        if config.zones.is_empty() || config.zones.len() > 16 {
            return Err(invalid("configure between one and sixteen zones"));
        }
        let mut zones = std::collections::HashSet::new();
        for zone in &config.zones {
            if !zones.insert(zone.zone_id.clone()) {
                return Err(invalid("duplicate zone configuration"));
            }
        }
        storage::prepare_paths(&mut config)?;
        let feeds = config
            .zones
            .into_iter()
            .map(Feed::open)
            .map(|feed| feed.map(Mutex::new))
            .collect::<HostResult<_>>()?;
        Ok(Self { feeds })
    }

    /// Check the exact zone, token and signed issuer using freshly loaded evidence.
    ///
    /// # Errors
    /// Denies unconfigured zones, unavailable sources, stale or equivocal state,
    /// incomplete chains, and every directly or transitively revoked authority.
    pub fn verify(&self, zone: &ZoneId, token_id: ObjectId, issuer: KeyId) -> HostResult<()> {
        self.verify_for_dispatch(zone, token_id, issuer).map(|_| ())
    }

    /// Refresh authority and retain its authenticated deadline across a short
    /// runtime-selection wait. This does not reserve a token use or replay nonce.
    ///
    /// # Errors
    /// Returns the same authority failures as [`Self::verify`].
    pub fn verify_for_dispatch(
        &self,
        zone: &ZoneId,
        token_id: ObjectId,
        issuer: KeyId,
    ) -> HostResult<RuntimeRevocationPermit> {
        for feed in &self.feeds {
            let mut feed = feed.lock().map_err(|_| invalid("feed state is poisoned"))?;
            if &feed.config.zone_id == zone {
                let snapshot = feed.refresh()?;
                let (tokens, keys) = indexes(&snapshot.tokens, &snapshot.keys)?;
                let chain = snapshot.chain(feed.owner.key_id());
                let observed_at = Instant::now();
                let clock = feed.require_fresh(&snapshot)?;
                check_revocation_chain(
                    token_id,
                    issuer,
                    &chain,
                    &CascadeConfig::default(),
                    clock.saturating_sub(snapshot.issued_at_ms) / 1000,
                    |token| {
                        tokens.get(token).map(|at| RevocationRecord {
                            revoked_at_unix_ms: *at,
                        })
                    },
                    |kid, hop| {
                        // Root tokens can reach the owner at hop zero; an owner
                        // revocation must still apply at that shorter path.
                        let owner_revocation = (kid == &chain.owner_key)
                            .then(|| keys.get(&(kid.clone(), CascadeHop::OwnerAttestation)))
                            .flatten();
                        owner_revocation
                            .or_else(|| keys.get(&(kid.clone(), hop)))
                            .map(|at| RevocationRecord {
                                revoked_at_unix_ms: *at,
                            })
                    },
                )
                .map_err(|error| invalid(&error.to_string()))?;
                let deadline = observed_at
                    .checked_add(Duration::from_millis(snapshot.expires_at_ms - clock))
                    .ok_or_else(|| invalid("dispatch deadline is invalid"))?;
                let permit = RuntimeRevocationPermit {
                    deadline,
                    expires_at_ms: snapshot.expires_at_ms,
                };
                permit.require_current()?;
                return Ok(permit);
            }
        }
        Err(invalid("request zone has no configured owner feed"))
    }
}

impl RuntimeRevocationSnapshot {
    fn chain(&self, owner: KeyId) -> AttestationChain {
        AttestationChain {
            owner_key: owner,
            issuance_to_node: self.issuance_to_node.clone(),
            node_to_owner: self.node_to_owner.clone(),
        }
    }
}

impl Feed {
    fn open(config: RuntimeRevocationZoneConfig) -> HostResult<Self> {
        let mut key = [0u8; 32];
        hex::decode_to_slice(&config.owner_public_key_hex, &mut key)
            .map_err(|_| invalid("owner public key must contain 64 hexadecimal digits"))?;
        let owner = Ed25519VerifyingKey::from_bytes(&key)
            .map_err(|_| invalid("owner public key is invalid"))?;
        let checkpoint_owner = storage::checkpoint_owner(&config.checkpoint_file)?;
        let lock_path = companion(&config.checkpoint_file, ".lock");
        let mut lock = private_options()
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|_| invalid("checkpoint lock cannot be opened"))?;
        storage::require_private(&lock, checkpoint_owner)?;
        lock.try_lock()
            .map_err(|_| invalid("checkpoint already has a writer"))?;
        let mut marker = Vec::new();
        (&mut lock)
            .take(INITIALIZED.len() as u64 + 1)
            .read_to_end(&mut marker)
            .map_err(|_| invalid("checkpoint lock cannot be read"))?;
        if !marker.is_empty() && marker != INITIALIZED {
            return Err(invalid("checkpoint initialization marker is corrupt"));
        }
        let mut checkpoint = match std::fs::symlink_metadata(&config.checkpoint_file) {
            Ok(_) => Some(read_checkpoint(
                &config.checkpoint_file,
                &config,
                &owner,
                checkpoint_owner,
            )?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && marker.is_empty() => None,
            Err(_) => return Err(invalid("initialized checkpoint is missing or unreadable")),
        };
        // A completed staged write can contain stronger revocations than the
        // published checkpoint. Recover it before consulting current input;
        // torn/invalid staging must refuse rather than disappear on restart.
        let next_path = companion(&config.checkpoint_file, ".next");
        match std::fs::symlink_metadata(&next_path) {
            Ok(_) => {
                let staged = read_checkpoint(&next_path, &config, &owner, checkpoint_owner)?;
                if let Some(previous) = &checkpoint {
                    require_checkpoint_successor(previous, &staged)?;
                }
                std::fs::rename(&next_path, &config.checkpoint_file)
                    .and_then(|()| sync_parent(&config.checkpoint_file))
                    .map_err(|_| invalid("interrupted checkpoint cannot be recovered"))?;
                checkpoint = Some(staged);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(invalid("checkpoint staging state is unavailable")),
        }
        let clock_ms = now_ms()?;
        if checkpoint
            .as_ref()
            .is_some_and(|value| clock_ms < value.observed_at_ms)
        {
            return Err(invalid("host clock is older than the durable checkpoint"));
        }
        let mut feed = Self {
            config,
            owner,
            checkpoint,
            failed: false,
            clock_ms,
            clock_at: Instant::now(),
            checkpoint_owner,
            _lock: lock,
        };
        feed.refresh()?;
        if marker.is_empty() {
            feed._lock
                .write_all(INITIALIZED)
                .and_then(|()| feed._lock.sync_all())
                .and_then(|()| sync_parent(&lock_path))
                .map_err(|_| invalid("checkpoint initialization could not be synchronized"))?;
        }
        Ok(feed)
    }

    fn observe_clock(&mut self) -> HostResult<u64> {
        Ok(self.observe_clock_at(now_ms()?, Instant::now()))
    }

    fn observe_clock_at(&mut self, wall: u64, now: Instant) -> u64 {
        let elapsed =
            u64::try_from(now.duration_since(self.clock_at).as_millis()).unwrap_or(u64::MAX);
        let monotonic = self.clock_ms.saturating_add(elapsed);
        if wall > monotonic {
            self.clock_ms = wall;
            self.clock_at = now;
        }
        // Keep the original anchor if wall time stalls or retreats. Resetting
        // it on every read would discard fractional milliseconds indefinitely.
        wall.max(monotonic)
    }

    fn refresh(&mut self) -> HostResult<RuntimeRevocationSnapshot> {
        if self.failed {
            return Err(invalid("checkpoint write failed; reopen after recovery"));
        }
        if self
            .checkpoint
            .as_ref()
            .is_some_and(|value| value.capacity_exhausted)
        {
            return Err(invalid(
                "conflicting revocations exceeded durable capacity; operator recovery required",
            ));
        }
        let bytes = read_bounded(&self.config.snapshot_file, MAX_BYTES)?;
        let signed: SignedRuntimeRevocations =
            serde_json::from_slice(&bytes).map_err(|_| invalid("snapshot is invalid JSON"))?;
        let snapshot = &signed.payload;
        let transcript = snapshot.signing_bytes()?;
        if signed.object_type != RUNTIME_REVOCATION_SCHEMA {
            return Err(invalid("snapshot envelope type is invalid"));
        }
        signed
            .verify_with_policy(
                &transcript,
                PqSigningPolicy::ClassicalOnly,
                Some(&self.owner),
                None,
            )
            .map_err(|_| invalid("snapshot owner signature is invalid"))?;
        if snapshot.schema != RUNTIME_REVOCATION_SCHEMA
            || snapshot.zone_id != self.config.zone_id
            || snapshot.generation == 0
            || !snapshot
                .expires_at_ms
                .checked_sub(snapshot.issued_at_ms)
                .is_some_and(|life| (1..=MAX_REVOCATION_SNAPSHOT_LIFETIME_MS).contains(&life))
        {
            return Err(invalid("snapshot identity or lifetime is invalid"));
        }
        let owner = self.owner.key_id();
        snapshot
            .chain(owner.clone())
            .validate()
            .map_err(|_| invalid("snapshot attestation chain is invalid"))?;
        let nodes: std::collections::HashSet<_> = snapshot
            .node_to_owner
            .iter()
            .map(|(node, _)| node)
            .collect();
        if snapshot
            .node_to_owner
            .iter()
            .any(|(node, root)| root != &owner || node == &owner)
            || snapshot.issuance_to_node.iter().any(|(issuer, node)| {
                issuer == &owner
                    || issuer == node
                    || nodes.contains(issuer)
                    || (node != &owner && !nodes.contains(node))
            })
        {
            return Err(invalid(
                "snapshot attestation edges must reach the pinned owner",
            ));
        }
        let (tokens, keys) = indexes(&snapshot.tokens, &snapshot.keys)?;
        if snapshot
            .issuance_to_node
            .iter()
            .any(|(issuer, _)| keys.contains_key(&(issuer.clone(), CascadeHop::NodeAttestation)))
            || snapshot
                .node_to_owner
                .iter()
                .any(|(node, _)| keys.contains_key(&(node.clone(), CascadeHop::IssuerKey)))
        {
            return Err(invalid(
                "snapshot reused a revoked key under a different role",
            ));
        }
        if tokens
            .values()
            .chain(keys.values())
            .any(|at| *at > snapshot.issued_at_ms)
        {
            return Err(invalid("snapshot revocations must already be effective"));
        }
        let clock = self.observe_clock()?;
        if snapshot.issued_at_ms > clock.saturating_add(MAX_FUTURE_SKEW_MS) {
            return Err(invalid("snapshot issuance is in the future"));
        }
        let digest = *blake3::hash(&transcript).as_bytes();
        if let Some(previous) = &self.checkpoint {
            if snapshot.generation < previous.generation {
                return Err(invalid("snapshot generation rolled back"));
            }
            if snapshot.generation == previous.generation {
                if digest != previous.digest {
                    let mut poisoned = previous.clone();
                    merge_history(&mut poisoned, snapshot, &tokens, &keys)?;
                    poisoned.equivocated = true;
                    poisoned.observed_at_ms = clock;
                    self.persist(poisoned)?;
                    return Err(invalid(
                        "owner signed conflicting snapshots for one generation",
                    ));
                }
                if previous.equivocated {
                    return Err(invalid(
                        "equivocal generation requires a newer complete snapshot",
                    ));
                }
                self.require_fresh(snapshot)?;
                return Ok(signed.payload);
            }
            let (old_tokens, old_keys) = indexes(&previous.tokens, &previous.keys)?;
            if old_tokens
                .iter()
                .any(|(id, at)| tokens.get(id).is_none_or(|next| next > at))
                || old_keys
                    .iter()
                    .any(|(id, at)| keys.get(id).is_none_or(|next| next > at))
                || bindings_changed(&previous.issuance_to_node, &snapshot.issuance_to_node)
                || bindings_changed(&previous.node_to_owner, &snapshot.node_to_owner)
                || roles_changed(previous, snapshot)
            {
                let mut poisoned = previous.clone();
                merge_history(&mut poisoned, snapshot, &tokens, &keys)?;
                poisoned.generation = snapshot.generation;
                poisoned.digest = digest;
                poisoned.equivocated = true;
                poisoned.observed_at_ms = clock;
                self.persist(poisoned)?;
                return Err(invalid(
                    "snapshot weakened a revocation or changed an attestation binding",
                ));
            }
        }
        // Even an expired authenticated successor advances the rollback floor.
        // It cannot authorize execution or be replaced by an older healthy file.
        let mut checkpoint = Checkpoint {
            zone_id: snapshot.zone_id.clone(),
            owner_kid: self.owner.key_id(),
            generation: snapshot.generation,
            digest,
            observed_at_ms: clock,
            equivocated: false,
            capacity_exhausted: false,
            issuance_to_node: self
                .checkpoint
                .as_ref()
                .map_or_else(Vec::new, |value| value.issuance_to_node.clone()),
            node_to_owner: self
                .checkpoint
                .as_ref()
                .map_or_else(Vec::new, |value| value.node_to_owner.clone()),
            tokens: snapshot.tokens.clone(),
            keys: snapshot.keys.clone(),
        };
        merge_history(&mut checkpoint, snapshot, &tokens, &keys)?;
        let exhausted = checkpoint.capacity_exhausted;
        self.persist(checkpoint)?;
        if exhausted {
            return Err(invalid("attestation history exceeded durable capacity"));
        }
        self.require_fresh(snapshot)?;
        Ok(signed.payload)
    }

    fn require_fresh(&mut self, snapshot: &RuntimeRevocationSnapshot) -> HostResult<u64> {
        let now = self.observe_clock()?;
        if now >= snapshot.expires_at_ms {
            if let Some(previous) = &self.checkpoint
                && previous.observed_at_ms < snapshot.expires_at_ms
            {
                let mut expired = previous.clone();
                expired.observed_at_ms = now;
                self.persist(expired)?;
            }
            return Err(invalid("snapshot expired"));
        }
        Ok(now)
    }

    fn persist(&mut self, checkpoint: Checkpoint) -> HostResult<()> {
        let stored = StoredCheckpoint {
            checksum: checkpoint_checksum(&checkpoint)?,
            checkpoint,
        };
        let bytes =
            serde_json::to_vec(&stored).map_err(|_| invalid("checkpoint cannot be encoded"))?;
        if bytes.len() > MAX_BYTES {
            return Err(invalid("checkpoint exceeds its byte limit"));
        }
        // A write/rename/sync failure may already have changed disk. Latch before
        // touching storage and clear only after publication is known durable.
        self.failed = true;
        let next_path = companion(&self.config.checkpoint_file, ".next");
        let mut next = private_options()
            .create(true)
            .truncate(false)
            .open(&next_path)
            .map_err(|_| invalid("checkpoint staging file cannot be opened"))?;
        storage::require_private(&next, self.checkpoint_owner)?;
        next.set_len(0)
            .and_then(|()| next.write_all(&bytes))
            .and_then(|()| next.sync_all())
            .and_then(|()| std::fs::rename(&next_path, &self.config.checkpoint_file))
            .and_then(|()| sync_parent(&self.config.checkpoint_file))
            .map_err(|_| invalid("checkpoint could not be synchronized"))?;
        self.checkpoint = Some(stored.checkpoint);
        self.failed = false;
        Ok(())
    }
}

fn indexes(
    tokens: &[RuntimeTokenRevocation],
    keys: &[RuntimeKeyRevocation],
) -> HostResult<(TokenIndex, KeyIndex)> {
    if tokens.len().saturating_add(keys.len()) > MAX_RECORDS {
        return Err(invalid("revocation record limit exceeded"));
    }
    let mut token_index = HashMap::new();
    let mut key_index = HashMap::new();
    for token in tokens {
        if token_index
            .insert(token.token_id, token.revoked_at_ms)
            .is_some()
        {
            return Err(invalid("duplicate token revocation"));
        }
    }
    for key in keys {
        if key_index
            .insert((key.kid.clone(), key.hop), key.revoked_at_ms)
            .is_some()
        {
            return Err(invalid("duplicate scoped key revocation"));
        }
    }
    Ok((token_index, key_index))
}

fn bindings_changed(known: &[(KeyId, KeyId)], next: &[(KeyId, KeyId)]) -> bool {
    next.iter().any(|(source, target)| {
        known
            .iter()
            .find(|(previous, _)| previous == source)
            .is_some_and(|(_, previous_target)| previous_target != target)
    })
}

fn roles_changed(known: &Checkpoint, next: &RuntimeRevocationSnapshot) -> bool {
    let (issuers, nodes) = known_roles(known);
    next.issuance_to_node
        .iter()
        .any(|(issuer, _)| nodes.contains(issuer))
        || next
            .node_to_owner
            .iter()
            .any(|(node, _)| issuers.contains(node))
}

fn known_roles(
    checkpoint: &Checkpoint,
) -> (
    std::collections::HashSet<KeyId>,
    std::collections::HashSet<KeyId>,
) {
    let mut issuers: std::collections::HashSet<_> = checkpoint
        .issuance_to_node
        .iter()
        .map(|(issuer, _)| issuer.clone())
        .collect();
    let mut nodes: std::collections::HashSet<_> = checkpoint
        .node_to_owner
        .iter()
        .map(|(node, _)| node.clone())
        .collect();
    for record in &checkpoint.keys {
        match record.hop {
            CascadeHop::IssuerKey => {
                issuers.insert(record.kid.clone());
            }
            CascadeHop::NodeAttestation => {
                nodes.insert(record.kid.clone());
            }
            CascadeHop::OwnerAttestation => {}
        }
    }
    (issuers, nodes)
}

fn merge_bindings(known: &mut Vec<(KeyId, KeyId)>, next: &[(KeyId, KeyId)]) {
    for (source, target) in next {
        if !known.iter().any(|(previous, _)| previous == source) {
            known.push((source.clone(), target.clone()));
        }
    }
}

fn merge_history(
    checkpoint: &mut Checkpoint,
    snapshot: &RuntimeRevocationSnapshot,
    tokens: &TokenIndex,
    keys: &KeyIndex,
) -> HostResult<()> {
    let (mut all_tokens, mut all_keys) = indexes(&checkpoint.tokens, &checkpoint.keys)?;
    for (id, at) in tokens {
        all_tokens
            .entry(*id)
            .and_modify(|old| *old = (*old).min(*at))
            .or_insert(*at);
    }
    for (id, at) in keys {
        all_keys
            .entry(id.clone())
            .and_modify(|old| *old = (*old).min(*at))
            .or_insert(*at);
    }
    if all_tokens.len().saturating_add(all_keys.len()) > MAX_RECORDS {
        // Do not forget an authenticated conflict merely because its union is
        // too large. Persist a terminal fence instead of allowing the old
        // generation to become healthy again after restart.
        checkpoint.capacity_exhausted = true;
        return Ok(());
    }
    checkpoint.tokens = all_tokens
        .into_iter()
        .map(|(token_id, revoked_at_ms)| RuntimeTokenRevocation {
            token_id,
            revoked_at_ms,
        })
        .collect();
    checkpoint.keys = all_keys
        .into_iter()
        .map(|((kid, hop), revoked_at_ms)| RuntimeKeyRevocation {
            kid,
            hop,
            revoked_at_ms,
        })
        .collect();
    let mut issuance = checkpoint.issuance_to_node.clone();
    let mut nodes = checkpoint.node_to_owner.clone();
    let (known_issuers, mut known_nodes) = known_roles(checkpoint);
    // One contradictory key cannot erase first-seen roles for all the other
    // authenticated keys. Retain every compatible node first, then only issuer
    // bindings whose source/target still respect the retained role history.
    for edge in &snapshot.node_to_owner {
        if !known_issuers.contains(&edge.0) {
            merge_bindings(&mut nodes, std::slice::from_ref(edge));
            known_nodes.insert(edge.0.clone());
        }
    }
    for edge in &snapshot.issuance_to_node {
        if !known_nodes.contains(&edge.0)
            && (edge.1 == checkpoint.owner_kid || nodes.iter().any(|(node, _)| node == &edge.1))
        {
            merge_bindings(&mut issuance, std::slice::from_ref(edge));
        }
    }
    if issuance.len().saturating_add(nodes.len())
        > fcp_evidence::revocation_cascade::MAX_ATTESTATION_CHAIN_EDGES
    {
        checkpoint.capacity_exhausted = true;
    } else {
        checkpoint.issuance_to_node = issuance;
        checkpoint.node_to_owner = nodes;
    }
    Ok(())
}

fn checkpoint_checksum(checkpoint: &Checkpoint) -> HostResult<[u8; 32]> {
    let bytes =
        serde_json::to_vec(checkpoint).map_err(|_| invalid("checkpoint cannot be encoded"))?;
    Ok(blake3::derive_key(
        "fcp.host.revocation-checkpoint.v1",
        &bytes,
    ))
}

fn read_checkpoint(
    path: &Path,
    config: &RuntimeRevocationZoneConfig,
    owner: &Ed25519VerifyingKey,
    file_owner: u32,
) -> HostResult<Checkpoint> {
    let bytes = read_local_file(path, MAX_BYTES, Some(file_owner))?;
    let stored: StoredCheckpoint =
        serde_json::from_slice(&bytes).map_err(|_| invalid("checkpoint is corrupt"))?;
    let value = stored.checkpoint;
    if stored.checksum != checkpoint_checksum(&value)?
        || value.zone_id != config.zone_id
        || value.owner_kid != owner.key_id()
        || value.generation == 0
    {
        return Err(invalid("checkpoint identity or checksum is invalid"));
    }
    indexes(&value.tokens, &value.keys)?;
    AttestationChain {
        owner_key: owner.key_id(),
        issuance_to_node: value.issuance_to_node.clone(),
        node_to_owner: value.node_to_owner.clone(),
    }
    .validate()
    .map_err(|_| invalid("checkpoint chain history is invalid"))?;
    if value.node_to_owner.iter().any(|(node, root)| {
        root != &value.owner_kid
            || node == &value.owner_kid
            || value
                .issuance_to_node
                .iter()
                .any(|(issuer, _)| issuer == node)
    }) {
        return Err(invalid("checkpoint key roles or owner binding are invalid"));
    }
    Ok(value)
}

fn require_checkpoint_successor(previous: &Checkpoint, next: &Checkpoint) -> HostResult<()> {
    let (tokens, keys) = indexes(&next.tokens, &next.keys)?;
    let retains_edges =
        |old: &[(KeyId, KeyId)], new: &[(KeyId, KeyId)]| old.iter().all(|edge| new.contains(edge));
    if next.generation < previous.generation
        || next.observed_at_ms < previous.observed_at_ms
        || previous.capacity_exhausted && !next.capacity_exhausted
        || next.generation == previous.generation && previous.equivocated && !next.equivocated
        || next.generation == previous.generation
            && next.digest != previous.digest
            && !next.equivocated
        || previous.tokens.iter().any(|entry| {
            tokens
                .get(&entry.token_id)
                .is_none_or(|at| *at > entry.revoked_at_ms)
        })
        || previous.keys.iter().any(|entry| {
            keys.get(&(entry.kid.clone(), entry.hop))
                .is_none_or(|at| *at > entry.revoked_at_ms)
        })
        || !retains_edges(&previous.issuance_to_node, &next.issuance_to_node)
        || !retains_edges(&previous.node_to_owner, &next.node_to_owner)
    {
        return Err(invalid(
            "interrupted checkpoint would weaken durable history",
        ));
    }
    Ok(())
}

fn companion(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options
}

fn read_bounded(path: &Path, limit: usize) -> HostResult<Vec<u8>> {
    read_local_file(path, limit, None)
}

fn read_local_file(path: &Path, limit: usize, private_owner: Option<u32>) -> HostResult<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| invalid("source is unavailable"))?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(invalid("source must be a bounded regular file"));
    }
    let file = options
        .open(path)
        .map_err(|_| invalid("source cannot be opened"))?;
    if let Some(owner) = private_owner {
        storage::require_private(&file, owner)?;
    }
    let metadata = file
        .metadata()
        .map_err(|_| invalid("source metadata is unavailable"))?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(invalid("source must be a bounded regular file"));
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid("source cannot be read"))?;
    if bytes.len() > limit {
        return Err(invalid("source exceeds its byte limit"));
    }
    Ok(bytes)
}

fn sync_parent(path: &Path) -> std::io::Result<()> {
    File::open(path.parent().unwrap_or_else(|| Path::new(".")))?.sync_all()
}

#[cfg(all(test, unix))]
#[path = "runtime_revocation/tests.rs"]
mod tests;
