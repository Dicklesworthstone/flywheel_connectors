//! Opt-in, private custody of completed invocation responses.
//!
//! Invocation history remains payload-free. This separate store retains only
//! bounded successful responses, under the exact durable attempt and effect
//! binding, for explicit operator recovery. A retained response is never an
//! instruction to execute again or authority to bypass current host policy.
//! Byte-limited attempts retain their exact settled envelope binding too;
//! recovery reads validate that binding without spending the same bytes again.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use fcp_kernel::{InvokeResponse, InvokeStatus, RequestId};
use serde::{Deserialize, Serialize};

use crate::{
    HostError, HostResult, InvocationIdempotency, InvocationOutcome, InvocationRecord,
    InvocationResponseBudget, InvocationTicket,
};

/// Maximum complete encoded custody record, including its response and binding.
pub const INVOCATION_RESULT_MAX_BYTES: usize = 2 * 1024 * 1024;
/// Maximum number of live result records in one host's private store.
pub const INVOCATION_RESULT_MAX_ENTRIES: usize = 64;
/// Maximum aggregate bytes of live result files, independent of record count.
pub const INVOCATION_RESULT_MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
/// Results expire one day after completion; retention and lookup never renew it.
pub const INVOCATION_RESULT_TTL_SECONDS: i64 = 24 * 60 * 60;

const VERSION: u32 = 1;
const CHECKSUM_DOMAIN: &str = "fcp.host.invocation-result.file.v1";
const RESPONSE_DOMAIN: &str = "fcp.host.invocation-result.response.v1";
const KEY_DOMAIN: &str = "fcp.host.invocation-result.key.v1";
const LOCK_NAME: &str = ".writer.lock";

/// Exact successful attempt whose response may be recovered.
///
/// Admission time prevents a recreated lifecycle journal from colliding with a
/// previous generation that happened to reuse the same numeric attempt ID.
/// Both digests are needed: verified principal scope and the original opaque
/// transport authority/effects must remain bound independently.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationResultBinding {
    pub ticket: InvocationTicket,
    pub admitted_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub connector_id: String,
    pub operation: String,
    pub zone_id: String,
    pub principal: String,
    pub idempotency: InvocationIdempotency,
    pub transport_idempotency: InvocationIdempotency,
    pub audit_event_id: String,
    /// Exact allowed response settlement for a byte-limited admission.
    /// Historical records and grants without a byte ceiling omit this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_response: Option<InvocationResponseBudget>,
}

impl InvocationResultBinding {
    /// Bind a fully finalized, durable local success without inferring missing
    /// historical fields. Mesh-origin observations are a different authority.
    ///
    /// # Errors
    /// Rejects incomplete/unsuccessful history or missing exact effect binding.
    pub fn from_record(record: &InvocationRecord) -> HostResult<Self> {
        let terminal = record.terminal.as_ref().ok_or_else(incomplete)?;
        let finalization = record.finalization.as_ref().ok_or_else(incomplete)?;
        if !record.durable
            || terminal.outcome != InvocationOutcome::Succeeded
            || !(200..300).contains(&terminal.http_status)
            || !finalization.budget_finalized
            || finalization.response_status != Some(InvokeStatus::Ok)
            || !finalization
                .response_http_status
                .is_some_and(|status| (200..300).contains(&status))
            || (terminal.receipt_id.is_some() && !finalization.receipt_recorded)
            || finalization.sampling_completed == Some(false)
            || (finalization.sampling_operation_id.is_some()
                && finalization.sampling_completed != Some(true))
            || record.ticket.operation_id != record.admission.operation_id
            || record
                .capability_response
                .as_ref()
                .is_some_and(|budget| !budget.is_settled())
        {
            return Err(incomplete());
        }
        let binding = Self {
            ticket: record.ticket.clone(),
            admitted_at: record.admitted_at,
            finished_at: record.finished_at.ok_or_else(incomplete)?,
            connector_id: record.admission.connector_id.clone(),
            operation: record.admission.operation.clone(),
            zone_id: record.admission.zone_id.clone(),
            principal: record.admission.principal.clone(),
            idempotency: record
                .admission
                .idempotency
                .clone()
                .ok_or_else(incomplete)?,
            transport_idempotency: record
                .admission
                .transport_idempotency
                .clone()
                .ok_or_else(incomplete)?,
            audit_event_id: finalization.audit_event_id.clone().ok_or_else(incomplete)?,
            capability_response: record.capability_response.clone(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validate a bounded request binding before any filesystem access.
    ///
    /// # Errors
    /// Rejects malformed identities, digests, or nonmonotonic timestamps.
    pub fn validate(&self) -> HostResult<()> {
        if self.ticket.attempt_id == 0
            || self.finished_at < self.admitted_at
            || self
                .finished_at
                .checked_add_signed(Duration::seconds(INVOCATION_RESULT_TTL_SECONDS))
                .is_none()
            || [
                &self.ticket.operation_id,
                &self.connector_id,
                &self.operation,
                &self.zone_id,
                &self.principal,
                &self.audit_event_id,
            ]
            .into_iter()
            .any(|value| {
                value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control)
            })
            || [
                &self.idempotency.scope_digest,
                &self.idempotency.effect_digest,
                &self.transport_idempotency.scope_digest,
                &self.transport_idempotency.effect_digest,
            ]
            .into_iter()
            .any(|digest| !valid_digest(digest))
            || self
                .capability_response
                .as_ref()
                .is_some_and(|budget| !budget.is_settled())
        {
            return Err(invalid("invalid invocation result binding"));
        }
        Ok(())
    }
}

/// Private response returned only by the explicitly authenticated result API.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedInvocationResult {
    pub version: u32,
    pub binding: InvocationResultBinding,
    pub retained_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Versioned digest of the complete final invoke envelope, not just output.
    pub response_digest: String,
    pub response: InvokeResponse,
}

impl RetainedInvocationResult {
    /// Verify custody before reusing its actual result in a checkpoint.
    ///
    /// # Errors
    /// Refuses another attempt/effect, expiry, clock rollback, an invalid success
    /// envelope, changed bytes, or an oversized encoded record.
    pub fn validate(
        &self,
        expected: &InvocationResultBinding,
        now: DateTime<Utc>,
    ) -> HostResult<()> {
        self.validate_contents(expected)?;
        if now < self.retained_at || now >= self.expires_at {
            return Err(unavailable(
                "invocation result retention has expired or clock moved backwards",
            ));
        }
        Ok(())
    }

    fn validate_contents(&self, expected: &InvocationResultBinding) -> HostResult<()> {
        self.binding.validate()?;
        if self.version != VERSION
            || &self.binding != expected
            || self.retained_at < self.binding.finished_at
            || Some(self.expires_at)
                != self
                    .binding
                    .finished_at
                    .checked_add_signed(Duration::seconds(INVOCATION_RESULT_TTL_SECONDS))
            || self.retained_at >= self.expires_at
            || !valid_digest(&self.response_digest)
        {
            return Err(invalid(
                "invocation result does not match its retained binding",
            ));
        }
        fcp_manifest::OperationContractSet::validate_response_envelope(
            &RequestId(self.binding.ticket.operation_id.clone()),
            &self.response,
        )
        .map_err(|_| invalid("invocation result has an invalid response envelope"))?;
        if self.response.status != InvokeStatus::Ok {
            return Err(invalid("invocation result is not a successful response"));
        }
        if let Some(budget) = &self.binding.capability_response {
            budget.validate_response(&self.response)?;
        }
        let encoded = encode_bounded(&self.response)?;
        if digest(RESPONSE_DOMAIN, &encoded) != self.response_digest {
            return Err(invalid("invocation result response checksum mismatch"));
        }
        // A caller can construct this type directly; enforce the same limit as
        // the durable/HTTP reader before it becomes private workflow state.
        encode_bounded(self)?;
        Ok(())
    }
}

/// Explicit exact-attempt request; identifiers alone never select an output.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationResultQueryRequest {
    pub binding: InvocationResultBinding,
}

/// No result is a custody limitation, never proof that an effect did not occur.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationResultQueryResponse {
    pub result: Option<RetainedInvocationResult>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultFile {
    result: RetainedInvocationResult,
    checksum: String,
}

struct Entry {
    bytes: u64,
    expires_at: DateTime<Utc>,
}

struct StoreState {
    entries: BTreeMap<String, Entry>,
    last_observed_at: DateTime<Utc>,
    poisoned: bool,
}

/// An exclusively owned, bounded directory separate from lifecycle metadata.
///
/// This is opt-in storage of potentially sensitive output. It requires Unix
/// private permissions and directory synchronization, and never falls back to
/// a public or memory-only cache. Full/oversized results are simply unavailable
/// for recovery; invocation completion evidence remains independently retained.
pub struct InvocationResultStore {
    directory: PathBuf,
    _writer_lock: File,
    state: Mutex<StoreState>,
}

impl InvocationResultStore {
    /// Open or create one private result directory and recover its bounded index.
    ///
    /// # Errors
    /// Refuses unsupported filesystems, shared permissions, links, concurrent
    /// writers, unknown/corrupt files, or an existing store over its limits.
    pub fn open(directory: PathBuf) -> HostResult<Self> {
        Self::open_at(directory, Utc::now())
    }

    fn open_at(directory: PathBuf, now: DateTime<Utc>) -> HostResult<Self> {
        if !cfg!(unix) {
            return Err(unavailable(
                "invocation result custody requires private Unix storage",
            ));
        }
        if !directory.is_absolute() {
            return Err(invalid("invocation result directory must be absolute"));
        }
        create_directory(&directory)?;
        let writer_lock = open_private(&directory.join(LOCK_NAME), true)?;
        writer_lock
            .try_lock()
            .map_err(|_| unavailable("invocation result store already has a writer"))?;
        writer_lock
            .sync_all()
            .map_err(|_| unavailable("invocation result lock cannot be synchronized"))?;
        sync_directory(&directory)?;
        let mut entries = BTreeMap::new();
        let mut total_bytes = 0_u64;
        let mut inspected_files = 0_usize;
        for item in fs::read_dir(&directory)
            .map_err(|_| unavailable("invocation result directory cannot be read"))?
        {
            let item =
                item.map_err(|_| unavailable("invocation result directory cannot be read"))?;
            let name = item
                .file_name()
                .into_string()
                .map_err(|_| invalid("unknown file in invocation result directory"))?;
            if name == LOCK_NAME {
                continue;
            }
            inspected_files += 1;
            if inspected_files > INVOCATION_RESULT_MAX_ENTRIES + 1 {
                return Err(invalid(
                    "invocation result directory contains too many files",
                ));
            }
            // A crash before atomic publication can leave only a private
            // temporary file. It is not completed custody and cannot be read.
            if name.starts_with(".pending-") {
                drop(open_private(&item.path(), false)?);
                fs::remove_file(item.path())
                    .map_err(|_| unavailable("incomplete invocation result cannot be retired"))?;
                sync_directory(&directory)?;
                continue;
            }
            if !valid_filename(&name) {
                return Err(invalid("unknown file in invocation result directory"));
            }
            let (result, bytes) = read_result(&item.path())?;
            total_bytes = total_bytes
                .checked_add(bytes)
                .ok_or_else(|| invalid("invocation result storage limit exceeded"))?;
            if total_bytes > INVOCATION_RESULT_MAX_TOTAL_BYTES {
                return Err(invalid("invocation result storage limit exceeded"));
            }
            if filename(&result.binding)? != name || result.retained_at > now {
                return Err(invalid(
                    "invocation result file has inconsistent identity or time",
                ));
            }
            if result.expires_at <= now {
                fs::remove_file(item.path())
                    .map_err(|_| unavailable("expired invocation result cannot be retired"))?;
                sync_directory(&directory)?;
                continue;
            }
            if entries.len() >= INVOCATION_RESULT_MAX_ENTRIES {
                return Err(invalid("invocation result storage limit exceeded"));
            }
            entries.insert(
                name,
                Entry {
                    bytes,
                    expires_at: result.expires_at,
                },
            );
        }
        Ok(Self {
            directory,
            _writer_lock: writer_lock,
            state: Mutex::new(StoreState {
                entries,
                last_observed_at: now,
                poisoned: false,
            }),
        })
    }

    /// Retain the actual final response after durable successful finalization.
    ///
    /// Returns false when the finite size/count/aggregate allowance is full.
    /// Repeating the identical write does not extend retention; a conflicting
    /// response for the same exact attempt is refused without replacing it.
    ///
    /// # Errors
    /// Refuses incomplete history, invalid responses, clock rollback, conflicts,
    /// corrupted custody, or failed durable publication.
    pub fn retain(
        &self,
        record: &InvocationRecord,
        response: &InvokeResponse,
        now: DateTime<Utc>,
    ) -> HostResult<bool> {
        let binding = InvocationResultBinding::from_record(record)?;
        if let Some(budget) = &binding.capability_response {
            budget.validate_response(response)?;
        }
        if now < binding.finished_at {
            return Err(invalid("invocation result precedes completion"));
        }
        let expires_at = binding
            .finished_at
            .checked_add_signed(Duration::seconds(INVOCATION_RESULT_TTL_SECONDS))
            .ok_or_else(|| invalid("invalid invocation result expiration"))?;
        if now >= expires_at {
            return Ok(false);
        }
        let Some(response_bytes) = try_encode_bounded(response)? else {
            return Ok(false);
        };
        let response_digest = digest(RESPONSE_DOMAIN, &response_bytes);
        let result = RetainedInvocationResult {
            version: VERSION,
            binding,
            retained_at: now,
            expires_at,
            response_digest,
            response: response.clone(),
        };
        let Some(result_bytes) = try_encode_bounded(&result)? else {
            return Ok(false);
        };
        result.validate(&result.binding, now)?;
        let file = ResultFile {
            checksum: digest(CHECKSUM_DOMAIN, &result_bytes),
            result,
        };
        let Some(bytes) = try_encode_bounded(&file)? else {
            return Ok(false);
        };
        let name = filename(&file.result.binding)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| unavailable("invocation result store poisoned"))?;
        observe_time(&mut state, now)?;
        self.prune(&mut state, now)?;
        if state.entries.contains_key(&name) {
            let (retained, _) = read_result(&self.directory.join(&name))?;
            retained.validate(&file.result.binding, now)?;
            if retained.response_digest != file.result.response_digest {
                return Err(invalid(
                    "refusing to replace a retained invocation response",
                ));
            }
            return Ok(true);
        }
        let total: u64 = state.entries.values().map(|entry| entry.bytes).sum();
        if state.entries.len() >= INVOCATION_RESULT_MAX_ENTRIES
            || total.saturating_add(bytes.len() as u64) > INVOCATION_RESULT_MAX_TOTAL_BYTES
        {
            return Ok(false);
        }
        if let Err(error) = publish(&self.directory, &name, &bytes) {
            state.poisoned = true;
            return Err(error);
        }
        state.entries.insert(
            name,
            Entry {
                bytes: bytes.len() as u64,
                expires_at: file.result.expires_at,
            },
        );
        Ok(true)
    }

    /// Read the exact retained response, checking private-file integrity again.
    ///
    /// # Errors
    /// Refuses malformed bindings, corrupt/changed files, clock rollback, or a
    /// store whose previous durable mutation failed. Missing/expired is None.
    pub fn get(
        &self,
        binding: &InvocationResultBinding,
        now: DateTime<Utc>,
    ) -> HostResult<Option<RetainedInvocationResult>> {
        binding.validate()?;
        let name = filename(binding)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| unavailable("invocation result store poisoned"))?;
        observe_time(&mut state, now)?;
        self.prune(&mut state, now)?;
        if !state.entries.contains_key(&name) {
            return Ok(None);
        }
        let (result, _) = read_result(&self.directory.join(name))?;
        result.validate(binding, now)?;
        Ok(Some(result))
    }

    fn prune(&self, state: &mut StoreState, now: DateTime<Utc>) -> HostResult<()> {
        let expired = state
            .entries
            .iter()
            .filter(|(_, entry)| entry.expires_at <= now)
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        for name in expired {
            if fs::remove_file(self.directory.join(&name)).is_err()
                || sync_directory(&self.directory).is_err()
            {
                state.poisoned = true;
                return Err(unavailable("expired invocation result cannot be retired"));
            }
            state.entries.remove(&name);
        }
        Ok(())
    }
}

fn observe_time(state: &mut StoreState, now: DateTime<Utc>) -> HostResult<()> {
    if state.poisoned || now < state.last_observed_at {
        return Err(unavailable(
            "invocation result custody requires recovery or a monotonic clock",
        ));
    }
    state.last_observed_at = now;
    Ok(())
}

fn read_result(path: &Path) -> HostResult<(RetainedInvocationResult, u64)> {
    let file = open_private(path, false)?;
    let size = file
        .metadata()
        .map_err(|_| unavailable("invocation result cannot be inspected"))?
        .len();
    if size > INVOCATION_RESULT_MAX_BYTES as u64 {
        return Err(invalid("invocation result exceeds its size limit"));
    }
    let mut bytes = Vec::new();
    file.take(INVOCATION_RESULT_MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable("invocation result cannot be read"))?;
    if bytes.len() > INVOCATION_RESULT_MAX_BYTES {
        return Err(invalid("invocation result exceeds its size limit"));
    }
    let file: ResultFile =
        serde_json::from_slice(&bytes).map_err(|_| invalid("invalid invocation result file"))?;
    let encoded = encode_bounded(&file.result)?;
    if !valid_digest(&file.checksum) || digest(CHECKSUM_DOMAIN, &encoded) != file.checksum {
        return Err(invalid("invocation result file checksum mismatch"));
    }
    file.result.validate_contents(&file.result.binding)?;
    Ok((file.result, bytes.len() as u64))
}

fn filename(binding: &InvocationResultBinding) -> HostResult<String> {
    Ok(format!(
        "result-{}.json",
        digest(KEY_DOMAIN, &encode_bounded(binding)?)
    ))
}

fn valid_filename(name: &str) -> bool {
    name.strip_prefix("result-")
        .and_then(|name| name.strip_suffix(".json"))
        .is_some_and(valid_digest)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

struct BoundedWriter {
    bytes: Vec<u8>,
    exceeded: bool,
}

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > INVOCATION_RESULT_MAX_BYTES.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::other("invocation result size limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn try_encode_bounded(value: &impl Serialize) -> HostResult<Option<Vec<u8>>> {
    let mut writer = BoundedWriter {
        bytes: Vec::new(),
        exceeded: false,
    };
    if serde_json::to_writer(&mut writer, value).is_err() {
        return if writer.exceeded {
            Ok(None)
        } else {
            Err(invalid("invocation result cannot be encoded"))
        };
    }
    Ok(Some(writer.bytes))
}

fn encode_bounded(value: &impl Serialize) -> HostResult<Vec<u8>> {
    try_encode_bounded(value)?.ok_or_else(|| invalid("invocation result exceeds its size limit"))
}

fn create_directory(path: &Path) -> HostResult<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => {
            sync_directory(
                path.parent()
                    .ok_or_else(|| invalid("invalid result directory"))?,
            )?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(unavailable("invocation result directory cannot be created")),
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| unavailable("invocation result directory cannot be inspected"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("invocation result directory must not be a symlink"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 {
            return Err(invalid(
                "invocation result directory must have private permissions",
            ));
        }
    }
    Ok(())
}

fn open_private(path: &Path, create: bool) -> HostResult<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(create)
        .create(create)
        .truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| unavailable("private invocation result cannot be opened"))?;
    let metadata = file
        .metadata()
        .map_err(|_| unavailable("invocation result cannot be inspected"))?;
    if !metadata.is_file() {
        return Err(invalid("invocation result must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(invalid(
                "invocation result files must be private with one link",
            ));
        }
    }
    Ok(file)
}

fn publish(directory: &Path, name: &str, bytes: &[u8]) -> HostResult<()> {
    let mut temporary = tempfile::Builder::new()
        .prefix(".pending-")
        .tempfile_in(directory)
        .map_err(|_| unavailable("invocation result temporary file cannot be created"))?;
    temporary
        .write_all(bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| unavailable("invocation result cannot be synchronized"))?;
    temporary
        .persist_noclobber(directory.join(name))
        .map_err(|_| unavailable("invocation result cannot be published without replacement"))?;
    sync_directory(directory)
}

fn sync_directory(path: &Path) -> HostResult<()> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|file| file.sync_all())
            .map_err(|_| unavailable("invocation result directory cannot be synchronized"))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(unavailable(
            "invocation result custody requires directory synchronization",
        ))
    }
}

fn invalid(message: &str) -> HostError {
    HostError::InvalidFilter(message.to_owned())
}
fn unavailable(message: &str) -> HostError {
    HostError::Unavailable(message.to_owned())
}
fn incomplete() -> HostError {
    unavailable("invocation result requires fully finalized durable local success")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{
        HostAdminStateStore, InvocationAdmission, InvocationFinalization, InvocationTerminal,
    };
    use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
    use fcp_kernel::{ConnectorId, InvokeRequest};
    use fcp_prelude::{CapabilityConstraints, CapabilityToken, OperationId, ZoneId};
    use serde_json::json;

    fn time() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-11-22T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn record(id: &str) -> InvocationRecord {
        InvocationRecord {
            budget_requests_reserved: false,
            budget_usage_digest: None,
            capability_response: None,
            ticket: InvocationTicket {
                operation_id: id.into(),
                attempt_id: 7,
            },
            admission: InvocationAdmission {
                operation_id: id.into(),
                connector_id: "fcp.test".into(),
                operation: "test.create".into(),
                zone_id: "z:work".into(),
                principal: "alice".into(),
                correlation_id: None,
                deadline_at: time() + Duration::seconds(60),
                idempotency: Some(InvocationIdempotency {
                    scope_digest: "a".repeat(64),
                    effect_digest: "b".repeat(64),
                }),
                transport_idempotency: Some(InvocationIdempotency {
                    scope_digest: "c".repeat(64),
                    effect_digest: "d".repeat(64),
                }),
            },
            admitted_at: time(),
            finished_at: Some(time() + Duration::seconds(1)),
            terminal: Some(InvocationTerminal {
                outcome: InvocationOutcome::Succeeded,
                receipt_id: None,
                duration_ms: 1_000,
                http_status: 200,
            }),
            finalization: Some(InvocationFinalization {
                budget_finalized: true,
                audit_event_id: Some("audit-7".into()),
                response_http_status: Some(200),
                response_status: Some(InvokeStatus::Ok),
                ..InvocationFinalization::default()
            }),
            durable: true,
        }
    }

    fn response(id: &str) -> InvokeResponse {
        InvokeResponse::ok(
            RequestId(id.into()),
            json!({"created_id": "resource-123", "private": "result-secret-canary"}),
        )
    }

    async fn byte_limited_attempt(
        directory: &Path,
        id: &str,
        limit: u64,
    ) -> (HostAdminStateStore, InvocationTicket) {
        let key = Ed25519SigningKey::from_bytes(&[73; 32]).unwrap();
        let constraints = CapabilityConstraints {
            max_bytes: Some(limit),
            ..Default::default()
        };
        let mut encoded = Vec::new();
        ciborium::into_writer(&constraints, &mut encoded).unwrap();
        let now = Utc::now();
        let request = InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new(id),
            connector_id: ConnectorId::from_static("fcp.test.results:utility:1.0.0"),
            operation: OperationId::from_static("test.create"),
            zone_id: ZoneId::work(),
            input: serde_json::Value::Null,
            capability_token: CapabilityToken::from_raw(
                CapabilityTokenBuilder::new()
                    .capability_id("test.create")
                    .zone_id("z:work")
                    .principal("alice")
                    .issuer("node:test")
                    .audience("*")
                    .operations(&["test.create"])
                    .token_id(b"result-budget-private-token")
                    .validity(now - Duration::minutes(1), now + Duration::hours(1))
                    .try_constraints_cbor(&encoded)
                    .unwrap()
                    .sign(&key)
                    .unwrap(),
            ),
            holder_proof: None,
            context: None,
            idempotency_key: Some("result-budget-recovery".into()),
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: Vec::new(),
        };
        let admission = InvocationAdmission {
            operation_id: id.into(),
            connector_id: request.connector_id.to_string(),
            operation: request.operation.to_string(),
            zone_id: request.zone_id.to_string(),
            principal: "alice".into(),
            correlation_id: None,
            deadline_at: now + Duration::minutes(1),
            idempotency: InvocationIdempotency::from_request(&request, "alice").unwrap(),
            transport_idempotency: InvocationIdempotency::from_relay_request(&request, None)
                .unwrap(),
        };
        let store = HostAdminStateStore::with_state_path(directory.join("admin-state.json"))
            .unwrap();
        let ticket = store
            .admit_capability_invocation(admission, &request, &key.verifying_key())
            .await
            .unwrap();
        store
            .finish_invocation(
                &ticket,
                InvocationTerminal {
                    outcome: InvocationOutcome::Succeeded,
                    receipt_id: None,
                    duration_ms: 1,
                    http_status: 200,
                },
            )
            .await
            .unwrap();
        (store, ticket)
    }

    #[fcp_async_core::runtime::test]
    async fn signed_response_settlement_survives_custody_and_recovery_without_recharging() {
        let directory = tempfile::tempdir().unwrap();
        let (admin, ticket) = byte_limited_attempt(directory.path(), "metered", 4_096).await;
        let output = response("metered");
        admin.settle_capability_response(&ticket, &output).await.unwrap();
        admin
            .record_invocation_finalization(
                &ticket,
                InvocationFinalization {
                    budget_finalized: true,
                    audit_event_id: Some("metered-audit".into()),
                    response_http_status: Some(200),
                    response_status: Some(InvokeStatus::Ok),
                    ..InvocationFinalization::default()
                },
            )
            .await
            .unwrap();
        let entry = admin
            .invocation_record(&ticket.operation_id, Some(ticket.attempt_id))
            .await
            .unwrap();
        let binding = InvocationResultBinding::from_record(&entry).unwrap();
        assert!(binding.capability_response.as_ref().unwrap().is_settled());
        let before_recovery = admin.export_snapshot_json().await.unwrap();
        let now = Utc::now();
        let path = directory.path().join("results");
        let store = InvocationResultStore::open_at(path.clone(), now).unwrap();

        // An equal-length replacement must not acquire custody under the
        // allowance settled for the original complete envelope.
        let mut changed = output.clone();
        changed.result.as_mut().unwrap()["created_id"] = json!("resource-999");
        assert_eq!(
            serde_json::to_vec(&output).unwrap().len(),
            serde_json::to_vec(&changed).unwrap().len()
        );
        assert!(store.retain(&entry, &changed, now).is_err());
        assert!(store.retain(&entry, &output, now).unwrap());
        let retained = store.get(&binding, now).unwrap().unwrap();
        assert_eq!(retained.response.result, output.result);
        let mut omitted = binding.clone();
        omitted.capability_response = None;
        assert!(store.get(&omitted, now).unwrap().is_none());

        // A fresh custody checksum cannot replace the independently settled
        // response binding when restored by a workflow or another client.
        let mut replaced = retained.clone();
        replaced.response = changed;
        replaced.response_digest =
            digest(RESPONSE_DOMAIN, &encode_bounded(&replaced.response).unwrap());
        assert!(replaced.validate(&binding, now).is_err());
        drop(store);
        let reopened = InvocationResultStore::open_at(path, now).unwrap();
        for _ in 0..2 {
            let recovered = reopened.get(&binding, now).unwrap().unwrap();
            recovered.validate(&binding, now).unwrap();
            assert_eq!(recovered.response.result, output.result);
        }
        assert_eq!(admin.export_snapshot_json().await.unwrap(), before_recovery);
    }

    #[fcp_async_core::runtime::test]
    async fn unresolved_or_denied_byte_authority_never_becomes_result_custody() {
        let directory = tempfile::tempdir().unwrap();
        let (admin, ticket) = byte_limited_attempt(directory.path(), "denied", 1).await;
        let mut entry = admin
            .invocation_record(&ticket.operation_id, Some(ticket.attempt_id))
            .await
            .unwrap();
        // Public record construction must not turn a delivery marker into
        // evidence of byte settlement. Only the captured allowed binding does.
        entry.finalization = record("denied").finalization;
        assert!(InvocationResultBinding::from_record(&entry).is_err());
        let now = Utc::now();
        let store = InvocationResultStore::open_at(directory.path().join("results"), now)
            .unwrap();
        assert!(store.retain(&entry, &response("denied"), now).is_err());
        assert!(admin.settle_capability_response(&ticket, &response("denied")).await.is_err());
        let mut denied = admin
            .invocation_record(&ticket.operation_id, Some(ticket.attempt_id))
            .await
            .unwrap();
        denied.finalization = entry.finalization;
        assert!(InvocationResultBinding::from_record(&denied).is_err());
        assert!(store.retain(&denied, &response("denied"), now).is_err());
        assert_eq!(denied.terminal.unwrap().outcome, InvocationOutcome::Succeeded);
    }

    #[test]
    fn durable_round_trip_preserves_actual_output_and_nonrenewable_expiry() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("results");
        let now = time() + Duration::seconds(2);
        let entry = record("op");
        let binding = InvocationResultBinding::from_record(&entry).unwrap();
        let store = InvocationResultStore::open_at(path.clone(), now).unwrap();
        assert!(store.retain(&entry, &response("op"), now).unwrap());
        let first = store.get(&binding, now).unwrap().unwrap();
        assert!(
            store
                .retain(&entry, &response("op"), now + Duration::hours(1))
                .unwrap()
        );
        let second = store
            .get(&binding, now + Duration::hours(1))
            .unwrap()
            .unwrap();
        assert_eq!(first.expires_at, second.expires_at);
        assert_eq!(first.response_digest, second.response_digest);
        drop(store);
        let reopened = InvocationResultStore::open_at(path, now + Duration::hours(2)).unwrap();
        let actual = reopened
            .get(&binding, now + Duration::hours(2))
            .unwrap()
            .unwrap();
        assert_eq!(actual.response.result, response("op").result);
        assert!(reopened.get(&binding, first.expires_at).unwrap().is_none());
    }

    #[test]
    fn mismatched_attempt_effect_zone_principal_and_admission_never_select_output() {
        let directory = tempfile::tempdir().unwrap();
        let now = time() + Duration::seconds(2);
        let store = InvocationResultStore::open_at(directory.path().join("results"), now).unwrap();
        let entry = record("op");
        let binding = InvocationResultBinding::from_record(&entry).unwrap();
        assert!(store.retain(&entry, &response("op"), now).unwrap());
        let actual = store.get(&binding, now).unwrap().unwrap();
        let changes: [fn(&mut InvocationResultBinding); 7] = [
            |b| b.ticket.attempt_id += 1,
            |b| b.ticket.operation_id = "other".into(),
            |b| b.zone_id = "z:private".into(),
            |b| b.principal = "bob".into(),
            |b| b.idempotency.effect_digest = "e".repeat(64),
            |b| b.transport_idempotency.effect_digest = "e".repeat(64),
            |b| b.admitted_at -= Duration::seconds(1),
        ];
        for change in changes {
            let mut wrong = binding.clone();
            change(&mut wrong);
            assert!(store.get(&wrong, now).unwrap().is_none());
            assert!(actual.validate(&wrong, now).is_err());
        }
    }

    #[test]
    fn incomplete_history_and_invalid_responses_never_become_recoverable() {
        let directory = tempfile::tempdir().unwrap();
        let now = time() + Duration::seconds(2);
        let store = InvocationResultStore::open_at(directory.path().join("results"), now).unwrap();
        let mutations: [fn(&mut InvocationRecord); 8] = [
            |r| r.durable = false,
            |r| r.terminal.as_mut().unwrap().outcome = InvocationOutcome::OutcomeUnknown,
            |r| r.finalization.as_mut().unwrap().budget_finalized = false,
            |r| r.finalization.as_mut().unwrap().audit_event_id = None,
            |r| r.finalization.as_mut().unwrap().response_status = None,
            |r| r.finalization.as_mut().unwrap().sampling_completed = Some(false),
            |r| r.admission.transport_idempotency = None,
            |r| r.admission.operation_id = "different".into(),
        ];
        for mutate in mutations {
            let mut entry = record("op");
            mutate(&mut entry);
            assert!(store.retain(&entry, &response("op"), now).is_err());
        }
        assert!(
            store
                .retain(&record("op"), &response("wrong-id"), now)
                .is_err()
        );
        let mut missing = response("op");
        missing.result = None;
        assert!(store.retain(&record("op"), &missing, now).is_err());
        let null = InvokeResponse::ok(RequestId("op".into()), serde_json::Value::Null);
        assert!(store.retain(&record("op"), &null, now).unwrap());
    }

    #[test]
    fn conflicting_response_and_corruption_cannot_replace_original_custody() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("results");
        let now = time() + Duration::seconds(2);
        let store = InvocationResultStore::open_at(path.clone(), now).unwrap();
        let entry = record("op");
        let binding = InvocationResultBinding::from_record(&entry).unwrap();
        store.retain(&entry, &response("op"), now).unwrap();
        let changed = InvokeResponse::ok(RequestId("op".into()), json!({"changed": true}));
        assert!(store.retain(&entry, &changed, now).is_err());
        assert_eq!(
            store.get(&binding, now).unwrap().unwrap().response.result,
            response("op").result
        );
        let file = path.join(filename(&binding).unwrap());
        let mut bytes = fs::read(&file).unwrap();
        let offset = bytes
            .windows(b"resource-123".len())
            .position(|w| w == b"resource-123")
            .unwrap();
        bytes[offset] = b'X';
        fs::write(&file, bytes).unwrap();
        assert!(store.get(&binding, now).is_err());
        drop(store);
        assert!(InvocationResultStore::open_at(path, now).is_err());
    }

    #[test]
    fn finite_size_and_count_limits_do_not_evict_unexpired_results() {
        let directory = tempfile::tempdir().unwrap();
        let now = time() + Duration::seconds(2);
        let store = InvocationResultStore::open_at(directory.path().join("results"), now).unwrap();
        let oversized = InvokeResponse::ok(
            RequestId("large".into()),
            json!("x".repeat(INVOCATION_RESULT_MAX_BYTES)),
        );
        assert!(!store.retain(&record("large"), &oversized, now).unwrap());
        for i in 0..INVOCATION_RESULT_MAX_ENTRIES {
            let id = format!("op-{i}");
            assert!(store.retain(&record(&id), &response(&id), now).unwrap());
        }
        assert!(
            !store
                .retain(&record("overflow"), &response("overflow"), now)
                .unwrap()
        );
        let first = InvocationResultBinding::from_record(&record("op-0")).unwrap();
        assert!(store.get(&first, now).unwrap().is_some());
        assert!(
            !store
                .retain(&record("op-0"), &response("op-0"), now + Duration::days(1))
                .unwrap()
        );
        let mut next = record("next-day");
        next.admitted_at += Duration::days(1);
        next.finished_at = next.finished_at.map(|time| time + Duration::days(1));
        assert!(
            store
                .retain(&next, &response("next-day"), now + Duration::days(1))
                .unwrap()
        );
    }

    #[test]
    fn private_permissions_links_and_single_writer_are_enforced() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("results");
        let now = time() + Duration::seconds(2);
        let store = InvocationResultStore::open_at(path.clone(), now).unwrap();
        assert!(InvocationResultStore::open_at(path.clone(), now).is_err());
        store.retain(&record("op"), &response("op"), now).unwrap();
        let binding = InvocationResultBinding::from_record(&record("op")).unwrap();
        let file = path.join(filename(&binding).unwrap());
        assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o077, 0);
        fs::hard_link(&file, directory.path().join("linked-result")).unwrap();
        assert!(store.get(&binding, now).is_err());
        symlink(&path, directory.path().join("symlink-store")).unwrap();
        assert!(
            InvocationResultStore::open_at(directory.path().join("symlink-store"), now).is_err()
        );
        drop(store);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(InvocationResultStore::open_at(path, now).is_err());
    }

    #[test]
    fn clock_rollback_does_not_extend_or_reveal_retained_output() {
        let directory = tempfile::tempdir().unwrap();
        let now = time() + Duration::seconds(2);
        let store = InvocationResultStore::open_at(directory.path().join("results"), now).unwrap();
        store.retain(&record("op"), &response("op"), now).unwrap();
        let binding = InvocationResultBinding::from_record(&record("op")).unwrap();
        assert!(store.get(&binding, now - Duration::seconds(1)).is_err());
        let result = store.get(&binding, now).unwrap().unwrap();
        assert!(result.validate(&binding, result.expires_at).is_err());
        assert!(
            result
                .validate(&binding, result.retained_at - Duration::seconds(1))
                .is_err()
        );
    }
}
