//! Explicit compensations for a small set of completed connector operations.
//!
//! Built-in mappings name existing create/delete or create/archive operations
//! and use the resource identities returned by the original invocation. A
//! compensation cannot retract notifications, readers, or later changes.
//!
//! # Design principles
//!
//! - History contains hashes, so callers supply the original input and response.
//! - Matching hashes establish local continuity, not authenticated provenance.
//! - Executable history plans use only reviewed built-in mappings.
//! - Custom mappings remain available for offline planning.
//! - Non-reversible operations are flagged with human-readable guidance.
//! - Planning grants no authority; execution still needs live host checks.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

/// Maximum size of either caller-supplied source JSON file.
pub const MAX_SOURCE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EXECUTION_RECORD_BYTES: u64 = 16 * 1024;

/// Read a bounded, regular JSON source file without retaining its raw bytes.
///
/// # Errors
/// Refuses unreadable, non-regular, oversized, or malformed input. Diagnostics
/// deliberately omit private paths and source data.
pub fn read_source_json(path: &Path) -> Result<serde_json::Value> {
    read_bounded_json(path, MAX_SOURCE_BYTES)
        .map_err(|_| anyhow::anyhow!("source must be a readable JSON file of at most 16 MiB"))
}

/// Payload-free identity persisted before a compensation can have effects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UndoExecutionIdentity {
    /// Local source history entry; determines the exclusive fence filename.
    pub source_entry_id: String,
    /// Exact canonical connector identity recorded for the original operation.
    pub connector_id: String,
    /// Original successful operation.
    pub source_operation: String,
    /// Recorded execution zone, preserved by the compensation.
    pub zone: String,
    /// Continuity hash recorded by local history for the original input.
    pub source_input_hash: String,
    /// Continuity hash recorded by local history for the full original response.
    pub source_response_hash: String,
    /// Exact reviewed inverse operation.
    pub inverse_operation: String,
    /// BLAKE3 digest of the inverse input; no resource payload is persisted.
    pub inverse_input_digest: String,
    /// Normalized host endpoint selected for this attempt.
    pub host: String,
    /// Host invocation identity retained for inspection after interruption.
    pub request_id: String,
    /// Stable compensation key linking the inverse history entry to its source.
    pub idempotency_key: String,
}

/// A terminal reply does not authorize another compensation attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UndoExecutionStatus {
    /// The host returned a successful terminal response.
    Completed,
    /// The host returned an error; partial effects remain possible.
    ReportedError,
}

/// Immutable, payload-free summary of an observed terminal host reply.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UndoCompletion {
    /// Invocation identity, required to match the original fence.
    pub request_id: String,
    /// Terminal response classification.
    pub status: UndoExecutionStatus,
    /// BLAKE3 digest of the full host response.
    pub response_digest: String,
    /// Whether the inverse operation was appended to ordinary CLI history.
    pub history_recorded: bool,
}

/// Inspectable evidence for a compensation already admitted locally.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UndoExecutionEvidence {
    /// Original pre-effect admission record.
    pub identity: UndoExecutionIdentity,
    /// Absent after interruption or an unconfirmed result.
    pub completion: Option<UndoCompletion>,
}

/// A permanent, exclusively-created effect fence for one source history entry.
///
/// The pending marker is never replaced or deleted. A second caller therefore
/// cannot race admission, and a restart, changed host, or missing completion
/// receipt cannot cause implicit replay. A terminal reply is recorded in a
/// separate immutable file. The local state is evidence, not host authority.
pub struct UndoExecutionFence {
    path: PathBuf,
    identity: UndoExecutionIdentity,
}

impl UndoExecutionFence {
    /// Inspect a prior attempt before any live discovery or preflight.
    ///
    /// # Errors
    /// A malformed, partial, or non-regular marker fails closed.
    pub fn inspect(
        directory: &Path,
        source_entry_id: &str,
    ) -> Result<Option<UndoExecutionEvidence>> {
        let path = Self::path(directory, source_entry_id);
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => anyhow::bail!("could not inspect the existing compensation fence"),
            Ok(metadata) => ensure!(
                metadata.is_file(),
                "compensation fence is not a regular file"
            ),
        }
        let identity: UndoExecutionIdentity =
            serde_json::from_value(read_bounded_json(&path, MAX_EXECUTION_RECORD_BYTES)?)
                .context("compensation fence is incomplete or malformed")?;
        ensure!(
            identity.source_entry_id == source_entry_id,
            "compensation fence belongs to a different source"
        );
        let completion_path = path.with_extension("result.json");
        let completion = match fs::symlink_metadata(&completion_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => anyhow::bail!("could not inspect the compensation receipt"),
            Ok(metadata) => {
                ensure!(
                    metadata.is_file(),
                    "compensation receipt is not a regular file"
                );
                let completion: UndoCompletion = serde_json::from_value(read_bounded_json(
                    &completion_path,
                    MAX_EXECUTION_RECORD_BYTES,
                )?)
                .context("compensation receipt is incomplete or malformed")?;
                ensure!(
                    completion.request_id == identity.request_id,
                    "compensation receipt belongs to a different invocation"
                );
                Some(completion)
            }
        };
        Ok(Some(UndoExecutionEvidence {
            identity,
            completion,
        }))
    }

    /// Durably reserve the source immediately before sending an invocation.
    ///
    /// # Errors
    /// Refuses any existing marker, including a partial prior write. A failed
    /// sync must never be followed by invocation.
    pub fn begin(directory: &Path, identity: UndoExecutionIdentity) -> Result<Self> {
        ensure!(
            valid_identity(&identity.source_entry_id, 128),
            "invalid compensation source identity"
        );
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(directory) {
            Ok(()) => sync_parent(directory)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => anyhow::bail!("could not create compensation evidence directory"),
        }
        ensure!(
            fs::symlink_metadata(directory)?.is_dir(),
            "compensation evidence directory must not be a symlink"
        );
        let path = Self::path(directory, &identity.source_entry_id);
        write_new_record(&path, &identity)?;
        Ok(Self { path, identity })
    }

    /// Persist the observed terminal reply without storing provider payloads.
    ///
    /// # Errors
    /// Refuses duplicate receipt writes or any persistence failure. The pending
    /// fence is retained regardless, so failed recording cannot enable replay.
    pub fn complete(
        &self,
        status: UndoExecutionStatus,
        response: &serde_json::Value,
        history_recorded: bool,
    ) -> Result<()> {
        let completion = UndoCompletion {
            request_id: self.identity.request_id.clone(),
            status,
            response_digest: blake3::hash(&serde_json::to_vec(response)?)
                .to_hex()
                .to_string(),
            history_recorded,
        };
        write_new_record(&self.path.with_extension("result.json"), &completion)
    }

    fn path(directory: &Path, source_entry_id: &str) -> PathBuf {
        directory.join(format!(
            "{}.json",
            blake3::hash(source_entry_id.as_bytes()).to_hex()
        ))
    }
}

fn read_bounded_json(path: &Path, maximum: u64) -> Result<serde_json::Value> {
    ensure!(
        fs::symlink_metadata(path)?.is_file(),
        "expected a regular JSON file"
    );
    let file = File::open(path)?;
    ensure!(file.metadata()?.is_file(), "expected a regular JSON file");
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= maximum,
        "JSON file exceeds its size limit"
    );
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_new_record(path: &Path, record: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(record)?;
    ensure!(
        bytes.len() as u64 <= MAX_EXECUTION_RECORD_BYTES,
        "compensation evidence exceeds its size limit"
    );
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .context("compensation evidence already exists or cannot be created")?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .context("could not persist compensation evidence")?;
    sync_parent(path)
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<()> {
    File::open(path.parent().unwrap_or_else(|| Path::new(".")))?
        .sync_all()
        .context("could not sync compensation evidence directory")
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<()> {
    Ok(())
}

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors that can occur while planning an undo.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum UndoError {
    /// The operation has no known inverse.
    NoInverse,
    /// A required field was missing from the original output.
    MissingOutputField(String),
    /// The operation id was not recognized.
    OperationNotFound,
    /// A path expression in the input mapping could not be evaluated.
    InputMappingFailed(String),
    /// The source does not record a definite successful invocation.
    SourceNotSuccessful,
    /// The recorded connector, zone, or history identity is unusable.
    InvalidSourceScope,
    /// The supplied input does not match the local history record.
    InputMismatch,
    /// The supplied response does not match the local history record.
    ResponseMismatch,
    /// The source response is not a complete successful invocation envelope.
    InvalidSourceResponse,
    /// A created resource identifier is missing or cannot be safely reused.
    InvalidResourceIdentity,
    /// A Discord delivery was suppressed or disagrees with its source channel.
    DeliveryMismatch,
}

impl fmt::Display for UndoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoInverse => write!(f, "operation has no known inverse"),
            Self::MissingOutputField(field) => {
                write!(f, "missing required output field: {field}")
            }
            Self::OperationNotFound => write!(f, "operation not found"),
            Self::InputMappingFailed(msg) => {
                write!(f, "input mapping failed: {msg}")
            }
            Self::SourceNotSuccessful => {
                write!(f, "undo requires a successful source history entry")
            }
            Self::InvalidSourceScope => {
                write!(f, "undo requires the recorded connector family and zone")
            }
            Self::InputMismatch => {
                write!(f, "original input does not match the local history hash")
            }
            Self::ResponseMismatch => {
                write!(f, "original response does not match the local history hash")
            }
            Self::InvalidSourceResponse => {
                write!(f, "undo requires a complete successful invocation response")
            }
            Self::InvalidResourceIdentity => {
                write!(
                    f,
                    "original response has no usable created resource identity"
                )
            }
            Self::DeliveryMismatch => {
                write!(
                    f,
                    "Discord delivery does not prove a message in the original channel"
                )
            }
        }
    }
}

impl std::error::Error for UndoError {}

impl UndoError {
    /// Stable, payload-free refusal code for CLI diagnostics.
    #[must_use]
    pub const fn error_type(&self) -> &'static str {
        match self {
            Self::NoInverse | Self::OperationNotFound => "undo-not-supported",
            Self::MissingOutputField(_)
            | Self::InputMappingFailed(_)
            | Self::InvalidResourceIdentity => "undo-resource-identity-required",
            Self::SourceNotSuccessful => "undo-source-not-successful",
            Self::InvalidSourceScope => "undo-source-scope-invalid",
            Self::InputMismatch => "undo-input-mismatch",
            Self::ResponseMismatch => "undo-response-mismatch",
            Self::InvalidSourceResponse => "undo-source-response-invalid",
            Self::DeliveryMismatch => "undo-delivery-mismatch",
        }
    }
}

// ── Core types ──────────────────────────────────────────────────────────────

/// Describes how to map fields from the original input/output into the inverse
/// operation's input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InverseMapping {
    /// Fully-qualified name of the inverse operation (e.g. `"notion.delete_page"`).
    pub inverse_operation: String,
    /// Maps target field names to JSON-path source expressions.
    ///
    /// Paths use a minimal `$.input.<field>` / `$.output.<field>` syntax.
    pub input_mapping: BTreeMap<String, String>,
}

/// A concrete plan to undo a specific operation invocation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndoPlan {
    /// Identifier of the original audit-log entry.
    pub original_entry_id: String,
    /// The operation that was originally performed.
    pub original_operation: String,
    /// The inverse operation that should be called.
    pub inverse_operation: String,
    /// Fully-constructed input for the inverse operation.
    pub inverse_input: serde_json::Value,
    /// Planning risk estimate; live metadata remains authoritative at execution.
    pub risk_level: String,
    /// Whether a human/agent must confirm before execution.
    pub requires_confirmation: bool,
    /// Any caveats or warnings about performing the undo.
    pub warnings: Vec<String>,
}

/// Result of checking whether an operation is reversible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReversibilityCheck {
    /// The operation that was checked.
    pub operation_id: String,
    /// Whether the operation is reversible.
    pub reversible: bool,
    /// The inverse operation, if one exists.
    pub inverse_operation: Option<String>,
    /// Human-readable guidance (especially useful when not reversible).
    pub guidance: String,
}

// ── Registry ────────────────────────────────────────────────────────────────

/// Registry of inverse-operation mappings.
///
/// Ships with reviewed connector pairs and allows custom offline mappings.
/// Custom registration does not extend the executable history-plan allowlist.
#[derive(Clone, Debug)]
pub struct UndoRegistry {
    mappings: BTreeMap<String, InverseMapping>,
    guidance: BTreeMap<String, String>,
}

impl Default for UndoRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl UndoRegistry {
    /// Create a new registry pre-loaded with the built-in inverse table.
    #[must_use]
    pub fn new() -> Self {
        let mut reg = Self {
            mappings: BTreeMap::new(),
            guidance: BTreeMap::new(),
        };
        reg.load_builtins();
        reg
    }

    /// Register a custom inverse mapping, returning `&mut Self` for chaining.
    pub fn register(&mut self, operation: &str, mapping: InverseMapping) -> &mut Self {
        self.mappings.insert(operation.to_owned(), mapping);
        self
    }

    /// Look up the inverse mapping for an operation.
    #[must_use]
    pub fn lookup(&self, operation_id: &str) -> Option<&InverseMapping> {
        self.mappings.get(operation_id)
    }

    /// Return the number of registered mappings (built-in + custom).
    #[must_use]
    pub fn len(&self) -> usize {
        self.mappings.len()
    }

    /// Return `true` if there are no registered mappings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }

    // ── Built-in table ──────────────────────────────────────────────────

    fn load_builtins(&mut self) {
        // Helper to insert a simple mapping with common id-based patterns.
        let mut add = |op: &str, inv: &str, fields: &[(&str, &str)]| {
            let input_mapping = fields
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect();
            self.mappings.insert(
                op.to_owned(),
                InverseMapping {
                    inverse_operation: inv.to_owned(),
                    input_mapping,
                },
            );
        };

        // These pairs are implemented by both manifest and connector runtime,
        // and the inverse runtimes declare strict idempotency.
        // Every resource key comes from the original successful result rather
        // than a caller-chosen deletion target.
        add(
            "discord.send_message",
            "discord.delete_message",
            &[
                ("channel_id", "$.output.channel_id"),
                ("message_id", "$.output.id"),
            ],
        );
        add(
            "todoist.tasks.create",
            "todoist.tasks.delete",
            &[("task_id", "$.output.id")],
        );
        add(
            "notion.create_page",
            "notion.delete_page",
            &[("page_id", "$.output.page.id")],
        );
        // Non-reversible operations — guidance only.
        self.guidance.insert(
            "trello.cards.create".to_owned(),
            "Automatic compensation is unavailable: the current trello.cards.delete runtime does not declare strict idempotency. Inspect current card state and retained host evidence before a separate authorized deletion.".to_owned(),
        );
        self.guidance.insert(
            "terraform.apply".to_owned(),
            "Destroying a workspace is not an undo of apply; inspect the prior state and plan a targeted repair.".to_owned(),
        );
        self.guidance.insert(
            "s3.upload_object".to_owned(),
            "Deleting an object cannot restore overwritten contents; inspect version history before a repair.".to_owned(),
        );
        self.guidance.insert(
            "gmail.send_email".to_owned(),
            "Emails cannot be unsent. Consider sending a follow-up correction.".to_owned(),
        );
        self.guidance.insert(
            "openai.create_completion".to_owned(),
            "Completions are stateless and cannot be undone.".to_owned(),
        );
        self.guidance.insert(
            "stripe.charge".to_owned(),
            "Charges can be refunded via stripe.create_refund, not reversed.".to_owned(),
        );
        self.guidance.insert(
            "twilio.send_sms".to_owned(),
            "SMS messages cannot be recalled once delivered.".to_owned(),
        );
    }

    /// Get non-reversible guidance for an operation.
    #[must_use]
    pub fn guidance(&self, operation_id: &str) -> Option<&str> {
        self.guidance.get(operation_id).map(String::as_str)
    }
}

// ── Path evaluation ─────────────────────────────────────────────────────────

/// Evaluate a path expression against the original input and output values.
///
/// Supported syntax:
/// - `$.input.field` — access `field` on the original input
/// - `$.output.field.nested` — access `field.nested` on the original output
/// - `$.input.array[N]` — access array element at index N
///
/// # Errors
///
/// Returns an error string if the path is malformed or the target field does
/// not exist.
pub fn evaluate_path(
    path: &str,
    input: &serde_json::Value,
    output: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let path = path.trim();

    if !path.starts_with("$.") {
        return Err(format!("path must start with '$.' — got: {path}"));
    }

    let rest = &path[2..];

    let (root_name, remainder) = rest
        .find('.')
        .map_or((rest, ""), |idx| (&rest[..idx], &rest[idx + 1..]));

    let root = match root_name {
        "input" => input,
        "output" => output,
        other => {
            return Err(format!(
                "unknown root '{other}' — expected 'input' or 'output'"
            ));
        }
    };

    if remainder.is_empty() {
        return Ok(root.clone());
    }

    resolve_segments(root, remainder)
}

/// Walk dot-separated segments, handling `field[N]` array indexing.
fn resolve_segments(
    mut current: &serde_json::Value,
    path: &str,
) -> Result<serde_json::Value, String> {
    for segment in path.split('.') {
        // Check for array index syntax: field[N]
        if let Some(bracket_pos) = segment.find('[') {
            let field = &segment[..bracket_pos];
            let idx_str = segment[bracket_pos + 1..]
                .strip_suffix(']')
                .ok_or_else(|| format!("malformed array index in segment: {segment}"))?;
            let idx: usize = idx_str
                .parse()
                .map_err(|_| format!("non-numeric array index: {idx_str}"))?;

            // Navigate to the field first (if non-empty).
            if !field.is_empty() {
                current = current
                    .get(field)
                    .ok_or_else(|| format!("field '{field}' not found"))?;
            }
            current = current
                .get(idx)
                .ok_or_else(|| format!("array index {idx} out of bounds"))?;
        } else {
            current = current
                .get(segment)
                .ok_or_else(|| format!("field '{segment}' not found"))?;
        }
    }
    Ok(current.clone())
}

// ── Plan construction ───────────────────────────────────────────────────────

/// Build a compensation from a recorded successful invocation and caller-held
/// source data. Neither source data nor credentials are persisted here.
///
/// `full_response` is the complete original `InvokeResponse` (the CLI's
/// `response` member), because history hashes that envelope rather than its
/// nested connector result. Matching hashes is a local continuity check, not
/// cryptographic authentication of the history or provider result. The caller
/// must still verify the exact live connector, operation, and recorded zone,
/// and use current capability, approval, and preflight checks before dispatch.
///
/// # Errors
/// Refuses unsuccessful history, changed source data, missing or contradictory
/// response evidence, mismatched scope, and unusable created resource IDs.
pub fn plan_history_undo(
    entry: &crate::history::HistoryEntry,
    original_input: &serde_json::Value,
    full_response: &serde_json::Value,
) -> Result<UndoPlan, UndoError> {
    let family = match entry.operation_id.as_str() {
        "discord.send_message" => "discord",
        "notion.create_page" => "notion",
        "todoist.tasks.create" => "todoist",
        _ => return Err(UndoError::NoInverse),
    };
    if entry.status != crate::history::OpStatus::Success || entry.error_code.is_some() {
        return Err(UndoError::SourceNotSuccessful);
    }
    let connector_family = entry
        .connector_id
        .strip_prefix("fcp.")
        .unwrap_or(&entry.connector_id)
        .split(':')
        .next();
    if !valid_identity(&entry.entry_id, 128)
        || !valid_scope_label(&entry.connector_id)
        || connector_family != Some(family)
        || !entry
            .zone
            .as_deref()
            .is_some_and(|zone| valid_scope_label(zone) && zone.starts_with("z:") && zone.len() > 2)
    {
        return Err(UndoError::InvalidSourceScope);
    }
    if crate::history::content_hash(original_input) != entry.input_hash {
        return Err(UndoError::InputMismatch);
    }
    let response_hash = crate::history::content_hash(full_response);
    if entry.output_hash.as_deref() != Some(response_hash.as_str()) {
        return Err(UndoError::ResponseMismatch);
    }
    if !original_input.is_object()
        || full_response
            .get("type")
            .and_then(serde_json::Value::as_str)
            != Some("response")
        || !full_response
            .get("id")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|id| valid_identity(id, 128))
        || full_response
            .get("status")
            .and_then(serde_json::Value::as_str)
            != Some("ok")
        || full_response
            .get("error")
            .is_some_and(|error| !error.is_null())
        || full_response
            .get("decision_receipt_id")
            .is_some_and(|receipt| !receipt.is_null())
    {
        return Err(UndoError::InvalidSourceResponse);
    }
    let result = full_response
        .get("result")
        .filter(|result| result.is_object())
        .ok_or(UndoError::InvalidSourceResponse)?;
    let mut plan = plan_undo(
        &UndoRegistry::new(),
        &entry.operation_id,
        original_input,
        result,
    )
    .map_err(|_| UndoError::InvalidResourceIdentity)?;
    if !plan.inverse_input.as_object().is_some_and(|fields| {
        fields
            .values()
            .all(|value| value.as_str().is_some_and(valid_resource_identity))
    }) {
        return Err(UndoError::InvalidResourceIdentity);
    }
    if family == "discord" {
        validate_discord_delivery(original_input, result)?;
    }
    plan.original_entry_id.clone_from(&entry.entry_id);
    plan.warnings.push(
        "Source input and response match local history hashes; this is not authenticated provider provenance. Live authorization and preflight remain required."
            .to_owned(),
    );
    plan.warnings.push(if family == "notion" {
        "This archives the created page, including any later edits. It does not restore prior state or retract notifications and access already observed by others."
            .to_owned()
    } else {
        "This deletes the created resource, including any later edits. It does not restore prior state or retract notifications and access already observed by others."
            .to_owned()
    });
    Ok(plan)
}

fn valid_identity(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
}

// These identifiers become URL path segments in connector clients. None of
// the reviewed providers needs delimiters, escapes, Unicode, or whitespace.
fn valid_resource_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_scope_label(value: &str) -> bool {
    value.len() <= 128
        && value
            .bytes()
            .next()
            .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'.' | b'_' | b':' | b'-')
        })
}

fn validate_discord_delivery(
    input: &serde_json::Value,
    result: &serde_json::Value,
) -> Result<(), UndoError> {
    let channel = result.get("channel_id").and_then(serde_json::Value::as_str);
    let message = result.get("id").and_then(serde_json::Value::as_str);
    if channel != input.get("channel_id").and_then(serde_json::Value::as_str)
        || !channel.is_some_and(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
        || !message.is_some_and(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(UndoError::DeliveryMismatch);
    }
    // Older successful responses have no delivery metadata. When present, the
    // metadata must agree with the provider-visible resource being removed.
    if let Some(delivery) = result.get("delivery")
        && (!delivery.is_object()
            || delivery.get("status").and_then(serde_json::Value::as_str) != Some("delivered")
            || delivery
                .get("visible")
                .is_some_and(|visible| visible != true)
            || delivery
                .get("visibility")
                .is_some_and(|visibility| visibility != "visible")
            || delivery
                .get("message_id")
                .is_some_and(|id| id.as_str() != message)
            || delivery
                .get("channel_id")
                .is_some_and(|id| id.as_str() != channel))
    {
        return Err(UndoError::DeliveryMismatch);
    }
    Ok(())
}

/// Construct an undo plan from the registry, original operation, and its
/// input/output. This general mapping helper does not establish history
/// continuity or execution authority; use `plan_history_undo` for live undo.
///
/// # Errors
///
/// Returns `UndoError` if the operation has no inverse, or if any required
/// field is missing from the original input/output.
pub fn plan_undo(
    registry: &UndoRegistry,
    operation_id: &str,
    original_input: &serde_json::Value,
    original_output: &serde_json::Value,
) -> Result<UndoPlan, UndoError> {
    let mapping = registry.lookup(operation_id).ok_or(UndoError::NoInverse)?;

    let mut inverse_input = serde_json::Map::new();
    let mut warnings: Vec<String> = Vec::new();

    for (target_field, source_path) in &mapping.input_mapping {
        match evaluate_path(source_path, original_input, original_output) {
            Ok(value) => {
                if value.is_null() {
                    warnings.push(format!(
                        "field '{target_field}' resolved to null from path '{source_path}'"
                    ));
                }
                inverse_input.insert(target_field.clone(), value);
            }
            Err(e) => {
                // Distinguish between output-sourced and input-sourced failures.
                if source_path.starts_with("$.output") {
                    return Err(UndoError::MissingOutputField(format!(
                        "{target_field}: {e}"
                    )));
                }
                return Err(UndoError::InputMappingFailed(format!(
                    "{target_field}: {e}"
                )));
            }
        }
    }

    // Determine risk level based on the inverse operation name.
    let risk_level = classify_risk(&mapping.inverse_operation);

    Ok(UndoPlan {
        original_entry_id: String::new(), // Filled by caller.
        original_operation: operation_id.to_owned(),
        inverse_operation: mapping.inverse_operation.clone(),
        inverse_input: serde_json::Value::Object(inverse_input),
        risk_level,
        requires_confirmation: true,
        warnings,
    })
}

/// Classify risk for an inverse operation based on its name.
fn classify_risk(operation: &str) -> String {
    let op_lower = operation.to_lowercase();
    if op_lower.contains("delete") || op_lower.contains("destroy") {
        "high".to_owned()
    } else if op_lower.contains("close")
        || op_lower.contains("archive")
        || op_lower.contains("cancel")
        || op_lower.contains("disable")
        || op_lower.contains("stop")
        || op_lower.contains("remove")
    {
        "medium".to_owned()
    } else {
        "low".to_owned()
    }
}

// ── Reversibility check ─────────────────────────────────────────────────────

/// Check whether an operation is reversible without actually planning an undo.
#[must_use]
pub fn check_reversibility(registry: &UndoRegistry, operation_id: &str) -> ReversibilityCheck {
    registry.lookup(operation_id).map_or_else(
        || {
            let guidance = registry.guidance(operation_id).map_or_else(
                || "No known inverse. Manual intervention may be required.".to_owned(),
                ToOwned::to_owned,
            );
            ReversibilityCheck {
                operation_id: operation_id.to_owned(),
                reversible: false,
                inverse_operation: None,
                guidance,
            }
        },
        |mapping| ReversibilityCheck {
            operation_id: operation_id.to_owned(),
            reversible: true,
            inverse_operation: Some(mapping.inverse_operation.clone()),
            guidance: format!(
                "A compensating operation is available via '{}'. Confirm its current scope and risk; it cannot restore all prior effects or retract notifications.",
                mapping.inverse_operation
            ),
        },
    )
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn execution_identity() -> UndoExecutionIdentity {
        UndoExecutionIdentity {
            source_entry_id: "history-source".to_owned(),
            connector_id: "fcp.discord:messaging:v1".to_owned(),
            source_operation: "discord.send_message".to_owned(),
            zone: "z:work".to_owned(),
            source_input_hash: "input-hash".to_owned(),
            source_response_hash: "response-hash".to_owned(),
            inverse_operation: "discord.delete_message".to_owned(),
            inverse_input_digest: "inverse-digest".to_owned(),
            host: "http://127.0.0.1:8787".to_owned(),
            request_id: "undo-request".to_owned(),
            idempotency_key: "undo:history-source".to_owned(),
        }
    }

    #[test]
    fn execution_fence_survives_interruption_completion_and_host_changes() {
        for complete in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let directory = root.path().join("undo");
            let identity = execution_identity();
            assert!(
                UndoExecutionFence::inspect(&directory, &identity.source_entry_id)
                    .unwrap()
                    .is_none()
            );
            let fence = UndoExecutionFence::begin(&directory, identity.clone()).unwrap();
            if complete {
                fence
                    .complete(
                        UndoExecutionStatus::Completed,
                        &json!({"private_result": "never-persist"}),
                        true,
                    )
                    .unwrap();
            }
            drop(fence);

            let evidence = UndoExecutionFence::inspect(&directory, &identity.source_entry_id)
                .unwrap()
                .unwrap();
            assert_eq!(evidence.identity, identity);
            assert_eq!(evidence.completion.is_some(), complete);
            assert!(
                !serde_json::to_string(&evidence)
                    .unwrap()
                    .contains("never-persist")
            );
            let mut changed = identity;
            changed.host = "https://different-host.example".to_owned();
            changed.request_id = "different-request".to_owned();
            assert!(UndoExecutionFence::begin(&directory, changed).is_err());
        }
    }

    #[test]
    fn execution_fence_exclusively_admits_one_concurrent_attempt() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("undo");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let attempts = (0..2)
            .map(|_| {
                let directory = directory.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    UndoExecutionFence::begin(&directory, execution_identity()).is_ok()
                })
            })
            .collect::<Vec<_>>();
        let admitted = attempts
            .into_iter()
            .map(|attempt| usize::from(attempt.join().unwrap()))
            .sum::<usize>();
        assert_eq!(admitted, 1);
        assert!(
            UndoExecutionFence::inspect(&directory, "history-source")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn execution_fence_refuses_partial_records_and_failed_receipt_rewrites() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("undo");
        fs::create_dir(&directory).unwrap();
        let identity = execution_identity();
        let path = UndoExecutionFence::path(&directory, &identity.source_entry_id);
        fs::write(&path, b"{partial").unwrap();
        assert!(UndoExecutionFence::inspect(&directory, &identity.source_entry_id).is_err());
        assert!(UndoExecutionFence::begin(&directory, identity.clone()).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"{partial");

        let separate = root.path().join("separate");
        let fence = UndoExecutionFence::begin(&separate, identity.clone()).unwrap();
        let receipt = fence.path.with_extension("result.json");
        fs::create_dir(&receipt).unwrap();
        assert!(
            fence
                .complete(UndoExecutionStatus::Completed, &json!({"ok": true}), true)
                .is_err()
        );
        assert!(UndoExecutionFence::begin(&separate, identity).is_err());
        assert!(UndoExecutionFence::inspect(&separate, "history-source").is_err());
    }

    #[test]
    fn execution_fence_receipt_is_immutable_and_bound_to_invocation() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("undo");
        let identity = execution_identity();
        let fence = UndoExecutionFence::begin(&directory, identity.clone()).unwrap();
        fence
            .complete(
                UndoExecutionStatus::ReportedError,
                &json!({"error": true}),
                false,
            )
            .unwrap();
        assert!(
            fence
                .complete(UndoExecutionStatus::Completed, &json!({"ok": true}), true)
                .is_err()
        );
        let evidence = UndoExecutionFence::inspect(&directory, &identity.source_entry_id)
            .unwrap()
            .unwrap();
        let completion = evidence.completion.unwrap();
        assert_eq!(completion.request_id, identity.request_id);
        assert_eq!(completion.status, UndoExecutionStatus::ReportedError);
        assert!(!completion.history_recorded);
    }

    #[test]
    fn source_json_read_is_bounded_and_diagnostics_do_not_echo_private_data() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("private-source.json");
        fs::write(&source, b"{\"data\":\"private-marker\"}").unwrap();
        assert_eq!(
            read_source_json(&source).unwrap(),
            json!({"data": "private-marker"})
        );
        fs::write(&source, b"private-marker not JSON").unwrap();
        let error = read_source_json(&source).unwrap_err().to_string();
        assert!(!error.contains("private-marker"));
        assert!(!error.contains("private-source"));
        let file = OpenOptions::new().write(true).open(&source).unwrap();
        file.set_len(MAX_SOURCE_BYTES + 1).unwrap();
        assert!(read_source_json(&source).is_err());
        assert!(read_source_json(root.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn execution_fence_and_source_read_refuse_symlinks() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let target = root.path().join("target");
        fs::create_dir(&target).unwrap();
        let directory = root.path().join("undo");
        symlink(&target, &directory).unwrap();
        assert!(UndoExecutionFence::begin(&directory, execution_identity()).is_err());
        let source = root.path().join("input.json");
        fs::write(&source, b"{}").unwrap();
        let source_link = root.path().join("input-link.json");
        symlink(&source, &source_link).unwrap();
        assert!(read_source_json(&source_link).is_err());
    }

    // ── UndoRegistry: built-in lookups ──────────────────────────────────

    #[test]
    fn registry_refuses_nonexistent_github_close_issue() {
        let reg = UndoRegistry::new();
        assert!(reg.lookup("github.create_issue").is_none());
    }

    #[test]
    fn registry_refuses_nonexistent_github_close_pull_request() {
        let reg = UndoRegistry::new();
        assert!(reg.lookup("github.create_pull_request").is_none());
    }

    #[test]
    fn registry_refuses_unverified_github_create_repo_pair() {
        let reg = UndoRegistry::new();
        assert!(reg.lookup("github.create_repo").is_none());
    }

    #[test]
    fn registry_refuses_label_removal_without_prior_state() {
        let reg = UndoRegistry::new();
        assert!(reg.lookup("github.add_label").is_none());
    }

    #[test]
    fn registry_refuses_nonexistent_slack_delete_message() {
        let reg = UndoRegistry::new();
        assert!(reg.lookup("slack.send_message").is_none());
        assert!(reg.lookup("slack.post_message").is_none());
    }

    #[test]
    fn registry_has_builtin_discord_send_message() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("discord.send_message").unwrap();
        assert_eq!(m.inverse_operation, "discord.delete_message");
    }

    #[test]
    fn registry_has_builtin_todoist_tasks_create() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("todoist.tasks.create").unwrap();
        assert_eq!(m.inverse_operation, "todoist.tasks.delete");
        assert!(reg.lookup("todoist.create_task").is_none());
    }

    #[test]
    fn registry_refuses_nonexistent_linear_close_issue() {
        let reg = UndoRegistry::new();
        assert!(reg.lookup("linear.create_issue").is_none());
    }

    #[test]
    fn registry_has_builtin_notion_create_page() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("notion.create_page").unwrap();
        assert_eq!(m.inverse_operation, "notion.delete_page");
    }

    #[test]
    fn registry_refuses_unverified_jira_close_issue() {
        let reg = UndoRegistry::new();
        assert!(reg.lookup("jira.create_issue").is_none());
    }

    #[test]
    fn registry_refuses_non_strict_trello_delete() {
        let reg = UndoRegistry::new();
        assert!(reg.lookup("trello.cards.create").is_none());
        assert!(reg.lookup("trello.create_card").is_none());
    }

    #[test]
    fn registry_refuses_unverified_asana_create_task() {
        let reg = UndoRegistry::new();
        assert!(reg.lookup("asana.create_task").is_none());
        assert!(reg.lookup("asana.tasks.create").is_none());
    }

    #[test]
    fn registry_refuses_name_reuse_as_pod_identity() {
        let reg = UndoRegistry::new();
        assert!(reg.lookup("kubernetes.create_pod").is_none());
    }

    #[test]
    fn registry_refuses_workspace_destruction_as_compensation() {
        let reg = UndoRegistry::new();
        assert!(reg.lookup("terraform.apply").is_none());
    }

    #[test]
    fn registry_refuses_object_delete_as_overwrite_restoration() {
        let reg = UndoRegistry::new();
        assert!(reg.lookup("s3.upload_object").is_none());
    }

    #[test]
    fn registry_refuses_unverified_stripe_create_subscription() {
        let reg = UndoRegistry::new();
        assert!(reg.lookup("stripe.create_subscription").is_none());
    }

    #[test]
    fn registry_refuses_unfollow_without_prior_follow_state() {
        let reg = UndoRegistry::new();
        assert!(reg.lookup("spotify.follow_playlist").is_none());
    }

    #[test]
    fn registry_does_not_guess_generic_pairs() {
        let reg = UndoRegistry::new();
        for operation in [
            "generic.create",
            "generic.enable",
            "generic.add",
            "generic.start",
            "generic.subscribe",
        ] {
            assert!(reg.lookup(operation).is_none(), "{operation}");
        }
    }

    #[test]
    fn registry_contains_only_reviewed_builtins() {
        let reg = UndoRegistry::new();
        assert_eq!(reg.len(), 3);
    }

    #[test]
    fn registry_unknown_operation_returns_none() {
        let reg = UndoRegistry::new();
        assert!(reg.lookup("nonexistent.op").is_none());
    }

    #[test]
    fn registry_custom_registration() {
        let mut reg = UndoRegistry::new();
        let before = reg.len();
        reg.register(
            "custom.lock",
            InverseMapping {
                inverse_operation: "custom.unlock".to_owned(),
                input_mapping: BTreeMap::from([(
                    "resource_id".to_owned(),
                    "$.output.id".to_owned(),
                )]),
            },
        );
        assert_eq!(reg.len(), before + 1);
        let m = reg.lookup("custom.lock").unwrap();
        assert_eq!(m.inverse_operation, "custom.unlock");
    }

    #[test]
    fn registry_custom_overwrites_builtin() {
        let mut reg = UndoRegistry::new();
        let before = reg.len();
        reg.register(
            "notion.create_page",
            InverseMapping {
                inverse_operation: "custom.archive_page".to_owned(),
                input_mapping: BTreeMap::new(),
            },
        );
        assert_eq!(reg.len(), before);
        assert_eq!(
            reg.lookup("notion.create_page").unwrap().inverse_operation,
            "custom.archive_page"
        );
    }

    #[test]
    fn registry_is_empty_false_after_new() {
        let reg = UndoRegistry::new();
        assert!(!reg.is_empty());
    }

    #[test]
    fn registry_default_equals_new() {
        let a = UndoRegistry::new();
        let b = UndoRegistry::default();
        assert_eq!(a.len(), b.len());
    }

    // ── Path evaluation ─────────────────────────────────────────────────

    #[test]
    fn path_eval_input_field() {
        let input = json!({"owner": "acme", "repo": "widgets"});
        let output = json!({});
        let val = evaluate_path("$.input.owner", &input, &output).unwrap();
        assert_eq!(val, json!("acme"));
    }

    #[test]
    fn path_eval_output_nested() {
        let input = json!({});
        let output = json!({"issue": {"number": 42}});
        let val = evaluate_path("$.output.issue.number", &input, &output).unwrap();
        assert_eq!(val, json!(42));
    }

    #[test]
    fn path_eval_deeply_nested() {
        let input = json!({});
        let output = json!({"a": {"b": {"c": {"d": "deep"}}}});
        let val = evaluate_path("$.output.a.b.c.d", &input, &output).unwrap();
        assert_eq!(val, json!("deep"));
    }

    #[test]
    fn path_eval_array_index() {
        let input = json!({"tags": ["alpha", "beta", "gamma"]});
        let output = json!({});
        let val = evaluate_path("$.input.tags[1]", &input, &output).unwrap();
        assert_eq!(val, json!("beta"));
    }

    #[test]
    fn path_eval_array_index_zero() {
        let input = json!({"items": [10, 20, 30]});
        let output = json!({});
        let val = evaluate_path("$.input.items[0]", &input, &output).unwrap();
        assert_eq!(val, json!(10));
    }

    #[test]
    fn path_eval_missing_field_error() {
        let input = json!({"owner": "acme"});
        let output = json!({});
        let err = evaluate_path("$.input.repo", &input, &output).unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
    }

    #[test]
    fn path_eval_bad_root_error() {
        let input = json!({});
        let output = json!({});
        let err = evaluate_path("$.context.field", &input, &output).unwrap_err();
        assert!(err.contains("unknown root"), "got: {err}");
    }

    #[test]
    fn path_eval_missing_prefix_error() {
        let input = json!({});
        let output = json!({});
        let err = evaluate_path("input.field", &input, &output).unwrap_err();
        assert!(err.contains("must start with"), "got: {err}");
    }

    #[test]
    fn path_eval_array_out_of_bounds() {
        let input = json!({"items": [1]});
        let output = json!({});
        let err = evaluate_path("$.input.items[5]", &input, &output).unwrap_err();
        assert!(err.contains("out of bounds"), "got: {err}");
    }

    #[test]
    fn path_eval_root_only_returns_whole_object() {
        let input = json!({"x": 1});
        let output = json!({});
        let val = evaluate_path("$.input", &input, &output).unwrap();
        assert_eq!(val, json!({"x": 1}));
    }

    #[test]
    fn path_eval_null_value() {
        let input = json!({"field": null});
        let output = json!({});
        let val = evaluate_path("$.input.field", &input, &output).unwrap();
        assert!(val.is_null());
    }

    #[test]
    fn path_eval_boolean_value() {
        let input = json!({});
        let output = json!({"active": true});
        let val = evaluate_path("$.output.active", &input, &output).unwrap();
        assert_eq!(val, json!(true));
    }

    #[test]
    fn path_eval_whitespace_trimmed() {
        let input = json!({"x": 99});
        let output = json!({});
        let val = evaluate_path("  $.input.x  ", &input, &output).unwrap();
        assert_eq!(val, json!(99));
    }

    #[test]
    fn path_eval_malformed_array_bracket() {
        let input = json!({"arr": [1, 2]});
        let output = json!({});
        let err = evaluate_path("$.input.arr[0", &input, &output).unwrap_err();
        assert!(err.contains("malformed"), "got: {err}");
    }

    #[test]
    fn path_eval_non_numeric_array_index() {
        let input = json!({"arr": [1, 2]});
        let output = json!({});
        let err = evaluate_path("$.input.arr[abc]", &input, &output).unwrap_err();
        assert!(err.contains("non-numeric"), "got: {err}");
    }

    // ── Plan construction ───────────────────────────────────────────────

    #[test]
    fn plan_simple_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({"content": "Review proposal"});
        let output = json!({"id": "task-7"});
        let plan = plan_undo(&reg, "todoist.tasks.create", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "todoist.tasks.delete");
        assert_eq!(plan.inverse_input, json!({"task_id": "task-7"}));
    }

    #[test]
    fn plan_refuses_unimplemented_slack_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({"channel": "C123"});
        let output = json!({"ts": "1234567890.123456"});
        let error = plan_undo(&reg, "slack.post_message", &input, &output).unwrap_err();
        assert_eq!(error, UndoError::NoInverse);
    }

    #[test]
    fn plan_missing_output_field_error() {
        let reg = UndoRegistry::new();
        let input = json!({});
        let output = json!({"page": {}}); // Missing page.id
        let err = plan_undo(&reg, "notion.create_page", &input, &output).unwrap_err();
        assert_eq!(
            std::mem::discriminant(&err),
            std::mem::discriminant(&UndoError::MissingOutputField(String::new()))
        );
    }

    #[test]
    fn plan_missing_input_field_error() {
        let mut reg = UndoRegistry::new();
        reg.register(
            "custom.open",
            InverseMapping {
                inverse_operation: "custom.close".to_owned(),
                input_mapping: BTreeMap::from([("scope".to_owned(), "$.input.scope".to_owned())]),
            },
        );
        let input = json!({}); // Missing scope in a custom offline mapping.
        let output = json!({"id": "created-1"});
        let err = plan_undo(&reg, "custom.open", &input, &output).unwrap_err();
        assert_eq!(
            std::mem::discriminant(&err),
            std::mem::discriminant(&UndoError::InputMappingFailed(String::new()))
        );
    }

    #[test]
    fn plan_no_inverse_error() {
        let reg = UndoRegistry::new();
        let err = plan_undo(&reg, "unknown.op", &json!({}), &json!({})).unwrap_err();
        assert_eq!(err, UndoError::NoInverse);
    }

    #[test]
    fn plan_risk_level_high_for_delete() {
        let reg = UndoRegistry::new();
        let input = json!({});
        let output = json!({"id": "task-1"});
        let plan = plan_undo(&reg, "todoist.tasks.create", &input, &output).unwrap();
        assert_eq!(plan.risk_level, "high");
        assert!(plan.requires_confirmation);
    }

    #[test]
    fn plan_risk_level_medium_for_close() {
        let mut reg = UndoRegistry::new();
        reg.register(
            "custom.open",
            InverseMapping {
                inverse_operation: "custom.close".to_owned(),
                input_mapping: BTreeMap::new(),
            },
        );
        let plan = plan_undo(&reg, "custom.open", &json!({}), &json!({})).unwrap();
        assert_eq!(plan.risk_level, "medium");
        assert!(plan.requires_confirmation);
    }

    #[test]
    fn plan_risk_level_low_for_generic() {
        let mut reg = UndoRegistry::new();
        reg.register(
            "custom.foo",
            InverseMapping {
                inverse_operation: "custom.bar".to_owned(),
                input_mapping: BTreeMap::new(),
            },
        );
        let plan = plan_undo(&reg, "custom.foo", &json!({}), &json!({})).unwrap();
        assert_eq!(plan.risk_level, "low");
        assert!(plan.requires_confirmation);
    }

    #[test]
    fn plan_null_value_generates_warning() {
        let mut reg = UndoRegistry::new();
        reg.register(
            "test.op",
            InverseMapping {
                inverse_operation: "test.inv".to_owned(),
                input_mapping: BTreeMap::from([("f".to_owned(), "$.input.f".to_owned())]),
            },
        );
        let plan = plan_undo(&reg, "test.op", &json!({"f": null}), &json!({})).unwrap();
        assert!(!plan.warnings.is_empty());
        assert!(plan.warnings[0].contains("null"));
    }

    #[test]
    fn plan_empty_mapping_produces_empty_input() {
        let mut reg = UndoRegistry::new();
        reg.register(
            "test.noop",
            InverseMapping {
                inverse_operation: "test.noop_inv".to_owned(),
                input_mapping: BTreeMap::new(),
            },
        );
        let plan = plan_undo(&reg, "test.noop", &json!({}), &json!({})).unwrap();
        assert_eq!(plan.inverse_input, json!({}));
    }

    #[test]
    fn plan_complex_mapping() {
        let mut reg = UndoRegistry::new();
        reg.register(
            "ci.deploy",
            InverseMapping {
                inverse_operation: "ci.rollback".to_owned(),
                input_mapping: BTreeMap::from([
                    ("environment".to_owned(), "$.input.environment".to_owned()),
                    (
                        "previous_version".to_owned(),
                        "$.output.deployment.previous_version".to_owned(),
                    ),
                    ("service".to_owned(), "$.input.service".to_owned()),
                ]),
            },
        );
        let input = json!({
            "environment": "production",
            "service": "api-gateway",
            "version": "v2.1.0"
        });
        let output = json!({
            "deployment": {
                "id": "dep-123",
                "previous_version": "v2.0.0",
                "status": "complete"
            }
        });
        let plan = plan_undo(&reg, "ci.deploy", &input, &output).unwrap();
        assert_eq!(plan.inverse_input["environment"], json!("production"));
        assert_eq!(plan.inverse_input["previous_version"], json!("v2.0.0"));
        assert_eq!(plan.inverse_input["service"], json!("api-gateway"));
    }

    // ── Reversibility check ─────────────────────────────────────────────

    #[test]
    fn reversibility_check_reversible() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "notion.create_page");
        assert!(check.reversible);
        assert_eq!(
            check.inverse_operation,
            Some("notion.delete_page".to_owned())
        );
        assert!(check.guidance.contains("delete_page"));
    }

    #[test]
    fn reversibility_check_non_reversible_with_guidance() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "gmail.send_email");
        assert!(!check.reversible);
        assert!(check.inverse_operation.is_none());
        assert!(check.guidance.contains("cannot be unsent"));
    }

    #[test]
    fn reversibility_check_openai_completion() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "openai.create_completion");
        assert!(!check.reversible);
        assert!(check.guidance.contains("stateless"));
    }

    #[test]
    fn reversibility_check_unknown_operation() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "mystery.op");
        assert!(!check.reversible);
        assert!(check.inverse_operation.is_none());
        assert!(check.guidance.contains("Manual intervention"));
    }

    // ── Serialization round-trips ───────────────────────────────────────

    #[test]
    fn undo_plan_serde_roundtrip() {
        let plan = UndoPlan {
            original_entry_id: "entry-42".to_owned(),
            original_operation: "github.create_issue".to_owned(),
            inverse_operation: "github.close_issue".to_owned(),
            inverse_input: json!({"owner": "acme", "issue_number": 7}),
            risk_level: "medium".to_owned(),
            requires_confirmation: false,
            warnings: vec!["field was null".to_owned()],
        };
        let json_str = serde_json::to_string(&plan).unwrap();
        let restored: UndoPlan = serde_json::from_str(&json_str).unwrap();
        assert_eq!(plan, restored);
    }

    #[test]
    fn inverse_mapping_serde_roundtrip() {
        let mapping = InverseMapping {
            inverse_operation: "github.close_issue".to_owned(),
            input_mapping: BTreeMap::from([
                ("owner".to_owned(), "$.input.owner".to_owned()),
                (
                    "issue_number".to_owned(),
                    "$.output.issue.number".to_owned(),
                ),
            ]),
        };
        let json_str = serde_json::to_string(&mapping).unwrap();
        let restored: InverseMapping = serde_json::from_str(&json_str).unwrap();
        assert_eq!(mapping, restored);
    }

    #[test]
    fn undo_error_serde_roundtrip() {
        let errors = vec![
            UndoError::NoInverse,
            UndoError::MissingOutputField("ts".to_owned()),
            UndoError::OperationNotFound,
            UndoError::InputMappingFailed("bad path".to_owned()),
            UndoError::SourceNotSuccessful,
            UndoError::InvalidSourceScope,
            UndoError::InputMismatch,
            UndoError::ResponseMismatch,
            UndoError::InvalidSourceResponse,
            UndoError::InvalidResourceIdentity,
            UndoError::DeliveryMismatch,
        ];
        for err in &errors {
            let json_str = serde_json::to_string(err).unwrap();
            let restored: UndoError = serde_json::from_str(&json_str).unwrap();
            assert_eq!(*err, restored);
        }
    }

    #[test]
    fn reversibility_check_serde_roundtrip() {
        let check = ReversibilityCheck {
            operation_id: "slack.send_message".to_owned(),
            reversible: true,
            inverse_operation: Some("slack.delete_message".to_owned()),
            guidance: "Can be reversed.".to_owned(),
        };
        let json_str = serde_json::to_string(&check).unwrap();
        let restored: ReversibilityCheck = serde_json::from_str(&json_str).unwrap();
        assert_eq!(check, restored);
    }

    // ── UndoError Display ───────────────────────────────────────────────

    #[test]
    fn undo_error_display_no_inverse() {
        let err = UndoError::NoInverse;
        assert_eq!(err.to_string(), "operation has no known inverse");
    }

    #[test]
    fn undo_error_display_missing_output_field() {
        let err = UndoError::MissingOutputField("ts".to_owned());
        assert!(err.to_string().contains("ts"));
    }

    #[test]
    fn undo_error_display_operation_not_found() {
        let err = UndoError::OperationNotFound;
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn undo_error_display_input_mapping_failed() {
        let err = UndoError::InputMappingFailed("bad path".to_owned());
        assert!(err.to_string().contains("bad path"));
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[test]
    fn plan_with_array_path_in_output() {
        let mut reg = UndoRegistry::new();
        reg.register(
            "test.batch",
            InverseMapping {
                inverse_operation: "test.unbatch".to_owned(),
                input_mapping: BTreeMap::from([(
                    "first_id".to_owned(),
                    "$.output.created[0]".to_owned(),
                )]),
            },
        );
        let output = json!({"created": ["id-a", "id-b"]});
        let plan = plan_undo(&reg, "test.batch", &json!({}), &output).unwrap();
        assert_eq!(plan.inverse_input["first_id"], json!("id-a"));
    }

    #[test]
    fn plan_preserves_original_operation() {
        let reg = UndoRegistry::new();
        let input = json!({"content": "Test task"});
        let output = json!({"id": "task-123"});
        let plan = plan_undo(&reg, "todoist.tasks.create", &input, &output).unwrap();
        assert_eq!(plan.original_operation, "todoist.tasks.create");
    }

    #[test]
    fn classify_risk_destroy_is_high() {
        assert_eq!(classify_risk("terraform.destroy"), "high");
    }

    #[test]
    fn classify_risk_archive_is_medium() {
        assert_eq!(classify_risk("notion.archive_page"), "medium");
    }

    #[test]
    fn classify_risk_unfollow_is_low() {
        assert_eq!(classify_risk("spotify.unfollow_playlist"), "low");
    }

    #[test]
    fn guidance_gmail() {
        let reg = UndoRegistry::new();
        let g = reg.guidance("gmail.send_email").unwrap();
        assert!(g.contains("cannot be unsent"));
    }

    #[test]
    fn guidance_openai() {
        let reg = UndoRegistry::new();
        let g = reg.guidance("openai.create_completion").unwrap();
        assert!(g.contains("stateless"));
    }

    #[test]
    fn guidance_unknown_is_none() {
        let reg = UndoRegistry::new();
        assert!(reg.guidance("unknown.op").is_none());
    }

    #[test]
    fn guidance_twilio() {
        let reg = UndoRegistry::new();
        let g = reg.guidance("twilio.send_sms").unwrap();
        assert!(g.contains("recalled"));
    }

    #[test]
    fn guidance_stripe_charge() {
        let reg = UndoRegistry::new();
        let g = reg.guidance("stripe.charge").unwrap();
        assert!(g.contains("refund"));
    }

    // ── Clone impls ──────────────────────────────────────────────────────

    #[test]
    fn undo_error_clone() {
        let err = UndoError::MissingOutputField("ts".to_owned());
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn undo_error_clone_no_inverse() {
        let err = UndoError::NoInverse;
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn undo_error_clone_operation_not_found() {
        let err = UndoError::OperationNotFound;
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn undo_error_clone_input_mapping_failed() {
        let err = UndoError::InputMappingFailed("path broken".to_owned());
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    #[test]
    fn inverse_mapping_clone() {
        let mapping = InverseMapping {
            inverse_operation: "github.close_issue".to_owned(),
            input_mapping: BTreeMap::from([("owner".to_owned(), "$.input.owner".to_owned())]),
        };
        let cloned = mapping.clone();
        assert_eq!(mapping, cloned);
    }

    #[test]
    fn undo_plan_clone() {
        let plan = UndoPlan {
            original_entry_id: "e1".to_owned(),
            original_operation: "op.a".to_owned(),
            inverse_operation: "op.b".to_owned(),
            inverse_input: json!({"x": 1}),
            risk_level: "low".to_owned(),
            requires_confirmation: false,
            warnings: vec!["w1".to_owned()],
        };
        let cloned = plan.clone();
        assert_eq!(plan, cloned);
    }

    #[test]
    fn reversibility_check_clone() {
        let check = ReversibilityCheck {
            operation_id: "test.op".to_owned(),
            reversible: true,
            inverse_operation: Some("test.inv".to_owned()),
            guidance: "ok".to_owned(),
        };
        let cloned = check.clone();
        assert_eq!(check, cloned);
    }

    #[test]
    fn undo_registry_clone() {
        let reg = UndoRegistry::new();
        let cloned = reg.clone();
        assert_eq!(reg.len(), cloned.len());
        // Verify a lookup works on clone
        assert!(cloned.lookup("notion.create_page").is_some());
    }

    // ── Debug impls ──────────────────────────────────────────────────────

    #[test]
    fn undo_error_debug() {
        let err = UndoError::NoInverse;
        let dbg = format!("{err:?}");
        assert!(dbg.contains("NoInverse"));
    }

    #[test]
    fn inverse_mapping_debug() {
        let mapping = InverseMapping {
            inverse_operation: "test.inv".to_owned(),
            input_mapping: BTreeMap::new(),
        };
        let dbg = format!("{mapping:?}");
        assert!(dbg.contains("test.inv"));
    }

    #[test]
    fn undo_plan_debug() {
        let plan = UndoPlan {
            original_entry_id: "e1".to_owned(),
            original_operation: "op.a".to_owned(),
            inverse_operation: "op.b".to_owned(),
            inverse_input: json!({}),
            risk_level: "low".to_owned(),
            requires_confirmation: false,
            warnings: vec![],
        };
        let dbg = format!("{plan:?}");
        assert!(dbg.contains("op.a"));
    }

    #[test]
    fn reversibility_check_debug() {
        let check = ReversibilityCheck {
            operation_id: "x".to_owned(),
            reversible: false,
            inverse_operation: None,
            guidance: "none".to_owned(),
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("reversible"));
    }

    #[test]
    fn undo_registry_debug() {
        let reg = UndoRegistry::new();
        let dbg = format!("{reg:?}");
        assert!(dbg.contains("UndoRegistry"));
    }

    // ── UndoError as std::error::Error ───────────────────────────────────

    #[test]
    fn undo_error_is_error_trait() {
        let err: Box<dyn std::error::Error> = Box::new(UndoError::NoInverse);
        assert!(err.to_string().contains("no known inverse"));
    }

    #[test]
    fn undo_error_source_is_none() {
        use std::error::Error;
        let err = UndoError::NoInverse;
        assert!(err.source().is_none());
    }

    // ── More path evaluation edge cases ──────────────────────────────────

    #[test]
    fn path_eval_output_root_returns_whole_output() {
        let input = json!({});
        let output = json!({"result": "ok"});
        let val = evaluate_path("$.output", &input, &output).unwrap();
        assert_eq!(val, json!({"result": "ok"}));
    }

    #[test]
    fn path_eval_numeric_value() {
        let input = json!({"count": 42});
        let output = json!({});
        let val = evaluate_path("$.input.count", &input, &output).unwrap();
        assert_eq!(val, json!(42));
    }

    #[test]
    fn path_eval_float_value() {
        let input = json!({"price": 9.99});
        let output = json!({});
        let val = evaluate_path("$.input.price", &input, &output).unwrap();
        assert_eq!(val, json!(9.99));
    }

    #[test]
    fn path_eval_nested_object_returned_as_object() {
        let input = json!({});
        let output = json!({"meta": {"key": "val", "num": 1}});
        let val = evaluate_path("$.output.meta", &input, &output).unwrap();
        assert!(val.is_object());
        assert_eq!(val["key"], json!("val"));
    }

    #[test]
    fn path_eval_array_returned_as_array() {
        let input = json!({"tags": ["a", "b"]});
        let output = json!({});
        let val = evaluate_path("$.input.tags", &input, &output).unwrap();
        assert!(val.is_array());
        assert_eq!(val.as_array().unwrap().len(), 2);
    }

    #[test]
    fn path_eval_nested_array_index() {
        let input = json!({});
        let output = json!({"data": {"items": [100, 200, 300]}});
        let val = evaluate_path("$.output.data.items[2]", &input, &output).unwrap();
        assert_eq!(val, json!(300));
    }

    #[test]
    fn path_eval_empty_string_value() {
        let input = json!({"name": ""});
        let output = json!({});
        let val = evaluate_path("$.input.name", &input, &output).unwrap();
        assert_eq!(val, json!(""));
    }

    #[test]
    fn path_eval_empty_array_at_field() {
        let input = json!({"items": []});
        let output = json!({});
        let val = evaluate_path("$.input.items", &input, &output).unwrap();
        assert_eq!(val, json!([]));
    }

    #[test]
    fn path_eval_empty_array_index_out_of_bounds() {
        let input = json!({"items": []});
        let output = json!({});
        let err = evaluate_path("$.input.items[0]", &input, &output).unwrap_err();
        assert!(err.contains("out of bounds"), "got: {err}");
    }

    #[test]
    fn path_eval_bare_array_index_on_root_array() {
        // When root itself might need indexing — but evaluate_path requires $.input/output first
        let input = json!({"arr": [[1, 2], [3, 4]]});
        let output = json!({});
        let val = evaluate_path("$.input.arr[1]", &input, &output).unwrap();
        assert_eq!(val, json!([3, 4]));
    }

    #[test]
    fn path_eval_nested_object_in_array() {
        let input = json!({});
        let output = json!({"results": [{"id": "a"}, {"id": "b"}]});
        let val = evaluate_path("$.output.results[1]", &input, &output).unwrap();
        assert_eq!(val, json!({"id": "b"}));
    }

    #[test]
    fn path_eval_dollar_only_is_error() {
        let err = evaluate_path("$", &json!({}), &json!({})).unwrap_err();
        assert!(err.contains("must start with"), "got: {err}");
    }

    #[test]
    fn path_eval_dollar_dot_only_unknown_root() {
        // "$." means rest="" → root_name="" which is unknown
        let err = evaluate_path("$.", &json!({}), &json!({})).unwrap_err();
        assert!(err.contains("unknown root"), "got: {err}");
    }

    #[test]
    fn path_eval_triple_nested_field() {
        let input = json!({});
        let output = json!({"level1": {"level2": {"level3": {"level4": 999}}}});
        let val = evaluate_path("$.output.level1.level2.level3.level4", &input, &output).unwrap();
        assert_eq!(val, json!(999));
    }

    #[test]
    fn path_eval_field_not_found_on_non_object() {
        let input = json!({"x": 42});
        let output = json!({});
        let err = evaluate_path("$.input.x.y", &input, &output).unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
    }

    // ── More plan_undo scenarios ─────────────────────────────────────────

    #[test]
    fn plan_discord_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({"channel_id": "123"});
        let output = json!({"id": "456", "channel_id": "123"});
        let plan = plan_undo(&reg, "discord.send_message", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "discord.delete_message");
        assert_eq!(plan.inverse_input["channel_id"], json!("123"));
        assert_eq!(plan.inverse_input["message_id"], json!("456"));
        assert_eq!(plan.risk_level, "high");
    }

    #[test]
    fn plan_todoist_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({});
        let output = json!({"id": "task-99"});
        let plan = plan_undo(&reg, "todoist.tasks.create", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "todoist.tasks.delete");
        assert_eq!(plan.inverse_input["task_id"], json!("task-99"));
    }

    #[test]
    fn plan_refuses_unimplemented_linear_close() {
        let reg = UndoRegistry::new();
        let input = json!({});
        let output = json!({"id": "LIN-42"});
        let error = plan_undo(&reg, "linear.create_issue", &input, &output).unwrap_err();
        assert_eq!(error, UndoError::NoInverse);
    }

    #[test]
    fn plan_notion_inverse() {
        let reg = UndoRegistry::new();
        let input = json!({});
        let output = json!({"page": {"id": "page-abc"}});
        let plan = plan_undo(&reg, "notion.create_page", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "notion.delete_page");
        assert_eq!(plan.inverse_input["page_id"], json!("page-abc"));
        assert_eq!(plan.risk_level, "high");
    }

    #[test]
    fn plan_refuses_unverified_jira_close() {
        let reg = UndoRegistry::new();
        let input = json!({"project": "PROJ"});
        let output = json!({"key": "PROJ-123"});
        let error = plan_undo(&reg, "jira.create_issue", &input, &output).unwrap_err();
        assert_eq!(error, UndoError::NoInverse);
    }

    #[test]
    fn plan_refuses_trello_delete_without_strict_runtime_metadata() {
        let reg = UndoRegistry::new();
        let input = json!({});
        let output = json!({"id": "card-7"});
        let error = plan_undo(&reg, "trello.cards.create", &input, &output).unwrap_err();
        assert_eq!(error, UndoError::NoInverse);
    }

    #[test]
    fn plan_refuses_unverified_asana_close() {
        let reg = UndoRegistry::new();
        let input = json!({});
        let output = json!({"gid": "12345"});
        let error = plan_undo(&reg, "asana.create_task", &input, &output).unwrap_err();
        assert_eq!(error, UndoError::NoInverse);
    }

    #[test]
    fn plan_refuses_pod_name_reuse_as_identity() {
        let reg = UndoRegistry::new();
        let input = json!({"namespace": "default", "name": "my-pod"});
        let output = json!({});
        let error = plan_undo(&reg, "kubernetes.create_pod", &input, &output).unwrap_err();
        assert_eq!(error, UndoError::NoInverse);
    }

    #[test]
    fn plan_refuses_workspace_destroy_as_apply_undo() {
        let reg = UndoRegistry::new();
        let input = json!({"workspace": "prod", "config_dir": "/infra"});
        let output = json!({});
        let error = plan_undo(&reg, "terraform.apply", &input, &output).unwrap_err();
        assert_eq!(error, UndoError::NoInverse);
    }

    #[test]
    fn plan_refuses_object_delete_as_overwrite_undo() {
        let reg = UndoRegistry::new();
        let input = json!({"bucket": "my-bucket", "key": "path/to/file.txt"});
        let output = json!({});
        let error = plan_undo(&reg, "s3.upload_object", &input, &output).unwrap_err();
        assert_eq!(error, UndoError::NoInverse);
    }

    #[test]
    fn plan_refuses_unverified_subscription_cancel() {
        let reg = UndoRegistry::new();
        let input = json!({});
        let output = json!({"id": "sub_abc123"});
        let error = plan_undo(&reg, "stripe.create_subscription", &input, &output).unwrap_err();
        assert_eq!(error, UndoError::NoInverse);
    }

    #[test]
    fn plan_refuses_unfollow_without_previous_state() {
        let reg = UndoRegistry::new();
        let input = json!({"playlist_id": "pl-42"});
        let output = json!({});
        let error = plan_undo(&reg, "spotify.follow_playlist", &input, &output).unwrap_err();
        assert_eq!(error, UndoError::NoInverse);
    }

    #[test]
    fn plan_generic_create_inverse() {
        let mut reg = UndoRegistry::new();
        reg.register(
            "generic.create",
            InverseMapping {
                inverse_operation: "generic.delete".to_owned(),
                input_mapping: BTreeMap::from([("id".to_owned(), "$.output.id".to_owned())]),
            },
        );
        let input = json!({});
        let output = json!({"id": "gen-1"});
        let plan = plan_undo(&reg, "generic.create", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "generic.delete");
        assert_eq!(plan.inverse_input["id"], json!("gen-1"));
        assert_eq!(plan.risk_level, "high");
    }

    #[test]
    fn plan_generic_enable_inverse() {
        let mut reg = UndoRegistry::new();
        reg.register(
            "generic.enable",
            InverseMapping {
                inverse_operation: "generic.disable".to_owned(),
                input_mapping: BTreeMap::from([("id".to_owned(), "$.input.id".to_owned())]),
            },
        );
        let input = json!({"id": "feat-1"});
        let output = json!({});
        let plan = plan_undo(&reg, "generic.enable", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "generic.disable");
        assert_eq!(plan.inverse_input["id"], json!("feat-1"));
        assert_eq!(plan.risk_level, "medium");
    }

    #[test]
    fn plan_generic_add_inverse() {
        let mut reg = UndoRegistry::new();
        reg.register(
            "generic.add",
            InverseMapping {
                inverse_operation: "generic.remove".to_owned(),
                input_mapping: BTreeMap::from([("id".to_owned(), "$.input.id".to_owned())]),
            },
        );
        let input = json!({"id": "item-1"});
        let output = json!({});
        let plan = plan_undo(&reg, "generic.add", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "generic.remove");
        assert_eq!(plan.inverse_input["id"], json!("item-1"));
        assert_eq!(plan.risk_level, "medium");
    }

    #[test]
    fn plan_generic_start_inverse() {
        let mut reg = UndoRegistry::new();
        reg.register(
            "generic.start",
            InverseMapping {
                inverse_operation: "generic.stop".to_owned(),
                input_mapping: BTreeMap::from([("id".to_owned(), "$.input.id".to_owned())]),
            },
        );
        let input = json!({"id": "proc-1"});
        let output = json!({});
        let plan = plan_undo(&reg, "generic.start", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "generic.stop");
        assert_eq!(plan.inverse_input["id"], json!("proc-1"));
        assert_eq!(plan.risk_level, "medium");
    }

    #[test]
    fn plan_generic_subscribe_inverse() {
        let mut reg = UndoRegistry::new();
        reg.register(
            "generic.subscribe",
            InverseMapping {
                inverse_operation: "generic.unsubscribe".to_owned(),
                input_mapping: BTreeMap::from([(
                    "subscription_id".to_owned(),
                    "$.output.id".to_owned(),
                )]),
            },
        );
        let input = json!({});
        let output = json!({"id": "sub-1"});
        let plan = plan_undo(&reg, "generic.subscribe", &input, &output).unwrap();
        assert_eq!(plan.inverse_operation, "generic.unsubscribe");
        assert_eq!(plan.inverse_input["subscription_id"], json!("sub-1"));
    }

    #[test]
    fn plan_refuses_removing_existing_github_label() {
        let reg = UndoRegistry::new();
        let input = json!({"owner": "acme", "repo": "w", "issue_number": 5, "label": "bug"});
        let output = json!({});
        let error = plan_undo(&reg, "github.add_label", &input, &output).unwrap_err();
        assert_eq!(error, UndoError::NoInverse);
    }

    #[test]
    fn plan_refuses_nonexistent_github_pr_close() {
        let reg = UndoRegistry::new();
        let input = json!({"owner": "acme", "repo": "widgets"});
        let output = json!({"pull_request": {"number": 101}});
        let error = plan_undo(&reg, "github.create_pull_request", &input, &output).unwrap_err();
        assert_eq!(error, UndoError::NoInverse);
    }

    #[test]
    fn plan_refuses_unverified_github_repo_delete() {
        let reg = UndoRegistry::new();
        let input = json!({});
        let output = json!({"owner": {"login": "acme"}, "name": "new-repo"});
        let error = plan_undo(&reg, "github.create_repo", &input, &output).unwrap_err();
        assert_eq!(error, UndoError::NoInverse);
    }

    // ── Multiple warnings ────────────────────────────────────────────────

    #[test]
    fn plan_multiple_null_fields_generate_multiple_warnings() {
        let mut reg = UndoRegistry::new();
        reg.register(
            "test.multi_null",
            InverseMapping {
                inverse_operation: "test.inv".to_owned(),
                input_mapping: BTreeMap::from([
                    ("a".to_owned(), "$.input.a".to_owned()),
                    ("b".to_owned(), "$.input.b".to_owned()),
                    ("c".to_owned(), "$.input.c".to_owned()),
                ]),
            },
        );
        let plan = plan_undo(
            &reg,
            "test.multi_null",
            &json!({"a": null, "b": null, "c": "ok"}),
            &json!({}),
        )
        .unwrap();
        assert_eq!(plan.warnings.len(), 2);
    }

    #[test]
    fn plan_no_warnings_when_all_fields_present() {
        let reg = UndoRegistry::new();
        let input = json!({});
        let output = json!({"id": "task-123"});
        let plan = plan_undo(&reg, "todoist.tasks.create", &input, &output).unwrap();
        assert!(plan.warnings.is_empty());
    }

    // ── Registry chaining ────────────────────────────────────────────────

    #[test]
    fn registry_register_chaining() {
        let mut reg = UndoRegistry::new();
        let before = reg.len();
        reg.register(
            "chain.a",
            InverseMapping {
                inverse_operation: "chain.a_inv".to_owned(),
                input_mapping: BTreeMap::new(),
            },
        )
        .register(
            "chain.b",
            InverseMapping {
                inverse_operation: "chain.b_inv".to_owned(),
                input_mapping: BTreeMap::new(),
            },
        );
        assert_eq!(reg.len(), before + 2);
        assert!(reg.lookup("chain.a").is_some());
        assert!(reg.lookup("chain.b").is_some());
    }

    // ── classify_risk edge cases ─────────────────────────────────────────

    #[test]
    fn classify_risk_delete_uppercase_is_high() {
        assert_eq!(classify_risk("s3.DELETE_object"), "high");
    }

    #[test]
    fn classify_risk_close_is_medium() {
        assert_eq!(classify_risk("github.close_issue"), "medium");
    }

    #[test]
    fn classify_risk_cancel_is_medium() {
        assert_eq!(classify_risk("stripe.cancel_subscription"), "medium");
    }

    #[test]
    fn classify_risk_disable_is_medium() {
        assert_eq!(classify_risk("generic.disable"), "medium");
    }

    #[test]
    fn classify_risk_stop_is_medium() {
        assert_eq!(classify_risk("generic.stop"), "medium");
    }

    #[test]
    fn classify_risk_remove_is_medium() {
        assert_eq!(classify_risk("github.remove_label"), "medium");
    }

    #[test]
    fn classify_risk_unknown_verb_is_low() {
        assert_eq!(classify_risk("custom.frobnicate"), "low");
    }

    #[test]
    fn classify_risk_empty_string_is_low() {
        assert_eq!(classify_risk(""), "low");
    }

    #[test]
    fn classify_risk_mixed_case_destroy() {
        assert_eq!(classify_risk("infra.DeStRoY_all"), "high");
    }

    // ── Reversibility check for more builtins ────────────────────────────

    #[test]
    fn reversibility_slack_send_message() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "slack.send_message");
        assert!(!check.reversible);
        assert!(check.inverse_operation.is_none());
    }

    #[test]
    fn reversibility_kubernetes_create_pod() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "kubernetes.create_pod");
        assert!(!check.reversible);
        assert!(check.inverse_operation.is_none());
    }

    #[test]
    fn reversibility_stripe_charge_not_reversible() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "stripe.charge");
        assert!(!check.reversible);
        assert!(check.guidance.contains("refund"));
    }

    #[test]
    fn reversibility_twilio_send_sms_not_reversible() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "twilio.send_sms");
        assert!(!check.reversible);
        assert!(check.guidance.contains("recalled"));
    }

    #[test]
    fn reversibility_terraform_apply() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "terraform.apply");
        assert!(!check.reversible);
        assert!(check.inverse_operation.is_none());
        assert!(check.guidance.contains("prior state"));
    }

    #[test]
    fn reversibility_check_operation_id_preserved() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "github.create_issue");
        assert_eq!(check.operation_id, "github.create_issue");
    }

    #[test]
    fn reversibility_check_guidance_format_for_reversible() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "notion.create_page");
        assert!(check.guidance.contains("compensating operation"));
        assert!(check.guidance.contains("cannot restore all prior effects"));
    }

    // ── Serde edge cases ─────────────────────────────────────────────────

    #[test]
    fn undo_plan_serde_with_empty_warnings() {
        let plan = UndoPlan {
            original_entry_id: String::new(),
            original_operation: "op".to_owned(),
            inverse_operation: "inv".to_owned(),
            inverse_input: json!({}),
            risk_level: "low".to_owned(),
            requires_confirmation: false,
            warnings: vec![],
        };
        let json_str = serde_json::to_string(&plan).unwrap();
        let restored: UndoPlan = serde_json::from_str(&json_str).unwrap();
        assert_eq!(plan, restored);
        assert!(restored.warnings.is_empty());
    }

    #[test]
    fn undo_plan_serde_with_complex_inverse_input() {
        let plan = UndoPlan {
            original_entry_id: "e".to_owned(),
            original_operation: "op".to_owned(),
            inverse_operation: "inv".to_owned(),
            inverse_input: json!({"nested": {"deep": [1, 2, 3]}, "flag": true}),
            risk_level: "high".to_owned(),
            requires_confirmation: true,
            warnings: vec!["w1".to_owned(), "w2".to_owned()],
        };
        let json_str = serde_json::to_string(&plan).unwrap();
        let restored: UndoPlan = serde_json::from_str(&json_str).unwrap();
        assert_eq!(plan, restored);
    }

    #[test]
    fn inverse_mapping_serde_empty_input_mapping() {
        let mapping = InverseMapping {
            inverse_operation: "test.inv".to_owned(),
            input_mapping: BTreeMap::new(),
        };
        let json_str = serde_json::to_string(&mapping).unwrap();
        let restored: InverseMapping = serde_json::from_str(&json_str).unwrap();
        assert_eq!(mapping, restored);
    }

    #[test]
    fn reversibility_check_serde_not_reversible() {
        let check = ReversibilityCheck {
            operation_id: "gmail.send_email".to_owned(),
            reversible: false,
            inverse_operation: None,
            guidance: "Cannot be unsent.".to_owned(),
        };
        let json_str = serde_json::to_string(&check).unwrap();
        let restored: ReversibilityCheck = serde_json::from_str(&json_str).unwrap();
        assert_eq!(check, restored);
    }

    // ── Equality / inequality ────────────────────────────────────────────

    #[test]
    fn undo_error_ne_different_variants() {
        assert_ne!(UndoError::NoInverse, UndoError::OperationNotFound);
    }

    #[test]
    fn undo_error_ne_different_fields() {
        assert_ne!(
            UndoError::MissingOutputField("a".to_owned()),
            UndoError::MissingOutputField("b".to_owned()),
        );
    }

    #[test]
    fn undo_plan_ne_different_risk() {
        let plan_a = UndoPlan {
            original_entry_id: String::new(),
            original_operation: "op".to_owned(),
            inverse_operation: "inv".to_owned(),
            inverse_input: json!({}),
            risk_level: "low".to_owned(),
            requires_confirmation: false,
            warnings: vec![],
        };
        let mut plan_b = plan_a.clone();
        plan_b.risk_level = "high".to_owned();
        assert_ne!(plan_a, plan_b);
    }

    // ── Builtin mapping field counts ─────────────────────────────────────

    #[test]
    fn notion_mapping_uses_nested_created_page_id() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("notion.create_page").unwrap();
        assert_eq!(
            m.input_mapping,
            BTreeMap::from([("page_id".to_owned(), "$.output.page.id".to_owned()),])
        );
    }

    #[test]
    fn discord_mapping_uses_response_channel_and_message_ids() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("discord.send_message").unwrap();
        assert_eq!(
            m.input_mapping,
            BTreeMap::from([
                ("channel_id".to_owned(), "$.output.channel_id".to_owned()),
                ("message_id".to_owned(), "$.output.id".to_owned()),
            ])
        );
    }

    #[test]
    fn todoist_mapping_has_one_field() {
        let reg = UndoRegistry::new();
        let m = reg.lookup("todoist.tasks.create").unwrap();
        assert_eq!(
            m.input_mapping,
            BTreeMap::from([("task_id".to_owned(), "$.output.id".to_owned()),])
        );
    }

    #[test]
    fn trello_guidance_explains_runtime_idempotency_gap() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "trello.cards.create");
        assert!(!check.reversible);
        assert!(check.inverse_operation.is_none());
        assert!(
            check
                .guidance
                .contains("does not declare strict idempotency")
        );
        assert!(check.guidance.contains("retained host evidence"));
    }

    #[test]
    fn overwrite_guidance_does_not_offer_a_delete_mapping() {
        let reg = UndoRegistry::new();
        let check = check_reversibility(&reg, "s3.upload_object");
        assert!(!check.reversible);
        assert!(check.inverse_operation.is_none());
        assert!(check.guidance.contains("overwritten contents"));
    }

    // ── plan_undo original_entry_id is empty ─────────────────────────────

    #[test]
    fn plan_original_entry_id_is_empty() {
        let reg = UndoRegistry::new();
        let input = json!({});
        let output = json!({"id": "task-1"});
        let plan = plan_undo(&reg, "todoist.tasks.create", &input, &output).unwrap();
        assert!(plan.original_entry_id.is_empty());
    }

    // History plans are the only plans suitable for the live CLI path. These
    // fixtures model the complete response envelope that history hashes.
    fn recorded_source(
        operation: &str,
        input: serde_json::Value,
        result: serde_json::Value,
    ) -> (
        crate::history::HistoryEntry,
        serde_json::Value,
        serde_json::Value,
    ) {
        let family = operation.split('.').next().unwrap();
        let response = json!({
            "type": "response",
            "id": "request-1",
            "status": "ok",
            "result": result,
            "resource_uris": [],
        });
        let entry = crate::history::HistoryEntry {
            entry_id: "history-entry-1".to_owned(),
            timestamp: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            connector_id: format!("fcp.{family}"),
            operation_id: operation.to_owned(),
            zone: Some("z:work".to_owned()),
            input_hash: crate::history::content_hash(&input),
            input_summary: "source input".to_owned(),
            output_hash: Some(crate::history::content_hash(&response)),
            output_summary: Some("source response".to_owned()),
            status: crate::history::OpStatus::Success,
            latency_ms: 1,
            error_code: None,
            idempotency_key: None,
            agent_session: None,
        };
        (entry, input, response)
    }

    #[test]
    fn history_plans_use_real_contracts_and_require_confirmation() {
        for (operation, input, result, inverse, expected) in [
            (
                "discord.send_message",
                json!({"channel_id": "123", "content": "private-body"}),
                json!({"id": "456", "channel_id": "123", "content": "private-body"}),
                "discord.delete_message",
                json!({"channel_id": "123", "message_id": "456"}),
            ),
            (
                "notion.create_page",
                json!({"private": "private-body"}),
                json!({"page": {"id": "page-123", "private": "private-body"}}),
                "notion.delete_page",
                json!({"page_id": "page-123"}),
            ),
            (
                "todoist.tasks.create",
                json!({"content": "private-body"}),
                json!({"id": "task_123", "content": "private-body"}),
                "todoist.tasks.delete",
                json!({"task_id": "task_123"}),
            ),
        ] {
            let (entry, input, response) = recorded_source(operation, input, result);
            let plan = plan_history_undo(&entry, &input, &response).unwrap();
            assert_eq!(plan.original_entry_id, entry.entry_id);
            assert_eq!(plan.original_operation, operation);
            assert_eq!(plan.inverse_operation, inverse);
            assert_eq!(plan.inverse_input, expected);
            assert!(plan.requires_confirmation);
            assert!(
                plan.warnings
                    .iter()
                    .any(|warning| warning.contains("not authenticated"))
            );
            assert!(
                !serde_json::to_string(&plan)
                    .unwrap()
                    .contains("private-body")
            );
        }
    }

    #[test]
    fn history_plan_requires_successful_definite_source() {
        let (mut entry, input, response) =
            recorded_source("todoist.tasks.create", json!({}), json!({"id": "task-1"}));
        for status in [
            crate::history::OpStatus::Error,
            crate::history::OpStatus::Timeout,
            crate::history::OpStatus::RateLimited,
            crate::history::OpStatus::Denied,
            crate::history::OpStatus::Simulated,
        ] {
            entry.status = status;
            assert_eq!(
                plan_history_undo(&entry, &input, &response),
                Err(UndoError::SourceNotSuccessful)
            );
        }
        entry.status = crate::history::OpStatus::Success;
        entry.error_code = Some("unexpected-error".to_owned());
        assert_eq!(
            plan_history_undo(&entry, &input, &response),
            Err(UndoError::SourceNotSuccessful)
        );
    }

    #[test]
    fn history_plan_checks_both_hashes_and_complete_response() {
        let (mut entry, input, response) = recorded_source(
            "todoist.tasks.create",
            json!({"content": "original"}),
            json!({"id": "task-1"}),
        );
        assert_eq!(
            plan_history_undo(&entry, &json!({"content": "changed"}), &response),
            Err(UndoError::InputMismatch)
        );
        let mut changed = response.clone();
        changed["id"] = json!("different-request");
        assert_eq!(
            plan_history_undo(&entry, &input, &changed),
            Err(UndoError::ResponseMismatch)
        );
        assert_eq!(
            plan_history_undo(&entry, &input, &response["result"]),
            Err(UndoError::ResponseMismatch)
        );
        entry.output_hash = None;
        assert_eq!(
            plan_history_undo(&entry, &input, &response),
            Err(UndoError::ResponseMismatch)
        );
    }

    #[test]
    fn history_plan_rejects_malformed_or_contradictory_envelopes() {
        let (entry, input, valid) =
            recorded_source("todoist.tasks.create", json!({}), json!({"id": "task-1"}));
        for (field, value) in [
            ("type", json!("other")),
            ("id", json!(null)),
            ("id", json!("")),
            ("status", json!("error")),
            ("error", json!({"code": "secret-provider-error"})),
            ("decision_receipt_id", json!("denied-decision")),
            ("result", json!(null)),
            ("result", json!([])),
        ] {
            let mut response = valid.clone();
            response[field] = value;
            let mut recorded = entry.clone();
            recorded.output_hash = Some(crate::history::content_hash(&response));
            assert_eq!(
                plan_history_undo(&recorded, &input, &response),
                Err(UndoError::InvalidSourceResponse),
                "field: {field}"
            );
        }
        for field in ["type", "id", "status", "result"] {
            let mut response = valid.clone();
            response.as_object_mut().unwrap().remove(field);
            let mut recorded = entry.clone();
            recorded.output_hash = Some(crate::history::content_hash(&response));
            assert_eq!(
                plan_history_undo(&recorded, &input, &response),
                Err(UndoError::InvalidSourceResponse),
                "missing: {field}"
            );
        }
        let (entry, input, response) =
            recorded_source("todoist.tasks.create", json!([]), json!({"id": "task-1"}));
        assert_eq!(
            plan_history_undo(&entry, &input, &response),
            Err(UndoError::InvalidSourceResponse)
        );
    }

    #[test]
    fn history_plan_requires_recorded_family_zone_and_bounded_entry_id() {
        let (entry, input, response) =
            recorded_source("todoist.tasks.create", json!({}), json!({"id": "task-1"}));
        for connector in [
            "fcp.notion",
            "todoist-other",
            "FCP.todoist",
            "todoist/other",
            "",
        ] {
            let mut recorded = entry.clone();
            recorded.connector_id = connector.to_owned();
            assert_eq!(
                plan_history_undo(&recorded, &input, &response),
                Err(UndoError::InvalidSourceScope)
            );
        }
        for zone in [None, Some(""), Some("z:"), Some("work"), Some("z:work\n")] {
            let mut recorded = entry.clone();
            recorded.zone = zone.map(str::to_owned);
            assert_eq!(
                plan_history_undo(&recorded, &input, &response),
                Err(UndoError::InvalidSourceScope)
            );
        }
        for id in [String::new(), "entry\ncontrol".to_owned(), "a".repeat(129)] {
            let mut recorded = entry.clone();
            recorded.entry_id = id;
            assert_eq!(
                plan_history_undo(&recorded, &input, &response),
                Err(UndoError::InvalidSourceScope)
            );
        }
        for connector in ["fcp.todoist", "fcp.todoist:utility:1.0.0", "todoist:fcp:v1"] {
            let mut recorded = entry.clone();
            recorded.connector_id = connector.to_owned();
            assert!(plan_history_undo(&recorded, &input, &response).is_ok());
        }
    }

    #[test]
    fn history_plan_rejects_unusable_or_url_active_resource_identifiers() {
        for id in [
            json!(null),
            json!(17),
            json!(false),
            json!(""),
            json!(" "),
            json!("a b"),
            json!("a\n"),
            json!("../other"),
            json!("a/b"),
            json!("a\\b"),
            json!("a?other"),
            json!("a#other"),
            json!("%2fother"),
            json!("%252fother"),
            json!("ページ"),
            json!("a".repeat(513)),
        ] {
            for operation in ["notion.create_page", "todoist.tasks.create"] {
                let result = if operation == "notion.create_page" {
                    json!({"page": {"id": id.clone()}})
                } else {
                    json!({"id": id.clone()})
                };
                let (entry, input, response) = recorded_source(operation, json!({}), result);
                let error = plan_history_undo(&entry, &input, &response).unwrap_err();
                assert_eq!(
                    error,
                    UndoError::InvalidResourceIdentity,
                    "{operation}: {id}"
                );
                assert_eq!(error.error_type(), "undo-resource-identity-required");
            }
        }
    }

    #[test]
    fn history_plan_rejects_missing_nested_identity_without_guessing() {
        for result in [
            json!({}),
            json!({"id": "top-level-id"}),
            json!({"page": {}}),
        ] {
            let (entry, input, response) = recorded_source("notion.create_page", json!({}), result);
            assert_eq!(
                plan_history_undo(&entry, &input, &response),
                Err(UndoError::InvalidResourceIdentity)
            );
        }
    }

    #[test]
    fn history_plan_checks_discord_channel_and_delivery_evidence() {
        for result in [
            json!({"id": "456", "channel_id": "999"}),
            json!({"id": "not-a-snowflake", "channel_id": "123"}),
            json!({"id": "456", "channel_id": "123", "delivery": {"status": "suppressed"}}),
            json!({"id": "456", "channel_id": "123", "delivery": {"status": "delivered", "visible": false}}),
            json!({"id": "456", "channel_id": "123", "delivery": {"status": "delivered", "visibility": "hidden"}}),
            json!({"id": "456", "channel_id": "123", "delivery": {"status": "delivered", "message_id": "789"}}),
            json!({"id": "456", "channel_id": "123", "delivery": {"status": "delivered", "channel_id": "999"}}),
            json!({"id": "456", "channel_id": "123", "delivery": null}),
        ] {
            let (entry, input, response) =
                recorded_source("discord.send_message", json!({"channel_id": "123"}), result);
            assert_eq!(
                plan_history_undo(&entry, &input, &response),
                Err(UndoError::DeliveryMismatch)
            );
        }
        let (entry, input, response) = recorded_source(
            "discord.send_message",
            json!({"channel_id": "123"}),
            json!({
                "id": null, "channel_id": "123", "delivery": {"status": "suppressed"},
            }),
        );
        assert_eq!(
            plan_history_undo(&entry, &input, &response),
            Err(UndoError::InvalidResourceIdentity)
        );
        let (entry, input, response) = recorded_source(
            "discord.send_message",
            json!({"channel_id": "123"}),
            json!({
                "id": "456", "channel_id": "123", "delivery": {
                    "status": "delivered", "visibility": "visible", "visible": true, "message_id": "456",
                },
            }),
        );
        assert!(plan_history_undo(&entry, &input, &response).is_ok());
    }

    #[test]
    fn history_plan_allowlist_is_independent_of_custom_offline_mappings() {
        let mut registry = UndoRegistry::new();
        registry.register(
            "notion.create_page",
            InverseMapping {
                inverse_operation: "custom.destroy_workspace".to_owned(),
                input_mapping: BTreeMap::new(),
            },
        );
        let (entry, input, response) = recorded_source(
            "notion.create_page",
            json!({}),
            json!({"page": {"id": "page-1"}}),
        );
        assert_eq!(
            plan_undo(&registry, &entry.operation_id, &input, &response["result"])
                .unwrap()
                .inverse_operation,
            "custom.destroy_workspace"
        );
        assert_eq!(
            plan_history_undo(&entry, &input, &response)
                .unwrap()
                .inverse_operation,
            "notion.delete_page"
        );
        for operation in [
            "terraform.apply",
            "s3.upload_object",
            "github.create_issue",
            "generic.create",
            "trello.cards.create",
        ] {
            let (entry, input, response) =
                recorded_source(operation, json!({}), json!({"id": "created-1"}));
            assert_eq!(
                plan_history_undo(&entry, &input, &response),
                Err(UndoError::NoInverse)
            );
        }
    }

    #[test]
    fn history_plan_errors_do_not_echo_source_payloads() {
        let (entry, input, response) = recorded_source(
            "todoist.tasks.create",
            json!({"secret": "sensitive-source"}),
            json!({"id": "sensitive-source?target"}),
        );
        let error = plan_history_undo(&entry, &input, &response).unwrap_err();
        assert_eq!(error, UndoError::InvalidResourceIdentity);
        assert!(!error.to_string().contains("sensitive-source"));
        assert!(!error.error_type().contains("sensitive-source"));
    }

    // ── path evaluation with special characters ──────────────────────────

    #[test]
    fn path_eval_value_with_special_chars() {
        let input = json!({"msg": "hello world! @#$%"});
        let output = json!({});
        let val = evaluate_path("$.input.msg", &input, &output).unwrap();
        assert_eq!(val, json!("hello world! @#$%"));
    }

    #[test]
    fn path_eval_unicode_value() {
        let input = json!({"name": "caf\u{00e9}"});
        let output = json!({});
        let val = evaluate_path("$.input.name", &input, &output).unwrap();
        assert_eq!(val, json!("caf\u{00e9}"));
    }

    #[test]
    fn path_eval_large_array_index() {
        let mut arr = Vec::new();
        for i in 0..50 {
            arr.push(json!(i));
        }
        let input = json!({"big": arr});
        let output = json!({});
        let val = evaluate_path("$.input.big[49]", &input, &output).unwrap();
        assert_eq!(val, json!(49));
    }
}
