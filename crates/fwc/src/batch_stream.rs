//! Incremental, bounded decoding of the host's batch NDJSON transport.
//!
//! Each validated member is offered once, immediately, in observed completion
//! order. Only a validated terminal record followed by EOF establishes complete
//! transport accounting. A failed read or output callback preserves known
//! outcomes; it never authorizes resubmitting a member.
//!
//! The transport allows 32 MiB per newline-terminated frame and 64 MiB overall.
//! Retained provider payloads use the host's 1 MiB/member and 16 MiB/batch limits;
//! fixed scheduler errors and submitted IDs are additional bounded accounting.
//! These are encoded-byte limits, not a claim about peak deserializer heap use.
//! A terminal frame duplicates the retained payloads, so its transport limit is
//! deliberately larger than one incremental member frame. The member count is
//! bounded by the exact submitted IDs; the host has no separate count ceiling.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::{self, BufRead, BufReader, Read, Write};

use fcp_host::{
    BatchBoundedResponse, BatchBoundedStreamingResponse, BatchDeliveryStatus, BatchInvokeResponse,
    BatchOperationError, BatchResultLimits, BatchScheduleReport, BatchStatus, OperationResult,
    OperationResultStatus,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

const MAX_FRAME_BYTES: usize = 32 * 1024 * 1024;
const MAX_STREAM_BYTES: usize = 64 * 1024 * 1024;

/// Stable, payload-free classifications suitable for machine-readable output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BatchStreamFailureKind {
    InvalidRequest,
    Transport,
    Truncated,
    Limit,
    InvalidRecord,
    InvalidResult,
    UnknownMember,
    DuplicateMember,
    InvalidTerminal,
    TrailingData,
    Remote,
    Sink,
}

impl BatchStreamFailureKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Transport => "transport_error",
            Self::Truncated => "incomplete_stream",
            Self::Limit => "stream_limit",
            Self::InvalidRecord => "invalid_record",
            Self::InvalidResult => "invalid_result",
            Self::UnknownMember => "unknown_member",
            Self::DuplicateMember => "duplicate_member",
            Self::InvalidTerminal => "invalid_terminal",
            Self::TrailingData => "trailing_data",
            Self::Remote => "remote_stream_failure",
            Self::Sink => "output_error",
        }
    }
}

/// Known outcomes survive transport/output failure without inventing failures
/// for unobserved members. Results are in completion order until a valid
/// terminal is observed, then in the terminal's authoritative submission order.
#[derive(Debug)]
pub(crate) struct BatchStreamFailure {
    pub(crate) kind: BatchStreamFailureKind,
    pub(crate) results: Vec<OperationResult>,
}

impl fmt::Display for BatchStreamFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "batch stream {}; reconcile member request IDs before retrying",
            self.kind.as_str(),
        )
    }
}

impl std::error::Error for BatchStreamFailure {}

// Strict transport mirrors reject misspelled fields and conflicting records.
// The presence-aware output field preserves Some(Value::Null), unlike the
// ordinary Option<Value> deserializer, which conflates null with an absent field.
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum StreamRecord {
    Result { result: ResultRecord },
    Complete { batch: Box<CompleteRecord> },
    Error { error: ErrorRecord },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultRecord {
    id: String,
    status: OperationResultStatus,
    #[serde(default, deserialize_with = "present_output")]
    output: Option<Value>,
    #[serde(default)]
    error: Option<ErrorRecord>,
    duration_ms: u64,
}

fn present_output<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ErrorRecord {
    code: String,
    message: String,
    #[serde(default)]
    retry_after_ms: Option<u64>,
}

impl From<ErrorRecord> for BatchOperationError {
    fn from(record: ErrorRecord) -> Self {
        Self {
            code: record.code,
            message: record.message,
            retry_after_ms: record.retry_after_ms,
        }
    }
}

impl From<ResultRecord> for OperationResult {
    fn from(record: ResultRecord) -> Self {
        Self {
            id: record.id,
            status: record.status,
            output: record.output,
            error: record.error.map(Into::into),
            duration_ms: record.duration_ms,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteRecord {
    bounded: BoundedRecord,
    acknowledged_results: usize,
    delivery_status: BatchDeliveryStatus,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundedRecord {
    response: ResponseRecord,
    limits: BatchResultLimits,
    retained_result_bytes: usize,
    withheld_results: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseRecord {
    status: BatchStatus,
    completed: usize,
    failed: usize,
    skipped: usize,
    results: Vec<ResultRecord>,
    total_duration_ms: u64,
    #[serde(default)]
    schedule_report: Option<BatchScheduleReport>,
}

impl From<CompleteRecord> for BatchBoundedStreamingResponse {
    fn from(record: CompleteRecord) -> Self {
        let bounded = record.bounded;
        let response = bounded.response;
        Self {
            bounded: BatchBoundedResponse {
                response: BatchInvokeResponse {
                    status: response.status,
                    completed: response.completed,
                    failed: response.failed,
                    skipped: response.skipped,
                    results: response.results.into_iter().map(Into::into).collect(),
                    total_duration_ms: response.total_duration_ms,
                    schedule_report: response.schedule_report,
                },
                limits: bounded.limits,
                retained_result_bytes: bounded.retained_result_bytes,
                withheld_results: bounded.withheld_results,
            },
            acknowledged_results: record.acknowledged_results,
            delivery_status: record.delivery_status,
        }
    }
}

/// Consume a host response without buffering the whole stream or retrying IO.
/// The callback should flush its output before returning. A callback error may
/// have written bytes; that result remains known and is never offered again.
///
/// # Errors
/// Returns sanitized protocol, resource, transport, remote, or callback failure
/// with all previously validated results. Raw response/IO/callback errors are
/// deliberately discarded because they may contain credentials or result data.
pub(crate) fn consume<R, F, E>(
    reader: R,
    expected_ids: &[String],
    on_result: F,
) -> Result<BatchBoundedStreamingResponse, BatchStreamFailure>
where
    R: Read,
    F: FnMut(&OperationResult) -> Result<(), E>,
{
    consume_with_limits(
        reader,
        expected_ids,
        on_result,
        MAX_FRAME_BYTES,
        MAX_STREAM_BYTES,
    )
}

fn consume_with_limits<R, F, E>(
    reader: R,
    expected_ids: &[String],
    mut on_result: F,
    frame_limit: usize,
    stream_limit: usize,
) -> Result<BatchBoundedStreamingResponse, BatchStreamFailure>
where
    R: Read,
    F: FnMut(&OperationResult) -> Result<(), E>,
{
    let members: HashMap<_, _> = expected_ids
        .iter()
        .enumerate()
        .map(|(index, id)| (id.as_str(), index))
        .collect();
    let mut results = Vec::new();
    let fail = |kind, results| BatchStreamFailure { kind, results };
    if members.is_empty() || members.len() != expected_ids.len() {
        return Err(fail(BatchStreamFailureKind::InvalidRequest, results));
    }
    let mut seen = vec![false; expected_ids.len()];
    let mut accounting = PayloadAccounting::default();
    let mut reader = BufReader::new(reader);
    let mut frame = Vec::new();
    let mut total = 0;
    loop {
        match read_frame(
            &mut reader,
            &mut frame,
            &mut total,
            frame_limit,
            stream_limit,
        ) {
            Ok(true) => {}
            Ok(false) => return Err(fail(BatchStreamFailureKind::Truncated, results)),
            Err(kind) => return Err(fail(kind, results)),
        }
        let record: StreamRecord = match serde_json::from_slice(&frame) {
            Ok(record) => record,
            Err(_) => return Err(fail(BatchStreamFailureKind::InvalidRecord, results)),
        };
        match record {
            StreamRecord::Result { result } => {
                let result = OperationResult::from(result);
                let Some(&index) = members.get(result.id.as_str()) else {
                    return Err(fail(BatchStreamFailureKind::UnknownMember, results));
                };
                if seen[index] {
                    return Err(fail(BatchStreamFailureKind::DuplicateMember, results));
                }
                if let Err(kind) = accounting.include(&result) {
                    return Err(fail(kind, results));
                }
                seen[index] = true;
                results.push(result);
                // Retain before calling the sink, which may already write bytes
                // before reporting an error. Never repeat this callback.
                if on_result(results.last().expect("record was retained")).is_err() {
                    return Err(fail(BatchStreamFailureKind::Sink, results));
                }
            }
            StreamRecord::Complete { batch } => {
                let terminal = BatchBoundedStreamingResponse::from(*batch);
                if let Err(kind) = validate_terminal(&terminal, expected_ids, &members, &results) {
                    return Err(fail(kind, results));
                }
                // A second terminal, another result, blank line, or arbitrary
                // suffix is not a complete stream. Even EOF reads can fail.
                let trailing = match reader.fill_buf() {
                    Ok([]) => return Ok(terminal),
                    Ok(_) => BatchStreamFailureKind::TrailingData,
                    Err(_) => BatchStreamFailureKind::Transport,
                };
                return Err(fail(trailing, terminal.bounded.response.results));
            }
            StreamRecord::Error { error } => {
                let error = BatchOperationError::from(error);
                let kind = if error.code == "BATCH_STREAM_FAILED"
                    && error.retry_after_ms.is_none()
                    && encoded_size(&error, BatchResultLimits::default().per_result_bytes).is_ok()
                {
                    BatchStreamFailureKind::Remote
                } else {
                    BatchStreamFailureKind::InvalidRecord
                };
                return Err(fail(kind, results));
            }
        }
    }
}

/// Read only bounded chunks. `read_until` or `read_line` would grow an attacker
/// supplied unterminated frame before allowing the caller to inspect its size.
fn read_frame<R: BufRead>(
    reader: &mut R,
    frame: &mut Vec<u8>,
    total: &mut usize,
    frame_limit: usize,
    stream_limit: usize,
) -> Result<bool, BatchStreamFailureKind> {
    frame.clear();
    loop {
        let available = reader
            .fill_buf()
            .map_err(|_| BatchStreamFailureKind::Transport)?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(false)
            } else {
                Err(BatchStreamFailureKind::Truncated)
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index + 1);
        if take > frame_limit.saturating_sub(frame.len())
            || take > stream_limit.saturating_sub(*total)
        {
            return Err(BatchStreamFailureKind::Limit);
        }
        frame.extend_from_slice(&available[..take]);
        reader.consume(take);
        *total += take;
        if newline.is_some() {
            return Ok(true);
        }
    }
}

#[derive(Default)]
struct PayloadAccounting {
    required: usize,
    possible: usize,
    withheld_candidates: usize,
}

impl PayloadAccounting {
    fn include(&mut self, result: &OperationResult) -> Result<(), BatchStreamFailureKind> {
        let limits = BatchResultLimits::default();
        let (required, possible, withheld) = match result.status {
            OperationResultStatus::Success if result.error.is_none() => {
                let output = result
                    .output
                    .as_ref()
                    .ok_or(BatchStreamFailureKind::InvalidResult)?;
                let bytes = encoded_size(output, limits.per_result_bytes)?;
                (bytes, bytes, false)
            }
            OperationResultStatus::Error if result.output.is_none() => {
                let error = result
                    .error
                    .as_ref()
                    .ok_or(BatchStreamFailureKind::InvalidResult)?;
                let bytes = encoded_size(error, limits.per_result_bytes)?;
                let fixed = fixed_error(error, false);
                (if fixed { 0 } else { bytes }, bytes, retention_error(error))
            }
            OperationResultStatus::Skipped
                if result.output.is_none() && result.duration_ms == 0 =>
            {
                let error = result
                    .error
                    .as_ref()
                    .ok_or(BatchStreamFailureKind::InvalidResult)?;
                if !fixed_error(error, true) {
                    return Err(BatchStreamFailureKind::InvalidResult);
                }
                (0, 0, false)
            }
            _ => return Err(BatchStreamFailureKind::InvalidResult),
        };
        self.required = self
            .required
            .checked_add(required)
            .ok_or(BatchStreamFailureKind::Limit)?;
        self.possible = self
            .possible
            .checked_add(possible)
            .ok_or(BatchStreamFailureKind::Limit)?;
        self.withheld_candidates += usize::from(withheld);
        if self.required > limits.total_result_bytes {
            return Err(BatchStreamFailureKind::Limit);
        }
        Ok(())
    }
}

fn retention_error(error: &BatchOperationError) -> bool {
    error.retry_after_ms.is_none()
        && matches!(
            (error.code.as_str(), error.message.as_str()),
            (
                "BATCH_RESULT_LIMIT",
                "operation returned a result that exceeded the retained-result budget; its external effects were not undone; do not retry without reconciliation"
            ) | (
                "BATCH_RESULT_ENCODING_FAILED",
                "operation returned a result that could not be encoded; its external effects were not undone; do not retry without reconciliation"
            )
        )
}

// Only exact, short scheduler-generated records are exempt from provider-byte
// charges. A forged reserved code with a huge message cannot bypass the quota.
fn fixed_error(error: &BatchOperationError, skipped: bool) -> bool {
    if error.retry_after_ms.is_some() {
        return false;
    }
    if !skipped {
        return retention_error(error)
            || matches!(
                (error.code.as_str(), error.message.as_str()),
                (
                    "BATCH_OUTCOME_UNKNOWN",
                    "batch handler panicked after admission; side effects may have occurred; do not retry without reconciliation"
                ) | (
                    "BATCH_OUTCOME_UNKNOWN",
                    "batch interrupted an admitted operation; side effects may have occurred; do not retry without reconciliation"
                )
            );
    }
    matches!(
        (error.code.as_str(), error.message.as_str()),
        ("DEP_FAILED", "dependency did not complete successfully")
            | ("BATCH_TIMEOUT", "batch timeout exceeded before admission")
            | (
                "BATCH_CANCELLED",
                "batch context cancelled before admission"
            )
            | (
                "BATCH_RUNTIME_ERROR",
                "batch runtime failed before admission"
            )
            | (
                "BATCH_PANICKED",
                "batch handler panicked before this operation was admitted"
            )
            | (
                "BATCH_RESULT_DELIVERY_FAILED",
                "batch result sink failed before this operation was admitted"
            )
            | (
                "BATCH_ADMISSION_REFUSED",
                "batch admission policy refused further operations"
            )
            | ("BATCH_ABORTED", "batch stopped before admission")
            | (
                "BATCH_RESULT_LIMIT",
                "batch retained-result budget was exhausted before this operation was admitted"
            )
            | (
                "BATCH_RESULT_ENCODING_FAILED",
                "batch result encoding failed before this operation was admitted"
            )
    )
}

fn validate_terminal(
    terminal: &BatchBoundedStreamingResponse,
    expected_ids: &[String],
    members: &HashMap<&str, usize>,
    observed: &[OperationResult],
) -> Result<(), BatchStreamFailureKind> {
    let invalid = BatchStreamFailureKind::InvalidTerminal;
    let bounded = &terminal.bounded;
    let response = &bounded.response;
    let limits = BatchResultLimits::default();
    if bounded.limits.per_result_bytes != limits.per_result_bytes
        || bounded.limits.total_result_bytes != limits.total_result_bytes
        || bounded.retained_result_bytes > limits.total_result_bytes
        || response.results.len() != expected_ids.len()
        || terminal.acknowledged_results != observed.len()
    {
        return Err(invalid);
    }
    let mut accounting = PayloadAccounting::default();
    let mut completed = 0;
    let mut failed = 0;
    let mut skipped = 0;
    let mut requires_aborted = bounded.withheld_results > 0;
    for (result, expected) in response.results.iter().zip(expected_ids) {
        if result.id != *expected {
            return Err(invalid);
        }
        accounting.include(result).map_err(|_| invalid)?;
        match result.status {
            OperationResultStatus::Success => completed += 1,
            OperationResultStatus::Error => failed += 1,
            OperationResultStatus::Skipped => {
                skipped += 1;
                requires_aborted |= result
                    .error
                    .as_ref()
                    .is_some_and(|error| error.code != "DEP_FAILED");
            }
            _ => return Err(invalid),
        }
    }
    if (response.completed, response.failed, response.skipped) != (completed, failed, skipped)
        || bounded.retained_result_bytes < accounting.required
        || bounded.retained_result_bytes > accounting.possible
        // A handler could return exactly the same error text as a synthesized
        // retention failure. The wire shape cannot distinguish that collision;
        // it contributes a candidate, not proof that a payload was withheld.
        || bounded.withheld_results > accounting.withheld_candidates
    {
        return Err(invalid);
    }
    let valid_status = match response.status {
        BatchStatus::Success => failed == 0 && skipped == 0,
        BatchStatus::PartialSuccess => completed > 0 && (failed > 0 || skipped > 0),
        BatchStatus::AllFailed => completed == 0 && failed > 0,
        BatchStatus::Aborted => true,
        _ => false,
    };
    if !valid_status
        || (requires_aborted && response.status != BatchStatus::Aborted)
        || (terminal.delivery_status == BatchDeliveryStatus::Complete
            && observed.len() != expected_ids.len())
        || (terminal.delivery_status != BatchDeliveryStatus::Complete
            && response.status != BatchStatus::Aborted)
    {
        return Err(invalid);
    }
    for earlier in observed {
        let final_result = &response.results[members[earlier.id.as_str()]];
        if !same_result(earlier, final_result) {
            return Err(invalid);
        }
    }
    if let Some(report) = &response.schedule_report {
        if report.total_operations != expected_ids.len()
            || !exact_members(
                members,
                report.original_tiers.iter().flatten().map(String::as_str),
            )
            || !exact_members(
                members,
                report.scheduled_tiers.iter().flatten().map(String::as_str),
            )
            || !exact_members(
                members,
                report
                    .decisions
                    .iter()
                    .map(|decision| decision.operation_id.as_str()),
            )
        {
            return Err(invalid);
        }
    }
    Ok(())
}

fn exact_members<'a>(members: &HashMap<&str, usize>, ids: impl Iterator<Item = &'a str>) -> bool {
    let mut seen = HashSet::new();
    for id in ids {
        if !members.contains_key(id) || !seen.insert(id) {
            return false;
        }
    }
    seen.len() == members.len()
}

fn same_result(left: &OperationResult, right: &OperationResult) -> bool {
    left.id == right.id
        && left.status == right.status
        && left.output == right.output
        && left.duration_ms == right.duration_ms
        && match (&left.error, &right.error) {
            (None, None) => true,
            (Some(left), Some(right)) => {
                left.code == right.code
                    && left.message == right.message
                    && left.retry_after_ms == right.retry_after_ms
            }
            _ => false,
        }
}

fn encoded_size(value: &impl Serialize, limit: usize) -> Result<usize, BatchStreamFailureKind> {
    struct Counter {
        written: usize,
        limit: usize,
    }
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() > self.limit.saturating_sub(self.written) {
                return Err(io::Error::other("encoded result limit"));
            }
            self.written += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter { written: 0, limit };
    serde_json::to_writer(&mut counter, value).map_err(|_| BatchStreamFailureKind::Limit)?;
    Ok(counter.written)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::future::{pending, ready};
    use std::io::Cursor;
    use std::rc::Rc;
    use std::time::Duration;

    use serde_json::json;

    use super::*;

    fn success(id: &str, output: Value) -> OperationResult {
        OperationResult {
            id: id.to_owned(),
            status: OperationResultStatus::Success,
            output: Some(output),
            error: None,
            duration_ms: 7,
        }
    }

    fn terminal(
        results: Vec<OperationResult>,
        acknowledged: usize,
    ) -> BatchBoundedStreamingResponse {
        let mut accounting = PayloadAccounting::default();
        for result in &results {
            accounting.include(result).unwrap();
        }
        let completed = results
            .iter()
            .filter(|result| result.status == OperationResultStatus::Success)
            .count();
        let failed = results
            .iter()
            .filter(|result| result.status == OperationResultStatus::Error)
            .count();
        let skipped = results.len() - completed - failed;
        let delivery_status = if acknowledged == results.len() {
            BatchDeliveryStatus::Complete
        } else {
            BatchDeliveryStatus::Interrupted
        };
        BatchBoundedStreamingResponse {
            bounded: BatchBoundedResponse {
                response: BatchInvokeResponse {
                    status: if delivery_status == BatchDeliveryStatus::Complete
                        && failed == 0
                        && skipped == 0
                    {
                        BatchStatus::Success
                    } else {
                        BatchStatus::Aborted
                    },
                    completed,
                    failed,
                    skipped,
                    results,
                    total_duration_ms: 9,
                    schedule_report: None,
                },
                limits: BatchResultLimits::default(),
                retained_result_bytes: accounting.required,
                withheld_results: accounting.withheld_candidates,
            },
            acknowledged_results: acknowledged,
            delivery_status,
        }
    }

    fn line(record: &Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(record).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn result_line(result: &OperationResult) -> Vec<u8> {
        line(&json!({"type": "result", "result": result}))
    }

    fn complete_line(terminal: &BatchBoundedStreamingResponse) -> Vec<u8> {
        line(&json!({"type": "complete", "batch": terminal}))
    }

    fn ids(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn read(
        bytes: &[u8],
        expected: &[&str],
    ) -> Result<BatchBoundedStreamingResponse, BatchStreamFailure> {
        consume(bytes, &ids(expected), |_| Ok::<(), ()>(()))
    }

    #[test]
    fn emits_completion_order_before_reading_the_terminal_and_preserves_null() {
        struct GatedReader {
            frames: Vec<Cursor<Vec<u8>>>,
            next: usize,
            callbacks: Rc<Cell<usize>>,
        }
        impl Read for GatedReader {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                loop {
                    let Some(frame) = self.frames.get_mut(self.next) else {
                        return Ok(0);
                    };
                    let count = frame.read(output)?;
                    if count != 0 {
                        return Ok(count);
                    }
                    if self.next < 2 {
                        assert_eq!(
                            self.callbacks.get(),
                            self.next + 1,
                            "callback must precede the next frame read"
                        );
                    }
                    self.next += 1;
                }
            }
        }
        let a = success("a", Value::Null);
        let b = success("b", json!({"value": "first\nsecond"}));
        let complete = terminal(vec![a.clone(), b.clone()], 2);
        let callbacks = Rc::new(Cell::new(0));
        let reader = GatedReader {
            frames: vec![result_line(&b), result_line(&a), complete_line(&complete)]
                .into_iter()
                .map(Cursor::new)
                .collect(),
            next: 0,
            callbacks: Rc::clone(&callbacks),
        };
        let mut observed = Vec::new();
        let response = consume(reader, &ids(&["a", "b"]), |result| {
            observed.push(result.id.clone());
            callbacks.set(callbacks.get() + 1);
            Ok::<(), ()>(())
        })
        .unwrap();
        assert_eq!(observed, ["b", "a"]);
        assert_eq!(
            response.bounded.response.results[0].output,
            Some(Value::Null)
        );
        assert_eq!(response.acknowledged_results, 2);
    }

    #[test]
    fn float_outputs_preserve_values_and_host_encoded_byte_accounting() {
        // These native provider values need serde_json's float_roundtrip
        // parser. Its default float parser can change their encoded length,
        // causing a valid host terminal to fail retained-byte validation.
        for value in [-36.573_994_842_753_436_f64, 52.314_008_204_106_244_f64] {
            let result = success("a", json!({"measurement": value}));
            let expected_bytes = serde_json::to_vec(result.output.as_ref().unwrap())
                .unwrap()
                .len();
            let complete = terminal(vec![result.clone()], 1);
            assert_eq!(complete.bounded.retained_result_bytes, expected_bytes);
            let mut bytes = result_line(&result);
            bytes.extend(complete_line(&complete));
            let mut emitted = Vec::new();
            let parsed = consume(bytes.as_slice(), &ids(&["a"]), |member| {
                emitted.push(member.clone());
                Ok::<(), ()>(())
            })
            .expect("a canonical host float must retain its value and byte count");
            assert_eq!(parsed.bounded.retained_result_bytes, expected_bytes);
            assert_eq!(emitted.len(), 1);
            for observed in [&emitted[0], &parsed.bounded.response.results[0]] {
                assert_eq!(observed.output, result.output);
                assert_eq!(
                    observed.output.as_ref().unwrap()["measurement"]
                        .as_f64()
                        .unwrap()
                        .to_bits(),
                    value.to_bits(),
                );
            }
        }
    }

    #[test]
    fn partial_eof_and_io_errors_preserve_only_validated_members() {
        struct Broken(Cursor<Vec<u8>>);
        impl Read for Broken {
            fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
                match self.0.read(output)? {
                    0 => Err(io::Error::other("secret bearer token and raw response")),
                    count => Ok(count),
                }
            }
        }
        let a = success("a", json!({"value": 1}));
        let bytes = result_line(&a);
        let failure = read(&bytes, &["a", "b"]).unwrap_err();
        assert_eq!(failure.kind, BatchStreamFailureKind::Truncated);
        assert_eq!(failure.results.len(), 1);
        let failure = consume(Broken(Cursor::new(bytes)), &ids(&["a", "b"]), |_| {
            Ok::<(), ()>(())
        })
        .unwrap_err();
        assert_eq!(failure.kind, BatchStreamFailureKind::Transport);
        assert_eq!(failure.results[0].id, "a");
        assert!(!failure.to_string().contains("secret"));
        assert!(std::error::Error::source(&failure).is_none());
    }

    #[test]
    fn sink_failure_keeps_current_result_and_never_calls_it_again() {
        let a = success("a", json!(1));
        let mut bytes = result_line(&a);
        bytes.extend(complete_line(&terminal(vec![a], 1)));
        let calls = Cell::new(0);
        let failure = consume(bytes.as_slice(), &ids(&["a"]), |_| {
            calls.set(calls.get() + 1);
            Err("secret output failure")
        })
        .unwrap_err();
        assert_eq!(failure.kind, BatchStreamFailureKind::Sink);
        assert_eq!(failure.results.len(), 1);
        assert_eq!(calls.get(), 1);
        assert!(!failure.to_string().contains("secret"));
    }

    #[test]
    fn duplicates_unknown_members_and_inconsistent_payloads_are_rejected() {
        let a = success("a", json!(1));
        let prefix = result_line(&a);
        for (suffix, expected) in [
            (result_line(&a), BatchStreamFailureKind::DuplicateMember),
            (
                result_line(&success("other", json!(2))),
                BatchStreamFailureKind::UnknownMember,
            ),
            (
                line(
                    &json!({"type":"result","result":{"id":"b","status":"success","duration_ms":0}}),
                ),
                BatchStreamFailureKind::InvalidResult,
            ),
            (
                line(
                    &json!({"type":"result","result":{"id":"b","status":"error","output":2,"error":{"code":"E","message":"bad"},"duration_ms":0}}),
                ),
                BatchStreamFailureKind::InvalidResult,
            ),
        ] {
            let mut bytes = prefix.clone();
            bytes.extend(suffix);
            let failure = read(&bytes, &["a", "b"]).unwrap_err();
            assert_eq!(failure.kind, expected);
            assert_eq!(failure.results.len(), 1);
        }
    }

    #[test]
    fn terminal_must_match_members_counts_status_limits_and_observed_results() {
        let a = success("a", json!(1));
        let b = success("b", json!(2));
        let valid = terminal(vec![a.clone(), b.clone()], 2);
        for mutation in 0..8 {
            let mut terminal = valid.clone();
            match mutation {
                0 => terminal.bounded.response.results.swap(0, 1),
                1 => terminal.bounded.response.completed = 1,
                2 => terminal.bounded.response.status = BatchStatus::AllFailed,
                3 => terminal.bounded.limits.total_result_bytes += 1,
                4 => terminal.acknowledged_results = 1,
                5 => terminal.bounded.response.results[0].duration_ms += 1,
                6 => terminal.bounded.retained_result_bytes += 1,
                7 => terminal.bounded.withheld_results = 1,
                _ => unreachable!(),
            }
            let mut bytes = result_line(&b);
            bytes.extend(result_line(&a));
            bytes.extend(complete_line(&terminal));
            let failure = read(&bytes, &["a", "b"]).unwrap_err();
            assert_eq!(
                failure.kind,
                BatchStreamFailureKind::InvalidTerminal,
                "mutation {mutation}"
            );
            assert_eq!(failure.results.len(), 2);
        }
    }

    #[test]
    fn terminal_reconciles_undelivered_outcomes_without_reemitting_them() {
        let a = success("a", json!(1));
        let b = OperationResult {
            id: "b".into(), status: OperationResultStatus::Error, output: None,
            error: Some(BatchOperationError {
                code: "BATCH_OUTCOME_UNKNOWN".into(),
                message: "batch interrupted an admitted operation; side effects may have occurred; do not retry without reconciliation".into(),
                retry_after_ms: None,
            }), duration_ms: 8,
        };
        let c = OperationResult {
            id: "c".into(),
            status: OperationResultStatus::Skipped,
            output: None,
            error: Some(BatchOperationError {
                code: "BATCH_TIMEOUT".into(),
                message: "batch timeout exceeded before admission".into(),
                retry_after_ms: None,
            }),
            duration_ms: 0,
        };
        let mut bytes = result_line(&a);
        bytes.extend(complete_line(&terminal(vec![a, b, c], 1)));
        let calls = Cell::new(0);
        let response = consume(bytes.as_slice(), &ids(&["a", "b", "c"]), |_| {
            calls.set(calls.get() + 1);
            Ok::<(), ()>(())
        })
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(response.bounded.response.results.len(), 3);
        assert_eq!(response.delivery_status, BatchDeliveryStatus::Interrupted);
        let mut trailing = bytes;
        trailing.push(b' ');
        let failure = read(&trailing, &["a", "b", "c"]).unwrap_err();
        assert_eq!(failure.kind, BatchStreamFailureKind::TrailingData);
        assert_eq!(
            failure.results.len(),
            3,
            "validated terminal remains useful after a trailing-data failure"
        );
    }

    #[test]
    fn frame_and_stream_caps_apply_before_unbounded_growth() {
        let a = success("a", json!(1));
        let result = result_line(&a);
        let mut bytes = result.clone();
        bytes.extend(complete_line(&terminal(vec![a], 1)));
        let failure = consume_with_limits(
            bytes.as_slice(),
            &ids(&["a"]),
            |_| Ok::<(), ()>(()),
            result.len() - 1,
            4096,
        )
        .unwrap_err();
        assert_eq!(failure.kind, BatchStreamFailureKind::Limit);
        assert!(failure.results.is_empty());
        let failure = consume_with_limits(
            bytes.as_slice(),
            &ids(&["a"]),
            |_| Ok::<(), ()>(()),
            4096,
            result.len(),
        )
        .unwrap_err();
        assert_eq!(failure.kind, BatchStreamFailureKind::Limit);
        assert_eq!(failure.results.len(), 1);
        let failure = consume_with_limits(
            &b"unterminatedxxxxxxxxxxxxxxxx"[..],
            &ids(&["a"]),
            |_| Ok::<(), ()>(()),
            8,
            16,
        )
        .unwrap_err();
        assert_eq!(failure.kind, BatchStreamFailureKind::Limit);
    }

    #[test]
    fn oversized_provider_payload_and_forged_fixed_error_cannot_bypass_limits() {
        let a = success("a", Value::String("x".repeat(1024 * 1024)));
        assert_eq!(
            read(&result_line(&a), &["a"]).unwrap_err().kind,
            BatchStreamFailureKind::Limit
        );
        let forged = OperationResult {
            id: "a".into(),
            status: OperationResultStatus::Error,
            output: None,
            error: Some(BatchOperationError {
                code: "BATCH_OUTCOME_UNKNOWN".into(),
                message: "x".repeat(1024 * 1024),
                retry_after_ms: None,
            }),
            duration_ms: 0,
        };
        assert_eq!(
            read(&result_line(&forged), &["a"]).unwrap_err().kind,
            BatchStreamFailureKind::Limit
        );
    }

    #[test]
    fn schema_errors_duplicate_keys_truncation_and_missing_terminal_fail_closed() {
        for bytes in [
            b"{\"type\":\"unknown\"}\n".as_slice(),
            b"{\"type\":\"result\",\"result\":{},\"extra\":true}\n",
            b"{\"type\":\"result\",\"type\":\"complete\",\"result\":{}}\n",
            b"\n",
        ] {
            assert_eq!(
                read(bytes, &["a"]).unwrap_err().kind,
                BatchStreamFailureKind::InvalidRecord
            );
        }
        let a = success("a", json!(1));
        let mut bytes = result_line(&a);
        let mut terminal = complete_line(&terminal(vec![a], 1));
        terminal.pop();
        bytes.extend(terminal);
        let failure = read(&bytes, &["a"]).unwrap_err();
        assert_eq!(failure.kind, BatchStreamFailureKind::Truncated);
        assert_eq!(failure.results.len(), 1);
    }

    #[test]
    fn remote_failure_is_sanitized_and_preserves_prior_results() {
        let mut bytes = result_line(&success("a", json!(1)));
        bytes.extend(line(&json!({"type":"error","error":{"code":"BATCH_STREAM_FAILED","message":"secret response body"}})));
        let failure = read(&bytes, &["a", "b"]).unwrap_err();
        assert_eq!(failure.kind, BatchStreamFailureKind::Remote);
        assert_eq!(failure.results.len(), 1);
        assert!(!failure.to_string().contains("secret"));
    }

    fn executor_request(count: usize, parallelism: u32) -> fcp_host::BatchInvokeRequest {
        fcp_host::BatchInvokeRequest {
            operations: (0..count)
                .map(|index| fcp_host::BatchOperation {
                    id: format!("op-{index}"),
                    tool: "test.echo".into(),
                    input: Value::Null,
                    depends_on: Vec::new(),
                    zone: None,
                    scheduler: fcp_host::BatchScheduleHint::default(),
                })
                .collect(),
            options: fcp_host::BatchOptions {
                max_parallelism: parallelism,
                ..fcp_host::BatchOptions::default()
            },
        }
    }

    fn executor_roundtrip(
        produced: &BatchBoundedStreamingResponse,
        observed: &[OperationResult],
        request: &fcp_host::BatchInvokeRequest,
    ) -> BatchBoundedStreamingResponse {
        let mut bytes = Vec::new();
        for result in observed {
            bytes.extend(result_line(result));
        }
        bytes.extend(complete_line(produced));
        let expected = request
            .operations
            .iter()
            .map(|operation| operation.id.clone())
            .collect::<Vec<_>>();
        consume(bytes.as_slice(), &expected, |_| Ok::<(), ()>(())).unwrap()
    }

    #[fcp_async_core::runtime::test]
    async fn actual_executor_quota_and_skipped_records_roundtrip() {
        let request = executor_request(2, 1);
        let mut observed = Vec::new();
        let calls = Cell::new(0);
        let produced = fcp_host::BatchExecutor::new()
            .execute_async_bounded_wait(
                &request,
                None,
                BatchResultLimits::default(),
                |_| {
                    calls.set(calls.get() + 1);
                    ready(Ok(Value::String("x".repeat(1024 * 1024))))
                },
                |result| {
                    observed.push(result);
                    ready(Ok(()))
                },
            )
            .await
            .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(produced.bounded.withheld_results, 1);
        assert_eq!(produced.bounded.response.skipped, 1);
        let parsed = executor_roundtrip(&produced, &observed, &request);
        assert_eq!(parsed.acknowledged_results, 2);
        assert_eq!(parsed.delivery_status, BatchDeliveryStatus::Complete);
        assert_eq!(parsed.bounded.response.status, BatchStatus::Aborted);
    }

    #[fcp_async_core::runtime::test]
    async fn actual_executor_timeout_reconciles_unoffered_success_unknown_and_skipped() {
        let mut request = executor_request(3, 2);
        request.options.timeout_ms = 100;
        let offered = Cell::new(0);
        let context = fcp_async_core::ExecutionContext::request_scoped(Duration::from_secs(2));
        let produced = fcp_host::BatchExecutor::new()
            .execute_async_bounded_wait(
                &request,
                Some(&context),
                BatchResultLimits::default(),
                |operation| async move {
                    if operation.id == "op-1" {
                        pending::<()>().await;
                    }
                    Ok(json!(operation.id))
                },
                |_| {
                    offered.set(offered.get() + 1);
                    pending::<Result<(), BatchOperationError>>()
                },
            )
            .await
            .unwrap();
        assert_eq!(offered.get(), 1);
        assert_eq!(produced.acknowledged_results, 0);
        assert_eq!(produced.delivery_status, BatchDeliveryStatus::Interrupted);
        assert_eq!(
            (
                produced.bounded.response.completed,
                produced.bounded.response.failed,
                produced.bounded.response.skipped
            ),
            (1, 1, 1),
        );
        let parsed = executor_roundtrip(&produced, &[], &request);
        assert_eq!(
            parsed.bounded.response.results[1]
                .error
                .as_ref()
                .unwrap()
                .code,
            "BATCH_OUTCOME_UNKNOWN"
        );
        assert_eq!(
            parsed.bounded.response.results[2]
                .error
                .as_ref()
                .unwrap()
                .code,
            "BATCH_TIMEOUT"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn actual_provider_error_matching_reserved_text_is_not_mistaken_for_withholding() {
        let request = executor_request(1, 1);
        let mut observed = Vec::new();
        let produced = fcp_host::BatchExecutor::new().execute_async_bounded_wait(
            &request,
            None,
            BatchResultLimits::default(),
            |_| ready(Err(BatchOperationError {
                code: "BATCH_RESULT_LIMIT".into(),
                message: "operation returned a result that exceeded the retained-result budget; its external effects were not undone; do not retry without reconciliation".into(),
                retry_after_ms: None,
            })),
            |result| {
                observed.push(result);
                ready(Ok(()))
            },
        ).await.unwrap();
        assert_eq!(produced.bounded.withheld_results, 0);
        assert!(produced.bounded.retained_result_bytes > 0);
        assert_eq!(produced.bounded.response.status, BatchStatus::AllFailed);
        let parsed = executor_roundtrip(&produced, &observed, &request);
        assert_eq!(parsed.bounded.withheld_results, 0);
        assert_eq!(parsed.bounded.response.status, BatchStatus::AllFailed);
    }
}
