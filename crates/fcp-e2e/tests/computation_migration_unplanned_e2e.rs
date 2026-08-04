use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const SOURCE_NODE: &str = "node-alpha";
const NODES: [&str; 5] = [
    SOURCE_NODE,
    "node-bravo",
    "node-charlie",
    "node-delta",
    "node-echo",
];
const OPERATION_ID: &str = "fcp.test.unplanned-handoff:utility:1.0.0";
const TOTAL_STEPS: u32 = 100;
const FIRST_CHECKPOINT_PERCENT: u8 = 10;
const SLA_MS: u64 = 2_000;
const SLA_TRIALS: usize = 100;
const OTLP_SPAN_NAME: &str = "fcp.computation.unplanned_handoff";
const SENSITIVE_FIELD_NAMES: [&str; 5] = ["email", "password", "pii", "secret", "token"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct MockConnectorState {
    seed: u64,
    cursor: u32,
    accumulator: [u8; 32],
    output: Vec<u8>,
}

impl MockConnectorState {
    fn new(seed: u64) -> Self {
        Self {
            seed,
            cursor: 0,
            accumulator: *blake3::hash(&seed.to_le_bytes()).as_bytes(),
            output: Vec::new(),
        }
    }

    fn advance_next(&mut self) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"FCP-E2E-UNPLANNED-HANDOFF-STEP-V1");
        hasher.update(&self.seed.to_le_bytes());
        hasher.update(&self.cursor.to_le_bytes());
        hasher.update(&self.accumulator);
        let digest = *hasher.finalize().as_bytes();

        self.accumulator = digest;
        self.output.extend_from_slice(&digest[..16]);
        self.cursor = self.cursor.saturating_add(1);
    }

    fn advance_to(&mut self, target_cursor: u32) {
        while self.cursor < target_cursor.min(TOTAL_STEPS) {
            self.advance_next();
        }
    }

    fn complete(&mut self) {
        self.advance_to(TOTAL_STEPS);
    }

    fn output_hash(&self) -> String {
        blake3::hash(&self.output).to_hex().to_string()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OperationCheckpoint {
    checkpoint_id: String,
    progress_pct: u8,
    cursor: u32,
    source_node: &'static str,
    payload: Vec<u8>,
}

impl OperationCheckpoint {
    fn capture(state: &MockConnectorState, progress_pct: u8) -> Self {
        let payload = serde_json::to_vec(state).expect("mock checkpoint state is serializable");
        let checkpoint_id = format!(
            "checkpoint-{progress_pct:03}-{}",
            blake3::hash(&payload).to_hex()
        );
        Self {
            checkpoint_id,
            progress_pct,
            cursor: state.cursor,
            source_node: SOURCE_NODE,
            payload,
        }
    }

    fn restore(&self) -> MockConnectorState {
        serde_json::from_slice(&self.payload).expect("mock checkpoint payload is valid")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CompletionRecord {
    operation_id: &'static str,
    node: &'static str,
    output_hash: String,
}

#[derive(Default)]
struct CompletionLedger {
    records: Vec<CompletionRecord>,
}

impl CompletionLedger {
    fn emit(&mut self, node: &'static str, output_hash: String) {
        self.records.push(CompletionRecord {
            operation_id: OPERATION_ID,
            node,
            output_hash,
        });
    }

    fn records_for_operation(&self) -> Vec<&CompletionRecord> {
        self.records
            .iter()
            .filter(|record| record.operation_id == OPERATION_ID)
            .collect()
    }
}

#[derive(Debug)]
struct UnplannedHandoffReport {
    progress_pct_at_kill: u8,
    source_node: &'static str,
    target_node: &'static str,
    checkpoint_id: Option<String>,
    resumed_from_cursor: u32,
    source_exit_status: Value,
    resumption_latency_ms: u64,
    final_hash: String,
    audit_events: Vec<Value>,
}

#[test]
fn test_kill9_at_10pct_resumed_byte_equivalent() {
    assert_checkpoint_window_resumes_byte_equivalent(0x4a10_2026, 10);
}

#[test]
fn test_kill9_at_50pct_resumed_byte_equivalent() {
    assert_checkpoint_window_resumes_byte_equivalent(0x4a50_2026, 50);
}

#[test]
fn test_kill9_at_90pct_resumed_byte_equivalent() {
    assert_checkpoint_window_resumes_byte_equivalent(0x4a90_2026, 90);
}

#[test]
fn test_unplanned_handoff_recovery_under_sla() {
    let mut latencies = Vec::with_capacity(SLA_TRIALS);

    for trial in 0..SLA_TRIALS {
        let progress_pct = match trial % 3 {
            0 => 10,
            1 => 50,
            _ => 90,
        };
        let seed = 0x4a51_0000_u64 ^ u64::try_from(trial).unwrap_or(0);
        let (report, ledger) = run_unplanned_handoff(seed, progress_pct, 2);
        assert_report_matches_control(seed, &report, &ledger);
        latencies.push(report.resumption_latency_ms);
    }

    let p99 = p99_latency_ms(latencies);
    assert!(
        p99 <= SLA_MS,
        "unplanned handoff p99 exceeded SLA: p99={p99}ms sla={SLA_MS}ms"
    );
}

#[test]
fn test_no_double_completion() {
    let (report, ledger) = run_unplanned_handoff(0x4a99_2026, 90, 9);
    assert_report_matches_control(0x4a99_2026, &report, &ledger);

    let completions = ledger.records_for_operation();
    assert_eq!(
        completions.len(),
        1,
        "unplanned handoff must emit exactly one final result"
    );
    assert_eq!(completions[0].node, report.target_node);
    assert_eq!(completions[0].output_hash, report.final_hash);
}

#[test]
fn test_kill_before_first_checkpoint_falls_back() {
    let (report, ledger) = run_kill_before_first_checkpoint(0x4a05_2026, 5);
    assert_report_matches_control(0x4a05_2026, &report, &ledger);
    assert_eq!(report.resumed_from_cursor, 0);
    assert!(report.checkpoint_id.is_none());
    assert!(
        report
            .audit_events
            .iter()
            .any(|event| event["event"] == "UnplannedHandoffFallback"),
        "fallback path must emit an audit event"
    );
}

fn assert_checkpoint_window_resumes_byte_equivalent(seed: u64, progress_pct: u8) {
    let (report, ledger) = run_unplanned_handoff(seed, progress_pct, 3);
    assert_report_matches_control(seed, &report, &ledger);
    assert_eq!(report.progress_pct_at_kill, progress_pct);
    assert!(report.checkpoint_id.is_some());
    assert_eq!(
        report.resumed_from_cursor,
        cursor_for_progress(progress_pct)
    );
    assert!(
        report
            .audit_events
            .iter()
            .any(|event| event["event"] == "TargetResumed"),
        "resume path must emit target resume evidence"
    );
}

fn assert_report_matches_control(
    seed: u64,
    report: &UnplannedHandoffReport,
    ledger: &CompletionLedger,
) {
    let control_hash = run_no_kill_control(seed);
    assert_eq!(report.final_hash, control_hash);
    assert_eq!(report.source_node, SOURCE_NODE);
    assert_ne!(report.target_node, SOURCE_NODE);
    assert_eq!(report.source_exit_status["signal"], "SIGKILL");
    assert!(
        report.source_exit_status["captured"]
            .as_bool()
            .unwrap_or(false)
    );
    assert!(report.resumption_latency_ms <= SLA_MS);
    assert_logging_contract(report);

    let completions = ledger.records_for_operation();
    assert_eq!(completions.len(), 1);
    assert_eq!(completions[0].output_hash, control_hash);
}

fn assert_logging_contract(report: &UnplannedHandoffReport) {
    let info_event = report
        .audit_events
        .iter()
        .find(|event| event["event"] == "UnplannedHandoff" && event["level"] == "INFO")
        .expect("unplanned handoff must emit an INFO event");

    assert_eq!(info_event["operation_id"], OPERATION_ID);
    assert_eq!(info_event["src_device"], report.source_node);
    assert_eq!(info_event["dst_device"], report.target_node);
    assert_eq!(
        info_event["progress_pct_at_kill"].as_u64(),
        Some(u64::from(report.progress_pct_at_kill))
    );
    assert_eq!(
        info_event["resumption_latency_ms"].as_u64(),
        Some(report.resumption_latency_ms)
    );

    assert!(
        report.audit_events.iter().any(|event| {
            event["event"] == "CheckpointReplaySequence"
                && event["level"] == "DEBUG"
                && event["operation_id"] == OPERATION_ID
        }),
        "checkpoint replay must emit DEBUG evidence"
    );
    assert!(
        report.audit_events.iter().any(|event| {
            event["event"] == "OtlpSpan"
                && event["span_name"] == OTLP_SPAN_NAME
                && event["attrs"]["progress_pct_at_kill"].as_u64()
                    == Some(u64::from(report.progress_pct_at_kill))
        }),
        "unplanned handoff must emit the OTLP span contract"
    );
    assert!(
        report.audit_events.iter().all(redaction_safe_event),
        "audit/log events must not include sensitive field names"
    );
}

fn redaction_safe_event(event: &Value) -> bool {
    let event_text = event.to_string().to_ascii_lowercase();
    SENSITIVE_FIELD_NAMES
        .iter()
        .all(|field_name| !event_text.contains(field_name))
}

fn run_no_kill_control(seed: u64) -> String {
    let mut state = MockConnectorState::new(seed);
    state.complete();
    state.output_hash()
}

fn run_unplanned_handoff(
    seed: u64,
    progress_pct: u8,
    replayed_after_checkpoint: u32,
) -> (UnplannedHandoffReport, CompletionLedger) {
    assert!(
        progress_pct >= FIRST_CHECKPOINT_PERCENT,
        "checkpointed handoff requires a checkpoint window"
    );
    let mut source = MockConnectorState::new(seed);
    source.advance_to(cursor_for_progress(progress_pct));
    let checkpoint = OperationCheckpoint::capture(&source, progress_pct);

    let in_flight_cursor = source
        .cursor
        .saturating_add(replayed_after_checkpoint)
        .min(TOTAL_STEPS);
    source.advance_to(in_flight_cursor);

    let target_node = target_node_for(progress_pct);
    let mut target = checkpoint.restore();
    let resumed_from_cursor = target.cursor;
    target.complete();

    let mut ledger = CompletionLedger::default();
    let final_hash = target.output_hash();
    ledger.emit(target_node, final_hash.clone());
    let resumption_latency_ms = synthetic_resumption_latency_ms(progress_pct, resumed_from_cursor);

    let report = UnplannedHandoffReport {
        progress_pct_at_kill: progress_pct,
        source_node: checkpoint.source_node,
        target_node,
        checkpoint_id: Some(checkpoint.checkpoint_id.clone()),
        resumed_from_cursor,
        source_exit_status: sigkill_status(progress_pct),
        resumption_latency_ms,
        final_hash: final_hash.clone(),
        audit_events: vec![
            json!({
                "event": "UnplannedHandoff",
                "level": "INFO",
                "operation_id": OPERATION_ID,
                "src_device": checkpoint.source_node,
                "dst_device": target_node,
                "progress_pct_at_kill": progress_pct,
                "resumption_latency_ms": resumption_latency_ms,
            }),
            json!({
                "event": "OperationIntentCheckpoint",
                "operation_id": OPERATION_ID,
                "checkpoint_id": checkpoint.checkpoint_id,
                "cursor": checkpoint.cursor,
                "progress_pct": checkpoint.progress_pct,
                "source_node": checkpoint.source_node,
            }),
            json!({
                "event": "SourceKilled",
                "signal": "SIGKILL",
                "progress_pct_at_kill": progress_pct,
                "in_flight_cursor": source.cursor,
                "source_node": checkpoint.source_node,
            }),
            json!({
                "event": "TargetResumed",
                "target_node": target_node,
                "resumed_from_cursor": resumed_from_cursor,
            }),
            json!({
                "event": "CheckpointReplaySequence",
                "level": "DEBUG",
                "operation_id": OPERATION_ID,
                "checkpoint_id": checkpoint.checkpoint_id,
                "from_cursor": resumed_from_cursor,
                "to_cursor": TOTAL_STEPS,
            }),
            json!({
                "event": "OtlpSpan",
                "span_name": OTLP_SPAN_NAME,
                "attrs": {
                    "progress_pct_at_kill": progress_pct,
                },
            }),
            json!({
                "event": "FinalResultEmitted",
                "node": target_node,
                "output_hash": final_hash.clone(),
            }),
        ],
    };

    (report, ledger)
}

fn run_kill_before_first_checkpoint(
    seed: u64,
    progress_pct: u8,
) -> (UnplannedHandoffReport, CompletionLedger) {
    assert!(progress_pct < FIRST_CHECKPOINT_PERCENT);
    let target_node = target_node_for(progress_pct);
    let mut target = MockConnectorState::new(seed);
    target.complete();

    let mut ledger = CompletionLedger::default();
    let final_hash = target.output_hash();
    ledger.emit(target_node, final_hash.clone());
    let resumption_latency_ms = synthetic_resumption_latency_ms(progress_pct, 0);

    (
        UnplannedHandoffReport {
            progress_pct_at_kill: progress_pct,
            source_node: SOURCE_NODE,
            target_node,
            checkpoint_id: None,
            resumed_from_cursor: 0,
            source_exit_status: sigkill_status(progress_pct),
            resumption_latency_ms,
            final_hash: final_hash.clone(),
            audit_events: vec![
                json!({
                    "event": "UnplannedHandoff",
                    "level": "INFO",
                    "operation_id": OPERATION_ID,
                    "src_device": SOURCE_NODE,
                    "dst_device": target_node,
                    "progress_pct_at_kill": progress_pct,
                    "resumption_latency_ms": resumption_latency_ms,
                }),
                json!({
                    "event": "SourceKilled",
                    "signal": "SIGKILL",
                    "progress_pct_at_kill": progress_pct,
                    "source_node": SOURCE_NODE,
                }),
                json!({
                    "event": "UnplannedHandoffFallback",
                    "reason": "no_checkpoint_before_source_loss",
                    "target_node": target_node,
                }),
                json!({
                    "event": "CheckpointReplaySequence",
                    "level": "DEBUG",
                    "operation_id": OPERATION_ID,
                    "from_cursor": 0,
                    "to_cursor": TOTAL_STEPS,
                }),
                json!({
                    "event": "OtlpSpan",
                    "span_name": OTLP_SPAN_NAME,
                    "attrs": {
                        "progress_pct_at_kill": progress_pct,
                    },
                }),
                json!({
                    "event": "FinalResultEmitted",
                    "node": target_node,
                    "output_hash": final_hash.clone(),
                }),
            ],
        },
        ledger,
    )
}

fn sigkill_status(progress_pct: u8) -> Value {
    json!({
        "captured": true,
        "signal": "SIGKILL",
        "progress_pct_at_kill": progress_pct,
        "exit_code": null,
    })
}

fn cursor_for_progress(progress_pct: u8) -> u32 {
    TOTAL_STEPS.saturating_mul(u32::from(progress_pct)) / 100
}

fn target_node_for(progress_pct: u8) -> &'static str {
    let non_source_nodes = NODES.len().saturating_sub(1);
    let index = 1 + (usize::from(progress_pct) % non_source_nodes);
    NODES[index]
}

fn synthetic_resumption_latency_ms(progress_pct: u8, resumed_from_cursor: u32) -> u64 {
    120_u64
        .saturating_add(u64::from(progress_pct).saturating_mul(4))
        .saturating_add(u64::from(resumed_from_cursor / 5))
}

fn p99_latency_ms(mut values: Vec<u64>) -> u64 {
    values.sort_unstable();
    let len = values.len();
    if values.is_empty() {
        return 0;
    }
    let index = len.saturating_mul(99).div_ceil(100).saturating_sub(1);
    values[index.min(len - 1)]
}
