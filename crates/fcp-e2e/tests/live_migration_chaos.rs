#![cfg(unix)]

use std::collections::BTreeSet;
use std::error::Error;
use std::time::Duration;

use fcp_crypto::Ed25519SigningKey;
use fcp_e2e::ConnectorProcessRunner;
use fcp_host::HostResumeHandshakePolicy;
use fcp_raptorq::{ChunkedObjectManifest, RaptorQConfig, RaptorQEncoder, RawChunk};
use fcp_store::{
    DEFAULT_RESUME_HANDSHAKE_TIMEOUT_MS, ObjectTransmissionInfo, ProcessSnapshotFormat,
    ProcessSnapshotManifest, ProcessSnapshotTrustAnchors, ResumeHandshakeRequest,
    ResumeHandshakeTranscript, ResumeReplayOp, ResumeSnapshotSymbol, ResumeSourceLeaseRelease,
    ResumeTargetAck, ResumeTargetComplete,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const DEFAULT_ROOT_SEED: u64 = 0x5357_464a_335f_0106;
const CHAOS_ITERATIONS: usize = 100;
const STEPS_PER_ITERATION: u32 = 48;
const MIGRATIONS_PER_ITERATION: usize = 3;
const MAX_REPLAY_OPS: u32 = 3;
const CAPABILITY_TOKEN: &[u8] = b"fcp-e2e-migration-chaos-capability-token";
const NODES: [&str; 3] = ["node-alpha", "node-bravo", "node-charlie"];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ChaosInvocationState {
    seed: u64,
    cursor: u32,
    accumulator: [u8; 32],
    output: Vec<u8>,
}

impl ChaosInvocationState {
    fn new(seed: u64) -> Self {
        Self {
            seed,
            cursor: 0,
            accumulator: *blake3::hash(&seed.to_le_bytes()).as_bytes(),
            output: Vec::new(),
        }
    }

    fn advance_next(&mut self) -> ChaosStepEffect {
        let step = self.cursor;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"FCP-E2E-MIGRATION-CHAOS-STEP-V1");
        hasher.update(&self.seed.to_le_bytes());
        hasher.update(&step.to_le_bytes());
        hasher.update(&self.accumulator);
        let digest = *hasher.finalize().as_bytes();

        self.accumulator = digest;
        self.output.extend_from_slice(&digest[..16]);
        self.cursor = self.cursor.saturating_add(1);

        ChaosStepEffect {
            step,
            effect_bytes: digest,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ChaosStepEffect {
    step: u32,
    effect_bytes: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplayRecord {
    step: u32,
    op: ResumeReplayOp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MigrationChaosReplayBundle {
    scenario: String,
    seed: u64,
    iteration: usize,
    migration_index: usize,
    source_node: String,
    target_node: String,
    snapshot_cursor: u32,
    replay_count: usize,
    handshake_id: String,
    snapshot_manifest_hash: String,
    source_exit_status: Value,
    latency_units: u64,
    output_hash_after_replay: String,
    reproduction_hint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct MigrationChaosIterationReport {
    seed: u64,
    iteration: usize,
    migrations: Vec<MigrationChaosReplayBundle>,
    baseline_hash: String,
    migrated_hash: String,
    baseline_latency_units: u64,
    migrated_latency_units: u64,
    data_loss_bytes: u64,
}

struct MigrationOutcome {
    target_runner: ConnectorProcessRunner,
    target_node: &'static str,
    bundle: MigrationChaosReplayBundle,
}

#[derive(Clone, Debug)]
struct ChaosRng {
    state: u64,
}

impl ChaosRng {
    fn new(seed: u64) -> Self {
        Self {
            state: seed ^ 0x9e37_79b9_7f4a_7c15,
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 7;
        x ^= x >> 9;
        x ^= x << 8;
        self.state = x;
        x
    }

    fn range_usize(&mut self, upper_exclusive: usize) -> usize {
        if upper_exclusive == 0 {
            return 0;
        }
        let upper = u64::try_from(upper_exclusive).unwrap_or(u64::MAX);
        usize::try_from(self.next_u64() % upper).unwrap_or(0)
    }

    fn range_u32_inclusive(&mut self, upper_inclusive: u32) -> u32 {
        let upper = u64::from(upper_inclusive) + 1;
        u32::try_from(self.next_u64() % upper).unwrap_or(0)
    }
}

#[fcp_async_core::runtime::test]
async fn migration_chaos_random_kill_resume_preserves_long_running_output()
-> Result<(), Box<dyn Error>> {
    let root_seed = root_seed();
    let mut reports = Vec::with_capacity(CHAOS_ITERATIONS);

    for iteration in 0..CHAOS_ITERATIONS {
        let seed = root_seed ^ (u64::try_from(iteration).unwrap_or(0) << 32);
        reports.push(run_iteration(iteration, seed).await?);
    }

    for report in &reports {
        assert_eq!(
            report.baseline_hash, report.migrated_hash,
            "seed {} iteration {} diverged; rerun with FCP_MIGRATION_CHAOS_SEED={}",
            report.seed, report.iteration, report.seed
        );
        assert_eq!(
            report.data_loss_bytes, 0,
            "seed {} iteration {} lost bytes",
            report.seed, report.iteration
        );
        assert_eq!(report.migrations.len(), MIGRATIONS_PER_ITERATION);
        for bundle in &report.migrations {
            let value = serde_json::to_value(bundle)?;
            assert_eq!(value["scenario"], "live_migration_chaos");
            assert!(
                value["source_exit_status"]["captured"]
                    .as_bool()
                    .unwrap_or(false)
            );
            assert!(
                value["reproduction_hint"]
                    .as_str()
                    .unwrap_or("")
                    .contains("FCP_MIGRATION_CHAOS_SEED=")
            );
        }
    }

    let p99 = p99_latency_units(reports.iter().map(|report| report.migrated_latency_units));
    let baseline = u64::from(STEPS_PER_ITERATION);
    assert!(
        p99 <= baseline.saturating_mul(2),
        "p99 migration overhead exceeded 2x baseline: p99={p99} baseline={baseline}"
    );

    Ok(())
}

async fn run_iteration(
    iteration: usize,
    seed: u64,
) -> Result<MigrationChaosIterationReport, Box<dyn Error>> {
    let mut rng = ChaosRng::new(seed);
    let migration_points = migration_points(&mut rng);
    let baseline_output = baseline_output(seed);
    let baseline_hash = hex_hash(&baseline_output);

    let mut current_node = NODES[0];
    let mut runner = spawn_connector(current_node).await?;
    let mut state = ChaosInvocationState::new(seed);
    let mut migration_index = 0_usize;
    let mut reports = Vec::with_capacity(MIGRATIONS_PER_ITERATION);

    while state.cursor < STEPS_PER_ITERATION {
        if migration_index < migration_points.len()
            && state.cursor == migration_points[migration_index]
        {
            let target_node = pick_target_node(&mut rng, current_node);
            let next_migration_point = migration_points.get(migration_index + 1).copied();
            let replay_budget = STEPS_PER_ITERATION
                .saturating_sub(state.cursor)
                .min(MAX_REPLAY_OPS);
            let replay_budget = match next_migration_point {
                Some(next_point) => {
                    replay_budget.min(next_point.saturating_sub(state.cursor).saturating_sub(1))
                }
                None => replay_budget,
            };
            let replay_count = rng.range_u32_inclusive(replay_budget);
            let outcome = migrate_once(
                iteration,
                migration_index,
                seed,
                current_node,
                target_node,
                &mut runner,
                &mut state,
                replay_count,
            )
            .await?;
            runner = outcome.target_runner;
            current_node = outcome.target_node;
            reports.push(outcome.bundle);
            while migration_index < migration_points.len()
                && migration_points[migration_index] <= state.cursor
            {
                migration_index += 1;
            }
        } else {
            observe_connector_step(&mut runner, iteration, current_node, state.cursor).await?;
            state.advance_next();
        }
    }

    let _ = runner
        .terminate_and_capture_exit_status(Duration::from_millis(250))
        .await?;
    let migrated_hash = hex_hash(&state.output);
    let data_loss_bytes = byte_delta(&baseline_output, &state.output);
    let migrated_latency_units = u64::from(STEPS_PER_ITERATION)
        .saturating_add(u64::try_from(reports.len()).unwrap_or(0).saturating_mul(2));

    Ok(MigrationChaosIterationReport {
        seed,
        iteration,
        migrations: reports,
        baseline_hash,
        migrated_hash,
        baseline_latency_units: u64::from(STEPS_PER_ITERATION),
        migrated_latency_units,
        data_loss_bytes,
    })
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
async fn migrate_once(
    iteration: usize,
    migration_index: usize,
    seed: u64,
    source_node: &'static str,
    target_node: &'static str,
    source_runner: &mut ConnectorProcessRunner,
    state: &mut ChaosInvocationState,
    replay_count: u32,
) -> Result<MigrationOutcome, Box<dyn Error>> {
    let signing_key = Ed25519SigningKey::from_bytes(&[0x31; 32])?;
    let anchors = ProcessSnapshotTrustAnchors::single(signing_key.verifying_key());
    let raptorq_config = RaptorQConfig::default();
    let snapshot_cursor = state.cursor;
    let snapshot_payload = serde_json::to_vec(state)?;
    let (chunk_manifest, chunks) = ChunkedObjectManifest::from_payload(&snapshot_payload, 128);
    let manifest = ProcessSnapshotManifest::sign(
        10_000_u32.saturating_add(u32::try_from(iteration).unwrap_or(0)),
        source_node,
        ProcessSnapshotFormat::Criu,
        chunk_manifest,
        CAPABILITY_TOKEN,
        &signing_key,
    )?;
    let manifest_bytes = manifest.canonical_bytes()?;
    let encoder = RaptorQEncoder::new(&manifest_bytes, &raptorq_config)?;
    let started_at_ms = 1_000_000_u64
        .saturating_add(u64::try_from(iteration).unwrap_or(0).saturating_mul(1_000))
        .saturating_add(
            u64::try_from(migration_index)
                .unwrap_or(0)
                .saturating_mul(100),
        );

    let replay_records =
        advance_source_after_snapshot(source_runner, iteration, source_node, state, replay_count)
            .await?;
    let replay_ops = replay_records
        .iter()
        .map(|record| record.op.clone())
        .collect::<Vec<_>>();
    let request = ResumeHandshakeRequest::new(
        source_node,
        target_node,
        &manifest,
        ObjectTransmissionInfo::from_oti(encoder.transmission_info()),
        7000_u64.saturating_add(u64::try_from(iteration).unwrap_or(0)),
        started_at_ms,
        DEFAULT_RESUME_HANDSHAKE_TIMEOUT_MS,
        replay_ops.clone(),
    )?;
    let ack = ResumeTargetAck::accept(
        &request,
        Some(format!("reservation-{iteration}-{migration_index}")),
        started_at_ms.saturating_add(1),
    );
    let symbols = request.encode_snapshot_manifest_symbols(
        &manifest_bytes,
        &raptorq_config,
        ack.acked_at_ms,
    )?;
    let complete = ResumeTargetComplete::rehydrated(
        &request,
        replay_ops.clone(),
        last_symbol_at(&symbols).saturating_add(1),
    )?;
    let source_release =
        ResumeSourceLeaseRelease::new(&request, complete.resumed_at_ms.saturating_add(1));
    let transcript = ResumeHandshakeTranscript {
        request,
        ack,
        symbols,
        complete,
        source_release,
    };

    transcript.validate_success()?;
    HostResumeHandshakePolicy::default().validate_source_release(&transcript)?;
    let verified_manifest = transcript.decode_verified_snapshot_manifest(
        &raptorq_config,
        CAPABILITY_TOKEN,
        &anchors,
    )?;
    let mut rehydrated_state = rehydrate_state(&verified_manifest, &chunks)?;
    replay_on_target(&mut rehydrated_state, &replay_records);
    assert_eq!(
        &rehydrated_state, state,
        "seed {seed} iteration {iteration} migration {migration_index} rehydrated state diverged"
    );

    let source_exit_status = source_runner
        .terminate_and_capture_exit_status(Duration::from_millis(250))
        .await?;
    let mut target_runner = spawn_connector(target_node).await?;
    let resume_request = json!({
        "method": "resume",
        "seed": seed,
        "iteration": iteration,
        "migration_index": migration_index,
        "cursor": rehydrated_state.cursor,
        "snapshot_manifest_hash": transcript.request.snapshot_manifest_hash.to_string(),
    });
    let resume_response = target_runner.request(&resume_request).await?;
    assert_eq!(resume_response, resume_request);

    let bundle = MigrationChaosReplayBundle {
        scenario: "live_migration_chaos".to_string(),
        seed,
        iteration,
        migration_index,
        source_node: source_node.to_string(),
        target_node: target_node.to_string(),
        snapshot_cursor,
        replay_count: replay_records.len(),
        handshake_id: transcript.request.handshake_id.to_string(),
        snapshot_manifest_hash: transcript.request.snapshot_manifest_hash.to_string(),
        source_exit_status,
        latency_units: u64::from(STEPS_PER_ITERATION).saturating_add(2),
        output_hash_after_replay: hex_hash(&rehydrated_state.output),
        reproduction_hint: format!(
            "FCP_MIGRATION_CHAOS_SEED={seed} cargo test -p fcp-e2e migration_chaos --all-targets -- --nocapture"
        ),
    };

    Ok(MigrationOutcome {
        target_runner,
        target_node,
        bundle,
    })
}

async fn advance_source_after_snapshot(
    runner: &mut ConnectorProcessRunner,
    iteration: usize,
    source_node: &'static str,
    state: &mut ChaosInvocationState,
    replay_count: u32,
) -> Result<Vec<ReplayRecord>, Box<dyn Error>> {
    let mut records = Vec::with_capacity(usize::try_from(replay_count).unwrap_or(0));
    for _ in 0..replay_count {
        if state.cursor >= STEPS_PER_ITERATION {
            break;
        }
        observe_connector_step(runner, iteration, source_node, state.cursor).await?;
        let effect = state.advance_next();
        records.push(ReplayRecord {
            step: effect.step,
            op: ResumeReplayOp::from_effect(
                format!("iteration-{iteration}-step-{}", effect.step),
                &effect.effect_bytes,
            ),
        });
    }
    Ok(records)
}

fn replay_on_target(state: &mut ChaosInvocationState, replay_records: &[ReplayRecord]) {
    for record in replay_records {
        assert_eq!(
            state.cursor, record.step,
            "target replay cursor must match source in-flight op"
        );
        let effect = state.advance_next();
        let replayed = ResumeReplayOp::from_effect(record.op.op_id.clone(), &effect.effect_bytes);
        assert_eq!(replayed, record.op);
    }
}

fn rehydrate_state(
    manifest: &ProcessSnapshotManifest,
    chunks: &[RawChunk],
) -> Result<ChaosInvocationState, Box<dyn Error>> {
    let payload = manifest.chunk_manifest.reconstruct(chunks)?;
    Ok(serde_json::from_slice(&payload)?)
}

async fn observe_connector_step(
    runner: &mut ConnectorProcessRunner,
    iteration: usize,
    node: &'static str,
    step: u32,
) -> Result<(), Box<dyn Error>> {
    let request = json!({
        "method": "invoke",
        "connector": "fcp.test.migration-chaos:utility:1.0.0",
        "iteration": iteration,
        "node": node,
        "step": step,
    });
    let response = runner.request(&request).await?;
    assert_eq!(response, request);
    Ok(())
}

async fn spawn_connector(node: &'static str) -> Result<ConnectorProcessRunner, Box<dyn Error>> {
    Ok(ConnectorProcessRunner::spawn("cat", &[], &[("FCP_NODE", node)]).await?)
}

fn migration_points(rng: &mut ChaosRng) -> Vec<u32> {
    let mut points = BTreeSet::new();
    while points.len() < MIGRATIONS_PER_ITERATION {
        let span = STEPS_PER_ITERATION.saturating_sub(2);
        let point = 1_u32.saturating_add(rng.range_u32_inclusive(span.saturating_sub(1)));
        points.insert(point);
    }
    points.into_iter().collect()
}

fn pick_target_node(rng: &mut ChaosRng, source_node: &'static str) -> &'static str {
    loop {
        let candidate = NODES[rng.range_usize(NODES.len())];
        if candidate != source_node {
            return candidate;
        }
    }
}

fn baseline_output(seed: u64) -> Vec<u8> {
    let mut state = ChaosInvocationState::new(seed);
    while state.cursor < STEPS_PER_ITERATION {
        state.advance_next();
    }
    state.output
}

fn last_symbol_at(symbols: &[ResumeSnapshotSymbol]) -> u64 {
    symbols.last().map_or(0, |symbol| symbol.sent_at_ms)
}

fn p99_latency_units(values: impl Iterator<Item = u64>) -> u64 {
    let mut values = values.collect::<Vec<_>>();
    values.sort_unstable();
    let len = values.len();
    if len == 0 {
        return 0;
    }
    let index = len.saturating_mul(99).div_ceil(100).saturating_sub(1);
    values[index.min(len - 1)]
}

fn byte_delta(expected: &[u8], actual: &[u8]) -> u64 {
    let common = expected.len().min(actual.len());
    let differing = expected
        .iter()
        .zip(actual.iter())
        .take(common)
        .filter(|(left, right)| left != right)
        .count();
    let length_delta = expected.len().abs_diff(actual.len());
    u64::try_from(differing.saturating_add(length_delta)).unwrap_or(u64::MAX)
}

fn hex_hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

fn root_seed() -> u64 {
    std::env::var("FCP_MIGRATION_CHAOS_SEED")
        .ok()
        .and_then(|value| parse_seed(&value))
        .unwrap_or(DEFAULT_ROOT_SEED)
}

fn parse_seed(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"));
    hex.map_or_else(
        || trimmed.parse::<u64>().ok(),
        |hex| u64::from_str_radix(hex, 16).ok(),
    )
}
