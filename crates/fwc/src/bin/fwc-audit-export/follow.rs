//! Streaming JSONL adapter over the shared host journal follower.
//! No whole-history buffering, file mutation, automatic restart or hidden task.

use std::io::Write;
use std::time::{Duration, Instant};

use fcp_host::{InvokeAuditFollowBatch, InvokeAuditFollower, InvokeAuditSnapshotError};
use serde_json::json;

use super::{Args, ExportError, Format, json_line, selection, validate_selection};

#[derive(Debug, Default, clap::Args)]
pub(super) struct FollowOptions {
    /// Follow complete appended records; requires --format jsonl. Ctrl-C stops.
    #[arg(long)]
    pub(super) follow: bool,
    /// Stop after this many matching records, including existing history.
    #[arg(long, requires = "follow")]
    limit: Option<u64>,
    /// Delay at sampled EOF or an incomplete tail (1..60000 ms; default 250).
    #[arg(long, requires = "follow")]
    poll_interval_ms: Option<u64>,
    /// Stop after no matching records for this duration; incomplete tails fail.
    #[arg(long, requires = "follow")]
    idle_timeout_ms: Option<u64>,
}

impl FollowOptions {
    pub(super) fn validate(&self, format: Format) -> Result<(), ExportError> {
        if (self.follow && format != Format::Jsonl)
            || (!self.follow && (self.limit.is_some() || self.poll_interval_ms.is_some()
                || self.idle_timeout_ms.is_some()))
            || self.limit == Some(0)
            || self.idle_timeout_ms == Some(0)
            || self.poll_interval_ms.is_some_and(|value| !(1..=60_000).contains(&value))
        {
            return Err(ExportError::Usage);
        }
        Ok(())
    }
}

pub(super) fn run(
    args: &Args,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
) -> Result<(), ExportError> {
    validate_selection(args)?;
    let mut follower = InvokeAuditFollower::open(&args.journal).map_err(ExportError::Follow)?;
    let start = Instant::now();
    run_loop(args, output, diagnostics, || follower.poll(), || start.elapsed(), std::thread::sleep)
}

fn matches(entry: &fcp_audit::AuditEntry, args: &Args) -> bool {
    args.zone.as_deref().is_none_or(|zone| entry.zone_id == zone)
        && args.request_id.as_deref().is_none_or(|id| entry.operation_id.as_deref() == Some(id))
        && args.from_seq.is_none_or(|seq| entry.seq >= seq)
}

fn progress(
    args: &Args,
    batch: &InvokeAuditFollowBatch,
    emitted: u64,
    stopped: Option<&str>,
    diagnostics: &mut impl Write,
) -> Result<(), ExportError> {
    json_line(diagnostics, &json!({
        "schema_version": "fcp.fwc.invoke_audit_follow.v1",
        "kind": "local-invoke-journal-follow",
        "live": false,
        "integrity": "observed-prefix-canonical-ids-and-per-zone-lineage",
        "authenticity": "not-verified",
        "durability": "not-assessed",
        "validated_prefix_bytes": batch.bytes(),
        "observed_bytes": batch.observed_bytes(),
        "observed_prefix_digest": batch.digest(),
        "validated_records": batch.total_records(),
        "emitted_records": emitted,
        "pending_frame": batch.pending_frame(),
        "caught_up_to_sample": batch.caught_up(),
        "selection": selection(args),
        "limit": args.stream.limit,
        "filtered": args.zone.is_some() || args.request_id.is_some()
            || args.from_seq.is_some() || args.stream.limit.is_some(),
        "stop_reason": stopped,
    }))?;
    diagnostics.flush().map_err(|_| ExportError::Output)
}

// Inject only scheduling, not evidence, so tests exercise the actual reader
// and JSONL writer without timing-dependent sleeps or a fabricated host source.
fn run_loop(
    args: &Args,
    output: &mut impl Write,
    diagnostics: &mut impl Write,
    mut poll: impl FnMut() -> Result<InvokeAuditFollowBatch, InvokeAuditSnapshotError>,
    mut elapsed: impl FnMut() -> Duration,
    mut wait: impl FnMut(Duration),
) -> Result<(), ExportError> {
    validate_selection(args)?;
    let cadence = Duration::from_millis(args.stream.poll_interval_ms.unwrap_or(250));
    let idle = args.stream.idle_timeout_ms.map(Duration::from_millis);
    let mut last_match = elapsed();
    let mut emitted = 0_u64;
    let mut last_progress = None;
    loop {
        let batch = poll().map_err(ExportError::Follow)?;
        if last_progress.is_none() {
            // Fail before any stdout if provenance cannot be delivered.
            progress(args, &batch, emitted, None, diagnostics)?;
        }
        let before = emitted;
        for entry in batch.entries().iter().filter(|entry| matches(entry, args)) {
            if args.stream.limit.is_some_and(|limit| emitted >= limit) {
                break;
            }
            json_line(output, entry)?;
            emitted += 1;
        }
        // Pipe consumers see each complete batch before the next polling wait.
        // Any write/flush failure stops observation and exits nonzero.
        output.flush().map_err(|_| ExportError::Output)?;
        if emitted != before {
            last_match = elapsed();
        }
        let current = (batch.bytes(), batch.observed_bytes(), batch.pending_frame(), emitted);
        if last_progress != Some(current) {
            progress(args, &batch, emitted, None, diagnostics)?;
            last_progress = Some(current);
        }
        if args.stream.limit.is_some_and(|limit| emitted >= limit) {
            progress(args, &batch, emitted, Some("record-limit"), diagnostics)?;
            return Ok(());
        }
        let idle_elapsed = elapsed().saturating_sub(last_match);
        if idle.is_some_and(|timeout| idle_elapsed >= timeout) {
            progress(args, &batch, emitted, Some("idle-timeout"), diagnostics)?;
            if batch.pending_frame() {
                return Err(ExportError::FollowIncomplete);
            }
            return if emitted == 0 {
                Err(ExportError::FollowNoMatch)
            } else {
                Ok(())
            };
        }
        if batch.caught_up() || batch.pending_frame() {
            let delay = idle.map_or(cadence, |timeout| cadence.min(timeout - idle_elapsed));
            // One synchronous CLI thread owns its timing; no per-poll async task.
            // Idle is checked between bounded polls/writes, not an OS I/O timeout.
            wait(delay);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs::OpenOptions;
    use clap::Parser;
    use fcp_audit::AuditEntry;
    use fcp_audit::explain::{explain_bundle, parse_replay_bundle};
    use fcp_host::{InvokeAuditChain, InvokeAuditContext, InvokePhase};
    use serde_json::Value;
    use super::*;

    fn context(zone: &str, request: &str) -> InvokeAuditContext {
        InvokeAuditContext {
            zone_id: zone.to_owned(), actor: "agent:follow-cli".to_owned(),
            connector_id: "github".to_owned(), operation: "issues.create".to_owned(),
            operation_id: request.to_owned(), correlation_id: Some("shared".to_owned()),
            occurred_at: 1_700_000_000,
        }
    }

    fn fixture() -> (tempfile::TempDir, Args, Vec<AuditEntry>) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal");
        let chain = InvokeAuditChain::open_with_journal(&path).unwrap();
        let entries = vec![
            chain.append(&context("z:work", "a"), InvokePhase::PreflightAllow).unwrap(),
            chain.append(&context("z:work", "b"), InvokePhase::PreflightDeny {
                reason: "preflight_denied".to_owned(),
            }).unwrap(),
            chain.append(&context("z:private", "a"), InvokePhase::PreflightAllow).unwrap(),
            chain.append(&context("z:work", "a"), InvokePhase::DispatchResult {
                receipt_id: None, success: true, duration_ms: 10,
            }).unwrap(),
        ];
        drop(chain);
        let args = Args::try_parse_from([
            "fwc-audit-export", "--journal", path.to_str().unwrap(),
            "--format", "jsonl", "--follow",
        ]).unwrap();
        (directory, args, entries)
    }

    fn frame(entry: &AuditEntry) -> Vec<u8> {
        let payload = serde_json::to_vec(entry).unwrap();
        let mut bytes = u32::try_from(payload.len()).unwrap().to_le_bytes().to_vec();
        bytes.extend_from_slice(&payload);
        bytes
    }

    fn transcript(output: &[u8]) -> Vec<AuditEntry> {
        parse_replay_bundle(std::str::from_utf8(output).unwrap()).unwrap().audit_entries
    }

    fn last_progress(bytes: &[u8]) -> Value {
        serde_json::from_str(std::str::from_utf8(bytes).unwrap().lines().last().unwrap()).unwrap()
    }

    #[test]
    fn finite_follow_uses_actual_dispatch_path_and_emits_replay_compatible_jsonl() {
        let (_directory, mut args, entries) = fixture();
        args.stream.limit = Some(2);
        args.zone = Some("z:work".to_owned());
        args.request_id = Some("a".to_owned());
        let before = std::fs::read(&args.journal).unwrap();
        let mut out = Vec::new();
        let mut err = Vec::new();
        super::super::run(&args, &mut out, &mut err).unwrap();
        assert_eq!(transcript(&out), vec![entries[0].clone(), entries[3].clone()]);
        let explanation = explain_bundle(&parse_replay_bundle(std::str::from_utf8(&out).unwrap()).unwrap()).unwrap();
        assert_eq!(explanation.operation_id, "issues.create");
        let progress = last_progress(&err);
        assert_eq!(progress["emitted_records"], 2);
        assert_eq!(progress["validated_records"], 4);
        assert_eq!(progress["stop_reason"], "record-limit");
        assert_eq!(progress["live"], false);
        assert_eq!(progress["authenticity"], "not-verified");
        assert_eq!(progress["durability"], "not-assessed");
        assert!(!std::str::from_utf8(&out).unwrap().contains("local-invoke-journal-follow"));
        assert_eq!(std::fs::read(&args.journal).unwrap(), before);
    }

    #[test]
    fn partial_appends_wait_and_each_record_is_emitted_once() {
        let (_directory, mut args, entries) = fixture();
        let bytes: Vec<u8> = b"FCPAUD1\n".iter().copied().chain(entries.iter().flat_map(frame)).collect();
        std::fs::write(&args.journal, &bytes[..8]).unwrap();
        let mut writer = OpenOptions::new().append(true).open(&args.journal).unwrap();
        let mut follower = InvokeAuditFollower::open(&args.journal).unwrap();
        args.stream.limit = Some(4);
        args.stream.poll_interval_ms = Some(10);
        args.stream.idle_timeout_ms = Some(100);
        let now = Cell::new(Duration::ZERO);
        let mut waits = 0;
        let mut out = Vec::new();
        run_loop(&args, &mut out, &mut Vec::new(), || follower.poll(), || now.get(), |delay| {
            now.set(now.get() + delay);
            waits += 1;
            match waits {
                1 => writer.write_all(&bytes[8..11]).unwrap(),
                2 => writer.write_all(&bytes[11..bytes.len() - 1]).unwrap(),
                3 => writer.write_all(&bytes[bytes.len() - 1..]).unwrap(),
                _ => panic!("finished stream must not keep waiting"),
            }
            writer.flush().unwrap();
        }).unwrap();
        assert_eq!(waits, 3);
        assert_eq!(transcript(&out), entries);
    }

    #[test]
    fn idle_deadline_stops_a_quiet_stream_without_real_sleeps() {
        let (_directory, mut args, _) = fixture();
        args.stream.idle_timeout_ms = Some(25);
        args.stream.poll_interval_ms = Some(10);
        let now = Cell::new(Duration::ZERO);
        let mut follower = InvokeAuditFollower::open(&args.journal).unwrap();
        let mut waits = Vec::new();
        let mut out = Vec::new();
        let mut diagnostics = Vec::new();
        run_loop(&args, &mut out, &mut diagnostics, || follower.poll(), || now.get(), |delay| {
            waits.push(delay);
            assert!(waits.len() <= 3);
            now.set(now.get() + delay);
        }).unwrap();
        assert_eq!(waits, vec![Duration::from_millis(10), Duration::from_millis(10), Duration::from_millis(5)]);
        assert_eq!(transcript(&out).len(), 4);
        assert_eq!(last_progress(&diagnostics)["stop_reason"], "idle-timeout");
    }

    #[test]
    fn an_unfinished_tail_at_idle_deadline_is_not_a_successful_export() {
        let (_directory, mut args, _) = fixture();
        let mut writer = OpenOptions::new().append(true).open(&args.journal).unwrap();
        writer.write_all(&100_u32.to_le_bytes()).unwrap();
        writer.write_all(b"partial-sensitive-data").unwrap();
        writer.flush().unwrap();
        let before = std::fs::read(&args.journal).unwrap();
        args.stream.idle_timeout_ms = Some(1);
        let now = Cell::new(Duration::ZERO);
        let mut follower = InvokeAuditFollower::open(&args.journal).unwrap();
        let mut out = Vec::new();
        let mut diagnostics = Vec::new();
        let error = run_loop(&args, &mut out, &mut diagnostics, || follower.poll(), || now.get(), |delay| {
            now.set(now.get() + delay);
        }).unwrap_err();
        assert!(matches!(error, ExportError::FollowIncomplete));
        assert_eq!(transcript(&out).len(), 4);
        assert_eq!(last_progress(&diagnostics)["pending_frame"], true);
        assert!(!error.message().contains("sensitive"));
        assert_eq!(std::fs::read(&args.journal).unwrap(), before);
    }

    #[test]
    fn idle_without_a_matching_request_does_not_substitute_other_records() {
        let (_directory, mut args, _) = fixture();
        args.zone = Some("z:work".to_owned());
        args.request_id = Some("not-yet-observed".to_owned());
        args.stream.idle_timeout_ms = Some(1);
        let now = Cell::new(Duration::ZERO);
        let mut follower = InvokeAuditFollower::open(&args.journal).unwrap();
        let mut out = Vec::new();
        let error = run_loop(&args, &mut out, &mut Vec::new(), || follower.poll(), || now.get(), |delay| {
            now.set(now.get() + delay);
        }).unwrap_err();
        assert!(matches!(error, ExportError::FollowNoMatch));
        assert!(out.is_empty());
    }

    #[test]
    fn bad_record_in_an_unselected_zone_stops_before_current_batch_output() {
        let (_directory, mut args, mut entries) = fixture();
        args.zone = Some("z:work".to_owned());
        args.stream.limit = Some(1);
        entries[2].actor = "secret-corrupt-actor".to_owned();
        let mut bytes = b"FCPAUD1\n".to_vec();
        for entry in entries { bytes.extend_from_slice(&frame(&entry)); }
        std::fs::write(&args.journal, bytes).unwrap();
        let mut out = Vec::new();
        let error = run(&args, &mut out, &mut Vec::new()).unwrap_err();
        assert!(matches!(error, ExportError::Follow(InvokeAuditSnapshotError::InvalidRecord { .. })));
        assert!(out.is_empty());
        assert!(!error.message().contains("secret-corrupt"));
    }

    #[test]
    fn output_and_provenance_failures_stop_following() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> { Err(std::io::ErrorKind::BrokenPipe.into()) }
            fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
        }
        let (_directory, mut args, _) = fixture();
        args.stream.limit = Some(1);
        assert!(matches!(run(&args, &mut Broken, &mut Vec::new()), Err(ExportError::Output)));
        let mut out = Vec::new();
        assert!(matches!(run(&args, &mut out, &mut Broken), Err(ExportError::Output)));
        assert!(out.is_empty());
    }

    #[test]
    fn unread_backlog_does_not_sleep_between_bounded_batches() {
        let (_directory, mut args, _) = fixture();
        let chain = InvokeAuditChain::open_with_journal(&args.journal).unwrap();
        for _ in 0..260 { chain.append(&context("z:work", "other"), InvokePhase::PreflightAllow).unwrap(); }
        drop(chain);
        args.stream.limit = Some(264);
        let mut follower = InvokeAuditFollower::open(&args.journal).unwrap();
        let mut out = Vec::new();
        run_loop(&args, &mut out, &mut Vec::new(), || follower.poll(), || Duration::ZERO,
            |_| panic!("ready backlog must drain without a polling sleep")).unwrap();
        assert_eq!(transcript(&out).len(), 264);
    }

    #[test]
    fn invalid_follow_flags_fail_before_opening_the_source() {
        let (_directory, mut args, _) = fixture();
        args.journal = "missing-source-must-not-be-opened".into();
        for format in [Format::Bundle, Format::Explanation] {
            args.format = format;
            assert!(matches!(run(&args, &mut Vec::new(), &mut Vec::new()), Err(ExportError::Usage)));
        }
        args.format = Format::Jsonl;
        for interval in [0, 60_001, u64::MAX] {
            args.stream.poll_interval_ms = Some(interval);
            assert!(matches!(validate_selection(&args), Err(ExportError::Usage)));
        }
        args.stream.poll_interval_ms = None;
        args.stream.limit = Some(0);
        assert!(matches!(validate_selection(&args), Err(ExportError::Usage)));
        args.stream.limit = None;
        args.stream.idle_timeout_ms = Some(0);
        assert!(matches!(validate_selection(&args), Err(ExportError::Usage)));
    }

    #[test]
    fn cli_requires_explicit_follow_for_stream_only_options() {
        for flag in ["--limit", "--poll-interval-ms", "--idle-timeout-ms"] {
            assert!(Args::try_parse_from(["fwc-audit-export", "--journal", "file", flag, "1"]).is_err());
        }
        let args = Args::try_parse_from([
            "fwc-audit-export", "--journal", "file", "--follow", "--format", "jsonl",
            "--limit", "20", "--idle-timeout-ms", "2000", "--poll-interval-ms", "100",
        ]).unwrap();
        assert!(validate_selection(&args).is_ok());
    }

    #[test]
    fn from_sequence_remains_inclusive_while_all_earlier_lineage_is_checked() {
        let (_directory, mut args, entries) = fixture();
        args.zone = Some("z:work".to_owned());
        args.from_seq = Some(1);
        args.stream.limit = Some(2);
        let mut out = Vec::new();
        let mut diagnostics = Vec::new();
        run(&args, &mut out, &mut diagnostics).unwrap();
        assert_eq!(transcript(&out), vec![entries[1].clone(), entries[3].clone()]);
        assert_eq!(last_progress(&diagnostics)["validated_records"], 4);
    }

    #[test]
    fn follow_does_not_create_missing_sources() {
        let (_directory, mut args, _) = fixture();
        args.journal = args.journal.with_file_name("missing");
        let error = run(&args, &mut Vec::new(), &mut Vec::new()).unwrap_err();
        assert!(matches!(error, ExportError::Follow(_)));
        assert!(!args.journal.exists());
    }
}
