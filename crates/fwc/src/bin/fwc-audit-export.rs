//! Export actual retained host journal records without opening writer recovery.
//! The JSON/JSONL shapes feed the existing `fwc audit explain` artifact path.

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use fcp_audit::AuditEntry;
use fcp_audit::explain::{CausalExplanation, ReplayBundle};
use fcp_audit::explain::host::explain_host_request;
use fcp_host::{InvokeAuditSnapshotError, read_invoke_audit_snapshot};
use serde::Serialize;

const SCHEMA: &str = "fcp.fwc.invoke_audit_export.v1";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
enum Format {
    /// Replay bundle with explicit snapshot provenance.
    #[default]
    Bundle,
    /// One captured AuditEntry per line; provenance goes to standard error.
    Jsonl,
    /// Explain one explicitly selected zone and server request as JSON.
    Explanation,
}

#[derive(Debug, Parser)]
#[command(name = "fwc-audit-export", version, about = "Read-only export of a retained host invoke journal")]
#[command(after_help = "This is a local file snapshot, not a live host RPC or authenticated checkpoint.\nThe journal is never repaired or modified. An incomplete sampled frame fails without output.\nDo not redirect output onto the source journal. Captured records may contain sensitive identities.")]
struct Args {
    /// Existing regular FCPAUD1 journal file; never created by this command.
    #[arg(long)]
    journal: PathBuf,
    /// Export one zone, after verifying the entire sampled journal.
    #[arg(long)]
    zone: Option<String>,
    /// Exact server-assigned request ID, not the client correlation or method.
    #[arg(long, requires = "zone")]
    request_id: Option<String>,
    /// Inclusive per-zone sequence lower bound; output may omit causal history.
    #[arg(long, requires = "zone")]
    from_seq: Option<u64>,
    /// Explanation requires --zone and --request-id, without --from-seq.
    #[arg(long, value_enum, default_value_t = Format::Bundle)]
    format: Format,
}

#[derive(Debug)]
enum ExportError {
    Usage,
    Snapshot(InvokeAuditSnapshotError),
    NoMatchingRecords,
    Explanation,
    Output,
}

impl ExportError {
    const fn code(&self) -> &'static str {
        match self {
            Self::Usage => "audit.export.invalid_selection",
            Self::Snapshot(error) => error.code(),
            Self::NoMatchingRecords => "audit.export.no_matching_records",
            Self::Explanation => "audit.export.unusable_explanation",
            Self::Output => "audit.export.output_failed",
        }
    }

    const fn message(&self) -> &'static str {
        match self {
            Self::Usage => "selection is invalid; request/sequence filters need a zone and explanations need one complete request",
            Self::Snapshot(_) => "the full sampled journal could not be validated; no export was emitted",
            Self::NoMatchingRecords => "no records in the sampled journal match the explicit selection",
            Self::Explanation => "the selected captured request cannot be explained consistently",
            Self::Output => "output could not be completed; discard any partial export",
        }
    }
}

#[derive(Debug, Serialize)]
struct Source {
    kind: &'static str,
    live: bool,
    integrity: &'static str,
    authenticity: &'static str,
    durability: &'static str,
    snapshot_bytes: u64,
    snapshot_digest: String,
    snapshot_records: usize,
    selected_records: usize,
    filtered: bool,
}

#[derive(Debug, Serialize)]
struct Selection<'a> {
    zone_id: Option<&'a str>,
    request_id: Option<&'a str>,
    from_seq: Option<u64>,
}

struct PreparedExport {
    source: Source,
    entries: Vec<AuditEntry>,
    explanation: Option<CausalExplanation>,
}

fn validate_selection(args: &Args) -> Result<(), ExportError> {
    let invalid_identity = |value: &str| {
        value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control)
    };
    if args.zone.as_deref().is_some_and(invalid_identity)
        || args.request_id.as_deref().is_some_and(invalid_identity)
        || ((args.request_id.is_some() || args.from_seq.is_some()) && args.zone.is_none())
        || (args.format == Format::Explanation
            && (args.zone.is_none() || args.request_id.is_none() || args.from_seq.is_some()))
    {
        return Err(ExportError::Usage);
    }
    Ok(())
}

fn prepare(args: &Args) -> Result<PreparedExport, ExportError> {
    // Selection mistakes must fail before opening even an unreadable source.
    validate_selection(args)?;
    let snapshot = read_invoke_audit_snapshot(&args.journal).map_err(ExportError::Snapshot)?;
    let mut source = Source {
        kind: "local-invoke-journal-snapshot",
        live: false,
        integrity: "canonical-ids-and-per-zone-lineage",
        authenticity: "not-verified",
        durability: "not-assessed",
        snapshot_bytes: snapshot.bytes(),
        snapshot_digest: snapshot.digest().to_owned(),
        snapshot_records: snapshot.entries().len(),
        selected_records: 0,
        filtered: args.zone.is_some() || args.request_id.is_some() || args.from_seq.is_some(),
    };
    let entries: Vec<_> = snapshot.into_entries().into_iter().filter(|entry| {
        args.zone.as_deref().is_none_or(|zone| entry.zone_id == zone)
            && args.request_id.as_deref().is_none_or(|id| entry.operation_id.as_deref() == Some(id))
            && args.from_seq.is_none_or(|seq| entry.seq >= seq)
    }).collect();
    source.selected_records = entries.len();
    if source.filtered && entries.is_empty() {
        return Err(ExportError::NoMatchingRecords);
    }
    // Move the records, rather than cloning an entire retained journal.
    let bundle = ReplayBundle { audit_entries: entries, ..ReplayBundle::default() };
    let explanation = if args.format == Format::Explanation {
        let zone = args.zone.as_deref().ok_or(ExportError::Usage)?;
        let request = args.request_id.as_deref().ok_or(ExportError::Usage)?;
        Some(explain_host_request(&bundle, zone, request).map_err(|_| ExportError::Explanation)?)
    } else {
        None
    };
    Ok(PreparedExport { source, entries: bundle.audit_entries, explanation })
}

#[derive(Serialize)]
struct BundleOutput<'a> {
    schema_version: &'static str,
    source: &'a Source,
    selection: Selection<'a>,
    audit_entries: &'a [AuditEntry],
}

#[derive(Serialize)]
struct ExplanationOutput<'a> {
    schema_version: &'static str,
    source: &'a Source,
    selection: Selection<'a>,
    explanation: &'a CausalExplanation,
}

fn selection(args: &Args) -> Selection<'_> {
    Selection {
        zone_id: args.zone.as_deref(),
        request_id: args.request_id.as_deref(),
        from_seq: args.from_seq,
    }
}

fn json_line(output: &mut impl Write, value: &impl Serialize) -> Result<(), ExportError> {
    serde_json::to_writer(&mut *output, value).map_err(|_| ExportError::Output)?;
    output.write_all(b"\n").map_err(|_| ExportError::Output)
}

fn run(args: &Args, output: &mut impl Write, diagnostics: &mut impl Write) -> Result<(), ExportError> {
    // Complete source validation and explanation precede all output. A corrupt
    // record in a filtered-out zone cannot be hidden behind a successful prefix.
    let prepared = prepare(args)?;
    match args.format {
        Format::Bundle => json_line(output, &BundleOutput {
            schema_version: SCHEMA,
            source: &prepared.source,
            selection: selection(args),
            audit_entries: &prepared.entries,
        })?,
        Format::Jsonl => {
            json_line(diagnostics, &prepared.source)?;
            diagnostics.flush().map_err(|_| ExportError::Output)?;
            for entry in &prepared.entries {
                json_line(output, entry)?;
            }
        }
        Format::Explanation => {
            let explanation = prepared.explanation.as_ref().ok_or(ExportError::Explanation)?;
            json_line(output, &ExplanationOutput {
                schema_version: SCHEMA,
                source: &prepared.source,
                selection: selection(args),
                explanation,
            })?;
        }
    }
    output.flush().map_err(|_| ExportError::Output)
}

fn main() -> ExitCode {
    let args = Args::parse();
    let result = {
        let mut output = io::BufWriter::new(io::stdout().lock());
        let mut diagnostics = io::stderr().lock();
        run(&args, &mut output, &mut diagnostics)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Neither parser diagnostics nor local filenames cross this boundary.
            eprintln!("{}: {}", error.code(), error.message());
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_audit::explain::host::HostRequestOutcome;
    use fcp_audit::explain::{explain_bundle, parse_replay_bundle};
    use fcp_host::{InvokeAuditChain, InvokeAuditContext, InvokePhase};
    use serde_json::Value;

    fn context(zone: &str, request: &str) -> InvokeAuditContext {
        InvokeAuditContext {
            zone_id: zone.to_owned(), actor: "agent:export-test".to_owned(),
            connector_id: "github".to_owned(), operation: "issues.create".to_owned(),
            operation_id: request.to_owned(), correlation_id: Some("shared-client-correlation".to_owned()),
            occurred_at: 1_700_000_000,
        }
    }

    fn fixture() -> (tempfile::TempDir, Args) {
        let directory = tempfile::tempdir().unwrap();
        let journal = directory.path().join("retained.journal");
        let writer = InvokeAuditChain::open_with_journal(&journal).unwrap();
        writer.append(&context("z:work", "a"), InvokePhase::PreflightAllow).unwrap();
        writer.append(&context("z:work", "b"), InvokePhase::PreflightDeny {
            reason: "untrusted-provider-secret".to_owned(),
        }).unwrap();
        writer.append(&context("z:private", "a"), InvokePhase::PreflightAllow).unwrap();
        writer.append(&context("z:work", "a"), InvokePhase::DispatchResult {
            receipt_id: None, success: true, duration_ms: 12,
        }).unwrap();
        drop(writer);
        (directory, Args { journal, zone: None, request_id: None, from_seq: None, format: Format::Bundle })
    }

    fn output(args: &Args) -> (String, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        run(args, &mut out, &mut err).unwrap();
        (String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
    }

    #[test]
    fn bundle_round_trips_through_existing_replay_parser_with_honest_provenance() {
        let (_directory, args) = fixture();
        let before = std::fs::read(&args.journal).unwrap();
        let (text, err) = output(&args);
        let bundle = parse_replay_bundle(&text).unwrap();
        assert_eq!(bundle.audit_entries.len(), 4);
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["source"]["live"], false);
        assert_eq!(value["source"]["authenticity"], "not-verified");
        assert_eq!(value["source"]["durability"], "not-assessed");
        assert_eq!(value["source"]["snapshot_records"], 4);
        assert_eq!(value["source"]["selected_records"], 4);
        assert_eq!(value["source"]["filtered"], false);
        assert_eq!(std::fs::read(&args.journal).unwrap(), before);
        assert!(err.is_empty());
        assert!(!text.contains("untrusted-provider-secret"));
    }

    #[test]
    fn request_selection_does_not_borrow_shared_correlations_or_other_zones() {
        let (_directory, mut args) = fixture();
        args.zone = Some("z:work".to_owned());
        args.request_id = Some("a".to_owned());
        let (text, _) = output(&args);
        let bundle = parse_replay_bundle(&text).unwrap();
        assert_eq!(bundle.audit_entries.len(), 2);
        assert!(bundle.audit_entries.iter().all(|entry| entry.zone_id == "z:work" && entry.operation_id.as_deref() == Some("a")));
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["source"]["filtered"], true);
        assert_eq!(value["source"]["snapshot_records"], 4);
        assert_eq!(value["source"]["selected_records"], 2);
        assert!(!text.contains("z:private"));
    }

    #[test]
    fn jsonl_contains_only_entries_and_can_be_explained_without_intermediate_conversion() {
        let (_directory, mut args) = fixture();
        args.zone = Some("z:work".to_owned());
        args.request_id = Some("a".to_owned());
        args.format = Format::Jsonl;
        let (text, diagnostic) = output(&args);
        assert_eq!(text.lines().count(), 2);
        let bundle = parse_replay_bundle(&text).unwrap();
        let explanation = explain_bundle(&bundle).unwrap();
        assert_eq!(explanation.operation_id, "issues.create");
        assert!(explanation.host_request.is_some());
        let source: Value = serde_json::from_str(&diagnostic).unwrap();
        assert_eq!(source["authenticity"], "not-verified");
        assert!(!text.contains("local-invoke-journal-snapshot"));
    }

    #[test]
    fn direct_explanation_keeps_a_denied_request_distinct_from_success() {
        let (_directory, mut args) = fixture();
        args.zone = Some("z:work".to_owned());
        args.request_id = Some("b".to_owned());
        args.format = Format::Explanation;
        let (text, _) = output(&args);
        let value: Value = serde_json::from_str(&text).unwrap();
        let explanation: CausalExplanation = serde_json::from_value(value["explanation"].clone()).unwrap();
        assert_eq!(explanation.operation_id, "issues.create");
        assert_eq!(explanation.host_request.unwrap().outcome, HostRequestOutcome::Denied);
        assert!(!text.contains("untrusted-provider-secret"));
    }

    #[test]
    fn contradictory_real_host_phases_refuse_explanation_before_output() {
        let (_directory, mut args) = fixture();
        let writer = InvokeAuditChain::open_with_journal(&args.journal).unwrap();
        writer.append(&context("z:work", "a"), InvokePhase::PreflightDeny {
            reason: "preflight_denied".to_owned(),
        }).unwrap();
        drop(writer);
        args.zone = Some("z:work".to_owned());
        args.request_id = Some("a".to_owned());
        args.format = Format::Explanation;
        let mut out = Vec::new();
        assert!(matches!(run(&args, &mut out, &mut Vec::new()), Err(ExportError::Explanation)));
        assert!(out.is_empty());
    }

    #[test]
    fn an_initialized_empty_journal_is_not_a_missing_source() {
        let directory = tempfile::tempdir().unwrap();
        let journal = directory.path().join("empty.journal");
        drop(InvokeAuditChain::open_with_journal(&journal).unwrap());
        let args = Args { journal, zone: None, request_id: None, from_seq: None, format: Format::Bundle };
        let (text, _) = output(&args);
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["source"]["snapshot_records"], 0);
        assert!(parse_replay_bundle(&text).unwrap().audit_entries.is_empty());
    }

    #[test]
    fn sequence_filter_is_inclusive_and_marks_output_as_partial_selection() {
        let (_directory, mut args) = fixture();
        args.zone = Some("z:work".to_owned());
        args.from_seq = Some(1);
        let (text, _) = output(&args);
        let bundle = parse_replay_bundle(&text).unwrap();
        assert_eq!(bundle.audit_entries.iter().map(|entry| entry.seq).collect::<Vec<_>>(), vec![1, 2]);
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["source"]["filtered"], true);
        assert_eq!(value["selection"]["from_seq"], 1);
    }

    #[test]
    fn malformed_filtered_out_tail_refuses_before_any_output() {
        let (_directory, mut args) = fixture();
        args.zone = Some("z:work".to_owned());
        args.request_id = Some("a".to_owned());
        let mut file = std::fs::OpenOptions::new().append(true).open(&args.journal).unwrap();
        file.write_all(&100u32.to_le_bytes()).unwrap();
        file.write_all(b"sensitive-incomplete-payload").unwrap();
        drop(file);
        for format in [Format::Bundle, Format::Jsonl, Format::Explanation] {
            args.format = format;
            let mut out = Vec::new();
            let mut err = Vec::new();
            let error = run(&args, &mut out, &mut err).unwrap_err();
            assert!(matches!(error, ExportError::Snapshot(_)));
            assert!(out.is_empty());
            assert!(err.is_empty());
            assert!(!error.message().contains("sensitive"));
        }
    }

    #[test]
    fn missing_selected_request_is_not_an_empty_success_or_another_request() {
        let (_directory, mut args) = fixture();
        args.zone = Some("z:work".to_owned());
        args.request_id = Some("missing".to_owned());
        let mut out = Vec::new();
        assert!(matches!(run(&args, &mut out, &mut Vec::new()), Err(ExportError::NoMatchingRecords)));
        assert!(out.is_empty());
    }

    #[test]
    fn selection_errors_precede_source_access() {
        let (_directory, mut args) = fixture();
        args.journal = PathBuf::from("/nonexistent/source-secret");
        args.format = Format::Explanation;
        assert!(matches!(prepare(&args), Err(ExportError::Usage)));
        args.zone = Some("z:work".to_owned());
        args.request_id = Some("a".to_owned());
        args.from_seq = Some(1);
        assert!(matches!(prepare(&args), Err(ExportError::Usage)));
        args.from_seq = None;
        args.request_id = Some("\n".to_owned());
        assert!(matches!(prepare(&args), Err(ExportError::Usage)));
    }

    #[test]
    fn output_errors_are_failures_not_successful_exports() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> { Err(io::Error::from(io::ErrorKind::BrokenPipe)) }
            fn flush(&mut self) -> io::Result<()> { Ok(()) }
        }
        let (_directory, mut args) = fixture();
        assert!(matches!(run(&args, &mut Broken, &mut Vec::new()), Err(ExportError::Output)));
        args.format = Format::Jsonl;
        let mut out = Vec::new();
        assert!(matches!(run(&args, &mut out, &mut Broken), Err(ExportError::Output)));
        assert!(out.is_empty());
    }

    #[test]
    fn cli_rejects_ambiguous_selection_and_accepts_documented_invocation() {
        assert!(Args::try_parse_from(["fwc-audit-export", "--journal", "file", "--request-id", "a"]).is_err());
        assert!(Args::try_parse_from(["fwc-audit-export", "--journal", "file", "--from-seq", "1"]).is_err());
        let args = Args::try_parse_from([
            "fwc-audit-export", "--journal", "file", "--zone", "z:work",
            "--request-id", "a", "--format", "explanation",
        ]).unwrap();
        assert!(validate_selection(&args).is_ok());
    }
}
