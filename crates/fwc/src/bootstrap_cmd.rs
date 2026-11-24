//! Mesh creation and verified cold recovery through the real bootstrap workflow.
//!
//! Recovery words and PINs never enter argv, command envelopes, or files written
//! by this module. Fresh words are confirmed on an attended terminal before the
//! workflow can publish genesis. Automation can import an existing phrase over
//! explicitly selected, bounded stdin.

use std::fs::File;
use std::io::{self, IsTerminal, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use clap::Args;
use console::Term;
use fcp_bootstrap::{
    BootstrapConfig, BootstrapMode, BootstrapWorkflow, ColdRecovery, DetectedToken, GenesisState,
    HardwareTokenEnrollment, HardwareTokenPin, RecoveryPhrase, TokenDetectionReport, TokenDetector,
};
use serde::Serialize;
use serde_json::{Value, json};
use zeroize::Zeroizing;

const MAX_SECRET_BYTES: u64 = 1024;
const MAX_GENESIS_BYTES: u64 = 1024 * 1024;

/// Options shared by creation and recovery. Replacement is deliberately absent:
/// an existing mesh must never be erased by a retry of initialization.
#[derive(Args, Debug, Serialize)]
pub struct RunArgs {
    /// Directory in which to create genesis.cbor.
    #[arg(long, value_name = "DIRECTORY")]
    pub data_dir: PathBuf,

    /// Resume a library-supported partial bootstrap phase in this directory.
    #[arg(long)]
    pub resume: bool,

    /// Skip bootstrap clock validation, for explicitly offline operation.
    #[arg(long)]
    pub skip_time_validation: bool,

    /// Permit a clock drift warning; excessive drift is still refused.
    #[arg(long)]
    pub allow_drift: bool,
}

#[derive(Args, Debug, Serialize)]
pub struct InitArgs {
    #[command(flatten)]
    pub run: RunArgs,
}

#[derive(Args, Debug, Serialize)]
pub struct RecoverArgs {
    #[command(flatten)]
    pub run: RunArgs,

    /// Previously saved BLAKE3 genesis fingerprint; checked before any write.
    #[arg(long, value_name = "FINGERPRINT")]
    pub expected_fingerprint: String,

    /// Read the existing 24 words from piped stdin instead of a secure prompt.
    #[arg(long)]
    pub phrase_stdin: bool,
}

#[derive(Args, Debug, Serialize)]
pub struct StatusArgs {
    /// Directory containing genesis.cbor, or an incomplete bootstrap.
    #[arg(long, value_name = "DIRECTORY")]
    pub data_dir: PathBuf,
}

#[derive(Args, Debug, Serialize)]
pub struct TokensArgs {
    /// Probe only this PKCS#11 library instead of the platform defaults.
    #[arg(long, value_name = "LIBRARY")]
    pub provider: Option<PathBuf>,
}

#[derive(Args, Debug, Serialize)]
pub struct EnrollTokenArgs {
    #[command(flatten)]
    pub run: RunArgs,

    /// Exact PKCS#11 provider library containing the selected token.
    #[arg(long, value_name = "LIBRARY")]
    pub provider: PathBuf,

    /// Slot reported by bootstrap tokens for this provider.
    #[arg(long)]
    pub slot: u32,

    /// Read the PIN from a pipe instead of the hidden terminal prompt.
    #[arg(long)]
    pub pin_stdin: bool,
}

/// Discover public token identities and report provider failures without logging in.
pub fn tokens(args: &TokensArgs) -> Result<Value> {
    let detector = args.provider.as_ref().map_or_else(
        TokenDetector::new,
        |provider| TokenDetector::from_provider_paths(vec![provider.clone()]),
    );
    let report = detector.detect_report();
    Ok(json!({
        "command": "bootstrap tokens",
        "status": "inspected",
        "discovery": report,
    }))
}

/// Complete real proof-of-possession enrollment of a selected hardware token.
pub fn enroll_token(args: &EnrollTokenArgs) -> Result<Value> {
    let report = TokenDetector::from_provider_paths(vec![args.provider.clone()]).detect_report();
    let token = select_token(&report, &args.provider, args.slot)?;
    let input = read_secret(args.pin_stdin, "Enter the selected hardware token's PIN:")?;
    let pin = pin_from_input(&input)?;
    let mut config = BootstrapConfig::builder()
        .data_dir(&args.run.data_dir)
        .mode(BootstrapMode::HardwareToken { token })
        .skip_time_validation(args.run.skip_time_validation)
        .allow_time_drift_warning(args.run.allow_drift)
        .build()?;
    config.hardware_token_pin = Some(pin);
    let workflow = if args.run.resume {
        BootstrapWorkflow::resume(config)
    } else {
        BootstrapWorkflow::new(config)
    }.context("cannot enroll a hardware token in this directory")?;
    let outcome = workflow.run().context("hardware-token enrollment failed")?;
    let enrollment = outcome.hardware_token.as_ref()
        .context("hardware-token bootstrap returned no verified signer enrollment")?;
    enrollment.validate_for_genesis(&outcome.genesis)?;
    let mut output = genesis_output(
        "bootstrap enroll-token", "enrolled", &args.run.data_dir, &outcome.genesis,
    );
    output["signer"] = signer_output(&args.run.data_dir, &outcome.genesis)?;
    Ok(output)
}

fn select_token(
    report: &TokenDetectionReport,
    provider: &Path,
    slot: u32,
) -> Result<DetectedToken> {
    let mut selected = report.providers.iter()
        .flat_map(|provider| &provider.tokens)
        .filter(|token| token.provider.as_path() == provider && token.slot == slot);
    let token = selected.next().context(
        "the requested token was not discovered; inspect bootstrap tokens for provider failures",
    )?;
    ensure!(selected.next().is_none(), "token selection is ambiguous");
    ensure!(
        token.supports_ed25519(),
        "the selected token does not advertise Ed25519 signing support"
    );
    Ok(token.clone())
}

fn pin_from_input(input: &str) -> Result<HardwareTokenPin> {
    validate_secret(input)?;
    // A pipe commonly terminates its single PIN with CRLF. Whitespace within
    // the PIN remains meaningful; do not trim it into a different credential.
    let value = input.trim_end_matches(&['\r', '\n'][..]);
    ensure!(
        !value.is_empty() && !value.contains('\r') && !value.contains('\n'),
        "PIN input must contain exactly one nonempty line"
    );
    Ok(HardwareTokenPin::new(value))
}

fn signer_output(data_dir: &Path, genesis: &GenesisState) -> Result<Value> {
    Ok(json!({
        "kind": "pkcs11",
        "algorithm": "Ed25519",
        "enrollment_path": HardwareTokenEnrollment::path_for_genesis(data_dir, genesis)?,
        "proof_of_possession_verified": true,
    }))
}

/// Create a new phrase-backed mesh, delivering the recovery material first.
pub fn init(args: &InitArgs) -> Result<Value> {
    let terminal = attended_terminal()?;
    init_with_confirmation(&args.run, |phrase| {
        terminal.write_line(
            "Write these 24 recovery words down and keep them offline. They control the mesh owner key.",
        )?;
        let words = Zeroizing::new(phrase.to_phrase());
        terminal.write_line(&words)?;
        terminal.write_line(
            "Re-enter all 24 words to confirm your copy. Input is hidden; genesis is not saved until it matches.",
        )?;
        let confirmation = Zeroizing::new(
            terminal
                .read_secure_line()
                .context("could not read the recovery confirmation")?,
        );
        verify_confirmation(phrase, &confirmation)
    })
}

fn init_with_confirmation(
    args: &RunArgs,
    confirm: impl FnOnce(&RecoveryPhrase) -> Result<()>,
) -> Result<Value> {
    let phrase = RecoveryPhrase::generate().context("could not generate recovery words")?;
    // Import the exact phrase we deliver. Generating a second phrase inside
    // SingleDevice after confirmation would produce a different owner.
    // Reserve the directory before showing any recovery material.
    let workflow = prepare_workflow(args, BootstrapMode::Import { phrase: phrase.clone() })?;
    confirm(&phrase)?;
    let outcome = workflow.run().context("mesh initialization failed")?;
    ensure!(
        outcome.recovery_phrase.is_none(),
        "import unexpectedly generated different recovery material"
    );
    Ok(genesis_output("bootstrap init", "created", &args.data_dir, &outcome.genesis))
}

fn verify_confirmation(expected: &RecoveryPhrase, input: &str) -> Result<()> {
    ensure!(
        input.len() as u64 <= MAX_SECRET_BYTES,
        "recovery confirmation exceeds the input limit"
    );
    let confirmed = RecoveryPhrase::from_mnemonic(input.trim())
        .context("recovery confirmation is not a valid 24-word phrase")?;
    ensure!(
        confirmed == *expected,
        "recovery confirmation does not match; no genesis was written"
    );
    Ok(())
}

/// Recover a phrase-backed identity only after matching its saved fingerprint.
pub fn recover(args: &RecoverArgs) -> Result<Value> {
    let secret = read_secret(args.phrase_stdin, "Enter the existing 24 recovery words:")?;
    recover_with_input(args, &secret)
}

fn recover_with_input(args: &RecoverArgs, input: &str) -> Result<Value> {
    ensure!(
        input.len() as u64 <= MAX_SECRET_BYTES,
        "recovery input exceeds the input limit"
    );
    ensure!(
        !args.expected_fingerprint.trim().is_empty(),
        "a saved genesis fingerprint is required"
    );
    let phrase = RecoveryPhrase::from_mnemonic(input.trim())
        .context("input is not a valid 24-word recovery phrase")?;
    // This comparison intentionally precedes directory creation or acquiring
    // the workflow lease. A valid but wrong phrase must not mutate the target.
    let recovered = ColdRecovery::from_phrase(&phrase, Some(&args.expected_fingerprint))
        .context("recovery phrase does not reproduce the expected mesh identity")?;
    let warnings: Vec<String> = recovered.warnings.iter().map(ToString::to_string).collect();
    let expected = recovered.genesis.to_cbor()?;
    drop(recovered);

    let outcome = prepare_workflow(&args.run, BootstrapMode::Import { phrase })?
        .run()
        .context("mesh recovery failed")?;
    ensure!(
        outcome.genesis.to_cbor()? == expected,
        "recovery workflow produced an unexpected genesis"
    );
    let mut output = genesis_output(
        "bootstrap recover",
        "recovered",
        &args.run.data_dir,
        &outcome.genesis,
    );
    output["fingerprint_verified"] = json!(true);
    output["warnings"] = json!(warnings);
    Ok(output)
}

fn prepare_workflow(args: &RunArgs, mode: BootstrapMode) -> Result<BootstrapWorkflow> {
    let config = BootstrapConfig::builder()
        .data_dir(&args.data_dir)
        .mode(mode)
        .skip_time_validation(args.skip_time_validation)
        .allow_time_drift_warning(args.allow_drift)
        .build()?;
    if args.resume {
        BootstrapWorkflow::resume(config).context("cannot resume bootstrap in this directory")
    } else {
        BootstrapWorkflow::new(config).context("cannot initialize this directory")
    }
}

/// Inspect saved public identity without creating directories, leases, or keys.
pub fn status(args: &StatusArgs) -> Result<Value> {
    let path = args.data_dir.join("genesis.cbor");
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let phase = fcp_bootstrap::phase::detect_partial_state(&args.data_dir);
            return Ok(json!({
                "command": "bootstrap status",
                "status": if phase.is_some() { "partial" } else { "uninitialized" },
                "data_dir": args.data_dir,
                "phase": phase,
            }));
        }
        Err(error) => return Err(error).context("cannot inspect genesis"),
    };
    ensure!(
        metadata.file_type().is_file(),
        "genesis.cbor must be a regular file, not a symlink or directory"
    );
    ensure!(metadata.len() <= MAX_GENESIS_BYTES, "genesis exceeds the input limit");
    let mut bytes = Vec::new();
    File::open(&path)?
        .take(MAX_GENESIS_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("cannot read genesis")?;
    ensure!(bytes.len() as u64 <= MAX_GENESIS_BYTES, "genesis exceeds the input limit");
    let genesis = GenesisState::from_cbor(&bytes).context("saved genesis is malformed")?;
    genesis.validate().context("saved genesis is invalid")?;
    let mut output = genesis_output("bootstrap status", "initialized", &args.data_dir, &genesis);
    if HardwareTokenEnrollment::load(&args.data_dir, &genesis)?.is_some() {
        output["signer"] = signer_output(&args.data_dir, &genesis)?;
    }
    Ok(output)
}

fn genesis_output(command: &str, status: &str, data_dir: &Path, genesis: &GenesisState) -> Value {
    let zones: Vec<&str> = genesis.initial_zones.iter().map(|zone| zone.zone_id.as_str()).collect();
    json!({
        "command": command,
        "status": status,
        "data_dir": data_dir,
        "genesis_path": data_dir.join("genesis.cbor"),
        "fingerprint": genesis.fingerprint(),
        "owner_public_key_hex": hex::encode(genesis.owner_public_key),
        "schema_version": genesis.schema_version,
        "zones": zones,
        "secret_material_written": false,
    })
}

fn attended_terminal() -> Result<Term> {
    ensure!(
        io::stdin().is_terminal() && io::stderr().is_terminal(),
        "interactive bootstrap requires terminal stdin and stderr; use recover --phrase-stdin with an existing phrase for automation"
    );
    let terminal = Term::stderr();
    ensure!(terminal.is_term(), "an attended terminal is required");
    Ok(terminal)
}

fn read_secret(from_stdin: bool, prompt: &str) -> Result<Zeroizing<String>> {
    if from_stdin {
        ensure!(
            !io::stdin().is_terminal(),
            "secret stdin must be a pipe; omit the stdin flag for hidden terminal input"
        );
        read_bounded_secret(io::stdin().lock())
    } else {
        let terminal = attended_terminal()?;
        terminal.write_line(prompt)?;
        let secret = Zeroizing::new(terminal.read_secure_line().context("cannot read secret input")?);
        validate_secret(&secret)?;
        Ok(secret)
    }
}

fn read_bounded_secret(reader: impl Read) -> Result<Zeroizing<String>> {
    let mut secret = Zeroizing::new(String::new());
    reader
        .take(MAX_SECRET_BYTES + 1)
        .read_to_string(&mut secret)
        .context("cannot read secret input")?;
    validate_secret(&secret)?;
    Ok(secret)
}

fn validate_secret(secret: &str) -> Result<()> {
    ensure!(secret.len() as u64 <= MAX_SECRET_BYTES, "secret input exceeds the input limit");
    ensure!(!secret.trim().is_empty(), "secret input is empty");
    ensure!(
        !secret.bytes().any(|byte| byte == 0),
        "secret input contains a NUL byte"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn run_args(path: &Path) -> RunArgs {
        RunArgs {
            data_dir: path.to_path_buf(),
            resume: false,
            skip_time_validation: true,
            allow_drift: false,
        }
    }

    fn detected_token(provider: &Path, slot: u32) -> DetectedToken {
        DetectedToken {
            provider: provider.to_path_buf(),
            slot,
            label: "owner token".to_owned(),
            manufacturer: "test provider".to_owned(),
            serial: "stable-serial".to_owned(),
            mechanisms: vec!["CKM_EDDSA".to_owned()],
        }
    }

    #[test]
    fn token_selection_is_exact_unambiguous_and_requires_ed25519() {
        use fcp_bootstrap::ProviderDetectionResult;

        let provider = Path::new("/configured/provider.so");
        let token = detected_token(provider, 7);
        let mut report = TokenDetectionReport {
            providers: vec![ProviderDetectionResult {
                provider: provider.to_path_buf(),
                tokens: vec![token.clone()],
                issues: vec![],
            }],
        };
        assert_eq!(select_token(&report, provider, 7).unwrap(), token);
        assert!(select_token(&report, provider, 8).is_err());
        assert!(select_token(&report, Path::new("/other/provider.so"), 7).is_err());
        report.providers[0].tokens.push(token);
        assert!(select_token(&report, provider, 7).is_err());
        report.providers[0].tokens.pop();
        report.providers[0].tokens[0].mechanisms = vec!["CKM_RSA_PKCS".to_owned()];
        assert!(select_token(&report, provider, 7).is_err());
    }

    #[test]
    fn pin_input_preserves_significant_spaces_and_never_leaks_into_debug() {
        let pin = pin_from_input(" 1234 \r\n").unwrap();
        assert_eq!(pin, HardwareTokenPin::new(" 1234 "));
        assert!(!format!("{pin:?}").contains("1234"));
        assert!(pin_from_input("1234\n5678").is_err());
        assert!(pin_from_input("\r\n").is_err());
        assert!(pin_from_input("1234\0").is_err());
    }

    #[test]
    fn status_refuses_a_corrupt_enrollment_instead_of_claiming_verified_signer() {
        let directory = tempfile::tempdir().unwrap();
        init_with_confirmation(&run_args(directory.path()), |_| Ok(())).unwrap();
        let bytes = std::fs::read(directory.path().join("genesis.cbor")).unwrap();
        let genesis = GenesisState::from_cbor(&bytes).unwrap();
        let path = HardwareTokenEnrollment::path_for_genesis(directory.path(), &genesis).unwrap();
        std::fs::write(path, b"{broken enrollment").unwrap();
        assert!(status(&StatusArgs {
            data_dir: directory.path().to_path_buf(),
        }).is_err());
        assert_eq!(std::fs::read(directory.path().join("genesis.cbor")).unwrap(), bytes);
    }

    #[test]
    fn init_confirms_delivered_phrase_before_publishing_and_recovers_exact_identity() {
        let directory = tempfile::tempdir().unwrap();
        let original = directory.path().join("original");
        let delivered = std::cell::RefCell::new(None);
        let output = init_with_confirmation(&run_args(&original), |phrase| {
            assert!(!original.join("genesis.cbor").exists());
            let words = Zeroizing::new(phrase.to_phrase());
            verify_confirmation(phrase, &words)?;
            *delivered.borrow_mut() = Some(words);
            Ok(())
        }).unwrap();
        let secret = delivered.into_inner().unwrap();
        let public_output = serde_json::to_string(&output).unwrap();
        assert!(!public_output.contains(secret.as_str()));
        assert_eq!(output["secret_material_written"], false);

        let recovered_dir = directory.path().join("recovered");
        let recovered = recover_with_input(&RecoverArgs {
            run: run_args(&recovered_dir),
            expected_fingerprint: output["fingerprint"].as_str().unwrap().to_owned(),
            phrase_stdin: true,
        }, &secret).unwrap();
        assert_eq!(recovered["fingerprint_verified"], true);
        assert_eq!(recovered["fingerprint"], output["fingerprint"]);
        assert_eq!(
            std::fs::read(original.join("genesis.cbor")).unwrap(),
            std::fs::read(recovered_dir.join("genesis.cbor")).unwrap()
        );
        let observed = status(&StatusArgs { data_dir: recovered_dir }).unwrap();
        assert_eq!(observed["fingerprint"], output["fingerprint"]);
        assert_eq!(observed["status"], "initialized");
    }

    #[test]
    fn declined_or_failed_phrase_delivery_never_publishes_genesis_and_releases_lease() {
        let directory = tempfile::tempdir().unwrap();
        let args = run_args(directory.path());
        let error = init_with_confirmation(&args, |_| anyhow::bail!("delivery was cancelled")).unwrap_err();
        assert!(error.to_string().contains("cancelled"));
        assert!(!directory.path().join("genesis.cbor").exists());
        assert!(!directory.path().join("init.lock").exists());
        init_with_confirmation(&args, |_| Ok(())).unwrap();
    }

    #[test]
    fn contention_and_existing_genesis_refuse_before_showing_new_words() {
        let directory = tempfile::tempdir().unwrap();
        let args = run_args(directory.path());
        let owner = prepare_workflow(&args, BootstrapMode::SingleDevice).unwrap();
        let called = Cell::new(false);
        assert!(init_with_confirmation(&args, |_| {
            called.set(true);
            Ok(())
        }).is_err());
        assert!(!called.get());
        drop(owner);
        init_with_confirmation(&args, |_| Ok(())).unwrap();
        let original = std::fs::read(directory.path().join("genesis.cbor")).unwrap();
        assert!(init_with_confirmation(&args, |_| {
            called.set(true);
            Ok(())
        }).is_err());
        assert!(!called.get());
        assert_eq!(std::fs::read(directory.path().join("genesis.cbor")).unwrap(), original);
    }

    #[test]
    fn wrong_phrase_or_fingerprint_never_creates_recovery_directory() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("must-not-exist");
        let first = RecoveryPhrase::generate().unwrap();
        let other = RecoveryPhrase::generate().unwrap();
        let identity = ColdRecovery::from_phrase(&first, None).unwrap();
        let args = RecoverArgs {
            run: run_args(&target),
            expected_fingerprint: identity.fingerprint(),
            phrase_stdin: true,
        };
        let input = Zeroizing::new(other.to_phrase());
        let error = recover_with_input(&args, &input).unwrap_err();
        assert!(!format!("{error:#}").contains(input.as_str()));
        assert!(!target.exists());
        assert!(verify_confirmation(&first, &input).is_err());
    }

    #[test]
    fn bounded_secret_inputs_reject_empty_oversized_and_invalid_utf8() {
        assert!(read_bounded_secret(&b" \r\n"[..]).is_err());
        assert!(read_bounded_secret(vec![b'a'; MAX_SECRET_BYTES as usize + 1].as_slice()).is_err());
        assert!(read_bounded_secret(&b"\xff"[..]).is_err());
        assert!(read_bounded_secret(&b"secret\0value"[..]).is_err());
        let accepted = read_bounded_secret(&b"word word\n"[..]).unwrap();
        assert_eq!(accepted.as_str(), "word word\n");
    }

    #[test]
    fn status_is_read_only_and_rejects_corrupt_or_oversized_genesis() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("absent");
        let output = status(&StatusArgs { data_dir: target.clone() }).unwrap();
        assert_eq!(output["status"], "uninitialized");
        assert!(!target.exists());
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("genesis.cbor"), b"not cbor").unwrap();
        assert!(status(&StatusArgs { data_dir: target.clone() }).is_err());
        let file = File::create(target.join("genesis.cbor")).unwrap();
        file.set_len(MAX_GENESIS_BYTES + 1).unwrap();
        assert!(status(&StatusArgs { data_dir: target }).is_err());
    }

    #[test]
    fn explicit_resume_restores_the_confirmed_phrase_and_cleans_partial_phase() {
        let directory = tempfile::tempdir().unwrap();
        fcp_bootstrap::phase::write_phase_lock(
            directory.path(), &fcp_bootstrap::BootstrapPhase::KeyGeneration,
        ).unwrap();
        let mut args = run_args(directory.path());
        assert!(init_with_confirmation(&args, |_| Ok(())).is_err());
        args.resume = true;
        let result = init_with_confirmation(&args, |_| Ok(())).unwrap();
        assert_eq!(result["status"], "created");
        assert!(!directory.path().join("init.lock").exists());
    }
}
