//! Bounded rule management and previews. Live execution uses the same persisted definitions.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use fcp_core::SafetyTier;
use serde_json::{Value, json};

use crate::reactive_rules::{
    CircuitBreaker, ExecutionOutcome, IncomingEvent, Rule, RuleDedupCache, RuleSet, RuleSetStore,
    ThrottleState, evaluate_rule_with_dedup, validate_rule,
};

const MAX_RULES_BYTES: u64 = 1024 * 1024;
const MAX_EVENTS_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EVENT_BYTES: usize = 256 * 1024;
const MAX_PREVIEW_BYTES: usize = 8 * 1024 * 1024;
const MAX_RULES: usize = 128;
const MAX_EVALUATIONS: usize = 10_000;

#[derive(Args, Debug)]
pub(crate) struct RulesArgs {
    /// Persisted rule definitions; defaults to ~/.fwc/rules.toml.
    #[arg(long, global = true, value_name = "PATH")]
    rules_file: Option<PathBuf>,
    #[command(subcommand)]
    command: RulesCommand,
}

#[derive(Subcommand, Debug)]
enum RulesCommand {
    /// Register a TOML file containing [[rules]] entries.
    Add {
        file: PathBuf,
        /// Acknowledge registration above the safe tier; live authorization is still required.
        #[arg(long)]
        allow_risky: bool,
    },
    /// List persisted definitions without contacting a host.
    List,
    /// Test a definition file against one event, without executing it.
    Test {
        file: PathBuf,
        #[arg(long, value_name = "JSON")]
        event: String,
    },
    /// Enable a registered rule.
    Enable {
        name: String,
        #[arg(long)]
        allow_risky: bool,
    },
    /// Disable a registered rule.
    Disable { name: String },
    /// Preview registered rules against a finite JSONL file without consuming events.
    Preview {
        #[arg(long, value_name = "PATH")]
        events: PathBuf,
        #[arg(long)]
        rule: Option<String>,
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u32).range(1..=10_000))]
        max_events: u32,
    },
}

pub(crate) struct RulesOutput {
    pub(crate) payload: Value,
    pub(crate) rejected: bool,
}

pub(crate) fn dispatch(args: &RulesArgs) -> Result<RulesOutput> {
    if let RulesCommand::Test { file, event } = &args.command {
        ensure!(
            event.len() <= MAX_EVENT_BYTES,
            "event exceeds the byte limit"
        );
        let event: IncomingEvent =
            serde_json::from_str(event).map_err(|_| anyhow::anyhow!("invalid event JSON"))?;
        validate_event(&event)?;
        return preview_output("test", &load_rules(file, false)?, &[event]);
    }
    let store = args
        .rules_file
        .as_ref()
        .map_or_else(RuleSetStore::default_path, RuleSetStore::new);
    let path = canonical_rules_path(
        store.path(),
        matches!(&args.command, RulesCommand::Add { .. }),
    )?;
    match &args.command {
        RulesCommand::List => Ok(output(
            "list",
            json!({"rules": load_rules(&path, true)?.rules}),
        )),
        RulesCommand::Add { file, allow_risky } => {
            let incoming = load_rules(file, false)?;
            ensure!(
                !incoming.is_empty(),
                "the definition file contains no rules"
            );
            for rule in &incoming.rules {
                registration_acknowledged(rule, *allow_risky)?;
            }
            let _lock = lock_rules(&path)?;
            let mut rules = load_rules(&path, true)?;
            for rule in &incoming.rules {
                ensure!(
                    rules.get(&rule.name).is_none(),
                    "a rule with that name is already registered"
                );
            }
            let added = incoming.len();
            rules.rules.extend(incoming.rules);
            validate_rules(&rules)?;
            save_rules(&path, &rules)?;
            Ok(output("add", json!({"added": added, "total": rules.len()})))
        }
        RulesCommand::Enable { name, allow_risky } => {
            let _lock = lock_rules(&path)?;
            let mut rules = load_rules(&path, false)?;
            let rule = rules
                .get_mut(name)
                .context("no registered rule has that name")?;
            registration_acknowledged(rule, *allow_risky)?;
            rule.enabled = true;
            save_rules(&path, &rules)?;
            Ok(output("enable", json!({"rule": name, "enabled": true})))
        }
        RulesCommand::Disable { name } => {
            let _lock = lock_rules(&path)?;
            let mut rules = load_rules(&path, false)?;
            rules
                .get_mut(name)
                .context("no registered rule has that name")?
                .enabled = false;
            save_rules(&path, &rules)?;
            Ok(output("disable", json!({"rule": name, "enabled": false})))
        }
        RulesCommand::Preview {
            events,
            rule,
            max_events,
        } => {
            let rules = selected_rules(&path, rule.as_deref())?;
            let events = read_events(events, *max_events)?;
            preview_output("preview", &rules, &events)
        }
        RulesCommand::Test { .. } => unreachable!("test returned before opening the store"),
    }
}

fn output(subcommand: &str, data: Value) -> RulesOutput {
    RulesOutput {
        payload: json!({"status": "ok", "command": "rules", "subcommand": subcommand, "data": data}),
        rejected: false,
    }
}

fn registration_acknowledged(rule: &Rule, allow_risky: bool) -> Result<()> {
    ensure!(
        rule.safety_tier == SafetyTier::Safe || allow_risky,
        "registering or enabling a rule above the safe tier requires --allow-risky; this does not grant execution authority"
    );
    Ok(())
}

fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn canonical_rules_path(path: &Path, create_parent: bool) -> Result<PathBuf> {
    if create_parent {
        fs::create_dir_all(parent_dir(path))?;
    }
    match fs::canonicalize(path) {
        Ok(path) => Ok(path),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Ok(parent) = fs::canonicalize(parent_dir(path)) {
                Ok(parent.join(path.file_name().context("rules file requires a filename")?))
            } else if path.is_absolute() {
                Ok(path.to_path_buf())
            } else {
                Ok(std::env::current_dir()?.join(path))
            }
        }
        Err(error) => Err(error).context("could not resolve the persisted rules file"),
    }
}

fn companion_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

fn lock_rules(path: &Path) -> Result<File> {
    fs::create_dir_all(parent_dir(path))?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let lock = options.open(companion_path(path, ".lock"))?;
    lock.try_lock()
        .map_err(|_| anyhow::anyhow!("this rules file is already being modified or executed"))?;
    Ok(lock)
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    ensure!(
        fs::metadata(path)?.is_file(),
        "rules artifacts must be regular files"
    );
    let file = File::open(path).context("could not open the requested rules artifact")?;
    ensure!(
        file.metadata()?.is_file(),
        "rules artifacts must be regular files"
    );
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "rules artifact exceeds its byte limit"
    );
    Ok(bytes)
}

fn load_rules(path: &Path, allow_missing: bool) -> Result<RuleSet> {
    if allow_missing && !path.exists() {
        return Ok(RuleSet::new());
    }
    let bytes = read_bounded(path, MAX_RULES_BYTES)?;
    let raw = std::str::from_utf8(&bytes).context("rules file must be UTF-8")?;
    let rules: RuleSet = toml::from_str(raw).map_err(|_| anyhow::anyhow!("invalid rules TOML"))?;
    validate_rules(&rules)?;
    Ok(rules)
}

fn validate_rules(rules: &RuleSet) -> Result<()> {
    ensure!(rules.len() <= MAX_RULES, "too many rules in one rules file");
    let mut names = BTreeSet::new();
    for rule in &rules.rules {
        ensure!(
            validate_rule(rule).is_empty(),
            "rule definition failed validation"
        );
        ensure!(
            !rule.name.chars().any(char::is_control),
            "rule names cannot contain control characters"
        );
        ensure!(names.insert(&rule.name), "rule names must be unique");
    }
    Ok(())
}

fn selected_rules(path: &Path, name: Option<&str>) -> Result<RuleSet> {
    let mut rules = load_rules(path, false)?;
    if let Some(name) = name {
        ensure!(
            rules.get(name).is_some(),
            "no registered rule has that name"
        );
        rules.rules.retain(|rule| rule.name == name);
    }
    Ok(rules)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::create_dir_all(parent_dir(path))?;
    let temporary = companion_path(path, &format!(".{}.tmp", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    #[cfg(unix)]
    File::open(parent_dir(path))?.sync_all()?;
    Ok(())
}

fn save_rules(path: &Path, rules: &RuleSet) -> Result<()> {
    let raw = toml::to_string_pretty(rules)?;
    ensure!(
        raw.len() as u64 <= MAX_RULES_BYTES,
        "rules file exceeds the byte limit"
    );
    write_atomic(path, raw.as_bytes())
}

fn validate_event(event: &IncomingEvent) -> Result<()> {
    ensure!(
        !event.connector.trim().is_empty()
            && !event.event_type.trim().is_empty()
            && event.connector.len() <= 512
            && event.event_type.len() <= 512
            && !event.connector.chars().any(char::is_control)
            && !event.event_type.chars().any(char::is_control)
            && event
                .event_id
                .as_ref()
                .is_none_or(|id| !id.is_empty() && id.len() <= 4096),
        "event requires bounded connector, event_type, and optional event_id fields"
    );
    Ok(())
}

fn read_events(path: &Path, max_events: u32) -> Result<Vec<IncomingEvent>> {
    let bytes = read_bounded(path, MAX_EVENTS_BYTES)?;
    let mut events = Vec::new();
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        ensure!(
            line.len() <= MAX_EVENT_BYTES,
            "event on line {} exceeds the byte limit",
            index + 1
        );
        ensure!(
            events.len() < max_events as usize,
            "event file exceeds --max-events; no actions were started"
        );
        let event: IncomingEvent = serde_json::from_slice(line)
            .map_err(|_| anyhow::anyhow!("invalid event JSON on line {}", index + 1))?;
        validate_event(&event)?;
        events.push(event);
    }
    Ok(events)
}

fn preview_output(command: &str, rules: &RuleSet, events: &[IncomingEvent]) -> Result<RulesOutput> {
    ensure!(
        events
            .len()
            .checked_mul(rules.len())
            .is_some_and(|count| count <= MAX_EVALUATIONS),
        "this preview exceeds the evaluation limit; select one rule or a smaller event file"
    );
    let dedup = RuleDedupCache::new();
    let mut results = Vec::new();
    let mut bytes = 0usize;
    let mut rejected = false;
    for (index, event) in events.iter().enumerate() {
        for rule in &rules.rules {
            let (outcome, matched) = evaluate_rule_with_dedup(
                rule,
                event,
                &ThrottleState::new(&rule.name),
                &CircuitBreaker::default(),
                &dedup,
                true,
            );
            rejected |= outcome == ExecutionOutcome::InputRejected;
            let result = json!({"event": index + 1, "rule": rule.name, "outcome": outcome,
                "match": matched, "authority_checked": false, "safety_ceiling": rule.safety_tier});
            bytes = bytes.saturating_add(serde_json::to_vec(&result)?.len());
            ensure!(
                bytes <= MAX_PREVIEW_BYTES,
                "preview exceeds its output byte limit; select one rule or a smaller event file"
            );
            results.push(result);
        }
    }
    let mut result = output(
        command,
        json!({"dry_run": true, "events": events.len(), "executed": 0, "results": results}),
    );
    result.rejected = rejected;
    if rejected {
        result.payload["status"] = json!("invalid");
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reactive_rules::{EventTrigger, RuleAction};

    fn rule() -> Rule {
        Rule::new(
            "search",
            EventTrigger::new("slack", "message.new"),
            RuleAction::new("github", "issues.search").with_input("query", "{{event.data.text}}"),
        )
    }

    #[test]
    fn management_persists_and_requires_risk_acknowledgment() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("input.toml");
        let path = temp.path().join("rules.toml");
        save_rules(
            &input,
            &RuleSet {
                rules: vec![rule().with_safety_tier(SafetyTier::Risky)],
            },
        )
        .unwrap();
        let args = |command| RulesArgs {
            rules_file: Some(path.clone()),
            command,
        };
        assert!(
            dispatch(&args(RulesCommand::Add {
                file: input.clone(),
                allow_risky: false
            }))
            .is_err()
        );
        assert!(!path.exists());
        dispatch(&args(RulesCommand::Add {
            file: input.clone(),
            allow_risky: true,
        }))
        .unwrap();
        assert!(
            dispatch(&args(RulesCommand::Add {
                file: input,
                allow_risky: true
            }))
            .is_err()
        );
        dispatch(&args(RulesCommand::Disable {
            name: "search".into(),
        }))
        .unwrap();
        assert!(!load_rules(&path, false).unwrap().rules[0].enabled);
        assert!(
            dispatch(&args(RulesCommand::Enable {
                name: "search".into(),
                allow_risky: false
            }))
            .is_err()
        );
        dispatch(&args(RulesCommand::Enable {
            name: "search".into(),
            allow_risky: true,
        }))
        .unwrap();
        assert!(load_rules(&path, false).unwrap().rules[0].enabled);
    }

    #[test]
    fn event_file_is_fully_validated_before_preview() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("events.jsonl");
        let event = r#"{"connector":"slack","event_type":"message.new"}"#;
        fs::write(&path, format!("{event}\nnot-json\n")).unwrap();
        assert!(read_events(&path, 2).is_err());
        fs::write(&path, format!("{event}\n{event}\n")).unwrap();
        assert!(read_events(&path, 1).is_err());
        assert_eq!(read_events(&path, 2).unwrap().len(), 2);
    }

    #[test]
    fn invalid_registration_batches_preserve_the_existing_store() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("rules.toml");
        let input = temp.path().join("input.toml");
        save_rules(
            &path,
            &RuleSet {
                rules: vec![rule()],
            },
        )
        .unwrap();
        let original = fs::read(&path).unwrap();
        let mut new_rule = rule();
        new_rule.name = "another-search".into();
        for incoming in [
            vec![new_rule.clone(), rule()],
            vec![new_rule.clone(), new_rule.clone()],
            vec![new_rule.with_safety_tier(SafetyTier::Forbidden)],
        ] {
            save_rules(&input, &RuleSet { rules: incoming }).unwrap();
            assert!(
                dispatch(&RulesArgs {
                    rules_file: Some(path.clone()),
                    command: RulesCommand::Add {
                        file: input.clone(),
                        allow_risky: true
                    },
                })
                .is_err()
            );
            assert_eq!(fs::read(&path).unwrap(), original);
            assert_eq!(load_rules(&path, false).unwrap().len(), 1);
        }
    }

    #[test]
    fn oversized_merged_store_is_rejected_before_publication() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("rules.toml");
        let input = temp.path().join("input.toml");
        let mut first = rule();
        first
            .action
            .input
            .insert("query".into(), "x".repeat(600_000));
        save_rules(
            &path,
            &RuleSet {
                rules: vec![first.clone()],
            },
        )
        .unwrap();
        let original = fs::read(&path).unwrap();
        first.name = "another-search".into();
        save_rules(&input, &RuleSet { rules: vec![first] }).unwrap();
        let error = dispatch(&RulesArgs {
            rules_file: Some(path.clone()),
            command: RulesCommand::Add {
                file: input,
                allow_risky: false,
            },
        })
        .err()
        .unwrap();
        assert!(error.to_string().contains("byte limit"));
        assert_eq!(fs::read(&path).unwrap(), original);
    }

    #[test]
    fn preview_can_be_replayed_without_changing_persisted_rules() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("rules.toml");
        let events = temp.path().join("events.jsonl");
        save_rules(
            &path,
            &RuleSet {
                rules: vec![rule()],
            },
        )
        .unwrap();
        let original = fs::read(&path).unwrap();
        let event = r#"{"connector":"slack","event_type":"message.new","event_id":"same-event","data":{"text":"same input"}}"#;
        fs::write(&events, format!("{event}\n{event}\n")).unwrap();
        let args = RulesArgs {
            rules_file: Some(path.clone()),
            command: RulesCommand::Preview {
                events,
                rule: None,
                max_events: 2,
            },
        };
        let first = dispatch(&args).unwrap();
        let replay = dispatch(&args).unwrap();
        assert_eq!(first.payload, replay.payload);
        assert_eq!(first.payload["data"]["executed"], 0);
        assert_eq!(
            first.payload["data"]["results"].as_array().unwrap().len(),
            2
        );
        for result in first.payload["data"]["results"].as_array().unwrap() {
            assert_eq!(result["outcome"], "dry_run");
            assert_eq!(result["authority_checked"], false);
        }
        assert_eq!(fs::read(&path).unwrap(), original);
        assert!(!companion_path(&path, ".lock").exists());
    }

    #[test]
    fn test_command_does_not_open_or_create_the_persisted_store() {
        let temp = tempfile::tempdir().unwrap();
        let definition = temp.path().join("input.toml");
        let unrelated_store = temp.path().join("uncreated").join("rules.toml");
        save_rules(
            &definition,
            &RuleSet {
                rules: vec![rule()],
            },
        )
        .unwrap();
        let result = dispatch(&RulesArgs {
            rules_file: Some(unrelated_store.clone()),
            command: RulesCommand::Test {
                file: definition,
                event:
                    r#"{"connector":"slack","event_type":"message.new","data":{"text":"query"}}"#
                        .into(),
            },
        })
        .unwrap();
        assert!(!result.rejected);
        assert_eq!(result.payload["subcommand"], "test");
        assert_eq!(result.payload["data"]["executed"], 0);
        assert!(!unrelated_store.parent().unwrap().exists());
    }

    #[test]
    fn event_and_artifact_byte_bounds_fail_without_echoing_contents() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("events.jsonl");
        fs::write(&path, b"12345678").unwrap();
        assert_eq!(read_bounded(&path, 8).unwrap(), b"12345678");
        assert!(read_bounded(&path, 7).is_err());
        assert!(read_bounded(temp.path(), 8).is_err());
        let event = json!({"connector": "slack", "event_type": "message.new",
            "data": {"text": "sensitive-event-value".repeat(MAX_EVENT_BYTES / 10)}});
        fs::write(&path, serde_json::to_vec(&event).unwrap()).unwrap();
        let error = read_events(&path, 1).unwrap_err().to_string();
        assert!(error.contains("byte limit"));
        assert!(!error.contains("sensitive-event-value"));
        fs::write(&path, b"{sensitive-invalid-json}").unwrap();
        let error = read_events(&path, 1).unwrap_err().to_string();
        assert!(error.contains("line 1"));
        assert!(!error.contains("sensitive-invalid-json"));
    }

    #[test]
    fn event_source_validation_rejects_blank_control_and_oversized_identifiers() {
        for event in [
            IncomingEvent::new(" ", "message.new"),
            IncomingEvent::new("slack", "message\nnew"),
            IncomingEvent::new("x".repeat(513), "message.new"),
            IncomingEvent::new("slack", "message.new").with_event_id(""),
            IncomingEvent::new("slack", "message.new").with_event_id("x".repeat(4097)),
        ] {
            assert!(validate_event(&event).is_err());
        }
        assert!(validate_event(&IncomingEvent::new("slack", "message.new")).is_ok());
    }

    #[test]
    fn preview_keeps_event_templates_literal_and_rejects_expansion_limits() {
        let event =
            IncomingEvent::new("slack", "message.new").with_data("text", "{{event.data.text}}");
        let rules = RuleSet {
            rules: vec![rule()],
        };
        let preview = preview_output("test", &rules, &[event]).unwrap();
        assert!(!preview.rejected);
        assert_eq!(preview.payload["data"]["executed"], 0);
        let result = &preview.payload["data"]["results"][0];
        assert_eq!(result["outcome"], "dry_run");
        assert_eq!(result["authority_checked"], false);
        assert_eq!(
            result["match"]["rendered_inputs"]["query"],
            "{{event.data.text}}"
        );
        let event = IncomingEvent::new("slack", "message.new").with_data(
            "text",
            &"x".repeat(crate::reactive_rules::MAX_RENDERED_INPUT_BYTES),
        );
        let preview = preview_output("test", &rules, &[event]).unwrap();
        assert!(preview.rejected);
        assert_eq!(
            preview.payload["data"]["results"][0]["outcome"],
            "input_rejected"
        );
    }

    #[test]
    fn aggregate_preview_budget_and_evaluation_budget_are_enforced() {
        let rules = RuleSet {
            rules: vec![rule()],
        };
        let event =
            IncomingEvent::new("slack", "message.new").with_data("text", &"x".repeat(900_000));
        assert!(preview_output("preview", &rules, &vec![event; 10]).is_err());
        let event = IncomingEvent::new("slack", "message.new");
        assert!(preview_output("preview", &rules, &vec![event; MAX_EVALUATIONS + 1]).is_err());
    }

    #[test]
    fn lock_excludes_another_writer_and_releases_on_drop() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("rules.toml");
        let lock = lock_rules(&path).unwrap();
        assert!(lock_rules(&path).is_err());
        drop(lock);
        assert!(lock_rules(&path).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn filename_aliases_share_lock_and_preserve_the_symlink_when_modified() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("rules.toml");
        save_rules(
            &path,
            &RuleSet {
                rules: vec![rule()],
            },
        )
        .unwrap();
        let alias = temp.path().join("alias.toml");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        let canonical = canonical_rules_path(&alias, false).unwrap();
        assert_eq!(canonical, canonical_rules_path(&path, false).unwrap());
        let lock = lock_rules(&canonical).unwrap();
        let args = RulesArgs {
            rules_file: Some(alias.clone()),
            command: RulesCommand::Disable {
                name: "search".into(),
            },
        };
        assert!(dispatch(&args).is_err());
        drop(lock);
        dispatch(&args).unwrap();
        assert!(!load_rules(&path, false).unwrap().rules[0].enabled);
        assert!(fs::symlink_metadata(&alias).unwrap().is_symlink());
    }

    #[test]
    fn clap_accepts_rules_and_enforces_event_limits() {
        use clap::Parser;
        #[derive(Parser)]
        struct Cli {
            #[command(flatten)]
            rules: RulesArgs,
        }
        let parsed = Cli::try_parse_from([
            "rules",
            "--rules-file",
            "custom.toml",
            "preview",
            "--events",
            "events.jsonl",
            "--max-events",
            "5",
        ])
        .unwrap();
        assert!(matches!(
            parsed.rules.command,
            RulesCommand::Preview { max_events: 5, .. }
        ));
        assert!(
            Cli::try_parse_from([
                "rules",
                "preview",
                "--events",
                "events.jsonl",
                "--max-events",
                "0"
            ])
            .is_err()
        );
    }
}
