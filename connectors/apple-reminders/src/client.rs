//! `Apple Reminders` process client based on `osascript`.
//!
//! Subprocess invocations are bounded by the
//! [`crate::types::AppleRemindersConfig::subprocess_timeout_secs`]
//! field (default 30s) per H.1 production hardening (krxpn). The
//! `bounded_subprocess` module owns the timeout / kill-on-
//! expiry / stderr-truncation contract.

use std::process::Command;
use std::time::Duration;

use serde_json::{Value, json};

use crate::bounded_subprocess::{self, BoundedOutput, run_with_timeout};
use crate::error::{AppleRemindersError, AppleRemindersResult};
use crate::types::AppleRemindersConfig;

#[cfg(test)]
const TEST_FAKE_SUCCESS_OSASCRIPT: &str = "__fcp_apple_reminders_fake_success_osascript__";
#[cfg(test)]
const TEST_FAKE_SUCCESS_OSASCRIPT_PATH: &str = "/tmp/fcp-apple-reminders-osascript-e2e-success";
#[cfg(test)]
const TEST_FAKE_ERRORS_OSASCRIPT: &str = "__fcp_apple_reminders_fake_errors_osascript__";
#[cfg(test)]
const TEST_FAKE_ERRORS_OSASCRIPT_PATH: &str = "/tmp/fcp-apple-reminders-osascript-e2e-errors";

const LIST_LISTS_SCRIPT: &str = r#"
tell application "Reminders"
  set outputLines to {}
  repeat with theList in lists
    set end of outputLines to ((id of theList as text) & tab & (name of theList as text))
  end repeat
  return outputLines as text
end tell
"#;

const LIST_REMINDERS_SCRIPT: &str = r#"
on run argv
  set requestedList to ""
  if (count of argv) ≥ 1 then set requestedList to item 1 of argv
  set outputLines to {}
  tell application "Reminders"
    repeat with theList in lists
      if requestedList is "" or (name of theList as text) is requestedList then
        repeat with theReminder in reminders of theList
          set dueText to ""
          if due date of theReminder is not missing value then set dueText to (due date of theReminder as text)
          set end of outputLines to ((id of theReminder as text) & tab & (name of theReminder as text) & tab & (name of theList as text) & tab & ((completed of theReminder) as text) & tab & dueText)
        end repeat
      end if
    end repeat
  end tell
  return outputLines as text
end run
"#;

const CREATE_REMINDER_SCRIPT: &str = r#"
on run argv
  set reminderTitle to item 1 of argv
  set requestedList to item 2 of argv
  tell application "Reminders"
    if requestedList is "" then
      set targetList to first list
    else
      set targetList to list requestedList
    end if
    set createdReminder to make new reminder at end of reminders of targetList with properties {name:reminderTitle}
    return (id of createdReminder as text) & tab & (name of createdReminder as text) & tab & (name of targetList as text)
  end tell
end run
"#;

const COMPLETE_REMINDER_SCRIPT: &str = r#"
on run argv
  set reminderId to item 1 of argv
  tell application "Reminders"
    repeat with theList in lists
      repeat with theReminder in reminders of theList
        if (id of theReminder as text) is reminderId then
          set completed of theReminder to true
          return (id of theReminder as text) & tab & (name of theReminder as text) & tab & "true"
        end if
      end repeat
    end repeat
  end tell
  error "Reminder not found"
end run
"#;

#[derive(Debug, Clone)]
pub struct ScriptInvocation {
    pub script: &'static str,
    pub args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AppleRemindersClient {
    osascript_path: String,
    default_list: Option<String>,
    subprocess_timeout: Duration,
}

fn normalize_script_output(raw: &str) -> String {
    raw.replace("\r\n", "\n").replace('\r', "\n")
}

fn parse_list_output(raw: &str) -> Vec<Value> {
    let normalized = normalize_script_output(raw);
    normalized
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let mut parts = line.split('\t');
            Some(json!({
                "id": parts.next()?,
                "name": parts.next()?,
            }))
        })
        .collect()
}

fn parse_reminder_output(raw: &str) -> Vec<Value> {
    let normalized = normalize_script_output(raw);
    normalized
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let mut parts = line.split('\t');
            Some(json!({
                "id": parts.next()?,
                "title": parts.next()?,
                "list": parts.next()?,
                "completed": parts.next()? == "true",
                "due": parts.next().unwrap_or(""),
            }))
        })
        .collect()
}

impl AppleRemindersClient {
    pub fn from_config(config: &AppleRemindersConfig) -> AppleRemindersResult<Self> {
        config
            .validate()
            .map_err(|error| AppleRemindersError::Config(error.to_string()))?;
        Ok(Self {
            osascript_path: config.osascript_path.clone(),
            default_list: config.default_list.clone(),
            subprocess_timeout: Duration::from_secs(config.subprocess_timeout_secs),
        })
    }

    fn ensure_supported() -> AppleRemindersResult<()> {
        if std::env::consts::OS != "macos" {
            return Err(AppleRemindersError::UnsupportedPlatform(
                "Apple Reminders connector requires macOS".into(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub const fn list_lists_invocation(&self) -> ScriptInvocation {
        ScriptInvocation {
            script: LIST_LISTS_SCRIPT,
            args: Vec::new(),
        }
    }

    #[must_use]
    pub fn list_reminders_invocation(&self, list_name: Option<&str>) -> ScriptInvocation {
        ScriptInvocation {
            script: LIST_REMINDERS_SCRIPT,
            args: vec![
                list_name
                    .or(self.default_list.as_deref())
                    .unwrap_or("")
                    .to_string(),
            ],
        }
    }

    #[must_use]
    pub fn create_reminder_invocation(
        &self,
        title: &str,
        list_name: Option<&str>,
    ) -> ScriptInvocation {
        ScriptInvocation {
            script: CREATE_REMINDER_SCRIPT,
            args: vec![
                title.to_string(),
                list_name
                    .or(self.default_list.as_deref())
                    .unwrap_or("")
                    .to_string(),
            ],
        }
    }

    #[must_use]
    pub fn complete_reminder_invocation(&self, reminder_id: &str) -> ScriptInvocation {
        ScriptInvocation {
            script: COMPLETE_REMINDER_SCRIPT,
            args: vec![reminder_id.to_string()],
        }
    }

    fn run_invocation(&self, invocation: ScriptInvocation) -> AppleRemindersResult<String> {
        Self::ensure_supported()?;
        self.run_checked_invocation(invocation)
    }

    fn run_checked_invocation(&self, invocation: ScriptInvocation) -> AppleRemindersResult<String> {
        let command = self.build_command(invocation);
        let output: BoundedOutput =
            run_with_timeout(command, self.subprocess_timeout).map_err(map_subprocess_error)?;
        if !output.status.success() {
            return Err(AppleRemindersError::Process(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(normalize_script_output(stdout.as_ref()).trim().to_string())
    }

    fn build_command(&self, invocation: ScriptInvocation) -> Command {
        debug_assert!(
            self.osascript_path == crate::types::DEFAULT_OSASCRIPT_PATH || cfg!(test),
            "production Apple Reminders clients only use the canonical osascript path"
        );
        #[cfg(test)]
        let mut command = match self.osascript_path.as_str() {
            TEST_FAKE_SUCCESS_OSASCRIPT => {
                Command::new("/tmp/fcp-apple-reminders-osascript-e2e-success")
            }
            TEST_FAKE_ERRORS_OSASCRIPT => {
                Command::new("/tmp/fcp-apple-reminders-osascript-e2e-errors")
            }
            _ => Command::new(crate::types::DEFAULT_OSASCRIPT_PATH),
        };
        #[cfg(not(test))]
        let mut command = Command::new(crate::types::DEFAULT_OSASCRIPT_PATH);
        command.arg("-e").arg(invocation.script);
        if !invocation.args.is_empty() {
            command.arg("--");
            for arg in invocation.args {
                command.arg(arg);
            }
        }
        command
    }

    pub fn list_lists(&self) -> AppleRemindersResult<Value> {
        let raw = self.run_invocation(self.list_lists_invocation())?;
        let lists = parse_list_output(&raw);
        Ok(json!({ "lists": lists }))
    }

    pub fn list_reminders(&self, list_name: Option<&str>) -> AppleRemindersResult<Value> {
        let raw = self.run_invocation(self.list_reminders_invocation(list_name))?;
        let reminders = parse_reminder_output(&raw);
        Ok(json!({ "reminders": reminders }))
    }

    pub fn create_reminder(
        &self,
        title: &str,
        list_name: Option<&str>,
    ) -> AppleRemindersResult<Value> {
        if title.trim().is_empty() {
            return Err(AppleRemindersError::Config(
                "title must not be empty".into(),
            ));
        }
        let raw = self.run_invocation(self.create_reminder_invocation(title, list_name))?;
        let mut parts = raw.split('\t');
        Ok(json!({
            "id": parts.next().ok_or_else(|| AppleRemindersError::Parse("Missing reminder id".into()))?,
            "title": parts.next().ok_or_else(|| AppleRemindersError::Parse("Missing reminder title".into()))?,
            "list": parts.next().ok_or_else(|| AppleRemindersError::Parse("Missing reminder list".into()))?,
        }))
    }

    pub fn complete_reminder(&self, reminder_id: &str) -> AppleRemindersResult<Value> {
        if reminder_id.trim().is_empty() {
            return Err(AppleRemindersError::Config(
                "reminder_id must not be empty".into(),
            ));
        }
        let raw = self.run_invocation(self.complete_reminder_invocation(reminder_id))?;
        let mut parts = raw.split('\t');
        Ok(json!({
            "id": parts.next().ok_or_else(|| AppleRemindersError::Parse("Missing reminder id".into()))?,
            "title": parts.next().ok_or_else(|| AppleRemindersError::Parse("Missing reminder title".into()))?,
            "completed": parts.next().unwrap_or("false") == "true",
        }))
    }
}

/// Map a [`bounded_subprocess::SubprocessError`] into the
/// connector-facing [`AppleRemindersError`]. Centralizes the
/// translation so the bounded-runner contract is the single source
/// of truth for what counts as a timeout vs a process-launch error.
fn map_subprocess_error(err: bounded_subprocess::SubprocessError) -> AppleRemindersError {
    match err {
        bounded_subprocess::SubprocessError::Spawn(msg)
        | bounded_subprocess::SubprocessError::Wait(msg) => AppleRemindersError::Process(msg),
        bounded_subprocess::SubprocessError::Timeout { timeout_secs } => {
            AppleRemindersError::Timeout { timeout_secs }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;

    #[cfg(unix)]
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        time::{Duration, Instant},
    };

    fn client_with_list() -> AppleRemindersClient {
        AppleRemindersClient::from_config(&AppleRemindersConfig {
            default_list: Some("Personal".into()),
            osascript_path: "/usr/bin/osascript".into(),
            subprocess_timeout_secs: 30,
        })
        .unwrap()
    }

    fn client_no_list() -> AppleRemindersClient {
        AppleRemindersClient::from_config(&AppleRemindersConfig {
            default_list: None,
            osascript_path: "/usr/bin/osascript".into(),
            subprocess_timeout_secs: 30,
        })
        .unwrap()
    }

    #[cfg(unix)]
    fn client_with_osascript_path(
        path: impl Into<String>,
        timeout_secs: u64,
    ) -> AppleRemindersClient {
        AppleRemindersClient {
            osascript_path: path.into(),
            default_list: Some("Personal".into()),
            subprocess_timeout: Duration::from_secs(timeout_secs),
        }
    }

    fn command_args(command: &Command) -> Vec<String> {
        command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    fn emit_e2e_log(
        scenario: &str,
        correlation_id: &str,
        phase: &str,
        result: &str,
        details: &Value,
    ) -> Value {
        let payload = json!({
            "test_name": "apple_reminders_osascript_e2e",
            "module": "fcp-apple-reminders",
            "scenario": scenario,
            "phase": phase,
            "result": result,
            "correlation_id": correlation_id,
            "details": details,
            "replay": {
                "command": "rch exec -- cargo test -p fcp-apple-reminders osascript_e2e -- --nocapture"
            }
        });
        assert_redacted(&payload.to_string());
        println!("{payload}");
        payload
    }

    fn assert_redacted(line: &str) {
        for forbidden in [
            "/Users/",
            "/tmp/",
            TEST_FAKE_SUCCESS_OSASCRIPT_PATH,
            TEST_FAKE_ERRORS_OSASCRIPT_PATH,
            "Buy milk",
            "Fake Reminder",
            "Personal",
            "Shopping",
            "password",
            "secret",
            "token",
        ] {
            assert!(
                !line.contains(forbidden),
                "E2E proof log leaked forbidden value: {forbidden}"
            );
        }
    }

    #[cfg(unix)]
    fn shell_quote(path: &Path) -> String {
        format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
    }

    #[cfg(unix)]
    fn write_fake_osascript(executable: &Path) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fcp-apple-reminders-osascript-e2e-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).expect("create fake osascript e2e dir");
        let argv_log = dir.join("argv.log");
        let script = format!(
            r#"#!/bin/sh
log={}
printf 'scenario=fake-osascript\n' >> "$log"
index=0
for arg in "$@"; do
  printf 'argv[%s]=%s\n' "$index" "$arg" >> "$log"
  index=$((index + 1))
done
case "$*" in
  *FCP_FAKE_NONZERO*) printf 'bounded stderr redacted\n' >&2; exit 7 ;;
  *FCP_FAKE_TIMEOUT*) exec /bin/sleep 30 ;;
  *FCP_FAKE_LARGE_STDERR*) dd if=/dev/zero bs=1024 count=1030 2>/dev/null | tr '\000' x >&2; exit 9 ;;
  *) printf 'rem-1\tFake Reminder\tPersonal\n'; exit 0 ;;
esac
"#,
            shell_quote(&argv_log)
        );
        fs::write(executable, script).expect("write fake osascript");
        let mut permissions = fs::metadata(executable)
            .expect("fake osascript metadata")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(executable, permissions).expect("chmod fake osascript");
        argv_log
    }

    #[test]
    fn list_reminders_invocation_uses_default_list() {
        let invocation = client_with_list().list_reminders_invocation(None);
        assert_eq!(invocation.args, vec!["Personal"]);
    }

    #[test]
    fn list_reminders_invocation_overrides_default() {
        let invocation = client_with_list().list_reminders_invocation(Some("Work"));
        assert_eq!(invocation.args, vec!["Work"]);
    }

    #[test]
    fn list_reminders_invocation_empty_when_no_default() {
        let invocation = client_no_list().list_reminders_invocation(None);
        assert_eq!(invocation.args, vec![""]);
    }

    #[test]
    fn list_lists_invocation_has_no_args() {
        let invocation = client_no_list().list_lists_invocation();
        assert!(invocation.args.is_empty());
    }

    #[test]
    fn create_invocation_passes_title_and_list() {
        let invocation =
            client_with_list().create_reminder_invocation("Buy milk", Some("Shopping"));
        assert_eq!(invocation.args, vec!["Buy milk", "Shopping"]);
    }

    #[test]
    fn create_invocation_uses_default_list() {
        let invocation = client_with_list().create_reminder_invocation("Buy milk", None);
        assert_eq!(invocation.args, vec!["Buy milk", "Personal"]);
    }

    #[test]
    fn create_invocation_empty_list_when_none() {
        let invocation = client_no_list().create_reminder_invocation("Buy milk", None);
        assert_eq!(invocation.args, vec!["Buy milk", ""]);
    }

    #[test]
    fn complete_invocation_passes_id() {
        let invocation = client_with_list().complete_reminder_invocation("rem-123");
        assert_eq!(invocation.args, vec!["rem-123"]);
    }

    #[test]
    fn command_builder_keeps_user_values_after_separator() {
        let client = client_with_list();
        let title = "Buy milk; exec source $(osascript)";
        let list = "Shopping `not evaluated`\nwith newline";
        let command = client.build_command(client.create_reminder_invocation(title, Some(list)));
        let args = command_args(&command);
        let separator = args
            .iter()
            .position(|arg| arg == "--")
            .expect("separator must be present");

        let user_args: Vec<&str> = args
            .get((separator + 1)..)
            .expect("user args must be present")
            .iter()
            .map(String::as_str)
            .collect();
        assert_eq!(args.first().map(String::as_str), Some("-e"));
        assert_eq!(user_args, [title, list]);
    }

    #[test]
    fn from_config_revalidates_manually_constructed_config() {
        let err = AppleRemindersClient::from_config(&AppleRemindersConfig {
            default_list: None,
            osascript_path: "/usr/bin/env".into(),
            subprocess_timeout_secs: 30,
        })
        .expect_err("carrier path must be rejected");

        assert!(
            matches!(err, AppleRemindersError::Config(message) if message.contains("canonical"))
        );
    }

    #[test]
    fn osascript_e2e_rejects_wrapper_carrier_config_with_log() {
        let correlation_id = Uuid::new_v4().to_string();
        let mut rejected = Vec::new();
        for path in [
            "/usr/bin/env",
            "/usr/bin/sudo",
            "/usr/bin/doas",
            "/usr/bin/command",
            "/usr/bin/builtin",
            "/usr/bin/exec",
            "/usr/bin/source",
            "/bin/sh",
            "/bin/bash",
            "/bin/zsh",
            "osascript",
            "/usr/bin/osascript --",
        ] {
            let result = AppleRemindersConfig::from_value(json!({ "osascript_path": path }));
            assert!(result.is_err(), "{path} should be rejected");
            rejected.push(path);
        }

        let log = emit_e2e_log(
            "reject-wrapper-carrier-config",
            &correlation_id,
            "configure",
            "pass",
            &json!({ "rejected_paths": rejected }),
        );
        assert_eq!(log["correlation_id"], correlation_id);
        assert!(
            log["replay"]["command"]
                .as_str()
                .unwrap()
                .contains("fcp-apple-reminders")
        );
    }

    #[test]
    fn osascript_e2e_non_macos_reports_unsupported_skip_metadata() {
        let correlation_id = Uuid::new_v4().to_string();
        if std::env::consts::OS == "macos" {
            emit_e2e_log(
                "platform-support",
                &correlation_id,
                "health",
                "skip",
                &json!({ "reason": "live Apple Reminders access requires explicit live flag" }),
            );
            return;
        }

        let err = client_no_list()
            .list_lists()
            .expect_err("non-macOS must not launch osascript");
        assert!(matches!(err, AppleRemindersError::UnsupportedPlatform(_)));
        emit_e2e_log(
            "platform-support",
            &correlation_id,
            "health",
            "skip",
            &json!({ "reason": "unsupported platform", "os": std::env::consts::OS }),
        );
    }

    #[test]
    #[cfg(unix)]
    fn osascript_e2e_fake_success_logs_argv_stdout_and_replay() {
        let fake_osascript = Path::new(TEST_FAKE_SUCCESS_OSASCRIPT_PATH);
        let argv_log = write_fake_osascript(fake_osascript);
        let client = client_with_osascript_path(TEST_FAKE_SUCCESS_OSASCRIPT, 5);
        let correlation_id = Uuid::new_v4().to_string();
        let config = AppleRemindersConfig::from_value(json!({})).expect("default config");
        emit_e2e_log(
            "fake-success",
            &correlation_id,
            "configure",
            "pass",
            &json!({
                "osascript_path_policy": "canonical-path-only",
                "timeout_secs": config.subprocess_timeout_secs
            }),
        );

        let title = "Buy milk; exec -a alias python3 -c 'oops'";
        let list = "Shopping $(command source) && `not evaluated`\nenv -S exec";
        let stdout = client
            .run_checked_invocation(client.create_reminder_invocation(title, Some(list)))
            .expect("fake osascript should succeed");
        assert!(stdout.contains("Fake Reminder"));

        let argv = fs::read_to_string(&argv_log).expect("read fake argv log");
        assert!(argv.contains("argv[0]=-e"));
        assert!(argv.contains("argv[2]=--"));
        assert!(argv.contains(title));
        assert!(argv.contains("not evaluated"));
        assert!(argv.contains("env -S exec"));

        emit_e2e_log(
            "fake-success",
            &correlation_id,
            "invoke",
            "pass",
            &json!({
                "argv_record_count": argv.lines().count(),
                "stdout_shape": "id-title-list-tab-separated",
                "malicious_payload_inert": true,
            }),
        );
        emit_e2e_log(
            "fake-success",
            &correlation_id,
            "simulate",
            "skip",
            &json!({ "reason": "client-level fake osascript harness exercises subprocess argv directly" }),
        );
        emit_e2e_log(
            "fake-success",
            &correlation_id,
            "shutdown",
            "pass",
            &json!({ "cleanup": "fake executable overwritten by deterministic harness" }),
        );
    }

    #[test]
    #[cfg(unix)]
    fn osascript_e2e_fake_error_timeout_and_truncation_are_logged() {
        let fake_osascript = Path::new(TEST_FAKE_ERRORS_OSASCRIPT_PATH);
        let _argv_log = write_fake_osascript(fake_osascript);
        let client = client_with_osascript_path(TEST_FAKE_ERRORS_OSASCRIPT, 1);
        let correlation_id = Uuid::new_v4().to_string();

        let nonzero = client
            .run_checked_invocation(ScriptInvocation {
                script: "return \"fake\"",
                args: vec!["FCP_FAKE_NONZERO".into()],
            })
            .expect_err("nonzero fake should fail");
        assert!(
            matches!(&nonzero, AppleRemindersError::Process(message) if message.contains("bounded stderr redacted"))
        );
        emit_e2e_log(
            "fake-errors",
            &correlation_id,
            "stderr",
            "pass",
            &json!({ "nonzero_error": nonzero.to_string() }),
        );

        let large_stderr = client
            .run_checked_invocation(ScriptInvocation {
                script: "return \"fake\"",
                args: vec!["FCP_FAKE_LARGE_STDERR".into()],
            })
            .expect_err("large stderr fake should fail");
        match large_stderr {
            AppleRemindersError::Process(message) => {
                assert!(message.len() <= crate::bounded_subprocess::MAX_OUTPUT_BYTES);
                emit_e2e_log(
                    "fake-errors",
                    &correlation_id,
                    "stderr_truncation",
                    "pass",
                    &json!({ "stderr_len": message.len(), "cap": crate::bounded_subprocess::MAX_OUTPUT_BYTES }),
                );
            }
            other => {
                assert!(
                    matches!(other, AppleRemindersError::Process(_)),
                    "large stderr should map to process error"
                );
            }
        }

        let started = Instant::now();
        let timeout = client
            .run_checked_invocation(ScriptInvocation {
                script: "return \"fake\"",
                args: vec!["FCP_FAKE_TIMEOUT".into()],
            })
            .expect_err("timeout fake should fail");
        assert!(matches!(
            timeout,
            AppleRemindersError::Timeout { timeout_secs: 1 }
        ));
        assert!(started.elapsed() < Duration::from_secs(3));
        emit_e2e_log(
            "fake-errors",
            &correlation_id,
            "timeout",
            "pass",
            &json!({ "timeout_secs": 1, "elapsed_ms": started.elapsed().as_millis() }),
        );
        emit_e2e_log(
            "fake-errors",
            &correlation_id,
            "shutdown",
            "pass",
            &json!({ "cleanup": "fake executable overwritten by deterministic harness" }),
        );
    }

    #[test]
    fn create_rejects_empty_title() {
        let err = client_with_list().create_reminder("  ", None);
        assert!(err.is_err());
    }

    #[test]
    fn complete_rejects_empty_id() {
        let err = client_with_list().complete_reminder("  ");
        assert!(err.is_err());
    }

    #[test]
    fn bounded_subprocess_wait_maps_to_process_error() {
        let err = map_subprocess_error(bounded_subprocess::SubprocessError::Wait(
            "try_wait failed after child exit".into(),
        ));

        assert!(matches!(
            &err,
            AppleRemindersError::Process(message)
                if message.contains("try_wait failed after child exit")
        ));
    }

    #[test]
    fn normalize_script_output_accepts_carriage_returns() {
        assert_eq!(normalize_script_output("a\rb\r\nc\n"), "a\nb\nc\n");
    }

    #[test]
    fn parse_list_output_handles_carriage_return_delimited_records() {
        let lists = parse_list_output(
            "36B7BEE9-47C2-4B22-A513-D05ACF76D8DE\tReminders\rA1B2C3D4\tShopping\r",
        );

        assert_eq!(lists.len(), 2);
        assert_eq!(lists[0]["name"], "Reminders");
        assert_eq!(lists[1]["name"], "Shopping");
    }

    #[test]
    fn parse_list_output_matches_live_artifact_separator_shape() {
        let lists = parse_list_output(concat!(
            "36B7BEE9-47C2-4B22-A513-D05ACF76D8DE\tReminders\r",
            "6A48664C-BCEB-4368-87B6-B8AB9EF4501D\tShopping\r",
        ));

        assert_eq!(lists.len(), 2);
        assert_eq!(lists[0]["id"], "36B7BEE9-47C2-4B22-A513-D05ACF76D8DE");
        assert_eq!(lists[0]["name"], "Reminders");
        assert_eq!(lists[1]["id"], "6A48664C-BCEB-4368-87B6-B8AB9EF4501D");
        assert_eq!(lists[1]["name"], "Shopping");
    }

    #[test]
    fn parse_reminder_output_handles_carriage_return_delimited_records() {
        let reminders = parse_reminder_output(concat!(
            "x-apple-reminder://D5C7ED01\tPay Caterine\tReminders\tfalse\tFriday, October 3, 2025 at 6:00:00 PM\r",
            "x-apple-reminder://5C3420C7\tFCP Mac E2E Reminder Default 20260325T192752\tReminders\ttrue\t\r",
        ));

        assert_eq!(reminders.len(), 2);
        assert_eq!(reminders[0]["due"], "Friday, October 3, 2025 at 6:00:00 PM");
        assert_eq!(
            reminders[1]["title"],
            "FCP Mac E2E Reminder Default 20260325T192752"
        );
        assert_eq!(reminders[1]["due"], "");
    }

    #[test]
    fn parse_reminder_output_matches_live_artifact_separator_shape() {
        let reminders = parse_reminder_output(concat!(
            "x-apple-reminder://D5C7ED01-AE69-4BC9-B5AA-A2FE8AC2B047\tPay Caterine\tReminders\tfalse\tFriday, October 3, 2025 at 6:00:00\u{202f}PM\r",
            "x-apple-reminder://5C3420C7-82E6-470A-A961-2004D8724CF5\tFCP Mac E2E Reminder Default 20260325T192752\tReminders\ttrue\t\r",
        ));

        assert_eq!(reminders.len(), 2);
        assert_eq!(
            reminders[0]["id"],
            "x-apple-reminder://D5C7ED01-AE69-4BC9-B5AA-A2FE8AC2B047"
        );
        assert_eq!(
            reminders[0]["due"],
            "Friday, October 3, 2025 at 6:00:00\u{202f}PM"
        );
        assert_eq!(
            reminders[1]["id"],
            "x-apple-reminder://5C3420C7-82E6-470A-A961-2004D8724CF5"
        );
        assert_eq!(
            reminders[1]["title"],
            "FCP Mac E2E Reminder Default 20260325T192752"
        );
        assert_eq!(reminders[1]["completed"], true);
        assert_eq!(reminders[1]["due"], "");
    }

    #[test]
    fn list_lists_script_tells_reminders() {
        assert!(LIST_LISTS_SCRIPT.contains("tell application \"Reminders\""));
    }

    #[test]
    fn list_reminders_script_includes_completed() {
        assert!(LIST_REMINDERS_SCRIPT.contains("completed of theReminder"));
    }

    #[test]
    fn create_script_makes_new_reminder() {
        assert!(CREATE_REMINDER_SCRIPT.contains("make new reminder"));
    }

    #[test]
    fn complete_script_sets_completed_true() {
        assert!(COMPLETE_REMINDER_SCRIPT.contains("set completed of theReminder to true"));
    }
}
