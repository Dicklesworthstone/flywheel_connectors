//! `Apple Notes` process client based on `osascript`.
//!
//! Subprocess invocations are bounded by the
//! [`crate::types::AppleNotesConfig::subprocess_timeout_secs`] field
//! (default 30s) per H.1 production hardening (krxpn). The
//! `bounded_subprocess` module owns the timeout / kill-on-expiry /
//! stderr-truncation contract; see its module docs for the wire
//! semantics.

use std::process::Command;
use std::time::Duration;

use serde_json::{Value, json};

use crate::error::{AppleNotesError, AppleNotesResult};
use crate::types::AppleNotesConfig;

use crate::bounded_subprocess::{self, BoundedOutput, run_with_timeout};

#[cfg(test)]
const TEST_FAKE_SUCCESS_OSASCRIPT: &str = "__fcp_apple_notes_fake_success_osascript__";
#[cfg(test)]
const TEST_FAKE_SUCCESS_OSASCRIPT_PATH: &str = "/tmp/fcp-apple-notes-osascript-e2e-success";
#[cfg(test)]
const TEST_FAKE_ERRORS_OSASCRIPT: &str = "__fcp_apple_notes_fake_errors_osascript__";
#[cfg(test)]
const TEST_FAKE_ERRORS_OSASCRIPT_PATH: &str = "/tmp/fcp-apple-notes-osascript-e2e-errors";

const LIST_NOTES_SCRIPT: &str = r#"
on run argv
  set requestedFolder to ""
  if (count of argv) ≥ 1 then set requestedFolder to item 1 of argv
  set outputLines to {}
  tell application "Notes"
    repeat with theAccount in accounts
      repeat with theFolder in folders of theAccount
        if requestedFolder is "" or (name of theFolder as text) is requestedFolder then
          repeat with theNote in notes of theFolder
            set end of outputLines to ((id of theNote as text) & tab & (name of theNote as text) & tab & (name of theFolder as text))
          end repeat
        end if
      end repeat
    end repeat
  end tell
  return outputLines as text
end run
"#;

const SEARCH_NOTES_SCRIPT: &str = r#"
on run argv
  set queryText to item 1 of argv
  set outputLines to {}
  tell application "Notes"
    repeat with theAccount in accounts
      repeat with theFolder in folders of theAccount
        repeat with theNote in notes of theFolder
          set noteName to (name of theNote as text)
          set noteBody to (body of theNote as text)
          if noteName contains queryText or noteBody contains queryText then
            set end of outputLines to ((id of theNote as text) & tab & noteName & tab & (name of theFolder as text))
          end if
        end repeat
      end repeat
    end repeat
  end tell
  return outputLines as text
end run
"#;

const GET_NOTE_SCRIPT: &str = r#"
on run argv
  set noteId to item 1 of argv
  tell application "Notes"
    repeat with theAccount in accounts
      repeat with theFolder in folders of theAccount
        repeat with theNote in notes of theFolder
          if (id of theNote as text) is noteId then
            return (id of theNote as text) & linefeed & (name of theNote as text) & linefeed & (name of theFolder as text) & linefeed & (body of theNote as text)
          end if
        end repeat
      end repeat
    end repeat
  end tell
  error "Note not found"
end run
"#;

const CREATE_NOTE_SCRIPT: &str = r#"
on run argv
  set noteTitle to item 1 of argv
  set noteBody to item 2 of argv
  set requestedFolder to ""
  if (count of argv) ≥ 3 then set requestedFolder to item 3 of argv
  tell application "Notes"
    set targetAccount to first account
    if requestedFolder is "" then
      set targetFolder to first folder of targetAccount
    else
      set targetFolder to folder requestedFolder of targetAccount
    end if
    set createdNote to make new note at targetFolder with properties {name:noteTitle, body:noteBody}
    return (id of createdNote as text) & tab & (name of createdNote as text) & tab & (name of targetFolder as text)
  end tell
end run
"#;

#[derive(Debug, Clone)]
pub struct ScriptInvocation {
    pub script: &'static str,
    pub args: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AppleNotesClient {
    osascript_path: String,
    default_folder: Option<String>,
    subprocess_timeout: Duration,
}

impl AppleNotesClient {
    pub fn from_config(config: &AppleNotesConfig) -> AppleNotesResult<Self> {
        config
            .validate()
            .map_err(|error| AppleNotesError::Config(error.to_string()))?;
        Ok(Self {
            osascript_path: config.osascript_path.clone(),
            default_folder: config.default_folder.clone(),
            subprocess_timeout: Duration::from_secs(config.subprocess_timeout_secs),
        })
    }

    fn ensure_supported() -> AppleNotesResult<()> {
        if std::env::consts::OS != "macos" {
            return Err(AppleNotesError::UnsupportedPlatform(
                "Apple Notes connector requires macOS".into(),
            ));
        }
        Ok(())
    }

    #[must_use]
    pub fn list_notes_invocation(&self, folder: Option<&str>) -> ScriptInvocation {
        ScriptInvocation {
            script: LIST_NOTES_SCRIPT,
            args: vec![
                folder
                    .or(self.default_folder.as_deref())
                    .unwrap_or("")
                    .to_string(),
            ],
        }
    }

    #[must_use]
    pub fn search_notes_invocation(&self, query: &str) -> ScriptInvocation {
        ScriptInvocation {
            script: SEARCH_NOTES_SCRIPT,
            args: vec![query.to_string()],
        }
    }

    #[must_use]
    pub fn get_note_invocation(&self, note_id: &str) -> ScriptInvocation {
        ScriptInvocation {
            script: GET_NOTE_SCRIPT,
            args: vec![note_id.to_string()],
        }
    }

    #[must_use]
    pub fn create_note_invocation(
        &self,
        title: &str,
        body: &str,
        folder: Option<&str>,
    ) -> ScriptInvocation {
        ScriptInvocation {
            script: CREATE_NOTE_SCRIPT,
            args: vec![
                title.to_string(),
                body.to_string(),
                folder
                    .or(self.default_folder.as_deref())
                    .unwrap_or("")
                    .to_string(),
            ],
        }
    }

    fn run_invocation(&self, invocation: ScriptInvocation) -> AppleNotesResult<String> {
        Self::ensure_supported()?;
        self.run_checked_invocation(invocation)
    }

    fn run_checked_invocation(&self, invocation: ScriptInvocation) -> AppleNotesResult<String> {
        let command = self.build_command(invocation);
        let output: BoundedOutput =
            run_with_timeout(command, self.subprocess_timeout).map_err(map_subprocess_error)?;
        if !output.status.success() {
            return Err(AppleNotesError::Process(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    fn build_command(&self, invocation: ScriptInvocation) -> Command {
        debug_assert!(
            self.osascript_path == crate::types::DEFAULT_OSASCRIPT_PATH || cfg!(test),
            "production Apple Notes clients only use the canonical osascript path"
        );
        #[cfg(test)]
        let mut command = match self.osascript_path.as_str() {
            TEST_FAKE_SUCCESS_OSASCRIPT => {
                Command::new("/tmp/fcp-apple-notes-osascript-e2e-success")
            }
            TEST_FAKE_ERRORS_OSASCRIPT => Command::new("/tmp/fcp-apple-notes-osascript-e2e-errors"),
            _ => Command::new(crate::types::DEFAULT_OSASCRIPT_PATH),
        };
        #[cfg(not(test))]
        let mut command = Command::new(crate::types::DEFAULT_OSASCRIPT_PATH);
        command.arg("-e").arg(invocation.script).arg("--");
        for arg in invocation.args {
            command.arg(arg);
        }
        command
    }

    fn parse_note_summaries(raw: &str) -> Value {
        let notes: Vec<Value> = raw
            .lines()
            .filter(|line| !line.trim().is_empty())
            .filter_map(|line| {
                let mut parts = line.split('\t');
                Some(json!({
                    "id": parts.next()?,
                    "title": parts.next()?,
                    "folder": parts.next()?,
                }))
            })
            .collect();
        json!({ "notes": notes })
    }

    pub fn list_notes(&self, folder: Option<&str>) -> AppleNotesResult<Value> {
        let raw = self.run_invocation(self.list_notes_invocation(folder))?;
        Ok(Self::parse_note_summaries(&raw))
    }

    pub fn search_notes(&self, query: &str) -> AppleNotesResult<Value> {
        if query.trim().is_empty() {
            return Err(AppleNotesError::Config("query must not be empty".into()));
        }
        let raw = self.run_invocation(self.search_notes_invocation(query))?;
        Ok(Self::parse_note_summaries(&raw))
    }

    pub fn get_note(&self, note_id: &str) -> AppleNotesResult<Value> {
        if note_id.trim().is_empty() {
            return Err(AppleNotesError::Config("note_id must not be empty".into()));
        }
        let raw = self.run_invocation(self.get_note_invocation(note_id))?;
        let mut parts = raw.splitn(4, '\n');
        let id = parts
            .next()
            .ok_or_else(|| AppleNotesError::Parse("Missing note id".into()))?;
        let title = parts
            .next()
            .ok_or_else(|| AppleNotesError::Parse("Missing note title".into()))?;
        let folder = parts
            .next()
            .ok_or_else(|| AppleNotesError::Parse("Missing note folder".into()))?;
        let body = parts.next().unwrap_or("");
        Ok(json!({
            "id": id,
            "title": title,
            "folder": folder,
            "body": body,
        }))
    }

    pub fn create_note(
        &self,
        title: &str,
        body: &str,
        folder: Option<&str>,
    ) -> AppleNotesResult<Value> {
        if title.trim().is_empty() {
            return Err(AppleNotesError::Config("title must not be empty".into()));
        }
        let raw = self.run_invocation(self.create_note_invocation(title, body, folder))?;
        let mut parts = raw.split('\t');
        Ok(json!({
            "id": parts.next().ok_or_else(|| AppleNotesError::Parse("Missing note id".into()))?,
            "title": parts.next().ok_or_else(|| AppleNotesError::Parse("Missing note title".into()))?,
            "folder": parts.next().ok_or_else(|| AppleNotesError::Parse("Missing note folder".into()))?,
        }))
    }
}

/// Map a [`bounded_subprocess::SubprocessError`] into the
/// connector-facing [`AppleNotesError`]. Centralizes the
/// translation so the bounded-runner contract is the single source
/// of truth for what counts as a timeout vs a process-launch error.
fn map_subprocess_error(err: bounded_subprocess::SubprocessError) -> AppleNotesError {
    match err {
        bounded_subprocess::SubprocessError::Spawn(msg)
        | bounded_subprocess::SubprocessError::Wait(msg) => AppleNotesError::Process(msg),
        bounded_subprocess::SubprocessError::Timeout { timeout_secs } => {
            AppleNotesError::Timeout { timeout_secs }
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

    fn test_client() -> AppleNotesClient {
        AppleNotesClient::from_config(&AppleNotesConfig {
            default_folder: Some("Inbox".into()),
            osascript_path: "/usr/bin/osascript".into(),
            subprocess_timeout_secs: 30,
        })
        .unwrap()
    }

    fn test_client_no_folder() -> AppleNotesClient {
        AppleNotesClient::from_config(&AppleNotesConfig {
            default_folder: None,
            osascript_path: "/usr/bin/osascript".into(),
            subprocess_timeout_secs: 30,
        })
        .unwrap()
    }

    #[cfg(unix)]
    fn test_client_with_osascript_path(
        path: impl Into<String>,
        timeout_secs: u64,
    ) -> AppleNotesClient {
        AppleNotesClient {
            osascript_path: path.into(),
            default_folder: Some("Inbox".into()),
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
            "test_name": "apple_notes_osascript_e2e",
            "module": "fcp-apple-notes",
            "scenario": scenario,
            "phase": phase,
            "result": result,
            "correlation_id": correlation_id,
            "details": details,
            "replay": {
                "command": "rch exec -- cargo test -p fcp-apple-notes osascript_e2e -- --nocapture"
            }
        });
        let line = payload.to_string();
        for forbidden in [
            "/Users/",
            "/tmp/fcp-apple-notes",
            title_marker(),
            body_marker(),
        ] {
            assert!(
                !line.contains(forbidden),
                "Apple Notes e2e log leaked forbidden marker: {forbidden}"
            );
        }
        println!("{payload}");
        payload
    }

    fn title_marker() -> &'static str {
        "Title; exec -a alias python3 -c 'oops'"
    }

    fn body_marker() -> &'static str {
        "body with \"quotes\"\n$(command source) && `not evaluated`"
    }

    #[cfg(unix)]
    fn shell_quote(path: &Path) -> String {
        format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
    }

    #[cfg(unix)]
    fn write_fake_osascript(executable: &Path) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fcp-apple-notes-osascript-e2e-{}", Uuid::new_v4()));
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
  *) printf 'id-1\tFake Title\tInbox\n'; exit 0 ;;
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
    fn list_invocation_uses_default_folder_when_present() {
        let client = test_client();
        let invocation = client.list_notes_invocation(None);
        assert_eq!(invocation.args, vec!["Inbox"]);
    }

    #[test]
    fn list_invocation_overrides_default_folder() {
        let client = test_client();
        let invocation = client.list_notes_invocation(Some("Work"));
        assert_eq!(invocation.args, vec!["Work"]);
    }

    #[test]
    fn list_invocation_empty_when_no_folder() {
        let client = test_client_no_folder();
        let invocation = client.list_notes_invocation(None);
        assert_eq!(invocation.args, vec![""]);
    }

    #[test]
    fn search_invocation_passes_query() {
        let client = test_client();
        let invocation = client.search_notes_invocation("meeting");
        assert_eq!(invocation.args, vec!["meeting"]);
    }

    #[test]
    fn get_note_invocation_passes_id() {
        let client = test_client();
        let invocation = client.get_note_invocation("note-123");
        assert_eq!(invocation.args, vec!["note-123"]);
    }

    #[test]
    fn create_invocation_passes_title_body_folder() {
        let client = test_client();
        let invocation = client.create_note_invocation("Title", "Body", Some("Work"));
        assert_eq!(invocation.args, vec!["Title", "Body", "Work"]);
    }

    #[test]
    fn create_invocation_uses_default_folder() {
        let client = test_client();
        let invocation = client.create_note_invocation("Title", "Body", None);
        assert_eq!(invocation.args, vec!["Title", "Body", "Inbox"]);
    }

    #[test]
    fn create_invocation_empty_folder_when_none() {
        let client = test_client_no_folder();
        let invocation = client.create_note_invocation("Title", "Body", None);
        assert_eq!(invocation.args, vec!["Title", "Body", ""]);
    }

    #[test]
    fn command_builder_keeps_user_values_after_separator() {
        let client = test_client();
        let title = "Title; exec source $(osascript)";
        let body = "body with \"quotes\"\nnew line && shell tokens";
        let folder = "Folder `not evaluated`";
        let command =
            client.build_command(client.create_note_invocation(title, body, Some(folder)));
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
        assert_eq!(user_args, [title, body, folder]);
    }

    #[test]
    fn from_config_revalidates_manually_constructed_config() {
        let err = AppleNotesClient::from_config(&AppleNotesConfig {
            default_folder: None,
            osascript_path: "/usr/bin/env".into(),
            subprocess_timeout_secs: 30,
        })
        .expect_err("carrier path must be rejected");

        assert!(matches!(err, AppleNotesError::Config(message) if message.contains("canonical")));
    }

    #[test]
    fn osascript_e2e_rejects_wrapper_carrier_config_with_log() {
        let correlation_id = Uuid::new_v4().to_string();
        let mut rejected_count = 0;
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
            let result = AppleNotesConfig::from_value(json!({ "osascript_path": path }));
            assert!(result.is_err(), "{path} should be rejected");
            rejected_count += 1;
        }

        let log = emit_e2e_log(
            "reject-wrapper-carrier-config",
            &correlation_id,
            "configure",
            "pass",
            &json!({
                "rejected_path_count": rejected_count,
                "rejected_classes": ["carrier", "relative", "multi-token"]
            }),
        );
        assert_eq!(log["correlation_id"], correlation_id);
        assert!(
            log["replay"]["command"]
                .as_str()
                .unwrap()
                .contains("fcp-apple-notes")
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
                &json!({ "reason": "live Apple Notes access requires explicit live flag" }),
            );
            return;
        }

        let err = test_client()
            .list_notes(None)
            .expect_err("non-macOS must not launch osascript");
        assert!(matches!(err, AppleNotesError::UnsupportedPlatform(_)));
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
        let client = test_client_with_osascript_path(TEST_FAKE_SUCCESS_OSASCRIPT, 5);
        let correlation_id = Uuid::new_v4().to_string();
        let config = AppleNotesConfig::from_value(json!({})).expect("default config");
        emit_e2e_log(
            "fake-success",
            &correlation_id,
            "configure",
            "pass",
            &json!({
                "osascript_path_policy": if config.osascript_path == crate::types::DEFAULT_OSASCRIPT_PATH {
                    "canonical-only"
                } else {
                    "rejected"
                }
            }),
        );

        let title = "Title; exec -a alias python3 -c 'oops'";
        let body = "body with \"quotes\"\n$(command source) && `not evaluated`";
        let folder = "env -S exec bash -lc osascript-wrapper";
        let stdout = client
            .run_checked_invocation(client.create_note_invocation(title, body, Some(folder)))
            .expect("fake osascript should succeed");
        assert!(stdout.contains("Fake Title"));

        let argv = fs::read_to_string(&argv_log).expect("read fake argv log");
        assert!(argv.contains("argv[0]=-e"));
        assert!(argv.contains("argv[2]=--"));
        assert!(argv.contains(title));
        assert!(argv.contains("not evaluated"));
        assert!(argv.contains(folder));

        emit_e2e_log(
            "fake-success",
            &correlation_id,
            "invoke",
            "pass",
            &json!({
                "argv_record_count": argv.lines().count(),
                "stdout_shape": if stdout.contains('\t') { "tab-delimited-note-summary" } else { "unexpected" },
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
            &json!({ "fake_osascript": "omitted-local-path" }),
        );
    }

    #[test]
    #[cfg(unix)]
    fn osascript_e2e_fake_error_timeout_and_truncation_are_logged() {
        let fake_osascript = Path::new(TEST_FAKE_ERRORS_OSASCRIPT_PATH);
        let _argv_log = write_fake_osascript(fake_osascript);
        let client = test_client_with_osascript_path(TEST_FAKE_ERRORS_OSASCRIPT, 1);
        let correlation_id = Uuid::new_v4().to_string();

        let nonzero = client
            .run_checked_invocation(ScriptInvocation {
                script: "return \"fake\"",
                args: vec!["FCP_FAKE_NONZERO".into()],
            })
            .expect_err("nonzero fake should fail");

        assert!(
            matches!(&nonzero, AppleNotesError::Process(message) if message.contains("bounded stderr redacted"))
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
            AppleNotesError::Process(message) => {
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
                    matches!(other, AppleNotesError::Process(_)),
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
            AppleNotesError::Timeout { timeout_secs: 1 }
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
            &json!({ "fake_osascript": "omitted-local-path" }),
        );
    }

    #[test]
    fn bounded_subprocess_wait_maps_to_process_error() {
        let err = map_subprocess_error(bounded_subprocess::SubprocessError::Wait(
            "try_wait failed after child exit".into(),
        ));

        assert!(matches!(
            &err,
            AppleNotesError::Process(message)
                if message.contains("try_wait failed after child exit")
        ));
    }

    #[test]
    fn parse_note_summaries_single_line() {
        let value = AppleNotesClient::parse_note_summaries("id-1\tTitle\tInbox\n");
        let notes = note_array(&value);
        assert_eq!(notes[0]["id"], "id-1");
        assert_eq!(notes[0]["title"], "Title");
        assert_eq!(notes[0]["folder"], "Inbox");
    }

    #[test]
    fn parse_note_summaries_multiple_lines() {
        let value =
            AppleNotesClient::parse_note_summaries("id-1\tNote A\tInbox\nid-2\tNote B\tWork\n");
        let notes = note_array(&value);
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[1]["title"], "Note B");
    }

    #[test]
    fn parse_note_summaries_empty_input() {
        let value = AppleNotesClient::parse_note_summaries("");
        let notes = note_array(&value);
        assert!(notes.is_empty());
    }

    #[test]
    fn parse_note_summaries_skips_blank_lines() {
        let value = AppleNotesClient::parse_note_summaries("id-1\tA\tB\n\n\nid-2\tC\tD\n");
        let notes = note_array(&value);
        assert_eq!(notes.len(), 2);
    }

    fn note_array(value: &Value) -> &[Value] {
        value
            .get("notes")
            .and_then(Value::as_array)
            .expect("parse_note_summaries should return a notes array")
    }

    #[test]
    fn search_rejects_empty_query() {
        // This tests the validation logic without needing macOS
        let client = test_client();
        let err = client.search_notes("  ");
        assert!(err.is_err());
    }

    #[test]
    fn get_note_rejects_empty_id() {
        let client = test_client();
        let err = client.get_note("  ");
        assert!(err.is_err());
    }

    #[test]
    fn create_note_rejects_empty_title() {
        let client = test_client();
        let err = client.create_note("  ", "body", None);
        assert!(err.is_err());
    }

    #[test]
    fn list_notes_script_contains_tell_notes() {
        assert!(LIST_NOTES_SCRIPT.contains("tell application \"Notes\""));
    }

    #[test]
    fn search_notes_script_contains_contains_check() {
        assert!(SEARCH_NOTES_SCRIPT.contains("contains queryText"));
    }

    #[test]
    fn get_note_script_returns_body() {
        assert!(GET_NOTE_SCRIPT.contains("body of theNote"));
    }

    #[test]
    fn create_note_script_makes_new_note() {
        assert!(CREATE_NOTE_SCRIPT.contains("make new note"));
    }

    #[test]
    fn list_invocation_uses_correct_script() {
        let client = test_client();
        let inv = client.list_notes_invocation(None);
        // LIST_NOTES_SCRIPT is the only script that uses "LIST" RPC pattern
        assert!(inv.script.contains("tell application \"Notes\""));
        assert!(inv.script.contains("outputLines"));
    }
}
