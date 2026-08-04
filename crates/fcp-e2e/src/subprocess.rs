//! Subprocess runner stub for connector binaries.
//!
//! This is a minimal IPC shim for connectors that speak JSON lines over
//! stdin/stdout. It is intentionally lightweight and deterministic.

use std::fmt::Write as _;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fcp_async_core::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use fcp_async_core::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use fcp_async_core::sync::Mutex;
use fcp_async_core::task::JoinHandle;

use crate::E2eCommandMetadata;

const RCH_RUNNER_PREFIX: &str = "rch exec --";

/// Subprocess runner for connector binaries using JSONL IPC.
pub struct ConnectorProcessRunner {
    child: Child,
    command: String,
    args: Vec<String>,
    env_keys: Vec<String>,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    stdout_lines: Arc<Mutex<Vec<String>>>,
    stderr_lines: Arc<Mutex<Vec<String>>>,
    _stderr_task: JoinHandle<()>,
}

impl ConnectorProcessRunner {
    /// Spawn a connector subprocess with JSONL stdin/stdout.
    ///
    /// # Errors
    /// Returns an IO error if the process fails to spawn or pipes cannot be opened.
    #[allow(clippy::unused_async, clippy::unused_async_trait_impl)] // Async for API consistency with other subprocess methods
    pub async fn spawn(command: &str, args: &[&str], env: &[(&str, &str)]) -> io::Result<Self> {
        let mut cmd = Command::new(command);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        for (key, value) in env {
            cmd.env(key, value);
        }

        let mut child = cmd.spawn()?;
        let stdin = child
            .stdin()
            .ok_or_else(|| io::Error::other("connector stdin unavailable"))?;
        let stdout = child
            .stdout()
            .ok_or_else(|| io::Error::other("connector stdout unavailable"))?;
        let stderr = child
            .stderr()
            .ok_or_else(|| io::Error::other("connector stderr unavailable"))?;

        let mut env_keys = env
            .iter()
            .map(|(key, _value)| (*key).to_string())
            .collect::<Vec<_>>();
        env_keys.sort();

        let stdout_lines = Arc::new(Mutex::new(Vec::new()));
        let stderr_lines = Arc::new(Mutex::new(Vec::new()));
        let stderr_lines_task = Arc::clone(&stderr_lines);
        let stderr_task = fcp_async_core::task::spawn(async move {
            let mut reader = BufReader::new(stderr);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let trimmed = line.trim_end();
                        if !trimmed.is_empty() {
                            let mut buffer = stderr_lines_task.lock().await;
                            buffer.push(trimmed.to_string());
                        }
                    }
                }
            }
        });

        Ok(Self {
            child,
            command: command.to_string(),
            args: args.iter().map(|value| (*value).to_string()).collect(),
            env_keys,
            stdin,
            stdout: BufReader::new(stdout),
            stdout_lines,
            stderr_lines,
            _stderr_task: stderr_task,
        })
    }

    /// Send a JSON request to the connector.
    ///
    /// # Errors
    /// Returns an IO error if the request cannot be serialized or written.
    pub async fn send_json(&mut self, value: &serde_json::Value) -> io::Result<()> {
        let line = serde_json::to_string(value)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        self.stdin.write_all(line.as_bytes()).await?;
        self.stdin.write_all(b"\n").await?;
        self.stdin.flush().await?;
        Ok(())
    }

    /// Read a JSON response from the connector.
    ///
    /// # Errors
    /// Returns an IO error if the response cannot be read or parsed.
    pub async fn read_json(&mut self) -> io::Result<serde_json::Value> {
        let mut line = String::new();
        let bytes = self.stdout.read_line(&mut line).await?;
        if bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connector closed stdout",
            ));
        }
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            let mut buffer = self.stdout_lines.lock().await;
            buffer.push(trimmed.to_string());
        }
        serde_json::from_str::<serde_json::Value>(trimmed)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))
    }

    /// Send a JSON request and wait for the next JSON response.
    ///
    /// # Errors
    /// Returns an IO error if IO or parsing fails.
    pub async fn request(&mut self, value: &serde_json::Value) -> io::Result<serde_json::Value> {
        self.send_json(value).await?;
        self.read_json().await
    }

    /// Terminate the connector subprocess.
    ///
    /// # Errors
    /// Returns an IO error if the process cannot be terminated.
    pub fn terminate(&mut self) -> io::Result<()> {
        self.child.kill().map_err(Into::into)
    }

    /// Terminate the connector subprocess and capture a stable exit-status payload.
    ///
    /// # Errors
    /// Returns an IO error if the process cannot be signalled or polled.
    pub async fn terminate_and_capture_exit_status(
        &mut self,
        timeout: Duration,
    ) -> io::Result<serde_json::Value> {
        if let Some(status) = self.child.try_wait()? {
            return Ok(serde_json::json!({
                "captured": true,
                "success": status.success(),
                "code": status.code(),
                "status": status.to_string(),
            }));
        }

        self.terminate()?;
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(serde_json::json!({
                    "captured": true,
                    "success": status.success(),
                    "code": status.code(),
                    "status": status.to_string(),
                }));
            }
            if Instant::now() >= deadline {
                return Ok(serde_json::json!({
                    "captured": false,
                    "success": false,
                    "code": serde_json::Value::Null,
                    "status": serde_json::Value::Null,
                }));
            }
            fcp_async_core::time::sleep(Duration::from_millis(25)).await;
        }
    }

    /// Structured metadata for replaying this subprocess boundary.
    #[must_use]
    pub fn command_metadata(&self) -> E2eCommandMetadata {
        E2eCommandMetadata {
            command: self.command.clone(),
            args: self.args.clone(),
            runner_prefix: runner_prefix_for_command(&self.command).map(str::to_string),
            working_directory: std::env::current_dir()
                .ok()
                .map(|cwd| cwd.display().to_string()),
            env_keys: self.env_keys.clone(),
        }
    }

    /// Render the shell command used to replay this subprocess boundary.
    #[must_use]
    pub fn replay_shell_command(&self) -> String {
        let mut segments = Vec::new();
        if let Some(prefix) = runner_prefix_for_command(&self.command) {
            segments.extend(prefix.split_whitespace().map(ToString::to_string));
        }
        segments.push(self.command.clone());
        segments.extend(self.args.iter().cloned());
        shell_join(&segments)
    }

    /// Render a replay script for this subprocess boundary.
    #[must_use]
    pub fn replay_script(&self) -> String {
        let mut script = String::from("#!/bin/sh\nset -eu\n");
        if !self.env_keys.is_empty() {
            script.push('\n');
            script.push_str("# Set required environment values before replaying.\n");
            for key in &self.env_keys {
                let _ = writeln!(script, "# export {key}=<value>");
            }
        }
        let _ = writeln!(script, "{}", self.replay_shell_command());
        script
    }

    /// Write the replay script for this subprocess boundary.
    ///
    /// # Errors
    /// Returns an IO error if the replay script cannot be written.
    pub fn write_replay_script<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        std::fs::write(path, self.replay_script())
    }

    /// Drain captured stdout lines since the last call.
    pub async fn drain_stdout_lines(&self) -> Vec<String> {
        let mut buffer = self.stdout_lines.lock().await;
        std::mem::take(&mut *buffer)
    }

    /// Snapshot captured stdout lines without draining.
    pub async fn stdout_lines(&self) -> Vec<String> {
        let lines = self.stdout_lines.lock().await;
        lines.clone()
    }

    /// Drain captured stderr lines since the last call.
    pub async fn drain_stderr_lines(&self) -> Vec<String> {
        let mut buffer = self.stderr_lines.lock().await;
        std::mem::take(&mut *buffer)
    }

    /// Snapshot captured stderr lines without draining.
    pub async fn stderr_lines(&self) -> Vec<String> {
        let lines = self.stderr_lines.lock().await;
        lines.clone()
    }
}

fn runner_prefix_for_command(command: &str) -> Option<&'static str> {
    Path::new(command)
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| *value == "cargo")
        .map(|_| RCH_RUNNER_PREFIX)
}

fn shell_join(parts: &[String]) -> String {
    parts
        .iter()
        .map(|part| shell_escape(part))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_escape(argument: &str) -> String {
    if argument.is_empty() {
        return "''".to_string();
    }

    if argument
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-_./:=+".contains(&byte))
    {
        return argument.to_string();
    }

    format!("'{}'", argument.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Use `cat` as a JSONL echo subprocess (reads stdin, writes to stdout).

    #[fcp_async_core::runtime::test]
    async fn spawn_and_terminate() {
        let mut runner = ConnectorProcessRunner::spawn("cat", &[], &[])
            .await
            .expect("cat should spawn");
        runner.terminate().expect("should terminate");
    }

    #[fcp_async_core::runtime::test]
    async fn send_and_read_json_roundtrip() {
        let mut runner = ConnectorProcessRunner::spawn("cat", &[], &[])
            .await
            .unwrap();
        let msg = json!({"method": "ping", "id": 1});
        runner.send_json(&msg).await.unwrap();
        let response = runner.read_json().await.unwrap();
        assert_eq!(response, msg);
        runner.terminate().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn request_roundtrip() {
        let mut runner = ConnectorProcessRunner::spawn("cat", &[], &[])
            .await
            .unwrap();
        let msg = json!({"jsonrpc": "2.0", "method": "test", "params": [1, 2, 3]});
        let response = runner.request(&msg).await.unwrap();
        assert_eq!(response, msg);
        runner.terminate().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn multiple_requests() {
        let mut runner = ConnectorProcessRunner::spawn("cat", &[], &[])
            .await
            .unwrap();
        for i in 0..5 {
            let msg = json!({"id": i, "data": format!("msg-{i}")});
            let response = runner.request(&msg).await.unwrap();
            assert_eq!(response["id"], i);
        }
        runner.terminate().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn read_json_after_eof_returns_error() {
        let mut runner = ConnectorProcessRunner::spawn("echo", &[], &[])
            .await
            .unwrap();
        // echo writes nothing to stdout (no args) and exits immediately.
        // Wait for exit, then read should get EOF.
        // Give it a moment to finish.
        fcp_async_core::time::sleep(std::time::Duration::from_millis(50)).await;
        let result = runner.read_json().await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn spawn_nonexistent_binary_fails() {
        let result = ConnectorProcessRunner::spawn("__nonexistent_binary_xyz_42__", &[], &[]).await;
        assert!(result.is_err());
    }

    #[fcp_async_core::runtime::test]
    async fn spawn_with_env_vars() {
        // Use `sh -c 'echo ...'` to echo a JSON object containing an env var.
        let mut runner = ConnectorProcessRunner::spawn(
            "sh",
            &["-c", r#"echo "{\"var\":\"$FCP_TEST_VAR\"}""#],
            &[("FCP_TEST_VAR", "hello_42")],
        )
        .await
        .unwrap();
        let response = runner.read_json().await.unwrap();
        assert_eq!(response["var"], "hello_42");
    }

    #[fcp_async_core::runtime::test]
    async fn drain_stderr_lines_initially_empty() {
        let runner = ConnectorProcessRunner::spawn("cat", &[], &[])
            .await
            .unwrap();
        let lines = runner.drain_stderr_lines().await;
        assert!(lines.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn drain_stdout_lines_initially_empty() {
        let runner = ConnectorProcessRunner::spawn("cat", &[], &[])
            .await
            .unwrap();
        let lines = runner.drain_stdout_lines().await;
        assert!(lines.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn drain_stderr_captures_output() {
        // Use sh -c to write to stderr
        let mut runner = ConnectorProcessRunner::spawn(
            "sh",
            &[
                "-c",
                "echo 'error line 1' >&2; echo 'error line 2' >&2; cat",
            ],
            &[],
        )
        .await
        .unwrap();
        // Give stderr time to be captured
        fcp_async_core::time::sleep(std::time::Duration::from_millis(100)).await;
        let lines = runner.drain_stderr_lines().await;
        assert!(
            lines.len() >= 2,
            "expected at least 2 stderr lines, got {}",
            lines.len()
        );
        assert!(lines[0].contains("error line 1"));
        assert!(lines[1].contains("error line 2"));
        runner.terminate().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn drain_stderr_clears_buffer() {
        let mut runner = ConnectorProcessRunner::spawn("sh", &["-c", "echo 'msg' >&2; cat"], &[])
            .await
            .unwrap();
        fcp_async_core::time::sleep(std::time::Duration::from_millis(100)).await;
        let first = runner.drain_stderr_lines().await;
        assert!(!first.is_empty());
        let second = runner.drain_stderr_lines().await;
        assert!(second.is_empty(), "drain should clear buffer");
        runner.terminate().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn drain_stdout_captures_raw_jsonl_output() {
        let mut runner = ConnectorProcessRunner::spawn("cat", &[], &[])
            .await
            .unwrap();
        let msg = json!({"method": "ping", "id": 7});
        let response = runner.request(&msg).await.unwrap();
        assert_eq!(response, msg);

        let stdout = runner.drain_stdout_lines().await;
        assert_eq!(stdout, vec![serde_json::to_string(&msg).unwrap()]);
        runner.terminate().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn send_json_complex_value() {
        let mut runner = ConnectorProcessRunner::spawn("cat", &[], &[])
            .await
            .unwrap();
        let msg = json!({
            "method": "invoke",
            "params": {
                "connector": "test",
                "operation": "get",
                "zone": "z:work",
                "nested": {"a": [1, 2, 3], "b": null, "c": true}
            }
        });
        let response = runner.request(&msg).await.unwrap();
        assert_eq!(response["params"]["nested"]["a"], json!([1, 2, 3]));
        assert!(response["params"]["nested"]["b"].is_null());
        runner.terminate().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn stderr_lines_returns_snapshot() {
        let mut runner = ConnectorProcessRunner::spawn(
            "sh",
            &["-c", "echo 'line1' >&2; echo 'line2' >&2; cat"],
            &[],
        )
        .await
        .unwrap();
        fcp_async_core::time::sleep(std::time::Duration::from_millis(100)).await;
        let snapshot = runner.stderr_lines().await;
        assert!(snapshot.len() >= 2);
        // stderr_lines doesn't drain, so calling again returns same content
        let snapshot2 = runner.stderr_lines().await;
        assert_eq!(snapshot.len(), snapshot2.len());
        runner.terminate().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn stdout_lines_returns_snapshot() {
        let mut runner = ConnectorProcessRunner::spawn("cat", &[], &[])
            .await
            .unwrap();
        let msg = json!({"hello": "world"});
        let _ = runner.request(&msg).await.unwrap();

        let snapshot = runner.stdout_lines().await;
        let snapshot2 = runner.stdout_lines().await;
        assert_eq!(snapshot, snapshot2);
        assert_eq!(snapshot, vec![serde_json::to_string(&msg).unwrap()]);
        runner.terminate().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn send_json_empty_object() {
        let mut runner = ConnectorProcessRunner::spawn("cat", &[], &[])
            .await
            .unwrap();
        let msg = json!({});
        let response = runner.request(&msg).await.unwrap();
        assert!(response.as_object().unwrap().is_empty());
        runner.terminate().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn command_metadata_tracks_env_keys() {
        let mut runner =
            ConnectorProcessRunner::spawn("sh", &["-c", "cat"], &[("B_KEY", "2"), ("A_KEY", "1")])
                .await
                .unwrap();

        let metadata = runner.command_metadata();
        assert_eq!(metadata.command, "sh");
        assert_eq!(metadata.args, vec!["-c".to_string(), "cat".to_string()]);
        assert_eq!(
            metadata.env_keys,
            vec!["A_KEY".to_string(), "B_KEY".to_string()]
        );
        runner.terminate().unwrap();
    }

    #[fcp_async_core::runtime::test]
    async fn replay_script_mentions_env_keys_without_values() {
        let mut runner = ConnectorProcessRunner::spawn(
            "sh",
            &["-c", "cat"],
            &[("TOKEN", "secret"), ("FCP_MODE", "test")],
        )
        .await
        .unwrap();
        let script = runner.replay_script();

        assert!(script.contains("# export TOKEN=<value>"));
        assert!(script.contains("# export FCP_MODE=<value>"));
        assert!(!script.contains("secret"));
        runner.terminate().unwrap();
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test]
    async fn drop_reaps_long_running_process() {
        let pid = {
            let runner =
                ConnectorProcessRunner::spawn("sh", &["-c", "while :; do sleep 1; done"], &[])
                    .await
                    .unwrap();
            runner.child.id().expect("child pid should be available")
        };

        let mut reaped = false;
        for _ in 0..80 {
            let status = std::process::Command::new("sh")
                .args(["-c", &format!("kill -0 {pid} >/dev/null 2>&1")])
                .status()
                .expect("kill -0 should run");
            if !status.success() {
                reaped = true;
                break;
            }
            fcp_async_core::time::sleep(std::time::Duration::from_millis(25)).await;
        }

        assert!(
            reaped,
            "child pid {pid} should be gone after drop-triggered cleanup"
        );
    }

    #[test]
    fn runner_prefix_detects_cargo_commands() {
        assert_eq!(runner_prefix_for_command("cargo"), Some(RCH_RUNNER_PREFIX));
        assert_eq!(
            runner_prefix_for_command("/usr/local/bin/cargo"),
            Some(RCH_RUNNER_PREFIX)
        );
        assert_eq!(runner_prefix_for_command("cat"), None);
    }

    #[test]
    fn replay_shell_command_quotes_arguments() {
        let command = shell_join(&[
            "sh".to_string(),
            "-c".to_string(),
            "echo 'hello world'".to_string(),
        ]);
        assert_eq!(command, "sh -c 'echo '\"'\"'hello world'\"'\"''");
    }
}
