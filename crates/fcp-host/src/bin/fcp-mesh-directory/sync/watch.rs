//! Continuous authenticated delivery with one persistent installer owner.
//!
//! Remote failure never refreshes authority. Local state or persistence failure
//! stops the process; a service supervisor must not erase state to restart it.

use super::*;

const DEFAULT_INTERVAL_SECS: u64 = 30;
const DEFAULT_MAX_BACKOFF_SECS: u64 = 300;
const MAX_POLL_SECS: u64 = 3600;

#[derive(Clone, Copy, Debug)]
struct WatchConfig {
    interval: Duration,
    max_backoff: Duration,
}

impl WatchConfig {
    fn from_options(options: &BTreeMap<String, OsString>) -> super::super::Result<Self> {
        let seconds = |name: &str, default: u64| {
            let value = match options.get(name) {
                None => default,
                Some(raw) => raw.to_str().and_then(|text| text.parse::<u64>().ok())
                    .ok_or_else(|| format!("{name} must be an integer number of seconds"))?,
            };
            if !(1..=MAX_POLL_SECS).contains(&value) {
                return Err(format!("{name} must be between 1 and {MAX_POLL_SECS} seconds"));
            }
            Ok(value)
        };
        let interval = seconds("--interval-secs", DEFAULT_INTERVAL_SECS)?;
        let max_backoff = seconds("--max-backoff-secs", DEFAULT_MAX_BACKOFF_SECS)?;
        if max_backoff < interval {
            return Err("--max-backoff-secs must not be smaller than --interval-secs".to_owned());
        }
        Ok(Self {
            interval: Duration::from_secs(interval),
            max_backoff: Duration::from_secs(max_backoff),
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct Installed {
    generation: u64,
    expires_at_ms: u64,
}

/// Retry state never controls signed validity or the installed generation.
struct PollSchedule {
    config: WatchConfig,
    failures: u64,
    retry_delay: Duration,
}

impl PollSchedule {
    const fn new(config: WatchConfig) -> Self {
        Self { config, failures: 0, retry_delay: config.interval }
    }

    fn completed(&mut self, succeeded: bool, installed: Option<Installed>, now_ms: u64) -> Duration {
        let base = if succeeded {
            self.failures = 0;
            self.retry_delay = self.config.interval;
            self.config.interval
        } else {
            if self.failures > 0 {
                self.retry_delay = self.retry_delay.saturating_mul(2).min(self.config.max_backoff);
            }
            self.failures = self.failures.saturating_add(1);
            self.retry_delay
        };
        // Try before a known expiration where possible, but never busy-loop on
        // an expired document. Fetch latency and host activation are separate.
        match installed.map(|state| state.expires_at_ms.saturating_sub(now_ms)) {
            Some(remaining) if remaining > 0 => {
                base.min(Duration::from_millis((remaining / 2).max(1000)))
            }
            _ => base,
        }
    }
}

#[derive(Serialize)]
struct WatchEvent<'a> {
    schema_version: &'static str,
    attempt: u64,
    observed_at_ms: u64,
    outcome: &'static str,
    consecutive_failures: u64,
    next_poll_ms: Option<u64>,
    installed_generation: Option<u64>,
    installed_expires_at_ms: Option<u64>,
    // This is the local wall-clock comparison, not a host readiness claim.
    installed_expired: Option<bool>,
    host_activation_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    installation: Option<&'a SyncReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn ensure_unchanged(installer: &disk::Installer, expected: &Option<String>) -> SyncResult<()> {
    if installer.read_installed()? != *expected {
        return Err(SyncError::Local("source changed outside its continuous installer; restart required"));
    }
    Ok(())
}

/// The waiter is injected for deterministic tests and cooperative embedding.
/// Returning false stops after the current report; production sleeps and repeats.
fn drive(
    installer: &mut disk::Installer,
    trust: &Trust,
    config: WatchConfig,
    output: &mut impl io::Write,
    mut fetch_document: impl FnMut() -> SyncResult<String>,
    mut wait: impl FnMut(Duration) -> bool,
) -> SyncResult<()> {
    let mut expected = installer.read_installed()?;
    let mut installed = expected.as_deref()
        .map(|text| trust.installed(text, unix_now_ms()))
        .transpose()?
        .map(|verified| Installed {
            generation: verified.payload().generation,
            expires_at_ms: verified.payload().expires_at_ms,
        });
    if expected.is_some() {
        // A pre-existing signed source already supplies history, even when the
        // publisher is down. Persist that fact before the first network attempt.
        installer.mark_initialized()?;
    }
    let mut schedule = PollSchedule::new(config);
    let mut attempt = 0_u64;
    loop {
        attempt = attempt.saturating_add(1);
        let result = ensure_unchanged(installer, &expected).and_then(|()| {
            let text = fetch_document()?;
            ensure_unchanged(installer, &expected)?;
            let report = installer.install(&text, trust)?;
            expected = Some(text);
            installed = Some(Installed {
                generation: report.generation,
                expires_at_ms: report.expires_at_ms,
            });
            Ok(report)
        });
        // Remote errors are recoverable only when the durable input is still
        // exactly the expected one. A late expiry after rename is ambiguous;
        // never resume with an older in-memory high-water mark in that case.
        let result = match result {
            Ok(report) => ensure_unchanged(installer, &expected).map(|()| report),
            Err(error @ SyncError::Remote(_)) => {
                match ensure_unchanged(installer, &expected) {
                    Ok(()) => Err(error),
                    Err(local) => Err(local),
                }
            }
            Err(error) => Err(error),
        };
        let now_ms = unix_now_ms();
        let (outcome, delay) = match &result {
            Ok(report) => (report.action, Some(schedule.completed(true, installed, now_ms))),
            Err(SyncError::Remote(_)) => ("retrying", Some(schedule.completed(false, installed, now_ms))),
            Err(_) => ("fatal", None),
        };
        let event = WatchEvent {
            schema_version: "fcp.mesh.directory_watch.v1",
            attempt,
            observed_at_ms: now_ms,
            outcome,
            consecutive_failures: schedule.failures,
            next_poll_ms: delay.map(|delay| u64::try_from(delay.as_millis()).unwrap_or(u64::MAX)),
            installed_generation: installed.map(|state| state.generation),
            installed_expires_at_ms: installed.map(|state| state.expires_at_ms),
            installed_expired: installed.map(|state| now_ms >= state.expires_at_ms),
            host_activation_verified: false,
            installation: result.as_ref().ok(),
            error: result.as_ref().err().map(ToString::to_string),
        };
        serde_json::to_writer(&mut *output, &event)
            .map_err(|_| SyncError::Local("watch report serialization or output failed"))?;
        writeln!(output).and_then(|()| output.flush())
            .map_err(|error| storage("watch_output", &error))?;
        if let Some(delay) = delay {
            if !wait(delay) {
                return Ok(());
            }
        } else {
            return match result {
                Err(error) => Err(error),
                Ok(_) => Err(SyncError::Local("watch terminated without a scheduling decision")),
            };
        }
    }
}

pub(super) fn run(options: &BTreeMap<String, OsString>, output: &mut impl io::Write) -> super::super::Result<()> {
    let config = WatchConfig::from_options(options)?;
    // Trust and source URL are pinned for this process. A downloaded key or a
    // rewritten public-key file cannot silently replace its roots during a run.
    let trust = Trust::from_options(options)?;
    let url = source_url(options["--url"].to_str().ok_or_else(|| "source URL is not UTF-8".to_owned())?)
        .map_err(|error| error.to_string())?;
    let mut installer = disk::Installer::open(Path::new(&options["--directory"]))
        .map_err(|error| error.to_string())?;
    drive(&mut installer, &trust, config, output, || fetch(&url, FETCH_TIMEOUT), |delay| {
        std::thread::sleep(delay);
        true
    }).map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_mesh::invoke_route::MeshPeerConfig;
    use fcp_mesh::peer_manifest::MESH_PEER_DIRECTORY_SCHEMA;

    use super::*;

    struct Fixture {
        dir: tempfile::TempDir,
        owner: Ed25519SigningKey,
        trust: Trust,
        payload: MeshPeerDirectoryPayload,
    }

    impl Fixture {
        fn new() -> Self {
            let owner = Ed25519SigningKey::from_bytes(&[71; 32]).unwrap();
            let local = Ed25519SigningKey::from_bytes(&[72; 32]).unwrap();
            let now = unix_now_ms();
            Self {
                dir: tempfile::tempdir().unwrap(),
                trust: Trust {
                    owner: owner.verifying_key(),
                    local: local.verifying_key(),
                    mesh_id: "watch-test".to_owned(),
                    node: TailscaleNodeId::new("local"),
                },
                payload: MeshPeerDirectoryPayload {
                    schema_version: MESH_PEER_DIRECTORY_SCHEMA.to_owned(),
                    mesh_id: "watch-test".to_owned(),
                    generation: 7,
                    issued_at_ms: now - 1000,
                    expires_at_ms: now + 300_000,
                    peers: vec![MeshPeerConfig {
                        node_id: "local".to_owned(),
                        endpoint: "http://127.0.0.1:19001".to_owned(),
                        public_key_hex: hex::encode(local.verifying_key().to_bytes()),
                    }],
                },
                owner,
            }
        }

        fn path(&self) -> std::path::PathBuf {
            self.dir.path().join("membership.json")
        }

        fn wire(&self) -> String {
            serde_json::to_string(&SignedMeshPeerDirectory::sign(&self.owner, &self.payload).unwrap()).unwrap()
        }
    }

    fn config() -> WatchConfig {
        WatchConfig { interval: Duration::from_secs(1), max_backoff: Duration::from_secs(4) }
    }

    fn events(output: &[u8]) -> Vec<serde_json::Value> {
        std::str::from_utf8(output).unwrap().lines()
            .map(|line| serde_json::from_str(line).unwrap()).collect()
    }

    #[test]
    fn polling_options_are_bounded_and_fail_without_echoing_values() {
        let defaults = WatchConfig::from_options(&BTreeMap::new()).unwrap();
        assert_eq!(defaults.interval, Duration::from_secs(30));
        assert_eq!(defaults.max_backoff, Duration::from_secs(300));
        for (name, value) in [
            ("--interval-secs", "0"), ("--interval-secs", "3601"),
            ("--interval-secs", "SECRET"), ("--max-backoff-secs", "0"),
            ("--max-backoff-secs", "1"), ("--max-backoff-secs", "18446744073709551615"),
        ] {
            let options = BTreeMap::from([(name.to_owned(), OsString::from(value))]);
            let error = WatchConfig::from_options(&options).unwrap_err();
            assert!(!error.contains("SECRET"));
        }
        let options = BTreeMap::from([
            ("--interval-secs".to_owned(), OsString::from("3600")),
            ("--max-backoff-secs".to_owned(), OsString::from("3600")),
        ]);
        assert_eq!(WatchConfig::from_options(&options).unwrap().interval, Duration::from_secs(3600));
    }

    #[test]
    fn retries_back_off_cap_and_reset_after_a_success() {
        let fixture = Fixture::new();
        let mut installer = disk::Installer::open(&fixture.path()).unwrap();
        let wire = fixture.wire();
        let mut responses = vec![
            Err(SyncError::Remote("offline".to_owned())),
            Err(SyncError::Remote("offline".to_owned())),
            Err(SyncError::Remote("offline".to_owned())),
            Err(SyncError::Remote("offline".to_owned())),
            Ok(wire.clone()),
            Err(SyncError::Remote("offline".to_owned())),
        ].into_iter();
        let mut waits = Vec::new();
        let mut output = Vec::new();
        drive(&mut installer, &fixture.trust, config(), &mut output,
            || responses.next().unwrap(),
            |delay| { waits.push(delay.as_secs()); waits.len() < 6 },
        ).unwrap();
        assert_eq!(waits, [1, 2, 4, 4, 1, 1]);
        assert_eq!(fs::read_to_string(fixture.path()).unwrap(), wire);
        let records = events(&output);
        assert_eq!(records[4]["outcome"], "installed");
        assert_eq!(records[4]["consecutive_failures"], 0);
        assert_eq!(records[5]["consecutive_failures"], 1);
        assert!(records.iter().all(|record| record["host_activation_verified"] == false));
    }

    #[test]
    fn expiry_adjusts_polling_without_extending_authority_or_busy_looping() {
        let mut schedule = PollSchedule::new(WatchConfig {
            interval: Duration::from_secs(30), max_backoff: Duration::from_secs(300),
        });
        let installed = Some(Installed { generation: 7, expires_at_ms: 5000 });
        assert_eq!(schedule.completed(true, installed, 1000), Duration::from_secs(2));
        assert_eq!(schedule.completed(false, installed, 4500), Duration::from_secs(1));
        assert_eq!(schedule.completed(false, installed, 5000), Duration::from_secs(60));
        schedule.failures = u64::MAX;
        schedule.retry_delay = Duration::from_secs(300);
        assert_eq!(schedule.completed(false, installed, u64::MAX), Duration::from_secs(300));
        assert_eq!(schedule.failures, u64::MAX);
    }

    #[test]
    fn expired_installed_history_is_retained_through_outage_and_renewed() {
        let mut fixture = Fixture::new();
        fixture.payload.expires_at_ms = unix_now_ms() - 1;
        let expired = fixture.wire();
        fs::write(fixture.path(), &expired).unwrap();
        fixture.payload.generation = 8;
        fixture.payload.expires_at_ms = unix_now_ms() + 300_000;
        let fresh = fixture.wire();
        let mut responses = vec![Err(SyncError::Remote("offline".to_owned())), Ok(fresh.clone())].into_iter();
        let mut installer = disk::Installer::open(&fixture.path()).unwrap();
        let mut output = Vec::new();
        let mut waits = 0;
        drive(&mut installer, &fixture.trust, config(), &mut output,
            || responses.next().unwrap(),
            |_| {
                waits += 1;
                if waits == 1 {
                    assert_eq!(fs::read_to_string(fixture.path()).unwrap(), expired);
                }
                waits < 2
            },
        ).unwrap();
        let records = events(&output);
        assert_eq!(records[0]["installed_expired"], true);
        assert_eq!(records[0]["installed_generation"], 7);
        assert_eq!(records[1]["installation"]["previous_generation"], 7);
        assert_eq!(fs::read_to_string(fixture.path()).unwrap(), fresh);
    }

    #[test]
    fn local_corruption_stops_before_any_network_attempt() {
        let fixture = Fixture::new();
        fs::write(fixture.path(), "{corrupt}").unwrap();
        let mut installer = disk::Installer::open(&fixture.path()).unwrap();
        let calls = AtomicUsize::new(0);
        let result = drive(&mut installer, &fixture.trust, config(), &mut Vec::new(),
            || { calls.fetch_add(1, Ordering::SeqCst); Ok(fixture.wire()) },
            |_| panic!("local failures cannot retry"),
        );
        assert!(matches!(result, Err(SyncError::Local(_))));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(fs::read_to_string(fixture.path()).unwrap(), "{corrupt}");
    }

    #[test]
    fn missing_initialized_state_during_an_outage_is_terminal() {
        let fixture = Fixture::new();
        let mut installer = disk::Installer::open(&fixture.path()).unwrap();
        installer.install(&fixture.wire(), &fixture.trust).unwrap();
        let mut output = Vec::new();
        let result = drive(&mut installer, &fixture.trust, config(), &mut output,
            || {
                fs::rename(fixture.path(), fixture.dir.path().join("retained")).unwrap();
                Err(SyncError::Remote("offline".to_owned()))
            },
            |_| panic!("missing history cannot retry"),
        );
        assert!(matches!(result, Err(SyncError::Local(_))));
        assert_eq!(events(&output)[0]["outcome"], "fatal");
        assert_eq!(events(&output)[0]["next_poll_ms"], serde_json::Value::Null);
        assert!(!fixture.path().exists());
    }

    #[test]
    fn one_installer_lock_is_held_across_every_retry_wait() {
        let fixture = Fixture::new();
        let mut installer = disk::Installer::open(&fixture.path()).unwrap();
        let mut waits = 0;
        drive(&mut installer, &fixture.trust, config(), &mut Vec::new(),
            || Err(SyncError::Remote("offline".to_owned())),
            |_| {
                assert!(disk::Installer::open(&fixture.path()).is_err());
                waits += 1;
                waits < 3
            },
        ).unwrap();
        drop(installer);
        assert!(disk::Installer::open(&fixture.path()).is_ok());
    }

    #[test]
    fn ambiguous_install_or_external_replacement_never_retries_from_old_history() {
        let mut fixture = Fixture::new();
        let mut installer = disk::Installer::open(&fixture.path()).unwrap();
        installer.install(&fixture.wire(), &fixture.trust).unwrap();
        fixture.payload.generation = 8;
        let next = fixture.wire();
        let mut output = Vec::new();
        let result = drive(&mut installer, &fixture.trust, config(), &mut output,
            || {
                // Model the filesystem-visible ambiguity of a completed replace
                // followed by an unsuccessful result; the real installer and
                // watcher comparison are used, not a successful-state substitute.
                fs::write(fixture.path(), &next).unwrap();
                Err(SyncError::Remote("candidate expired during install".to_owned()))
            },
            |_| panic!("ambiguous writes require restart"),
        );
        assert!(matches!(result, Err(SyncError::Local(_))));
        assert_eq!(events(&output)[0]["outcome"], "fatal");
        assert_eq!(fs::read_to_string(fixture.path()).unwrap(), next);
    }

    #[test]
    fn failed_report_flush_stops_without_issuing_another_fetch() {
        struct BrokenOutput;
        impl Write for BrokenOutput {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> { Ok(bytes.len()) }
            fn flush(&mut self) -> io::Result<()> { Err(io::Error::from(io::ErrorKind::BrokenPipe)) }
        }
        let fixture = Fixture::new();
        let mut installer = disk::Installer::open(&fixture.path()).unwrap();
        let calls = AtomicUsize::new(0);
        let result = drive(&mut installer, &fixture.trust, config(), &mut BrokenOutput,
            || { calls.fetch_add(1, Ordering::SeqCst); Ok(fixture.wire()) },
            |_| panic!("failed output must stop"),
        );
        assert!(matches!(result, Err(SyncError::Storage("watch_output", io::ErrorKind::BrokenPipe))));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(fs::read_to_string(fixture.path()).unwrap(), fixture.wire());
    }

    #[test]
    fn real_http_polling_recovers_from_refusal_and_tampering_without_rollback() {
        let mut fixture = Fixture::new();
        let first = fixture.wire();
        fixture.payload.generation = 8;
        let next = fixture.wire();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = source_url(&format!("http://{}/members", listener.local_addr().unwrap())).unwrap();
        let mut forged: SignedMeshPeerDirectory = serde_json::from_str(&next).unwrap();
        forged.payload_json.push(' ');
        let responses = vec![
            (503, "untrusted-error-body".to_owned()),
            (200, serde_json::to_string(&forged).unwrap()),
            (200, first.clone()), (200, next.clone()), (200, first),
        ];
        let server = thread::spawn(move || {
            for (status, body) in responses {
                let start = Instant::now();
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            assert!(start.elapsed() < Duration::from_secs(5));
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("accept: {error}"),
                    }
                };
                socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                socket.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut reader = BufReader::new(&mut socket);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert_eq!(line, "GET /members HTTP/1.1\r\n");
                let mut total = line.len();
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    total += line.len();
                    assert!(!line.is_empty() && total <= 8192);
                    if line == "\r\n" { break; }
                    assert!(!line.to_ascii_lowercase().starts_with("authorization:"));
                }
                let _ = write!(socket, "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            }
        });
        let mut installer = disk::Installer::open(&fixture.path()).unwrap();
        let mut output = Vec::new();
        let mut waits = 0;
        let result = drive(&mut installer, &fixture.trust, config(), &mut output,
            || fetch(&url, FETCH_TIMEOUT),
            |_| { waits += 1; waits < 5 },
        );
        server.join().unwrap();
        result.unwrap();
        let records = events(&output);
        let outcomes: Vec<_> = records.iter().map(|record| record["outcome"].as_str().unwrap()).collect();
        assert_eq!(outcomes, ["retrying", "retrying", "installed", "installed", "retrying"]);
        assert_eq!(records[4]["installed_generation"], 8);
        assert_eq!(fs::read_to_string(fixture.path()).unwrap(), next);
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("untrusted-error-body"));
        assert!(!text.contains(url.as_str()));
        assert!(!text.contains(&hex::encode(fixture.owner.to_bytes())));
    }
}
