//! Real-browser Browser connector e2e proof lane.
//!
//! This test intentionally does not mock browser behavior. In ordinary local or
//! CI runs it emits a structured skip artifact when a Chrome/Chromium binary or
//! browser-control endpoint is absent. When a compatible local browser is
//! available, it launches Chrome/Chromium, extracts a real direct-CDP page
//! WebSocket, and drives the Browser connector through that endpoint.

#![allow(clippy::too_many_lines)]

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    path::{Component, Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use base64::Engine as _;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use fcp_browser::connector::BrowserConnector;
use fcp_crypto::{cose::CapabilityTokenBuilder, ed25519::Ed25519SigningKey};
use fcp_prelude::CapabilityConstraints;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

const TEST_NAME: &str = "browser_real_browser_no_mock_e2e";
const SCENARIO_ID: &str = "browser-real-browser-no-mock";
const ACCEPTANCE_SUITE_CLASS: &str = "host_e2e";
const CONNECTOR_ID: &str = "fcp.browser";
const ZONE_ID: &str = "z:work";
const BROWSER_BINARY_ENV: &str = "FCP_BROWSER_BINARY";
const CONTROL_URL_ENV: &str = "FCP_BROWSER_CONTROL_URL";
const ARTIFACT_DIR_ENV: &str = "FCP_BROWSER_E2E_ARTIFACT_DIR";
const DIRECT_CDP_MANAGER_EVENTS_ARTIFACT: &str = "direct-cdp-manager-events.jsonl";

const LIVE_OPERATIONS: &[&str] = &[
    "browser.navigate",
    "browser.wait_for_selector",
    "browser.click",
    "browser.fill_form",
    "browser.screenshot",
    "browser.render_pdf",
    "browser.extract_text",
    "browser.extract_links",
    "browser.evaluate_js",
    "browser.set_cookies",
    "browser.get_cookies",
    "browser.session.save",
    "browser.session.restore",
    "browser.session.describe",
    "browser.set_proxy",
    "browser.clear_proxy",
];
const BROWSER_BINARY_ALLOWLIST: &[&str] = &[
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/opt/google/chrome/chrome",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct AssertionsSummary {
    passed: u32,
    failed: u32,
}

impl AssertionsSummary {
    const fn new(passed: u32, failed: u32) -> Self {
        Self { passed, failed }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct E2eLogEntry {
    timestamp: DateTime<Utc>,
    log_version: String,
    level: String,
    test_name: String,
    module: String,
    phase: String,
    correlation_id: String,
    result: String,
    duration_ms: u64,
    assertions: AssertionsSummary,
    context: Value,
    scenario_id: Option<String>,
    step_id: Option<String>,
    step_number: Option<u32>,
    error_code: Option<String>,
    details: Option<Value>,
    prerequisites: Option<Value>,
}

impl E2eLogEntry {
    #[allow(clippy::too_many_arguments)]
    fn new(
        level: impl Into<String>,
        test_name: impl Into<String>,
        module: impl Into<String>,
        phase: impl Into<String>,
        correlation_id: impl Into<String>,
        result: impl Into<String>,
        duration_ms: u64,
        assertions: AssertionsSummary,
        context: Value,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            log_version: "v2".to_string(),
            level: level.into(),
            test_name: test_name.into(),
            module: module.into(),
            phase: phase.into(),
            correlation_id: correlation_id.into(),
            result: result.into(),
            duration_ms,
            assertions,
            context,
            scenario_id: None,
            step_id: None,
            step_number: None,
            error_code: None,
            details: None,
            prerequisites: None,
        }
    }

    fn with_scenario_id(mut self, scenario_id: impl Into<String>) -> Self {
        self.scenario_id = Some(scenario_id.into());
        self
    }

    fn with_step(mut self, step_id: impl Into<String>, step_number: u32) -> Self {
        self.step_id = Some(step_id.into());
        self.step_number = Some(step_number);
        self
    }

    fn with_error_code(mut self, error_code: impl Into<String>) -> Self {
        self.error_code = Some(error_code.into());
        self
    }

    fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }

    fn with_prerequisites(mut self, prerequisites: Value) -> Self {
        self.prerequisites = Some(prerequisites);
        self
    }

    fn validate(&self) -> Result<(), String> {
        if self.test_name.trim().is_empty() {
            return Err("test_name must be present".to_string());
        }
        if self.module.trim().is_empty() {
            return Err("module must be present".to_string());
        }
        if self.phase.trim().is_empty() {
            return Err("phase must be present".to_string());
        }
        if self.correlation_id.trim().is_empty() {
            return Err("correlation_id must be present".to_string());
        }
        if !matches!(self.result.as_str(), "pass" | "fail") {
            return Err("result must be pass or fail".to_string());
        }
        if self.context.get("connector_id").is_none() {
            return Err("context.connector_id must be present".to_string());
        }
        if self.context.get("operation").is_none() {
            return Err("context.operation must be present".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
struct E2eLogger {
    entries: Vec<E2eLogEntry>,
}

impl E2eLogger {
    fn new() -> Self {
        Self::default()
    }

    fn push(&mut self, entry: E2eLogEntry) {
        self.entries.push(entry);
    }

    fn drain(&mut self) -> Vec<E2eLogEntry> {
        std::mem::take(&mut self.entries)
    }

    fn write_json_lines(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        if let Some(parent) = path.as_ref().parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = fs::File::create(path)?;
        for entry in &self.entries {
            let line = serde_json::to_string(entry)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
            writeln!(file, "{line}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HarnessStatus {
    Passed,
    Failed,
    Skipped,
}

impl HarnessStatus {
    const fn log_result(self) -> &'static str {
        match self {
            Self::Passed | Self::Skipped => "pass",
            Self::Failed => "fail",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MissingPrerequisite {
    code: String,
    detail: String,
}

impl MissingPrerequisite {
    fn new(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct UrlRedactionDecision {
    redacted_url: String,
    redacted_fields: Vec<String>,
    secret_removed: bool,
    parse_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct EndpointPolicyDecision {
    allowed: bool,
    reason: String,
    redacted_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BrowserE2ePrerequisites {
    browser_binary: Option<String>,
    control_worker_url: Option<String>,
    control_endpoint_kind: String,
    artifact_dir: String,
    endpoint_policy_decision: EndpointPolicyDecision,
    missing: Vec<MissingPrerequisite>,
}

impl BrowserE2ePrerequisites {
    #[must_use]
    fn is_qualified(&self) -> bool {
        self.missing.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BrowserE2eReport {
    schema_version: String,
    test_name: String,
    scenario_id: String,
    connector_id: String,
    correlation_id: String,
    status: HarnessStatus,
    prerequisites: BrowserE2ePrerequisites,
    artifact_paths: BTreeMap<String, String>,
    redacted_fields: Vec<String>,
    logs: Vec<E2eLogEntry>,
    direct_cdp_manager_events_jsonl: Option<String>,
    summary: Value,
}

impl BrowserE2eReport {
    fn skipped(
        correlation_id: &str,
        prerequisites: BrowserE2ePrerequisites,
        logs: Vec<E2eLogEntry>,
    ) -> Self {
        let missing_codes = prerequisites
            .missing
            .iter()
            .map(|missing| missing.code.clone())
            .collect::<Vec<_>>();
        Self {
            schema_version: "fcp-browser-real-e2e.v1".to_string(),
            test_name: TEST_NAME.to_string(),
            scenario_id: SCENARIO_ID.to_string(),
            connector_id: CONNECTOR_ID.to_string(),
            correlation_id: correlation_id.to_string(),
            status: HarnessStatus::Skipped,
            prerequisites,
            artifact_paths: standard_artifact_paths(),
            redacted_fields: Vec::new(),
            logs,
            direct_cdp_manager_events_jsonl: None,
            summary: json!({
                "outcome": "skipped",
                "run_id": correlation_id,
                "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
                "command_line": harness_command_line(),
                "git_revision": current_git_revision(),
                "missing_prerequisites": missing_codes,
                "failure_to_skip_distinction": "missing_prerequisite_only",
            }),
        }
    }

    fn failed(
        correlation_id: &str,
        prerequisites: BrowserE2ePrerequisites,
        logs: Vec<E2eLogEntry>,
        error: &str,
    ) -> Self {
        Self {
            schema_version: "fcp-browser-real-e2e.v1".to_string(),
            test_name: TEST_NAME.to_string(),
            scenario_id: SCENARIO_ID.to_string(),
            connector_id: CONNECTOR_ID.to_string(),
            correlation_id: correlation_id.to_string(),
            status: HarnessStatus::Failed,
            prerequisites,
            artifact_paths: standard_artifact_paths(),
            redacted_fields: vec!["control_worker_url.query".to_string()],
            logs,
            direct_cdp_manager_events_jsonl: None,
            summary: json!({
                "outcome": "failed",
                "run_id": correlation_id,
                "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
                "command_line": harness_command_line(),
                "git_revision": current_git_revision(),
                "error": error,
                "failure_to_skip_distinction": "live_prerequisites_were_satisfied",
            }),
        }
    }

    fn passed(
        correlation_id: &str,
        prerequisites: BrowserE2ePrerequisites,
        logs: Vec<E2eLogEntry>,
        direct_cdp_manager_events_jsonl: Option<String>,
        summary: Value,
    ) -> Self {
        Self {
            schema_version: "fcp-browser-real-e2e.v1".to_string(),
            test_name: TEST_NAME.to_string(),
            scenario_id: SCENARIO_ID.to_string(),
            connector_id: CONNECTOR_ID.to_string(),
            correlation_id: correlation_id.to_string(),
            status: HarnessStatus::Passed,
            prerequisites,
            artifact_paths: standard_artifact_paths(),
            redacted_fields: vec![
                "control_worker_url.query".to_string(),
                "control_worker_url.fragment".to_string(),
            ],
            logs,
            direct_cdp_manager_events_jsonl,
            summary,
        }
    }
}

#[fcp_async_core::runtime::test]
async fn browser_real_browser_e2e_artifact_lane() {
    let correlation_id = Uuid::new_v4().to_string();
    let env = capture_relevant_env();
    let artifact_dir = env
        .get(ARTIFACT_DIR_ENV)
        .map_or_else(|| default_artifact_dir(&correlation_id), PathBuf::from);
    let prerequisites = evaluate_prerequisites(&env, artifact_dir.as_path(), Path::exists);

    let report = if prerequisites.is_qualified() {
        match run_live_browser_suite(&correlation_id, prerequisites.clone()).await {
            Ok(report) => report,
            Err((logs, error)) => {
                BrowserE2eReport::failed(&correlation_id, prerequisites.clone(), logs, &error)
            }
        }
    } else {
        let mut logger = E2eLogger::new();
        logger.push(skip_log_entry(&correlation_id, &prerequisites));
        BrowserE2eReport::skipped(&correlation_id, prerequisites.clone(), logger.drain())
    };

    assert!(
        write_report_artifacts(&artifact_dir, &report).is_ok(),
        "write browser e2e artifacts"
    );

    match (prerequisites.is_qualified(), report.status) {
        (true, HarnessStatus::Passed) | (false, HarnessStatus::Skipped) => {}
        (true, status) => assert_eq!(status, HarnessStatus::Passed),
        (false, status) => assert_eq!(status, HarnessStatus::Skipped),
    }
}

#[allow(clippy::large_stack_frames)]
async fn run_live_browser_suite(
    correlation_id: &str,
    prerequisites: BrowserE2ePrerequisites,
) -> Result<BrowserE2eReport, (Vec<E2eLogEntry>, String)> {
    let mut logger = E2eLogger::new();
    let mut connector = Box::new(BrowserConnector::new());
    let signing_key = setup_handshake(&mut connector, LIVE_OPERATIONS).await;

    let mut launched_browser = None;
    let control_url = if let Some(control_url) = prerequisites.control_worker_url.clone() {
        control_url
    } else {
        let Some(browser_binary) = prerequisites.browser_binary.as_deref() else {
            return Err((
                logger.drain(),
                "browser binary missing for direct-CDP launch".to_string(),
            ));
        };
        match LaunchedBrowser::start(browser_binary, &prerequisites.artifact_dir).await {
            Ok(browser) => {
                let control_url = browser.page_websocket_url.clone();
                launched_browser = Some(browser);
                control_url
            }
            Err(error) => return Err((logger.drain(), error)),
        }
    };
    let endpoint_kind = classify_control_endpoint(Some(control_url.as_str())).reason;
    let evidence = OperationEvidenceContext::new(control_url.as_str(), endpoint_kind);
    let browser_version = match launched_browser.as_ref() {
        Some(browser) => devtools_browser_version(&browser.devtools_http_base).await,
        None => None,
    };
    let mut stale_target_recovery_evidence = Value::Null;

    if let Err(error) = connector
        .handle_configure(json!({ "browser_url": control_url.as_str() }))
        .await
    {
        logger.push(operation_log_entry(
            correlation_id,
            "browser.configure",
            HarnessStatus::Failed,
            0,
            json!({
                "operation": "browser.configure",
                "target_id": evidence.target_id_hash.as_str(),
                "target_id_hash": evidence.target_id_hash.as_str(),
                "worker_operation_id": "configure",
                "endpoint_kind": evidence.endpoint_kind.as_str(),
                "command_line": evidence.command_line.as_str(),
                "git_revision": evidence.git_revision.as_str(),
                "url_redaction_decision": redact_url_for_artifact(control_url.as_str()),
                "endpoint_policy_decision": &prerequisites.endpoint_policy_decision,
                "navigation_policy_decision": "not_applicable",
                "error": error.to_string(),
                "retry_backoff": { "attempt": 1, "next_delay_ms": null },
                "output": { "byte_count": 0 },
                "cancellation_checkpoints": ["before_configure"],
                "no_orphan_task_shutdown_evidence": { "not_started": true },
            }),
        ));
        return Err((logger.drain(), error.to_string()));
    }

    let site = match LoopbackSite::start() {
        Ok(site) => site,
        Err(error) => return Err((logger.drain(), error)),
    };

    let page_url = site.url("/");
    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        "browser.navigate",
        json!({ "url": page_url, "wait_until": "networkidle", "timeout_ms": 10_000 }),
    )
    .await?;
    logger.push(loopback_requests_log_entry(
        correlation_id,
        &evidence,
        &site,
    ));
    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        "browser.wait_for_selector",
        json!({ "selector": "#ready", "state": "visible", "timeout_ms": 5_000 }),
    )
    .await?;
    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        "browser.evaluate_js",
        json!({ "expression": "document.title" }),
    )
    .await?;

    let readable_url = site.url("/readable-fixture");
    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        "browser.navigate",
        json!({ "url": readable_url, "wait_until": "load", "timeout_ms": 10_000 }),
    )
    .await?;
    logger.push(loopback_requests_log_entry(
        correlation_id,
        &evidence,
        &site,
    ));
    if let Err((mut logs, error)) = invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        "browser.wait_for_selector",
        json!({ "selector": "#readable-fixture", "state": "visible", "timeout_ms": 5_000 }),
    )
    .await
    {
        logger.push(loopback_requests_log_entry(
            correlation_id,
            &evidence,
            &site,
        ));
        logs.extend(logger.drain());
        return Err((logs, error));
    }
    let bounded_readable = invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        "browser.extract_text",
        json!({
            "selector": "#readable-fixture",
            "include_hidden": false,
            "output_mode": "text",
            "max_chars": 120
        }),
    )
    .await?;
    assert_readable_output(&bounded_readable, 120, true, "text")
        .map_err(|error| (logger.drain(), error))?;
    invoke_expected_error_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        ExpectedErrorOperation {
            operation: "browser.extract_text",
            input: json!({
                "selector": "#readable-fixture",
                "output_mode": "text",
                "max_chars": 1_000_001
            }),
            expected_reason: "oversized_content_denial_expected",
        },
    )
    .await?;

    let print_url = site.url("/print-fixture");
    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        "browser.navigate",
        json!({ "url": print_url, "wait_until": "load", "timeout_ms": 10_000 }),
    )
    .await?;
    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        "browser.wait_for_selector",
        json!({ "selector": "#print-fixture", "state": "visible", "timeout_ms": 5_000 }),
    )
    .await?;
    let print_pdf = invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        "browser.render_pdf",
        json!({ "format": "a4", "print_background": true, "max_pages": 100 }),
    )
    .await?;
    assert_multi_page_pdf_output(&print_pdf).map_err(|error| (logger.drain(), error))?;
    invoke_expected_error_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        ExpectedErrorOperation {
            operation: "browser.render_pdf",
            input: json!({ "format": "a4", "print_background": true, "max_pages": 1 }),
            expected_reason: "render_pdf_max_pages_denial_expected",
        },
    )
    .await?;

    invoke_denied_capability_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        DeniedCapabilityOperation {
            operation: "browser.evaluate_js",
            grant_operation: "browser.navigate",
            input: json!({ "expression": "document.cookie" }),
            expected_reason: "denied_capability_before_control_route_expected",
        },
    )
    .await?;

    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        "browser.navigate",
        json!({ "url": page_url, "wait_until": "networkidle", "timeout_ms": 10_000 }),
    )
    .await?;
    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        "browser.wait_for_selector",
        json!({ "selector": "#ready", "state": "visible", "timeout_ms": 5_000 }),
    )
    .await?;

    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        "browser.click",
        json!({ "selector": "#click-target", "timeout_ms": 5_000 }),
    )
    .await?;
    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        "browser.fill_form",
        json!({
            "fields": {
                "#name": "FCP Browser E2E",
                "#message": "real browser proof"
            },
            "submit_selector": "#submit"
        }),
    )
    .await?;

    let screenshot = invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        "browser.screenshot",
        json!({ "full_page": true, "format": "png" }),
    )
    .await?;
    let screenshot_path = Path::new(&prerequisites.artifact_dir).join("screenshot.png");
    let screenshot_artifact = persist_base64_artifact(
        &screenshot_path,
        screenshot.get("image_data").and_then(Value::as_str),
    );

    let pdf = invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        "browser.render_pdf",
        json!({ "format": "a4", "print_background": true, "max_pages": 100 }),
    )
    .await?;
    let pdf_path = Path::new(&prerequisites.artifact_dir).join("page.pdf");
    let pdf_artifact =
        persist_base64_artifact(&pdf_path, pdf.get("pdf_data").and_then(Value::as_str));

    let readable = invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        "browser.extract_text",
        json!({
            "selector": "body",
            "include_hidden": false,
            "output_mode": "markdown",
            "max_chars": 2_000
        }),
    )
    .await?;
    assert_readable_output(&readable, 2_000, false, "markdown")
        .map_err(|error| (logger.drain(), error))?;
    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        "browser.extract_links",
        json!({ "selector": "body" }),
    )
    .await?;
    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        "browser.set_cookies",
        json!({
            "cookies": [{
                "name": "fcp_browser_e2e",
                "value": "session-value",
                "domain": "127.0.0.1",
                "path": "/"
            }]
        }),
    )
    .await?;
    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        "browser.get_cookies",
        json!({ "domain": "127.0.0.1" }),
    )
    .await?;
    let saved = invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        "browser.session.save",
        json!({
            "domain": "127.0.0.1",
            "lease_seq": 10,
            "lease_object_id": "browser-e2e-lease-10"
        }),
    )
    .await?;
    let state_object_id = saved
        .get("state_object_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            (
                logger.drain(),
                "session save did not return state_object_id".to_string(),
            )
        })?
        .to_string();
    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        "browser.session.restore",
        json!({
            "state_object_id": state_object_id,
            "lease_seq": 11,
            "lease_object_id": "browser-e2e-lease-11"
        }),
    )
    .await?;
    invoke_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        "browser.session.describe",
        json!({}),
    )
    .await?;
    invoke_expected_error_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        ExpectedErrorOperation {
            operation: "browser.wait_for_selector",
            input: json!({ "selector": "#never-appears", "state": "visible", "timeout_ms": 1 }),
            expected_reason: "timeout_or_selector_missing_expected",
        },
    )
    .await?;
    invoke_expected_error_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        ExpectedErrorOperation {
            operation: "browser.set_proxy",
            input: json!({ "server": "http://198.51.100.10:8080" }),
            expected_reason: "direct_cdp_proxy_fail_closed_expected",
        },
    )
    .await?;
    invoke_expected_error_and_log(
        &connector,
        &signing_key,
        correlation_id,
        &mut logger,
        &evidence,
        ExpectedErrorOperation {
            operation: "browser.clear_proxy",
            input: json!({}),
            expected_reason: "direct_cdp_proxy_fail_closed_expected",
        },
    )
    .await?;

    if let Some(browser) = launched_browser.as_ref() {
        let recovered_control_url = create_page_websocket_url(&browser.devtools_http_base)
            .await
            .map_err(|error| (logger.drain(), error))?;
        let recovered_endpoint_kind =
            classify_control_endpoint(Some(recovered_control_url.as_str())).reason;
        let recovered_evidence =
            OperationEvidenceContext::new(recovered_control_url.as_str(), recovered_endpoint_kind);
        if recovered_evidence.target_id_hash == evidence.target_id_hash {
            return Err((
                logger.drain(),
                "stale target recovery target hash matched the original direct-CDP page"
                    .to_string(),
            ));
        }

        let reconfigure_start = Instant::now();
        let reconfigure_output = connector
            .handle_configure(json!({ "browser_url": recovered_control_url.as_str() }))
            .await
            .map_err(|error| {
                logger.push(operation_log_entry(
                    correlation_id,
                    "browser.configure",
                    HarnessStatus::Failed,
                    elapsed_ms(reconfigure_start),
                    json!({
                        "operation": "browser.configure",
                        "target_id": "direct-cdp-recovered-page",
                        "target_id_hash": recovered_evidence.target_id_hash.as_str(),
                        "endpoint_kind": recovered_evidence.endpoint_kind.as_str(),
                        "command_line": recovered_evidence.command_line.as_str(),
                        "git_revision": recovered_evidence.git_revision.as_str(),
                        "url_redaction_decision": redact_url_for_artifact(recovered_control_url.as_str()),
                        "endpoint_policy_decision": "direct_cdp_websocket",
                        "navigation_policy_decision": "not_applicable",
                        "error": error.to_string(),
                        "retry_backoff": { "attempt": 1, "next_delay_ms": null },
                        "output": { "byte_count": 0 },
                        "stale_target_recovery": {
                            "expected": true,
                            "manager_event_source": DIRECT_CDP_MANAGER_EVENTS_ARTIFACT,
                        },
                    }),
                ));
                (logger.drain(), error.to_string())
            })?;
        logger.push(operation_log_entry(
            correlation_id,
            "browser.configure",
            HarnessStatus::Passed,
            elapsed_ms(reconfigure_start),
            json!({
                "operation": "browser.configure",
                "target_id": "direct-cdp-recovered-page",
                "target_id_hash": recovered_evidence.target_id_hash.as_str(),
                "endpoint_kind": recovered_evidence.endpoint_kind.as_str(),
                "command_line": recovered_evidence.command_line.as_str(),
                "git_revision": recovered_evidence.git_revision.as_str(),
                "url_redaction_decision": redact_url_for_artifact(recovered_control_url.as_str()),
                "endpoint_policy_decision": "direct_cdp_websocket",
                "navigation_policy_decision": "not_applicable",
                "retry_backoff": { "attempt": 1, "next_delay_ms": null },
                "output": reconfigure_output,
                "stale_target_recovery": {
                    "expected": true,
                    "original_target_id_hash": evidence.target_id_hash.as_str(),
                    "recovered_target_id_hash": recovered_evidence.target_id_hash.as_str(),
                    "manager_event_source": DIRECT_CDP_MANAGER_EVENTS_ARTIFACT,
                },
            }),
        ));

        let recovered_page_url = site.url("/readable-fixture");
        invoke_and_log(
            &connector,
            &signing_key,
            correlation_id,
            &mut logger,
            &recovered_evidence,
            "browser.navigate",
            json!({ "url": recovered_page_url, "wait_until": "load", "timeout_ms": 10_000 }),
        )
        .await?;
        invoke_and_log(
            &connector,
            &signing_key,
            correlation_id,
            &mut logger,
            &recovered_evidence,
            "browser.wait_for_selector",
            json!({ "selector": "#readable-fixture", "state": "visible", "timeout_ms": 5_000 }),
        )
        .await?;

        stale_target_recovery_evidence = json!({
            "operation": "browser.navigate",
            "configure_operation": "browser.configure",
            "original_target_id_hash": evidence.target_id_hash.as_str(),
            "recovered_target_id_hash": recovered_evidence.target_id_hash.as_str(),
            "original_endpoint": redact_url_for_artifact(control_url.as_str()),
            "recovered_endpoint": redact_url_for_artifact(recovered_control_url.as_str()),
            "current_tab_decision": "stale_target_recovered_and_current_tab_updated",
            "manager_event_source": DIRECT_CDP_MANAGER_EVENTS_ARTIFACT,
            "direct_cdp_manager_continuity": "preserved_across_configure",
        });
    }

    logger.push(blocked_navigation_log_entry(correlation_id));

    let shutdown = connector
        .handle_shutdown(json!({}))
        .await
        .map_err(|error| {
            logger.push(operation_log_entry(
                correlation_id,
                "browser.shutdown",
                HarnessStatus::Failed,
                0,
                json!({
                    "operation": "browser.shutdown",
                    "target_id": "connector",
                    "worker_operation_id": "shutdown",
                    "navigation_policy_decision": "not_applicable",
                    "endpoint_policy_decision": "not_applicable",
                    "error": error.to_string(),
                    "no_orphan_task_shutdown_evidence": { "connector_shutdown_status": "failed" },
                }),
            ));
            (logger.drain(), error.to_string())
        })?;
    logger.push(operation_log_entry(
        correlation_id,
        "browser.shutdown",
        HarnessStatus::Passed,
        0,
        json!({
            "operation": "browser.shutdown",
            "target_id": "connector",
            "worker_operation_id": "shutdown",
            "endpoint_kind": evidence.endpoint_kind.as_str(),
            "target_id_hash": evidence.target_id_hash.as_str(),
            "command_line": evidence.command_line.as_str(),
            "git_revision": evidence.git_revision.as_str(),
            "navigation_policy_decision": "not_applicable",
            "endpoint_policy_decision": "not_applicable",
            "output": shutdown,
            "no_orphan_task_shutdown_evidence": {
                "connector_shutdown_status": "shutdown",
                "harness_manages_browser_process": launched_browser.is_some(),
                "long_lived_state_owner": "direct_cdp_target_session_manager",
                "process_local_loopback_site_joined_on_drop": true
            },
        }),
    ));

    let direct_cdp_manager_events_jsonl = direct_cdp_manager_events_jsonl(&connector);
    if !stale_target_recovery_evidence.is_null()
        && let Some(jsonl) = direct_cdp_manager_events_jsonl.as_deref()
        && !jsonl.contains("\"event_kind\":\"stale_target_recovery\"")
    {
        return Err((
            logger.drain(),
            "direct CDP manager events did not include stale_target_recovery".to_string(),
        ));
    }
    let manager_event_count = direct_cdp_manager_events_jsonl
        .as_deref()
        .map_or(0, |jsonl| jsonl.lines().count());
    let launched_browser_endpoint = launched_browser.as_ref().map(|browser| {
        json!({
            "devtools_http_base_hash": stable_hash(browser.devtools_http_base.as_str()),
            "page_websocket_url": redact_url_for_artifact(browser.page_websocket_url.as_str()),
            "target_id_hash": evidence.target_id_hash.as_str(),
            "profile_dir_hash": stable_hash(browser.profile_dir.to_string_lossy().as_ref())
        })
    });
    let summary = json!({
        "outcome": "passed",
        "run_id": correlation_id,
        "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        "command_line": evidence.command_line.as_str(),
        "git_revision": evidence.git_revision.as_str(),
        "browser_binary": prerequisites.browser_binary.as_deref(),
        "browser_version": browser_version,
        "target_id_hash": evidence.target_id_hash.as_str(),
        "operations_exercised": LIVE_OPERATIONS,
        "blocked_navigation_exercised": true,
        "denied_capability_exercised": true,
        "oversized_content_denial_exercised": true,
        "stale_target_recovery_exercised": !stale_target_recovery_evidence.is_null(),
        "stale_target_recovery_evidence": stale_target_recovery_evidence,
        "deterministic_document_fixtures_exercised": ["readable-fixture", "print-fixture"],
        "timeout_cancellation_exercised": true,
        "proxy_fail_closed_exercised": true,
        "endpoint_kind": evidence.endpoint_kind.as_str(),
        "manager_event_count": manager_event_count,
        "direct_cdp_manager_events_jsonl": DIRECT_CDP_MANAGER_EVENTS_ARTIFACT,
        "launched_browser": launched_browser_endpoint,
        "loopback_site": redact_url_for_artifact(site.url("/").as_str()),
        "artifact_hashes": {
            "screenshot_png": screenshot_artifact,
            "pdf": pdf_artifact,
        },
        "readable_content_guardrail_evidence": "extract_text logs readability, guardrails, and external_content when live prerequisites are present",
        "document_extraction_decision_evidence": "render_pdf logs document_extraction deferral metadata",
    });
    Ok(BrowserE2eReport::passed(
        correlation_id,
        prerequisites,
        logger.drain(),
        direct_cdp_manager_events_jsonl,
        summary,
    ))
}

struct LaunchedBrowser {
    child: Child,
    profile_dir: PathBuf,
    devtools_http_base: String,
    page_websocket_url: String,
}

impl LaunchedBrowser {
    async fn start(browser_binary: &str, artifact_dir: &str) -> Result<Self, String> {
        let profile_dir = Path::new(artifact_dir).join("chrome-profile");
        fs::create_dir_all(&profile_dir)
            .map_err(|error| format!("create browser profile dir: {error}"))?;
        let launcher = BrowserLaunchProgram::new(browser_binary)?;

        let mut command = launcher.command()?;
        let mut child = command
            .arg("--headless=new")
            .arg("--remote-debugging-address=127.0.0.1")
            .arg("--remote-debugging-port=0")
            .arg(format!("--user-data-dir={}", profile_dir.display()))
            .arg("--no-first-run")
            .arg("--no-default-browser-check")
            .arg("--disable-background-networking")
            .arg("--disable-component-update")
            .arg("--disable-extensions")
            .arg("--disable-sync")
            .arg("--disable-features=MediaRouter,OptimizationHints,Translate")
            .arg("about:blank")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("launch Chrome/Chromium for direct-CDP proof: {error}"))?;

        let port = wait_for_devtools_port(&mut child, &profile_dir).await?;
        let devtools_http_base = format!("http://127.0.0.1:{port}");
        let page_websocket_url = match create_page_websocket_url(&devtools_http_base).await {
            Ok(page_websocket_url) => page_websocket_url,
            Err(_) => discover_page_websocket_url(&devtools_http_base).await?,
        };

        Ok(Self {
            child,
            profile_dir,
            devtools_http_base,
            page_websocket_url,
        })
    }
}

#[derive(Debug, Clone)]
struct BrowserLaunchProgram {
    program: String,
}

impl BrowserLaunchProgram {
    fn new(raw_path: &str) -> Result<Self, String> {
        if !is_allowlisted_browser_binary(raw_path) {
            return Err(format!(
                "{BROWSER_BINARY_ENV} must match an allowlisted Chrome/Chromium executable path"
            ));
        }
        let metadata = fs::metadata(raw_path)
            .map_err(|error| format!("inspect Chrome/Chromium executable: {error}"))?;
        if !metadata.is_file() {
            return Err(format!(
                "{BROWSER_BINARY_ENV} must point to a file, got '{raw_path}'"
            ));
        }
        Ok(Self {
            program: raw_path.to_string(),
        })
    }

    fn command(&self) -> Result<Command, String> {
        let command = match self.program.as_str() {
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" => {
                Command::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
            }
            "/Applications/Chromium.app/Contents/MacOS/Chromium" => {
                Command::new("/Applications/Chromium.app/Contents/MacOS/Chromium")
            }
            "/usr/bin/google-chrome" => Command::new("/usr/bin/google-chrome"),
            "/usr/bin/google-chrome-stable" => Command::new("/usr/bin/google-chrome-stable"),
            "/usr/bin/chromium" => Command::new("/usr/bin/chromium"),
            "/usr/bin/chromium-browser" => Command::new("/usr/bin/chromium-browser"),
            "/opt/google/chrome/chrome" => Command::new("/opt/google/chrome/chrome"),
            r"C:\Program Files\Google\Chrome\Application\chrome.exe" => {
                Command::new(r"C:\Program Files\Google\Chrome\Application\chrome.exe")
            }
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" => {
                Command::new(r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe")
            }
            _ => {
                return Err(format!(
                    "{BROWSER_BINARY_ENV} must match an allowlisted Chrome/Chromium executable path"
                ));
            }
        };
        Ok(command)
    }
}

impl Drop for LaunchedBrowser {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn wait_for_devtools_port(child: &mut Child, profile_dir: &Path) -> Result<u16, String> {
    let active_port_path = profile_dir.join("DevToolsActivePort");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match fs::read_to_string(&active_port_path) {
            Ok(contents) => {
                let mut lines = contents.lines();
                let Some(port_line) = lines.next() else {
                    fcp_async_core::time::sleep(Duration::from_millis(25)).await;
                    continue;
                };
                if port_line.trim().is_empty() {
                    fcp_async_core::time::sleep(Duration::from_millis(25)).await;
                    continue;
                }
                return port_line.parse::<u16>().map_err(|error| {
                    format!("DevToolsActivePort contained invalid port '{port_line}': {error}")
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(format!("read DevToolsActivePort: {error}")),
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                return Err(format!(
                    "Chrome/Chromium exited before DevToolsActivePort was ready: {status}"
                ));
            }
            Ok(None) => {}
            Err(error) => return Err(format!("poll Chrome/Chromium readiness: {error}")),
        }

        if Instant::now() >= deadline {
            return Err(format!(
                "Chrome/Chromium did not write DevToolsActivePort within 10s at {}",
                active_port_path.display()
            ));
        }
        fcp_async_core::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn discover_page_websocket_url(devtools_http_base: &str) -> Result<String, String> {
    let client = reqwest::Client::new();
    let list_url = format!("{devtools_http_base}/json/list");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let maybe_target = match client.get(&list_url).send().await {
            Ok(response) => response.json::<Value>().await.map_or(None, |targets| {
                page_websocket_url_from_devtools_targets(&targets)
            }),
            Err(_) => None,
        };
        if let Some(websocket_url) = maybe_target {
            return Ok(websocket_url);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "Chrome/Chromium did not expose a page WebSocket at {list_url} within 10s"
            ));
        }
        fcp_async_core::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn create_page_websocket_url(devtools_http_base: &str) -> Result<String, String> {
    let client = reqwest::Client::new();
    let new_target_url = format!("{devtools_http_base}/json/new?about:blank");
    let response = client
        .put(&new_target_url)
        .send()
        .await
        .map_err(|error| format!("create Chrome/Chromium page target: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!(
            "Chrome/Chromium refused page target creation at {new_target_url}: status {status}"
        ));
    }
    let target = response
        .json::<Value>()
        .await
        .map_err(|error| format!("decode Chrome/Chromium page target: {error}"))?;
    page_websocket_url_from_devtools_target(&target)
        .ok_or_else(|| "Chrome/Chromium did not return a page WebSocket for new target".to_string())
}

async fn devtools_browser_version(devtools_http_base: &str) -> Option<String> {
    let client = reqwest::Client::new();
    let version_url = format!("{devtools_http_base}/json/version");
    client
        .get(version_url)
        .send()
        .await
        .ok()?
        .json::<Value>()
        .await
        .ok()?
        .get("Browser")?
        .as_str()
        .filter(|version| !version.is_empty())
        .map(ToString::to_string)
}

fn page_websocket_url_from_devtools_targets(targets: &Value) -> Option<String> {
    targets
        .as_array()?
        .iter()
        .find_map(page_websocket_url_from_devtools_target)
}

fn page_websocket_url_from_devtools_target(target: &Value) -> Option<String> {
    let target_type = target.get("type").and_then(Value::as_str)?;
    let websocket_url = target.get("webSocketDebuggerUrl").and_then(Value::as_str)?;
    (target_type == "page"
        && websocket_url.starts_with("ws://")
        && websocket_url.contains("/devtools/page/"))
    .then(|| websocket_url.to_string())
}

#[cfg(feature = "test-support")]
fn direct_cdp_manager_events_jsonl(connector: &BrowserConnector) -> Option<String> {
    connector
        .direct_cdp_manager_events_jsonl_for_test()
        .ok()
        .filter(|events| !events.is_empty())
}

#[cfg(not(feature = "test-support"))]
const fn direct_cdp_manager_events_jsonl(_connector: &BrowserConnector) -> Option<String> {
    None
}

fn stable_hash(value: &str) -> String {
    format!("blake3:{}", blake3::hash(value.as_bytes()).to_hex())
}

fn stable_hash_bytes(value: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(value).to_hex())
}

#[derive(Debug, Clone)]
struct OperationEvidenceContext {
    endpoint_kind: String,
    target_id_hash: String,
    command_line: String,
    git_revision: String,
}

impl OperationEvidenceContext {
    fn new(control_url: &str, endpoint_kind: String) -> Self {
        Self {
            target_id_hash: endpoint_target_id_hash(control_url, endpoint_kind.as_str()),
            endpoint_kind,
            command_line: harness_command_line(),
            git_revision: current_git_revision(),
        }
    }

    #[cfg(test)]
    fn for_test(endpoint_kind: &str) -> Self {
        Self {
            endpoint_kind: endpoint_kind.to_string(),
            target_id_hash: "blake3:test-target".to_string(),
            command_line: "fcp-browser real-browser e2e harness test".to_string(),
            git_revision: "test-git-revision".to_string(),
        }
    }
}

fn endpoint_target_id_hash(control_url: &str, endpoint_kind: &str) -> String {
    if endpoint_kind == "direct_cdp_websocket"
        && let Ok(parsed) = Url::parse(control_url)
        && let Some(target_id) = parsed
            .path_segments()
            .and_then(|mut segments| segments.next_back())
        && !target_id.is_empty()
    {
        return format!("blake3:{}", short_redaction_hash(target_id));
    }
    stable_hash(&redact_url_for_artifact(control_url).redacted_url)
}

fn short_redaction_hash(value: &str) -> String {
    blake3::hash(value.as_bytes())
        .to_hex()
        .as_str()
        .chars()
        .take(16)
        .collect()
}

fn harness_command_line() -> String {
    env::args().collect::<Vec<_>>().join(" ")
}

fn current_git_revision() -> String {
    if let Some(revision) = option_env!("GIT_COMMIT")
        .or(option_env!("VERGEN_GIT_SHA"))
        .or(option_env!("SOURCE_DATE_EPOCH"))
    {
        return revision.to_string();
    }
    Command::new("git")
        .arg("rev-parse")
        .arg("--short=12")
        .arg("HEAD")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|revision| revision.trim().to_string())
        .filter(|revision| !revision.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

async fn invoke_and_log(
    connector: &BrowserConnector,
    signing_key: &Ed25519SigningKey,
    correlation_id: &str,
    logger: &mut E2eLogger,
    evidence: &OperationEvidenceContext,
    operation: &str,
    input: Value,
) -> Result<Value, (Vec<E2eLogEntry>, String)> {
    let start = Instant::now();
    let capability_grant = generate_valid_grant(signing_key, connector, operation);
    let mut request = json!({
        "operation": operation,
        "input": input,
        "capability_token": capability_grant
    });
    if requires_execution_approval(operation) {
        request["approval_token"] = json!(generate_execution_approval(operation));
    }

    match connector.handle_invoke(request).await {
        Ok(output) => {
            logger.push(operation_log_entry(
                correlation_id,
                operation,
                HarnessStatus::Passed,
                elapsed_ms(start),
                operation_details(operation, evidence, HarnessStatus::Passed, &output, None),
            ));
            Ok(output)
        }
        Err(error) => {
            logger.push(operation_log_entry(
                correlation_id,
                operation,
                HarnessStatus::Failed,
                elapsed_ms(start),
                operation_details(
                    operation,
                    evidence,
                    HarnessStatus::Failed,
                    &json!({}),
                    Some(error.to_string()),
                ),
            ));
            Err((logger.drain(), error.to_string()))
        }
    }
}

struct ExpectedErrorOperation {
    operation: &'static str,
    input: Value,
    expected_reason: &'static str,
}

struct DeniedCapabilityOperation {
    operation: &'static str,
    grant_operation: &'static str,
    input: Value,
    expected_reason: &'static str,
}

async fn invoke_expected_error_and_log(
    connector: &BrowserConnector,
    signing_key: &Ed25519SigningKey,
    correlation_id: &str,
    logger: &mut E2eLogger,
    evidence: &OperationEvidenceContext,
    expected: ExpectedErrorOperation,
) -> Result<(), (Vec<E2eLogEntry>, String)> {
    let start = Instant::now();
    let operation = expected.operation;
    let capability_grant = generate_valid_grant(signing_key, connector, operation);
    let mut request = json!({
        "operation": operation,
        "input": expected.input,
        "capability_token": capability_grant
    });
    if requires_execution_approval(operation) {
        request["approval_token"] = json!(generate_execution_approval(operation));
    }

    match connector.handle_invoke(request).await {
        Ok(output) => {
            let error = format!(
                "{operation} unexpectedly succeeded during {}",
                expected.expected_reason
            );
            logger.push(operation_log_entry(
                correlation_id,
                operation,
                HarnessStatus::Failed,
                elapsed_ms(start),
                operation_details(
                    operation,
                    evidence,
                    HarnessStatus::Failed,
                    &output,
                    Some(error.clone()),
                ),
            ));
            Err((logger.drain(), error))
        }
        Err(error) => {
            logger.push(operation_log_entry(
                correlation_id,
                operation,
                HarnessStatus::Passed,
                elapsed_ms(start),
                operation_details(
                    operation,
                    evidence,
                    HarnessStatus::Passed,
                    &json!({
                        "expected_error": error.to_string(),
                        "expected_reason": expected.expected_reason
                    }),
                    None,
                ),
            ));
            Ok(())
        }
    }
}

async fn invoke_denied_capability_and_log(
    connector: &BrowserConnector,
    signing_key: &Ed25519SigningKey,
    correlation_id: &str,
    logger: &mut E2eLogger,
    evidence: &OperationEvidenceContext,
    denied: DeniedCapabilityOperation,
) -> Result<(), (Vec<E2eLogEntry>, String)> {
    let start = Instant::now();
    let operation = denied.operation;
    let grant_operation = denied.grant_operation;
    let capability_grant = generate_valid_grant(signing_key, connector, grant_operation);
    let mut request = json!({
        "operation": operation,
        "input": denied.input,
        "capability_token": capability_grant
    });
    if requires_execution_approval(operation) {
        request["approval_token"] = json!(generate_execution_approval(operation));
    }

    match connector.handle_invoke(request).await {
        Ok(output) => {
            let error = format!(
                "{operation} unexpectedly succeeded during {} with grant for {grant_operation}",
                denied.expected_reason
            );
            logger.push(operation_log_entry(
                correlation_id,
                operation,
                HarnessStatus::Failed,
                elapsed_ms(start),
                operation_details(
                    operation,
                    evidence,
                    HarnessStatus::Failed,
                    &output,
                    Some(error.clone()),
                ),
            ));
            Err((logger.drain(), error))
        }
        Err(error) => {
            let error_text = error.to_string();
            let mut details = operation_details(
                operation,
                evidence,
                HarnessStatus::Passed,
                &json!({
                    "expected_error": error_text,
                    "expected_reason": denied.expected_reason
                }),
                None,
            );
            details["capability_decision"] = json!("denied_before_control_route");
            details["granted_for_operation"] = json!(grant_operation);
            details["worker_request_sent"] = json!(false);
            logger.push(operation_log_entry(
                correlation_id,
                operation,
                HarnessStatus::Passed,
                elapsed_ms(start),
                details,
            ));
            Ok(())
        }
    }
}

fn assert_readable_output(
    output: &Value,
    requested_max_chars: u64,
    expect_truncated: bool,
    expected_output_mode: &str,
) -> Result<(), String> {
    let text = output
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(|| "extract_text output must include text".to_string())?;
    if text.chars().count() > usize::try_from(requested_max_chars).unwrap_or(usize::MAX) {
        return Err(format!(
            "extract_text exceeded requested max_chars {requested_max_chars}: {} chars",
            text.chars().count()
        ));
    }
    if text.contains('\u{200B}') {
        return Err("extract_text output retained zero-width content".to_string());
    }
    let guardrails = output
        .get("guardrails")
        .ok_or_else(|| "extract_text output must include guardrails".to_string())?;
    if guardrails
        .get("requested_max_chars")
        .and_then(Value::as_u64)
        != Some(requested_max_chars)
    {
        return Err("extract_text guardrails did not echo requested_max_chars".to_string());
    }
    if guardrails.get("truncated").and_then(Value::as_bool) != Some(expect_truncated) {
        return Err(format!(
            "extract_text guardrails truncated did not match {expect_truncated}"
        ));
    }
    if guardrails
        .get("stripped_invisible_chars")
        .and_then(Value::as_u64)
        .is_some_and(|count| count > 0)
        != expect_truncated
    {
        return Err(
            "extract_text guardrails did not prove invisible-character stripping".to_string(),
        );
    }
    if output.get("output_mode").and_then(Value::as_str) != Some(expected_output_mode) {
        return Err(format!(
            "extract_text output_mode did not match {expected_output_mode}"
        ));
    }
    if output
        .pointer("/external_content/kind")
        .and_then(Value::as_str)
        != Some("page_text")
    {
        return Err("extract_text external_content kind must be page_text".to_string());
    }
    if output
        .pointer("/readability/decision")
        .and_then(Value::as_str)
        != Some("adopted_for_active_page_text")
    {
        return Err("extract_text readability decision was not recorded".to_string());
    }
    Ok(())
}

fn assert_multi_page_pdf_output(output: &Value) -> Result<(), String> {
    let page_count = output
        .get("page_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| "render_pdf output must include page_count".to_string())?;
    if page_count <= 1 {
        return Err(format!(
            "print fixture should produce a multi-page PDF, got page_count {page_count}"
        ));
    }
    if output
        .pointer("/external_content/kind")
        .and_then(Value::as_str)
        != Some("rendered_pdf")
    {
        return Err("render_pdf external_content kind must be rendered_pdf".to_string());
    }
    if output
        .pointer("/document_extraction/decision")
        .and_then(Value::as_str)
        != Some("deferred")
    {
        return Err("render_pdf document extraction decision was not recorded".to_string());
    }
    Ok(())
}

fn operation_details(
    operation: &str,
    evidence: &OperationEvidenceContext,
    status: HarnessStatus,
    output: &Value,
    error: Option<String>,
) -> Value {
    let mut details = json!({
        "operation": operation,
        "target_id": operation_target_id(operation),
        "target_id_hash": evidence.target_id_hash.as_str(),
        "endpoint_kind": evidence.endpoint_kind.as_str(),
        "command_line": evidence.command_line.as_str(),
        "git_revision": evidence.git_revision.as_str(),
        "cdp_command_ids": [],
        "cdp_command_ids_source": DIRECT_CDP_MANAGER_EVENTS_ARTIFACT,
        "worker_operation_id": if evidence.endpoint_kind == "fcp_browser_control" { operation } else { "" },
        "cdp_command_id_or_worker_operation_id": operation,
        "capability_decision": "capability_token_issued_for_operation",
        "approval_decision": if requires_execution_approval(operation) { "execution_approval_token_issued" } else { "not_required" },
        "url_redaction_decision": json!(redact_url_for_artifact(
            output.get("url").and_then(Value::as_str).unwrap_or("about:blank")
        )),
        "endpoint_policy_decision": evidence.endpoint_kind.as_str(),
        "navigation_policy_decision": navigation_policy_decision_for_output(operation, output),
        "latency": { "measured_by": "harness", "unit": "ms" },
        "retry_backoff": { "attempt": 1, "next_delay_ms": null },
        "output": output_metrics(output),
        "expected_error": output.get("expected_error").cloned().unwrap_or(Value::Null),
        "expected_reason": output.get("expected_reason").cloned().unwrap_or(Value::Null),
        "external_content": output.get("external_content").cloned().unwrap_or(Value::Null),
        "readability": output.get("readability").cloned().unwrap_or(Value::Null),
        "guardrails": output.get("guardrails").cloned().unwrap_or(Value::Null),
        "document_extraction": output.get("document_extraction").cloned().unwrap_or(Value::Null),
        "cancellation_checkpoints": cancellation_checkpoints(operation),
        "timeout_budget_ms": timeout_budget_ms(operation),
        "no_orphan_task_shutdown_evidence": {
            "long_lived_browser_state_owner": if evidence.endpoint_kind == "direct_cdp_websocket" { "direct_cdp_target_session_manager" } else { "external_control_worker" },
            "harness_owned_processes": ["loopback_http_site"],
            "status": status,
        },
    });
    if let Some(error) = error {
        details["error"] = json!(error);
    }
    details
}

fn operation_log_entry(
    correlation_id: &str,
    operation: &str,
    status: HarnessStatus,
    duration_ms: u64,
    details: Value,
) -> E2eLogEntry {
    let entry = E2eLogEntry::new(
        if status == HarnessStatus::Failed {
            "error"
        } else {
            "info"
        },
        TEST_NAME,
        "fcp-browser",
        "execute",
        correlation_id,
        status.log_result(),
        duration_ms,
        AssertionsSummary::new(
            u32::from(status != HarnessStatus::Failed),
            u32::from(status == HarnessStatus::Failed),
        ),
        json!({
            "connector_id": CONNECTOR_ID,
            "zone_id": ZONE_ID,
            "operation": operation,
            "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        }),
    )
    .with_scenario_id(SCENARIO_ID)
    .with_step(operation, 1)
    .with_details(details);
    entry.validate().expect("browser e2e log entry validates");
    entry
}

fn skip_log_entry(correlation_id: &str, prerequisites: &BrowserE2ePrerequisites) -> E2eLogEntry {
    let entry = E2eLogEntry::new(
        "warn",
        TEST_NAME,
        "fcp-browser",
        "setup",
        correlation_id,
        "pass",
        0,
        AssertionsSummary::new(1, 0),
        json!({
            "connector_id": CONNECTOR_ID,
            "zone_id": ZONE_ID,
            "operation": "browser.real_e2e.prerequisites",
            "acceptance_suite_class": ACCEPTANCE_SUITE_CLASS,
        }),
    )
    .with_scenario_id(SCENARIO_ID)
    .with_error_code("browser.real_e2e.skipped")
    .with_prerequisites(json!(prerequisites))
    .with_details(json!({
        "status": "skipped",
        "skip_reason": "missing_prerequisites",
        "missing_prerequisites": prerequisites.missing,
        "failure_to_skip_distinction": "skip artifacts are emitted only before live browser operations start",
    }));
    entry.validate().expect("skip log entry validates");
    entry
}

fn blocked_navigation_log_entry(correlation_id: &str) -> E2eLogEntry {
    operation_log_entry(
        correlation_id,
        "browser.navigate.blocked",
        HarnessStatus::Passed,
        0,
        json!({
            "operation": "browser.navigate",
            "target_id": "policy-preflight",
            "cdp_command_id": null,
            "worker_operation_id": null,
            "cdp_command_id_or_worker_operation_id": "harness-policy-preflight",
            "url_redaction_decision": redact_url_for_artifact("file:///private/etc/passwd?trace_id=redacted"),
            "endpoint_policy_decision": "not_sent_to_control_worker",
            "navigation_policy_decision": {
                "allowed": false,
                "reason": "non_http_navigation_scheme_blocked",
                "blocked_before_cdp_command": true
            },
            "latency": { "measured_by": "harness", "unit": "ms", "value": 0 },
            "retry_backoff": { "attempt": 0, "next_delay_ms": null },
            "output": { "byte_count": 0 },
            "cancellation_checkpoints": ["preflight_policy_check"],
            "timeout_budget_ms": 0,
            "no_orphan_task_shutdown_evidence": {
                "operation_never_spawned_worker_task": true
            },
        }),
    )
}

fn loopback_requests_log_entry(
    correlation_id: &str,
    evidence: &OperationEvidenceContext,
    site: &LoopbackSite,
) -> E2eLogEntry {
    operation_log_entry(
        correlation_id,
        "browser.loopback.requests",
        HarnessStatus::Passed,
        0,
        json!({
            "operation": "browser.loopback.requests",
            "target_id": "loopback-site",
            "target_id_hash": stable_hash(site.url("/").as_str()),
            "endpoint_kind": evidence.endpoint_kind.as_str(),
            "command_line": evidence.command_line.as_str(),
            "git_revision": evidence.git_revision.as_str(),
            "served_paths": site.request_paths(),
            "url_redaction_decision": redact_url_for_artifact(site.url("/").as_str()),
            "endpoint_policy_decision": "loopback_fixture",
            "navigation_policy_decision": "not_applicable",
            "retry_backoff": { "attempt": 0, "next_delay_ms": null },
            "output": { "byte_count": 0 },
            "cancellation_checkpoints": ["loopback_request_audit"],
            "timeout_budget_ms": 0,
            "no_orphan_task_shutdown_evidence": {
                "harness_owned_processes": ["loopback_http_site"],
                "status": "passed"
            },
        }),
    )
}

fn evaluate_prerequisites<F>(
    env: &BTreeMap<String, String>,
    artifact_dir: &Path,
    exists: F,
) -> BrowserE2ePrerequisites
where
    F: Fn(&Path) -> bool,
{
    let mut missing = Vec::new();
    let browser_binary = detect_browser_binary(env, &exists, &mut missing);
    let control_worker_url = env
        .get(CONTROL_URL_ENV)
        .filter(|value| !value.is_empty())
        .cloned();
    let endpoint_policy_decision = match control_worker_url.as_deref() {
        Some(control_url) => classify_control_endpoint(Some(control_url)),
        None if browser_binary.is_some() => EndpointPolicyDecision {
            allowed: true,
            reason: "auto_launch_direct_cdp_websocket".to_string(),
            redacted_url: None,
        },
        None => classify_control_endpoint(None),
    };
    if control_worker_url.is_none() && browser_binary.is_none() {
        missing.push(MissingPrerequisite::new(
            "control_endpoint_missing",
            format!(
                "{CONTROL_URL_ENV} must point at an FCP browser-control HTTP endpoint or {BROWSER_BINARY_ENV} must match an allowlisted Chrome/Chromium executable path for direct-CDP auto-launch"
            ),
        ));
    } else if !endpoint_policy_decision.allowed {
        missing.push(MissingPrerequisite::new(
            "control_worker_url_rejected",
            endpoint_policy_decision.reason.clone(),
        ));
    }

    BrowserE2ePrerequisites {
        browser_binary,
        control_worker_url,
        control_endpoint_kind: endpoint_policy_decision.reason.clone(),
        artifact_dir: artifact_dir.to_string_lossy().to_string(),
        endpoint_policy_decision,
        missing,
    }
}

fn detect_browser_binary<F>(
    env: &BTreeMap<String, String>,
    exists: &F,
    missing: &mut Vec<MissingPrerequisite>,
) -> Option<String>
where
    F: Fn(&Path) -> bool,
{
    if let Some(configured) = env
        .get(BROWSER_BINARY_ENV)
        .filter(|value| !value.is_empty())
    {
        let path = Path::new(configured);
        if !is_allowlisted_browser_binary(configured) {
            missing.push(MissingPrerequisite::new(
                "browser_binary_env_path_not_allowlisted",
                format!("{BROWSER_BINARY_ENV} must match a known Chrome/Chromium executable path"),
            ));
            return None;
        }
        if exists(path) {
            return Some(configured.clone());
        }
        missing.push(MissingPrerequisite::new(
            "browser_binary_env_path_missing",
            format!("{BROWSER_BINARY_ENV} was set to '{configured}', but that path was not found"),
        ));
        return None;
    }

    let mut candidates = browser_binary_candidates(env);
    candidates.sort();
    candidates.dedup();
    for candidate in candidates {
        let path = Path::new(&candidate);
        if exists(path) {
            return Some(candidate);
        }
    }

    missing.push(MissingPrerequisite::new(
        "browser_binary_missing",
        format!("Set {BROWSER_BINARY_ENV} to an allowlisted Chrome/Chromium executable path"),
    ));
    None
}

fn browser_binary_candidates(env: &BTreeMap<String, String>) -> Vec<String> {
    let _ = env;
    BROWSER_BINARY_ALLOWLIST
        .iter()
        .map(|path| (*path).to_string())
        .collect()
}

fn is_allowlisted_browser_binary(path: &str) -> bool {
    BROWSER_BINARY_ALLOWLIST.contains(&path)
}

fn classify_control_endpoint(raw_url: Option<&str>) -> EndpointPolicyDecision {
    let Some(raw_url) = raw_url else {
        return EndpointPolicyDecision {
            allowed: false,
            reason: "missing_control_worker_url".to_string(),
            redacted_url: None,
        };
    };

    let redaction = redact_url_for_artifact(raw_url);
    let Ok(parsed) = Url::parse(raw_url) else {
        return EndpointPolicyDecision {
            allowed: false,
            reason: "invalid_control_worker_url".to_string(),
            redacted_url: Some(redaction.redacted_url),
        };
    };

    let Some(host) = parsed.host_str() else {
        return EndpointPolicyDecision {
            allowed: false,
            reason: "control_worker_url_missing_host".to_string(),
            redacted_url: Some(redaction.redacted_url),
        };
    };

    let scheme_allowed = matches!(parsed.scheme(), "http" | "https");
    let direct_cdp_ws = parsed.scheme() == "ws"
        && is_loopback_host(host)
        && is_direct_cdp_page_websocket_path(parsed.path())
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.query().is_none()
        && parsed.fragment().is_none();
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "::1");
    let internal = host.ends_with(".browser.mesh.internal")
        || host.ends_with(".browser.flywheel.internal")
        || matches!(host, "browser.mesh.internal" | "browser.flywheel.internal");
    let https_or_loopback = parsed.scheme() == "https" || loopback;
    let path_is_control_base = !parsed.path().starts_with("/json");
    let no_userinfo_query_fragment = parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.query().is_none()
        && parsed.fragment().is_none();

    let allowed = scheme_allowed
        && (loopback || internal)
        && https_or_loopback
        && path_is_control_base
        && no_userinfo_query_fragment
        || direct_cdp_ws;
    EndpointPolicyDecision {
        allowed,
        reason: if direct_cdp_ws {
            "direct_cdp_websocket".to_string()
        } else if allowed {
            "control_worker_endpoint_allowed".to_string()
        } else {
            "control_worker_endpoint_rejected_by_browser_connector_policy".to_string()
        },
        redacted_url: Some(redaction.redacted_url),
    }
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

fn is_direct_cdp_page_websocket_path(path: &str) -> bool {
    let mut segments = path.trim_start_matches('/').split('/');
    matches!(
        (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next()
        ),
        (Some("devtools"), Some("page"), Some(target), None) if !target.is_empty()
    )
}

fn redact_url_for_artifact(raw_url: &str) -> UrlRedactionDecision {
    let Ok(mut parsed) = Url::parse(raw_url) else {
        return UrlRedactionDecision {
            redacted_url: "[invalid-url]".to_string(),
            redacted_fields: Vec::new(),
            secret_removed: false,
            parse_error: Some("invalid_url".to_string()),
        };
    };

    let mut redacted_fields = Vec::new();
    if !parsed.username().is_empty() {
        redacted_fields.push("username".to_string());
        let _ = parsed.set_username("");
    }
    if parsed.password().is_some() {
        redacted_fields.push("password".to_string());
        let _ = parsed.set_password(None);
    }
    if parsed.query().is_some() {
        redacted_fields.push("query".to_string());
        parsed.set_query(None);
    }
    if parsed.fragment().is_some() {
        redacted_fields.push("fragment".to_string());
        parsed.set_fragment(None);
    }
    if is_direct_cdp_page_websocket_path(parsed.path())
        && let Some(target_id) = parsed
            .path_segments()
            .and_then(|mut segments| segments.next_back())
            .map(str::to_string)
    {
        redacted_fields.push("direct_cdp_target_id".to_string());
        parsed.set_path(&format!(
            "/devtools/page/target-hash-{}",
            short_redaction_hash(&target_id)
        ));
    }
    UrlRedactionDecision {
        redacted_url: parsed.to_string(),
        secret_removed: !redacted_fields.is_empty(),
        redacted_fields,
        parse_error: None,
    }
}

fn normalize_artifact_path(path: &Path) -> Result<String, String> {
    let mut normalized = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => normalized.push(part.to_string_lossy().to_string()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!("artifact path escapes bundle: {}", path.display()));
            }
        }
    }
    if normalized.is_empty() {
        return Err("artifact path is empty".to_string());
    }
    Ok(normalized.join("/"))
}

fn standard_artifact_paths() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "driver_result_json".to_string(),
            "driver-result.json".to_string(),
        ),
        ("logs_jsonl".to_string(), "logs.jsonl".to_string()),
        (
            "direct_cdp_manager_events_jsonl".to_string(),
            DIRECT_CDP_MANAGER_EVENTS_ARTIFACT.to_string(),
        ),
        ("screenshot_png".to_string(), "screenshot.png".to_string()),
        ("pdf".to_string(), "page.pdf".to_string()),
    ])
}

fn write_report_artifacts(artifact_dir: &Path, report: &BrowserE2eReport) -> std::io::Result<()> {
    fs::create_dir_all(artifact_dir)?;
    let report_path = artifact_dir.join("driver-result.json");
    let log_path = artifact_dir.join("logs.jsonl");
    let report_json = serde_json::to_string_pretty(report)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    fs::write(report_path, report_json)?;
    let mut logger = E2eLogger::new();
    for entry in &report.logs {
        logger.push(entry.clone());
    }
    logger.write_json_lines(log_path)?;
    if let Some(events) = report.direct_cdp_manager_events_jsonl.as_deref() {
        fs::write(
            artifact_dir.join(DIRECT_CDP_MANAGER_EVENTS_ARTIFACT),
            events,
        )?;
    }
    Ok(())
}

fn persist_base64_artifact(path: &Path, encoded: Option<&str>) -> Option<Value> {
    let encoded = encoded?;
    let parent = path.parent()?;
    if fs::create_dir_all(parent).is_err() {
        return None;
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded)
        && fs::write(path, &bytes).is_ok()
    {
        return Some(json!({
            "path": path.file_name().and_then(|name| name.to_str()).unwrap_or_default(),
            "byte_count": bytes.len(),
            "blake3": stable_hash_bytes(&bytes),
        }));
    }
    None
}

fn capture_relevant_env() -> BTreeMap<String, String> {
    [
        BROWSER_BINARY_ENV,
        CONTROL_URL_ENV,
        ARTIFACT_DIR_ENV,
        "PATH",
    ]
    .into_iter()
    .filter_map(|key| env::var(key).ok().map(|value| (key.to_string(), value)))
    .collect()
}

fn default_artifact_dir(correlation_id: &str) -> PathBuf {
    env::temp_dir().join(format!("fcp-browser-real-e2e-{correlation_id}"))
}

async fn setup_handshake(
    connector: &mut BrowserConnector,
    operations: &[&str],
) -> Ed25519SigningKey {
    let signing_key = Ed25519SigningKey::generate();
    let caps = operations
        .iter()
        .copied()
        .map(capability_for_operation)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    connector
        .handle_handshake(json!({
            "protocol_version": "1.0.0",
            "zone": ZONE_ID,
            "host_public_key": signing_key.verifying_key().to_bytes(),
            "nonce": vec![0_u8; 32],
            "capabilities_requested": caps
        }))
        .await
        .expect("browser handshake succeeds");
    signing_key
}

fn generate_valid_grant(
    signing_key: &Ed25519SigningKey,
    connector: &BrowserConnector,
    operation: &str,
) -> fcp_core::CapabilityToken {
    let now = Utc::now();
    let constraints = CapabilityConstraints {
        resource_allow: vec!["*".into()],
        ..Default::default()
    };
    let mut cbor = Vec::new();
    ciborium::into_writer(&constraints, &mut cbor).expect("serialize constraints");
    let cose = CapabilityTokenBuilder::new()
        .capability_id(capability_for_operation(operation))
        .zone_id(ZONE_ID)
        .principal("user:browser-e2e")
        .operations(&[operation])
        .issuer("node:browser-e2e")
        .target_instance(connector.instance_id())
        .validity(now, now + ChronoDuration::hours(1))
        .try_constraints_cbor(&cbor)
        .expect("constraints CBOR should validate")
        .sign(signing_key)
        .expect("sign browser e2e token");
    fcp_core::CapabilityToken::from_raw(cose)
}

fn generate_execution_approval(operation: &str) -> fcp_core::ApprovalToken {
    let now_ms = u64::try_from(Utc::now().timestamp_millis()).unwrap_or(0);
    fcp_core::ApprovalToken::approved(
        format!("browser-e2e-approval-{operation}-{now_ms}"),
        now_ms.saturating_sub(1_000),
        now_ms + 300_000,
        "owner:browser-e2e",
        fcp_core::ApprovalScope::Execution(fcp_core::ExecutionScope {
            connector_id: CONNECTOR_ID.into(),
            method_pattern: operation.into(),
            request_object_id: None,
            input_hash: None,
            input_constraints: vec![],
        }),
        fcp_core::ZoneId::work(),
        None,
    )
}

const fn requires_execution_approval(operation: &str) -> bool {
    matches!(
        operation.as_bytes(),
        b"browser.evaluate_js"
            | b"browser.fill_form"
            | b"browser.get_cookies"
            | b"browser.set_cookies"
            | b"browser.session.save"
            | b"browser.session.restore"
            | b"browser.set_proxy"
            | b"browser.clear_proxy"
    )
}

const fn capability_for_operation(operation: &str) -> &'static str {
    match operation.as_bytes() {
        b"browser.screenshot" | b"browser.render_pdf" => "browser.capture",
        b"browser.extract_text" | b"browser.extract_links" | b"browser.wait_for_selector" => {
            "browser.extract"
        }
        b"browser.click" | b"browser.fill_form" => "browser.interact",
        b"browser.evaluate_js" => "browser.execute",
        b"browser.get_cookies" | b"browser.set_cookies" => "browser.cookies",
        b"browser.session.save" | b"browser.session.restore" | b"browser.session.describe" => {
            "browser.sessions"
        }
        b"browser.set_proxy" | b"browser.clear_proxy" => "browser.proxy",
        _ => "browser.navigate",
    }
}

const fn timeout_budget_ms(operation: &str) -> u64 {
    match operation.as_bytes() {
        b"browser.screenshot" | b"browser.render_pdf" | b"browser.navigate" => 60_000,
        b"browser.wait_for_selector" => 10_000,
        _ => 30_000,
    }
}

fn cancellation_checkpoints(operation: &str) -> Vec<&'static str> {
    match operation {
        "browser.navigate" => vec!["before_send", "after_page_enable", "after_response"],
        "browser.wait_for_selector" => vec!["before_wait", "selector_poll", "after_response"],
        _ => vec!["before_send", "after_response"],
    }
}

const fn operation_target_id(operation: &str) -> &'static str {
    match operation.as_bytes() {
        b"browser.set_cookies"
        | b"browser.get_cookies"
        | b"browser.session.save"
        | b"browser.session.restore"
        | b"browser.session.describe" => "browser-context",
        _ => "active-page",
    }
}

fn navigation_policy_decision_for_output(operation: &str, output: &Value) -> Value {
    if operation != "browser.navigate" {
        return json!("not_applicable");
    }
    let url = output
        .get("url")
        .and_then(Value::as_str)
        .unwrap_or_default();
    json!({
        "allowed": url.starts_with("http://127.0.0.1:") || url.starts_with("https://"),
        "reason": "loopback_or_https_navigation_allowed",
        "redacted_url": redact_url_for_artifact(url).redacted_url,
    })
}

fn output_metrics(output: &Value) -> Value {
    json!({
        "byte_count": output.to_string().len(),
        "title_chars": output.get("title").and_then(Value::as_str).map(str::len),
        "title_hash": output
            .get("title")
            .and_then(Value::as_str)
            .map(stable_hash),
        "image_bytes_base64": output.get("image_data").and_then(Value::as_str).map(str::len),
        "pdf_bytes_base64": output.get("pdf_data").and_then(Value::as_str).map(str::len),
        "width": output.get("width").and_then(Value::as_u64),
        "height": output.get("height").and_then(Value::as_u64),
        "page_count": output.get("page_count").and_then(Value::as_u64),
        "cookie_count": output.get("cookie_count").and_then(Value::as_u64),
        "text_chars": output.get("text").and_then(Value::as_str).map(str::len),
    })
}

fn elapsed_ms(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

struct LoopbackSite {
    url_base: String,
    running: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<String>>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl LoopbackSite {
    fn start() -> Result<Self, String> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
        let addr = listener.local_addr().map_err(|error| error.to_string())?;
        listener
            .set_nonblocking(true)
            .map_err(|error| error.to_string())?;
        let running = Arc::new(AtomicBool::new(true));
        let thread_running = Arc::clone(&running);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let thread_requests = Arc::clone(&requests);
        let handle = thread::spawn(move || {
            serve_loopback(listener, thread_running, thread_requests);
        });
        Ok(Self {
            url_base: format!("http://{addr}"),
            running,
            requests,
            handle: Some(handle),
        })
    }

    #[must_use]
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.url_base, path)
    }

    fn request_paths(&self) -> Vec<String> {
        self.requests
            .lock()
            .map_or_else(|_| Vec::new(), |requests| requests.clone())
    }
}

impl Drop for LoopbackSite {
    fn drop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
        if let Ok(stream) = TcpStream::connect(self.url_base.trim_start_matches("http://")) {
            let _ = stream.shutdown(Shutdown::Both);
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[allow(clippy::needless_pass_by_value)]
fn serve_loopback(
    listener: TcpListener,
    running: Arc<AtomicBool>,
    requests: Arc<Mutex<Vec<String>>>,
) {
    while running.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let request_log = Arc::clone(&requests);
                thread::spawn(move || serve_loopback_request(stream, &request_log));
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
}

fn serve_loopback_request(mut stream: TcpStream, requests: &Mutex<Vec<String>>) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let mut request_bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    while request_bytes.len() < 16 * 1024 {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                request_bytes.extend_from_slice(&buffer[..n]);
                if request_bytes.windows(2).any(|window| window == b"\r\n") {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(_) => break,
        }
    }
    let Some(path) = parse_loopback_request_path(&request_bytes) else {
        if let Ok(mut requests) = requests.lock() {
            requests.push("[connection-without-request-line]".to_string());
        }
        let _ = stream.shutdown(Shutdown::Both);
        return;
    };
    if let Ok(mut requests) = requests.lock() {
        requests.push(path.clone());
    }
    let response = loopback_response_for_path(&path);
    let wire_response = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nSet-Cookie: fcp_browser_e2e=loopback; Path=/; SameSite=Lax\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        response.status,
        response.content_type,
        response.body.len(),
        response.body
    );
    let _ = stream.write_all(wire_response.as_bytes());
    let _ = stream.shutdown(Shutdown::Both);
}

fn parse_loopback_request_path(request_bytes: &[u8]) -> Option<String> {
    let request = String::from_utf8_lossy(request_bytes);
    let request_line = request
        .lines()
        .next()
        .map(str::trim_end)
        .filter(|line| !line.is_empty())?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    let _version = parts.next()?;
    matches!(method, "GET" | "HEAD").then(|| normalize_loopback_request_path(target))
}

struct LoopbackResponse {
    status: &'static str,
    content_type: &'static str,
    body: String,
}

fn loopback_response_for_path(path: &str) -> LoopbackResponse {
    let path = normalize_loopback_request_path(path);
    let body = match path.as_str() {
        "/submit" => "<html><body><div id=\"ready\">submitted</div></body></html>".to_string(),
        "/readable-fixture" => readable_fixture_body(),
        "/print-fixture" => print_fixture_body(),
        _ => r#"
<!doctype html>
<html>
  <head><title>FCP Browser E2E</title></head>
  <body>
    <main id="ready">
      <h1>FCP Browser E2E</h1>
      <a href="/next" id="next-link">next</a>
      <button id="click-target" onclick="document.body.dataset.clicked='true'">Click</button>
      <form action="/submit" method="get">
        <input id="name" name="name">
        <textarea id="message" name="message"></textarea>
        <button id="submit" type="submit">Submit</button>
      </form>
    </main>
  </body>
</html>
"#
        .to_string(),
    };
    LoopbackResponse {
        status: "200 OK",
        content_type: "text/html; charset=utf-8",
        body,
    }
}

fn normalize_loopback_request_path(raw_path: &str) -> String {
    if let Ok(url) = Url::parse(raw_path) {
        return url.path().to_string();
    }
    raw_path.split('?').next().unwrap_or(raw_path).to_string()
}

fn readable_fixture_body() -> String {
    let oversized_text = " visible bounded browser content with hostile markup nearby".repeat(64);
    format!(
        r#"<!doctype html>
<html>
  <head>
    <title>Readable Fixture</title>
    <style>.hidden {{ display: none; }}</style>
    <script>document.documentElement.dataset.scriptRan = "true";</script>
  </head>
  <body>
    <main id="readable-fixture">
      <section><article><div><p>Readable alpha &#8203; beta.</p></div></article></section>
      <div class="hidden">Hidden content must not appear in visible extraction.</div>
      <noscript>Noscript fallback text remains inert document text.</noscript>
      <p>{oversized_text}</p>
    </main>
  </body>
</html>"#
    )
}

fn print_fixture_body() -> String {
    r#"<!doctype html>
<html>
  <head>
    <title>Print Fixture</title>
    <style>
      @page { size: A4; margin: 0.5in; }
      body { font-family: sans-serif; }
      .page { break-after: page; min-height: 10in; }
      .page:last-child { break-after: auto; }
    </style>
  </head>
  <body>
    <main id="print-fixture">
      <section class="page"><h1>Document page one</h1><p>Browser render proof.</p></section>
      <section class="page"><h1>Document page two</h1><p>Multi-page guardrail proof.</p></section>
      <section class="page"><h1>Document page three</h1><p>Document extraction remains deferred.</p></section>
    </main>
  </body>
</html>"#
        .to_string()
}

#[test]
fn prerequisite_detection_reports_exact_missing_inputs() {
    let env = BTreeMap::new();
    let artifact_dir = PathBuf::from("browser-e2e");
    let prerequisites = evaluate_prerequisites(&env, artifact_dir.as_path(), |_| false);

    assert!(!prerequisites.is_qualified());
    let codes = prerequisites
        .missing
        .iter()
        .map(|missing| missing.code.as_str())
        .collect::<BTreeSet<_>>();
    assert!(codes.contains("browser_binary_missing"));
    assert!(codes.contains("control_endpoint_missing"));
}

#[test]
fn prerequisite_detection_accepts_env_binary_and_loopback_control_worker() {
    let mut env = BTreeMap::new();
    env.insert(
        BROWSER_BINARY_ENV.to_string(),
        "/usr/bin/google-chrome".to_string(),
    );
    env.insert(
        CONTROL_URL_ENV.to_string(),
        "http://127.0.0.1:9222".to_string(),
    );
    let artifact_dir = PathBuf::from("browser-e2e");
    let prerequisites = evaluate_prerequisites(&env, artifact_dir.as_path(), |path| {
        path == Path::new("/usr/bin/google-chrome")
    });

    assert!(prerequisites.is_qualified());
    assert_eq!(
        prerequisites.browser_binary.as_deref(),
        Some("/usr/bin/google-chrome")
    );
    assert!(prerequisites.endpoint_policy_decision.allowed);
    assert_eq!(
        prerequisites.control_endpoint_kind,
        "control_worker_endpoint_allowed"
    );
}

#[test]
fn prerequisite_detection_accepts_env_binary_for_direct_cdp_auto_launch() {
    let mut env = BTreeMap::new();
    env.insert(
        BROWSER_BINARY_ENV.to_string(),
        "/usr/bin/google-chrome".to_string(),
    );
    let artifact_dir = PathBuf::from("browser-e2e");
    let prerequisites = evaluate_prerequisites(&env, artifact_dir.as_path(), |path| {
        path == Path::new("/usr/bin/google-chrome")
    });

    assert!(prerequisites.is_qualified());
    assert!(prerequisites.endpoint_policy_decision.allowed);
    assert_eq!(
        prerequisites.control_endpoint_kind,
        "auto_launch_direct_cdp_websocket"
    );
}

#[test]
fn prerequisite_detection_accepts_direct_cdp_page_websocket_endpoint() {
    let mut env = BTreeMap::new();
    env.insert(
        BROWSER_BINARY_ENV.to_string(),
        "/usr/bin/google-chrome".to_string(),
    );
    env.insert(
        CONTROL_URL_ENV.to_string(),
        "ws://127.0.0.1:9222/devtools/page/target-1".to_string(),
    );
    let artifact_dir = PathBuf::from("browser-e2e");
    let prerequisites = evaluate_prerequisites(&env, artifact_dir.as_path(), |path| {
        path == Path::new("/usr/bin/google-chrome")
    });

    assert!(prerequisites.is_qualified());
    assert_eq!(prerequisites.control_endpoint_kind, "direct_cdp_websocket");
}

#[test]
fn direct_cdp_target_hash_uses_redacted_page_target_id() {
    let hash = endpoint_target_id_hash(
        "ws://127.0.0.1:9222/devtools/page/target-1",
        "direct_cdp_websocket",
    );

    assert_eq!(hash, format!("blake3:{}", short_redaction_hash("target-1")));
}

#[test]
fn direct_cdp_page_websocket_extraction_selects_page_target() {
    let targets = json!([
        {
            "type": "service_worker",
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/service_worker/sw-1"
        },
        {
            "type": "page",
            "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/page-1"
        }
    ]);

    assert_eq!(
        page_websocket_url_from_devtools_targets(&targets).as_deref(),
        Some("ws://127.0.0.1:9222/devtools/page/page-1")
    );
}

#[test]
fn loopback_site_serves_ready_page_and_joins_on_drop() {
    let site = LoopbackSite::start().expect("loopback site starts");
    let mut stream = TcpStream::connect(site.url_base.trim_start_matches("http://"))
        .expect("connect loopback site");
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        .expect("write loopback request");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("read loopback response");

    assert!(response.contains("HTTP/1.1 200 OK"));
    assert!(response.contains("id=\"ready\""));
    assert_eq!(site.request_paths(), vec!["/"]);
    drop(site);
}

#[test]
fn loopback_request_parser_keeps_distinct_paths() {
    assert_eq!(
        parse_loopback_request_path(b"GET /readable-fixture HTTP/1.1\r\nHost: 127.0.0.1\r\n"),
        Some("/readable-fixture".to_string())
    );
    assert_eq!(
        parse_loopback_request_path(
            b"GET http://127.0.0.1:41831/print-fixture?download=1 HTTP/1.1\r\n"
        ),
        Some("/print-fixture".to_string())
    );
}

#[test]
fn loopback_request_parser_rejects_empty_connections() {
    assert_eq!(parse_loopback_request_path(b""), None);
    assert_eq!(parse_loopback_request_path(b"\r\n"), None);
    assert_eq!(parse_loopback_request_path(b"GET"), None);
}

#[test]
fn artifact_paths_include_direct_cdp_manager_events_jsonl() {
    let paths = standard_artifact_paths();

    assert_eq!(
        paths
            .get("direct_cdp_manager_events_jsonl")
            .map(String::as_str),
        Some(DIRECT_CDP_MANAGER_EVENTS_ARTIFACT)
    );
}

#[test]
fn skip_artifact_schema_distinguishes_missing_prereqs_from_live_failure() {
    let artifact_dir = PathBuf::from("out");
    let prerequisites = evaluate_prerequisites(&BTreeMap::new(), artifact_dir.as_path(), |_| false);
    let mut logger = E2eLogger::new();
    logger.push(skip_log_entry("corr-skip", &prerequisites));
    let skipped = BrowserE2eReport::skipped("corr-skip", prerequisites.clone(), logger.drain());
    let failed = BrowserE2eReport::failed(
        "corr-fail",
        prerequisites,
        Vec::new(),
        "control worker returned 500",
    );

    assert_eq!(skipped.status, HarnessStatus::Skipped);
    assert_eq!(failed.status, HarnessStatus::Failed);
    assert_eq!(
        skipped.summary["failure_to_skip_distinction"],
        "missing_prerequisite_only"
    );
    assert_eq!(
        failed.summary["failure_to_skip_distinction"],
        "live_prerequisites_were_satisfied"
    );
}

#[test]
fn log_schema_contains_required_browser_evidence_fields() {
    let evidence = OperationEvidenceContext::for_test("fcp_browser_control");
    let log = operation_log_entry(
        "corr-log",
        "browser.screenshot",
        HarnessStatus::Passed,
        12,
        operation_details(
            "browser.screenshot",
            &evidence,
            HarnessStatus::Passed,
            &json!({ "image_data": "aW1n", "width": 2, "height": 1 }),
            None,
        ),
    );
    let value = serde_json::to_value(log).expect("serialize log");

    assert_eq!(value["correlation_id"], "corr-log");
    assert_eq!(value["details"]["operation"], "browser.screenshot");
    assert_eq!(
        value["details"]["worker_operation_id"],
        "browser.screenshot"
    );
    assert!(value["details"]["target_id"].is_string());
    assert!(value["details"]["target_id_hash"].is_string());
    assert!(value["details"]["command_line"].is_string());
    assert!(value["details"]["git_revision"].is_string());
    assert!(value["details"]["endpoint_policy_decision"].is_string());
    assert!(value["details"]["navigation_policy_decision"].is_string());
    assert!(value["details"]["capability_decision"].is_string());
    assert!(value["details"]["approval_decision"].is_string());
    assert!(value["details"]["output"]["width"].is_u64());
    assert!(value["details"]["cancellation_checkpoints"].is_array());
}

#[test]
fn log_schema_records_browser_extraction_guardrail_metadata() {
    let evidence = OperationEvidenceContext::for_test("direct_cdp_websocket");
    let details = operation_details(
        "browser.extract_text",
        &evidence,
        HarnessStatus::Passed,
        &json!({
            "text": "Readable page",
            "output_mode": "markdown",
            "external_content": { "untrusted": true, "kind": "page_text" },
            "readability": { "decision": "adopted_for_active_page_text" },
            "guardrails": { "truncated": false, "requested_max_chars": 2000 }
        }),
        None,
    );

    assert_eq!(details["external_content"]["untrusted"], true);
    assert_eq!(
        details["readability"]["decision"],
        "adopted_for_active_page_text"
    );
    assert_eq!(details["guardrails"]["requested_max_chars"], 2000);

    let pdf_details = operation_details(
        "browser.render_pdf",
        &evidence,
        HarnessStatus::Passed,
        &json!({
            "pdf_data": "JVBERg==",
            "page_count": 1,
            "document_extraction": { "decision": "deferred" }
        }),
        None,
    );

    assert_eq!(pdf_details["document_extraction"]["decision"], "deferred");
}

#[test]
fn url_redaction_removes_credentials_query_and_fragment() {
    let decision =
        redact_url_for_artifact("https://user:credential@example.com/path?trace_id=abc#private");

    assert_eq!(decision.redacted_url, "https://example.com/path");
    assert!(decision.secret_removed);
    assert!(decision.redacted_fields.contains(&"username".to_string()));
    assert!(decision.redacted_fields.contains(&"password".to_string()));
    assert!(decision.redacted_fields.contains(&"query".to_string()));
    assert!(decision.redacted_fields.contains(&"fragment".to_string()));
    assert!(!decision.redacted_url.contains("credential"));
    assert!(!decision.redacted_url.contains("trace_id"));
}

#[test]
fn url_redaction_hashes_direct_cdp_page_target_ids() {
    let decision = redact_url_for_artifact("ws://127.0.0.1:9222/devtools/page/raw-target-secret");

    assert!(decision.secret_removed);
    assert!(
        decision
            .redacted_fields
            .contains(&"direct_cdp_target_id".to_string())
    );
    assert!(
        decision
            .redacted_url
            .contains("/devtools/page/target-hash-")
    );
    assert!(!decision.redacted_url.contains("raw-target-secret"));
}

#[test]
fn artifact_path_normalization_rejects_escape_paths() {
    assert_eq!(
        normalize_artifact_path(Path::new("./logs/browser.jsonl")).unwrap(),
        "logs/browser.jsonl"
    );
    assert!(normalize_artifact_path(Path::new("../escape")).is_err());
    assert!(normalize_artifact_path(Path::new("/tmp/out")).is_err());
}

#[test]
fn timeout_and_cancellation_markers_are_explicit() {
    let evidence = OperationEvidenceContext::for_test("direct_cdp_websocket");
    let details = operation_details(
        "browser.wait_for_selector",
        &evidence,
        HarnessStatus::Passed,
        &json!({ "found": true }),
        None,
    );

    assert_eq!(details["timeout_budget_ms"], 10_000);
    assert_eq!(
        details["cancellation_checkpoints"],
        json!(["before_wait", "selector_poll", "after_response"])
    );
}

#[test]
fn expected_error_details_are_logged_explicitly() {
    let evidence = OperationEvidenceContext::for_test("direct_cdp_websocket");
    let details = operation_details(
        "browser.clear_proxy",
        &evidence,
        HarnessStatus::Passed,
        &json!({
            "expected_error": "browser.clear_proxy proxy_unavailable control_mode=direct_cdp_websocket",
            "expected_reason": "direct_cdp_proxy_fail_closed_expected"
        }),
        None,
    );

    assert_eq!(
        details["expected_reason"],
        "direct_cdp_proxy_fail_closed_expected"
    );
    assert!(
        details["expected_error"]
            .as_str()
            .expect("expected_error string")
            .contains("proxy_unavailable")
    );
}

#[fcp_async_core::runtime::test]
async fn browser_contract_operations_are_covered_by_live_plan() {
    let connector = BrowserConnector::new();
    let health = connector.handle_health().await.expect("health response");
    let operations = health["browser_control_contract"]["connector_operations"]
        .as_array()
        .expect("connector operations");
    let documented = operations
        .iter()
        .filter_map(|operation| operation["id"].as_str())
        .collect::<BTreeSet<_>>();
    for operation in LIVE_OPERATIONS {
        assert!(
            documented.contains(operation),
            "live harness must cover documented operation {operation}"
        );
    }
}
