//! Browser automation API client.
//!
//! Talks to the FCP browser-control plane. The control plane may use Chrome
//! DevTools Protocol internally, but this client does not treat a raw Chrome
//! `/json/version` endpoint as sufficient proof that FCP browser operations are
//! available.

use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    net::IpAddr,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use fcp_async_core::{
    AsyncError, Cx,
    net::TcpStream,
    process::{Child, Command, Stdio},
    websocket::{Message as WebSocketMessage, WebSocket, WebSocketConfig, WsError, WsUrl},
};
use fcp_prelude::CredentialId;
use fcp_sdk::migration::{
    AttemptOutcome, HttpRetryConfig, RetryLoop, transport_error_reached_service,
};
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use futures_util::StreamExt;
use reqwest::{Client, StatusCode, header};

use crate::{
    error::{BrowserError, BrowserResult},
    types::{
        ApiErrorResponse, ClickResult, Cookie, FormResult, JsResult, LinksResult, NavigateResult,
        PdfResult, ProxyConfig, ProxyResult, ScreenshotResult, TextResult, WaitResult,
    },
};

/// Default browser-control endpoint.
pub const DEFAULT_BROWSER_URL: &str = "http://localhost:9222";

/// Required FCP browser-control contract version.
pub const BROWSER_CONTROL_PROTOCOL_VERSION: u64 = 1;

const CONTROL_RESPONSE_BYTES_SMALL: usize = 1_048_576;
const CONTROL_RESPONSE_BYTES_STANDARD: usize = 10_485_760;
const CONTROL_RESPONSE_BYTES_CAPTURE: usize = 52_428_800;
const CONTROL_TIMEOUT_MS_SHORT: u64 = 10_000;
const CONTROL_TIMEOUT_MS_STANDARD: u64 = 30_000;
const CONTROL_TIMEOUT_MS_CAPTURE: u64 = 60_000;
const CONTROL_OPERATION_HEADER: &str = "X-FCP-Browser-Operation";
const CONTROL_RESPONSE_BUDGET_HEADER: &str = "X-FCP-Browser-Max-Response-Bytes";
const CONTROL_TIMEOUT_BUDGET_HEADER: &str = "X-FCP-Browser-Timeout-Ms";
const CONTROL_TARGET_SCOPE_HEADER: &str = "X-FCP-Browser-Target-Scope";
const CONTROL_TARGET_SELECTION_HEADER: &str = "X-FCP-Browser-Target-Selection";
const CONTROL_STALE_TARGET_RECOVERY_HEADER: &str = "X-FCP-Browser-Stale-Target-Recovery";
const CONTROL_CURRENT_TAB_GUARD_HEADER: &str = "X-FCP-Browser-Current-Tab-Guard";
const CONTROL_EXPORT_GUARD_HEADER: &str = "X-FCP-Browser-Export-Guard";
const PROXY_DESCRIPTOR_MAX_BYTES: usize = 4_096;
const PROXY_BYPASS_MAX_ENTRIES: usize = 128;
const PROXY_BYPASS_ENTRY_MAX_BYTES: usize = 256;
const PROXY_REDACTION_CONTRACT: &str =
    "proxy credentials, target URLs, local paths, cookies, and raw CDP endpoints must be redacted";
const RUST_LAUNCHER_COMMAND_LINE: &str = "fcp-browser rust-owned-launcher-supervisor";
pub(crate) const RUST_LAUNCHER_DEFAULT_READINESS_TIMEOUT_MS: u64 = 10_000;
const RUST_LAUNCHER_MAX_ARGS: usize = 32;
const RUST_LAUNCHER_ARG_MAX_BYTES: usize = 512;
const RUST_LAUNCHER_PROFILE_ARG: &str = "--user-data-dir=fcp-runtime-profile-dir";
const RUST_LAUNCHER_DEVTOOLS_ACTIVE_PORT: &str = "DevToolsActivePort";
const RUST_LAUNCHER_READINESS_POLL_MS: u64 = 25;

/// Runtime mode for the Rust-owned browser launcher supervisor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserLauncherMode {
    /// Build and validate a native browser launch plan.
    Native,
    /// Deterministic in-process fixture mode for proof lanes.
    Fixture,
}

impl BrowserLauncherMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Fixture => "fixture",
        }
    }
}

/// Configuration for the opt-in Rust-owned launcher supervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserLauncherConfig {
    mode: BrowserLauncherMode,
    browser_binary_path: Option<String>,
    readiness_timeout_ms: u64,
}

impl BrowserLauncherConfig {
    /// Native launcher mode using an optional configured browser binary path.
    pub fn native(
        browser_binary_path: Option<String>,
        readiness_timeout_ms: u64,
    ) -> BrowserResult<Self> {
        let config = Self {
            mode: BrowserLauncherMode::Native,
            browser_binary_path,
            readiness_timeout_ms,
        };
        validate_rust_owned_launcher_config(&config)?;
        Ok(config)
    }

    /// Deterministic fixture mode for test/proof lanes.
    #[must_use]
    pub fn fixture(readiness_timeout_ms: u64) -> Self {
        Self {
            mode: BrowserLauncherMode::Fixture,
            browser_binary_path: None,
            readiness_timeout_ms,
        }
    }

    #[must_use]
    pub const fn mode(&self) -> BrowserLauncherMode {
        self.mode
    }

    #[must_use]
    pub fn browser_binary_path(&self) -> Option<&str> {
        self.browser_binary_path.as_deref()
    }

    #[must_use]
    pub const fn readiness_timeout_ms(&self) -> u64 {
        self.readiness_timeout_ms
    }
}

#[derive(Clone, Copy)]
struct BrowserControlOperation {
    id: &'static str,
    method: &'static str,
    path: &'static str,
    max_response_bytes: usize,
    timeout_ms: u64,
    target_policy: BrowserTargetPolicy,
    implementation: BrowserControlImplementation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectCdpEndpoint {
    url: String,
    endpoint_kind: DirectCdpEndpointKind,
    target: DirectCdpTarget,
    redacted_url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BrowserControlEndpoint {
    FcpControlPlane,
    DirectCdp(DirectCdpEndpoint),
}

type DirectCdpSessionFuture<'a, T> = Pin<Box<dyn Future<Output = BrowserResult<T>> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectCdpEndpointKind {
    WebSocket,
}

impl DirectCdpEndpointKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::WebSocket => "direct_cdp_websocket",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectCdpTarget {
    kind: DirectCdpTargetKind,
    path_kind: String,
    id_hash: String,
}

impl DirectCdpTarget {
    #[cfg(test)]
    fn descriptor(&self) -> serde_json::Value {
        serde_json::json!({
            "target_kind": self.kind.as_str(),
            "path_kind": self.path_kind.as_str(),
            "target_id_hash": format!("blake3:{}", self.id_hash),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectCdpTargetKind {
    Page,
    Browser,
    Worker,
    Unsupported,
}

impl DirectCdpTargetKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Page => "page",
            Self::Browser => "browser",
            Self::Worker => "worker",
            Self::Unsupported => "unsupported",
        }
    }
}

impl DirectCdpEndpoint {
    #[cfg(test)]
    fn descriptor(&self) -> serde_json::Value {
        serde_json::json!({
            "endpoint_kind": self.endpoint_kind.as_str(),
            "redacted_endpoint": self.redacted_url.as_str(),
            "target": self.target.descriptor(),
            "target_selection": "configured_page_websocket",
            "current_tab_decision": "configured_target_is_current_tab",
            "export_target_decision": "configured_target_is_export_target",
            "stale_target_recovery": false,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectCdpOwnedTarget {
    kind: DirectCdpTargetKind,
    path_kind: String,
    id_hash: String,
}

impl From<&DirectCdpTarget> for DirectCdpOwnedTarget {
    fn from(target: &DirectCdpTarget) -> Self {
        Self {
            kind: target.kind,
            path_kind: target.path_kind.clone(),
            id_hash: target.id_hash.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectCdpActiveLease {
    lease_seq: u64,
    operation_id: &'static str,
    target_id_hash: String,
    timeout_budget_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectCdpSessionObjectLease {
    object_id_hash: String,
    lease_seq: u64,
    cookie_scope_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
struct DirectCdpManagerEvent {
    command_line: &'static str,
    git_revision: String,
    run_id: String,
    event_kind: &'static str,
    manager_id_hash: String,
    endpoint_kind: &'static str,
    target_kind: &'static str,
    target_id_hash: String,
    operation_id: &'static str,
    cdp_command_ids: Vec<u64>,
    current_tab_decision: &'static str,
    session_object_id_hash: Option<String>,
    session_lease_seq: Option<u64>,
    retry_decision: &'static str,
    timeout_budget_ms: u64,
    timeout_checkpoint: &'static str,
    cancellation_checkpoint: &'static str,
    cleanup_result: &'static str,
    skip_reason: Option<&'static str>,
}

#[derive(Debug)]
struct DirectCdpTargetSessionManager {
    manager_id_hash: String,
    started: bool,
    current_target: Option<DirectCdpOwnedTarget>,
    active_lease: Option<DirectCdpActiveLease>,
    session_objects: BTreeMap<String, DirectCdpSessionObjectLease>,
    events: Vec<DirectCdpManagerEvent>,
    next_lease_seq: u64,
    shutdown: bool,
}

impl Default for DirectCdpTargetSessionManager {
    fn default() -> Self {
        Self {
            manager_id_hash: direct_cdp_redaction_hash("fcp.browser.direct_cdp.manager.v1"),
            started: false,
            current_target: None,
            active_lease: None,
            session_objects: BTreeMap::new(),
            events: Vec::new(),
            next_lease_seq: 1,
            shutdown: false,
        }
    }
}

impl DirectCdpTargetSessionManager {
    fn begin_operation(
        &mut self,
        endpoint: &DirectCdpEndpoint,
        operation_id: &'static str,
        timeout: Duration,
    ) -> BrowserResult<u64> {
        if self.shutdown {
            return Err(BrowserError::InvalidConfig(
                "direct CDP target/session manager is shut down".into(),
            ));
        }
        if let Some(active) = &self.active_lease {
            return Err(BrowserError::InvalidConfig(format!(
                "direct CDP target/session manager already owns operation {} for target hash {}; retry after the active lease is cleaned up",
                active.operation_id, active.target_id_hash
            )));
        }
        if endpoint.target.kind != DirectCdpTargetKind::Page {
            return Err(BrowserError::InvalidConfig(format!(
                "direct CDP target/session manager supports only page targets, got {}",
                endpoint.target.kind.as_str()
            )));
        }
        self.ensure_started(endpoint, operation_id, timeout);

        let target = DirectCdpOwnedTarget::from(&endpoint.target);
        let current_tab_decision = if self.current_target.as_ref() == Some(&target) {
            "configured_target_already_current_tab"
        } else if self.current_target.is_some() {
            self.current_target = Some(target);
            self.push_event(DirectCdpManagerEvent {
                event_kind: "stale_target_recovery",
                command_line: direct_cdp_manager_command_line(),
                git_revision: direct_cdp_git_revision(),
                run_id: self.manager_id_hash.clone(),
                manager_id_hash: self.manager_id_hash.clone(),
                endpoint_kind: endpoint.endpoint_kind.as_str(),
                target_kind: endpoint.target.kind.as_str(),
                target_id_hash: endpoint.target.id_hash.clone(),
                operation_id,
                cdp_command_ids: Vec::new(),
                current_tab_decision: "stale_target_recovered_and_current_tab_updated",
                session_object_id_hash: None,
                session_lease_seq: None,
                retry_decision: "not_retried_manager_state_update",
                timeout_budget_ms: duration_millis_u64(timeout),
                timeout_checkpoint: "before_connect",
                cancellation_checkpoint: "checkpoint_before_connect",
                cleanup_result: "target_rebound",
                skip_reason: None,
            });
            "stale_target_recovered_and_current_tab_updated"
        } else {
            self.current_target = Some(target);
            self.push_event(DirectCdpManagerEvent {
                event_kind: "target_attach",
                command_line: direct_cdp_manager_command_line(),
                git_revision: direct_cdp_git_revision(),
                run_id: self.manager_id_hash.clone(),
                manager_id_hash: self.manager_id_hash.clone(),
                endpoint_kind: endpoint.endpoint_kind.as_str(),
                target_kind: endpoint.target.kind.as_str(),
                target_id_hash: endpoint.target.id_hash.clone(),
                operation_id,
                cdp_command_ids: Vec::new(),
                current_tab_decision: "configured_target_attached_as_current_tab",
                session_object_id_hash: None,
                session_lease_seq: None,
                retry_decision: "not_retried_initial_attach",
                timeout_budget_ms: duration_millis_u64(timeout),
                timeout_checkpoint: "before_connect",
                cancellation_checkpoint: "checkpoint_before_connect",
                cleanup_result: "target_attached",
                skip_reason: None,
            });
            "configured_target_attached_as_current_tab"
        };

        let lease_seq = self.next_lease_seq;
        self.next_lease_seq =
            self.next_lease_seq
                .checked_add(1)
                .ok_or_else(|| BrowserError::Api {
                    message: "direct CDP target/session manager lease sequence overflowed u64"
                        .into(),
                    status_code: None,
                })?;
        self.active_lease = Some(DirectCdpActiveLease {
            lease_seq,
            operation_id,
            target_id_hash: endpoint.target.id_hash.clone(),
            timeout_budget_ms: duration_millis_u64(timeout),
        });
        self.push_event(DirectCdpManagerEvent {
            event_kind: "operation_begin",
            command_line: direct_cdp_manager_command_line(),
            git_revision: direct_cdp_git_revision(),
            run_id: self.manager_id_hash.clone(),
            manager_id_hash: self.manager_id_hash.clone(),
            endpoint_kind: endpoint.endpoint_kind.as_str(),
            target_kind: endpoint.target.kind.as_str(),
            target_id_hash: endpoint.target.id_hash.clone(),
            operation_id,
            cdp_command_ids: Vec::new(),
            current_tab_decision,
            session_object_id_hash: None,
            session_lease_seq: None,
            retry_decision: "not_retried_single_direct_session_attempt",
            timeout_budget_ms: duration_millis_u64(timeout),
            timeout_checkpoint: "before_connect",
            cancellation_checkpoint: "checkpoint_before_connect",
            cleanup_result: "pending",
            skip_reason: None,
        });

        Ok(lease_seq)
    }

    fn ensure_started(
        &mut self,
        endpoint: &DirectCdpEndpoint,
        operation_id: &'static str,
        timeout: Duration,
    ) {
        if self.started {
            return;
        }
        self.started = true;
        self.push_event(DirectCdpManagerEvent {
            event_kind: "manager_start",
            command_line: direct_cdp_manager_command_line(),
            git_revision: direct_cdp_git_revision(),
            run_id: self.manager_id_hash.clone(),
            manager_id_hash: self.manager_id_hash.clone(),
            endpoint_kind: endpoint.endpoint_kind.as_str(),
            target_kind: endpoint.target.kind.as_str(),
            target_id_hash: endpoint.target.id_hash.clone(),
            operation_id,
            cdp_command_ids: Vec::new(),
            current_tab_decision: "manager_started_without_current_tab",
            session_object_id_hash: None,
            session_lease_seq: None,
            retry_decision: "not_applicable_manager_start",
            timeout_budget_ms: duration_millis_u64(timeout),
            timeout_checkpoint: "manager_initialized_before_connect",
            cancellation_checkpoint: "checkpoint_before_connect",
            cleanup_result: "manager_started",
            skip_reason: None,
        });
    }

    fn finish_operation(
        &mut self,
        endpoint: &DirectCdpEndpoint,
        lease_seq: u64,
        operation_id: &'static str,
        cdp_command_ids: &[u64],
        outcome: &'static str,
        cleanup_result: &'static str,
    ) -> BrowserResult<()> {
        let Some(active) = self.active_lease.take() else {
            return Err(BrowserError::Api {
                message: "direct CDP target/session manager has no active lease to finish".into(),
                status_code: None,
            });
        };
        if active.lease_seq != lease_seq || active.operation_id != operation_id {
            self.active_lease = Some(active);
            return Err(BrowserError::Api {
                message: "direct CDP target/session manager lease mismatch during cleanup".into(),
                status_code: None,
            });
        }
        let event_kind = if outcome == "success" {
            "operation_complete"
        } else {
            "operation_failed"
        };
        self.push_event(DirectCdpManagerEvent {
            event_kind,
            command_line: direct_cdp_manager_command_line(),
            git_revision: direct_cdp_git_revision(),
            run_id: self.manager_id_hash.clone(),
            manager_id_hash: self.manager_id_hash.clone(),
            endpoint_kind: endpoint.endpoint_kind.as_str(),
            target_kind: endpoint.target.kind.as_str(),
            target_id_hash: endpoint.target.id_hash.clone(),
            operation_id,
            cdp_command_ids: cdp_command_ids.to_vec(),
            current_tab_decision: "configured_target_remains_current_tab",
            session_object_id_hash: None,
            session_lease_seq: None,
            retry_decision: if outcome == "success" {
                "not_retried_completed"
            } else {
                "retry_delegated_to_operation_policy"
            },
            timeout_budget_ms: active.timeout_budget_ms,
            timeout_checkpoint: "operation_scope_finished",
            cancellation_checkpoint: "checkpoint_after_operation",
            cleanup_result,
            skip_reason: None,
        });
        Ok(())
    }

    fn record_session_object(
        &mut self,
        endpoint: &DirectCdpEndpoint,
        operation_id: &'static str,
        raw_object_id: &str,
        lease_seq: u64,
        cookie_scope: Option<&str>,
    ) -> BrowserResult<String> {
        if self.shutdown {
            return Err(BrowserError::InvalidConfig(
                "direct CDP target/session manager is shut down".into(),
            ));
        }
        if lease_seq == 0 {
            return Err(BrowserError::InvalidConfig(
                "direct CDP session object lease_seq must be greater than zero".into(),
            ));
        }
        self.ensure_started(endpoint, operation_id, Duration::ZERO);
        let object_id_hash = direct_cdp_redaction_hash(raw_object_id);
        let cookie_scope_hash = cookie_scope.map(direct_cdp_redaction_hash);
        self.session_objects.insert(
            object_id_hash.clone(),
            DirectCdpSessionObjectLease {
                object_id_hash: object_id_hash.clone(),
                lease_seq,
                cookie_scope_hash,
            },
        );
        let recorded =
            self.session_objects
                .get(&object_id_hash)
                .ok_or_else(|| BrowserError::Api {
                    message: "direct CDP session object lease was not recorded".into(),
                    status_code: None,
                })?;
        self.push_event(DirectCdpManagerEvent {
            event_kind: "session_object_recorded",
            command_line: direct_cdp_manager_command_line(),
            git_revision: direct_cdp_git_revision(),
            run_id: self.manager_id_hash.clone(),
            manager_id_hash: self.manager_id_hash.clone(),
            endpoint_kind: endpoint.endpoint_kind.as_str(),
            target_kind: endpoint.target.kind.as_str(),
            target_id_hash: endpoint.target.id_hash.clone(),
            operation_id,
            cdp_command_ids: Vec::new(),
            current_tab_decision: if recorded.cookie_scope_hash.is_some() {
                "cookie_state_owned_by_manager"
            } else {
                "session_state_owned_by_manager"
            },
            session_object_id_hash: Some(format!("blake3:{}", recorded.object_id_hash)),
            session_lease_seq: Some(recorded.lease_seq),
            retry_decision: "not_applicable_local_state",
            timeout_budget_ms: 0,
            timeout_checkpoint: "not_applicable_local_state",
            cancellation_checkpoint: "not_applicable_local_state",
            cleanup_result: "session_object_leased",
            skip_reason: None,
        });
        Ok(object_id_hash)
    }

    fn shutdown(&mut self) {
        let had_active_lease = self.active_lease.take().is_some();
        let cleared_target = self.current_target.take();
        let had_target = cleared_target.is_some();
        let had_session_objects = !self.session_objects.is_empty();
        self.session_objects.clear();
        self.shutdown = true;
        if let Some(target) = cleared_target.as_ref() {
            self.push_event(DirectCdpManagerEvent {
                event_kind: "target_detach",
                command_line: direct_cdp_manager_command_line(),
                git_revision: direct_cdp_git_revision(),
                run_id: self.manager_id_hash.clone(),
                manager_id_hash: self.manager_id_hash.clone(),
                endpoint_kind: "direct_cdp_websocket",
                target_kind: target.kind.as_str(),
                target_id_hash: target.id_hash.clone(),
                operation_id: "browser.shutdown",
                cdp_command_ids: Vec::new(),
                current_tab_decision: "manager_shutdown_detached_current_tab",
                session_object_id_hash: None,
                session_lease_seq: None,
                retry_decision: "not_applicable_shutdown",
                timeout_budget_ms: 0,
                timeout_checkpoint: "not_applicable_shutdown",
                cancellation_checkpoint: "shutdown_signal_observed",
                cleanup_result: "target_detached_no_orphan",
                skip_reason: None,
            });
        }
        self.push_event(DirectCdpManagerEvent {
            event_kind: "manager_shutdown",
            command_line: direct_cdp_manager_command_line(),
            git_revision: direct_cdp_git_revision(),
            run_id: self.manager_id_hash.clone(),
            manager_id_hash: self.manager_id_hash.clone(),
            endpoint_kind: "not_applicable",
            target_kind: cleared_target
                .as_ref()
                .map_or("not_applicable", |target| target.kind.as_str()),
            target_id_hash: cleared_target.as_ref().map_or_else(
                || "not_applicable".to_string(),
                |target| target.id_hash.clone(),
            ),
            operation_id: "browser.shutdown",
            cdp_command_ids: Vec::new(),
            current_tab_decision: "manager_shutdown_cleared_active_owner",
            session_object_id_hash: None,
            session_lease_seq: None,
            retry_decision: "not_applicable_shutdown",
            timeout_budget_ms: 0,
            timeout_checkpoint: "not_applicable_shutdown",
            cancellation_checkpoint: "shutdown_signal_observed",
            cleanup_result: if had_active_lease {
                "active_lease_released_targets_and_sessions_cleared_no_orphan"
            } else if had_target || had_session_objects {
                "targets_and_sessions_cleared_no_orphan"
            } else {
                "no_active_lease_no_orphan"
            },
            skip_reason: None,
        });
    }

    fn push_event(&mut self, event: DirectCdpManagerEvent) {
        self.events.push(event);
    }

    #[cfg(any(test, feature = "test-support"))]
    fn events_jsonl(&self) -> String {
        self.events
            .iter()
            .map(|event| serde_json::to_string(event).expect("manager event should serialize"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[derive(Debug, Clone, serde::Serialize)]
struct RustOwnedLauncherEvent {
    schema_version: &'static str,
    command_line: &'static str,
    git_revision: String,
    run_id: String,
    platform: &'static str,
    browser_binary_descriptor_hash: String,
    launch_mode: &'static str,
    control_endpoint_kind: &'static str,
    control_endpoint_hash: String,
    operation_id: &'static str,
    capability_decision: &'static str,
    approval_decision: &'static str,
    proxy_descriptor_hash: Option<String>,
    target_session_id_hash: String,
    readiness_checkpoint: &'static str,
    timeout_cancellation_checkpoint: &'static str,
    cleanup_result: &'static str,
    artifact_paths: Vec<String>,
    skip_reason: Option<&'static str>,
    reason_code: Option<&'static str>,
    launch_args_hash: String,
}

#[derive(Debug, Default)]
struct RustOwnedLauncherState {
    run_id: String,
    launched: bool,
    shutdown: bool,
    current_proxy_hash: Option<String>,
    target_session_id_hash: Option<String>,
    launch_generation: u64,
    native_child: Option<Child>,
    native_control_endpoint_hash: Option<String>,
    events: Vec<RustOwnedLauncherEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RustOwnedDevtoolsEndpoint {
    port: u16,
    path: String,
}

#[derive(Debug)]
struct RustOwnedLauncherSupervisor {
    config: BrowserLauncherConfig,
    state: RustOwnedLauncherState,
}

impl RustOwnedLauncherSupervisor {
    fn new(config: BrowserLauncherConfig) -> BrowserResult<Self> {
        validate_rust_owned_launcher_config(&config)?;
        Ok(Self {
            config,
            state: RustOwnedLauncherState {
                run_id: rust_owned_redaction_hash("fcp.browser.rust-owned-launcher.v1"),
                ..RustOwnedLauncherState::default()
            },
        })
    }

    fn descriptor(&self) -> serde_json::Value {
        serde_json::json!({
            "enabled": true,
            "mode": self.config.mode().as_str(),
            "control_endpoint_kind": "rust_owned_launcher",
            "readiness_timeout_ms": self.config.readiness_timeout_ms(),
            "browser_binary_descriptor_hash": self.browser_binary_descriptor_hash(),
            "proxy_support": match self.config.mode() {
                BrowserLauncherMode::Fixture => "fixture_available",
                BrowserLauncherMode::Native => "native_spawn_available",
            },
            "redaction_contract": PROXY_REDACTION_CONTRACT,
            "platform": std::env::consts::OS,
        })
    }

    fn health_check(&self) -> BrowserResult<()> {
        validate_rust_owned_launcher_config(&self.config)?;
        if self.config.mode() == BrowserLauncherMode::Native {
            let _ = resolve_rust_owned_browser_binary(&self.config)?;
        }
        Ok(())
    }

    fn set_proxy<F>(
        &mut self,
        proxy: &ProxyConfig,
        runtime_shutting_down: F,
    ) -> BrowserResult<ProxyResult>
    where
        F: Fn() -> bool,
    {
        self.ensure_can_operate("browser.set_proxy", runtime_shutting_down())?;
        let proxy_hash = Some(proxy_config_descriptor_hash(proxy)?);
        let launch_args = build_rust_owned_launcher_args(Some(proxy))?;
        let launch_args_hash = rust_owned_redaction_hash(&launch_args.join("\0"));

        match self.config.mode() {
            BrowserLauncherMode::Fixture => {
                let readiness_checkpoint = self.readiness_checkpoint();
                if let Some((reason_code, reason)) = readiness_failure(readiness_checkpoint) {
                    self.push_event(
                        "browser.set_proxy",
                        proxy_hash,
                        if reason_code == "launcher_readiness_timeout" {
                            "timeout_before_ready"
                        } else {
                            "not_started"
                        },
                        "launch_not_started",
                        Some(reason_code),
                        &launch_args_hash,
                    );
                    return Err(rust_owned_launcher_error(
                        "browser.set_proxy",
                        reason_code,
                        reason,
                    ));
                }
            }
            BrowserLauncherMode::Native => {
                self.launch_native_browser(
                    "browser.set_proxy",
                    &launch_args,
                    proxy_hash.clone(),
                    &launch_args_hash,
                    &runtime_shutting_down,
                )?;
            }
        }

        self.state.launched = true;
        if self.config.mode() == BrowserLauncherMode::Fixture {
            self.state.launch_generation = self.state.launch_generation.saturating_add(1);
            let target_session_id_hash = self.next_target_session_id_hash();
            self.state.target_session_id_hash = Some(target_session_id_hash);
        }
        self.state.current_proxy_hash.clone_from(&proxy_hash);
        self.push_event(
            "browser.set_proxy",
            proxy_hash,
            "not_cancelled",
            "proxy_state_applied_supervisor_alive",
            None,
            &launch_args_hash,
        );

        Ok(ProxyResult {
            enabled: true,
            mode: "fixed_servers".to_string(),
            server: Some(proxy.server.clone()),
        })
    }

    fn clear_proxy<F>(&mut self, runtime_shutting_down: F) -> BrowserResult<ProxyResult>
    where
        F: Fn() -> bool,
    {
        self.ensure_can_operate("browser.clear_proxy", runtime_shutting_down())?;
        let launch_args = build_rust_owned_launcher_args(None)?;
        let launch_args_hash = rust_owned_redaction_hash(&launch_args.join("\0"));

        match self.config.mode() {
            BrowserLauncherMode::Fixture => {
                let readiness_checkpoint = self.readiness_checkpoint();
                if let Some((reason_code, reason)) = readiness_failure(readiness_checkpoint) {
                    self.push_event(
                        "browser.clear_proxy",
                        None,
                        if reason_code == "launcher_readiness_timeout" {
                            "timeout_before_ready"
                        } else {
                            "not_started"
                        },
                        "launch_not_started",
                        Some(reason_code),
                        &launch_args_hash,
                    );
                    return Err(rust_owned_launcher_error(
                        "browser.clear_proxy",
                        reason_code,
                        reason,
                    ));
                }
            }
            BrowserLauncherMode::Native => {
                self.launch_native_browser(
                    "browser.clear_proxy",
                    &launch_args,
                    None,
                    &launch_args_hash,
                    &runtime_shutting_down,
                )?;
            }
        }

        self.state.launched = true;
        self.state.current_proxy_hash = None;
        if self.config.mode() == BrowserLauncherMode::Fixture
            && self.state.target_session_id_hash.is_none()
        {
            self.state.launch_generation = self.state.launch_generation.saturating_add(1);
            self.state.target_session_id_hash = Some(self.next_target_session_id_hash());
        }
        self.push_event(
            "browser.clear_proxy",
            None,
            "not_cancelled",
            "proxy_state_cleared_supervisor_alive",
            None,
            &launch_args_hash,
        );

        Ok(ProxyResult {
            enabled: false,
            mode: "direct".to_string(),
            server: None,
        })
    }

    fn shutdown(&mut self) {
        if self.state.shutdown {
            return;
        }
        let cleanup_result = self.terminate_native_child();
        self.state.shutdown = true;
        self.state.launched = false;
        self.state.current_proxy_hash = None;
        let launch_args_hash = rust_owned_redaction_hash("shutdown");
        self.push_event(
            "browser.shutdown",
            None,
            "shutdown_signal_observed",
            cleanup_result,
            None,
            &launch_args_hash,
        );
        self.state.target_session_id_hash = None;
        self.state.native_control_endpoint_hash = None;
    }

    fn events_jsonl(&self) -> BrowserResult<String> {
        let mut lines = Vec::with_capacity(self.state.events.len());
        for event in &self.state.events {
            lines.push(serde_json::to_string(event).map_err(|err| {
                rust_owned_launcher_error(
                    "browser.launcher_events",
                    "launcher_event_serialize_failed",
                    &format!("failed to serialize launcher event: {err}"),
                )
            })?);
        }
        Ok(lines.join("\n"))
    }

    fn ensure_can_operate(
        &mut self,
        operation_id: &'static str,
        runtime_shutting_down: bool,
    ) -> BrowserResult<()> {
        if runtime_shutting_down || self.state.shutdown {
            self.push_event(
                operation_id,
                None,
                "shutdown_signal_observed",
                "operation_not_started",
                Some("launcher_cancelled"),
                &rust_owned_redaction_hash("cancelled"),
            );
            return Err(rust_owned_launcher_error(
                operation_id,
                "launcher_cancelled",
                "connector runtime is shutting down",
            ));
        }
        validate_rust_owned_launcher_config(&self.config)
    }

    fn readiness_checkpoint(&self) -> &'static str {
        if self.config.readiness_timeout_ms() == 0 {
            "readiness_timeout"
        } else {
            match self.config.mode() {
                BrowserLauncherMode::Fixture => "fixture_ready",
                BrowserLauncherMode::Native if self.state.launched => "native_ready",
                BrowserLauncherMode::Native => "native_not_started",
            }
        }
    }

    fn launch_native_browser<F>(
        &mut self,
        operation_id: &'static str,
        planned_args: &[String],
        proxy_hash: Option<String>,
        launch_args_hash: &str,
        runtime_shutting_down: &F,
    ) -> BrowserResult<()>
    where
        F: Fn() -> bool,
    {
        if self.config.readiness_timeout_ms() == 0 {
            self.push_event(
                operation_id,
                proxy_hash,
                "timeout_before_ready",
                "launch_not_started",
                Some("launcher_readiness_timeout"),
                launch_args_hash,
            );
            return Err(rust_owned_launcher_error(
                operation_id,
                "launcher_readiness_timeout",
                "browser readiness did not complete before the configured timeout",
            ));
        }

        let browser_binary = match resolve_rust_owned_browser_binary(&self.config) {
            Ok(path) => path,
            Err(err) => {
                self.push_event(
                    operation_id,
                    proxy_hash,
                    "not_started",
                    "launch_not_started",
                    Some("launcher_browser_binary_not_found"),
                    launch_args_hash,
                );
                return Err(err);
            }
        };

        let previous_cleanup = self.terminate_native_child();
        self.state.launch_generation = self.state.launch_generation.saturating_add(1);
        self.state.launched = false;
        self.state.target_session_id_hash = None;
        self.state.native_control_endpoint_hash = None;
        let profile_dir = self.native_profile_dir_for_generation();
        std::fs::create_dir_all(&profile_dir).map_err(|err| {
            rust_owned_launcher_error(
                operation_id,
                "launcher_profile_dir_create_failed",
                &format!("failed to create browser profile directory: {err}"),
            )
        })?;
        let actual_args = materialize_rust_owned_launcher_args(planned_args, &profile_dir)?;

        let mut command = Command::new(browser_binary.as_str());
        command
            .args(actual_args.iter().map(String::as_str))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(err) => {
                self.push_event(
                    operation_id,
                    proxy_hash,
                    "not_started",
                    previous_cleanup,
                    Some("launcher_spawn_failed"),
                    launch_args_hash,
                );
                return Err(rust_owned_launcher_error(
                    operation_id,
                    "launcher_spawn_failed",
                    &format!("failed to spawn browser binary: {err}"),
                ));
            }
        };

        let deadline = Instant::now() + Duration::from_millis(self.config.readiness_timeout_ms());
        loop {
            if runtime_shutting_down() {
                let cleanup_result = terminate_child_for_launcher(&mut child);
                self.push_event(
                    operation_id,
                    proxy_hash,
                    "shutdown_signal_observed",
                    cleanup_result,
                    Some("launcher_cancelled"),
                    launch_args_hash,
                );
                return Err(rust_owned_launcher_error(
                    operation_id,
                    "launcher_cancelled",
                    "connector runtime is shutting down",
                ));
            }

            match child.try_wait() {
                Ok(Some(status)) => {
                    self.push_event(
                        operation_id,
                        proxy_hash,
                        "exited_before_ready",
                        "native_child_exited_no_orphan",
                        Some("launcher_exited_before_ready"),
                        launch_args_hash,
                    );
                    return Err(rust_owned_launcher_error(
                        operation_id,
                        "launcher_exited_before_ready",
                        &format!("browser process exited before readiness: {status}"),
                    ));
                }
                Ok(None) => {}
                Err(err) => {
                    self.push_event(
                        operation_id,
                        proxy_hash,
                        "readiness_poll_error",
                        "native_child_state_unknown",
                        Some("launcher_process_poll_failed"),
                        launch_args_hash,
                    );
                    return Err(rust_owned_launcher_error(
                        operation_id,
                        "launcher_process_poll_failed",
                        &format!("failed to poll browser process readiness: {err}"),
                    ));
                }
            }

            match read_devtools_active_port(&profile_dir) {
                Ok(Some(endpoint)) => {
                    self.state.target_session_id_hash =
                        Some(self.native_target_session_id_hash(&endpoint));
                    self.state.native_control_endpoint_hash =
                        Some(Self::native_control_endpoint_hash(&endpoint));
                    self.state.native_child = Some(child);
                    self.state.launched = true;
                    return Ok(());
                }
                Ok(None) => {}
                Err(err) => {
                    let cleanup_result = terminate_child_for_launcher(&mut child);
                    self.push_event(
                        operation_id,
                        proxy_hash,
                        "readiness_file_invalid",
                        cleanup_result,
                        Some("launcher_readiness_file_invalid"),
                        launch_args_hash,
                    );
                    return Err(err);
                }
            }

            if Instant::now() >= deadline {
                let cleanup_result = terminate_child_for_launcher(&mut child);
                self.push_event(
                    operation_id,
                    proxy_hash,
                    "timeout_before_ready",
                    cleanup_result,
                    Some("launcher_readiness_timeout"),
                    launch_args_hash,
                );
                return Err(rust_owned_launcher_error(
                    operation_id,
                    "launcher_readiness_timeout",
                    "browser readiness did not complete before the configured timeout",
                ));
            }

            std::thread::sleep(Duration::from_millis(RUST_LAUNCHER_READINESS_POLL_MS));
        }
    }

    fn native_profile_dir_for_generation(&self) -> PathBuf {
        std::env::temp_dir().join(format!(
            "fcp-browser-launcher-{}-{}-{}",
            std::process::id(),
            self.state.run_id,
            self.state.launch_generation
        ))
    }

    fn native_target_session_id_hash(&self, endpoint: &RustOwnedDevtoolsEndpoint) -> String {
        format!(
            "blake3:{}",
            rust_owned_redaction_hash(&format!(
                "{}:{}:{}",
                self.state.run_id, endpoint.port, endpoint.path
            ))
        )
    }

    fn native_control_endpoint_hash(endpoint: &RustOwnedDevtoolsEndpoint) -> String {
        format!(
            "blake3:{}",
            rust_owned_redaction_hash(&format!("127.0.0.1:{}{}", endpoint.port, endpoint.path))
        )
    }

    fn terminate_native_child(&mut self) -> &'static str {
        let Some(mut child) = self.state.native_child.take() else {
            return "launcher_shutdown_no_orphan";
        };
        terminate_child_for_launcher(&mut child)
    }

    fn browser_binary_descriptor_hash(&self) -> String {
        let descriptor = self
            .config
            .browser_binary_path()
            .map_or_else(rust_owned_platform_discovery_descriptor, |path| {
                format!("configured:{path}")
            });
        format!("blake3:{}", rust_owned_redaction_hash(&descriptor))
    }

    fn next_target_session_id_hash(&self) -> String {
        format!(
            "blake3:{}",
            rust_owned_redaction_hash(&format!(
                "{}:{}",
                self.state.run_id, self.state.launch_generation
            ))
        )
    }

    fn push_event(
        &mut self,
        operation_id: &'static str,
        proxy_descriptor_hash: Option<String>,
        timeout_cancellation_checkpoint: &'static str,
        cleanup_result: &'static str,
        reason_code: Option<&'static str>,
        launch_args_hash: &str,
    ) {
        let target_session_id_hash = self
            .state
            .target_session_id_hash
            .clone()
            .unwrap_or_else(|| "blake3:not_applicable".to_string());
        let control_endpoint_hash = self
            .state
            .native_control_endpoint_hash
            .clone()
            .unwrap_or_else(|| "blake3:not_applicable".to_string());
        self.state.events.push(RustOwnedLauncherEvent {
            schema_version: "fcp-browser-rust-owned-launcher-evidence.v1",
            command_line: RUST_LAUNCHER_COMMAND_LINE,
            git_revision: direct_cdp_git_revision(),
            run_id: self.state.run_id.clone(),
            platform: std::env::consts::OS,
            browser_binary_descriptor_hash: self.browser_binary_descriptor_hash(),
            launch_mode: self.config.mode().as_str(),
            control_endpoint_kind: "rust_owned_launcher",
            control_endpoint_hash,
            operation_id,
            capability_decision: "granted_by_connector_before_launcher",
            approval_decision: "granted_by_connector_before_launcher",
            proxy_descriptor_hash,
            target_session_id_hash,
            readiness_checkpoint: self.readiness_checkpoint(),
            timeout_cancellation_checkpoint,
            cleanup_result,
            artifact_paths: Vec::new(),
            skip_reason: None,
            reason_code,
            launch_args_hash: format!("blake3:{launch_args_hash}"),
        });
    }
}

#[derive(Debug)]
struct DirectCdpManagerLease {
    manager: Arc<Mutex<DirectCdpTargetSessionManager>>,
    endpoint: DirectCdpEndpoint,
    operation_id: &'static str,
    lease_seq: u64,
    finished: bool,
}

impl DirectCdpManagerLease {
    fn acquire(
        manager: Arc<Mutex<DirectCdpTargetSessionManager>>,
        endpoint: &DirectCdpEndpoint,
        operation_id: &'static str,
        timeout: Duration,
    ) -> BrowserResult<Self> {
        let lease_seq = {
            let mut state = lock_direct_cdp_manager(&manager)?;
            state.begin_operation(endpoint, operation_id, timeout)?
        };

        Ok(Self {
            manager,
            endpoint: endpoint.clone(),
            operation_id,
            lease_seq,
            finished: false,
        })
    }

    fn finish(
        &mut self,
        cdp_command_ids: &[u64],
        outcome: &'static str,
        cleanup_result: &'static str,
    ) -> BrowserResult<()> {
        let mut state = lock_direct_cdp_manager(&self.manager)?;
        state.finish_operation(
            &self.endpoint,
            self.lease_seq,
            self.operation_id,
            cdp_command_ids,
            outcome,
            cleanup_result,
        )?;
        drop(state);
        self.finished = true;
        Ok(())
    }
}

impl Drop for DirectCdpManagerLease {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if let Ok(mut state) = self.manager.lock() {
            let _ = state.finish_operation(
                &self.endpoint,
                self.lease_seq,
                self.operation_id,
                &[],
                "cancelled_or_dropped",
                "lease_dropped_cleanup",
            );
            self.finished = true;
        }
    }
}

impl BrowserControlOperation {
    fn descriptor(self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "method": self.method,
            "path": self.path,
            "max_response_bytes": self.max_response_bytes,
            "timeout_ms": self.timeout_ms,
            "target_policy": self.target_policy.descriptor(),
            "request_headers": self.request_headers_descriptor(),
            "implementation": self.implementation.descriptor(),
        })
    }

    fn request_headers_descriptor(self) -> serde_json::Value {
        serde_json::json!([
            { "name": CONTROL_OPERATION_HEADER, "value": self.id },
            { "name": CONTROL_RESPONSE_BUDGET_HEADER, "value": self.max_response_bytes.to_string() },
            { "name": CONTROL_TIMEOUT_BUDGET_HEADER, "value": self.timeout_ms.to_string() },
            { "name": CONTROL_TARGET_SCOPE_HEADER, "value": self.target_policy.scope },
            { "name": CONTROL_TARGET_SELECTION_HEADER, "value": self.target_policy.selection },
            {
                "name": CONTROL_STALE_TARGET_RECOVERY_HEADER,
                "value": self.target_policy.stale_target_recovery.to_string()
            },
            {
                "name": CONTROL_CURRENT_TAB_GUARD_HEADER,
                "value": self.target_policy.current_tab_guard.to_string()
            },
            {
                "name": CONTROL_EXPORT_GUARD_HEADER,
                "value": self.target_policy.export_guard.to_string()
            },
        ])
    }

    fn request_headers_summary(self) -> String {
        format!(
            "{}={}, {}={}, {}={}, {}={}, {}={}, {}={}, {}={}, {}={}",
            CONTROL_OPERATION_HEADER,
            self.id,
            CONTROL_RESPONSE_BUDGET_HEADER,
            self.max_response_bytes,
            CONTROL_TIMEOUT_BUDGET_HEADER,
            self.timeout_ms,
            CONTROL_TARGET_SCOPE_HEADER,
            self.target_policy.scope,
            CONTROL_TARGET_SELECTION_HEADER,
            self.target_policy.selection,
            CONTROL_STALE_TARGET_RECOVERY_HEADER,
            self.target_policy.stale_target_recovery,
            CONTROL_CURRENT_TAB_GUARD_HEADER,
            self.target_policy.current_tab_guard,
            CONTROL_EXPORT_GUARD_HEADER,
            self.target_policy.export_guard
        )
    }
}

#[derive(Clone, Copy)]
struct BrowserTargetPolicy {
    scope: &'static str,
    selection: &'static str,
    stale_target_recovery: bool,
    current_tab_guard: bool,
    export_guard: bool,
}

impl BrowserTargetPolicy {
    fn descriptor(self) -> serde_json::Value {
        serde_json::json!({
            "scope": self.scope,
            "selection": self.selection,
            "stale_target_recovery": self.stale_target_recovery,
            "current_tab_guard": self.current_tab_guard,
            "export_guard": self.export_guard,
        })
    }

    fn summary(self) -> String {
        format!(
            "{}:{} stale_target_recovery={} current_tab_guard={} export_guard={}",
            self.scope,
            self.selection,
            self.stale_target_recovery,
            self.current_tab_guard,
            self.export_guard
        )
    }
}

const TARGET_CREATE_OR_REUSE_PAGE: BrowserTargetPolicy = BrowserTargetPolicy {
    scope: "page",
    selection: "create_or_reuse_active_page",
    stale_target_recovery: true,
    current_tab_guard: false,
    export_guard: false,
};
const TARGET_ACTIVE_PAGE_INTERACTION: BrowserTargetPolicy = BrowserTargetPolicy {
    scope: "page",
    selection: "active_page_required",
    stale_target_recovery: true,
    current_tab_guard: true,
    export_guard: false,
};
const TARGET_ACTIVE_PAGE_EXPORT: BrowserTargetPolicy = BrowserTargetPolicy {
    scope: "page",
    selection: "active_page_required",
    stale_target_recovery: true,
    current_tab_guard: true,
    export_guard: true,
};
const TARGET_BROWSER_CONTEXT: BrowserTargetPolicy = BrowserTargetPolicy {
    scope: "browser_context",
    selection: "active_context_required",
    stale_target_recovery: true,
    current_tab_guard: false,
    export_guard: false,
};
const TARGET_CONNECTOR_POLICY: BrowserTargetPolicy = BrowserTargetPolicy {
    scope: "connector_policy",
    selection: "no_browser_target",
    stale_target_recovery: false,
    current_tab_guard: false,
    export_guard: false,
};

#[derive(Clone, Copy)]
enum BrowserControlImplementation {
    Cdp { methods: &'static [&'static str] },
    WorkerPolicy { description: &'static str },
}

impl BrowserControlImplementation {
    fn descriptor(self) -> serde_json::Value {
        match self {
            Self::Cdp { methods } => serde_json::json!({
                "kind": "cdp",
                "protocol": "Chrome DevTools Protocol",
                "methods": methods,
            }),
            Self::WorkerPolicy { description } => serde_json::json!({
                "kind": "worker_policy",
                "description": description,
                "redaction_contract": PROXY_REDACTION_CONTRACT,
                "methods": [],
            }),
        }
    }

    fn summary(self) -> String {
        match self {
            Self::Cdp { methods } => format!("cdp methods [{}]", methods.join(", ")),
            Self::WorkerPolicy { description } => format!(
                "worker_policy description `{description}` with redaction_contract `{PROXY_REDACTION_CONTRACT}`"
            ),
        }
    }
}

fn browser_control_endpoint_for_url(url: &str) -> BrowserResult<BrowserControlEndpoint> {
    if !url.starts_with("ws://") && !url.starts_with("wss://") {
        return Ok(BrowserControlEndpoint::FcpControlPlane);
    }

    let parsed = WsUrl::parse(url).map_err(|err| {
        BrowserError::InvalidConfig(format!(
            "invalid direct Chrome DevTools WebSocket URL: {err}"
        ))
    })?;
    let authority = url
        .split_once("://")
        .and_then(|(_, rest)| rest.split('/').next())
        .unwrap_or_default();
    if authority.contains('@') {
        return Err(BrowserError::InvalidConfig(
            "direct Chrome DevTools WebSocket URL must not contain userinfo".into(),
        ));
    }
    if parsed.tls {
        return Err(BrowserError::InvalidConfig(
            "direct Chrome DevTools WebSocket URLs must use ws:// until the asupersync TLS WebSocket transport is wired"
                .into(),
        ));
    }
    if parsed.path.contains('?') || parsed.path.contains('#') {
        return Err(BrowserError::InvalidConfig(
            "direct Chrome DevTools WebSocket URL must not contain query strings or fragments"
                .into(),
        ));
    }
    if !is_loopback_direct_cdp_host(&parsed.host) {
        return Err(BrowserError::InvalidConfig(format!(
            "direct Chrome DevTools WebSocket URL must use a loopback host, got `{}`",
            parsed.host
        )));
    }

    let target = direct_cdp_target_from_path(&parsed.path)?;
    if target.kind != DirectCdpTargetKind::Page {
        return Err(BrowserError::InvalidConfig(format!(
            "direct Chrome DevTools WebSocket URL targets an unsupported {} endpoint; direct CDP mode supports only page endpoints under /devtools/page/<target-id>",
            target.kind.as_str()
        )));
    }
    let redacted_url = redacted_direct_cdp_url(&parsed, &target);

    Ok(BrowserControlEndpoint::DirectCdp(DirectCdpEndpoint {
        url: url.to_string(),
        endpoint_kind: DirectCdpEndpointKind::WebSocket,
        target,
        redacted_url,
    }))
}

fn direct_cdp_target_from_path(path: &str) -> BrowserResult<DirectCdpTarget> {
    let mut segments = path.split('/').filter(|segment| !segment.is_empty());
    let Some("devtools") = segments.next() else {
        return Err(BrowserError::InvalidConfig(
            "direct Chrome DevTools WebSocket URL must target /devtools/page/<target-id>".into(),
        ));
    };
    let Some(path_kind) = segments.next() else {
        return Err(BrowserError::InvalidConfig(
            "direct Chrome DevTools WebSocket URL is missing target kind".into(),
        ));
    };
    let Some(target_id) = segments.next().filter(|target_id| !target_id.is_empty()) else {
        return Err(BrowserError::InvalidConfig(
            "direct Chrome DevTools WebSocket URL is missing target id".into(),
        ));
    };
    if segments.next().is_some() {
        return Err(BrowserError::InvalidConfig(
            "direct Chrome DevTools target id must be a single path segment".into(),
        ));
    }

    let kind = match path_kind {
        "page" => DirectCdpTargetKind::Page,
        "browser" => DirectCdpTargetKind::Browser,
        "worker" | "shared_worker" | "service_worker" => DirectCdpTargetKind::Worker,
        _ => DirectCdpTargetKind::Unsupported,
    };
    Ok(DirectCdpTarget {
        kind,
        path_kind: path_kind.to_string(),
        id_hash: direct_cdp_target_id_hash(target_id),
    })
}

fn direct_cdp_target_id_hash(target_id: &str) -> String {
    direct_cdp_redaction_hash(target_id)
}

fn direct_cdp_redaction_hash(value: &str) -> String {
    blake3::hash(value.as_bytes())
        .to_hex()
        .as_str()
        .chars()
        .take(16)
        .collect()
}

const fn direct_cdp_manager_command_line() -> &'static str {
    "fcp-browser direct-cdp target-session-manager"
}

fn direct_cdp_git_revision() -> String {
    option_env!("GIT_COMMIT")
        .or(option_env!("VERGEN_GIT_SHA"))
        .or(option_env!("SOURCE_DATE_EPOCH"))
        .unwrap_or("unknown")
        .to_string()
}

fn rust_owned_redaction_hash(value: &str) -> String {
    direct_cdp_redaction_hash(value)
}

fn rust_owned_platform_discovery_descriptor() -> String {
    rust_owned_platform_discovery_candidates().join("|")
}

fn rust_owned_platform_discovery_candidates() -> &'static [&'static str] {
    #[cfg(target_os = "macos")]
    {
        &[
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        ]
    }
    #[cfg(target_os = "linux")]
    {
        &[
            "/usr/bin/google-chrome",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/bin/microsoft-edge",
        ]
    }
    #[cfg(target_os = "windows")]
    {
        &[
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        ]
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        &[]
    }
}

fn validate_rust_owned_launcher_config(config: &BrowserLauncherConfig) -> BrowserResult<()> {
    match config.mode() {
        BrowserLauncherMode::Fixture => Ok(()),
        BrowserLauncherMode::Native => {
            if let Some(path) = config.browser_binary_path() {
                validate_rust_owned_browser_binary_path(path)?;
            } else if rust_owned_platform_discovery_candidates().is_empty() {
                return Err(rust_owned_launcher_error(
                    "browser.launch",
                    "launcher_unsupported_platform",
                    "no documented browser discovery paths exist for this platform",
                ));
            }
            Ok(())
        }
    }
}

fn validate_rust_owned_browser_binary_path(path: &str) -> BrowserResult<()> {
    if path.is_empty() {
        return Err(rust_owned_launcher_error(
            "browser.launch",
            "launcher_invalid_binary_path",
            "browser binary path must not be empty",
        ));
    }
    if !Path::new(path).is_absolute() {
        return Err(rust_owned_launcher_error(
            "browser.launch",
            "launcher_invalid_binary_path",
            "browser binary path must be absolute",
        ));
    }
    reject_launcher_arg_injection("browser_binary_path", path)
}

fn readiness_failure(checkpoint: &'static str) -> Option<(&'static str, &'static str)> {
    match checkpoint {
        "readiness_timeout" => Some((
            "launcher_readiness_timeout",
            "browser readiness did not complete before the configured timeout",
        )),
        _ => None,
    }
}

fn build_rust_owned_launcher_args(proxy: Option<&ProxyConfig>) -> BrowserResult<Vec<String>> {
    let mut args = vec![
        "--headless=new".to_string(),
        "--disable-background-networking".to_string(),
        "--disable-sync".to_string(),
        "--no-first-run".to_string(),
        "--remote-debugging-address=127.0.0.1".to_string(),
        "--remote-debugging-port=0".to_string(),
        RUST_LAUNCHER_PROFILE_ARG.to_string(),
    ];

    if let Some(proxy) = proxy {
        args.push(format!("--proxy-server={}", proxy.server));
        if let Some(bypass_list) = &proxy.bypass_list {
            if !bypass_list.is_empty() {
                args.push(format!("--proxy-bypass-list={}", bypass_list.join(",")));
            }
        }
    }

    deduplicate_and_validate_launcher_args(args)
}

fn deduplicate_and_validate_launcher_args(args: Vec<String>) -> BrowserResult<Vec<String>> {
    if args.len() > RUST_LAUNCHER_MAX_ARGS {
        return Err(rust_owned_launcher_error(
            "browser.launch",
            "launcher_too_many_arguments",
            "browser launch argument count exceeds the bounded policy",
        ));
    }

    let mut deduplicated = Vec::with_capacity(args.len());
    for arg in args {
        reject_launcher_arg_injection("browser_launch_arg", &arg)?;
        if !deduplicated.iter().any(|existing| existing == &arg) {
            deduplicated.push(arg);
        }
    }
    Ok(deduplicated)
}

fn materialize_rust_owned_launcher_args(
    planned_args: &[String],
    profile_dir: &Path,
) -> BrowserResult<Vec<String>> {
    let profile_arg = format!("--user-data-dir={}", profile_dir.display());
    reject_launcher_arg_injection("browser_profile_dir", &profile_arg)?;
    planned_args
        .iter()
        .map(|arg| {
            if arg == RUST_LAUNCHER_PROFILE_ARG {
                Ok(profile_arg.clone())
            } else {
                Ok(arg.clone())
            }
        })
        .collect()
}

fn reject_launcher_arg_injection(field: &'static str, value: &str) -> BrowserResult<()> {
    if value.len() > RUST_LAUNCHER_ARG_MAX_BYTES {
        return Err(rust_owned_launcher_error(
            "browser.launch",
            "launcher_argument_too_large",
            "browser launch argument exceeds the bounded byte policy",
        ));
    }
    if value
        .chars()
        .any(|ch| ch.is_control() || matches!(ch, ';' | '`' | '$' | '|' | '&' | '<' | '>'))
    {
        return Err(rust_owned_launcher_error(
            "browser.launch",
            "launcher_argument_injection",
            &format!("{field} contains shell metacharacters or control characters"),
        ));
    }
    Ok(())
}

fn proxy_config_descriptor_hash(proxy: &ProxyConfig) -> BrowserResult<String> {
    let bytes = serde_json::to_vec(proxy)?;
    Ok(format!(
        "blake3:{}",
        blake3::hash(&bytes)
            .to_hex()
            .as_str()
            .chars()
            .take(16)
            .collect::<String>()
    ))
}

fn resolve_rust_owned_browser_binary(config: &BrowserLauncherConfig) -> BrowserResult<String> {
    if let Some(path) = config.browser_binary_path() {
        validate_rust_owned_browser_binary_path(path)?;
        if Path::new(path).is_file() {
            return Ok(path.to_string());
        }
        return Err(rust_owned_launcher_error(
            "browser.launch",
            "launcher_browser_binary_not_found",
            "configured browser binary path does not exist or is not a file",
        ));
    }

    rust_owned_platform_discovery_candidates()
        .iter()
        .copied()
        .find(|path| Path::new(path).is_file())
        .map(str::to_string)
        .ok_or_else(|| {
            rust_owned_launcher_error(
                "browser.launch",
                "launcher_browser_binary_not_found",
                "no configured or documented browser binary path exists on this host",
            )
        })
}

fn read_devtools_active_port(
    profile_dir: &Path,
) -> BrowserResult<Option<RustOwnedDevtoolsEndpoint>> {
    let active_port_path = profile_dir.join(RUST_LAUNCHER_DEVTOOLS_ACTIVE_PORT);
    let contents = match std::fs::read_to_string(&active_port_path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(rust_owned_launcher_error(
                "browser.launch",
                "launcher_readiness_file_invalid",
                &format!("failed to read browser readiness file: {err}"),
            ));
        }
    };

    let mut lines = contents.lines();
    let port = lines
        .next()
        .ok_or_else(|| {
            rust_owned_launcher_error(
                "browser.launch",
                "launcher_readiness_file_invalid",
                "browser readiness file is missing the DevTools port",
            )
        })?
        .parse::<u16>()
        .map_err(|_| {
            rust_owned_launcher_error(
                "browser.launch",
                "launcher_readiness_file_invalid",
                "browser readiness file contains an invalid DevTools port",
            )
        })?;
    let path = lines.next().unwrap_or("/devtools/browser").to_string();
    reject_launcher_arg_injection("browser_devtools_path", &path)?;
    Ok(Some(RustOwnedDevtoolsEndpoint { port, path }))
}

fn terminate_child_for_launcher(child: &mut Child) -> &'static str {
    match child.try_wait() {
        Ok(Some(_)) => return "native_child_already_reaped",
        Ok(None) => {}
        Err(_) => return "native_child_state_unknown",
    }

    let _ = child.kill();
    for _ in 0..80 {
        match child.try_wait() {
            Ok(Some(_)) => return "native_child_killed_and_reaped",
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(_) => return "native_child_state_unknown_after_kill",
        }
    }
    "native_child_kill_requested_not_reaped"
}

fn duration_millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn lock_direct_cdp_manager(
    manager: &Arc<Mutex<DirectCdpTargetSessionManager>>,
) -> BrowserResult<MutexGuard<'_, DirectCdpTargetSessionManager>> {
    manager.lock().map_err(|_| BrowserError::Api {
        message: "direct CDP target/session manager lock was poisoned".into(),
        status_code: None,
    })
}

fn lock_rust_owned_launcher(
    launcher: &Arc<Mutex<Option<RustOwnedLauncherSupervisor>>>,
) -> BrowserResult<MutexGuard<'_, Option<RustOwnedLauncherSupervisor>>> {
    launcher.lock().map_err(|_| BrowserError::Api {
        message: "rust-owned browser launcher supervisor lock was poisoned".into(),
        status_code: None,
    })
}

fn redacted_direct_cdp_url(parsed: &WsUrl, target: &DirectCdpTarget) -> String {
    format!(
        "ws://{}/devtools/{}/target-hash-{}",
        parsed.host_header(),
        target.path_kind,
        target.id_hash
    )
}

fn is_loopback_direct_cdp_host(host: &str) -> bool {
    let normalized = host
        .trim_matches(|ch| ch == '[' || ch == ']')
        .to_ascii_lowercase();
    normalized == "localhost"
        || normalized
            .parse::<IpAddr>()
            .is_ok_and(|addr| addr.is_loopback())
}

#[derive(Debug, Clone, PartialEq, serde::Serialize)]
struct CdpCommand {
    id: u64,
    method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<serde_json::Value>,
}

impl CdpCommand {
    fn new(id: u64, method: impl Into<String>, params: Option<serde_json::Value>) -> Self {
        Self {
            id,
            method: method.into(),
            params,
        }
    }

    fn to_websocket_message(&self) -> BrowserResult<WebSocketMessage> {
        Ok(WebSocketMessage::Text(serde_json::to_string(self)?))
    }
}

#[derive(Debug, Clone, PartialEq)]
struct CdpNavigateResponse {
    frame_id: String,
    loader_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CdpNavigationWait {
    DomContentLoaded,
    Load,
    NetworkIdle,
}

#[derive(Debug, Clone, PartialEq)]
struct CdpNavigationCompletion {
    status: Option<u16>,
    loader_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
struct CdpNavigationResponseEvent {
    status: u16,
    loader_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
struct CdpEvent {
    method: String,
    params: serde_json::Value,
}

impl CdpNavigateResponse {
    fn from_result(result: &serde_json::Value) -> BrowserResult<Self> {
        if let Some(error_text) = result
            .get("errorText")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
        {
            return Err(BrowserError::Api {
                message: format!(
                    "Chrome DevTools Protocol navigation failed: {}",
                    redact_browser_control_error_text(error_text)
                ),
                status_code: None,
            });
        }

        let frame_id = result
            .get("frameId")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| BrowserError::Api {
                message: "Chrome DevTools Protocol Page.navigate response is missing frameId"
                    .into(),
                status_code: None,
            })?
            .to_string();
        let loader_id = result
            .get("loaderId")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_string);

        Ok(Self {
            frame_id,
            loader_id,
        })
    }
}

impl CdpNavigationWait {
    fn from_wait_until(wait_until: Option<&str>) -> BrowserResult<Self> {
        let Some(wait_until) = wait_until else {
            return Ok(Self::Load);
        };
        match wait_until.to_ascii_lowercase().as_str() {
            "domcontentloaded" | "dom_content_loaded" => Ok(Self::DomContentLoaded),
            "load" => Ok(Self::Load),
            "networkidle" | "network_idle" => Ok(Self::NetworkIdle),
            other => Err(BrowserError::InvalidConfig(format!(
                "direct Chrome DevTools navigation wait_until must be domcontentloaded, load, or networkidle, got `{other}`"
            ))),
        }
    }

    fn matches_event(self, event: &CdpEvent, navigation: &CdpNavigateResponse) -> bool {
        match event.method.as_str() {
            "Page.domContentEventFired" => {
                self == Self::DomContentLoaded
                    && cdp_event_matches_navigation_for_wait(event, navigation)
            }
            "Page.loadEventFired" => {
                self == Self::Load && cdp_event_matches_navigation_for_wait(event, navigation)
            }
            "Page.lifecycleEvent" => {
                cdp_event_matches_navigation_frame(&event.params, navigation)
                    && event
                        .params
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|name| match self {
                            Self::DomContentLoaded => name == "DOMContentLoaded",
                            Self::Load => name == "load",
                            Self::NetworkIdle => name == "networkIdle",
                        })
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct CdpEvaluateResponse {
    result: String,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
struct CdpLocationReadiness {
    href: String,
    ready_state: String,
    #[serde(default)]
    navigation_entry_name: Option<String>,
    #[serde(default)]
    time_origin: Option<f64>,
    matched: bool,
}

#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
struct CdpDocumentSnapshot {
    href: String,
    #[serde(default)]
    time_origin: Option<f64>,
}

impl CdpEvaluateResponse {
    fn from_result(result: &serde_json::Value) -> BrowserResult<Self> {
        if let Some(exception) = result.get("exceptionDetails") {
            let mut redacted_exception = exception.clone();
            redact_sensitive_json(&mut redacted_exception);
            return Err(BrowserError::Api {
                message: format!(
                    "Chrome DevTools Protocol Runtime.evaluate failed: {}",
                    serde_json::to_string(&redacted_exception)?
                ),
                status_code: None,
            });
        }

        let remote_object = result.get("result").ok_or_else(|| BrowserError::Api {
            message: "Chrome DevTools Protocol Runtime.evaluate response is missing result object"
                .into(),
            status_code: None,
        })?;

        let result = if let Some(value) = remote_object.get("value") {
            cdp_remote_value_to_result_string(value)?
        } else if let Some(value) = remote_object
            .get("unserializableValue")
            .and_then(serde_json::Value::as_str)
        {
            value.to_string()
        } else if remote_object
            .get("type")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|kind| kind == "undefined")
        {
            "undefined".to_string()
        } else if let Some(description) = remote_object
            .get("description")
            .and_then(serde_json::Value::as_str)
        {
            description.to_string()
        } else {
            return Err(BrowserError::Api {
                message:
                    "Chrome DevTools Protocol Runtime.evaluate result has no serializable value"
                        .into(),
                status_code: None,
            });
        };

        Ok(Self { result })
    }
}

fn cdp_parse_text_result(response: &CdpEvaluateResponse) -> BrowserResult<TextResult> {
    serde_json::from_str::<TextResult>(&response.result).map_err(|err| BrowserError::Api {
        message: format!(
            "Chrome DevTools Protocol Runtime.evaluate returned invalid extract_text payload: {err}"
        ),
        status_code: None,
    })
}

fn cdp_parse_links_result(response: &CdpEvaluateResponse) -> BrowserResult<LinksResult> {
    serde_json::from_str::<LinksResult>(&response.result).map_err(|err| BrowserError::Api {
        message: format!(
            "Chrome DevTools Protocol Runtime.evaluate returned invalid extract_links payload: {err}"
        ),
        status_code: None,
    })
}

fn cdp_parse_wait_result(response: &CdpEvaluateResponse) -> BrowserResult<WaitResult> {
    serde_json::from_str::<WaitResult>(&response.result).map_err(|err| BrowserError::Api {
        message: format!(
            "Chrome DevTools Protocol Runtime.evaluate returned invalid wait_for_selector payload: {err}"
        ),
        status_code: None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CdpFormField {
    selector: String,
    value: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
struct CdpFormFieldPlan {
    text_to_insert: Option<String>,
}

fn cdp_parse_form_field_plan(response: &CdpEvaluateResponse) -> BrowserResult<CdpFormFieldPlan> {
    serde_json::from_str::<CdpFormFieldPlan>(&response.result).map_err(|err| BrowserError::Api {
        message: format!(
            "Chrome DevTools Protocol Runtime.evaluate returned invalid fill_form payload: {err}"
        ),
        status_code: None,
    })
}

#[derive(Debug, Clone, PartialEq)]
struct CdpScreenshotResponse {
    image_data: String,
    width: u32,
    height: u32,
}

impl CdpScreenshotResponse {
    fn from_capture_result(
        result: &serde_json::Value,
        clip: CdpCaptureClip,
    ) -> BrowserResult<Self> {
        let image_data = result
            .get("data")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| BrowserError::Api {
                message: "Chrome DevTools Protocol Page.captureScreenshot response is missing data"
                    .into(),
                status_code: None,
            })?
            .to_string();

        Ok(Self {
            image_data,
            width: capture_dimension_to_u32("width", clip.width)?,
            height: capture_dimension_to_u32("height", clip.height)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CdpPdfResponse {
    pdf_data: String,
    page_count: u32,
}

impl CdpPdfResponse {
    fn from_print_result(result: &serde_json::Value) -> BrowserResult<Self> {
        if result.get("stream").is_some() {
            return Err(BrowserError::Api {
                message: "Chrome DevTools Protocol Page.printToPDF returned an IO stream; expected base64 data"
                    .into(),
                status_code: None,
            });
        }

        let pdf_data = result
            .get("data")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| BrowserError::Api {
                message: "Chrome DevTools Protocol Page.printToPDF response is missing data".into(),
                status_code: None,
            })?
            .to_string();
        let page_count = count_pdf_pages_from_base64(&pdf_data)?;

        Ok(Self {
            pdf_data,
            page_count,
        })
    }
}

#[derive(Debug, Clone)]
struct CdpCookieResponse {
    cookies: Vec<Cookie>,
}

impl CdpCookieResponse {
    fn from_result(result: &serde_json::Value, domain_filter: Option<&str>) -> BrowserResult<Self> {
        let cookies = result
            .get("cookies")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| BrowserError::Api {
                message: "Chrome DevTools Protocol Network.getCookies response is missing cookies"
                    .into(),
                status_code: None,
            })?;
        let mut parsed = Vec::new();
        for cookie in cookies {
            let cookie = cdp_cookie_from_value(cookie)?;
            if cookie_matches_domain_filter(cookie.domain.as_deref(), domain_filter) {
                parsed.push(cookie);
            }
        }

        Ok(Self { cookies: parsed })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CdpSetCookiesResponse {
    set_count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct CdpCaptureClip {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
}

impl CdpCaptureClip {
    fn new(x: f64, y: f64, width: f64, height: f64) -> BrowserResult<Self> {
        for (name, value) in [("x", x), ("y", y), ("width", width), ("height", height)] {
            if !value.is_finite() {
                return Err(BrowserError::Api {
                    message: format!(
                        "Chrome DevTools Protocol screenshot clip {name} is not finite"
                    ),
                    status_code: None,
                });
            }
        }

        if width <= 0.0 || height <= 0.0 {
            return Err(BrowserError::Api {
                message: format!(
                    "Chrome DevTools Protocol screenshot clip must have positive dimensions: width={width}, height={height}"
                ),
                status_code: None,
            });
        }

        Ok(Self {
            x,
            y,
            width,
            height,
        })
    }

    fn from_box_model(result: &serde_json::Value) -> BrowserResult<Self> {
        let content = result
            .get("model")
            .and_then(|model| model.get("content"))
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| BrowserError::Api {
                message:
                    "Chrome DevTools Protocol DOM.getBoxModel response is missing model.content"
                        .into(),
                status_code: None,
            })?;
        if content.len() != 8 {
            return Err(BrowserError::Api {
                message: format!(
                    "Chrome DevTools Protocol DOM.getBoxModel content quad must have 8 coordinates, got {}",
                    content.len()
                ),
                status_code: None,
            });
        }

        let mut min_x = f64::INFINITY;
        let mut min_y = f64::INFINITY;
        let mut max_x = f64::NEG_INFINITY;
        let mut max_y = f64::NEG_INFINITY;
        for point in content.chunks_exact(2) {
            let [x_value, y_value] = point else {
                return Err(BrowserError::Api {
                    message: "Chrome DevTools Protocol DOM.getBoxModel content point is malformed"
                        .into(),
                    status_code: None,
                });
            };
            let x = cdp_required_number(x_value, "DOM.getBoxModel model.content x")?;
            let y = cdp_required_number(y_value, "DOM.getBoxModel model.content y")?;
            min_x = min_x.min(x);
            min_y = min_y.min(y);
            max_x = max_x.max(x);
            max_y = max_y.max(y);
        }

        Self::new(min_x, min_y, max_x - min_x, max_y - min_y)
    }

    fn from_layout_metrics(result: &serde_json::Value, full_page: bool) -> BrowserResult<Self> {
        if full_page {
            let content = result
                .get("cssContentSize")
                .or_else(|| result.get("contentSize"))
                .ok_or_else(|| BrowserError::Api {
                    message: "Chrome DevTools Protocol Page.getLayoutMetrics response is missing content size"
                        .into(),
                    status_code: None,
                })?;
            return Self::new(
                cdp_required_object_number(content, "x", "Page.getLayoutMetrics content x")?,
                cdp_required_object_number(content, "y", "Page.getLayoutMetrics content y")?,
                cdp_required_object_number(
                    content,
                    "width",
                    "Page.getLayoutMetrics content width",
                )?,
                cdp_required_object_number(
                    content,
                    "height",
                    "Page.getLayoutMetrics content height",
                )?,
            );
        }

        let viewport = result
            .get("cssVisualViewport")
            .or_else(|| result.get("visualViewport"))
            .or_else(|| result.get("cssLayoutViewport"))
            .or_else(|| result.get("layoutViewport"))
            .ok_or_else(|| BrowserError::Api {
                message: "Chrome DevTools Protocol Page.getLayoutMetrics response is missing viewport size"
                    .into(),
                status_code: None,
            })?;
        Self::new(
            cdp_required_object_number(viewport, "pageX", "Page.getLayoutMetrics viewport pageX")
                .or_else(|_| {
                cdp_required_object_number(viewport, "x", "Page.getLayoutMetrics viewport x")
            })?,
            cdp_required_object_number(viewport, "pageY", "Page.getLayoutMetrics viewport pageY")
                .or_else(|_| {
                cdp_required_object_number(viewport, "y", "Page.getLayoutMetrics viewport y")
            })?,
            cdp_required_object_number(
                viewport,
                "clientWidth",
                "Page.getLayoutMetrics viewport clientWidth",
            )
            .or_else(|_| {
                cdp_required_object_number(
                    viewport,
                    "width",
                    "Page.getLayoutMetrics viewport width",
                )
            })?,
            cdp_required_object_number(
                viewport,
                "clientHeight",
                "Page.getLayoutMetrics viewport clientHeight",
            )
            .or_else(|_| {
                cdp_required_object_number(
                    viewport,
                    "height",
                    "Page.getLayoutMetrics viewport height",
                )
            })?,
        )
    }

    fn descriptor(self) -> serde_json::Value {
        serde_json::json!({
            "x": self.x,
            "y": self.y,
            "width": self.width,
            "height": self.height,
            "scale": 1,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct CdpMousePoint {
    x: f64,
    y: f64,
}

impl CdpMousePoint {
    fn from_box_model(result: &serde_json::Value) -> BrowserResult<Self> {
        let clip = CdpCaptureClip::from_box_model(result)?;
        Ok(Self {
            x: clip.x + (clip.width / 2.0),
            y: clip.y + (clip.height / 2.0),
        })
    }
}

fn cdp_remote_value_to_result_string(value: &serde_json::Value) -> BrowserResult<String> {
    match value {
        serde_json::Value::String(text) => Ok(text.clone()),
        serde_json::Value::Null => Ok("null".to_string()),
        other => Ok(serde_json::to_string(other)?),
    }
}

fn cdp_wait_for_location_expression(
    expected_url: &str,
    wait_until: Option<&str>,
    require_new_document: bool,
    previous_time_origin: Option<f64>,
) -> BrowserResult<String> {
    let expected_url = serde_json::to_string(expected_url)?;
    let required_ready_state =
        serde_json::to_string(cdp_required_ready_state_for_navigation(wait_until)?)?;
    let previous_time_origin = serde_json::to_string(&previous_time_origin)?;
    Ok(format!(
        r#"(function() {{
  const expectedUrl = {expected_url};
  const requiredReadyState = {required_ready_state};
  const requireNewDocument = {require_new_document};
  const previousTimeOrigin = {previous_time_origin};
  const isDocumentReady = () => {{
    if (requiredReadyState === "interactive") {{
      return document.readyState === "interactive" || document.readyState === "complete";
    }}
    return document.readyState === "complete";
  }};
  const navigationEntryName = () => {{
    const entries = performance.getEntriesByType("navigation");
    if (!entries || entries.length === 0) {{
      return null;
    }}
    const entry = entries[entries.length - 1];
    return typeof entry.name === "string" ? entry.name : null;
  }};
  const timeOriginChanged = () => typeof previousTimeOrigin !== "number" || performance.timeOrigin !== previousTimeOrigin;
  // A new document's final URL legitimately diverges from the requested URL
  // on server-side redirects (and trailing-slash normalization), so document
  // identity is proven by the time-origin change rather than URL equality —
  // the loader-aware navigation wait that precedes this poll already
  // confirmed which navigation committed. Same-document (fragment)
  // navigations keep exact URL matching: they never change the time origin.
  const isExpectedDocument = () => requireNewDocument
    ? timeOriginChanged()
    : window.location.href === expectedUrl;
  const snapshot = (matched) => ({{
    href: window.location.href,
    ready_state: document.readyState,
    navigation_entry_name: navigationEntryName(),
    time_origin: Number.isFinite(performance.timeOrigin) ? performance.timeOrigin : null,
    matched,
  }});
  const matched = isExpectedDocument() && isDocumentReady();
  return snapshot(matched);
}})()"#
    ))
}

fn cdp_required_ready_state_for_navigation(
    wait_until: Option<&str>,
) -> BrowserResult<&'static str> {
    match CdpNavigationWait::from_wait_until(wait_until)? {
        CdpNavigationWait::DomContentLoaded => Ok("interactive"),
        CdpNavigationWait::Load | CdpNavigationWait::NetworkIdle => Ok("complete"),
    }
}

fn redact_browser_url(raw_url: &str) -> String {
    let Ok(mut parsed) = reqwest::Url::parse(raw_url) else {
        return "[redacted-url]".to_string();
    };
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.to_string()
}

fn cdp_parse_location_readiness_snapshot(
    response: &CdpEvaluateResponse,
) -> BrowserResult<CdpLocationReadiness> {
    serde_json::from_str::<CdpLocationReadiness>(&response.result).map_err(|err| {
        BrowserError::Api {
            message: format!(
                "Chrome DevTools Protocol Runtime.evaluate returned invalid navigation readiness payload: {err}"
            ),
            status_code: None,
        }
    })
}

fn cdp_parse_document_snapshot(
    response: &CdpEvaluateResponse,
) -> BrowserResult<CdpDocumentSnapshot> {
    serde_json::from_str::<CdpDocumentSnapshot>(&response.result).map_err(|err| {
        BrowserError::Api {
            message: format!(
                "Chrome DevTools Protocol Runtime.evaluate returned invalid document snapshot payload: {err}"
            ),
            status_code: None,
        }
    })
}

fn cdp_navigation_readiness_timeout_error(
    expected_url: &str,
    readiness: Option<&CdpLocationReadiness>,
) -> BrowserError {
    let (observed_url, ready_state, navigation_entry_name, time_origin) = readiness.map_or_else(
        || {
            (
                "[unobserved]".to_string(),
                "unknown".to_string(),
                "missing".to_string(),
                "missing".to_string(),
            )
        },
        |readiness| {
            (
                redact_browser_url(&readiness.href),
                readiness.ready_state.clone(),
                readiness
                    .navigation_entry_name
                    .as_deref()
                    .map_or_else(|| "missing".to_string(), redact_browser_url),
                readiness
                    .time_origin
                    .map_or_else(|| "missing".to_string(), |value| value.to_string()),
            )
        },
    );
    BrowserError::Api {
        message: format!(
            "Chrome DevTools Protocol navigation did not reach expected active document before timeout: expected {}, observed {} with readyState {}, navigation entry {}, and timeOrigin {}",
            redact_browser_url(expected_url),
            observed_url,
            ready_state,
            navigation_entry_name,
            time_origin
        ),
        status_code: Some(408),
    }
}

fn cdp_location_readiness_error_is_retryable(error: &BrowserError) -> bool {
    let BrowserError::Api { message, .. } = error else {
        return false;
    };
    message.contains("Execution context was destroyed")
        || message.contains("Cannot find context with specified id")
        || message.contains("Inspected target navigated or closed")
}

fn cdp_requires_new_document_for_navigation(previous_url: Option<&str>, next_url: &str) -> bool {
    previous_url.is_none_or(|previous_url| {
        let (Ok(mut previous), Ok(mut next)) = (
            reqwest::Url::parse(previous_url),
            reqwest::Url::parse(next_url),
        ) else {
            return true;
        };
        let previous_fragment = previous.fragment().map(str::to_string);
        let next_fragment = next.fragment().map(str::to_string);
        previous.set_fragment(None);
        next.set_fragment(None);
        previous != next || previous_fragment == next_fragment
    })
}

fn cdp_extract_text_expression(
    selector: Option<&str>,
    include_hidden: Option<bool>,
) -> BrowserResult<String> {
    let selector = serde_json::to_string(&selector)?;
    let include_hidden = include_hidden.unwrap_or(false);
    Ok(format!(
        r#"(function() {{
  const selector = {selector};
  const includeHidden = {include_hidden};
  const root = selector === null ? (document.body ?? document.documentElement) : document.querySelector(selector);
  if (!root) {{
    throw new Error("selector not found: " + selector);
  }}
  const rawText = (includeHidden ? root.textContent : (root.innerText ?? root.textContent)) ?? "";
  const text = rawText.replace(/\s+/g, " ").trim();
  return {{
    text,
    word_count: text.length === 0 ? 0 : text.split(/\s+/).length,
  }};
}})()"#
    ))
}

fn cdp_extract_links_expression(selector: Option<&str>) -> BrowserResult<String> {
    let selector = serde_json::to_string(&selector)?;
    Ok(format!(
        r#"(function() {{
  const selector = {selector};
  const root = selector === null ? document : document.querySelector(selector);
  if (!root) {{
    throw new Error("selector not found: " + selector);
  }}
  const descendants = Array.from(root.querySelectorAll("a[href]"));
  const nodes = typeof root.matches === "function" && root.matches("a[href]") ? [root, ...descendants] : descendants;
  return {{
    links: nodes
      .map((node) => {{
        const text = ((node.innerText ?? node.textContent) ?? "").replace(/\s+/g, " ").trim();
        return {{ href: node.href, text: text.length === 0 ? null : text }};
      }})
      .filter((link) => link.href.length > 0),
  }};
}})()"#
    ))
}

fn cdp_wait_for_selector_expression(
    selector: &str,
    state: Option<&str>,
    timeout_ms: Option<u64>,
) -> BrowserResult<String> {
    let selector = serde_json::to_string(selector)?;
    let state = serde_json::to_string(cdp_wait_for_selector_state(state)?)?;
    let timeout_ms = cdp_wait_timeout_ms(timeout_ms)?;
    Ok(format!(
        r#"(function() {{
  const selector = {selector};
  const state = {state};
  const timeoutMs = {timeout_ms};
  const isVisible = (element) => {{
    if (!element) {{
      return false;
    }}
    const style = window.getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    return style.visibility !== "hidden"
      && style.display !== "none"
      && Number(style.opacity) !== 0
      && rect.width > 0
      && rect.height > 0;
  }};
  const matchesState = () => {{
    const element = document.querySelector(selector);
    switch (state) {{
      case "attached":
        return element !== null;
      case "detached":
        return element === null;
      case "visible":
        return isVisible(element);
      case "hidden":
        return element === null || !isVisible(element);
      default:
        throw new Error("unsupported wait state: " + state);
    }}
  }};
  if (matchesState()) {{
    return Promise.resolve({{ found: true }});
  }}
  if (timeoutMs === 0) {{
    return Promise.resolve({{ found: false }});
  }}
  return new Promise((resolve) => {{
    const root = document.documentElement ?? document;
    let settled = false;
    const observer = new MutationObserver(check);
    const finish = (found) => {{
      if (settled) {{
        return;
      }}
      settled = true;
      clearTimeout(timeoutId);
      clearInterval(intervalId);
      observer.disconnect();
      resolve({{ found }});
    }};
    const timeoutId = setTimeout(() => finish(false), timeoutMs);
    const intervalId = setInterval(check, 50);
    function check() {{
      if (matchesState()) {{
        finish(true);
      }}
    }}
    observer.observe(root, {{
      subtree: true,
      childList: true,
      attributes: true,
      attributeFilter: ["style", "class", "hidden", "aria-hidden"],
    }});
    check();
  }});
}})()"#
    ))
}

fn cdp_wait_for_selector_state(state: Option<&str>) -> BrowserResult<&'static str> {
    match state.unwrap_or("attached").to_ascii_lowercase().as_str() {
        "attached" | "present" => Ok("attached"),
        "detached" | "absent" => Ok("detached"),
        "visible" => Ok("visible"),
        "hidden" => Ok("hidden"),
        other => Err(BrowserError::Api {
            message: format!(
                "Chrome DevTools Protocol wait_for_selector does not support state `{other}`"
            ),
            status_code: None,
        }),
    }
}

fn cdp_wait_timeout_ms(timeout_ms: Option<u64>) -> BrowserResult<u64> {
    let timeout_ms = timeout_ms.unwrap_or(CONTROL_TIMEOUT_MS_STANDARD);
    if timeout_ms <= CONTROL_TIMEOUT_MS_STANDARD {
        Ok(timeout_ms)
    } else {
        Err(BrowserError::Api {
            message: format!(
                "Chrome DevTools Protocol wait_for_selector timeout {timeout_ms}ms exceeds operation budget {CONTROL_TIMEOUT_MS_STANDARD}ms"
            ),
            status_code: None,
        })
    }
}

fn cdp_form_fields(fields: &serde_json::Value) -> BrowserResult<Vec<CdpFormField>> {
    let object = fields.as_object().ok_or_else(|| BrowserError::Api {
        message: "Chrome DevTools Protocol fill_form fields must be an object map".into(),
        status_code: None,
    })?;

    let mut parsed = Vec::with_capacity(object.len());
    for (selector, value) in object {
        if selector.trim().is_empty() {
            return Err(BrowserError::Api {
                message: "Chrome DevTools Protocol fill_form field selector cannot be empty".into(),
                status_code: None,
            });
        }
        if matches!(
            value,
            serde_json::Value::Array(_) | serde_json::Value::Object(_)
        ) {
            return Err(BrowserError::Api {
                message: format!(
                    "Chrome DevTools Protocol fill_form field `{selector}` value must be scalar"
                ),
                status_code: None,
            });
        }
        parsed.push(CdpFormField {
            selector: selector.clone(),
            value: value.clone(),
        });
    }

    Ok(parsed)
}

fn cdp_fill_form_prepare_expression(
    selector: &str,
    value: &serde_json::Value,
) -> BrowserResult<String> {
    let selector = serde_json::to_string(selector)?;
    let value = serde_json::to_string(value)?;
    Ok(format!(
        r#"(function() {{
  const selector = {selector};
  const value = {value};
  const element = document.querySelector(selector);
  if (!element) {{
    throw new Error("selector not found: " + selector);
  }}
  const tagName = element.tagName.toLowerCase();
  const type = (element.getAttribute("type") ?? "").toLowerCase();
  const stringValue = value === null ? "" : String(value);
  const dispatch = () => {{
    element.dispatchEvent(new Event("input", {{ bubbles: true }}));
    element.dispatchEvent(new Event("change", {{ bubbles: true }}));
  }};
  element.scrollIntoView({{ block: "center", inline: "center" }});
  element.focus();
  if (tagName === "select") {{
    const values = Array.from(element.options).map((option) => option.value);
    if (!values.includes(stringValue)) {{
      throw new Error("select option not found for " + selector + ": " + stringValue);
    }}
    element.value = stringValue;
    dispatch();
    return {{ mode: "direct", text_to_insert: null }};
  }}
  if (type === "checkbox" || type === "radio") {{
    const checked = typeof value === "boolean"
      ? value
      : value === null
        ? false
        : ["true", "1", "yes", "on", "checked"].includes(String(value).toLowerCase());
    element.checked = checked;
    dispatch();
    return {{ mode: "direct", text_to_insert: null }};
  }}
  if (element.isContentEditable) {{
    element.textContent = "";
    dispatch();
    return {{ mode: "text", text_to_insert: stringValue }};
  }}
  if ("value" in element) {{
    element.value = "";
    dispatch();
    return {{ mode: "text", text_to_insert: stringValue }};
  }}
  throw new Error("unsupported form control for " + selector);
}})()"#
    ))
}

fn cdp_mouse_event_params(
    event_type: &str,
    point: CdpMousePoint,
    button: Option<&str>,
    buttons: Option<u32>,
    click_count: Option<u32>,
) -> serde_json::Value {
    let mut params = serde_json::Map::new();
    params.insert(
        "type".to_string(),
        serde_json::Value::String(event_type.to_string()),
    );
    params.insert("x".to_string(), serde_json::json!(point.x));
    params.insert("y".to_string(), serde_json::json!(point.y));
    if let Some(button) = button {
        params.insert(
            "button".to_string(),
            serde_json::Value::String(button.to_string()),
        );
    }
    if let Some(buttons) = buttons {
        params.insert("buttons".to_string(), serde_json::json!(buttons));
    }
    if let Some(click_count) = click_count {
        params.insert("clickCount".to_string(), serde_json::json!(click_count));
    }
    serde_json::Value::Object(params)
}

fn cdp_required_object_number(
    object: &serde_json::Value,
    field: &str,
    label: &str,
) -> BrowserResult<f64> {
    cdp_required_number(object.get(field).unwrap_or(&serde_json::Value::Null), label)
}

fn cdp_required_number(value: &serde_json::Value, label: &str) -> BrowserResult<f64> {
    let number = value.as_f64().ok_or_else(|| BrowserError::Api {
        message: format!("Chrome DevTools Protocol response is missing numeric {label}"),
        status_code: None,
    })?;
    if number.is_finite() {
        Ok(number)
    } else {
        Err(BrowserError::Api {
            message: format!("Chrome DevTools Protocol response {label} is not finite"),
            status_code: None,
        })
    }
}

fn cdp_required_node_id(result: &serde_json::Value, path: &str) -> BrowserResult<u64> {
    result
        .pointer(path)
        .and_then(serde_json::Value::as_u64)
        .filter(|node_id| *node_id != 0)
        .ok_or_else(|| BrowserError::Api {
            message: format!("Chrome DevTools Protocol response is missing non-zero {path}"),
            status_code: None,
        })
}

fn capture_dimension_to_u32(name: &str, value: f64) -> BrowserResult<u32> {
    if !value.is_finite() || value <= 0.0 || value > f64::from(u32::MAX) {
        return Err(BrowserError::Api {
            message: format!("Chrome DevTools Protocol screenshot {name} is out of range: {value}"),
            status_code: None,
        });
    }

    let rounded = value.ceil();
    format!("{rounded:.0}")
        .parse::<u32>()
        .map_err(|err| BrowserError::Api {
            message: format!(
                "Chrome DevTools Protocol screenshot {name} cannot be represented as u32: {err}"
            ),
            status_code: None,
        })
}

fn cdp_screenshot_format(format: Option<&str>) -> BrowserResult<String> {
    let format = format.unwrap_or("png").to_ascii_lowercase();
    if matches!(format.as_str(), "jpeg" | "png" | "webp") {
        Ok(format)
    } else {
        Err(BrowserError::Api {
            message: format!(
                "Chrome DevTools Protocol Page.captureScreenshot does not support image format `{format}`"
            ),
            status_code: None,
        })
    }
}

fn cdp_pdf_paper_size(format: Option<&str>) -> BrowserResult<Option<(f64, f64)>> {
    let Some(format) = format else {
        return Ok(None);
    };
    let size = match format.to_ascii_lowercase().as_str() {
        "letter" => (8.5, 11.0),
        "legal" => (8.5, 14.0),
        "tabloid" => (11.0, 17.0),
        "a0" => (33.11, 46.81),
        "a1" => (23.39, 33.11),
        "a2" => (16.54, 23.39),
        "a3" => (11.69, 16.54),
        "a4" => (8.27, 11.69),
        "a5" => (5.83, 8.27),
        "a6" => (4.13, 5.83),
        other => {
            return Err(BrowserError::Api {
                message: format!(
                    "Chrome DevTools Protocol Page.printToPDF does not support paper format `{other}`"
                ),
                status_code: None,
            });
        }
    };
    Ok(Some(size))
}

fn count_pdf_pages_from_base64(encoded: &str) -> BrowserResult<u32> {
    let pdf_bytes = BASE64_STANDARD
        .decode(encoded)
        .map_err(|err| BrowserError::Api {
            message: format!(
                "Chrome DevTools Protocol Page.printToPDF returned invalid base64 PDF data: {err}"
            ),
            status_code: None,
        })?;
    let page_count = count_pdf_page_objects(&pdf_bytes)?;
    u32::try_from(page_count).map_err(|err| BrowserError::Api {
        message: format!("Chrome DevTools Protocol Page.printToPDF page count exceeds u32: {err}"),
        status_code: None,
    })
}

fn count_pdf_page_objects(pdf_bytes: &[u8]) -> BrowserResult<usize> {
    let mut count = 0_usize;
    let mut offset = 0_usize;

    while let Some(relative_position) = pdf_bytes.get(offset..).and_then(|tail| {
        tail.windows(b"/Type".len())
            .position(|window| window == b"/Type")
    }) {
        let type_position = offset + relative_position;
        let after_type = type_position + b"/Type".len();
        if let Some(token_position) = skip_pdf_whitespace(pdf_bytes, after_type)
            && pdf_bytes
                .get(token_position..)
                .is_some_and(pdf_token_is_page_object)
        {
            count = count.checked_add(1).ok_or_else(|| BrowserError::Api {
                message: "Chrome DevTools Protocol Page.printToPDF page count overflowed usize"
                    .into(),
                status_code: None,
            })?;
        }
        offset = after_type;
    }

    if count == 0 {
        return Err(BrowserError::Api {
            message: "Chrome DevTools Protocol Page.printToPDF PDF data contains no page objects"
                .into(),
            status_code: None,
        });
    }

    Ok(count)
}

fn skip_pdf_whitespace(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start;
    loop {
        let byte = bytes.get(index)?;
        if matches!(byte, b'\0' | b'\t' | b'\n' | b'\x0c' | b'\r' | b' ') {
            index = index.checked_add(1)?;
        } else {
            return Some(index);
        }
    }
}

fn pdf_token_is_page_object(tail: &[u8]) -> bool {
    tail.starts_with(b"/Page") && tail.get(b"/Page".len()).is_some_and(pdf_delimits_token)
}

fn pdf_delimits_token(byte: &u8) -> bool {
    matches!(
        byte,
        b'\0'
            | b'\t'
            | b'\n'
            | b'\x0c'
            | b'\r'
            | b' '
            | b'/'
            | b'<'
            | b'>'
            | b'['
            | b']'
            | b'('
            | b')'
    )
}

fn cdp_cookie_from_value(value: &serde_json::Value) -> BrowserResult<Cookie> {
    let name = cdp_required_object_string(value, "name", "Network.Cookie name")?;
    let cookie_value = cdp_required_object_string(value, "value", "Network.Cookie value")?;

    Ok(Cookie {
        name,
        value: cookie_value,
        domain: cdp_optional_object_string(value, "domain"),
        path: cdp_optional_object_string(value, "path"),
        expires: value.get("expires").and_then(serde_json::Value::as_f64),
        http_only: value.get("httpOnly").and_then(serde_json::Value::as_bool),
        secure: value.get("secure").and_then(serde_json::Value::as_bool),
        same_site: cdp_optional_object_string(value, "sameSite"),
    })
}

fn cdp_cookie_param(cookie: &Cookie) -> serde_json::Value {
    let mut param = serde_json::Map::new();
    param.insert(
        "name".to_string(),
        serde_json::Value::String(cookie.name.clone()),
    );
    param.insert(
        "value".to_string(),
        serde_json::Value::String(cookie.value.clone()),
    );
    if let Some(domain) = &cookie.domain {
        param.insert(
            "domain".to_string(),
            serde_json::Value::String(domain.clone()),
        );
    }
    if let Some(path) = &cookie.path {
        param.insert("path".to_string(), serde_json::Value::String(path.clone()));
    }
    if let Some(expires) = cookie.expires {
        param.insert("expires".to_string(), serde_json::json!(expires));
    }
    if let Some(http_only) = cookie.http_only {
        param.insert("httpOnly".to_string(), serde_json::Value::Bool(http_only));
    }
    if let Some(secure) = cookie.secure {
        param.insert("secure".to_string(), serde_json::Value::Bool(secure));
    }
    if let Some(same_site) = &cookie.same_site {
        param.insert(
            "sameSite".to_string(),
            serde_json::Value::String(same_site.clone()),
        );
    }
    serde_json::Value::Object(param)
}

fn cdp_required_object_string(
    object: &serde_json::Value,
    field: &str,
    label: &str,
) -> BrowserResult<String> {
    object
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| BrowserError::Api {
            message: format!("Chrome DevTools Protocol response is missing non-empty {label}"),
            status_code: None,
        })
}

fn cdp_optional_object_string(object: &serde_json::Value, field: &str) -> Option<String> {
    object
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

fn cookie_matches_domain_filter(cookie_domain: Option<&str>, domain_filter: Option<&str>) -> bool {
    let Some(domain_filter) = domain_filter else {
        return true;
    };
    let Some(cookie_domain) = cookie_domain else {
        return false;
    };

    let normalized_cookie = cookie_domain.trim_start_matches('.').to_ascii_lowercase();
    let normalized_filter = domain_filter.trim_start_matches('.').to_ascii_lowercase();
    normalized_cookie == normalized_filter
        || normalized_cookie
            .strip_suffix(&normalized_filter)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn decode_cdp_event_message(message: WebSocketMessage) -> BrowserResult<Option<CdpEvent>> {
    match message {
        WebSocketMessage::Text(text) => decode_cdp_event_text(&text),
        WebSocketMessage::Binary(_) => Err(BrowserError::Api {
            message: "Chrome DevTools Protocol event must be UTF-8 text JSON".into(),
            status_code: None,
        }),
        WebSocketMessage::Close(_) => Err(BrowserError::Api {
            message: "Chrome DevTools Protocol connection closed before event stream completed"
                .into(),
            status_code: None,
        }),
        WebSocketMessage::Ping(_) | WebSocketMessage::Pong(_) => Ok(None),
    }
}

fn decode_cdp_event_text(text: &str) -> BrowserResult<Option<CdpEvent>> {
    let value: serde_json::Value = serde_json::from_str(text)?;
    let Some(method) = value.get("method").and_then(serde_json::Value::as_str) else {
        return Ok(None);
    };
    let params = value
        .get("params")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));

    Ok(Some(CdpEvent {
        method: method.to_string(),
        params,
    }))
}

fn cdp_event_matches_navigation_frame(
    params: &serde_json::Value,
    navigation: &CdpNavigateResponse,
) -> bool {
    let Some(frame_id) = params.get("frameId").and_then(serde_json::Value::as_str) else {
        return false;
    };
    if frame_id != navigation.frame_id {
        return false;
    }

    if let Some(expected_loader_id) = navigation.loader_id.as_deref() {
        let Some(loader_id) = params.get("loaderId").and_then(serde_json::Value::as_str) else {
            return false;
        };
        if loader_id != expected_loader_id {
            return false;
        }
    }

    true
}

fn cdp_event_matches_navigation_for_wait(
    event: &CdpEvent,
    navigation: &CdpNavigateResponse,
) -> bool {
    if event.params.get("frameId").is_some() {
        return cdp_event_matches_navigation_frame(&event.params, navigation);
    }

    false
}

fn cdp_navigation_response_event(
    event: &CdpEvent,
    navigation: &CdpNavigateResponse,
    expected_url: &str,
) -> BrowserResult<Option<CdpNavigationResponseEvent>> {
    if event.method != "Network.responseReceived" {
        return Ok(None);
    }
    if !cdp_event_matches_navigation_frame(&event.params, navigation) {
        return Ok(None);
    }
    if event.params.get("type").and_then(serde_json::Value::as_str) != Some("Document") {
        return Ok(None);
    }
    if navigation.loader_id.is_none() {
        let Some(response_url) = event
            .params
            .pointer("/response/url")
            .and_then(serde_json::Value::as_str)
        else {
            return Ok(None);
        };
        if response_url != expected_url {
            return Ok(None);
        }
    }

    let Some(status) = event
        .params
        .pointer("/response/status")
        .and_then(serde_json::Value::as_u64)
    else {
        return Err(BrowserError::Api {
            message: "Chrome DevTools Protocol Network.responseReceived document event is missing response.status"
                .into(),
            status_code: None,
        });
    };
    let status = u16::try_from(status).map_err(|_| BrowserError::Api {
        message: format!(
            "Chrome DevTools Protocol Network.responseReceived status {status} exceeds u16"
        ),
        status_code: None,
    })?;
    let loader_id = event
        .params
        .get("loaderId")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    Ok(Some(CdpNavigationResponseEvent { status, loader_id }))
}

#[async_trait::async_trait]
trait CdpCommandTransport {
    async fn send_cdp_message(&mut self, cx: &Cx, message: WebSocketMessage) -> BrowserResult<()>;

    async fn recv_cdp_message(&mut self, cx: &Cx) -> BrowserResult<Option<WebSocketMessage>>;
}

#[async_trait::async_trait]
impl CdpCommandTransport for WebSocket<TcpStream> {
    async fn send_cdp_message(&mut self, cx: &Cx, message: WebSocketMessage) -> BrowserResult<()> {
        self.send(cx, message)
            .await
            .map_err(|err| cdp_websocket_error(&err))
    }

    async fn recv_cdp_message(&mut self, cx: &Cx) -> BrowserResult<Option<WebSocketMessage>> {
        self.recv(cx).await.map_err(|err| cdp_websocket_error(&err))
    }
}

async fn execute_cdp_command<T>(
    cx: &Cx,
    transport: &mut T,
    command: CdpCommand,
) -> BrowserResult<serde_json::Value>
where
    T: CdpCommandTransport + Send,
{
    let expected_command_id = command.id;
    cx.checkpoint().map_err(|err| BrowserError::Api {
        message: format!(
            "Chrome DevTools Protocol command {expected_command_id} cancelled before send: {err}"
        ),
        status_code: None,
    })?;

    transport
        .send_cdp_message(cx, command.to_websocket_message()?)
        .await?;

    loop {
        cx.checkpoint().map_err(|err| BrowserError::Api {
            message: format!(
                "Chrome DevTools Protocol command {expected_command_id} cancelled while waiting for response: {err}"
            ),
            status_code: None,
        })?;

        let Some(message) = transport.recv_cdp_message(cx).await? else {
            return Err(BrowserError::Api {
                message: format!(
                    "Chrome DevTools Protocol connection closed before command {expected_command_id} response"
                ),
                status_code: None,
            });
        };

        if let Some(result) = decode_cdp_response_message(message, expected_command_id)? {
            return Ok(result);
        }
    }
}

fn cdp_websocket_error(error: &WsError) -> BrowserError {
    BrowserError::Api {
        message: format!("Chrome DevTools Protocol WebSocket error: {error}"),
        status_code: None,
    }
}

fn direct_cdp_context_error(operation: &str, error: AsyncError) -> BrowserError {
    match error {
        AsyncError::Timeout { timeout_ms } => BrowserError::Api {
            message: format!(
                "Chrome DevTools Protocol direct {operation} exceeded {timeout_ms}ms timeout"
            ),
            status_code: Some(408),
        },
        AsyncError::Cancelled => BrowserError::Api {
            message: format!("Chrome DevTools Protocol direct {operation} was cancelled"),
            status_code: None,
        },
        other => BrowserError::Api {
            message: format!("Chrome DevTools Protocol direct {operation} failed: {other}"),
            status_code: None,
        },
    }
}

async fn connect_direct_cdp_session(
    cx: &Cx,
    endpoint: &DirectCdpEndpoint,
    timeout: Duration,
    max_response_bytes: usize,
) -> BrowserResult<CdpSession<WebSocket<TcpStream>>> {
    let config = WebSocketConfig::new()
        .connect_timeout(Some(timeout))
        .max_frame_size(max_response_bytes)
        .max_message_size(max_response_bytes)
        .ping_interval(None);
    tracing::debug!(
        endpoint_kind = endpoint.endpoint_kind.as_str(),
        target_kind = endpoint.target.kind.as_str(),
        target_path_kind = endpoint.target.path_kind.as_str(),
        target_id_hash = %endpoint.target.id_hash,
        redacted_endpoint = endpoint.redacted_url.as_str(),
        timeout_ms = timeout.as_millis(),
        max_response_bytes,
        "connecting direct Chrome DevTools endpoint"
    );
    let websocket = WebSocket::connect_with_config(cx, &endpoint.url, config)
        .await
        .map_err(|err| BrowserError::Api {
            message: format!("Chrome DevTools Protocol WebSocket connect failed: {err}"),
            status_code: None,
        })?;
    Ok(CdpSession::new(websocket))
}

struct CdpSession<T> {
    transport: T,
    next_command_id: u64,
    pending_events: VecDeque<CdpEvent>,
}

impl<T> CdpSession<T>
where
    T: CdpCommandTransport + Send,
{
    fn new(transport: T) -> Self {
        Self {
            transport,
            next_command_id: 1,
            pending_events: VecDeque::new(),
        }
    }

    fn next_command_id(&self) -> u64 {
        self.next_command_id
    }

    fn command_ids_since(&self, start_command_id: u64) -> Vec<u64> {
        if start_command_id >= self.next_command_id {
            return Vec::new();
        }
        (start_command_id..self.next_command_id).collect()
    }

    async fn call_method(
        &mut self,
        cx: &Cx,
        method: impl Into<String>,
        params: Option<serde_json::Value>,
    ) -> BrowserResult<serde_json::Value> {
        let command = self.next_command(method, params)?;
        let expected_command_id = command.id;
        cx.checkpoint().map_err(|err| BrowserError::Api {
            message: format!(
                "Chrome DevTools Protocol command {expected_command_id} cancelled before send: {err}"
            ),
            status_code: None,
        })?;
        self.transport
            .send_cdp_message(cx, command.to_websocket_message()?)
            .await?;

        loop {
            cx.checkpoint().map_err(|err| BrowserError::Api {
                message: format!(
                    "Chrome DevTools Protocol command {expected_command_id} cancelled before response: {err}"
                ),
                status_code: None,
            })?;

            let Some(message) = self.transport.recv_cdp_message(cx).await? else {
                return Err(BrowserError::Api {
                    message: format!(
                        "Chrome DevTools Protocol connection closed before command {expected_command_id} response"
                    ),
                    status_code: None,
                });
            };

            if let Some(result) = decode_cdp_response_message(message.clone(), expected_command_id)?
            {
                return Ok(result);
            }
            if let Some(event) = decode_cdp_event_message(message)? {
                self.pending_events.push_back(event);
            }
        }
    }

    async fn next_event(&mut self, cx: &Cx) -> BrowserResult<Option<CdpEvent>> {
        if let Some(event) = self.pending_events.pop_front() {
            return Ok(Some(event));
        }

        loop {
            let Some(message) = self.transport.recv_cdp_message(cx).await? else {
                return Ok(None);
            };
            if let Some(event) = decode_cdp_event_message(message)? {
                return Ok(Some(event));
            }
        }
    }

    async fn navigate_page(
        &mut self,
        cx: &Cx,
        url: &str,
        user_agent: Option<&str>,
    ) -> BrowserResult<CdpNavigateResponse> {
        self.call_method(cx, "Page.enable", None).await?;
        self.call_method(cx, "Network.enable", None).await?;
        self.call_method(
            cx,
            "Page.setLifecycleEventsEnabled",
            Some(serde_json::json!({ "enabled": true })),
        )
        .await?;

        if let Some(user_agent) = user_agent {
            self.call_method(
                cx,
                "Network.setUserAgentOverride",
                Some(serde_json::json!({ "userAgent": user_agent })),
            )
            .await?;
        }

        let result = self
            .call_method(cx, "Page.navigate", Some(serde_json::json!({ "url": url })))
            .await?;
        CdpNavigateResponse::from_result(&result)
    }

    async fn wait_for_navigation(
        &mut self,
        cx: &Cx,
        navigation: &CdpNavigateResponse,
        wait_until: Option<&str>,
        require_new_document: bool,
        expected_url: &str,
    ) -> BrowserResult<CdpNavigationCompletion> {
        let wait = CdpNavigationWait::from_wait_until(wait_until)?;
        let mut status = None;
        let mut effective_navigation = navigation.clone();

        loop {
            cx.checkpoint().map_err(|err| BrowserError::Api {
                message: format!(
                    "Chrome DevTools Protocol navigation wait cancelled for frame {}: {err}",
                    navigation.frame_id
                ),
                status_code: None,
            })?;

            let Some(event) = self.next_event(cx).await? else {
                return Err(BrowserError::Api {
                    message: format!(
                        "Chrome DevTools Protocol connection closed before navigation completed for frame {}",
                        navigation.frame_id
                    ),
                    status_code: None,
                });
            };
            if let Some(response) =
                cdp_navigation_response_event(&event, &effective_navigation, expected_url)?
            {
                status = Some(response.status);
                if effective_navigation.loader_id.is_none() {
                    effective_navigation.loader_id = response.loader_id;
                }
            }
            if wait.matches_event(&event, &effective_navigation)
                && (!require_new_document || effective_navigation.loader_id.is_some())
            {
                return Ok(CdpNavigationCompletion {
                    status,
                    loader_id: effective_navigation.loader_id,
                });
            }
        }
    }

    async fn wait_for_location(
        &mut self,
        cx: &Cx,
        expected_url: &str,
        wait_until: Option<&str>,
        timeout_ms: Option<u64>,
        require_new_document: bool,
        previous_time_origin: Option<f64>,
    ) -> BrowserResult<String> {
        let expression = cdp_wait_for_location_expression(
            expected_url,
            wait_until,
            require_new_document,
            previous_time_origin,
        )?;
        let timeout = Duration::from_millis(timeout_ms.unwrap_or(CONTROL_TIMEOUT_MS_STANDARD));
        let deadline = Instant::now() + timeout;
        let mut last_readiness = None;

        loop {
            cx.checkpoint().map_err(|err| BrowserError::Api {
                message: format!(
                    "Chrome DevTools Protocol navigation readiness wait cancelled for {}: {err}",
                    redact_browser_url(expected_url)
                ),
                status_code: None,
            })?;

            match self.evaluate_expression(cx, &expression).await {
                Ok(response) => {
                    let readiness = cdp_parse_location_readiness_snapshot(&response)?;
                    if readiness.matched {
                        return Ok(readiness.href);
                    }
                    last_readiness = Some(readiness);
                }
                Err(error)
                    if Instant::now() < deadline
                        && cdp_location_readiness_error_is_retryable(&error) => {}
                Err(error) => return Err(error),
            }

            if Instant::now() >= deadline {
                return Err(cdp_navigation_readiness_timeout_error(
                    expected_url,
                    last_readiness.as_ref(),
                ));
            }

            fcp_async_core::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn current_document_snapshot(&mut self, cx: &Cx) -> BrowserResult<CdpDocumentSnapshot> {
        let response = self
            .evaluate_expression(
                cx,
                r"(function() {
  return {
    href: window.location.href,
    time_origin: Number.isFinite(performance.timeOrigin) ? performance.timeOrigin : null,
  };
})()",
            )
            .await?;
        cdp_parse_document_snapshot(&response)
    }

    async fn evaluate_expression(
        &mut self,
        cx: &Cx,
        expression: &str,
    ) -> BrowserResult<CdpEvaluateResponse> {
        let result = self
            .call_method(
                cx,
                "Runtime.evaluate",
                Some(serde_json::json!({
                    "expression": expression,
                    "awaitPromise": true,
                    "returnByValue": true,
                })),
            )
            .await?;
        CdpEvaluateResponse::from_result(&result)
    }

    async fn extract_text(
        &mut self,
        cx: &Cx,
        selector: Option<&str>,
        include_hidden: Option<bool>,
    ) -> BrowserResult<TextResult> {
        let expression = cdp_extract_text_expression(selector, include_hidden)?;
        let response = self.evaluate_expression(cx, &expression).await?;
        cdp_parse_text_result(&response)
    }

    async fn extract_links(
        &mut self,
        cx: &Cx,
        selector: Option<&str>,
    ) -> BrowserResult<LinksResult> {
        let expression = cdp_extract_links_expression(selector)?;
        let response = self.evaluate_expression(cx, &expression).await?;
        cdp_parse_links_result(&response)
    }

    async fn wait_for_selector(
        &mut self,
        cx: &Cx,
        selector: &str,
        state: Option<&str>,
        timeout_ms: Option<u64>,
    ) -> BrowserResult<WaitResult> {
        let expression = cdp_wait_for_selector_expression(selector, state, timeout_ms)?;
        let response = self.evaluate_expression(cx, &expression).await?;
        cdp_parse_wait_result(&response)
    }

    async fn click(
        &mut self,
        cx: &Cx,
        selector: &str,
        timeout_ms: Option<u64>,
    ) -> BrowserResult<ClickResult> {
        let readiness = self
            .wait_for_selector(cx, selector, Some("visible"), timeout_ms)
            .await?;
        if !readiness.found {
            return Err(BrowserError::Api {
                message: format!(
                    "Chrome DevTools Protocol click selector `{selector}` was not visible before timeout"
                ),
                status_code: None,
            });
        }

        let document = self
            .call_method(
                cx,
                "DOM.getDocument",
                Some(serde_json::json!({ "depth": 0, "pierce": false })),
            )
            .await?;
        let root_node_id = cdp_required_node_id(&document, "/root/nodeId")?;
        let query = self
            .call_method(
                cx,
                "DOM.querySelector",
                Some(serde_json::json!({
                    "nodeId": root_node_id,
                    "selector": selector,
                })),
            )
            .await?;
        let node_id = cdp_required_node_id(&query, "/nodeId").map_err(|_| BrowserError::Api {
            message: format!("Chrome DevTools Protocol click selector `{selector}` did not match"),
            status_code: None,
        })?;
        let box_model = self
            .call_method(
                cx,
                "DOM.getBoxModel",
                Some(serde_json::json!({ "nodeId": node_id })),
            )
            .await?;
        let point = CdpMousePoint::from_box_model(&box_model)?;

        for params in [
            cdp_mouse_event_params("mouseMoved", point, Some("none"), Some(0), Some(0)),
            cdp_mouse_event_params("mousePressed", point, Some("left"), Some(1), Some(1)),
            cdp_mouse_event_params("mouseReleased", point, Some("left"), Some(0), Some(1)),
        ] {
            self.call_method(cx, "Input.dispatchMouseEvent", Some(params))
                .await?;
        }

        Ok(ClickResult {
            clicked: true,
            navigation_url: None,
        })
    }

    async fn fill_form(
        &mut self,
        cx: &Cx,
        fields: &serde_json::Value,
        submit_selector: Option<&str>,
    ) -> BrowserResult<FormResult> {
        let fields = cdp_form_fields(fields)?;
        let mut filled_count = 0_u32;

        if !fields.is_empty() {
            let document = self
                .call_method(
                    cx,
                    "DOM.getDocument",
                    Some(serde_json::json!({ "depth": 0, "pierce": false })),
                )
                .await?;
            let root_node_id = cdp_required_node_id(&document, "/root/nodeId")?;

            for field in fields {
                let query = self
                    .call_method(
                        cx,
                        "DOM.querySelector",
                        Some(serde_json::json!({
                            "nodeId": root_node_id,
                            "selector": field.selector.as_str(),
                        })),
                    )
                    .await?;
                let node_id =
                    cdp_required_node_id(&query, "/nodeId").map_err(|_| BrowserError::Api {
                        message: format!(
                            "Chrome DevTools Protocol fill_form selector `{}` did not match",
                            field.selector
                        ),
                        status_code: None,
                    })?;

                self.call_method(
                    cx,
                    "DOM.focus",
                    Some(serde_json::json!({ "nodeId": node_id })),
                )
                .await?;
                let expression = cdp_fill_form_prepare_expression(&field.selector, &field.value)?;
                let response = self.evaluate_expression(cx, &expression).await?;
                let plan = cdp_parse_form_field_plan(&response)?;
                if let Some(text) = plan.text_to_insert
                    && !text.is_empty()
                {
                    self.call_method(
                        cx,
                        "Input.insertText",
                        Some(serde_json::json!({ "text": text })),
                    )
                    .await?;
                }

                filled_count = filled_count
                    .checked_add(1)
                    .ok_or_else(|| BrowserError::Api {
                        message: "Chrome DevTools Protocol fill_form filled_count overflowed u32"
                            .into(),
                        status_code: None,
                    })?;
            }
        }

        let submitted = if let Some(submit_selector) = submit_selector {
            let click = self
                .click(cx, submit_selector, Some(CONTROL_TIMEOUT_MS_STANDARD))
                .await?;
            Some(click.clicked)
        } else {
            None
        };

        Ok(FormResult {
            filled_count,
            submitted,
        })
    }

    async fn capture_screenshot(
        &mut self,
        cx: &Cx,
        selector: Option<&str>,
        full_page: bool,
        format: Option<&str>,
        quality: Option<u32>,
    ) -> BrowserResult<CdpScreenshotResponse> {
        let clip = if let Some(selector) = selector {
            let document = self
                .call_method(
                    cx,
                    "DOM.getDocument",
                    Some(serde_json::json!({ "depth": 0, "pierce": false })),
                )
                .await?;
            let root_node_id = cdp_required_node_id(&document, "/root/nodeId")?;
            let query = self
                .call_method(
                    cx,
                    "DOM.querySelector",
                    Some(serde_json::json!({
                        "nodeId": root_node_id,
                        "selector": selector,
                    })),
                )
                .await?;
            let node_id = query
                .get("nodeId")
                .and_then(serde_json::Value::as_u64)
                .filter(|node_id| *node_id != 0)
                .ok_or_else(|| BrowserError::Api {
                    message: format!(
                        "Chrome DevTools Protocol DOM.querySelector selector `{selector}` did not match any node"
                    ),
                    status_code: None,
                })?;
            let box_model = self
                .call_method(
                    cx,
                    "DOM.getBoxModel",
                    Some(serde_json::json!({ "nodeId": node_id })),
                )
                .await?;
            CdpCaptureClip::from_box_model(&box_model)?
        } else {
            let layout_metrics = self.call_method(cx, "Page.getLayoutMetrics", None).await?;
            CdpCaptureClip::from_layout_metrics(&layout_metrics, full_page)?
        };

        let format = cdp_screenshot_format(format)?;
        let mut params = serde_json::Map::new();
        params.insert(
            "captureBeyondViewport".to_string(),
            serde_json::json!(full_page || selector.is_some()),
        );
        params.insert("clip".to_string(), clip.descriptor());
        params.insert("format".to_string(), serde_json::Value::String(format));
        params.insert("fromSurface".to_string(), serde_json::Value::Bool(true));
        if let Some(quality) = quality {
            if quality > 100 {
                return Err(BrowserError::Api {
                    message: format!(
                        "Chrome DevTools Protocol Page.captureScreenshot quality must be <= 100, got {quality}"
                    ),
                    status_code: None,
                });
            }
            params.insert("quality".to_string(), serde_json::json!(quality));
        }

        let result = self
            .call_method(
                cx,
                "Page.captureScreenshot",
                Some(serde_json::Value::Object(params)),
            )
            .await?;
        CdpScreenshotResponse::from_capture_result(&result, clip)
    }

    async fn render_pdf(
        &mut self,
        cx: &Cx,
        format: Option<&str>,
        landscape: Option<bool>,
        print_background: Option<bool>,
    ) -> BrowserResult<CdpPdfResponse> {
        let mut params = serde_json::Map::new();
        if let Some((paper_width, paper_height)) = cdp_pdf_paper_size(format)? {
            params.insert("paperWidth".to_string(), serde_json::json!(paper_width));
            params.insert("paperHeight".to_string(), serde_json::json!(paper_height));
        }
        if let Some(landscape) = landscape {
            params.insert("landscape".to_string(), serde_json::Value::Bool(landscape));
        }
        if let Some(print_background) = print_background {
            params.insert(
                "printBackground".to_string(),
                serde_json::Value::Bool(print_background),
            );
        }
        params.insert(
            "transferMode".to_string(),
            serde_json::Value::String("ReturnAsBase64".to_string()),
        );

        let result = self
            .call_method(
                cx,
                "Page.printToPDF",
                Some(serde_json::Value::Object(params)),
            )
            .await?;
        CdpPdfResponse::from_print_result(&result)
    }

    async fn get_cookies(
        &mut self,
        cx: &Cx,
        domain_filter: Option<&str>,
    ) -> BrowserResult<CdpCookieResponse> {
        let result = self.call_method(cx, "Network.getCookies", None).await?;
        CdpCookieResponse::from_result(&result, domain_filter)
    }

    async fn set_cookies(
        &mut self,
        cx: &Cx,
        cookies: &[Cookie],
    ) -> BrowserResult<CdpSetCookiesResponse> {
        let set_count = u32::try_from(cookies.len()).map_err(|err| BrowserError::Api {
            message: format!(
                "Chrome DevTools Protocol Network.setCookies cookie count exceeds u32: {err}"
            ),
            status_code: None,
        })?;
        let cdp_cookies = cookies.iter().map(cdp_cookie_param).collect::<Vec<_>>();
        self.call_method(
            cx,
            "Network.setCookies",
            Some(serde_json::json!({ "cookies": cdp_cookies })),
        )
        .await?;

        Ok(CdpSetCookiesResponse { set_count })
    }

    fn next_command(
        &mut self,
        method: impl Into<String>,
        params: Option<serde_json::Value>,
    ) -> BrowserResult<CdpCommand> {
        let id = self.next_command_id;
        self.next_command_id =
            self.next_command_id
                .checked_add(1)
                .ok_or_else(|| BrowserError::Api {
                    message: "Chrome DevTools Protocol command id space exhausted".into(),
                    status_code: None,
                })?;
        Ok(CdpCommand::new(id, method, params))
    }

    #[cfg(test)]
    fn into_transport(self) -> T {
        self.transport
    }
}

#[derive(Clone, Copy)]
struct BrowserConnectorOperation {
    id: &'static str,
    mapping: &'static str,
    worker_operation_ids: &'static [&'static str],
}

impl BrowserConnectorOperation {
    fn descriptor(self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "mapping": self.mapping,
            "worker_operation_ids": self.worker_operation_ids,
        })
    }
}

const WORKER_NAVIGATE: BrowserControlOperation = BrowserControlOperation {
    id: "browser.navigate",
    method: "POST",
    path: "/navigate",
    max_response_bytes: CONTROL_RESPONSE_BYTES_CAPTURE,
    timeout_ms: CONTROL_TIMEOUT_MS_CAPTURE,
    target_policy: TARGET_CREATE_OR_REUSE_PAGE,
    implementation: BrowserControlImplementation::Cdp {
        methods: &[
            "Page.enable",
            "Network.enable",
            "Page.setLifecycleEventsEnabled",
            "Network.setUserAgentOverride",
            "Page.navigate",
        ],
    },
};
const WORKER_SCREENSHOT: BrowserControlOperation = BrowserControlOperation {
    id: "browser.screenshot",
    method: "POST",
    path: "/screenshot",
    max_response_bytes: CONTROL_RESPONSE_BYTES_CAPTURE,
    timeout_ms: CONTROL_TIMEOUT_MS_CAPTURE,
    target_policy: TARGET_ACTIVE_PAGE_EXPORT,
    implementation: BrowserControlImplementation::Cdp {
        methods: &[
            "DOM.getDocument",
            "DOM.querySelector",
            "DOM.getBoxModel",
            "Page.getLayoutMetrics",
            "Page.captureScreenshot",
        ],
    },
};
const WORKER_RENDER_PDF: BrowserControlOperation = BrowserControlOperation {
    id: "browser.render_pdf",
    method: "POST",
    path: "/pdf",
    max_response_bytes: CONTROL_RESPONSE_BYTES_CAPTURE,
    timeout_ms: CONTROL_TIMEOUT_MS_CAPTURE,
    target_policy: TARGET_ACTIVE_PAGE_EXPORT,
    implementation: BrowserControlImplementation::Cdp {
        methods: &["Page.printToPDF"],
    },
};
const WORKER_EXTRACT_TEXT: BrowserControlOperation = BrowserControlOperation {
    id: "browser.extract_text",
    method: "POST",
    path: "/extract_text",
    max_response_bytes: CONTROL_RESPONSE_BYTES_STANDARD,
    timeout_ms: CONTROL_TIMEOUT_MS_STANDARD,
    target_policy: TARGET_ACTIVE_PAGE_EXPORT,
    implementation: BrowserControlImplementation::Cdp {
        methods: &["Runtime.evaluate"],
    },
};
const WORKER_EXTRACT_LINKS: BrowserControlOperation = BrowserControlOperation {
    id: "browser.extract_links",
    method: "POST",
    path: "/extract_links",
    max_response_bytes: CONTROL_RESPONSE_BYTES_STANDARD,
    timeout_ms: CONTROL_TIMEOUT_MS_STANDARD,
    target_policy: TARGET_ACTIVE_PAGE_EXPORT,
    implementation: BrowserControlImplementation::Cdp {
        methods: &["Runtime.evaluate"],
    },
};
const WORKER_WAIT_FOR_SELECTOR: BrowserControlOperation = BrowserControlOperation {
    id: "browser.wait_for_selector",
    method: "POST",
    path: "/wait_for_selector",
    max_response_bytes: CONTROL_RESPONSE_BYTES_SMALL,
    timeout_ms: CONTROL_TIMEOUT_MS_STANDARD,
    target_policy: TARGET_ACTIVE_PAGE_INTERACTION,
    implementation: BrowserControlImplementation::Cdp {
        methods: &["Runtime.evaluate"],
    },
};
const WORKER_CLICK: BrowserControlOperation = BrowserControlOperation {
    id: "browser.click",
    method: "POST",
    path: "/click",
    max_response_bytes: CONTROL_RESPONSE_BYTES_STANDARD,
    timeout_ms: CONTROL_TIMEOUT_MS_STANDARD,
    target_policy: TARGET_ACTIVE_PAGE_INTERACTION,
    implementation: BrowserControlImplementation::Cdp {
        methods: &[
            "Runtime.evaluate",
            "DOM.getDocument",
            "DOM.querySelector",
            "DOM.getBoxModel",
            "Input.dispatchMouseEvent",
        ],
    },
};
const WORKER_FILL_FORM: BrowserControlOperation = BrowserControlOperation {
    id: "browser.fill_form",
    method: "POST",
    path: "/fill_form",
    max_response_bytes: CONTROL_RESPONSE_BYTES_STANDARD,
    timeout_ms: CONTROL_TIMEOUT_MS_STANDARD,
    target_policy: TARGET_ACTIVE_PAGE_INTERACTION,
    implementation: BrowserControlImplementation::Cdp {
        methods: &[
            "DOM.getDocument",
            "DOM.querySelector",
            "DOM.focus",
            "Runtime.evaluate",
            "Input.insertText",
            "DOM.getBoxModel",
            "Input.dispatchMouseEvent",
        ],
    },
};
const WORKER_EVALUATE_JS: BrowserControlOperation = BrowserControlOperation {
    id: "browser.evaluate_js",
    method: "POST",
    path: "/evaluate",
    max_response_bytes: CONTROL_RESPONSE_BYTES_STANDARD,
    timeout_ms: CONTROL_TIMEOUT_MS_STANDARD,
    target_policy: TARGET_ACTIVE_PAGE_INTERACTION,
    implementation: BrowserControlImplementation::Cdp {
        methods: &["Runtime.evaluate"],
    },
};
const WORKER_GET_COOKIES: BrowserControlOperation = BrowserControlOperation {
    id: "browser.get_cookies",
    method: "POST",
    path: "/cookies",
    max_response_bytes: CONTROL_RESPONSE_BYTES_SMALL,
    timeout_ms: CONTROL_TIMEOUT_MS_SHORT,
    target_policy: TARGET_BROWSER_CONTEXT,
    implementation: BrowserControlImplementation::Cdp {
        methods: &["Network.getCookies"],
    },
};
const WORKER_SET_COOKIES: BrowserControlOperation = BrowserControlOperation {
    id: "browser.set_cookies",
    method: "POST",
    path: "/set_cookies",
    max_response_bytes: CONTROL_RESPONSE_BYTES_SMALL,
    timeout_ms: CONTROL_TIMEOUT_MS_SHORT,
    target_policy: TARGET_BROWSER_CONTEXT,
    implementation: BrowserControlImplementation::Cdp {
        methods: &["Network.setCookies"],
    },
};
const WORKER_SET_PROXY: BrowserControlOperation = BrowserControlOperation {
    id: "browser.set_proxy",
    method: "POST",
    path: "/proxy/set",
    max_response_bytes: CONTROL_RESPONSE_BYTES_SMALL,
    timeout_ms: CONTROL_TIMEOUT_MS_SHORT,
    target_policy: TARGET_CONNECTOR_POLICY,
    implementation: BrowserControlImplementation::WorkerPolicy {
        description: "Apply connector-scoped proxy policy before browser target launch.",
    },
};
const WORKER_CLEAR_PROXY: BrowserControlOperation = BrowserControlOperation {
    id: "browser.clear_proxy",
    method: "POST",
    path: "/proxy/clear",
    max_response_bytes: CONTROL_RESPONSE_BYTES_SMALL,
    timeout_ms: CONTROL_TIMEOUT_MS_SHORT,
    target_policy: TARGET_CONNECTOR_POLICY,
    implementation: BrowserControlImplementation::WorkerPolicy {
        description: "Clear connector-scoped proxy policy for future browser targets.",
    },
};

const REQUIRED_BROWSER_CONTROL_OPERATIONS: &[BrowserControlOperation] = &[
    WORKER_NAVIGATE,
    WORKER_SCREENSHOT,
    WORKER_RENDER_PDF,
    WORKER_EXTRACT_TEXT,
    WORKER_EXTRACT_LINKS,
    WORKER_WAIT_FOR_SELECTOR,
    WORKER_CLICK,
    WORKER_FILL_FORM,
    WORKER_EVALUATE_JS,
    WORKER_GET_COOKIES,
    WORKER_SET_COOKIES,
    WORKER_SET_PROXY,
    WORKER_CLEAR_PROXY,
];

const PROXY_BROWSER_CONTROL_OPERATIONS: &[BrowserControlOperation] =
    &[WORKER_SET_PROXY, WORKER_CLEAR_PROXY];

const BROWSER_CONNECTOR_OPERATIONS: &[BrowserConnectorOperation] = &[
    BrowserConnectorOperation {
        id: "browser.navigate",
        mapping: "worker",
        worker_operation_ids: &["browser.navigate"],
    },
    BrowserConnectorOperation {
        id: "browser.screenshot",
        mapping: "worker",
        worker_operation_ids: &["browser.screenshot"],
    },
    BrowserConnectorOperation {
        id: "browser.render_pdf",
        mapping: "worker",
        worker_operation_ids: &["browser.render_pdf"],
    },
    BrowserConnectorOperation {
        id: "browser.extract_text",
        mapping: "worker",
        worker_operation_ids: &["browser.extract_text"],
    },
    BrowserConnectorOperation {
        id: "browser.extract_links",
        mapping: "worker",
        worker_operation_ids: &["browser.extract_links"],
    },
    BrowserConnectorOperation {
        id: "browser.wait_for_selector",
        mapping: "worker",
        worker_operation_ids: &["browser.wait_for_selector"],
    },
    BrowserConnectorOperation {
        id: "browser.click",
        mapping: "worker",
        worker_operation_ids: &["browser.click"],
    },
    BrowserConnectorOperation {
        id: "browser.fill_form",
        mapping: "worker",
        worker_operation_ids: &["browser.fill_form"],
    },
    BrowserConnectorOperation {
        id: "browser.evaluate_js",
        mapping: "worker",
        worker_operation_ids: &["browser.evaluate_js"],
    },
    BrowserConnectorOperation {
        id: "browser.get_cookies",
        mapping: "worker",
        worker_operation_ids: &["browser.get_cookies"],
    },
    BrowserConnectorOperation {
        id: "browser.set_cookies",
        mapping: "worker",
        worker_operation_ids: &["browser.set_cookies"],
    },
    BrowserConnectorOperation {
        id: "browser.session.save",
        mapping: "derived",
        worker_operation_ids: &["browser.get_cookies"],
    },
    BrowserConnectorOperation {
        id: "browser.session.restore",
        mapping: "derived",
        worker_operation_ids: &["browser.set_cookies"],
    },
    BrowserConnectorOperation {
        id: "browser.session.describe",
        mapping: "connector_state",
        worker_operation_ids: &[],
    },
    BrowserConnectorOperation {
        id: "browser.set_proxy",
        mapping: "worker",
        worker_operation_ids: &["browser.set_proxy"],
    },
    BrowserConnectorOperation {
        id: "browser.clear_proxy",
        mapping: "worker",
        worker_operation_ids: &["browser.clear_proxy"],
    },
];

/// FCP browser-control worker contract expected by this connector client.
pub(crate) fn browser_control_contract_descriptor() -> serde_json::Value {
    serde_json::json!({
        "control_plane": "fcp-browser-control",
        "protocol_version": BROWSER_CONTROL_PROTOCOL_VERSION,
        "control_modes": {
            "direct_cdp_websocket": {
                "page_operations": "available",
                "proxy_support": "proxy_unavailable_direct_cdp",
                "remediation": "use a proxy-capable fcp-browser-control worker or future Rust-owned launcher for browser.set_proxy/browser.clear_proxy",
            },
            "fcp_browser_control": {
                "page_operations": "available",
                "proxy_support": "available_when_proxy_operations_advertised",
                "proxy_operations": PROXY_BROWSER_CONTROL_OPERATIONS
                    .iter()
                    .map(|operation| operation.id)
                    .collect::<Vec<_>>(),
            },
            "rust_owned_launcher": {
                "status": "native_spawn_available_fixture_available",
                "page_operations": "delegated_to_configured_browser_url",
                "proxy_support": "native_spawn_or_fixture_when_configured",
                "redaction_contract": PROXY_REDACTION_CONTRACT,
                "modes": ["native", "fixture"],
            },
        },
        "operations": REQUIRED_BROWSER_CONTROL_OPERATIONS
            .iter()
            .map(|operation| operation.descriptor())
            .collect::<Vec<_>>(),
        "connector_operations": BROWSER_CONNECTOR_OPERATIONS
            .iter()
            .map(|operation| operation.descriptor())
            .collect::<Vec<_>>(),
    })
}

/// Authentication mode for the Browser connector.
#[derive(Clone)]
pub enum BrowserAuth {
    /// No authentication (local browser, no API key required).
    None,
    /// Bearer API key for authenticated browser endpoints.
    ApiKey(String),
    /// Secretless mode – egress proxy injects credentials at runtime.
    CredentialId(CredentialId),
}

impl std::fmt::Debug for BrowserAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserAuth").finish_non_exhaustive()
    }
}

impl BrowserAuth {
    /// Human-readable label with secrets redacted.
    #[must_use]
    pub fn redacted_label(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ApiKey(_) => "api_key:****",
            Self::CredentialId(_) => "credential_id",
        }
    }

    /// Whether this auth mode is secretless (egress proxy).
    #[must_use]
    pub const fn is_secretless(&self) -> bool {
        matches!(self, Self::CredentialId(_))
    }
}

/// Browser automation HTTP client.
pub struct BrowserClient {
    http: Client,
    browser_url: String,
    max_retries: u32,
    auth: BrowserAuth,
    runtime: ConnectorRuntime,
    retry_config: HttpRetryConfig,
    direct_cdp_manager: Arc<Mutex<DirectCdpTargetSessionManager>>,
    rust_owned_launcher: Arc<Mutex<Option<RustOwnedLauncherSupervisor>>>,
}

impl std::fmt::Debug for BrowserClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserClient").finish_non_exhaustive()
    }
}

impl BrowserClient {
    /// Create a new browser client with an optional API key.
    pub fn new(api_key: Option<&str>) -> BrowserResult<Self> {
        let auth = match api_key {
            Some(key) => BrowserAuth::ApiKey(key.to_string()),
            None => BrowserAuth::None,
        };
        Self::new_with_auth(auth)
    }

    /// Create a new browser client with the specified auth mode.
    pub fn new_with_auth(auth: BrowserAuth) -> BrowserResult<Self> {
        let mut headers = header::HeaderMap::new();
        match &auth {
            BrowserAuth::None => {}
            BrowserAuth::ApiKey(key) => {
                headers.insert(
                    header::AUTHORIZATION,
                    format!("Bearer {key}")
                        .parse()
                        .map_err(|_| BrowserError::Api {
                            message: "Invalid API key value for header".into(),
                            status_code: None,
                        })?,
                );
            }
            BrowserAuth::CredentialId(id) => {
                headers.insert(
                    "X-FCP-Credential-ID",
                    id.to_string().parse().map_err(|_| BrowserError::Api {
                        message: "Invalid credential_id value for header".into(),
                        status_code: None,
                    })?,
                );
            }
        }

        let http = Client::builder()
            .default_headers(headers)
            .user_agent("fcp-browser/0.1.0")
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(BrowserError::Http)?;

        Ok(Self {
            http,
            browser_url: DEFAULT_BROWSER_URL.to_string(),
            max_retries: 2,
            auth,
            runtime: ConnectorRuntime::new(
                ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(30)),
            ),
            retry_config: HttpRetryConfig {
                max_retries: 2,
                ..HttpRetryConfig::default()
            },
            direct_cdp_manager: Arc::new(Mutex::new(DirectCdpTargetSessionManager::default())),
            rust_owned_launcher: Arc::new(Mutex::new(None)),
        })
    }

    /// Shut down the connector runtime.
    pub fn shutdown(&self) {
        self.runtime.shutdown();
        if let Ok(mut manager) = self.direct_cdp_manager.lock() {
            manager.shutdown();
        }
        if let Ok(mut launcher) = self.rust_owned_launcher.lock() {
            if let Some(launcher) = launcher.as_mut() {
                launcher.shutdown();
            }
        }
    }

    pub(crate) fn record_direct_cdp_session_object(
        &self,
        operation_id: &'static str,
        raw_object_id: &str,
        lease_seq: u64,
        cookie_scope: Option<&str>,
    ) -> BrowserResult<Option<String>> {
        let BrowserControlEndpoint::DirectCdp(endpoint) = self.control_endpoint()? else {
            return Ok(None);
        };
        let mut manager = lock_direct_cdp_manager(&self.direct_cdp_manager)?;
        manager
            .record_session_object(
                &endpoint,
                operation_id,
                raw_object_id,
                lease_seq,
                cookie_scope,
            )
            .map(Some)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn direct_cdp_manager_events_jsonl(&self) -> BrowserResult<String> {
        let manager = lock_direct_cdp_manager(&self.direct_cdp_manager)?;
        Ok(manager.events_jsonl())
    }

    pub fn rust_owned_launcher_events_jsonl(&self) -> BrowserResult<String> {
        let launcher = lock_rust_owned_launcher(&self.rust_owned_launcher)?;
        launcher.as_ref().map_or_else(
            || Ok(String::new()),
            RustOwnedLauncherSupervisor::events_jsonl,
        )
    }

    /// Lightweight connectivity probe for the FCP browser-control plane.
    pub async fn health_check(&self) -> BrowserResult<()> {
        if let Some(result) =
            self.inspect_rust_owned_launcher(|launcher| launcher.health_check())?
        {
            return Ok(result);
        }

        if let BrowserControlEndpoint::DirectCdp(endpoint) = self.control_endpoint()? {
            return self.direct_cdp_health_check(&endpoint).await;
        }

        let url = format!("{}/health", self.browser_url);
        let timeout = Duration::from_millis(CONTROL_TIMEOUT_MS_STANDARD);
        match self
            .execute(CONTROL_RESPONSE_BYTES_STANDARD, timeout, || {
                self.http.get(&url).timeout(timeout)
            })
            .await
        {
            Ok(body) => validate_fcp_browser_control_health(&body).map_err(|reason| {
                BrowserError::InvalidConfig(format!(
                    "browser control-plane /health response is not compatible with fcp-browser-control contract v{BROWSER_CONTROL_PROTOCOL_VERSION}: {reason}"
                ))
            }),
            Err(err) => {
                if self.raw_chrome_cdp_endpoint_detected().await {
                    Err(BrowserError::InvalidConfig(
                        "browser_url points at a raw Chrome DevTools endpoint; configure an FCP browser-control endpoint for browser operations".into(),
                    ))
                } else {
                    Err(err)
                }
            }
        }
    }

    /// Set a custom browser URL.
    #[must_use]
    pub fn with_browser_url(mut self, url: &str) -> Self {
        self.browser_url = url.to_string();
        self
    }

    #[must_use]
    pub(crate) fn continue_direct_cdp_manager_from(mut self, previous: Option<&Self>) -> Self {
        if let Some(previous) = previous
            && let Ok(manager) = previous.direct_cdp_manager.lock()
            && !manager.shutdown
        {
            self.direct_cdp_manager = Arc::clone(&previous.direct_cdp_manager);
        }
        self
    }

    /// Enable the Rust-owned browser launcher supervisor for proxy operations.
    pub fn with_rust_owned_launcher(
        mut self,
        config: BrowserLauncherConfig,
    ) -> BrowserResult<Self> {
        self.rust_owned_launcher =
            Arc::new(Mutex::new(Some(RustOwnedLauncherSupervisor::new(config)?)));
        Ok(self)
    }

    /// Redaction-safe descriptor for the configured Rust-owned launcher, if any.
    pub fn rust_owned_launcher_descriptor(&self) -> BrowserResult<Option<serde_json::Value>> {
        self.inspect_rust_owned_launcher(|launcher| Ok(launcher.descriptor()))
    }

    /// Set the maximum number of retries.
    #[must_use]
    pub fn with_retry_config(mut self, max_retries: u32) -> Self {
        self.retry_config.max_retries = max_retries;
        self.retry_config = HttpRetryConfig {
            max_retries,
            ..self.retry_config
        };
        self
    }

    fn control_endpoint(&self) -> BrowserResult<BrowserControlEndpoint> {
        browser_control_endpoint_for_url(&self.browser_url)
    }

    fn inspect_rust_owned_launcher<T>(
        &self,
        f: impl FnOnce(&RustOwnedLauncherSupervisor) -> BrowserResult<T>,
    ) -> BrowserResult<Option<T>> {
        let launcher = lock_rust_owned_launcher(&self.rust_owned_launcher)?;
        launcher.as_ref().map(f).transpose()
    }

    fn with_rust_owned_launcher_mut<T>(
        &self,
        f: impl FnOnce(&mut RustOwnedLauncherSupervisor) -> BrowserResult<T>,
    ) -> BrowserResult<Option<T>> {
        let mut launcher = lock_rust_owned_launcher(&self.rust_owned_launcher)?;
        launcher.as_mut().map(f).transpose()
    }

    async fn direct_cdp_session_operation<T, F>(
        &self,
        endpoint: &DirectCdpEndpoint,
        operation_id: &'static str,
        context_operation: &'static str,
        timeout: Duration,
        max_response_bytes: usize,
        run: F,
    ) -> BrowserResult<T>
    where
        F: for<'a> FnOnce(
            &'a Cx,
            &'a mut CdpSession<WebSocket<TcpStream>>,
        ) -> DirectCdpSessionFuture<'a, T>,
    {
        let ctx = self.request_context_for_timeout(timeout);
        let manager = Arc::clone(&self.direct_cdp_manager);
        let endpoint = endpoint.clone();
        ctx.run(async move {
            let mut lease =
                DirectCdpManagerLease::acquire(manager, &endpoint, operation_id, timeout)?;
            let cx = fcp_async_core::compatibility_cx();
            let mut session =
                match connect_direct_cdp_session(&cx, &endpoint, timeout, max_response_bytes).await
                {
                    Ok(session) => session,
                    Err(err) => {
                        lease.finish(&[], "connect_error", "connect_failed_cleanup")?;
                        return Err(err);
                    }
                };
            let first_command_id = session.next_command_id();
            let result = run(&cx, &mut session).await;
            let cdp_command_ids = session.command_ids_since(first_command_id);
            let outcome = if result.is_ok() { "success" } else { "error" };
            let finish_result = lease.finish(&cdp_command_ids, outcome, "session_closed_by_scope");

            match (result, finish_result) {
                (Ok(value), Ok(())) => Ok(value),
                (Err(err), Ok(())) => Err(err),
                (Ok(_), Err(err)) => Err(err),
                (Err(err), Err(_)) => Err(err),
            }
        })
        .await
        .map_err(|err| direct_cdp_context_error(context_operation, err))?
    }

    async fn direct_cdp_health_check(&self, endpoint: &DirectCdpEndpoint) -> BrowserResult<()> {
        let timeout = Duration::from_millis(CONTROL_TIMEOUT_MS_SHORT);
        self.direct_cdp_session_operation(
            endpoint,
            "browser.health_check",
            "health_check",
            timeout,
            CONTROL_RESPONSE_BYTES_SMALL,
            |cx, session| {
                Box::pin(async move { session.evaluate_expression(cx, "1").await.map(|_| ()) })
            },
        )
        .await
    }

    async fn direct_cdp_navigate(
        &self,
        endpoint: &DirectCdpEndpoint,
        url: &str,
        wait_until: Option<&str>,
        timeout_ms: Option<u64>,
        user_agent: Option<&str>,
    ) -> BrowserResult<NavigateResult> {
        let timeout = Duration::from_millis(timeout_ms.unwrap_or(CONTROL_TIMEOUT_MS_STANDARD));
        let url = url.to_string();
        let wait_until = wait_until.map(str::to_string);
        let user_agent = user_agent.map(str::to_string);
        self.direct_cdp_session_operation(
            endpoint,
            "browser.navigate",
            "navigate",
            timeout,
            CONTROL_RESPONSE_BYTES_STANDARD,
            |cx, session| {
                Box::pin(async move {
                    let previous_document = session.current_document_snapshot(cx).await.ok();
                    let require_new_document = cdp_requires_new_document_for_navigation(
                        previous_document
                            .as_ref()
                            .map(|document| document.href.as_str()),
                        &url,
                    );
                    let navigation = session
                        .navigate_page(cx, &url, user_agent.as_deref())
                        .await?;
                    let completion = session
                        .wait_for_navigation(
                            cx,
                            &navigation,
                            wait_until.as_deref(),
                            require_new_document,
                            &url,
                        )
                        .await?;
                    let current_url = session
                        .wait_for_location(
                            cx,
                            &url,
                            wait_until.as_deref(),
                            timeout_ms,
                            require_new_document,
                            previous_document.and_then(|document| document.time_origin),
                        )
                        .await?;
                    let title = session
                        .evaluate_expression(cx, "document.title")
                        .await?
                        .result;
                    Ok(NavigateResult {
                        url: current_url,
                        status: completion.status.unwrap_or(0),
                        title: (!title.is_empty()).then_some(title),
                    })
                })
            },
        )
        .await
    }

    async fn direct_cdp_screenshot(
        &self,
        endpoint: &DirectCdpEndpoint,
        selector: Option<&str>,
        full_page: Option<bool>,
        format: Option<&str>,
        quality: Option<u32>,
    ) -> BrowserResult<ScreenshotResult> {
        let timeout = Duration::from_millis(CONTROL_TIMEOUT_MS_CAPTURE);
        let selector = selector.map(str::to_string);
        let format = format.map(str::to_string);
        self.direct_cdp_session_operation(
            endpoint,
            "browser.screenshot",
            "screenshot",
            timeout,
            CONTROL_RESPONSE_BYTES_CAPTURE,
            |cx, session| {
                Box::pin(async move {
                    let response = session
                        .capture_screenshot(
                            cx,
                            selector.as_deref(),
                            full_page.unwrap_or(false),
                            format.as_deref(),
                            quality,
                        )
                        .await?;
                    Ok(ScreenshotResult {
                        image_data: response.image_data,
                        width: response.width,
                        height: response.height,
                    })
                })
            },
        )
        .await
    }

    async fn direct_cdp_render_pdf(
        &self,
        endpoint: &DirectCdpEndpoint,
        format: Option<&str>,
        landscape: Option<bool>,
        print_background: Option<bool>,
    ) -> BrowserResult<PdfResult> {
        let timeout = Duration::from_millis(CONTROL_TIMEOUT_MS_CAPTURE);
        let format = format.map(str::to_string);
        self.direct_cdp_session_operation(
            endpoint,
            "browser.render_pdf",
            "render_pdf",
            timeout,
            CONTROL_RESPONSE_BYTES_CAPTURE,
            |cx, session| {
                Box::pin(async move {
                    let response = session
                        .render_pdf(cx, format.as_deref(), landscape, print_background)
                        .await?;
                    Ok(PdfResult {
                        pdf_data: response.pdf_data,
                        page_count: response.page_count,
                    })
                })
            },
        )
        .await
    }

    async fn direct_cdp_extract_text(
        &self,
        endpoint: &DirectCdpEndpoint,
        selector: Option<&str>,
        include_hidden: Option<bool>,
    ) -> BrowserResult<TextResult> {
        let timeout = Duration::from_millis(CONTROL_TIMEOUT_MS_STANDARD);
        let selector = selector.map(str::to_string);
        self.direct_cdp_session_operation(
            endpoint,
            "browser.extract_text",
            "extract_text",
            timeout,
            CONTROL_RESPONSE_BYTES_STANDARD,
            |cx, session| {
                Box::pin(async move {
                    session
                        .extract_text(cx, selector.as_deref(), include_hidden)
                        .await
                })
            },
        )
        .await
    }

    async fn direct_cdp_extract_links(
        &self,
        endpoint: &DirectCdpEndpoint,
        selector: Option<&str>,
    ) -> BrowserResult<LinksResult> {
        let timeout = Duration::from_millis(CONTROL_TIMEOUT_MS_STANDARD);
        let selector = selector.map(str::to_string);
        self.direct_cdp_session_operation(
            endpoint,
            "browser.extract_links",
            "extract_links",
            timeout,
            CONTROL_RESPONSE_BYTES_STANDARD,
            |cx, session| {
                Box::pin(async move { session.extract_links(cx, selector.as_deref()).await })
            },
        )
        .await
    }

    async fn direct_cdp_wait_for_selector(
        &self,
        endpoint: &DirectCdpEndpoint,
        selector: &str,
        state: Option<&str>,
        timeout_ms: Option<u64>,
    ) -> BrowserResult<WaitResult> {
        let timeout = Duration::from_millis(timeout_ms.unwrap_or(CONTROL_TIMEOUT_MS_STANDARD));
        let selector = selector.to_string();
        let state = state.map(str::to_string);
        self.direct_cdp_session_operation(
            endpoint,
            "browser.wait_for_selector",
            "wait_for_selector",
            timeout,
            CONTROL_RESPONSE_BYTES_STANDARD,
            |cx, session| {
                Box::pin(async move {
                    session
                        .wait_for_selector(cx, &selector, state.as_deref(), timeout_ms)
                        .await
                })
            },
        )
        .await
    }

    async fn direct_cdp_click(
        &self,
        endpoint: &DirectCdpEndpoint,
        selector: &str,
        timeout_ms: Option<u64>,
    ) -> BrowserResult<ClickResult> {
        let timeout = Duration::from_millis(timeout_ms.unwrap_or(CONTROL_TIMEOUT_MS_STANDARD));
        let selector = selector.to_string();
        self.direct_cdp_session_operation(
            endpoint,
            "browser.click",
            "click",
            timeout,
            CONTROL_RESPONSE_BYTES_STANDARD,
            |cx, session| Box::pin(async move { session.click(cx, &selector, timeout_ms).await }),
        )
        .await
    }

    async fn direct_cdp_fill_form(
        &self,
        endpoint: &DirectCdpEndpoint,
        fields: &serde_json::Value,
        submit_selector: Option<&str>,
    ) -> BrowserResult<FormResult> {
        let timeout = Duration::from_millis(CONTROL_TIMEOUT_MS_STANDARD);
        let fields = fields.clone();
        let submit_selector = submit_selector.map(str::to_string);
        self.direct_cdp_session_operation(
            endpoint,
            "browser.fill_form",
            "fill_form",
            timeout,
            CONTROL_RESPONSE_BYTES_STANDARD,
            |cx, session| {
                Box::pin(async move {
                    session
                        .fill_form(cx, &fields, submit_selector.as_deref())
                        .await
                })
            },
        )
        .await
    }

    async fn direct_cdp_evaluate_js(
        &self,
        endpoint: &DirectCdpEndpoint,
        expression: &str,
    ) -> BrowserResult<JsResult> {
        let timeout = Duration::from_millis(CONTROL_TIMEOUT_MS_STANDARD);
        let expression = expression.to_string();
        self.direct_cdp_session_operation(
            endpoint,
            "browser.evaluate_js",
            "evaluate_js",
            timeout,
            CONTROL_RESPONSE_BYTES_STANDARD,
            |cx, session| {
                Box::pin(async move {
                    let response = session.evaluate_expression(cx, &expression).await?;
                    Ok(JsResult {
                        result: response.result,
                    })
                })
            },
        )
        .await
    }

    async fn direct_cdp_get_cookies_with_operation(
        &self,
        endpoint: &DirectCdpEndpoint,
        operation_id: &'static str,
        context_operation: &'static str,
        domain: Option<&str>,
    ) -> BrowserResult<Vec<Cookie>> {
        let timeout = Duration::from_millis(CONTROL_TIMEOUT_MS_STANDARD);
        let domain = domain.map(str::to_string);
        self.direct_cdp_session_operation(
            endpoint,
            operation_id,
            context_operation,
            timeout,
            CONTROL_RESPONSE_BYTES_STANDARD,
            |cx, session| {
                Box::pin(async move {
                    session
                        .get_cookies(cx, domain.as_deref())
                        .await
                        .map(|response| response.cookies)
                })
            },
        )
        .await
    }

    async fn direct_cdp_get_cookies(
        &self,
        endpoint: &DirectCdpEndpoint,
        domain: Option<&str>,
    ) -> BrowserResult<Vec<Cookie>> {
        self.direct_cdp_get_cookies_with_operation(
            endpoint,
            "browser.get_cookies",
            "get_cookies",
            domain,
        )
        .await
    }

    async fn direct_cdp_set_cookies_with_operation(
        &self,
        endpoint: &DirectCdpEndpoint,
        operation_id: &'static str,
        context_operation: &'static str,
        cookies: &[Cookie],
    ) -> BrowserResult<u32> {
        let timeout = Duration::from_millis(CONTROL_TIMEOUT_MS_STANDARD);
        let cookies = cookies.to_vec();
        self.direct_cdp_session_operation(
            endpoint,
            operation_id,
            context_operation,
            timeout,
            CONTROL_RESPONSE_BYTES_STANDARD,
            |cx, session| {
                Box::pin(async move {
                    session
                        .set_cookies(cx, &cookies)
                        .await
                        .map(|response| response.set_count)
                })
            },
        )
        .await
    }

    async fn direct_cdp_set_cookies(
        &self,
        endpoint: &DirectCdpEndpoint,
        cookies: &[Cookie],
    ) -> BrowserResult<u32> {
        self.direct_cdp_set_cookies_with_operation(
            endpoint,
            "browser.set_cookies",
            "set_cookies",
            cookies,
        )
        .await
    }

    // -- Navigation --

    /// Navigate to a URL.
    pub async fn navigate(
        &self,
        url: &str,
        wait_until: Option<&str>,
        timeout_ms: Option<u64>,
        user_agent: Option<&str>,
    ) -> BrowserResult<NavigateResult> {
        if let BrowserControlEndpoint::DirectCdp(endpoint) = self.control_endpoint()? {
            return self
                .direct_cdp_navigate(&endpoint, url, wait_until, timeout_ms, user_agent)
                .await;
        }

        let mut body = serde_json::json!({ "url": url });
        if let Some(w) = wait_until {
            body["wait_until"] = serde_json::Value::String(w.to_string());
        }
        if let Some(t) = timeout_ms {
            body["timeout_ms"] = serde_json::Value::Number(t.into());
        }
        if let Some(ua) = user_agent {
            body["user_agent"] = serde_json::Value::String(ua.to_string());
        }
        let data = self.post_json(WORKER_NAVIGATE, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- Screenshot --

    /// Capture a screenshot.
    pub async fn screenshot(
        &self,
        selector: Option<&str>,
        full_page: Option<bool>,
        format: Option<&str>,
        quality: Option<u32>,
    ) -> BrowserResult<ScreenshotResult> {
        if let BrowserControlEndpoint::DirectCdp(endpoint) = self.control_endpoint()? {
            return self
                .direct_cdp_screenshot(&endpoint, selector, full_page, format, quality)
                .await;
        }

        let mut body = serde_json::json!({});
        if let Some(s) = selector {
            body["selector"] = serde_json::Value::String(s.to_string());
        }
        if let Some(fp) = full_page {
            body["full_page"] = serde_json::Value::Bool(fp);
        }
        if let Some(f) = format {
            body["format"] = serde_json::Value::String(f.to_string());
        }
        if let Some(q) = quality {
            body["quality"] = serde_json::Value::Number(q.into());
        }
        let data = self.post_json(WORKER_SCREENSHOT, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- PDF --

    /// Render the current page as PDF.
    pub async fn render_pdf(
        &self,
        format: Option<&str>,
        landscape: Option<bool>,
        print_background: Option<bool>,
    ) -> BrowserResult<PdfResult> {
        if let BrowserControlEndpoint::DirectCdp(endpoint) = self.control_endpoint()? {
            return self
                .direct_cdp_render_pdf(&endpoint, format, landscape, print_background)
                .await;
        }

        let mut body = serde_json::json!({});
        if let Some(f) = format {
            body["format"] = serde_json::Value::String(f.to_string());
        }
        if let Some(l) = landscape {
            body["landscape"] = serde_json::Value::Bool(l);
        }
        if let Some(pb) = print_background {
            body["print_background"] = serde_json::Value::Bool(pb);
        }
        let data = self.post_json(WORKER_RENDER_PDF, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- Extraction --

    /// Extract text content from the page.
    pub async fn extract_text(
        &self,
        selector: Option<&str>,
        include_hidden: Option<bool>,
    ) -> BrowserResult<TextResult> {
        if let BrowserControlEndpoint::DirectCdp(endpoint) = self.control_endpoint()? {
            return self
                .direct_cdp_extract_text(&endpoint, selector, include_hidden)
                .await;
        }

        let mut body = serde_json::json!({});
        if let Some(s) = selector {
            body["selector"] = serde_json::Value::String(s.to_string());
        }
        if let Some(ih) = include_hidden {
            body["include_hidden"] = serde_json::Value::Bool(ih);
        }
        let data = self.post_json(WORKER_EXTRACT_TEXT, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Extract links from the page.
    pub async fn extract_links(&self, selector: Option<&str>) -> BrowserResult<LinksResult> {
        if let BrowserControlEndpoint::DirectCdp(endpoint) = self.control_endpoint()? {
            return self.direct_cdp_extract_links(&endpoint, selector).await;
        }

        let mut body = serde_json::json!({});
        if let Some(s) = selector {
            body["selector"] = serde_json::Value::String(s.to_string());
        }
        let data = self.post_json(WORKER_EXTRACT_LINKS, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- Wait --

    /// Wait for a selector to appear.
    pub async fn wait_for_selector(
        &self,
        selector: &str,
        state: Option<&str>,
        timeout_ms: Option<u64>,
    ) -> BrowserResult<WaitResult> {
        if let BrowserControlEndpoint::DirectCdp(endpoint) = self.control_endpoint()? {
            return self
                .direct_cdp_wait_for_selector(&endpoint, selector, state, timeout_ms)
                .await;
        }

        let mut body = serde_json::json!({ "selector": selector });
        if let Some(s) = state {
            body["state"] = serde_json::Value::String(s.to_string());
        }
        if let Some(t) = timeout_ms {
            body["timeout_ms"] = serde_json::Value::Number(t.into());
        }
        let data = self.post_json(WORKER_WAIT_FOR_SELECTOR, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- Interaction --

    /// Click an element.
    pub async fn click(
        &self,
        selector: &str,
        timeout_ms: Option<u64>,
    ) -> BrowserResult<ClickResult> {
        if let BrowserControlEndpoint::DirectCdp(endpoint) = self.control_endpoint()? {
            return self.direct_cdp_click(&endpoint, selector, timeout_ms).await;
        }

        let mut body = serde_json::json!({ "selector": selector });
        if let Some(t) = timeout_ms {
            body["timeout_ms"] = serde_json::Value::Number(t.into());
        }
        let data = self.post_json(WORKER_CLICK, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Fill form fields.
    pub async fn fill_form(
        &self,
        fields: &serde_json::Value,
        submit_selector: Option<&str>,
    ) -> BrowserResult<FormResult> {
        if let BrowserControlEndpoint::DirectCdp(endpoint) = self.control_endpoint()? {
            return self
                .direct_cdp_fill_form(&endpoint, fields, submit_selector)
                .await;
        }

        let mut body = serde_json::json!({ "fields": fields });
        if let Some(ss) = submit_selector {
            body["submit_selector"] = serde_json::Value::String(ss.to_string());
        }
        let data = self.post_json(WORKER_FILL_FORM, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- JavaScript --

    /// Evaluate JavaScript in the page context.
    pub async fn evaluate_js(&self, expression: &str) -> BrowserResult<JsResult> {
        if let BrowserControlEndpoint::DirectCdp(endpoint) = self.control_endpoint()? {
            return self.direct_cdp_evaluate_js(&endpoint, expression).await;
        }

        let body = serde_json::json!({ "expression": expression });
        let data = self.post_json(WORKER_EVALUATE_JS, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- Cookies --

    /// Get cookies.
    pub async fn get_cookies(&self, domain: Option<&str>) -> BrowserResult<Vec<Cookie>> {
        if let BrowserControlEndpoint::DirectCdp(endpoint) = self.control_endpoint()? {
            return self.direct_cdp_get_cookies(&endpoint, domain).await;
        }

        let mut body = serde_json::json!({});
        if let Some(d) = domain {
            body["domain"] = serde_json::Value::String(d.to_string());
        }
        let data = self.post_json(WORKER_GET_COOKIES, &body).await?;
        let cookies: Vec<Cookie> = serde_json::from_value(
            data.get("cookies")
                .cloned()
                .unwrap_or(serde_json::Value::Array(vec![])),
        )?;
        Ok(cookies)
    }

    /// Set cookies.
    pub async fn set_cookies(&self, cookies: &[Cookie]) -> BrowserResult<u32> {
        if let BrowserControlEndpoint::DirectCdp(endpoint) = self.control_endpoint()? {
            return self.direct_cdp_set_cookies(&endpoint, cookies).await;
        }

        let body = serde_json::json!({ "cookies": cookies });
        let data = self.post_json(WORKER_SET_COOKIES, &body).await?;
        let count = data.get("set_count").and_then(|v| v.as_u64()).unwrap_or(0);
        Ok(count as u32)
    }

    pub(crate) async fn session_save_cookies(
        &self,
        domain: Option<&str>,
    ) -> BrowserResult<Vec<Cookie>> {
        if let BrowserControlEndpoint::DirectCdp(endpoint) = self.control_endpoint()? {
            return self
                .direct_cdp_get_cookies_with_operation(
                    &endpoint,
                    "browser.session.save",
                    "session_save",
                    domain,
                )
                .await;
        }

        self.get_cookies(domain).await
    }

    pub(crate) async fn session_restore_cookies(&self, cookies: &[Cookie]) -> BrowserResult<u32> {
        if let BrowserControlEndpoint::DirectCdp(endpoint) = self.control_endpoint()? {
            return self
                .direct_cdp_set_cookies_with_operation(
                    &endpoint,
                    "browser.session.restore",
                    "session_restore",
                    cookies,
                )
                .await;
        }

        self.set_cookies(cookies).await
    }

    // -- Proxy --

    /// Configure outbound proxy for browser traffic.
    pub async fn set_proxy(&self, proxy: &ProxyConfig) -> BrowserResult<ProxyResult> {
        validate_proxy_config(proxy)?;
        if let Some(result) = self.with_rust_owned_launcher_mut(|launcher| {
            launcher.set_proxy(proxy, || self.runtime.is_shutting_down())
        })? {
            return Ok(result);
        }

        if let BrowserControlEndpoint::DirectCdp(_) = self.control_endpoint()? {
            return Err(proxy_unavailable_error(
                "browser.set_proxy",
                "direct_cdp_websocket",
                "proxy_unavailable_direct_cdp",
            ));
        }

        self.ensure_proxy_control_plane_available("browser.set_proxy")
            .await?;
        let body = serde_json::to_value(proxy)?;
        let data = self.post_json(WORKER_SET_PROXY, &body).await?;
        Ok(serde_json::from_value(data)?)
    }

    /// Clear outbound proxy configuration.
    pub async fn clear_proxy(&self) -> BrowserResult<ProxyResult> {
        if let Some(result) = self.with_rust_owned_launcher_mut(|launcher| {
            launcher.clear_proxy(|| self.runtime.is_shutting_down())
        })? {
            return Ok(result);
        }

        if let BrowserControlEndpoint::DirectCdp(_) = self.control_endpoint()? {
            return Err(proxy_unavailable_error(
                "browser.clear_proxy",
                "direct_cdp_websocket",
                "proxy_unavailable_direct_cdp",
            ));
        }

        self.ensure_proxy_control_plane_available("browser.clear_proxy")
            .await?;
        let data = self
            .post_json(WORKER_CLEAR_PROXY, &serde_json::json!({}))
            .await?;
        Ok(serde_json::from_value(data)?)
    }

    // -- HTTP helpers --

    async fn ensure_proxy_control_plane_available(
        &self,
        operation_id: &'static str,
    ) -> BrowserResult<()> {
        let url = format!("{}/health", self.browser_url);
        let timeout = Duration::from_millis(CONTROL_TIMEOUT_MS_SHORT);
        let body = self
            .execute(CONTROL_RESPONSE_BYTES_STANDARD, timeout, || {
                self.http.get(&url).timeout(timeout)
            })
            .await?;

        validate_fcp_browser_control_proxy_support(&body)
            .map_err(|reason| proxy_unavailable_error(operation_id, "fcp_browser_control", &reason))
    }

    fn worker_endpoint(&self, operation: BrowserControlOperation) -> String {
        debug_assert_eq!(operation.method, "POST");
        format!("{}{}", self.browser_url, operation.path)
    }

    async fn post_json(
        &self,
        operation: BrowserControlOperation,
        body: &serde_json::Value,
    ) -> BrowserResult<serde_json::Value> {
        let url = self.worker_endpoint(operation);
        let timeout = Duration::from_millis(operation.timeout_ms);
        self.execute(operation.max_response_bytes, timeout, || {
            self.http
                .post(&url)
                .timeout(timeout)
                .header(CONTROL_OPERATION_HEADER, operation.id)
                .header(
                    CONTROL_RESPONSE_BUDGET_HEADER,
                    operation.max_response_bytes.to_string(),
                )
                .header(
                    CONTROL_TIMEOUT_BUDGET_HEADER,
                    operation.timeout_ms.to_string(),
                )
                .header(CONTROL_TARGET_SCOPE_HEADER, operation.target_policy.scope)
                .header(
                    CONTROL_TARGET_SELECTION_HEADER,
                    operation.target_policy.selection,
                )
                .header(
                    CONTROL_STALE_TARGET_RECOVERY_HEADER,
                    operation.target_policy.stale_target_recovery.to_string(),
                )
                .header(
                    CONTROL_CURRENT_TAB_GUARD_HEADER,
                    operation.target_policy.current_tab_guard.to_string(),
                )
                .header(
                    CONTROL_EXPORT_GUARD_HEADER,
                    operation.target_policy.export_guard.to_string(),
                )
                .json(body)
        })
        .await
    }

    /// Execute one browser control-plane request with retry.
    ///
    /// br-kxd3e: NOT replay-safe, and deliberately not parameterised. Every
    /// request through here drives a REAL browser — navigate, click, type,
    /// submit, download — and `BrowserControlOperation` carries no idempotency
    /// marker, so this layer cannot tell a screenshot from a checkout button.
    /// Replaying a click after the worker already dispatched it can submit a
    /// form or place an order twice.
    ///
    /// Same reasoning as mcp-bridge's `tools/call`: when the side effect is
    /// unknowable from here, fail closed. The rate-limit arm above stays
    /// retryable (the worker refused it WITHOUT driving the browser), and a
    /// connect-phase transport failure still retries because the request
    /// provably never reached the worker.
    async fn execute(
        &self,
        max_response_bytes: usize,
        timeout: Duration,
        build_request: impl Fn() -> reqwest::RequestBuilder,
    ) -> BrowserResult<serde_json::Value> {
        let ctx = self.request_context_for_timeout(timeout);
        let policy = self.retry_config.to_retry_policy();

        RetryLoop::execute(&ctx, &policy, |_attempt| {
            let req = build_request();
            async move {
                match req.send().await {
                    Ok(response) => {
                        let status = response.status();

                        if status == StatusCode::TOO_MANY_REQUESTS {
                            let err = BrowserError::Api {
                                message: "Rate limited by browser API".into(),
                                status_code: Some(429),
                            };
                            return AttemptOutcome::Retryable {
                                retry_after: err.retry_after(),
                                error: err,
                            };
                        }

                        if status.is_server_error() {
                            let body = match read_limited_response_text(
                                response,
                                max_response_bytes,
                            )
                            .await
                            {
                                Ok(body) => body,
                                Err(err) => return AttemptOutcome::Terminal(err),
                            };
                            let body = redact_browser_control_error_text(&body);
                            let err = BrowserError::Api {
                                message: format!("Server error {status}: {body}"),
                                status_code: Some(status.as_u16()),
                            };
                            // A 5xx means the worker received the operation and
                            // may already have driven the browser with it.
                            return AttemptOutcome::Terminal(err);
                        }

                        if !status.is_success() {
                            let body = match read_limited_response_text(
                                response,
                                max_response_bytes,
                            )
                            .await
                            {
                                Ok(body) => body,
                                Err(err) => return AttemptOutcome::Terminal(err),
                            };
                            let api_err: Option<ApiErrorResponse> =
                                serde_json::from_str(&body).ok();
                            let redacted_body = redact_browser_control_error_text(&body);
                            let message = api_err
                                .as_ref()
                                .and_then(|e| e.error.as_ref())
                                .and_then(|d| d.message.clone())
                                .map(|message| redact_browser_control_error_text(&message))
                                .unwrap_or(format!("HTTP {status}: {redacted_body}"));
                            return AttemptOutcome::Terminal(BrowserError::Api {
                                message,
                                status_code: Some(status.as_u16()),
                            });
                        }

                        match read_limited_response_text(response, max_response_bytes).await {
                            Ok(body) => match serde_json::from_str(&body) {
                                Ok(data) => AttemptOutcome::Success(data),
                                Err(e) => AttemptOutcome::Terminal(BrowserError::Serialization(e)),
                            },
                            Err(e) => AttemptOutcome::Terminal(e),
                        }
                    }
                    Err(e) => {
                        // Only a connect-phase failure proves the operation
                        // never reached the control worker.
                        let replayable = !transport_error_reached_service(&e);
                        AttemptOutcome::retryable_if_replayable(
                            BrowserError::Http(e),
                            None,
                            replayable,
                        )
                    }
                }
            }
        })
        .await
    }

    fn request_context_for_timeout(&self, timeout: Duration) -> fcp_async_core::ExecutionContext {
        self.runtime.request_context_with_timeout(timeout)
    }

    async fn raw_chrome_cdp_endpoint_detected(&self) -> bool {
        let url = format!("{}/json/version", self.browser_url);
        let timeout = Duration::from_millis(CONTROL_TIMEOUT_MS_STANDARD);
        match self
            .execute(CONTROL_RESPONSE_BYTES_STANDARD, timeout, || {
                self.http.get(&url).timeout(timeout)
            })
            .await
        {
            Ok(body) => looks_like_chrome_cdp_version(&body),
            Err(_) => false,
        }
    }
}

async fn read_limited_response_text(
    response: reqwest::Response,
    max_response_bytes: usize,
) -> BrowserResult<String> {
    let status = response.status();
    if let Some(content_length) = response.content_length() {
        if usize::try_from(content_length).map_or(true, |length| length > max_response_bytes) {
            return Err(response_size_limit_error(
                status,
                max_response_bytes,
                Some(content_length),
            ));
        }
    }

    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(BrowserError::Http)?;
        if body.len().saturating_add(chunk.len()) > max_response_bytes {
            return Err(response_size_limit_error(status, max_response_bytes, None));
        }
        body.extend_from_slice(&chunk);
    }

    String::from_utf8(body).map_err(|e| BrowserError::Api {
        message: format!("browser control response is not valid UTF-8 JSON: {e}"),
        status_code: Some(status.as_u16()),
    })
}

fn response_size_limit_error(
    status: StatusCode,
    max_response_bytes: usize,
    content_length: Option<u64>,
) -> BrowserError {
    let message = match content_length {
        Some(content_length) => format!(
            "browser control response exceeds {max_response_bytes} byte limit: content-length {content_length}"
        ),
        None => {
            format!("browser control response exceeds {max_response_bytes} byte limit")
        }
    };

    BrowserError::Api {
        message,
        status_code: Some(status.as_u16()),
    }
}

fn redact_browser_control_error_text(body: &str) -> String {
    if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(body) {
        redact_sensitive_json(&mut value);
        return serde_json::to_string(&value)
            .unwrap_or_else(|_| "[redacted browser-control error body]".to_string());
    }

    if contains_sensitive_marker(body) {
        "[redacted browser-control error body]".to_string()
    } else {
        body.to_string()
    }
}

fn redact_sensitive_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if is_sensitive_error_key(key) {
                    *child = redacted_json_value();
                } else {
                    redact_sensitive_json(child);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_sensitive_json(item);
            }
        }
        serde_json::Value::String(text) => {
            if contains_sensitive_marker(text) {
                *text = "[redacted]".to_string();
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

fn redacted_json_value() -> serde_json::Value {
    serde_json::Value::String("[redacted]".to_string())
}

fn is_sensitive_error_key(key: &str) -> bool {
    let normalized = key.replace(['-', '_'], "").to_ascii_lowercase();
    normalized.contains("token")
        || normalized.contains("secret")
        || normalized.contains("password")
        || normalized.contains("cookie")
        || normalized.contains("authorization")
        || normalized.contains("apikey")
        || normalized.contains("credential")
}

fn contains_sensitive_marker(text: &str) -> bool {
    let normalized = text.to_ascii_lowercase();
    normalized.contains("bearer ")
        || normalized.contains("authorization")
        || normalized.contains("access_token")
        || normalized.contains("refresh_token")
        || normalized.contains("id_token")
        || normalized.contains("api_key")
        || normalized.contains("apikey")
        || normalized.contains("password")
        || normalized.contains("secret")
        || normalized.contains("cookie")
        || normalized.contains("set-cookie")
        || normalized.contains("credential")
}

fn decode_cdp_response_message(
    message: WebSocketMessage,
    expected_command_id: u64,
) -> BrowserResult<Option<serde_json::Value>> {
    match message {
        WebSocketMessage::Text(text) => decode_cdp_response_text(&text, expected_command_id),
        WebSocketMessage::Binary(_) => Err(BrowserError::Api {
            message: "Chrome DevTools Protocol response must be UTF-8 text JSON".into(),
            status_code: None,
        }),
        WebSocketMessage::Close(_) => Err(BrowserError::Api {
            message: "Chrome DevTools Protocol connection closed before command response".into(),
            status_code: None,
        }),
        WebSocketMessage::Ping(_) | WebSocketMessage::Pong(_) => Ok(None),
    }
}

fn decode_cdp_response_text(
    text: &str,
    expected_command_id: u64,
) -> BrowserResult<Option<serde_json::Value>> {
    let mut value: serde_json::Value = serde_json::from_str(text)?;

    let Some(id) = value.get("id").and_then(serde_json::Value::as_u64) else {
        if value
            .get("method")
            .and_then(serde_json::Value::as_str)
            .is_some()
        {
            return Ok(None);
        }
        return Err(BrowserError::Api {
            message: "Chrome DevTools Protocol response is missing numeric command id".into(),
            status_code: None,
        });
    };

    if id != expected_command_id {
        return Ok(None);
    }

    if let Some(error) = value.get_mut("error") {
        redact_sensitive_json(error);
        return Err(BrowserError::Api {
            message: format!(
                "Chrome DevTools Protocol command {expected_command_id} failed: {}",
                serde_json::to_string(error)?
            ),
            status_code: None,
        });
    }

    Ok(Some(
        value
            .get("result")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
    ))
}

fn validate_fcp_browser_control_health(body: &serde_json::Value) -> Result<(), String> {
    let operations = validate_fcp_browser_control_metadata(body)?;
    for required in REQUIRED_BROWSER_CONTROL_OPERATIONS
        .iter()
        .filter(|operation| !is_proxy_browser_control_operation(operation.id))
    {
        let operation = find_browser_control_operation(operations, required.id)
            .ok_or_else(|| format!("missing required operation `{}`", required.id))?;
        validate_browser_control_operation(operation, required)?;
    }

    for proxy_operation in PROXY_BROWSER_CONTROL_OPERATIONS {
        if let Some(operation) = find_browser_control_operation(operations, proxy_operation.id) {
            validate_browser_control_operation(operation, proxy_operation)?;
        }
    }

    Ok(())
}

fn validate_fcp_browser_control_proxy_support(body: &serde_json::Value) -> Result<(), String> {
    let operations = validate_fcp_browser_control_metadata(body)?;

    for required in REQUIRED_BROWSER_CONTROL_OPERATIONS
        .iter()
        .filter(|operation| !is_proxy_browser_control_operation(operation.id))
    {
        let operation = find_browser_control_operation(operations, required.id)
            .ok_or_else(|| format!("missing required operation `{}`", required.id))?;
        validate_browser_control_operation(operation, required)?;
    }

    let mut missing = Vec::new();
    for required in PROXY_BROWSER_CONTROL_OPERATIONS {
        match find_browser_control_operation(operations, required.id) {
            Some(operation) => validate_browser_control_operation(operation, required)
                .map_err(|reason| format!("proxy_invalid_worker_contract {reason}"))?,
            None => missing.push(required.id),
        }
    }

    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "proxy_unavailable_worker_contract missing required proxy operations [{}]",
            missing.join(", ")
        ))
    }
}

fn validate_fcp_browser_control_metadata(
    body: &serde_json::Value,
) -> Result<&[serde_json::Value], String> {
    let control_plane = body
        .get("control_plane")
        .or_else(|| body.get("service"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing control_plane/service".to_string())?;
    if control_plane != "fcp-browser-control" && control_plane != "fcp.browser-control" {
        return Err(format!(
            "unexpected control_plane/service `{control_plane}`"
        ));
    }

    let protocol_version = body
        .get("protocol_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "missing numeric protocol_version".to_string())?;
    if protocol_version != BROWSER_CONTROL_PROTOCOL_VERSION {
        return Err(format!(
            "unsupported protocol_version {protocol_version}; expected {BROWSER_CONTROL_PROTOCOL_VERSION}"
        ));
    }

    let operations = body
        .get("operations")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "missing operations array".to_string())?;
    Ok(operations.as_slice())
}

fn find_browser_control_operation<'a>(
    operations: &'a [serde_json::Value],
    operation_id: &str,
) -> Option<&'a serde_json::Value> {
    operations.iter().find(|operation| {
        operation.get("id").and_then(serde_json::Value::as_str) == Some(operation_id)
    })
}

fn is_proxy_browser_control_operation(operation_id: &str) -> bool {
    PROXY_BROWSER_CONTROL_OPERATIONS
        .iter()
        .any(|operation| operation.id == operation_id)
}

fn validate_browser_control_operation(
    operation: &serde_json::Value,
    required: &BrowserControlOperation,
) -> Result<(), String> {
    if operation
        .get("id")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|id| id == required.id)
        && operation
            .get("method")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|method| method == required.method)
        && operation
            .get("path")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|path| path == required.path)
        && operation
            .get("max_response_bytes")
            .and_then(serde_json::Value::as_u64)
            .and_then(|limit| usize::try_from(limit).ok())
            .is_some_and(|limit| limit == required.max_response_bytes)
        && operation
            .get("timeout_ms")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|timeout_ms| timeout_ms == required.timeout_ms)
        && operation
            .get("target_policy")
            .is_some_and(|target_policy| target_policy == &required.target_policy.descriptor())
        && operation
            .get("request_headers")
            .is_some_and(|request_headers| {
                request_headers == &required.request_headers_descriptor()
            })
        && browser_control_implementation_matches(operation, required)
    {
        Ok(())
    } else {
        Err(format!(
            "operation `{}` is incompatible; expected {} `{}` with max_response_bytes {}, timeout_ms {}, target_policy {}, request_headers [{}], and implementation {}",
            required.id,
            required.method,
            required.path,
            required.max_response_bytes,
            required.timeout_ms,
            required.target_policy.summary(),
            required.request_headers_summary(),
            required.implementation.summary()
        ))
    }
}

fn browser_control_implementation_matches(
    operation: &serde_json::Value,
    required: &BrowserControlOperation,
) -> bool {
    let implementation = &operation["implementation"];
    match required.implementation {
        BrowserControlImplementation::Cdp { methods } => {
            implementation
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|kind| kind == "cdp")
                && implementation
                    .get("methods")
                    .is_some_and(|advertised| advertised == &serde_json::json!(methods))
        }
        BrowserControlImplementation::WorkerPolicy { description } => {
            implementation
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|kind| kind == "worker_policy")
                && implementation
                    .get("methods")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(Vec::is_empty)
                && implementation
                    .get("description")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|advertised| advertised == description)
                && implementation
                    .get("redaction_contract")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|advertised| advertised == PROXY_REDACTION_CONTRACT)
        }
    }
}

fn validate_proxy_config(proxy: &ProxyConfig) -> BrowserResult<()> {
    let descriptor_len = serde_json::to_vec(proxy)?.len();
    if descriptor_len > PROXY_DESCRIPTOR_MAX_BYTES {
        return Err(proxy_descriptor_error("proxy_descriptor_too_large"));
    }

    reject_proxy_control_chars("server", &proxy.server)?;
    if let Some(username) = &proxy.username {
        reject_proxy_control_chars("username", username)?;
    }
    if let Some(password) = &proxy.password {
        reject_proxy_control_chars("password", password)?;
    }

    let server = reqwest::Url::parse(&proxy.server)
        .map_err(|_| proxy_descriptor_error("proxy_invalid_server_url"))?;
    match server.scheme() {
        "http" | "https" | "socks5" | "socks5h" => {}
        _ => return Err(proxy_descriptor_error("proxy_invalid_scheme")),
    }
    if !server.username().is_empty() || server.password().is_some() {
        return Err(proxy_descriptor_error("proxy_embedded_credentials"));
    }

    let host = server
        .host_str()
        .ok_or_else(|| proxy_descriptor_error("proxy_missing_host"))?;
    if proxy_host_is_disallowed(host) {
        return Err(proxy_descriptor_error("proxy_private_or_internal_host"));
    }

    if let Some(bypass_list) = &proxy.bypass_list {
        if bypass_list.len() > PROXY_BYPASS_MAX_ENTRIES {
            return Err(proxy_descriptor_error("proxy_bypass_list_too_large"));
        }
        for entry in bypass_list {
            if entry.is_empty() || entry.len() > PROXY_BYPASS_ENTRY_MAX_BYTES {
                return Err(proxy_descriptor_error("proxy_invalid_bypass_entry"));
            }
            reject_proxy_control_chars("bypass_list", entry)?;
        }
    }

    Ok(())
}

fn reject_proxy_control_chars(field: &'static str, value: &str) -> BrowserResult<()> {
    if value.chars().any(char::is_control) {
        Err(BrowserError::InvalidConfig(format!(
            "proxy descriptor rejected: reason_code=proxy_descriptor_control_char field={field}"
        )))
    } else {
        Ok(())
    }
}

fn proxy_host_is_disallowed(host: &str) -> bool {
    let normalized = host
        .trim_matches(|ch| ch == '[' || ch == ']')
        .to_ascii_lowercase();
    if normalized == "localhost"
        || proxy_host_has_suffix_label(&normalized, "localhost")
        || proxy_host_has_suffix_label(&normalized, "local")
        || proxy_host_has_suffix_label(&normalized, "internal")
    {
        return true;
    }

    normalized
        .parse::<IpAddr>()
        .is_ok_and(disallowed_proxy_ip_address)
}

fn proxy_host_has_suffix_label(host: &str, suffix_label: &str) -> bool {
    host.strip_suffix(suffix_label)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

fn disallowed_proxy_ip_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 64)
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        }
    }
}

fn proxy_descriptor_error(reason_code: &'static str) -> BrowserError {
    BrowserError::InvalidConfig(format!(
        "proxy descriptor rejected: reason_code={reason_code}"
    ))
}

fn proxy_unavailable_error(
    operation_id: &'static str,
    control_mode: &'static str,
    reason: &str,
) -> BrowserError {
    let reason_code = reason.split_whitespace().next().unwrap_or(reason);
    BrowserError::InvalidConfig(format!(
        "{operation_id} proxy_unavailable control_mode={control_mode} reason_code={reason_code}; {reason}; remediation=configure a proxy-capable fcp-browser-control worker that advertises browser.set_proxy and browser.clear_proxy contract v{BROWSER_CONTROL_PROTOCOL_VERSION}"
    ))
}

fn rust_owned_launcher_error(
    operation_id: &'static str,
    reason_code: &'static str,
    reason: &str,
) -> BrowserError {
    BrowserError::InvalidConfig(format!(
        "{operation_id} rust_owned_launcher_unavailable control_mode=rust_owned_launcher reason_code={reason_code}; {reason}; remediation=configure a safe browser binary path or use the existing proxy-capable fcp-browser-control worker path"
    ))
}

fn looks_like_chrome_cdp_version(body: &serde_json::Value) -> bool {
    body.get("webSocketDebuggerUrl")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|value| value.starts_with("ws://") || value.starts_with("wss://"))
        || body
            .get("Browser")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|value| {
                value.starts_with("Chrome/") || value.starts_with("HeadlessChrome/")
            })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::{BTreeSet, VecDeque},
        io::{BufRead, BufReader, Read, Write},
        net::{TcpListener, TcpStream},
        sync::{Arc, Mutex},
        thread::{self, JoinHandle},
    };

    fn browser_control_contract_without_proxy_operations() -> serde_json::Value {
        let mut descriptor = browser_control_contract_descriptor();
        descriptor["operations"]
            .as_array_mut()
            .unwrap()
            .retain(|operation| {
                operation
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .is_none_or(|id| !is_proxy_browser_control_operation(id))
            });
        descriptor
    }

    #[derive(Clone)]
    struct TestControlResponse {
        method: &'static str,
        path: &'static str,
        status: u16,
        body: Vec<u8>,
        content_type: &'static str,
        delay: Duration,
        expected_headers: Vec<(&'static str, String)>,
    }

    impl TestControlResponse {
        fn json(
            method: &'static str,
            path: &'static str,
            status: u16,
            body: impl serde::Serialize,
        ) -> Self {
            Self {
                method,
                path,
                status,
                body: serde_json::to_vec(&body).expect("serialize response json"),
                content_type: "application/json",
                delay: Duration::ZERO,
                expected_headers: Vec::new(),
            }
        }

        fn text(method: &'static str, path: &'static str, status: u16, body: &str) -> Self {
            Self {
                method,
                path,
                status,
                body: body.as_bytes().to_vec(),
                content_type: "text/plain; charset=utf-8",
                delay: Duration::ZERO,
                expected_headers: Vec::new(),
            }
        }

        fn bytes(method: &'static str, path: &'static str, status: u16, body: Vec<u8>) -> Self {
            Self {
                method,
                path,
                status,
                body,
                content_type: "application/octet-stream",
                delay: Duration::ZERO,
                expected_headers: Vec::new(),
            }
        }

        fn with_delay(mut self, delay: Duration) -> Self {
            self.delay = delay;
            self
        }

        fn expect_header(mut self, name: &'static str, value: impl Into<String>) -> Self {
            self.expected_headers.push((name, value.into()));
            self
        }
    }

    #[derive(Clone, Debug)]
    struct TestControlRequest {
        method: String,
        path: String,
    }

    struct TestControlServer {
        base_url: String,
        requests: Arc<Mutex<Vec<TestControlRequest>>>,
        _handle: JoinHandle<()>,
    }

    impl TestControlServer {
        fn respond(response: TestControlResponse) -> Self {
            Self::respond_sequence(vec![response])
        }

        fn respond_sequence(responses: Vec<TestControlResponse>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
            let base_url = format!("http://{}", listener.local_addr().expect("local address"));
            let requests = Arc::new(Mutex::new(Vec::new()));
            let thread_requests = Arc::clone(&requests);
            let handle = thread::spawn(move || {
                for response in responses {
                    let (stream, _) = listener.accept().expect("accept browser client request");
                    handle_test_control_request(stream, &response, &thread_requests);
                }
            });
            Self {
                base_url,
                requests,
                _handle: handle,
            }
        }

        fn uri(&self) -> String {
            self.base_url.clone()
        }

        fn received_requests(&self) -> Vec<TestControlRequest> {
            self.requests.lock().expect("request log poisoned").clone()
        }
    }

    fn health_response(body: serde_json::Value) -> TestControlResponse {
        TestControlResponse::json("GET", "/health", 200, body)
    }

    fn handle_test_control_request(
        mut stream: TcpStream,
        response: &TestControlResponse,
        requests: &Arc<Mutex<Vec<TestControlRequest>>>,
    ) {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));

        let mut request_line = String::new();
        reader
            .read_line(&mut request_line)
            .expect("read request line");
        let mut parts = request_line.split_whitespace();
        let method = parts.next().expect("request method").to_owned();
        let raw_path = parts.next().expect("request target").to_owned();
        let path = raw_path.split('?').next().expect("request path").to_owned();

        let mut headers = Vec::<(String, String)>::new();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).expect("read header line");
            if line == "\r\n" || line.is_empty() {
                break;
            }
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().expect("content-length parses");
            }
            headers.push((name, value));
        }
        if content_length > 0 {
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).expect("read request body");
        }

        assert_eq!(method, response.method);
        assert_eq!(path, response.path);
        for (expected_name, expected_value) in &response.expected_headers {
            let actual = headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case(expected_name))
                .map(|(_, value)| value.as_str());
            assert_eq!(actual, Some(expected_value.as_str()), "{expected_name}");
        }

        requests
            .lock()
            .expect("request log poisoned")
            .push(TestControlRequest { method, path });

        if !response.delay.is_zero() {
            thread::sleep(response.delay);
        }

        let status_text = match response.status {
            400 => "Bad Request",
            404 => "Not Found",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            _ => "OK",
        };
        write!(
            stream,
            "HTTP/1.1 {} {}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            response.status,
            status_text,
            response.content_type,
            response.body.len(),
        )
        .expect("write response header");
        if stream.write_all(&response.body).is_ok() {
            let _ = stream.flush();
        }
    }

    #[derive(Debug, Default)]
    struct ScriptedCdpTransport {
        sent: Vec<WebSocketMessage>,
        received: VecDeque<WebSocketMessage>,
    }

    impl ScriptedCdpTransport {
        fn with_received(messages: impl IntoIterator<Item = WebSocketMessage>) -> Self {
            Self {
                sent: Vec::new(),
                received: messages.into_iter().collect(),
            }
        }
    }

    fn assert_cdp_text_message(message: &WebSocketMessage, expected: &serde_json::Value) {
        assert!(
            matches!(message, WebSocketMessage::Text(_)),
            "expected CDP text WebSocket message, got {message:?}"
        );
        let WebSocketMessage::Text(text) = message else {
            return;
        };
        let actual = serde_json::from_str::<serde_json::Value>(text).unwrap();
        assert_eq!(&actual, expected);
    }

    #[async_trait::async_trait]
    impl CdpCommandTransport for ScriptedCdpTransport {
        async fn send_cdp_message(
            &mut self,
            _cx: &Cx,
            message: WebSocketMessage,
        ) -> BrowserResult<()> {
            self.sent.push(message);
            Ok(())
        }

        async fn recv_cdp_message(&mut self, _cx: &Cx) -> BrowserResult<Option<WebSocketMessage>> {
            Ok(self.received.pop_front())
        }
    }

    #[test]
    fn test_direct_cdp_endpoint_accepts_page_websocket_url() -> BrowserResult<()> {
        let endpoint =
            browser_control_endpoint_for_url("ws://127.0.0.1:9222/devtools/page/page-1")?;

        let BrowserControlEndpoint::DirectCdp(endpoint) = endpoint else {
            return Err(BrowserError::InvalidConfig(
                "expected direct CDP endpoint".into(),
            ));
        };
        assert_eq!(endpoint.url, "ws://127.0.0.1:9222/devtools/page/page-1");
        assert_eq!(endpoint.endpoint_kind, DirectCdpEndpointKind::WebSocket);
        assert_eq!(endpoint.target.kind, DirectCdpTargetKind::Page);
        assert_eq!(endpoint.target.path_kind, "page");
        assert_eq!(endpoint.target.id_hash, direct_cdp_target_id_hash("page-1"));
        assert_eq!(
            endpoint.redacted_url,
            format!(
                "ws://127.0.0.1:9222/devtools/page/target-hash-{}",
                direct_cdp_target_id_hash("page-1")
            )
        );
        assert!(!endpoint.redacted_url.contains("page-1"));
        Ok(())
    }

    #[test]
    fn test_direct_cdp_target_path_classification_is_explicit() {
        let page = direct_cdp_target_from_path("/devtools/page/page-target").unwrap();
        assert_eq!(page.kind, DirectCdpTargetKind::Page);
        assert_eq!(page.path_kind, "page");
        assert_eq!(page.id_hash, direct_cdp_target_id_hash("page-target"));

        let browser = direct_cdp_target_from_path("/devtools/browser/browser-target").unwrap();
        assert_eq!(browser.kind, DirectCdpTargetKind::Browser);
        assert_eq!(browser.path_kind, "browser");
        assert_eq!(
            browser.descriptor(),
            serde_json::json!({
                "target_kind": "browser",
                "path_kind": "browser",
                "target_id_hash": format!("blake3:{}", direct_cdp_target_id_hash("browser-target")),
            })
        );

        let worker = direct_cdp_target_from_path("/devtools/service_worker/sw-target").unwrap();
        assert_eq!(worker.kind, DirectCdpTargetKind::Worker);
        assert_eq!(worker.path_kind, "service_worker");

        let unsupported = direct_cdp_target_from_path("/devtools/iframe/frame-target").unwrap();
        assert_eq!(unsupported.kind, DirectCdpTargetKind::Unsupported);
        assert_eq!(unsupported.path_kind, "iframe");

        let missing_target = direct_cdp_target_from_path("/devtools/page/").unwrap_err();
        assert!(format!("{missing_target}").contains("missing target id"));
    }

    #[test]
    fn test_direct_cdp_endpoint_rejects_unsafe_or_unsupported_urls() {
        for (url, expected) in [
            (
                "wss://127.0.0.1:9222/devtools/page/page-1",
                "must use ws://",
            ),
            (
                "ws://user:pass@127.0.0.1:9222/devtools/page/page-1",
                "must not contain userinfo",
            ),
            (
                "ws://127.0.0.1:9222/devtools/page/page-1?debug=true",
                "must not contain query",
            ),
            (
                "ws://10.0.0.2:9222/devtools/page/page-1",
                "must use a loopback host",
            ),
            (
                "ws://127.0.0.1:9222/devtools/browser/browser-1",
                "unsupported browser endpoint",
            ),
            (
                "ws://127.0.0.1:9222/devtools/worker/worker-1",
                "unsupported worker endpoint",
            ),
            ("ws://127.0.0.1:9222/devtools/page/", "missing target id"),
        ] {
            let error = browser_control_endpoint_for_url(url).unwrap_err();
            assert!(
                format!("{error}").contains(expected),
                "{url} should fail with {expected}, got {error}"
            );
        }
    }

    #[test]
    fn test_http_browser_url_remains_fcp_control_plane_endpoint() {
        let endpoint = browser_control_endpoint_for_url("http://127.0.0.1:9222").unwrap();

        assert_eq!(endpoint, BrowserControlEndpoint::FcpControlPlane);
    }

    #[test]
    fn test_direct_cdp_endpoint_descriptor_is_redaction_safe() -> BrowserResult<()> {
        let endpoint =
            browser_control_endpoint_for_url("ws://localhost:9222/devtools/page/sensitive-target")?;
        let BrowserControlEndpoint::DirectCdp(endpoint) = endpoint else {
            return Err(BrowserError::InvalidConfig(
                "expected direct CDP endpoint".into(),
            ));
        };

        let descriptor = endpoint.descriptor();

        assert_eq!(descriptor["endpoint_kind"], "direct_cdp_websocket");
        assert_eq!(descriptor["target"]["target_kind"], "page");
        assert_eq!(
            descriptor["current_tab_decision"],
            "configured_target_is_current_tab"
        );
        assert_eq!(
            descriptor["export_target_decision"],
            "configured_target_is_export_target"
        );
        assert_eq!(descriptor["stale_target_recovery"], false);
        assert!(
            descriptor["target"]["target_id_hash"]
                .as_str()
                .unwrap()
                .starts_with("blake3:")
        );
        let redacted = descriptor["redacted_endpoint"].as_str().unwrap();
        assert!(redacted.starts_with("ws://localhost:9222/devtools/page/target-hash-"));
        assert!(!redacted.contains("sensitive-target"));
        assert!(!descriptor.to_string().contains("sensitive-target"));
        Ok(())
    }

    #[test]
    fn test_direct_cdp_manager_single_owner_state_transitions_and_jsonl() -> BrowserResult<()> {
        let endpoint =
            browser_control_endpoint_for_url("ws://127.0.0.1:9222/devtools/page/page-alpha")?;
        let BrowserControlEndpoint::DirectCdp(endpoint) = endpoint else {
            return Err(BrowserError::InvalidConfig(
                "expected direct CDP endpoint".into(),
            ));
        };
        let replacement =
            browser_control_endpoint_for_url("ws://127.0.0.1:9222/devtools/page/page-beta")?;
        let BrowserControlEndpoint::DirectCdp(replacement) = replacement else {
            return Err(BrowserError::InvalidConfig(
                "expected direct CDP endpoint".into(),
            ));
        };
        let manager = Arc::new(Mutex::new(DirectCdpTargetSessionManager::default()));
        let mut lease = DirectCdpManagerLease::acquire(
            Arc::clone(&manager),
            &endpoint,
            "browser.navigate",
            Duration::from_millis(1_500),
        )?;

        let busy = DirectCdpManagerLease::acquire(
            Arc::clone(&manager),
            &endpoint,
            "browser.screenshot",
            Duration::from_millis(1_500),
        )
        .unwrap_err();
        assert!(format!("{busy}").contains("already owns operation browser.navigate"));

        lease.finish(&[1, 2, 3], "success", "session_closed_by_scope")?;
        let mut replacement_lease = DirectCdpManagerLease::acquire(
            Arc::clone(&manager),
            &replacement,
            "browser.get_cookies",
            Duration::from_secs(2),
        )?;
        replacement_lease.finish(&[4], "success", "session_closed_by_scope")?;

        let guard = manager.lock().unwrap();
        assert!(guard.active_lease.is_none());
        assert_eq!(
            guard
                .current_target
                .as_ref()
                .map(|target| target.id_hash.as_str()),
            Some(replacement.target.id_hash.as_str())
        );
        let jsonl = guard.events_jsonl();
        drop(guard);
        let artifact_dir = std::env::temp_dir().join("fcp-browser-direct-cdp-manager");
        std::fs::create_dir_all(&artifact_dir).expect("manager artifact dir should be writable");
        let artifact_path = artifact_dir.join("logs.jsonl");
        std::fs::write(&artifact_path, &jsonl).expect("manager JSONL artifact should be writable");
        assert!(artifact_path.ends_with("logs.jsonl"));
        assert!(
            jsonl.contains("\"command_line\":\"fcp-browser direct-cdp target-session-manager\"")
        );
        assert!(jsonl.contains("\"git_revision\""));
        assert!(jsonl.contains("\"run_id\""));
        assert!(jsonl.contains("\"event_kind\":\"target_attach\""));
        assert!(jsonl.contains("\"event_kind\":\"stale_target_recovery\""));
        assert!(jsonl.contains("\"event_kind\":\"operation_complete\""));
        assert!(jsonl.contains("\"manager_id_hash\""));
        assert!(jsonl.contains("\"cdp_command_ids\":[1,2,3]"));
        assert!(jsonl.contains("\"timeout_budget_ms\":1500"));
        assert!(!jsonl.contains("page-alpha"));
        assert!(!jsonl.contains("page-beta"));
        assert!(!jsonl.contains("ws://127.0.0.1:9222/devtools/page/page"));
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_direct_cdp_manager_continues_across_reconfigured_client() -> BrowserResult<()> {
        let original =
            BrowserClient::new(None)?.with_browser_url("ws://127.0.0.1:9/devtools/page/page-alpha");
        assert!(original.health_check().await.is_err());

        let reconfigured = BrowserClient::new(None)?
            .with_browser_url("ws://127.0.0.1:9/devtools/page/page-beta")
            .continue_direct_cdp_manager_from(Some(&original));
        assert!(reconfigured.health_check().await.is_err());

        let jsonl = reconfigured.direct_cdp_manager_events_jsonl()?;
        assert!(jsonl.contains("\"event_kind\":\"stale_target_recovery\""));
        assert!(jsonl.contains("\"operation_id\":\"browser.health_check\""));
        assert!(jsonl.contains(
            "\"current_tab_decision\":\"stale_target_recovered_and_current_tab_updated\""
        ));
        assert!(!jsonl.contains("page-alpha"));
        assert!(!jsonl.contains("page-beta"));
        Ok(())
    }

    #[test]
    fn test_direct_cdp_manager_cookie_session_lease_metadata_is_redacted() -> BrowserResult<()> {
        let endpoint = browser_control_endpoint_for_url(
            "ws://localhost:9222/devtools/page/session-target-secret",
        )?;
        let BrowserControlEndpoint::DirectCdp(endpoint) = endpoint else {
            return Err(BrowserError::InvalidConfig(
                "expected direct CDP endpoint".into(),
            ));
        };
        let mut manager = DirectCdpTargetSessionManager::default();
        let object_hash = manager.record_session_object(
            &endpoint,
            "browser.session.save",
            "/Users/example/private/profile/session-object-secret",
            42,
            Some("private.example.test"),
        )?;

        assert_eq!(object_hash.len(), 16);
        let jsonl = manager.events_jsonl();
        assert!(jsonl.contains("\"event_kind\":\"session_object_recorded\""));
        assert!(jsonl.contains("\"current_tab_decision\":\"cookie_state_owned_by_manager\""));
        assert!(jsonl.contains("\"session_object_id_hash\":\"blake3:"));
        assert!(!jsonl.contains("session-object-secret"));
        assert!(!jsonl.contains("/Users/example"));
        assert!(!jsonl.contains("private.example.test"));
        assert!(!jsonl.contains("session-target-secret"));
        Ok(())
    }

    #[test]
    fn test_direct_cdp_client_records_session_object_leases_only_in_direct_mode()
    -> BrowserResult<()> {
        let client = BrowserClient::new(None)?
            .with_browser_url("ws://localhost:9222/devtools/page/session-client-target-secret");
        let object_hash = client
            .record_direct_cdp_session_object(
                "browser.session.restore",
                "state-object-secret-123",
                77,
                Some("private.example.test"),
            )?
            .ok_or_else(|| {
                BrowserError::InvalidConfig("expected direct CDP session object record".into())
            })?;

        assert_eq!(object_hash.len(), 16);
        let jsonl = client.direct_cdp_manager_events_jsonl()?;
        assert!(jsonl.contains("\"event_kind\":\"session_object_recorded\""));
        assert!(jsonl.contains("\"operation_id\":\"browser.session.restore\""));
        assert!(jsonl.contains("\"session_lease_seq\":77"));
        assert!(!jsonl.contains("state-object-secret-123"));
        assert!(!jsonl.contains("private.example.test"));
        assert!(!jsonl.contains("session-client-target-secret"));

        let worker_client = BrowserClient::new(None)?.with_browser_url("http://localhost:9222");
        assert_eq!(
            worker_client.record_direct_cdp_session_object(
                "browser.session.save",
                "state-object-secret-456",
                78,
                Some("worker.example.test"),
            )?,
            None
        );
        assert_eq!(worker_client.direct_cdp_manager_events_jsonl()?, "");
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_direct_cdp_session_cookie_helpers_use_session_operation_ids() -> BrowserResult<()>
    {
        let client = BrowserClient::new(None)?
            .with_browser_url("ws://127.0.0.1:9/devtools/page/session-operation-target-secret");

        let save_error = client
            .session_save_cookies(Some("private.example.test"))
            .await
            .unwrap_err();
        assert!(!format!("{save_error}").contains("private.example.test"));

        let restore_error = client
            .session_restore_cookies(&[Cookie {
                name: "session".into(),
                value: "secret-cookie-value".into(),
                domain: Some("private.example.test".into()),
                path: Some("/".into()),
                expires: None,
                http_only: Some(true),
                secure: Some(true),
                same_site: Some("Lax".into()),
            }])
            .await
            .unwrap_err();
        assert!(!format!("{restore_error}").contains("secret-cookie-value"));

        let jsonl = client.direct_cdp_manager_events_jsonl()?;
        assert!(jsonl.contains("\"operation_id\":\"browser.session.save\""));
        assert!(jsonl.contains("\"operation_id\":\"browser.session.restore\""));
        assert!(jsonl.contains("\"event_kind\":\"operation_failed\""));
        assert!(jsonl.contains("\"cleanup_result\":\"connect_failed_cleanup\""));
        assert!(!jsonl.contains("\"operation_id\":\"browser.get_cookies\""));
        assert!(!jsonl.contains("\"operation_id\":\"browser.set_cookies\""));
        assert!(!jsonl.contains("session-operation-target-secret"));
        assert!(!jsonl.contains("private.example.test"));
        assert!(!jsonl.contains("secret-cookie-value"));
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_direct_cdp_all_client_operations_acquire_manager_lease_before_network()
    -> BrowserResult<()> {
        let client = BrowserClient::new(None)?
            .with_browser_url("ws://127.0.0.1:9/devtools/page/all-operation-target-secret");
        let cookies = [Cookie {
            name: "session".into(),
            value: "secret-cookie-value".into(),
            domain: Some("private.example.test".into()),
            path: Some("/".into()),
            expires: None,
            http_only: Some(true),
            secure: Some(true),
            same_site: Some("Lax".into()),
        }];

        assert!(client.health_check().await.is_err());
        assert!(
            client
                .navigate("https://private.example.test/secret", None, Some(1), None)
                .await
                .is_err()
        );
        assert!(client.screenshot(None, None, None, None).await.is_err());
        assert!(client.render_pdf(None, None, None).await.is_err());
        assert!(client.extract_text(None, None).await.is_err());
        assert!(client.extract_links(None).await.is_err());
        assert!(
            client
                .wait_for_selector("#ready", Some("visible"), Some(1))
                .await
                .is_err()
        );
        assert!(client.click("#submit", Some(1)).await.is_err());
        assert!(
            client
                .fill_form(
                    &serde_json::json!({ "#email": "private@example.test" }),
                    None
                )
                .await
                .is_err()
        );
        assert!(client.evaluate_js("document.title").await.is_err());
        assert!(
            client
                .get_cookies(Some("private.example.test"))
                .await
                .is_err()
        );
        assert!(client.set_cookies(&cookies).await.is_err());
        assert!(
            client
                .session_save_cookies(Some("private.example.test"))
                .await
                .is_err()
        );
        assert!(client.session_restore_cookies(&cookies).await.is_err());

        let jsonl = client.direct_cdp_manager_events_jsonl()?;
        let operation_begins = jsonl
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .filter(|event| event["event_kind"] == "operation_begin")
            .filter_map(|event| {
                event["operation_id"]
                    .as_str()
                    .map(std::string::ToString::to_string)
            })
            .collect::<BTreeSet<_>>();

        for operation in [
            "browser.health_check",
            "browser.navigate",
            "browser.screenshot",
            "browser.render_pdf",
            "browser.extract_text",
            "browser.extract_links",
            "browser.wait_for_selector",
            "browser.click",
            "browser.fill_form",
            "browser.evaluate_js",
            "browser.get_cookies",
            "browser.set_cookies",
            "browser.session.save",
            "browser.session.restore",
        ] {
            assert!(
                operation_begins.contains(operation),
                "missing manager operation_begin for {operation}: {operation_begins:?}"
            );
        }
        assert!(!jsonl.contains("\"operation_id\":\"browser.set_proxy\""));
        assert!(!jsonl.contains("\"operation_id\":\"browser.clear_proxy\""));
        assert!(!jsonl.contains("all-operation-target-secret"));
        assert!(!jsonl.contains("private.example.test"));
        assert!(!jsonl.contains("private@example.test"));
        assert!(!jsonl.contains("secret-cookie-value"));
        Ok(())
    }

    #[test]
    fn test_direct_cdp_manager_shutdown_releases_active_lease_without_orphan() -> BrowserResult<()>
    {
        let endpoint =
            browser_control_endpoint_for_url("ws://127.0.0.1:9222/devtools/page/page-shutdown")?;
        let BrowserControlEndpoint::DirectCdp(endpoint) = endpoint else {
            return Err(BrowserError::InvalidConfig(
                "expected direct CDP endpoint".into(),
            ));
        };
        let manager = Arc::new(Mutex::new(DirectCdpTargetSessionManager::default()));
        let lease = DirectCdpManagerLease::acquire(
            Arc::clone(&manager),
            &endpoint,
            "browser.evaluate_js",
            Duration::from_millis(500),
        )?;
        drop(lease);
        {
            let mut guard = manager.lock().unwrap();
            assert!(guard.active_lease.is_none());
            let session_hash = guard.record_session_object(
                &endpoint,
                "browser.session.save",
                "shutdown-state-object-secret",
                7,
                Some("private.example.test"),
            )?;
            assert!(guard.session_objects.contains_key(&session_hash));
            guard.shutdown();
            assert!(guard.current_target.is_none());
            assert!(guard.session_objects.is_empty());
            drop(guard);
        }
        let rejected = DirectCdpManagerLease::acquire(
            Arc::clone(&manager),
            &endpoint,
            "browser.evaluate_js",
            Duration::from_millis(500),
        )
        .unwrap_err();
        assert!(format!("{rejected}").contains("manager is shut down"));

        let jsonl = manager.lock().unwrap().events_jsonl();
        assert!(jsonl.contains("\"cleanup_result\":\"lease_dropped_cleanup\""));
        assert!(jsonl.contains("\"cleanup_result\":\"targets_and_sessions_cleared_no_orphan\""));
        assert!(jsonl.contains("\"cancellation_checkpoint\":\"shutdown_signal_observed\""));
        assert!(!jsonl.contains("shutdown-state-object-secret"));
        assert!(!jsonl.contains("private.example.test"));
        assert!(!jsonl.contains("page-shutdown"));
        Ok(())
    }

    #[test]
    fn test_direct_cdp_manager_artifact_contains_closeout_evidence() -> BrowserResult<()> {
        let endpoint =
            browser_control_endpoint_for_url("ws://127.0.0.1:9222/devtools/page/page-alpha")?;
        let BrowserControlEndpoint::DirectCdp(endpoint) = endpoint else {
            return Err(BrowserError::InvalidConfig(
                "expected direct CDP endpoint".into(),
            ));
        };
        let replacement =
            browser_control_endpoint_for_url("ws://127.0.0.1:9222/devtools/page/page-beta")?;
        let BrowserControlEndpoint::DirectCdp(replacement) = replacement else {
            return Err(BrowserError::InvalidConfig(
                "expected direct CDP endpoint".into(),
            ));
        };
        let manager = Arc::new(Mutex::new(DirectCdpTargetSessionManager::default()));

        let mut navigate = DirectCdpManagerLease::acquire(
            Arc::clone(&manager),
            &endpoint,
            "browser.navigate",
            Duration::from_secs(60),
        )?;
        navigate.finish(&[1, 2, 3, 4, 5], "success", "session_closed_by_scope")?;

        {
            let mut guard = manager.lock().unwrap();
            guard.record_session_object(
                &endpoint,
                "browser.session.save",
                "session-object-secret-save",
                10,
                Some("private.example.test"),
            )?;
            guard.record_session_object(
                &endpoint,
                "browser.session.restore",
                "session-object-secret-restore",
                11,
                Some("private.example.test"),
            )?;
            guard.record_session_object(
                &endpoint,
                "browser.session.describe",
                "session-object-secret-describe",
                11,
                Some("private.example.test"),
            )?;
        }

        let mut screenshot = DirectCdpManagerLease::acquire(
            Arc::clone(&manager),
            &replacement,
            "browser.screenshot",
            Duration::from_secs(60),
        )?;
        screenshot.finish(&[6, 7], "success", "session_closed_by_scope")?;

        let operation_matrix: [(&str, &[u64]); 7] = [
            ("browser.render_pdf", &[8, 9]),
            ("browser.extract_text", &[10]),
            ("browser.extract_links", &[11]),
            ("browser.wait_for_selector", &[12, 13]),
            ("browser.fill_form", &[14, 15, 16]),
            ("browser.get_cookies", &[17]),
            ("browser.set_cookies", &[18]),
        ];
        for (operation_id, cdp_command_ids) in operation_matrix {
            let mut lease = DirectCdpManagerLease::acquire(
                Arc::clone(&manager),
                &replacement,
                operation_id,
                Duration::from_secs(30),
            )?;
            lease.finish(cdp_command_ids, "success", "session_closed_by_scope")?;
        }

        let dropped = DirectCdpManagerLease::acquire(
            Arc::clone(&manager),
            &replacement,
            "browser.click",
            Duration::from_secs(30),
        )?;
        drop(dropped);

        let active_at_shutdown = DirectCdpManagerLease::acquire(
            Arc::clone(&manager),
            &replacement,
            "browser.evaluate_js",
            Duration::from_secs(30),
        )?;
        manager.lock().unwrap().shutdown();
        drop(active_at_shutdown);

        let jsonl = manager.lock().unwrap().events_jsonl();
        let event_kinds = jsonl
            .lines()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line)
                    .expect("manager JSONL event should parse")
                    .get("event_kind")
                    .and_then(serde_json::Value::as_str)
                    .expect("manager event_kind should be present")
                    .to_string()
            })
            .collect::<Vec<_>>();
        for expected in [
            "manager_start",
            "target_attach",
            "operation_begin",
            "operation_complete",
            "session_object_recorded",
            "stale_target_recovery",
            "operation_failed",
            "target_detach",
            "manager_shutdown",
        ] {
            assert!(
                event_kinds.iter().any(|kind| kind == expected),
                "missing direct-CDP manager event kind {expected}: {event_kinds:?}"
            );
        }
        assert!(jsonl.contains("\"operation_id\":\"browser.navigate\""));
        assert!(jsonl.contains("\"operation_id\":\"browser.screenshot\""));
        assert!(jsonl.contains("\"operation_id\":\"browser.render_pdf\""));
        assert!(jsonl.contains("\"operation_id\":\"browser.extract_text\""));
        assert!(jsonl.contains("\"operation_id\":\"browser.extract_links\""));
        assert!(jsonl.contains("\"operation_id\":\"browser.wait_for_selector\""));
        assert!(jsonl.contains("\"operation_id\":\"browser.fill_form\""));
        assert!(jsonl.contains("\"operation_id\":\"browser.click\""));
        assert!(jsonl.contains("\"operation_id\":\"browser.evaluate_js\""));
        assert!(jsonl.contains("\"operation_id\":\"browser.get_cookies\""));
        assert!(jsonl.contains("\"operation_id\":\"browser.set_cookies\""));
        assert!(jsonl.contains("\"operation_id\":\"browser.session.save\""));
        assert!(jsonl.contains("\"operation_id\":\"browser.session.restore\""));
        assert!(jsonl.contains("\"operation_id\":\"browser.session.describe\""));
        assert!(jsonl.contains("\"cdp_command_ids\":[1,2,3,4,5]"));
        assert!(jsonl.contains("\"cdp_command_ids\":[6,7]"));
        assert!(jsonl.contains("\"cdp_command_ids\":[14,15,16]"));
        assert!(jsonl.contains("\"cleanup_result\":\"lease_dropped_cleanup\""));
        assert!(jsonl.contains(
            "\"cleanup_result\":\"active_lease_released_targets_and_sessions_cleared_no_orphan\""
        ));
        assert!(!jsonl.contains("page-alpha"));
        assert!(!jsonl.contains("page-beta"));
        assert!(!jsonl.contains("session-object-secret"));
        assert!(!jsonl.contains("private.example.test"));

        for line in jsonl.lines() {
            println!("BROWSER_TARGET_SESSION_MANAGER_JSONL {line}");
        }
        println!(
            "BROWSER_TARGET_SESSION_MANAGER_SUMMARY {}",
            serde_json::json!({
                "schema_version": "fcp-browser-target-session-manager-evidence.v1",
                "manager_event_count": event_kinds.len(),
                "event_kinds": event_kinds,
                "operations_exercised": [
                    "browser.navigate",
                    "browser.screenshot",
                    "browser.render_pdf",
                    "browser.extract_text",
                    "browser.extract_links",
                    "browser.wait_for_selector",
                    "browser.click",
                    "browser.fill_form",
                    "browser.evaluate_js",
                    "browser.get_cookies",
                    "browser.set_cookies",
                    "browser.session.save",
                    "browser.session.restore",
                    "browser.session.describe",
                    "browser.shutdown"
                ],
                "redaction": {
                    "raw_target_ids": false,
                    "raw_session_object_ids": false,
                    "raw_cookie_scope": false
                }
            })
        );
        Ok(())
    }

    #[fcp_async_core::runtime::test]
    async fn test_direct_cdp_proxy_operations_fail_closed_before_network() {
        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url("ws://127.0.0.1:9222/devtools/page/page-1");
        let proxy = ProxyConfig {
            server: "http://proxy.example.test:8080".to_string(),
            bypass_list: None,
            username: None,
            password: None,
        };

        let set_error = client.set_proxy(&proxy).await.unwrap_err();
        let clear_error = client.clear_proxy().await.unwrap_err();

        let set_error = format!("{set_error}");
        let clear_error = format!("{clear_error}");
        assert!(set_error.contains("reason_code=proxy_unavailable_direct_cdp"));
        assert!(clear_error.contains("reason_code=proxy_unavailable_direct_cdp"));
        assert!(set_error.contains("remediation=configure a proxy-capable"));
        assert!(clear_error.contains("remediation=configure a proxy-capable"));
    }

    #[test]
    fn test_rust_owned_launcher_binary_policy_accepts_safe_paths_and_discovery() {
        let configured = BrowserLauncherConfig::native(
            Some("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome".into()),
            RUST_LAUNCHER_DEFAULT_READINESS_TIMEOUT_MS,
        )
        .expect("absolute configured browser path should be policy-safe");
        assert_eq!(configured.mode(), BrowserLauncherMode::Native);

        let discovery =
            BrowserLauncherConfig::native(None, RUST_LAUNCHER_DEFAULT_READINESS_TIMEOUT_MS)
                .expect("documented platform discovery should be policy-safe");
        assert!(discovery.browser_binary_path().is_none());
    }

    #[test]
    fn test_rust_owned_launcher_binary_policy_rejects_injection() {
        for path in [
            "relative/chrome",
            "/Applications/Chrome.app/Contents/MacOS/Chrome;rm",
            "/Applications/Chrome.app/Contents/MacOS/Chrome\nInjected",
        ] {
            let error = BrowserLauncherConfig::native(
                Some(path.into()),
                RUST_LAUNCHER_DEFAULT_READINESS_TIMEOUT_MS,
            )
            .unwrap_err();
            let error = format!("{error}");
            assert!(
                error.contains("launcher_invalid_binary_path")
                    || error.contains("launcher_argument_injection"),
                "{path:?} should fail binary policy, got {error}"
            );
        }
    }

    #[test]
    fn test_rust_owned_launcher_args_are_bounded_ordered_and_redaction_safe() {
        let proxy = ProxyConfig {
            server: "http://proxy.example.com:8080".into(),
            bypass_list: Some(vec!["localhost".into(), "127.0.0.1".into()]),
            username: Some("proxy-user".into()),
            password: Some("proxy-password".into()),
        };

        let args = build_rust_owned_launcher_args(Some(&proxy)).unwrap();

        assert_eq!(args[0], "--headless=new");
        assert!(args.iter().any(|arg| arg == "--remote-debugging-port=0"));
        assert!(
            args.iter()
                .any(|arg| arg == "--proxy-server=http://proxy.example.com:8080")
        );
        assert!(
            args.iter()
                .any(|arg| arg == "--proxy-bypass-list=localhost,127.0.0.1")
        );
        assert!(!args.iter().any(|arg| arg.contains("proxy-password")));

        let rejected = deduplicate_and_validate_launcher_args(vec![
            "--headless=new".into(),
            "--headless=new".into(),
            "--proxy-server=http://proxy.example.com:8080;touch".into(),
        ])
        .unwrap_err();
        assert!(format!("{rejected}").contains("launcher_argument_injection"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rust_owned_launcher_fixture_set_clear_shutdown_jsonl() {
        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url("ws://127.0.0.1:9222/devtools/page/page-1")
            .with_rust_owned_launcher(BrowserLauncherConfig::fixture(
                RUST_LAUNCHER_DEFAULT_READINESS_TIMEOUT_MS,
            ))
            .unwrap();
        let proxy = ProxyConfig {
            server: "http://proxy.example.com:8080".into(),
            bypass_list: Some(vec!["localhost".into()]),
            username: Some("proxy-user".into()),
            password: Some("proxy-password".into()),
        };

        let set = client.set_proxy(&proxy).await.unwrap();
        assert!(set.enabled);
        assert_eq!(set.mode, "fixed_servers");
        let cleared = client.clear_proxy().await.unwrap();
        assert!(!cleared.enabled);
        client.shutdown();

        let jsonl = client.rust_owned_launcher_events_jsonl().unwrap();
        assert!(jsonl.contains("fcp-browser-rust-owned-launcher-evidence.v1"));
        assert!(jsonl.contains("\"operation_id\":\"browser.set_proxy\""));
        assert!(jsonl.contains("\"operation_id\":\"browser.clear_proxy\""));
        assert!(jsonl.contains("\"operation_id\":\"browser.shutdown\""));
        assert!(jsonl.contains("\"control_endpoint_kind\":\"rust_owned_launcher\""));
        assert!(jsonl.contains("\"cleanup_result\":\"launcher_shutdown_no_orphan\""));
        assert!(!jsonl.contains("proxy.example.com:8080"));
        assert!(!jsonl.contains("proxy-user"));
        assert!(!jsonl.contains("proxy-password"));
        assert!(!jsonl.contains("page-1"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rust_owned_launcher_readiness_timeout_fails_closed() {
        let client = BrowserClient::new(None)
            .unwrap()
            .with_rust_owned_launcher(BrowserLauncherConfig::fixture(0))
            .unwrap();
        let proxy = ProxyConfig {
            server: "http://proxy.example.com:8080".into(),
            bypass_list: None,
            username: None,
            password: None,
        };

        let error = client.set_proxy(&proxy).await.unwrap_err();
        assert!(format!("{error}").contains("launcher_readiness_timeout"));
        let jsonl = client.rust_owned_launcher_events_jsonl().unwrap();
        assert!(jsonl.contains("\"reason_code\":\"launcher_readiness_timeout\""));
        assert!(jsonl.contains("\"timeout_cancellation_checkpoint\":\"timeout_before_ready\""));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rust_owned_launcher_native_mode_fails_closed_when_binary_missing() {
        let client = BrowserClient::new(None)
            .unwrap()
            .with_rust_owned_launcher(
                BrowserLauncherConfig::native(
                    Some("/definitely/missing/fcp-browser-test-chrome".into()),
                    RUST_LAUNCHER_DEFAULT_READINESS_TIMEOUT_MS,
                )
                .unwrap(),
            )
            .unwrap();
        let proxy = ProxyConfig {
            server: "http://proxy.example.com:8080".into(),
            bypass_list: None,
            username: None,
            password: None,
        };

        let health_error = client.health_check().await.unwrap_err();
        assert!(format!("{health_error}").contains("launcher_browser_binary_not_found"));
        let error = client.set_proxy(&proxy).await.unwrap_err();
        assert!(format!("{error}").contains("launcher_browser_binary_not_found"));
        let jsonl = client.rust_owned_launcher_events_jsonl().unwrap();
        assert!(jsonl.contains("\"reason_code\":\"launcher_browser_binary_not_found\""));
        assert!(jsonl.contains("\"readiness_checkpoint\":\"native_not_started\""));
    }

    #[cfg(unix)]
    #[fcp_async_core::runtime::test]
    async fn test_rust_owned_launcher_native_mode_spawns_and_cleans_up_fake_browser() {
        use std::os::unix::fs::PermissionsExt;

        let fixture_dir = std::env::temp_dir().join(format!(
            "fcp-browser-native-fixture-{}-{}",
            std::process::id(),
            rust_owned_redaction_hash("native-success")
        ));
        std::fs::create_dir_all(&fixture_dir).unwrap();
        let fake_browser = fixture_dir.join("fake-chrome");
        std::fs::write(
            &fake_browser,
            r#"#!/bin/sh
set -eu
profile_dir=""
for arg in "$@"; do
  case "$arg" in
    --user-data-dir=*) profile_dir="${arg#--user-data-dir=}" ;;
  esac
done
if [ -z "$profile_dir" ]; then
  exit 42
fi
mkdir -p "$profile_dir"
printf '9333\n/devtools/browser/fake-browser\n' > "$profile_dir/DevToolsActivePort"
trap 'exit 0' TERM INT
while :; do sleep 1; done
"#,
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&fake_browser).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&fake_browser, permissions).unwrap();

        let client = BrowserClient::new(None)
            .unwrap()
            .with_rust_owned_launcher(
                BrowserLauncherConfig::native(
                    Some(fake_browser.display().to_string()),
                    RUST_LAUNCHER_DEFAULT_READINESS_TIMEOUT_MS,
                )
                .unwrap(),
            )
            .unwrap();
        let proxy = ProxyConfig {
            server: "http://proxy.example.com:8080".into(),
            bypass_list: Some(vec!["localhost".into()]),
            username: Some("proxy-user".into()),
            password: Some("proxy-password".into()),
        };

        let set = client.set_proxy(&proxy).await.unwrap();
        assert!(set.enabled);
        let cleared = client.clear_proxy().await.unwrap();
        assert!(!cleared.enabled);
        client.shutdown();

        let jsonl = client.rust_owned_launcher_events_jsonl().unwrap();
        assert!(jsonl.contains("\"launch_mode\":\"native\""));
        assert!(jsonl.contains("\"readiness_checkpoint\":\"native_ready\""));
        assert!(jsonl.contains("\"operation_id\":\"browser.set_proxy\""));
        assert!(jsonl.contains("\"operation_id\":\"browser.clear_proxy\""));
        assert!(jsonl.contains("\"operation_id\":\"browser.shutdown\""));
        assert!(jsonl.contains("native_child_killed_and_reaped"));
        assert!(!jsonl.contains("proxy.example.com:8080"));
        assert!(!jsonl.contains("proxy-user"));
        assert!(!jsonl.contains("proxy-password"));
        assert!(!jsonl.contains("fake-browser"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rust_owned_launcher_shutdown_preempts_proxy_dispatch() {
        let client = BrowserClient::new(None)
            .unwrap()
            .with_rust_owned_launcher(BrowserLauncherConfig::fixture(
                RUST_LAUNCHER_DEFAULT_READINESS_TIMEOUT_MS,
            ))
            .unwrap();
        client.shutdown();
        let proxy = ProxyConfig {
            server: "http://proxy.example.com:8080".into(),
            bypass_list: None,
            username: None,
            password: None,
        };

        let error = client.set_proxy(&proxy).await.unwrap_err();
        assert!(format!("{error}").contains("launcher_cancelled"));
        let jsonl = client.rust_owned_launcher_events_jsonl().unwrap();
        assert!(jsonl.contains("\"timeout_cancellation_checkpoint\":\"shutdown_signal_observed\""));
    }

    #[fcp_async_core::runtime::test]
    async fn test_direct_cdp_health_rejects_invalid_endpoint_before_network() {
        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url("ws://127.0.0.1:9222/json/version");

        let error = client.health_check().await.unwrap_err();

        assert!(format!("{error}").contains("must target /devtools/page"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_check_accepts_fcp_browser_control_plane() {
        let server =
            TestControlServer::respond(health_response(browser_control_contract_descriptor()));

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&server.uri());

        client.health_check().await.unwrap();
    }

    #[test]
    fn test_health_contract_accepts_worker_without_proxy_for_non_proxy_operations() {
        let descriptor = browser_control_contract_without_proxy_operations();

        validate_fcp_browser_control_health(&descriptor).unwrap();

        let err = validate_fcp_browser_control_proxy_support(&descriptor).unwrap_err();
        assert!(err.contains("proxy_unavailable_worker_contract"));
        assert!(err.contains("browser.set_proxy"));
        assert!(err.contains("browser.clear_proxy"));
    }

    #[test]
    fn test_worker_contract_advertises_every_client_route() {
        let descriptor = browser_control_contract_descriptor();
        let operations = descriptor["operations"].as_array().unwrap();

        for required in REQUIRED_BROWSER_CONTROL_OPERATIONS {
            assert!(
                operations.iter().any(|operation| {
                    operation["id"] == required.id
                        && operation["method"] == required.method
                        && operation["path"] == required.path
                        && operation["max_response_bytes"]
                            == serde_json::json!(required.max_response_bytes)
                        && operation["timeout_ms"] == serde_json::json!(required.timeout_ms)
                        && operation["target_policy"] == required.target_policy.descriptor()
                        && operation["request_headers"] == required.request_headers_descriptor()
                }),
                "missing {} {} {}",
                required.method,
                required.path,
                required.id
            );
        }
        assert_eq!(operations.len(), REQUIRED_BROWSER_CONTROL_OPERATIONS.len());
    }

    #[test]
    fn test_worker_contract_pins_cdp_command_plan() {
        fn operation<'a>(operations: &'a [serde_json::Value], id: &str) -> &'a serde_json::Value {
            operations
                .iter()
                .find(|operation| operation["id"] == id)
                .unwrap()
        }

        let descriptor = browser_control_contract_descriptor();
        let operations = descriptor["operations"].as_array().unwrap();

        let navigate = operation(operations, "browser.navigate");
        assert_eq!(navigate["implementation"]["kind"], "cdp");
        assert_eq!(navigate["target_policy"]["scope"], "page");
        assert_eq!(
            navigate["target_policy"]["selection"],
            "create_or_reuse_active_page"
        );
        assert_eq!(navigate["target_policy"]["stale_target_recovery"], true);
        assert_eq!(navigate["target_policy"]["current_tab_guard"], false);
        assert_eq!(navigate["target_policy"]["export_guard"], false);
        assert_eq!(
            navigate["implementation"]["methods"],
            serde_json::json!([
                "Page.enable",
                "Network.enable",
                "Page.setLifecycleEventsEnabled",
                "Network.setUserAgentOverride",
                "Page.navigate"
            ])
        );

        let screenshot = operation(operations, "browser.screenshot");
        assert_eq!(screenshot["implementation"]["kind"], "cdp");
        assert_eq!(screenshot["target_policy"]["scope"], "page");
        assert_eq!(
            screenshot["target_policy"]["selection"],
            "active_page_required"
        );
        assert_eq!(screenshot["target_policy"]["stale_target_recovery"], true);
        assert_eq!(screenshot["target_policy"]["current_tab_guard"], true);
        assert_eq!(screenshot["target_policy"]["export_guard"], true);
        assert_eq!(
            screenshot["implementation"]["methods"],
            serde_json::json!([
                "DOM.getDocument",
                "DOM.querySelector",
                "DOM.getBoxModel",
                "Page.getLayoutMetrics",
                "Page.captureScreenshot"
            ])
        );

        let click = operation(operations, "browser.click");
        assert_eq!(click["implementation"]["kind"], "cdp");
        assert_eq!(click["target_policy"]["scope"], "page");
        assert_eq!(click["target_policy"]["selection"], "active_page_required");
        assert_eq!(click["target_policy"]["stale_target_recovery"], true);
        assert_eq!(click["target_policy"]["current_tab_guard"], true);
        assert_eq!(click["target_policy"]["export_guard"], false);
        assert_eq!(
            click["implementation"]["methods"],
            serde_json::json!([
                "Runtime.evaluate",
                "DOM.getDocument",
                "DOM.querySelector",
                "DOM.getBoxModel",
                "Input.dispatchMouseEvent"
            ])
        );

        let get_cookies = operation(operations, "browser.get_cookies");
        assert_eq!(get_cookies["target_policy"]["scope"], "browser_context");
        assert_eq!(
            get_cookies["target_policy"]["selection"],
            "active_context_required"
        );
        assert_eq!(
            get_cookies["implementation"]["methods"],
            serde_json::json!(["Network.getCookies"])
        );

        let set_proxy = operation(operations, "browser.set_proxy");
        assert_eq!(set_proxy["implementation"]["kind"], "worker_policy");
        assert_eq!(set_proxy["target_policy"]["scope"], "connector_policy");
        assert_eq!(set_proxy["target_policy"]["selection"], "no_browser_target");
        assert_eq!(
            set_proxy["implementation"]["methods"],
            serde_json::json!([])
        );
    }

    #[test]
    fn test_worker_contract_gives_every_worker_operation_an_execution_plan() {
        let descriptor = browser_control_contract_descriptor();
        let operations = descriptor["operations"].as_array().unwrap();

        for operation in operations {
            let id = operation["id"].as_str().unwrap();
            let implementation = &operation["implementation"];
            let kind = implementation["kind"].as_str().unwrap();
            let methods = implementation["methods"].as_array().unwrap();
            let max_response_bytes = operation["max_response_bytes"].as_u64().unwrap();
            let timeout_ms = operation["timeout_ms"].as_u64().unwrap();
            let target_policy = &operation["target_policy"];
            let request_headers = operation["request_headers"].as_array().unwrap();
            assert!(max_response_bytes > 0, "{id} must expose a response cap");
            assert!(timeout_ms > 0, "{id} must expose a timeout budget");
            assert!(
                target_policy["scope"].as_str().is_some(),
                "{id} must expose a target scope"
            );
            assert!(
                target_policy["selection"].as_str().is_some(),
                "{id} must expose a target selection policy"
            );
            assert!(
                target_policy["stale_target_recovery"].as_bool().is_some(),
                "{id} must expose stale-target recovery policy"
            );
            assert!(
                target_policy["current_tab_guard"].as_bool().is_some(),
                "{id} must expose current-tab guard policy"
            );
            assert!(
                target_policy["export_guard"].as_bool().is_some(),
                "{id} must expose export guard policy"
            );
            assert!(
                request_headers
                    .iter()
                    .any(|header| header["name"] == CONTROL_OPERATION_HEADER),
                "{id} must advertise operation metadata header"
            );
            assert!(
                request_headers
                    .iter()
                    .any(|header| header["name"] == CONTROL_TARGET_SCOPE_HEADER),
                "{id} must advertise target-scope metadata header"
            );

            assert!(
                matches!(kind, "cdp" | "worker_policy"),
                "{id} has unknown implementation kind `{kind}`"
            );
            if kind == "cdp" {
                assert!(!methods.is_empty(), "{id} must list CDP methods");
                for method in methods {
                    let method = method.as_str().unwrap();
                    assert!(
                        method.split_once('.').is_some(),
                        "{id} has invalid CDP method `{method}`"
                    );
                }
            } else {
                assert!(
                    methods.is_empty(),
                    "{id} policy operations do not issue CDP"
                );
                assert!(
                    implementation["description"].as_str().is_some(),
                    "{id} policy operation must explain worker behavior"
                );
            }
        }
    }

    #[test]
    fn test_cdp_command_serializes_to_websocket_text_message() {
        let command = CdpCommand::new(
            7,
            "Page.navigate",
            Some(serde_json::json!({ "url": "https://example.com" })),
        );

        let message = command.to_websocket_message().unwrap();
        assert!(matches!(
            message,
            WebSocketMessage::Text(text)
                if text == r#"{"id":7,"method":"Page.navigate","params":{"url":"https://example.com"}}"#
        ));
    }

    #[test]
    fn test_cdp_command_omits_empty_params() {
        let command = CdpCommand::new(8, "Page.enable", None);

        let message = command.to_websocket_message().unwrap();
        assert!(matches!(
            message,
            WebSocketMessage::Text(text) if text == r#"{"id":8,"method":"Page.enable"}"#
        ));
    }

    #[test]
    fn test_cdp_response_decoder_correlates_command_result() {
        let result = decode_cdp_response_message(
            WebSocketMessage::Text(r#"{"id":7,"result":{"frameId":"abc"}}"#.into()),
            7,
        )
        .unwrap();

        assert_eq!(result, Some(serde_json::json!({ "frameId": "abc" })));
    }

    #[test]
    fn test_cdp_response_decoder_ignores_events_and_other_command_ids() {
        let event = decode_cdp_response_message(
            WebSocketMessage::Text(
                r#"{"method":"Page.loadEventFired","params":{"timestamp":1}}"#.into(),
            ),
            7,
        )
        .unwrap();
        let other_command = decode_cdp_response_message(
            WebSocketMessage::Text(r#"{"id":9,"result":{"ok":true}}"#.into()),
            7,
        )
        .unwrap();

        assert_eq!(event, None);
        assert_eq!(other_command, None);
    }

    #[test]
    fn test_cdp_event_decoder_extracts_methods_and_ignores_command_responses() {
        let event = decode_cdp_event_message(WebSocketMessage::Text(
            r#"{"method":"Page.lifecycleEvent","params":{"name":"networkIdle"}}"#.into(),
        ))
        .unwrap();
        let command_response =
            decode_cdp_event_message(WebSocketMessage::Text(r#"{"id":7,"result":{}}"#.into()))
                .unwrap();

        assert_eq!(
            event,
            Some(CdpEvent {
                method: "Page.lifecycleEvent".to_string(),
                params: serde_json::json!({ "name": "networkIdle" }),
            })
        );
        assert_eq!(command_response, None);
    }

    #[test]
    fn test_cdp_navigation_wait_rejects_unsupported_wait_until() {
        let error = CdpNavigationWait::from_wait_until(Some("commit")).unwrap_err();

        assert!(format!("{error}").contains("wait_until"));
    }

    #[test]
    fn test_cdp_response_decoder_redacts_error_payloads() {
        let err = decode_cdp_response_message(
            WebSocketMessage::Text(
                serde_json::json!({
                    "id": 7,
                    "error": {
                        "code": -32000,
                        "message": "Authorization failed for Bearer browser-token",
                        "data": {
                            "access_token": "secret-token",
                            "cookies": [{ "name": "session", "value": "secret-cookie" }]
                        }
                    }
                })
                .to_string(),
            ),
            7,
        )
        .unwrap_err();

        let message = format!("{err}");
        assert!(!message.contains("browser-token"));
        assert!(!message.contains("secret-token"));
        assert!(!message.contains("secret-cookie"));
        assert!(message.contains("[redacted]"));
    }

    #[test]
    fn test_cdp_response_decoder_rejects_non_text_messages() {
        let err =
            decode_cdp_response_message(WebSocketMessage::binary(vec![1_u8, 2, 3]), 7).unwrap_err();

        assert!(format!("{err}").contains("UTF-8 text JSON"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_execute_cdp_command_sends_request_and_waits_for_matching_response() {
        let cx = fcp_async_core::compatibility_cx();
        let mut transport = ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(
                r#"{"method":"Page.frameStartedLoading","params":{"frameId":"abc"}}"#.into(),
            ),
            WebSocketMessage::Text(r#"{"id":99,"result":{"ignored":true}}"#.into()),
            WebSocketMessage::Text(r#"{"id":7,"result":{"frameId":"abc"}}"#.into()),
        ]);

        let result = execute_cdp_command(
            &cx,
            &mut transport,
            CdpCommand::new(
                7,
                "Page.navigate",
                Some(serde_json::json!({ "url": "https://example.com" })),
            ),
        )
        .await
        .unwrap();

        assert_eq!(result, serde_json::json!({ "frameId": "abc" }));
        assert_eq!(transport.sent.len(), 1);
        assert!(matches!(
            &transport.sent[0],
            WebSocketMessage::Text(text)
                if text == r#"{"id":7,"method":"Page.navigate","params":{"url":"https://example.com"}}"#
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_execute_cdp_command_reports_close_before_matching_response() {
        let cx = fcp_async_core::compatibility_cx();
        let mut transport = ScriptedCdpTransport::with_received([WebSocketMessage::Text(
            r#"{"method":"Page.frameStartedLoading"}"#.into(),
        )]);

        let err = execute_cdp_command(
            &cx,
            &mut transport,
            CdpCommand::new(7, "Page.navigate", None),
        )
        .await
        .unwrap_err();

        let message = format!("{err}");
        assert!(message.contains("closed before command 7 response"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_execute_cdp_command_checks_cancellation_before_send() {
        let cx = fcp_async_core::compatibility_cx();
        cx.set_cancel_requested(true);
        let mut transport = ScriptedCdpTransport::default();

        let err = execute_cdp_command(
            &cx,
            &mut transport,
            CdpCommand::new(7, "Page.navigate", None),
        )
        .await
        .unwrap_err();

        let message = format!("{err}");
        assert!(message.contains("cancelled before send"));
        assert!(transport.sent.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_allocates_monotonic_command_ids() {
        let cx = fcp_async_core::compatibility_cx();
        let mut session = CdpSession::new(ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(r#"{"id":1,"result":{"enabled":true}}"#.into()),
            WebSocketMessage::Text(r#"{"id":2,"result":{"frameId":"abc"}}"#.into()),
        ]));

        let page_enable = session.call_method(&cx, "Page.enable", None).await.unwrap();
        let navigate = session
            .call_method(
                &cx,
                "Page.navigate",
                Some(serde_json::json!({ "url": "https://example.com" })),
            )
            .await
            .unwrap();
        let transport = session.into_transport();

        assert_eq!(page_enable, serde_json::json!({ "enabled": true }));
        assert_eq!(navigate, serde_json::json!({ "frameId": "abc" }));
        assert_eq!(transport.sent.len(), 2);
        assert!(matches!(
            &transport.sent[0],
            WebSocketMessage::Text(text) if text == r#"{"id":1,"method":"Page.enable"}"#
        ));
        assert!(matches!(
            &transport.sent[1],
            WebSocketMessage::Text(text)
                if text == r#"{"id":2,"method":"Page.navigate","params":{"url":"https://example.com"}}"#
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_navigate_page_issues_documented_cdp_sequence() {
        let cx = fcp_async_core::compatibility_cx();
        let mut session = CdpSession::new(ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(r#"{"id":1,"result":{}}"#.into()),
            WebSocketMessage::Text(r#"{"id":2,"result":{}}"#.into()),
            WebSocketMessage::Text(r#"{"id":3,"result":{}}"#.into()),
            WebSocketMessage::Text(r#"{"id":4,"result":{}}"#.into()),
            WebSocketMessage::Text(
                r#"{"id":5,"result":{"frameId":"frame-1","loaderId":"loader-1"}}"#.into(),
            ),
        ]));

        let response = session
            .navigate_page(&cx, "https://example.com", Some("FCP Browser/1.0"))
            .await
            .unwrap();
        let transport = session.into_transport();

        assert_eq!(
            response,
            CdpNavigateResponse {
                frame_id: "frame-1".to_string(),
                loader_id: Some("loader-1".to_string()),
            }
        );
        assert_eq!(transport.sent.len(), 5);
        assert!(matches!(
            &transport.sent[0],
            WebSocketMessage::Text(text) if text == r#"{"id":1,"method":"Page.enable"}"#
        ));
        assert!(matches!(
            &transport.sent[1],
            WebSocketMessage::Text(text) if text == r#"{"id":2,"method":"Network.enable"}"#
        ));
        assert!(matches!(
            &transport.sent[2],
            WebSocketMessage::Text(text)
                if text == r#"{"id":3,"method":"Page.setLifecycleEventsEnabled","params":{"enabled":true}}"#
        ));
        assert!(matches!(
            &transport.sent[3],
            WebSocketMessage::Text(text)
                if text == r#"{"id":4,"method":"Network.setUserAgentOverride","params":{"userAgent":"FCP Browser/1.0"}}"#
        ));
        assert!(matches!(
            &transport.sent[4],
            WebSocketMessage::Text(text)
                if text == r#"{"id":5,"method":"Page.navigate","params":{"url":"https://example.com"}}"#
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_wait_for_navigation_ignores_global_load_for_loader_bound_navigation()
    {
        let cx = fcp_async_core::compatibility_cx();
        let navigation = CdpNavigateResponse {
            frame_id: "frame-1".to_string(),
            loader_id: Some("loader-1".to_string()),
        };
        let mut session = CdpSession::new(ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(
                r#"{"method":"Page.loadEventFired","params":{"timestamp":1}}"#.into(),
            ),
            WebSocketMessage::Text(
                serde_json::json!({
                    "method": "Network.requestWillBeSent",
                    "params": {
                        "frameId": "frame-1",
                        "loaderId": "loader-1",
                        "type": "Document",
                        "request": { "url": "https://example.com" }
                    }
                })
                .to_string(),
            ),
            WebSocketMessage::Text(
                serde_json::json!({
                    "method": "Page.lifecycleEvent",
                    "params": {
                        "frameId": "frame-1",
                        "loaderId": "loader-1",
                        "name": "load"
                    }
                })
                .to_string(),
            ),
        ]));

        let completion = session
            .wait_for_navigation(&cx, &navigation, Some("load"), true, "https://example.com")
            .await
            .unwrap();
        let transport = session.into_transport();

        assert_eq!(
            completion,
            CdpNavigationCompletion {
                status: None,
                loader_id: Some("loader-1".to_string())
            }
        );
        assert!(transport.sent.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_wait_for_navigation_ignores_global_load_without_loader_id() {
        let cx = fcp_async_core::compatibility_cx();
        let navigation = CdpNavigateResponse {
            frame_id: "frame-1".to_string(),
            loader_id: None,
        };
        let mut session = CdpSession::new(ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(
                r#"{"method":"Page.loadEventFired","params":{"timestamp":1}}"#.into(),
            ),
            WebSocketMessage::Text(
                serde_json::json!({
                    "method": "Network.responseReceived",
                    "params": {
                        "frameId": "frame-1",
                        "loaderId": "stale-loader",
                        "type": "Document",
                        "response": {
                            "status": 200,
                            "url": "https://stale.example/"
                        }
                    }
                })
                .to_string(),
            ),
            WebSocketMessage::Text(
                serde_json::json!({
                    "method": "Page.lifecycleEvent",
                    "params": {
                        "frameId": "frame-1",
                        "loaderId": "stale-loader",
                        "name": "load"
                    }
                })
                .to_string(),
            ),
            WebSocketMessage::Text(
                serde_json::json!({
                    "method": "Network.responseReceived",
                    "params": {
                        "frameId": "frame-1",
                        "loaderId": "loader-2",
                        "type": "Document",
                        "response": {
                            "status": 202,
                            "url": "https://example.com"
                        }
                    }
                })
                .to_string(),
            ),
            WebSocketMessage::Text(
                serde_json::json!({
                    "method": "Page.lifecycleEvent",
                    "params": {
                        "frameId": "frame-1",
                        "loaderId": "loader-2",
                        "name": "load"
                    }
                })
                .to_string(),
            ),
        ]));

        let completion = session
            .wait_for_navigation(&cx, &navigation, Some("load"), true, "https://example.com")
            .await
            .unwrap();
        let transport = session.into_transport();

        assert_eq!(
            completion,
            CdpNavigationCompletion {
                status: Some(202),
                loader_id: Some("loader-2".to_string())
            }
        );
        assert!(transport.sent.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_wait_for_location_accepts_ready_expected_url() {
        let cx = fcp_async_core::compatibility_cx();
        let expected_url = "http://127.0.0.1:9999/readable-fixture";
        let mut session = CdpSession::new(ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(
                serde_json::json!({
                    "id": 1,
                    "result": {
                        "result": {
                            "type": "object",
                            "value": {
                                "href": expected_url,
                                "ready_state": "complete",
                                "matched": true
                            }
                        }
                    }
                })
                .to_string(),
            ),
        ]));

        let href = session
            .wait_for_location(&cx, expected_url, Some("load"), Some(1_000), false, None)
            .await
            .unwrap();
        let transport = session.into_transport();

        assert_eq!(href, expected_url);
        assert_eq!(transport.sent.len(), 1);
        assert!(matches!(
            &transport.sent[0],
            WebSocketMessage::Text(text) if text.contains("\"method\":\"Runtime.evaluate\"")
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_wait_for_location_rejects_stale_url() {
        let cx = fcp_async_core::compatibility_cx();
        let expected_url = "http://127.0.0.1:9999/readable-fixture";
        let mut session = CdpSession::new(ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(
                serde_json::json!({
                    "id": 1,
                    "result": {
                        "result": {
                            "type": "object",
                            "value": {
                                "href": "http://127.0.0.1:9999/",
                                "ready_state": "complete",
                                "matched": false
                            }
                        }
                    }
                })
                .to_string(),
            ),
        ]));

        let error = session
            .wait_for_location(&cx, expected_url, Some("load"), Some(0), false, None)
            .await
            .unwrap_err();
        let message = format!("{error}");

        assert!(message.contains("did not reach expected active document"));
        assert!(message.contains("readable-fixture"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_wait_for_location_rejects_stale_document_for_loader_navigation() {
        let cx = fcp_async_core::compatibility_cx();
        let expected_url = "http://127.0.0.1:9999/readable-fixture";
        let mut session = CdpSession::new(ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(
                serde_json::json!({
                    "id": 1,
                    "result": {
                        "result": {
                            "type": "object",
                            "value": {
                                "href": expected_url,
                                "ready_state": "complete",
                                "navigation_entry_name": expected_url,
                                "time_origin": 42.0,
                                "matched": false
                            }
                        }
                    }
                })
                .to_string(),
            ),
        ]));

        let error = session
            .wait_for_location(&cx, expected_url, Some("load"), Some(0), true, Some(42.0))
            .await
            .unwrap_err();
        let message = format!("{error}");

        assert!(message.contains("did not reach expected active document"));
        assert!(message.contains("readable-fixture"));
        assert!(message.contains("navigation entry"));
    }

    #[test]
    fn cdp_wait_for_location_expression_tolerates_redirects_for_new_documents() {
        let expression = cdp_wait_for_location_expression(
            "http://127.0.0.1:9999/start",
            Some("load"),
            true,
            Some(42.0),
        )
        .unwrap();

        // New documents are identified by the time-origin change so that
        // server-side redirects (final URL != requested URL) still complete;
        // same-document navigations keep exact URL matching.
        assert!(expression.contains("requireNewDocument\n    ? timeOriginChanged()"));
        assert!(expression.contains(": window.location.href === expectedUrl"));
        assert!(!expression.contains("navigationEntryName() === expectedUrl"));
        assert!(expression.contains("const matched = isExpectedDocument() && isDocumentReady();"));
    }

    #[test]
    fn test_cdp_requires_new_document_for_path_and_query_changes() {
        assert!(cdp_requires_new_document_for_navigation(
            Some("http://127.0.0.1:9999/"),
            "http://127.0.0.1:9999/readable-fixture"
        ));
        assert!(cdp_requires_new_document_for_navigation(
            Some("http://127.0.0.1:9999/?page=1"),
            "http://127.0.0.1:9999/?page=2"
        ));
        assert!(cdp_requires_new_document_for_navigation(
            Some("http://127.0.0.1:9999/readable-fixture"),
            "http://127.0.0.1:9999/readable-fixture"
        ));
    }

    #[test]
    fn test_cdp_requires_new_document_allows_fragment_only_navigation() {
        assert!(!cdp_requires_new_document_for_navigation(
            Some("http://127.0.0.1:9999/page#top"),
            "http://127.0.0.1:9999/page#details"
        ));
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_wait_for_navigation_captures_document_status() {
        let cx = fcp_async_core::compatibility_cx();
        let navigation = CdpNavigateResponse {
            frame_id: "frame-1".to_string(),
            loader_id: Some("loader-1".to_string()),
        };
        let mut session = CdpSession::new(ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(
                serde_json::json!({
                    "method": "Network.responseReceived",
                    "params": {
                        "frameId": "frame-1",
                        "loaderId": "loader-1",
                        "type": "Document",
                        "response": {
                            "status": 201,
                            "url": "https://example.com"
                        }
                    }
                })
                .to_string(),
            ),
            WebSocketMessage::Text(
                serde_json::json!({
                    "method": "Page.lifecycleEvent",
                    "params": {
                        "frameId": "frame-1",
                        "loaderId": "loader-1",
                        "name": "networkIdle"
                    }
                })
                .to_string(),
            ),
        ]));

        let completion = session
            .wait_for_navigation(
                &cx,
                &navigation,
                Some("networkidle"),
                true,
                "https://example.com",
            )
            .await
            .unwrap();
        let transport = session.into_transport();

        assert_eq!(
            completion,
            CdpNavigationCompletion {
                status: Some(201),
                loader_id: Some("loader-1".to_string())
            }
        );
        assert!(transport.sent.is_empty());
    }

    #[test]
    fn test_cdp_navigate_response_rejects_error_text_and_missing_frame() {
        let error = CdpNavigateResponse::from_result(&serde_json::json!({
            "errorText": "Authorization failed for Bearer browser-token",
            "frameId": "frame-1",
        }))
        .unwrap_err();
        let error_message = format!("{error}");
        assert!(!error_message.contains("browser-token"));
        assert!(error_message.contains("[redacted browser-control error body]"));

        let missing_frame = CdpNavigateResponse::from_result(&serde_json::json!({})).unwrap_err();
        assert!(format!("{missing_frame}").contains("missing frameId"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_evaluate_expression_issues_documented_command() {
        let cx = fcp_async_core::compatibility_cx();
        let mut session = CdpSession::new(ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(
                r#"{"id":1,"result":{"result":{"type":"string","value":"Example Domain"}}}"#.into(),
            ),
        ]));

        let response = session
            .evaluate_expression(&cx, "document.title")
            .await
            .unwrap();
        let transport = session.into_transport();

        assert_eq!(
            response,
            CdpEvaluateResponse {
                result: "Example Domain".to_string(),
            }
        );
        assert_eq!(transport.sent.len(), 1);
        let WebSocketMessage::Text(sent_text) = &transport.sent[0] else {
            panic!("Expected text message");
        };
        let sent_json: serde_json::Value = serde_json::from_str(sent_text).unwrap();
        let expected_json = serde_json::json!({
            "id": 1,
            "method": "Runtime.evaluate",
            "params": {
                "awaitPromise": true,
                "expression": "document.title",
                "returnByValue": true
            }
        });
        assert_eq!(sent_json, expected_json);
    }

    #[test]
    fn test_cdp_evaluate_response_serializes_non_string_values() {
        let object = CdpEvaluateResponse::from_result(&serde_json::json!({
            "result": { "type": "object", "value": { "ok": true } }
        }))
        .unwrap();
        let undefined = CdpEvaluateResponse::from_result(&serde_json::json!({
            "result": { "type": "undefined" }
        }))
        .unwrap();
        let unserializable = CdpEvaluateResponse::from_result(&serde_json::json!({
            "result": { "type": "number", "unserializableValue": "NaN" }
        }))
        .unwrap();

        assert_eq!(object.result, r#"{"ok":true}"#);
        assert_eq!(undefined.result, "undefined");
        assert_eq!(unserializable.result, "NaN");
    }

    #[test]
    fn test_cdp_evaluate_response_redacts_exception_details() {
        let token_field = ["access", "_token"].concat();
        let cookie_field = ["coo", "kie"].concat();
        let exception_description =
            format!("{token_field}=value-alpha; {cookie_field}=session-alpha");

        let error = CdpEvaluateResponse::from_result(&serde_json::json!({
            "exceptionDetails": {
                "text": "Uncaught Authorization failed for Bearer browser-token",
                "exception": {
                    "description": exception_description
                }
            }
        }))
        .unwrap_err();

        let message = format!("{error}");
        assert!(!message.contains("browser-token"));
        assert!(!message.contains("value-alpha"));
        assert!(!message.contains("session-alpha"));
        assert!(message.contains("[redacted]"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_extract_text_issues_selector_safe_evaluate_command() {
        let cx = fcp_async_core::compatibility_cx();
        let selector = r#"main[data-label="hero"]"#;
        let expression = cdp_extract_text_expression(Some(selector), Some(true)).unwrap();
        let mut session = CdpSession::new(ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(
                serde_json::json!({
                    "id": 1,
                    "result": {
                        "result": {
                            "type": "object",
                            "value": {
                                "text": "Visible hidden copy",
                                "word_count": 3,
                            },
                        },
                    },
                })
                .to_string(),
            ),
        ]));

        let response = session
            .extract_text(&cx, Some(selector), Some(true))
            .await
            .unwrap();
        let transport = session.into_transport();

        assert_eq!(response.text, "Visible hidden copy");
        assert_eq!(response.word_count, Some(3));
        assert!(expression.contains(r#"const selector = "main[data-label=\"hero\"]";"#));
        assert!(expression.contains("const includeHidden = true;"));
        assert_eq!(transport.sent.len(), 1);
        assert_cdp_text_message(
            &transport.sent[0],
            &serde_json::json!({
                "id": 1,
                "method": "Runtime.evaluate",
                "params": {
                    "awaitPromise": true,
                    "expression": expression,
                    "returnByValue": true,
                },
            }),
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_extract_links_includes_selected_anchor_and_descendants() {
        let cx = fcp_async_core::compatibility_cx();
        let expression = cdp_extract_links_expression(Some("nav.primary")).unwrap();
        let mut session = CdpSession::new(ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(
                serde_json::json!({
                    "id": 1,
                    "result": {
                        "result": {
                            "type": "object",
                            "value": {
                                "links": [
                                    { "href": "https://example.test/", "text": "Home" },
                                    { "href": "https://example.test/docs", "text": null },
                                ],
                            },
                        },
                    },
                })
                .to_string(),
            ),
        ]));

        let response = session
            .extract_links(&cx, Some("nav.primary"))
            .await
            .unwrap();
        let transport = session.into_transport();

        assert_eq!(response.links.len(), 2);
        assert_eq!(response.links[0].href, "https://example.test/");
        assert_eq!(response.links[0].text.as_deref(), Some("Home"));
        assert_eq!(response.links[1].href, "https://example.test/docs");
        assert_eq!(response.links[1].text, None);
        assert!(expression.contains(r#"const selector = "nav.primary";"#));
        assert!(expression.contains(r#"root.matches("a[href]")"#));
        assert_eq!(transport.sent.len(), 1);
        assert_cdp_text_message(
            &transport.sent[0],
            &serde_json::json!({
                "id": 1,
                "method": "Runtime.evaluate",
                "params": {
                    "awaitPromise": true,
                    "expression": expression,
                    "returnByValue": true,
                },
            }),
        );
    }

    #[test]
    fn test_cdp_extract_result_parsers_reject_invalid_payloads() {
        let text_error = cdp_parse_text_result(&CdpEvaluateResponse {
            result: r#"{"links":[]}"#.to_string(),
        })
        .unwrap_err();
        let links_error = cdp_parse_links_result(&CdpEvaluateResponse {
            result: r#"{"text":"not links","word_count":2}"#.to_string(),
        })
        .unwrap_err();

        assert!(format!("{text_error}").contains("invalid extract_text payload"));
        assert!(format!("{links_error}").contains("invalid extract_links payload"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_wait_for_selector_issues_bounded_visible_wait() {
        let cx = fcp_async_core::compatibility_cx();
        let selector = r#"button[data-action="submit"]"#;
        let expression =
            cdp_wait_for_selector_expression(selector, Some("visible"), Some(1_250)).unwrap();
        let mut session = CdpSession::new(ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(
                serde_json::json!({
                    "id": 1,
                    "result": {
                        "result": {
                            "type": "object",
                            "value": { "found": true },
                        },
                    },
                })
                .to_string(),
            ),
        ]));

        let response = session
            .wait_for_selector(&cx, selector, Some("visible"), Some(1_250))
            .await
            .unwrap();
        let transport = session.into_transport();

        assert!(response.found);
        assert!(expression.contains(r#"const selector = "button[data-action=\"submit\"]";"#));
        assert!(expression.contains(r#"const state = "visible";"#));
        assert!(expression.contains("const timeoutMs = 1250;"));
        assert!(expression.contains("MutationObserver"));
        assert_eq!(transport.sent.len(), 1);
        assert_cdp_text_message(
            &transport.sent[0],
            &serde_json::json!({
                "id": 1,
                "method": "Runtime.evaluate",
                "params": {
                    "awaitPromise": true,
                    "expression": expression,
                    "returnByValue": true,
                },
            }),
        );
    }

    #[test]
    fn test_cdp_wait_for_selector_rejects_invalid_state_timeout_and_payload() {
        let invalid_state =
            cdp_wait_for_selector_expression(".ready", Some("stable"), Some(10)).unwrap_err();
        let too_long =
            cdp_wait_for_selector_expression(".ready", Some("attached"), Some(30_001)).unwrap_err();
        let bad_payload = cdp_parse_wait_result(&CdpEvaluateResponse {
            result: r#"{"found":"yes"}"#.to_string(),
        })
        .unwrap_err();
        let alias = cdp_wait_for_selector_expression(".gone", Some("absent"), Some(0)).unwrap();

        assert!(format!("{invalid_state}").contains("state `stable`"));
        assert!(format!("{too_long}").contains("exceeds operation budget"));
        assert!(format!("{bad_payload}").contains("invalid wait_for_selector payload"));
        assert!(alias.contains(r#"const state = "detached";"#));
        assert!(alias.contains("const timeoutMs = 0;"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_click_waits_resolves_box_and_dispatches_mouse_events() {
        let cx = fcp_async_core::compatibility_cx();
        let selector = "button.submit";
        let wait_expression =
            cdp_wait_for_selector_expression(selector, Some("visible"), Some(500)).unwrap();
        let mut session = CdpSession::new(ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(
                serde_json::json!({
                    "id": 1,
                    "result": {
                        "result": {
                            "type": "object",
                            "value": { "found": true },
                        },
                    },
                })
                .to_string(),
            ),
            WebSocketMessage::Text(r#"{"id":2,"result":{"root":{"nodeId":1}}}"#.into()),
            WebSocketMessage::Text(r#"{"id":3,"result":{"nodeId":2}}"#.into()),
            WebSocketMessage::Text(
                r#"{"id":4,"result":{"model":{"content":[10,20,110,20,110,60,10,60]}}}"#.into(),
            ),
            WebSocketMessage::Text(r#"{"id":5,"result":{}}"#.into()),
            WebSocketMessage::Text(r#"{"id":6,"result":{}}"#.into()),
            WebSocketMessage::Text(r#"{"id":7,"result":{}}"#.into()),
        ]));

        let response = session.click(&cx, selector, Some(500)).await.unwrap();
        let transport = session.into_transport();

        assert!(response.clicked);
        assert_eq!(response.navigation_url, None);
        assert_eq!(transport.sent.len(), 7);
        assert_cdp_text_message(
            &transport.sent[0],
            &serde_json::json!({
                "id": 1,
                "method": "Runtime.evaluate",
                "params": {
                    "awaitPromise": true,
                    "expression": wait_expression,
                    "returnByValue": true,
                },
            }),
        );
        assert_cdp_text_message(
            &transport.sent[1],
            &serde_json::json!({
                "id": 2,
                "method": "DOM.getDocument",
                "params": { "depth": 0, "pierce": false },
            }),
        );
        assert_cdp_text_message(
            &transport.sent[2],
            &serde_json::json!({
                "id": 3,
                "method": "DOM.querySelector",
                "params": { "nodeId": 1, "selector": selector },
            }),
        );
        assert_cdp_text_message(
            &transport.sent[3],
            &serde_json::json!({
                "id": 4,
                "method": "DOM.getBoxModel",
                "params": { "nodeId": 2 },
            }),
        );
        for (index, event_type, button, buttons, click_count) in [
            (4, "mouseMoved", "none", 0, 0),
            (5, "mousePressed", "left", 1, 1),
            (6, "mouseReleased", "left", 0, 1),
        ] {
            assert_cdp_text_message(
                &transport.sent[index],
                &serde_json::json!({
                    "id": index + 1,
                    "method": "Input.dispatchMouseEvent",
                    "params": {
                        "button": button,
                        "buttons": buttons,
                        "clickCount": click_count,
                        "type": event_type,
                        "x": 60.0,
                        "y": 40.0,
                    },
                }),
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_click_stops_when_selector_never_visible() {
        let cx = fcp_async_core::compatibility_cx();
        let mut session = CdpSession::new(ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(
                serde_json::json!({
                    "id": 1,
                    "result": {
                        "result": {
                            "type": "object",
                            "value": { "found": false },
                        },
                    },
                })
                .to_string(),
            ),
        ]));

        let error = session.click(&cx, ".missing", Some(0)).await.unwrap_err();
        let transport = session.into_transport();

        assert!(format!("{error}").contains("not visible before timeout"));
        assert_eq!(transport.sent.len(), 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_fill_form_uses_focus_insert_text_direct_set_and_submit_click() {
        let cx = fcp_async_core::compatibility_cx();
        let fields = serde_json::json!({
            "#email": "agent@example.test",
            "select[name=role]": "admin",
        });
        let email_expression =
            cdp_fill_form_prepare_expression("#email", &serde_json::json!("agent@example.test"))
                .unwrap();
        let role_expression =
            cdp_fill_form_prepare_expression("select[name=role]", &serde_json::json!("admin"))
                .unwrap();
        let submit_wait_expression = cdp_wait_for_selector_expression(
            "button[type=submit]",
            Some("visible"),
            Some(CONTROL_TIMEOUT_MS_STANDARD),
        )
        .unwrap();
        let mut session = CdpSession::new(ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(r#"{"id":1,"result":{"root":{"nodeId":1}}}"#.into()),
            WebSocketMessage::Text(r#"{"id":2,"result":{"nodeId":2}}"#.into()),
            WebSocketMessage::Text(r#"{"id":3,"result":{}}"#.into()),
            WebSocketMessage::Text(
                serde_json::json!({
                    "id": 4,
                    "result": {
                        "result": {
                            "type": "object",
                            "value": {
                                "mode": "text",
                                "text_to_insert": "agent@example.test",
                            },
                        },
                    },
                })
                .to_string(),
            ),
            WebSocketMessage::Text(r#"{"id":5,"result":{}}"#.into()),
            WebSocketMessage::Text(r#"{"id":6,"result":{"nodeId":3}}"#.into()),
            WebSocketMessage::Text(r#"{"id":7,"result":{}}"#.into()),
            WebSocketMessage::Text(
                serde_json::json!({
                    "id": 8,
                    "result": {
                        "result": {
                            "type": "object",
                            "value": {
                                "mode": "direct",
                                "text_to_insert": null,
                            },
                        },
                    },
                })
                .to_string(),
            ),
            WebSocketMessage::Text(
                serde_json::json!({
                    "id": 9,
                    "result": {
                        "result": {
                            "type": "object",
                            "value": { "found": true },
                        },
                    },
                })
                .to_string(),
            ),
            WebSocketMessage::Text(r#"{"id":10,"result":{"root":{"nodeId":10}}}"#.into()),
            WebSocketMessage::Text(r#"{"id":11,"result":{"nodeId":11}}"#.into()),
            WebSocketMessage::Text(
                r#"{"id":12,"result":{"model":{"content":[0,0,20,0,20,10,0,10]}}}"#.into(),
            ),
            WebSocketMessage::Text(r#"{"id":13,"result":{}}"#.into()),
            WebSocketMessage::Text(r#"{"id":14,"result":{}}"#.into()),
            WebSocketMessage::Text(r#"{"id":15,"result":{}}"#.into()),
        ]));

        let response = session
            .fill_form(&cx, &fields, Some("button[type=submit]"))
            .await
            .unwrap();
        let transport = session.into_transport();

        assert_eq!(response.filled_count, 2);
        assert_eq!(response.submitted, Some(true));
        assert_eq!(transport.sent.len(), 15);
        assert_cdp_text_message(
            &transport.sent[0],
            &serde_json::json!({
                "id": 1,
                "method": "DOM.getDocument",
                "params": { "depth": 0, "pierce": false },
            }),
        );
        assert_cdp_text_message(
            &transport.sent[1],
            &serde_json::json!({
                "id": 2,
                "method": "DOM.querySelector",
                "params": { "nodeId": 1, "selector": "#email" },
            }),
        );
        assert_cdp_text_message(
            &transport.sent[2],
            &serde_json::json!({
                "id": 3,
                "method": "DOM.focus",
                "params": { "nodeId": 2 },
            }),
        );
        assert_cdp_text_message(
            &transport.sent[3],
            &serde_json::json!({
                "id": 4,
                "method": "Runtime.evaluate",
                "params": {
                    "awaitPromise": true,
                    "expression": email_expression,
                    "returnByValue": true,
                },
            }),
        );
        assert_cdp_text_message(
            &transport.sent[4],
            &serde_json::json!({
                "id": 5,
                "method": "Input.insertText",
                "params": { "text": "agent@example.test" },
            }),
        );
        assert_cdp_text_message(
            &transport.sent[5],
            &serde_json::json!({
                "id": 6,
                "method": "DOM.querySelector",
                "params": { "nodeId": 1, "selector": "select[name=role]" },
            }),
        );
        assert_cdp_text_message(
            &transport.sent[6],
            &serde_json::json!({
                "id": 7,
                "method": "DOM.focus",
                "params": { "nodeId": 3 },
            }),
        );
        assert_cdp_text_message(
            &transport.sent[7],
            &serde_json::json!({
                "id": 8,
                "method": "Runtime.evaluate",
                "params": {
                    "awaitPromise": true,
                    "expression": role_expression,
                    "returnByValue": true,
                },
            }),
        );
        assert_cdp_text_message(
            &transport.sent[8],
            &serde_json::json!({
                "id": 9,
                "method": "Runtime.evaluate",
                "params": {
                    "awaitPromise": true,
                    "expression": submit_wait_expression,
                    "returnByValue": true,
                },
            }),
        );
        assert_cdp_text_message(
            &transport.sent[9],
            &serde_json::json!({
                "id": 10,
                "method": "DOM.getDocument",
                "params": { "depth": 0, "pierce": false },
            }),
        );
        assert_cdp_text_message(
            &transport.sent[10],
            &serde_json::json!({
                "id": 11,
                "method": "DOM.querySelector",
                "params": { "nodeId": 10, "selector": "button[type=submit]" },
            }),
        );
        assert_cdp_text_message(
            &transport.sent[11],
            &serde_json::json!({
                "id": 12,
                "method": "DOM.getBoxModel",
                "params": { "nodeId": 11 },
            }),
        );
        for (index, event_type, button, buttons, click_count) in [
            (12, "mouseMoved", "none", 0, 0),
            (13, "mousePressed", "left", 1, 1),
            (14, "mouseReleased", "left", 0, 1),
        ] {
            assert_cdp_text_message(
                &transport.sent[index],
                &serde_json::json!({
                    "id": index + 1,
                    "method": "Input.dispatchMouseEvent",
                    "params": {
                        "button": button,
                        "buttons": buttons,
                        "clickCount": click_count,
                        "type": event_type,
                        "x": 10.0,
                        "y": 5.0,
                    },
                }),
            );
        }
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_fill_form_rejects_missing_field_selector() {
        let cx = fcp_async_core::compatibility_cx();
        let fields = serde_json::json!({ "#missing": "value" });
        let mut session = CdpSession::new(ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(r#"{"id":1,"result":{"root":{"nodeId":1}}}"#.into()),
            WebSocketMessage::Text(r#"{"id":2,"result":{"nodeId":0}}"#.into()),
        ]));

        let error = session.fill_form(&cx, &fields, None).await.unwrap_err();
        let transport = session.into_transport();

        assert!(format!("{error}").contains("selector `#missing` did not match"));
        assert_eq!(transport.sent.len(), 2);
    }

    #[test]
    fn test_cdp_fill_form_rejects_invalid_fields_values_and_payloads() {
        let not_object = cdp_form_fields(&serde_json::json!(["#email"])).unwrap_err();
        let empty_selector = cdp_form_fields(&serde_json::json!({ "": "value" })).unwrap_err();
        let nested_value =
            cdp_form_fields(&serde_json::json!({ "#profile": { "name": "Agent" } })).unwrap_err();
        let invalid_plan = cdp_parse_form_field_plan(&CdpEvaluateResponse {
            result: r#"{"text_to_insert":7}"#.to_string(),
        })
        .unwrap_err();
        let checkbox_expression =
            cdp_fill_form_prepare_expression("#remember", &serde_json::json!(true)).unwrap();

        assert!(format!("{not_object}").contains("object map"));
        assert!(format!("{empty_selector}").contains("selector cannot be empty"));
        assert!(format!("{nested_value}").contains("value must be scalar"));
        assert!(format!("{invalid_plan}").contains("invalid fill_form payload"));
        assert!(checkbox_expression.contains("const value = true;"));
        assert!(checkbox_expression.contains(r#"type === "checkbox""#));
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_capture_screenshot_issues_full_page_sequence() {
        let cx = fcp_async_core::compatibility_cx();
        let mut session = CdpSession::new(ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(
                r#"{"id":1,"result":{"cssContentSize":{"x":0,"y":0,"width":1280,"height":2048}}}"#
                    .into(),
            ),
            WebSocketMessage::Text(r#"{"id":2,"result":{"data":"image-alpha"}}"#.into()),
        ]));

        let response = session
            .capture_screenshot(&cx, None, true, Some("jpeg"), Some(80))
            .await
            .unwrap();
        let transport = session.into_transport();

        assert_eq!(
            response,
            CdpScreenshotResponse {
                image_data: "image-alpha".to_string(),
                width: 1280,
                height: 2048,
            }
        );
        assert_eq!(transport.sent.len(), 2);
        assert_cdp_text_message(
            &transport.sent[0],
            &serde_json::json!({
                "id": 1,
                "method": "Page.getLayoutMetrics",
            }),
        );
        assert_cdp_text_message(
            &transport.sent[1],
            &serde_json::json!({
                "id": 2,
                "method": "Page.captureScreenshot",
                "params": {
                    "captureBeyondViewport": true,
                    "clip": { "x": 0.0, "y": 0.0, "width": 1280.0, "height": 2048.0, "scale": 1 },
                    "format": "jpeg",
                    "fromSurface": true,
                    "quality": 80,
                }
            }),
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_capture_screenshot_uses_selector_clip() {
        let cx = fcp_async_core::compatibility_cx();
        let mut session = CdpSession::new(ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(r#"{"id":1,"result":{"root":{"nodeId":1}}}"#.into()),
            WebSocketMessage::Text(r#"{"id":2,"result":{"nodeId":2}}"#.into()),
            WebSocketMessage::Text(
                r#"{"id":3,"result":{"model":{"content":[10.5,20,110.5,20,110.5,70.25,10.5,70.25]}}}"#
                    .into(),
            ),
            WebSocketMessage::Text(r#"{"id":4,"result":{"data":"image-beta"}}"#.into()),
        ]));

        let response = session
            .capture_screenshot(&cx, Some("#main"), false, None, None)
            .await
            .unwrap();
        let transport = session.into_transport();

        assert_eq!(
            response,
            CdpScreenshotResponse {
                image_data: "image-beta".to_string(),
                width: 100,
                height: 51,
            }
        );
        assert_eq!(transport.sent.len(), 4);
        assert_cdp_text_message(
            &transport.sent[0],
            &serde_json::json!({
                "id": 1,
                "method": "DOM.getDocument",
                "params": { "depth": 0, "pierce": false },
            }),
        );
        assert_cdp_text_message(
            &transport.sent[1],
            &serde_json::json!({
                "id": 2,
                "method": "DOM.querySelector",
                "params": { "nodeId": 1, "selector": "#main" },
            }),
        );
        assert_cdp_text_message(
            &transport.sent[2],
            &serde_json::json!({
                "id": 3,
                "method": "DOM.getBoxModel",
                "params": { "nodeId": 2 },
            }),
        );
        assert_cdp_text_message(
            &transport.sent[3],
            &serde_json::json!({
                "id": 4,
                "method": "Page.captureScreenshot",
                "params": {
                    "captureBeyondViewport": true,
                    "clip": { "x": 10.5, "y": 20.0, "width": 100.0, "height": 50.25, "scale": 1 },
                    "format": "png",
                    "fromSurface": true,
                }
            }),
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_capture_screenshot_rejects_missing_selector() {
        let cx = fcp_async_core::compatibility_cx();
        let mut session = CdpSession::new(ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(r#"{"id":1,"result":{"root":{"nodeId":1}}}"#.into()),
            WebSocketMessage::Text(r#"{"id":2,"result":{"nodeId":0}}"#.into()),
        ]));

        let error = session
            .capture_screenshot(&cx, Some("#missing"), false, None, None)
            .await
            .unwrap_err();
        let transport = session.into_transport();

        assert!(format!("{error}").contains("selector `#missing` did not match"));
        assert_eq!(transport.sent.len(), 2);
    }

    #[test]
    fn test_cdp_screenshot_response_rejects_missing_data_and_bad_clip() {
        let clip = CdpCaptureClip::new(0.0, 0.0, 10.0, 20.0).unwrap();
        let missing_data =
            CdpScreenshotResponse::from_capture_result(&serde_json::json!({}), clip).unwrap_err();
        let empty_clip = CdpCaptureClip::new(0.0, 0.0, 0.0, 20.0).unwrap_err();

        assert!(format!("{missing_data}").contains("missing data"));
        assert!(format!("{empty_clip}").contains("positive dimensions"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_render_pdf_issues_documented_command_and_counts_pages() {
        let cx = fcp_async_core::compatibility_cx();
        let pdf_data = BASE64_STANDARD.encode(
            b"%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Count 2 /Kids [3 0 R 4 0 R] >> endobj
3 0 obj << /Type /Page /Parent 2 0 R >> endobj
4 0 obj << /Type /Page /Parent 2 0 R >> endobj
%%EOF",
        );
        let mut session = CdpSession::new(ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(
                serde_json::json!({ "id": 1, "result": { "data": pdf_data } }).to_string(),
            ),
        ]));

        let response = session
            .render_pdf(&cx, Some("a4"), Some(true), Some(false))
            .await
            .unwrap();
        let transport = session.into_transport();

        assert_eq!(response.page_count, 2);
        assert!(response.pdf_data.starts_with("JVBER"));
        assert_eq!(transport.sent.len(), 1);
        assert_cdp_text_message(
            &transport.sent[0],
            &serde_json::json!({
                "id": 1,
                "method": "Page.printToPDF",
                "params": {
                    "landscape": true,
                    "paperHeight": 11.69,
                    "paperWidth": 8.27,
                    "printBackground": false,
                    "transferMode": "ReturnAsBase64",
                },
            }),
        );
    }

    #[test]
    fn test_cdp_pdf_response_rejects_missing_stream_invalid_and_uninspectable_data() {
        let missing_data = CdpPdfResponse::from_print_result(&serde_json::json!({})).unwrap_err();
        let stream_response = CdpPdfResponse::from_print_result(&serde_json::json!({
            "stream": "stream-handle-alpha"
        }))
        .unwrap_err();
        let invalid_base64 = CdpPdfResponse::from_print_result(&serde_json::json!({
            "data": "not pdf data"
        }))
        .unwrap_err();
        let no_pages = CdpPdfResponse::from_print_result(&serde_json::json!({
            "data": BASE64_STANDARD.encode(b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n%%EOF")
        }))
        .unwrap_err();
        let bad_format = cdp_pdf_paper_size(Some("envelope")).unwrap_err();

        assert!(format!("{missing_data}").contains("missing data"));
        assert!(format!("{stream_response}").contains("IO stream"));
        assert!(format!("{invalid_base64}").contains("invalid base64"));
        assert!(format!("{no_pages}").contains("contains no page objects"));
        assert!(format!("{bad_format}").contains("paper format `envelope`"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_get_cookies_issues_documented_command_and_filters_domain() {
        let cx = fcp_async_core::compatibility_cx();
        let mut session = CdpSession::new(ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(
                r#"{"id":1,"result":{"cookies":[{"name":"theme","value":"light","domain":".example.test","path":"/","httpOnly":true,"secure":true,"sameSite":"Lax"},{"name":"mode","value":"dense","domain":"app.example.test","path":"/app"},{"name":"outside","value":"skip","domain":"example.org","path":"/"},{"name":"host","value":"local","path":"/"}]}}"#
                    .into(),
            ),
        ]));

        let response = session
            .get_cookies(&cx, Some("example.test"))
            .await
            .unwrap();
        let transport = session.into_transport();

        assert_eq!(response.cookies.len(), 2);
        assert_eq!(response.cookies[0].name, "theme");
        assert_eq!(response.cookies[0].value, "light");
        assert_eq!(response.cookies[0].domain.as_deref(), Some(".example.test"));
        assert_eq!(response.cookies[0].path.as_deref(), Some("/"));
        assert_eq!(response.cookies[0].http_only, Some(true));
        assert_eq!(response.cookies[0].secure, Some(true));
        assert_eq!(response.cookies[0].same_site.as_deref(), Some("Lax"));
        assert_eq!(response.cookies[1].name, "mode");
        assert_eq!(
            response.cookies[1].domain.as_deref(),
            Some("app.example.test")
        );
        assert_eq!(transport.sent.len(), 1);
        assert_cdp_text_message(
            &transport.sent[0],
            &serde_json::json!({
                "id": 1,
                "method": "Network.getCookies",
            }),
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_cdp_session_set_cookies_issues_documented_command_and_counts_input() {
        let cx = fcp_async_core::compatibility_cx();
        let mut session = CdpSession::new(ScriptedCdpTransport::with_received([
            WebSocketMessage::Text(r#"{"id":1,"result":{}}"#.into()),
        ]));
        let cookies = [
            Cookie {
                name: "theme".to_string(),
                value: "light".to_string(),
                domain: Some(".example.test".to_string()),
                path: Some("/".to_string()),
                expires: Some(4_102_444_800.0),
                http_only: Some(true),
                secure: Some(true),
                same_site: Some("Lax".to_string()),
            },
            Cookie {
                name: "mode".to_string(),
                value: "dense".to_string(),
                domain: Some("app.example.test".to_string()),
                path: Some("/app".to_string()),
                expires: None,
                http_only: None,
                secure: Some(false),
                same_site: None,
            },
        ];

        let response = session.set_cookies(&cx, &cookies).await.unwrap();
        let transport = session.into_transport();

        assert_eq!(response, CdpSetCookiesResponse { set_count: 2 });
        assert_eq!(transport.sent.len(), 1);
        assert_cdp_text_message(
            &transport.sent[0],
            &serde_json::json!({
                "id": 1,
                "method": "Network.setCookies",
                "params": {
                    "cookies": [
                        {
                            "name": "theme",
                            "value": "light",
                            "domain": ".example.test",
                            "path": "/",
                            "expires": 4_102_444_800.0,
                            "httpOnly": true,
                            "secure": true,
                            "sameSite": "Lax",
                        },
                        {
                            "name": "mode",
                            "value": "dense",
                            "domain": "app.example.test",
                            "path": "/app",
                            "secure": false,
                        },
                    ],
                },
            }),
        );
    }

    #[test]
    fn test_cdp_cookie_response_rejects_missing_name_or_value() {
        let missing_name = CdpCookieResponse::from_result(
            &serde_json::json!({ "cookies": [{ "value": "light" }] }),
            None,
        )
        .unwrap_err();
        let missing_value = CdpCookieResponse::from_result(
            &serde_json::json!({ "cookies": [{ "name": "theme" }] }),
            None,
        )
        .unwrap_err();
        let missing_list =
            CdpCookieResponse::from_result(&serde_json::json!({}), None).unwrap_err();

        assert!(format!("{missing_name}").contains("Network.Cookie name"));
        assert!(format!("{missing_value}").contains("Network.Cookie value"));
        assert!(format!("{missing_list}").contains("missing cookies"));
    }

    #[test]
    fn test_cdp_session_rejects_exhausted_command_ids() {
        let mut session = CdpSession {
            transport: ScriptedCdpTransport::default(),
            next_command_id: u64::MAX,
            pending_events: VecDeque::new(),
        };

        let err = session.next_command("Page.enable", None).unwrap_err();

        assert!(format!("{err}").contains("command id space exhausted"));
    }

    #[test]
    fn test_worker_contract_maps_session_operations_to_worker_primitives() {
        let descriptor = browser_control_contract_descriptor();
        let connector_operations = descriptor["connector_operations"].as_array().unwrap();
        assert_eq!(
            connector_operations.len(),
            BROWSER_CONNECTOR_OPERATIONS.len()
        );

        let session_save = connector_operations
            .iter()
            .find(|operation| operation["id"] == "browser.session.save")
            .unwrap();
        assert_eq!(session_save["mapping"], "derived");
        assert_eq!(
            session_save["worker_operation_ids"],
            serde_json::json!(["browser.get_cookies"])
        );

        let session_restore = connector_operations
            .iter()
            .find(|operation| operation["id"] == "browser.session.restore")
            .unwrap();
        assert_eq!(session_restore["mapping"], "derived");
        assert_eq!(
            session_restore["worker_operation_ids"],
            serde_json::json!(["browser.set_cookies"])
        );

        let session_describe = connector_operations
            .iter()
            .find(|operation| operation["id"] == "browser.session.describe")
            .unwrap();
        assert_eq!(session_describe["mapping"], "connector_state");
        assert_eq!(
            session_describe["worker_operation_ids"],
            serde_json::json!([])
        );
    }

    #[test]
    fn test_health_contract_rejects_missing_operation_advertisement() {
        let mut body = browser_control_contract_descriptor();
        body["operations"] = serde_json::Value::Array(vec![
            WORKER_NAVIGATE.descriptor(),
            WORKER_SCREENSHOT.descriptor(),
        ]);

        let err = validate_fcp_browser_control_health(&body).unwrap_err();
        assert!(err.contains("browser.render_pdf"));
    }

    #[test]
    fn test_health_contract_rejects_wrong_operation_path() {
        let mut body = browser_control_contract_descriptor();
        let operations = body["operations"].as_array_mut().unwrap();
        operations[0]["path"] = serde_json::Value::String("/wrong-navigate".into());

        let err = validate_fcp_browser_control_health(&body).unwrap_err();
        assert!(err.contains("browser.navigate"));
        assert!(err.contains("/navigate"));
    }

    #[test]
    fn test_health_contract_rejects_wrong_operation_method() {
        let mut body = browser_control_contract_descriptor();
        let operations = body["operations"].as_array_mut().unwrap();
        operations[0]["method"] = serde_json::Value::String("GET".into());

        let err = validate_fcp_browser_control_health(&body).unwrap_err();
        assert!(err.contains("browser.navigate"));
        assert!(err.contains("POST"));
    }

    #[test]
    fn test_health_contract_rejects_wrong_operation_response_budget() {
        let mut body = browser_control_contract_descriptor();
        let operations = body["operations"].as_array_mut().unwrap();
        operations[0]["max_response_bytes"] = serde_json::json!(CONTROL_RESPONSE_BYTES_SMALL);

        let err = validate_fcp_browser_control_health(&body).unwrap_err();
        assert!(err.contains("browser.navigate"));
        assert!(err.contains("max_response_bytes"));
        assert!(err.contains(&CONTROL_RESPONSE_BYTES_CAPTURE.to_string()));
    }

    #[test]
    fn test_health_contract_rejects_wrong_operation_timeout_budget() {
        let mut body = browser_control_contract_descriptor();
        let operations = body["operations"].as_array_mut().unwrap();
        operations[0]["timeout_ms"] = serde_json::json!(CONTROL_TIMEOUT_MS_SHORT);

        let err = validate_fcp_browser_control_health(&body).unwrap_err();
        assert!(err.contains("browser.navigate"));
        assert!(err.contains("timeout_ms"));
        assert!(err.contains(&CONTROL_TIMEOUT_MS_CAPTURE.to_string()));
    }

    #[test]
    fn test_health_contract_rejects_wrong_target_policy() {
        let mut body = browser_control_contract_descriptor();
        let operations = body["operations"].as_array_mut().unwrap();
        operations[0]["target_policy"]["selection"] =
            serde_json::Value::String("active_page_required".into());

        let err = validate_fcp_browser_control_health(&body).unwrap_err();
        assert!(err.contains("browser.navigate"));
        assert!(err.contains("target_policy"));
        assert!(err.contains("create_or_reuse_active_page"));
    }

    #[test]
    fn test_health_contract_rejects_wrong_request_header_contract() {
        let mut body = browser_control_contract_descriptor();
        let operations = body["operations"].as_array_mut().unwrap();
        operations[0]["request_headers"][0]["value"] =
            serde_json::Value::String("browser.screenshot".into());

        let err = validate_fcp_browser_control_health(&body).unwrap_err();
        assert!(err.contains("browser.navigate"));
        assert!(err.contains("request_headers"));
        assert!(err.contains(CONTROL_OPERATION_HEADER));
    }

    #[test]
    fn test_health_contract_rejects_missing_operation_implementation() {
        let mut body = browser_control_contract_descriptor();
        let operations = body["operations"].as_array_mut().unwrap();
        operations[0]
            .as_object_mut()
            .unwrap()
            .remove("implementation");

        let err = validate_fcp_browser_control_health(&body).unwrap_err();
        assert!(err.contains("browser.navigate"));
        assert!(err.contains("implementation"));
    }

    #[test]
    fn test_health_contract_rejects_wrong_cdp_command_plan() {
        let mut body = browser_control_contract_descriptor();
        let operations = body["operations"].as_array_mut().unwrap();
        operations[0]["implementation"]["methods"] =
            serde_json::json!(["Page.enable", "Page.navigate"]);

        let err = validate_fcp_browser_control_health(&body).unwrap_err();
        assert!(err.contains("browser.navigate"));
        assert!(err.contains("Network.enable"));
    }

    #[test]
    fn test_health_contract_rejects_policy_operation_without_description() {
        let mut body = browser_control_contract_descriptor();
        let operations = body["operations"].as_array_mut().unwrap();
        let set_proxy = operations
            .iter_mut()
            .find(|operation| operation["id"] == "browser.set_proxy")
            .unwrap();
        set_proxy["implementation"]
            .as_object_mut()
            .unwrap()
            .remove("description");

        let err = validate_fcp_browser_control_health(&body).unwrap_err();
        assert!(err.contains("browser.set_proxy"));
        assert!(err.contains("worker_policy"));
    }

    #[test]
    fn test_proxy_contract_rejects_policy_operation_without_redaction_contract() {
        let mut body = browser_control_contract_descriptor();
        let operations = body["operations"].as_array_mut().unwrap();
        let clear_proxy = operations
            .iter_mut()
            .find(|operation| operation["id"] == "browser.clear_proxy")
            .unwrap();
        clear_proxy["implementation"]
            .as_object_mut()
            .unwrap()
            .remove("redaction_contract");

        let err = validate_fcp_browser_control_proxy_support(&body).unwrap_err();
        assert!(err.contains("browser.clear_proxy"));
        assert!(err.contains("redaction_contract"));
    }

    #[test]
    fn test_health_contract_rejects_wrong_protocol_version() {
        let mut body = browser_control_contract_descriptor();
        body["protocol_version"] = serde_json::Value::Number(2.into());

        let err = validate_fcp_browser_control_health(&body).unwrap_err();
        assert!(err.contains("unsupported protocol_version 2"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_health_check_rejects_raw_chrome_cdp_endpoint() {
        let server = TestControlServer::respond_sequence(vec![
            TestControlResponse::text("GET", "/health", 404, "not found"),
            TestControlResponse::json(
                "GET",
                "/json/version",
                200,
                serde_json::json!({
                    "Browser": "HeadlessChrome/123.0.0.0",
                    "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/browser/abc"
                }),
            ),
        ]);

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&server.uri())
            .with_retry_config(0);

        let err = client.health_check().await.unwrap_err();
        let message = match err {
            BrowserError::InvalidConfig(message) => message,
            _ => String::new(),
        };
        assert!(message.contains("raw Chrome DevTools endpoint"));
    }

    #[test]
    fn test_chrome_cdp_version_detection_requires_cdp_shape() {
        assert!(looks_like_chrome_cdp_version(&serde_json::json!({
            "webSocketDebuggerUrl": "wss://browser.example/devtools/browser/abc"
        })));
        assert!(looks_like_chrome_cdp_version(&serde_json::json!({
            "Browser": "Chrome/123.0.0.0"
        })));
        assert!(!looks_like_chrome_cdp_version(&serde_json::json!({
            "control_plane": "fcp-browser-control",
            "protocol_version": 1,
            "operations": []
        })));
    }

    #[fcp_async_core::runtime::test]
    async fn test_navigate() {
        let server = TestControlServer::respond(
            TestControlResponse::json(
                "POST",
                "/navigate",
                200,
                serde_json::json!({
                    "url": "https://example.com",
                    "status": 200,
                    "title": "Example Domain"
                }),
            )
            .expect_header(CONTROL_OPERATION_HEADER, "browser.navigate")
            .expect_header(
                CONTROL_RESPONSE_BUDGET_HEADER,
                CONTROL_RESPONSE_BYTES_CAPTURE.to_string(),
            )
            .expect_header(
                CONTROL_TIMEOUT_BUDGET_HEADER,
                CONTROL_TIMEOUT_MS_CAPTURE.to_string(),
            )
            .expect_header(CONTROL_TARGET_SCOPE_HEADER, "page")
            .expect_header(
                CONTROL_TARGET_SELECTION_HEADER,
                "create_or_reuse_active_page",
            )
            .expect_header(CONTROL_STALE_TARGET_RECOVERY_HEADER, "true")
            .expect_header(CONTROL_CURRENT_TAB_GUARD_HEADER, "false")
            .expect_header(CONTROL_EXPORT_GUARD_HEADER, "false"),
        );

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&server.uri());

        let result = client
            .navigate("https://example.com", None, None, None)
            .await
            .unwrap();
        assert_eq!(result.url, "https://example.com");
        assert_eq!(result.status, 200);
        assert_eq!(result.title.as_deref(), Some("Example Domain"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_screenshot() {
        let server = TestControlServer::respond(
            TestControlResponse::json(
                "POST",
                "/screenshot",
                200,
                serde_json::json!({
                    "image_data": "iVBOR...",
                    "width": 1920,
                    "height": 1080
                }),
            )
            .expect_header(CONTROL_TARGET_SCOPE_HEADER, "page")
            .expect_header(CONTROL_TARGET_SELECTION_HEADER, "active_page_required")
            .expect_header(CONTROL_STALE_TARGET_RECOVERY_HEADER, "true")
            .expect_header(CONTROL_CURRENT_TAB_GUARD_HEADER, "true")
            .expect_header(CONTROL_EXPORT_GUARD_HEADER, "true"),
        );

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&server.uri());

        let result = client
            .screenshot(None, Some(true), None, None)
            .await
            .unwrap();
        assert_eq!(result.width, 1920);
        assert_eq!(result.height, 1080);
    }

    #[fcp_async_core::runtime::test]
    async fn test_extract_text() {
        let server = TestControlServer::respond(TestControlResponse::json(
            "POST",
            "/extract_text",
            200,
            serde_json::json!({
                "text": "Hello, world!",
                "word_count": 2
            }),
        ));

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&server.uri());

        let result = client.extract_text(Some("body"), None).await.unwrap();
        assert_eq!(result.text, "Hello, world!");
        assert_eq!(result.word_count, Some(2));
    }

    #[fcp_async_core::runtime::test]
    async fn test_extract_links() {
        let server = TestControlServer::respond(TestControlResponse::json(
            "POST",
            "/extract_links",
            200,
            serde_json::json!({
                "links": [
                    { "href": "https://example.com/a", "text": "Link A" },
                    { "href": "https://example.com/b", "text": "Link B" }
                ]
            }),
        ));

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&server.uri());

        let result = client.extract_links(None).await.unwrap();
        assert_eq!(result.links.len(), 2);
        assert_eq!(result.links[0].href, "https://example.com/a");
    }

    #[fcp_async_core::runtime::test]
    async fn test_click() {
        let server = TestControlServer::respond(TestControlResponse::json(
            "POST",
            "/click",
            200,
            serde_json::json!({
                "clicked": true,
                "navigation_url": null
            }),
        ));

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&server.uri());

        let result = client.click("button.submit", None).await.unwrap();
        assert!(result.clicked);
    }

    #[fcp_async_core::runtime::test]
    async fn test_evaluate_js() {
        let server = TestControlServer::respond(TestControlResponse::json(
            "POST",
            "/evaluate",
            200,
            serde_json::json!({
                "result": "Example Domain"
            }),
        ));

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&server.uri());

        let result = client.evaluate_js("document.title").await.unwrap();
        assert_eq!(result.result, "Example Domain");
    }

    #[fcp_async_core::runtime::test]
    async fn test_get_cookies() {
        let server = TestControlServer::respond(TestControlResponse::json(
            "POST",
            "/cookies",
            200,
            serde_json::json!({
                "cookies": [
                    { "name": "session", "value": "abc123", "domain": "example.com" }
                ]
            }),
        ));

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&server.uri());

        let cookies = client.get_cookies(Some("example.com")).await.unwrap();
        assert_eq!(cookies.len(), 1);
        assert_eq!(cookies[0].name, "session");
    }

    #[fcp_async_core::runtime::test]
    async fn test_set_cookies() {
        let server = TestControlServer::respond(TestControlResponse::json(
            "POST",
            "/set_cookies",
            200,
            serde_json::json!({
                "set_count": 1
            }),
        ));

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&server.uri());

        let cookies = vec![Cookie {
            name: "session".into(),
            value: "abc123".into(),
            domain: Some("example.com".into()),
            path: Some("/".into()),
            expires: None,
            http_only: None,
            secure: None,
            same_site: None,
        }];
        let count = client.set_cookies(&cookies).await.unwrap();
        assert_eq!(count, 1);
    }

    #[fcp_async_core::runtime::test]
    async fn test_set_proxy() {
        let server = TestControlServer::respond_sequence(vec![
            health_response(browser_control_contract_descriptor()),
            TestControlResponse::json(
                "POST",
                "/proxy/set",
                200,
                serde_json::json!({
                    "enabled": true,
                    "mode": "fixed_servers",
                    "server": "http://proxy.example.com:8080"
                }),
            ),
        ]);

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&server.uri());

        let proxy = ProxyConfig {
            server: "http://proxy.example.com:8080".into(),
            bypass_list: Some(vec!["localhost".into()]),
            username: None,
            password: None,
        };
        let result = client.set_proxy(&proxy).await.unwrap();
        assert!(result.enabled);
        assert_eq!(result.mode, "fixed_servers");
        assert_eq!(
            result.server.as_deref(),
            Some("http://proxy.example.com:8080")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn test_set_proxy_rejects_worker_without_proxy_contract_before_post() {
        let server = TestControlServer::respond(health_response(
            browser_control_contract_without_proxy_operations(),
        ));

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&server.uri());
        let proxy = ProxyConfig {
            server: "http://proxy.example.com:8080".into(),
            bypass_list: None,
            username: None,
            password: None,
        };

        let err = client.set_proxy(&proxy).await.unwrap_err();
        let err = format!("{err}");
        assert!(err.contains("reason_code=proxy_unavailable_worker_contract"));
        assert!(err.contains("browser.set_proxy"));
        assert!(err.contains("browser.clear_proxy"));

        let requests = server.received_requests();
        assert!(requests.iter().all(|request| request.path != "/proxy/set"));
    }

    #[test]
    fn test_proxy_config_rejects_untrusted_descriptors() {
        let mut proxy = ProxyConfig {
            server: "http://proxy.example.com:8080".into(),
            bypass_list: None,
            username: None,
            password: None,
        };
        validate_proxy_config(&proxy).unwrap();

        for (server, reason_code) in [
            ("ftp://proxy.example.com:21", "proxy_invalid_scheme"),
            (
                "http://user:pass@proxy.example.com:8080",
                "proxy_embedded_credentials",
            ),
            ("http://127.0.0.1:8080", "proxy_private_or_internal_host"),
            ("http://10.0.0.10:8080", "proxy_private_or_internal_host"),
            ("http://localhost:8080", "proxy_private_or_internal_host"),
            (
                "http://proxy.example.com:8080\nx",
                "proxy_descriptor_control_char",
            ),
        ] {
            proxy.server = server.into();
            let err = validate_proxy_config(&proxy).unwrap_err();
            assert!(
                format!("{err}").contains(reason_code),
                "expected {reason_code} for {server:?}, got {err}"
            );
        }

        proxy.server = "http://proxy.example.com:8080".into();
        proxy.bypass_list = Some(vec!["example.com\nInjected-Header: value".into()]);
        let err = validate_proxy_config(&proxy).unwrap_err();
        assert!(format!("{err}").contains("proxy_descriptor_control_char"));

        proxy.bypass_list = Some(vec!["example.com".into(); PROXY_BYPASS_MAX_ENTRIES + 1]);
        let err = validate_proxy_config(&proxy).unwrap_err();
        assert!(format!("{err}").contains("proxy_bypass_list_too_large"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_clear_proxy() {
        let server = TestControlServer::respond_sequence(vec![
            health_response(browser_control_contract_descriptor()),
            TestControlResponse::json(
                "POST",
                "/proxy/clear",
                200,
                serde_json::json!({
                    "enabled": false,
                    "mode": "direct",
                    "server": null
                }),
            ),
        ]);

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&server.uri());

        let result = client.clear_proxy().await.unwrap();
        assert!(!result.enabled);
        assert_eq!(result.mode, "direct");
        assert!(result.server.is_none());
    }

    #[fcp_async_core::runtime::test]
    async fn test_worker_operation_timeout_budget_is_applied_to_request() {
        const SLOW_OPERATION: BrowserControlOperation = BrowserControlOperation {
            id: "browser.test_timeout",
            method: "POST",
            path: "/slow",
            max_response_bytes: CONTROL_RESPONSE_BYTES_SMALL,
            timeout_ms: 20,
            target_policy: TARGET_ACTIVE_PAGE_INTERACTION,
            implementation: BrowserControlImplementation::Cdp {
                methods: &["Runtime.evaluate"],
            },
        };

        let server = TestControlServer::respond(
            TestControlResponse::json("POST", "/slow", 200, serde_json::json!({ "ok": true }))
                .with_delay(Duration::from_millis(250)),
        );

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&server.uri())
            .with_retry_config(0);

        let err = client
            .post_json(SLOW_OPERATION, &serde_json::json!({}))
            .await
            .unwrap_err();
        assert!(matches!(err, BrowserError::Http(err) if err.is_timeout()));
    }

    #[test]
    fn test_worker_operation_timeout_budget_is_applied_to_runtime_context() {
        let client = BrowserClient::new(None).unwrap();
        let ctx =
            client.request_context_for_timeout(Duration::from_millis(WORKER_SCREENSHOT.timeout_ms));

        assert_eq!(ctx.scope(), fcp_async_core::ContextScope::Request);
        let remaining = ctx.remaining_budget().unwrap();
        assert!(
            remaining > Duration::from_secs(30),
            "capture operations must not inherit the default 30s runtime request budget"
        );
        assert!(remaining <= Duration::from_millis(WORKER_SCREENSHOT.timeout_ms));
    }

    #[fcp_async_core::runtime::test]
    async fn test_server_error_retry() {
        let server = TestControlServer::respond(TestControlResponse::text(
            "POST",
            "/navigate",
            500,
            "internal error",
        ));

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&server.uri())
            .with_retry_config(0);

        let result = client
            .navigate("https://example.com", None, None, None)
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.is_retryable());
    }

    #[fcp_async_core::runtime::test]
    async fn test_server_error_redacts_sensitive_body_fields() {
        let server = TestControlServer::respond(TestControlResponse::json(
            "POST",
            "/navigate",
            500,
            serde_json::json!({
                "error": "upstream failed",
                "access_token": "browser-worker-token",
                "cookies": [{ "name": "session", "value": "cookie-secret" }]
            }),
        ));

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&server.uri())
            .with_retry_config(0);

        let err = client
            .navigate("https://example.com", None, None, None)
            .await
            .unwrap_err();
        let message = format!("{err}");
        assert!(!message.contains("browser-worker-token"));
        assert!(!message.contains("cookie-secret"));
        assert!(message.contains("[redacted]"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_client_error_redacts_sensitive_api_message() {
        let server = TestControlServer::respond(TestControlResponse::json(
            "POST",
            "/click",
            400,
            serde_json::json!({
                "error": {
                    "message": "Authorization failed for Bearer browser-worker-token",
                    "code": "auth_failed"
                }
            }),
        ));

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&server.uri());

        let err = client.click(".submit", None).await.unwrap_err();
        let message = format!("{err}");
        assert!(!message.contains("browser-worker-token"));
        assert!(!message.contains("Bearer"));
        assert!(message.contains("[redacted browser-control error body]"));
    }

    #[fcp_async_core::runtime::test]
    async fn test_oversized_browser_control_response_is_rejected() {
        let server = TestControlServer::respond(TestControlResponse::bytes(
            "POST",
            "/wait_for_selector",
            200,
            vec![b'x'; CONTROL_RESPONSE_BYTES_SMALL + 1],
        ));

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&server.uri())
            .with_retry_config(0);

        let result = client
            .wait_for_selector(".ready", Some("visible"), Some(1_000))
            .await;
        let err = result.unwrap_err();
        assert!(format!("{err}").contains("browser control response exceeds"));
        assert!(format!("{err}").contains(&CONTROL_RESPONSE_BYTES_SMALL.to_string()));
    }

    #[fcp_async_core::runtime::test]
    async fn test_rate_limited() {
        let server =
            TestControlServer::respond(TestControlResponse::text("POST", "/navigate", 429, ""));

        let client = BrowserClient::new(None)
            .unwrap()
            .with_browser_url(&server.uri())
            .with_retry_config(0);

        let result = client
            .navigate("https://example.com", None, None, None)
            .await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BrowserError::Api {
                status_code: Some(429),
                ..
            }
        ));
    }

    #[test]
    fn test_error_is_retryable() {
        let err = BrowserError::Timeout {
            message: "timed out".into(),
        };
        assert!(err.is_retryable());

        let err = BrowserError::InvalidConfig("bad config".into());
        assert!(!err.is_retryable());

        let err = BrowserError::Api {
            message: "Server error".into(),
            status_code: Some(500),
        };
        assert!(err.is_retryable());
    }
}
