//! Live host bridge for reactive rules. Credentials and target identities are
//! frozen for the whole batch; the host independently enforces the tier ceiling.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use fcp_core::{EventEnvelope, InvokeResponse, InvokeStatus, Provenance, RequestId, SafetyTier};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;

use crate::invocation_cmd::{LookupFailure, query_invocation, read_admin_token};
use crate::native_events::{NativeStreamClient, NativeStreamConfig, StreamFailure};
use crate::reactive_rules::Rule;
use crate::rules_cmd::{
    self, ExecutionScope, InvocationResult, RuleEventBatch, RuleEventSource, RuleExecutor,
    RulePollingSource, RuleReconciler, RulesArgs, RulesExecutionOptions, RulesPollOptions,
    RulesReconcileOptions,
};
use crate::webhook_events::{self, PollStart, WebhookFailure, WebhookPollPage, WebhookSourceScope};
use crate::{
    CliExitCode, CommandAvailability, CommandEnvelope, DispatchOutcome, HostAdminClient,
    HostGuardedInvokeRequest, HostPreflightResponse, InvokeArgs, InvokeRequest, KnowledgeState,
    LiveAuthArgs, ResolvedHostConfig, ResolvedLiveAuth, inject_truth_source_metadata,
    invoke_dispatch_host_controlled, normalize_host_endpoint, resolve_host_config,
    resolve_host_tool, resolve_live_auth, resolved_zone,
};

pub(crate) fn dispatch(args: &RulesArgs, explicit_host: Option<&str>) -> Result<DispatchOutcome> {
    let live = args.execution_options().is_some() || args.reconcile_options().is_some();
    let result = if let Some(options) = args.reconcile_options() {
        (|| {
            let host = resolve_host_config(explicit_host)?
                .context("rule reconciliation requires the original host or --host")?;
            let mut reconciler = HostRuleReconciler::new(&host, options)?;
            rules_cmd::reconcile(args, &mut reconciler)
        })()
    } else if let Some(options) = args.execution_options() {
        (|| {
            let host = resolve_host_config(explicit_host)?
                .context("live rules require a configured host or --host")?;
            let mut executor = HostRuleExecutor::new(host, options)?;
            if let Some(options) = args.poll_options() {
                let mut source = WebhookRuleSource::new(&executor.host, options)?;
                rules_cmd::poll(args, &mut executor, &mut source)
            } else if let Some(options) = args.consume_options() {
                let mut source = NativeRuleSource(NativeStreamClient::new(
                    NativeStreamConfig {
                        connector: options.connector.clone(),
                        zone: options.source_zone.clone(),
                        topic: options.topic.clone(),
                        request_id: options.request_id.clone(),
                        stream_id: options.stream_id.clone(),
                        executor_node: options.executor_node.clone(),
                        capability_token_file: options.stream_capability_token_file.clone(),
                        timeout_seconds: options.stream_timeout_seconds,
                    },
                    Some(&executor.host.endpoint),
                )?);
                ensure!(
                    source.0.stream_id() == options.stream_id
                        && source.0.connector() == options.connector
                        && source.0.zone() == options.source_zone
                        && source.0.topic() == options.topic
                        && source.0.executor_node() == options.executor_node.as_ref(),
                    "native source scope changed during preparation"
                );
                rules_cmd::consume(args, &mut executor, &mut source)
            } else {
                rules_cmd::run(args, &mut executor)
            }
        })()
    } else {
        rules_cmd::dispatch(args)
    };
    let (mut payload, exit_code, availability, truth) = match result {
        Ok(output) => {
            let uncertain = live && has_uncertain_results(&output.payload);
            (
                output.payload,
                if output.rejected {
                    if live {
                        CliExitCode::Connector
                    } else {
                        CliExitCode::Validation
                    }
                } else {
                    CliExitCode::Success
                },
                if uncertain {
                    CommandAvailability::Unknown
                } else if live {
                    CommandAvailability::LiveRuntime
                } else {
                    CommandAvailability::OfflineArtifact
                },
                if uncertain {
                    None
                } else {
                    Some(if live {
                        KnowledgeState::HostBacked
                    } else {
                        KnowledgeState::Offline
                    })
                },
            )
        }
        Err(error) => {
            let (kind, exit_code) = if let Some(failure) = error.downcast_ref::<WebhookFailure>() {
                (failure.details().0, webhook_failure_exit(*failure))
            } else if let Some(failure) = error.downcast_ref::<StreamFailure>() {
                let (kind, _, code) = failure.details();
                (kind, code)
            } else if let Some(failure) = error.downcast_ref::<LookupFailure>() {
                let (kind, _, code) = failure.description();
                (kind, code)
            } else {
                ("rules-request-failed", CliExitCode::Validation)
            };
            (
                json!({"status": "error", "command": "rules",
                    "error": {"type": kind, "message": error.to_string()}}),
                exit_code,
                if live {
                    CommandAvailability::Unavailable
                } else {
                    CommandAvailability::OfflineArtifact
                },
                if live {
                    None
                } else {
                    Some(KnowledgeState::Offline)
                },
            )
        }
    };
    CommandEnvelope::new(availability, "rules").inject_into(&mut payload);
    if let Some(truth) = truth {
        inject_truth_source_metadata(&mut payload, truth);
    } else {
        payload["_truth_source"] = json!("unavailable");
    }
    Ok(DispatchOutcome { payload, exit_code })
}

fn has_uncertain_results(payload: &serde_json::Value) -> bool {
    payload["data"]["source"]["acknowledgement_unknown"] == true
        || payload["data"]["source"]["ack_state_persisted"] == false
        || payload["data"]["source"]["cursor_commit_unknown"] == true
        || payload["data"]["results"]
            .as_array()
            .is_some_and(|results| {
                results.iter().any(|result| {
                    let reconciled = matches!(
                        result["outcome"].as_str(),
                        Some("reconciled" | "already_completed")
                    ) && result["state_persisted"] == true;
                    result["outcome"] == "outcome_unknown"
                        || (!reconciled
                            && (result["previous_outcome"] == "pending"
                                || result["previous_outcome"] == "unknown"))
                        || result["state_persisted"] == false
                })
            })
}

/// Reuses the protected invocation-inspection transport. No action authority,
/// provider input, connector discovery or source acknowledgement is involved.
struct HostRuleReconciler {
    endpoint: String,
    client: HostAdminClient,
    token: String,
}

impl HostRuleReconciler {
    fn new(host: &ResolvedHostConfig, options: &RulesReconcileOptions) -> Result<Self> {
        let endpoint = canonical_host(&host.endpoint)
            .map_err(|_| anyhow::anyhow!("invalid reconciliation host endpoint"))?;
        let client = HostAdminClient::new(&endpoint)
            .map_err(|_| anyhow::anyhow!("could not construct the reconciliation host client"))?;
        let token = read_admin_token(options.admin_token_file.as_deref())?;
        Ok(Self {
            endpoint,
            client,
            token,
        })
    }
}

impl RuleReconciler for HostRuleReconciler {
    fn host(&self) -> &str {
        &self.endpoint
    }

    fn query(
        &mut self,
        request_id: &str,
        attempt_id: Option<u64>,
    ) -> Result<fcp_host::InvocationQueryResponse> {
        Ok(query_invocation(
            &self.client,
            &fcp_host::InvocationQueryRequest {
                operation_id: request_id.to_owned(),
                attempt_id,
            },
            &self.token,
        )?)
    }
}

struct NativeRuleSource(NativeStreamClient);

impl RuleEventSource for NativeRuleSource {
    fn host(&self) -> &str {
        self.0.endpoint()
    }

    fn executor_node(&self) -> Option<&fcp_core::TailscaleNodeId> {
        self.0.executor_node()
    }

    fn poll(&mut self, limit: u32, wait_seconds: u64) -> Result<RuleEventBatch> {
        let batch = self.0.poll(limit, wait_seconds)?;
        Ok(RuleEventBatch {
            events: batch.events,
            closed: batch.closed,
            wait_expired: batch.wait_expired,
        })
    }

    fn acknowledge(&mut self, events: &[EventEnvelope]) -> Result<bool> {
        let seqs = events.iter().map(|event| event.seq).collect::<Vec<_>>();
        let cursors = events
            .iter()
            .map(|event| event.cursor.clone())
            .collect::<Vec<_>>();
        Ok(self.0.ack(&seqs, &cursors)?.upstream_notified)
    }
}

const WEBHOOK_POLL_OPERATION: &str = "webhook.events.poll";
const WEBHOOK_SOURCE_ENVELOPE_BYTES: usize = 256 * 1024;

/// Reads the receiver's authenticated operation without passing source payloads
/// through ordinary invoke history or borrowing any action credentials.
struct WebhookRuleSource {
    scope: WebhookSourceScope,
    client: HostAdminClient,
    auth: ResolvedLiveAuth,
    lease_seq: Option<u64>,
    timeout: Duration,
}

impl WebhookRuleSource {
    fn new(host: &ResolvedHostConfig, options: &RulesPollOptions) -> Result<Self> {
        if options.connector != "fcp.webhook-receiver"
            || options.endpoint_id.is_empty()
            || options.endpoint_id.len() > 512
            || options.endpoint_id.trim() != options.endpoint_id
            || options.endpoint_id.chars().any(char::is_control)
            || !(1..=60).contains(&options.source_timeout_seconds)
        {
            return Err(WebhookFailure::InvalidRequest.into());
        }
        let zone = options
            .source_zone
            .parse::<fcp_core::ZoneId>()
            .map_err(|_| WebhookFailure::InvalidRequest)?;
        let auth = resolve_live_auth(&LiveAuthArgs {
            capability_token_file: Some(options.source_capability_token_file.clone()),
            holder_key_file: options.source_holder_key_file.clone(),
            ..LiveAuthArgs::default()
        })
        .map_err(|_| WebhookFailure::Credential)?;
        let client = HostAdminClient::new(&host.endpoint).map_err(|_| WebhookFailure::Transport)?;
        Ok(Self {
            scope: WebhookSourceScope {
                host: host.endpoint.clone(),
                connector: options.connector.clone(),
                zone: zone.to_string(),
                endpoint_id: options.endpoint_id.clone(),
            },
            client,
            auth,
            lease_seq: options.source_lease_seq,
            timeout: Duration::from_secs(options.source_timeout_seconds),
        })
    }
}

impl RulePollingSource for WebhookRuleSource {
    fn scope(&self) -> &WebhookSourceScope {
        &self.scope
    }

    fn poll(
        &mut self,
        cursor: Option<&str>,
        start: PollStart,
        limit: u32,
        max_bytes: usize,
    ) -> Result<WebhookPollPage> {
        let started = Instant::now();
        if !(1..=64).contains(&limit) || !(1..=16 * 1024 * 1024).contains(&max_bytes) {
            return Err(WebhookFailure::InvalidRequest.into());
        }
        let mut input = json!({
            "endpoint_id": self.scope.endpoint_id,
            "limit": limit,
            "max_bytes": max_bytes,
        });
        if let Some(cursor) = cursor {
            input["cursor"] = json!(cursor);
        } else {
            input["start"] = json!(match start {
                PollStart::Earliest => "earliest",
                PollStart::Latest => "latest",
            });
        }
        // Each read gets a fresh identity: caching a prior empty response under
        // a stable consumer key would prevent that consumer from seeing arrivals.
        let request_id = RequestId::new(format!("req_webhook_poll_{}", uuid::Uuid::new_v4()));
        let request = HostGuardedInvokeRequest {
            max_safety_tier: SafetyTier::Safe,
            request: InvokeRequest {
                r#type: "invoke".to_owned(),
                id: request_id.clone(),
                connector_id: self
                    .scope
                    .connector
                    .parse()
                    .map_err(|_| WebhookFailure::InvalidRequest)?,
                operation: WEBHOOK_POLL_OPERATION
                    .parse()
                    .map_err(|_| WebhookFailure::InvalidRequest)?,
                zone_id: self
                    .scope
                    .zone
                    .parse()
                    .map_err(|_| WebhookFailure::InvalidRequest)?,
                input,
                capability_token: self.auth.capability_token.clone(),
                holder_proof: self
                    .auth
                    .holder_proof_for(&request_id, WEBHOOK_POLL_OPERATION)
                    .map_err(|_| WebhookFailure::Credential)?,
                context: None,
                idempotency_key: Some(format!("webhook-poll:{request_id}")),
                lease_seq: self.lease_seq,
                deadline_ms: Some(
                    u64::try_from(self.timeout.as_millis())
                        .map_err(|_| WebhookFailure::InvalidRequest)?,
                ),
                correlation_id: None,
                provenance: None,
                approval_tokens: Vec::new(),
            },
        };
        let preflight: HostPreflightResponse = webhook_source_post(
            &self.client,
            "/rpc/preflight/guarded",
            &request,
            source_remaining(started, self.timeout)?,
            WEBHOOK_SOURCE_ENVELOPE_BYTES,
        )?;
        if !preflight.allowed {
            return Err(WebhookFailure::Denied.into());
        }
        let response: InvokeResponse = webhook_source_post(
            &self.client,
            "/rpc/invoke/guarded",
            &request,
            source_remaining(started, self.timeout)?,
            max_bytes
                .checked_add(WEBHOOK_SOURCE_ENVELOPE_BYTES)
                .ok_or(WebhookFailure::InvalidRequest)?,
        )?;
        source_remaining(started, self.timeout)?;
        if response.r#type != "response" || response.id != request_id {
            return Err(WebhookFailure::InvalidResponse.into());
        }
        let value = match (response.status, response.result, response.error) {
            (InvokeStatus::Ok, Some(value), None) => value,
            (InvokeStatus::Error, None, Some(error)) => {
                return Err(WebhookFailure::from_fcp_error(&error).into());
            }
            _ => return Err(WebhookFailure::InvalidResponse.into()),
        };
        let page =
            webhook_events::decode_page(&self.scope, cursor, start, limit, max_bytes, value)?;
        source_remaining(started, self.timeout)?;
        Ok(page)
    }
}

fn source_remaining(started: Instant, timeout: Duration) -> Result<Duration> {
    timeout
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| WebhookFailure::Timeout.into())
}

/// The generic admin decoder can reflect remote error bodies and buffer an
/// unbounded response. A webhook source instead bounds the complete envelope
/// and reports only static errors, including failures during body consumption.
fn webhook_source_post<B: Serialize, T: DeserializeOwned>(
    client: &HostAdminClient,
    path: &str,
    body: &B,
    timeout: Duration,
    max_response_bytes: usize,
) -> Result<T> {
    if timeout.is_zero() {
        return Err(WebhookFailure::Timeout.into());
    }
    let body = serde_json::to_vec(body).map_err(|_| WebhookFailure::InvalidRequest)?;
    if body.len() > WEBHOOK_SOURCE_ENVELOPE_BYTES || max_response_bytes == 0 {
        return Err(WebhookFailure::InvalidRequest.into());
    }
    let response = client
        .client
        .post(format!("{}{path}", client.base_url))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .timeout(timeout)
        .body(body)
        .send()
        .map_err(|error| {
            if error.is_timeout() {
                WebhookFailure::Timeout
            } else {
                WebhookFailure::Transport
            }
        })?;
    if !response.status().is_success() {
        return Err(WebhookFailure::Http(response.status().as_u16()).into());
    }
    if response
        .content_length()
        .is_some_and(|length| length > u64::try_from(max_response_bytes).unwrap_or(u64::MAX))
    {
        return Err(WebhookFailure::ResponseTooLarge.into());
    }
    let read_limit = max_response_bytes
        .checked_add(1)
        .and_then(|limit| u64::try_from(limit).ok())
        .ok_or(WebhookFailure::InvalidRequest)?;
    let mut bytes = Vec::with_capacity(max_response_bytes.min(64 * 1024));
    response
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::TimedOut
                || error
                    .get_ref()
                    .and_then(|cause| cause.downcast_ref::<reqwest::Error>())
                    .is_some_and(reqwest::Error::is_timeout)
            {
                WebhookFailure::Timeout
            } else {
                WebhookFailure::Transport
            }
        })?;
    if bytes.len() > max_response_bytes {
        return Err(WebhookFailure::ResponseTooLarge.into());
    }
    serde_json::from_slice(&bytes).map_err(|_| WebhookFailure::InvalidResponse.into())
}

const fn webhook_failure_exit(failure: WebhookFailure) -> CliExitCode {
    match failure {
        WebhookFailure::InvalidRequest => CliExitCode::Validation,
        WebhookFailure::Credential | WebhookFailure::Denied | WebhookFailure::Http(401 | 403) => {
            CliExitCode::PolicyDenied
        }
        WebhookFailure::Transport
        | WebhookFailure::Timeout
        | WebhookFailure::InvalidResponse
        | WebhookFailure::ResponseTooLarge
        | WebhookFailure::Http(300..=399) => CliExitCode::Transport,
        WebhookFailure::Http(_)
        | WebhookFailure::ReplayGap
        | WebhookFailure::CursorExpired
        | WebhookFailure::PageTooLarge
        | WebhookFailure::SourceUnavailable => CliExitCode::Connector,
    }
}

struct PreparedRule {
    scope: ExecutionScope,
    auth: ResolvedLiveAuth,
}

struct HostRuleExecutor {
    host: ResolvedHostConfig,
    client: HostAdminClient,
    options: RulesExecutionOptions,
    prepared: BTreeMap<String, PreparedRule>,
}

impl HostRuleExecutor {
    fn new(mut host: ResolvedHostConfig, options: &RulesExecutionOptions) -> Result<Self> {
        host.endpoint = canonical_host(&host.endpoint)?;
        let client = HostAdminClient::new(&host.endpoint)?;
        Ok(Self {
            host,
            client,
            options: options.clone(),
            prepared: BTreeMap::new(),
        })
    }
}

fn canonical_host(endpoint: &str) -> Result<String> {
    let normalized = normalize_host_endpoint(endpoint)?;
    #[cfg(unix)]
    if normalized.starts_with("unix://") || normalized.starts_with('/') {
        let path = normalized.strip_prefix("unix://").unwrap_or(&normalized);
        let path = std::fs::canonicalize(path).context("cannot resolve the host socket path")?;
        let path = path.to_str().context("host socket path must be UTF-8")?;
        return Ok(format!("unix://{path}"));
    }
    let url = url::Url::parse(&normalized)?;
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

fn credential_bindings(
    values: &[String],
    flag: &str,
    names: &BTreeSet<&str>,
) -> Result<BTreeMap<String, String>> {
    let mut bindings = BTreeMap::new();
    for raw in values {
        let (name, value) = raw
            .split_once('=')
            .with_context(|| format!("{flag} requires RULE=VALUE"))?;
        let name = name.trim();
        // Never echo unknown keys: a bare base64 credential can contain '='.
        ensure!(
            names.contains(name),
            "{flag} names an unknown or disabled rule"
        );
        ensure!(!value.trim().is_empty(), "{flag} has an empty value");
        ensure!(
            bindings.insert(name.to_owned(), value.to_owned()).is_none(),
            "{flag} repeats a rule"
        );
    }
    Ok(bindings)
}

const fn tier_rank(tier: SafetyTier) -> u8 {
    match tier {
        SafetyTier::Safe => 0,
        SafetyTier::Risky => 1,
        SafetyTier::Dangerous => 2,
        SafetyTier::Critical => 3,
        SafetyTier::Forbidden => 4,
    }
}

fn require_tier(actual: SafetyTier, ceiling: SafetyTier) -> Result<()> {
    ensure!(
        ceiling != SafetyTier::Forbidden
            && actual != SafetyTier::Forbidden
            && tier_rank(actual) <= tier_rank(ceiling),
        "live operation exceeds the registered rule safety ceiling"
    );
    Ok(())
}

impl RuleExecutor for HostRuleExecutor {
    fn prepare(&mut self, rules: &[Rule]) -> Result<BTreeMap<String, ExecutionScope>> {
        ensure!(
            self.prepared.is_empty(),
            "rule authority has already been prepared"
        );
        let names = rules.iter().map(|rule| rule.name.as_str()).collect();
        let inline = credential_bindings(
            &self.options.rule_capability_token,
            "--rule-capability-token",
            &names,
        )?;
        let files = credential_bindings(
            &self.options.rule_capability_token_file,
            "--rule-capability-token-file",
            &names,
        )?;
        let keys = credential_bindings(
            &self.options.rule_holder_key_file,
            "--rule-holder-key-file",
            &names,
        )?;
        for name in inline.keys() {
            ensure!(
                !files.contains_key(name),
                "a rule has both inline and file capability tokens"
            );
        }
        for name in keys.keys() {
            ensure!(
                inline.contains_key(name) || files.contains_key(name),
                "a rule holder key requires that rule's explicit capability token"
            );
        }
        let client = &self.client;
        let (catalog, _) = client.catalog(None)?;
        let zone = resolved_zone(self.options.zone.as_deref(), &self.host);
        let zone = zone
            .parse::<fcp_core::ZoneId>()
            .context("invalid reactive execution zone")?
            .to_string();
        let mut targets = BTreeMap::new();
        let mut default_connectors = BTreeSet::new();
        for rule in rules {
            let connector = catalog
                .resolve_connector(&rule.action.connector)
                .map_err(|_| {
                    anyhow::anyhow!("reactive connector selector did not resolve uniquely")
                })?;
            let introspection = client.introspect(connector.summary.id.as_str())?;
            let operation = resolve_host_tool(&introspection.tools, &rule.action.operation)
                .map_err(|_| {
                    anyhow::anyhow!("reactive operation selector did not resolve uniquely")
                })?;
            require_tier(operation.safety_tier, rule.safety_tier)?;
            let connector_id = connector.summary.id.to_string();
            let operation_id = operation.name.clone();
            // Reject invalid canonical identifiers before any rule can execute.
            connector_id.parse::<fcp_core::ConnectorId>()?;
            operation_id.parse::<fcp_core::OperationId>()?;
            if !inline.contains_key(&rule.name) && !files.contains_key(&rule.name) {
                default_connectors.insert(connector_id.clone());
            }
            targets.insert(rule.name.clone(), (connector_id, operation_id));
        }
        ensure!(
            default_connectors.len() <= 1,
            "default credentials may cover only one connector; assign --rule-capability-token-file RULE=PATH to separately authorized rules"
        );
        let default_args = LiveAuthArgs {
            capability_token: self.options.capability_token.clone(),
            capability_token_file: self.options.capability_token_file.clone(),
            holder_key_file: self.options.holder_key_file.clone(),
            approval_token: self.options.approval_token.clone(),
            approval_token_file: self.options.approval_token_file.clone(),
        };
        let default_requested = default_args.capability_token.is_some()
            || default_args.capability_token_file.is_some()
            || default_args.holder_key_file.is_some();
        let default_auth = if default_requested || !default_connectors.is_empty() {
            Some(
                resolve_live_auth(&default_args)
                    .map_err(|error| anyhow::anyhow!(error.message()))?,
            )
        } else {
            None
        };
        let mut prepared = BTreeMap::new();
        let mut scopes = BTreeMap::new();
        for rule in rules {
            let auth = if inline.contains_key(&rule.name) || files.contains_key(&rule.name) {
                let args = LiveAuthArgs {
                    capability_token: inline.get(&rule.name).cloned(),
                    capability_token_file: files.get(&rule.name).map(PathBuf::from),
                    // Different capabilities never inherit the default holder key.
                    holder_key_file: keys.get(&rule.name).map(PathBuf::from),
                    approval_token: default_args.approval_token.clone(),
                    approval_token_file: default_args.approval_token_file.clone(),
                };
                resolve_live_auth(&args).map_err(|error| anyhow::anyhow!(error.message()))?
            } else {
                default_auth
                    .clone()
                    .context("rule is missing a capability token")?
            };
            if let Some(principal) = &self.options.principal {
                ensure!(
                    auth.principal_hint.as_deref() == Some(principal.as_str()),
                    "reactive principal must match the capability's principal"
                );
            }
            let (connector, operation) = targets
                .remove(&rule.name)
                .context("rule has no resolved target")?;
            let scope = ExecutionScope {
                host: self.host.endpoint.clone(),
                zone: zone.clone(),
                principal: self
                    .options
                    .principal
                    .clone()
                    .or_else(|| auth.principal_hint.clone()),
                connector,
                operation,
            };
            scopes.insert(rule.name.clone(), scope.clone());
            prepared.insert(rule.name.clone(), PreparedRule { scope, auth });
        }
        self.prepared = prepared;
        Ok(scopes)
    }

    fn invoke(
        &mut self,
        rule: &Rule,
        inputs: &BTreeMap<String, String>,
        idempotency_key: &str,
        provenance: Option<&Provenance>,
        admit: &mut dyn FnMut(&str, &str) -> Result<()>,
    ) -> Result<InvocationResult> {
        let prepared = self
            .prepared
            .get(&rule.name)
            .context("rule authority was not prepared")?;
        let args = InvokeArgs {
            connector: prepared.scope.connector.clone(),
            operation: prepared.scope.operation.clone(),
            input: Some(serde_json::to_string(inputs)?),
            file: None,
            stdin: false,
            set: Vec::new(),
            zone: Some(prepared.scope.zone.clone()),
            principal: prepared.scope.principal.clone(),
            idempotency_key: Some(idempotency_key.to_owned()),
            lease_seq: self.options.lease_seq,
            deadline_ms: self.options.deadline_ms,
            auth: LiveAuthArgs::default(),
        };
        let mut guard = InvocationGuard {
            auth: &prepared.auth,
            client: &self.client,
            scope: &prepared.scope,
            max_safety_tier: rule.safety_tier,
            provenance,
            admit,
        };
        let outcome = invoke_dispatch_host_controlled(
            "invoke",
            &args,
            &self.host,
            None,
            None,
            Some(&mut guard),
        )?;
        Ok(InvocationResult {
            success: outcome.exit_code == CliExitCode::Success,
            payload: outcome.payload,
        })
    }
}

/// Only the live rules bridge constructs this guard. It ties the ordinary invoke
/// path to frozen authority and a durable reservation immediately before I/O.
pub(crate) struct InvocationGuard<'a> {
    pub(crate) auth: &'a ResolvedLiveAuth,
    pub(crate) client: &'a HostAdminClient,
    scope: &'a ExecutionScope,
    pub(crate) max_safety_tier: SafetyTier,
    pub(crate) provenance: Option<&'a Provenance>,
    admit: &'a mut dyn FnMut(&str, &str) -> Result<()>,
}

impl InvocationGuard<'_> {
    pub(crate) fn validate_target(
        &self,
        host: &str,
        connector: &str,
        operation: &str,
        zone: &str,
        principal: Option<&str>,
        safety: SafetyTier,
    ) -> Result<()> {
        ensure!(
            self.scope.host == host
                && self.scope.connector == connector
                && self.scope.operation == operation
                && self.scope.zone == zone
                && self.scope.principal.as_deref() == principal,
            "live invocation no longer matches the prepared rule scope"
        );
        require_tier(safety, self.max_safety_tier)
    }

    pub(crate) fn reserve(&mut self, request: &InvokeRequest) -> Result<()> {
        ensure!(
            request.connector_id.as_str() == self.scope.connector
                && request.operation.as_str() == self.scope.operation
                && request.zone_id.as_str() == self.scope.zone
                && request.provenance.as_ref() == self.provenance,
            "prepared rule request changed before reservation"
        );
        let key = request
            .idempotency_key
            .as_deref()
            .context("reactive invoke requires an idempotency key")?;
        (self.admit)(&request.id.to_string(), key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_unknown_results_never_claim_confirmed_live_execution() {
        for result in [
            json!({"outcome": "outcome_unknown"}),
            json!({"outcome": "duplicate", "previous_outcome": "pending"}),
            json!({"outcome": "duplicate", "previous_outcome": "unknown"}),
            json!({"outcome": "executed", "state_persisted": false}),
        ] {
            assert!(has_uncertain_results(&json!({"data": {"results": [
                {"outcome": "executed", "state_persisted": true}, result
            ]}})));
        }
        assert!(!has_uncertain_results(&json!({"data": {"results": [
            {"outcome": "executed", "state_persisted": true},
            {"outcome": "duplicate", "previous_outcome": "completed"}
        ]}})));
        assert!(has_uncertain_results(&json!({
            "data": {"source": {"acknowledgement_unknown": true}}
        })));
        assert!(has_uncertain_results(&json!({
            "data": {"source": {"ack_state_persisted": false}}
        })));
        assert!(has_uncertain_results(&json!({
            "data": {"source": {"cursor_commit_unknown": true}}
        })));
    }

    #[test]
    fn credential_bindings_reject_unknown_keys_without_exposing_tokens() {
        let names = BTreeSet::from(["known"]);
        let secret = "not-a-rule-secret==";
        let error = credential_bindings(&[secret.to_owned()], "--rule-capability-token", &names)
            .unwrap_err();
        assert!(!error.to_string().contains(secret));
        assert!(
            credential_bindings(&["known=one".into(), "known=two".into()], "flag", &names).is_err()
        );
        assert!(credential_bindings(&["known=".into()], "flag", &names).is_err());
        assert_eq!(
            credential_bindings(&["known=abc==".into()], "flag", &names).unwrap()["known"],
            "abc=="
        );
    }

    #[test]
    fn live_tiers_cannot_exceed_registration_or_admit_forbidden() {
        let tiers = [
            SafetyTier::Safe,
            SafetyTier::Risky,
            SafetyTier::Dangerous,
            SafetyTier::Critical,
            SafetyTier::Forbidden,
        ];
        for (actual_index, actual) in tiers.iter().enumerate() {
            for (ceiling_index, ceiling) in tiers.iter().enumerate() {
                assert_eq!(
                    require_tier(*actual, *ceiling).is_ok(),
                    actual_index < 4 && ceiling_index < 4 && actual_index <= ceiling_index
                );
            }
        }
    }

    #[test]
    fn equivalent_http_endpoints_share_replay_scope() {
        assert_eq!(
            canonical_host("http://LOCALHOST:80/").unwrap(),
            canonical_host("localhost").unwrap()
        );
        assert!(canonical_host("https://user:secret@example.com").is_err());
        assert!(canonical_host("https://example.com?token=secret").is_err());
        assert_ne!(
            canonical_host("https://example.com/a").unwrap(),
            canonical_host("https://example.com/b").unwrap()
        );
    }

    fn source_http_server<F>(respond: F) -> (HostAdminClient, std::thread::JoinHandle<()>)
    where
        F: FnOnce(&mut std::net::TcpStream, serde_json::Value) + Send + 'static,
    {
        use std::io::{BufRead, BufReader};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let client = HostAdminClient::new(&endpoint).unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let request = {
                let mut reader = BufReader::new(&mut socket);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert!(line.starts_with("POST /rpc/"));
                let mut length = None;
                let mut header_bytes = line.len();
                loop {
                    line.clear();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    header_bytes += line.len();
                    assert!(header_bytes < 64 * 1024);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':')
                        && name.eq_ignore_ascii_case("content-length")
                    {
                        length = Some(value.trim().parse::<usize>().unwrap());
                    }
                }
                let length = length.expect("source POST must use a bounded serialized body");
                assert!(length <= WEBHOOK_SOURCE_ENVELOPE_BYTES);
                let mut bytes = vec![0; length];
                reader.read_exact(&mut bytes).unwrap();
                serde_json::from_slice(&bytes).unwrap()
            };
            respond(&mut socket, request);
        });
        (client, server)
    }

    #[test]
    fn reconciled_result_truth_requires_a_confirmed_journal_write() {
        for previous in ["pending", "unknown"] {
            for outcome in ["reconciled", "already_completed"] {
                let result = json!({
                    "outcome": outcome, "previous_outcome": previous,
                    "state_persisted": true,
                });
                assert!(!has_uncertain_results(
                    &json!({"data": {"results": [result.clone()]}})
                ));
                let mut failed = result;
                failed["state_persisted"] = json!(false);
                assert!(has_uncertain_results(
                    &json!({"data": {"results": [failed]}})
                ));
            }
        }
    }

    #[test]
    fn reconciliation_bridge_uses_only_the_selected_protected_host_query() {
        use std::io::{BufRead, BufReader, Write};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let mut reader = HostRuleReconciler {
            endpoint: endpoint.clone(),
            client: HostAdminClient::new(&endpoint).unwrap(),
            token: "private-admin-token".into(),
        };
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut line = String::new();
            let mut input = BufReader::new(&mut socket);
            input.read_line(&mut line).unwrap();
            assert_eq!(line, "POST /rpc/admin/invocations HTTP/1.1\r\n");
            let mut headers = BTreeMap::new();
            loop {
                line.clear();
                assert!(input.read_line(&mut line).unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
                let (name, value) = line.split_once(':').unwrap();
                headers.insert(name.to_ascii_lowercase(), value.trim().to_owned());
            }
            assert_eq!(headers["authorization"], "Bearer private-admin-token");
            assert_eq!(headers["x-fcp-zone"], "z:owner");
            let length: usize = headers["content-length"].parse().unwrap();
            assert!(length < 1024);
            let mut body = vec![0; length];
            input.read_exact(&mut body).unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                json!({"operation_id": "retained-request", "attempt_id": 7}),
            );
            drop(input);
            let response = br#"{"invocation":null,"mesh_invocation":null,"host_job_active":false}"#;
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response.len(),
            )
            .unwrap();
            socket.write_all(response).unwrap();
        });
        assert_eq!(reader.host(), endpoint);
        let response = reader.query("retained-request", Some(7)).unwrap();
        assert!(response.invocation.is_none());
        assert!(!response.host_job_active);
        server.join().unwrap();
    }

    #[test]
    fn reconciliation_bridge_refuses_redirects_and_redacts_remote_error_bodies() {
        use std::io::Write;

        for status in [302, 401, 403, 500] {
            let (client, server) = source_http_server(move |socket, _| {
                let secret = "private-host-error-and-bearer-material";
                let _ = write!(
                    socket,
                    "HTTP/1.1 {status} Error\r\nLocation: http://127.0.0.1:1/other\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{secret}",
                    secret.len(),
                );
            });
            let mut reader = HostRuleReconciler {
                endpoint: client.endpoint.clone(),
                client,
                token: "private-admin-token".into(),
            };
            let error = reader.query("retained-request", None).unwrap_err();
            assert!(matches!(
                error.downcast_ref::<LookupFailure>(),
                Some(LookupFailure::Http(actual)) if *actual == status
            ));
            assert!(!error.to_string().contains("private-"));
            server.join().unwrap();
        }
    }

    #[test]
    fn reconciliation_bridge_bounds_and_validates_the_complete_host_response() {
        use std::io::Write;

        for response in [
            "HTTP/1.1 200 OK\r\nContent-Length: 524289\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nnot-json!",
        ] {
            let (client, server) = source_http_server(move |socket, _| {
                let _ = socket.write_all(response.as_bytes());
            });
            let mut reader = HostRuleReconciler {
                endpoint: client.endpoint.clone(),
                client,
                token: "private-admin-token".into(),
            };
            let error = reader.query("retained-request", Some(7)).unwrap_err();
            assert!(matches!(
                error.downcast_ref::<LookupFailure>(),
                Some(LookupFailure::ResponseTooLarge | LookupFailure::InvalidResponse)
            ));
            server.join().unwrap();
        }
    }

    #[test]
    fn webhook_transport_reads_complete_bounded_json() {
        use std::io::Write;

        let (client, server) = source_http_server(|socket, request| {
            assert_eq!(request, json!({"cursor": "opaque"}));
            write!(
                socket,
                "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{{\"ok\":true}}"
            )
            .unwrap();
        });
        let value: serde_json::Value = webhook_source_post(
            &client,
            "/rpc/invoke/guarded",
            &json!({"cursor": "opaque"}),
            Duration::from_secs(2),
            11,
        )
        .unwrap();
        assert_eq!(value, json!({"ok": true}));
        server.join().unwrap();
    }

    #[test]
    fn webhook_transport_bounds_declared_and_streamed_response_bodies() {
        use std::io::Write;

        for response in [
            "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\nConnection: close\r\n\r\n",
            "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n01234567890123456789012345678901234",
        ] {
            let (client, server) = source_http_server(move |socket, _| {
                let _ = socket.write_all(response.as_bytes());
            });
            let error = webhook_source_post::<_, serde_json::Value>(
                &client,
                "/rpc/invoke/guarded",
                &json!({}),
                Duration::from_secs(2),
                32,
            )
            .unwrap_err();
            assert_eq!(
                error.downcast_ref::<WebhookFailure>(),
                Some(&WebhookFailure::ResponseTooLarge)
            );
            server.join().unwrap();
        }
    }

    #[test]
    fn webhook_transport_never_follows_redirects_or_reflects_error_bodies() {
        use std::io::Write;

        for status in [302, 403, 500] {
            let (client, server) = source_http_server(move |socket, _| {
                let secret = "private-provider-payload-or-capability";
                let _ = write!(
                    socket,
                    "HTTP/1.1 {status} Error\r\nLocation: http://127.0.0.1:1/private\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{secret}",
                    secret.len()
                );
            });
            let error = webhook_source_post::<_, serde_json::Value>(
                &client,
                "/rpc/invoke/guarded",
                &json!({"capability_token": "private-source-authority"}),
                Duration::from_secs(2),
                1024,
            )
            .unwrap_err();
            assert_eq!(
                error.downcast_ref::<WebhookFailure>(),
                Some(&WebhookFailure::Http(status))
            );
            assert!(!error.to_string().contains("private-"));
            server.join().unwrap();
        }
    }

    #[test]
    fn webhook_transport_rejects_malformed_json_without_body_disclosure() {
        use std::io::Write;

        let (client, server) = source_http_server(|socket, _| {
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nprivate-provider-payload");
        });
        let error = webhook_source_post::<_, serde_json::Value>(
            &client,
            "/rpc/invoke/guarded",
            &json!({}),
            Duration::from_secs(2),
            1024,
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<WebhookFailure>(),
            Some(&WebhookFailure::InvalidResponse)
        );
        assert!(!error.to_string().contains("private-provider"));
        server.join().unwrap();
    }

    #[test]
    fn webhook_transport_deadline_includes_body_consumption() {
        use std::io::Write;

        let (client, server) = source_http_server(|socket, _| {
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\n");
            std::thread::sleep(Duration::from_millis(750));
            let _ = socket.write_all(b"{\"ok\":true}");
        });
        let error = webhook_source_post::<_, serde_json::Value>(
            &client,
            "/rpc/invoke/guarded",
            &json!({}),
            Duration::from_millis(500),
            1024,
        )
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<WebhookFailure>(),
            Some(&WebhookFailure::Timeout)
        );
        server.join().unwrap();
    }

    #[test]
    fn webhook_poll_uses_one_deadline_across_source_phases() {
        let started = Instant::now().checked_sub(Duration::from_secs(2)).unwrap();
        let error = source_remaining(started, Duration::from_secs(1)).unwrap_err();
        assert_eq!(
            error.downcast_ref::<WebhookFailure>(),
            Some(&WebhookFailure::Timeout)
        );
        assert!(source_remaining(Instant::now(), Duration::from_secs(1)).is_ok());
    }

    #[test]
    fn webhook_poll_preflight_uses_only_source_authority_and_stops_on_denial() {
        use std::io::Write;

        for cursor in [None, Some("saved_source_cursor")] {
            let source_capability = fcp_core::CapabilityToken::test_token();
            let expected_capability = serde_json::to_value(&source_capability).unwrap();
            let (client, server) = source_http_server(move |socket, body| {
                let guarded: HostGuardedInvokeRequest = serde_json::from_value(body).unwrap();
                assert_eq!(guarded.max_safety_tier, SafetyTier::Safe);
                let request = guarded.request;
                assert_eq!(request.connector_id.as_str(), "fcp.webhook-receiver");
                assert_eq!(request.operation.as_str(), WEBHOOK_POLL_OPERATION);
                assert_eq!(request.zone_id.as_str(), "z:work");
                assert_eq!(
                    serde_json::to_value(request.capability_token).unwrap(),
                    expected_capability
                );
                assert!(request.approval_tokens.is_empty());
                assert!(request.provenance.is_none());
                assert_eq!(request.lease_seq, Some(17));
                assert_eq!(request.input["endpoint_id"], "endpoint-one");
                assert_eq!(request.input["limit"], 4);
                assert_eq!(request.input["max_bytes"], 4096);
                if let Some(cursor) = cursor {
                    assert_eq!(request.input["cursor"], cursor);
                    assert!(request.input.get("start").is_none());
                } else {
                    assert_eq!(request.input["start"], "earliest");
                    assert!(request.input.get("cursor").is_none());
                }
                let response = serde_json::to_vec(&HostPreflightResponse::denied(
                    "private-source-policy-detail",
                ))
                .unwrap();
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                )
                .unwrap();
                socket.write_all(&response).unwrap();
            });
            let mut source = WebhookRuleSource {
                scope: WebhookSourceScope {
                    host: client.endpoint.clone(),
                    connector: "fcp.webhook-receiver".into(),
                    zone: "z:work".into(),
                    endpoint_id: "endpoint-one".into(),
                },
                client,
                auth: ResolvedLiveAuth::for_test_token(source_capability),
                lease_seq: Some(17),
                timeout: Duration::from_secs(2),
            };
            let error = source
                .poll(cursor, PollStart::Earliest, 4, 4096)
                .unwrap_err();
            assert_eq!(
                error.downcast_ref::<WebhookFailure>(),
                Some(&WebhookFailure::Denied)
            );
            assert!(!error.to_string().contains("private-source-policy-detail"));
            server.join().unwrap();
        }
    }
}
