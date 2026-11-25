//! Pin connector authority and bind MCP calls to host invocations.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, bail, ensure};
use clap::Args;
use serde::Serialize;

use crate::serve_mcp::McpCallContext;
use crate::serve_mcp::cancellation::{self, CancelAttempt};
use crate::{
    CancelReason, CapabilityToken, CleanupBehavior, HostAdminClient, HostCancellationRequest,
    HostCancellationResponse, HostConnectorCatalog, HostConnectorRecord, InvokeRequest,
    InvokeResponse, LiveAuthArgs, LiveAuthError, ResolvedLiveAuth, host_invoke_http_timeout,
    parse_capability_token_bytes, parse_capability_token_str, resolve_live_auth,
};

const MAX_CANCELLATION_TOKEN_BYTES: usize = 64 * 1024;
const MAX_CANCELLATION_RESPONSE_BYTES: u64 = 64 * 1024;
const CANCELLATION_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);
const CANCEL_SELF_PATH: &str = "/rpc/cancel-self";

#[cfg(test)]
#[path = "serve_mcp_host/tests.rs"]
mod tests;

/// Execution-only credentials. Each connector supplies an independent group.
#[derive(Args, Clone, Default, Serialize)]
pub(crate) struct ConnectorAuthArgs {
    /// Capability for one connector; repeat for different connectors.
    #[arg(long, value_name = "CONNECTOR=TOKEN")]
    #[serde(skip_serializing)]
    connector_capability_token: Vec<String>,

    /// Capability file for one connector; repeat for different connectors.
    #[arg(long, value_name = "CONNECTOR=PATH")]
    #[serde(skip_serializing)]
    connector_capability_token_file: Vec<String>,

    /// Holder signing key for the same connector's holder-bound capability.
    #[arg(long, value_name = "CONNECTOR=PATH")]
    #[serde(skip_serializing)]
    connector_holder_key_file: Vec<String>,

    /// Approval for one connector; repeat for multiple approvals.
    #[arg(long, value_name = "CONNECTOR=JSON")]
    #[serde(skip_serializing)]
    connector_approval_token: Vec<String>,

    /// Approval file for one connector; repeat for multiple approvals.
    #[arg(long, value_name = "CONNECTOR=PATH")]
    #[serde(skip_serializing)]
    connector_approval_token_file: Vec<String>,
}

impl std::fmt::Debug for ConnectorAuthArgs {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectorAuthArgs")
            .field("capability_tokens", &self.connector_capability_token.len())
            .field(
                "capability_files",
                &self.connector_capability_token_file.len(),
            )
            .field("holder_keys", &self.connector_holder_key_file.len())
            .field("approvals", &self.connector_approval_token.len())
            .field("approval_files", &self.connector_approval_token_file.len())
            .finish()
    }
}

impl ConnectorAuthArgs {
    pub(crate) fn is_present(&self) -> bool {
        !self.connector_capability_token.is_empty()
            || !self.connector_capability_token_file.is_empty()
            || !self.connector_holder_key_file.is_empty()
            || !self.connector_approval_token.is_empty()
            || !self.connector_approval_token_file.is_empty()
    }
}

/// Resolve aliases once. Refreshes can withdraw tools but cannot assign these
/// credentials to a newly discovered or replacement canonical connector identity.
pub(crate) struct McpAuthorityRegistry {
    bindings: BTreeMap<String, LiveAuthArgs>,
}

impl McpAuthorityRegistry {
    pub(crate) fn resolve(
        defaults: &LiveAuthArgs,
        args: &ConnectorAuthArgs,
        catalog: &HostConnectorCatalog,
        selected: &[HostConnectorRecord],
        zone: &str,
        principal: Option<&str>,
    ) -> std::result::Result<Self, LiveAuthError> {
        let eligible = selected
            .iter()
            .filter(|connector| connector.summary.enabled)
            .map(|connector| connector.summary.id.as_str())
            .collect::<BTreeSet<_>>();
        let parse = |values: &[String], flag, repeated| {
            parse_connector_bindings(values, flag, repeated, catalog, &eligible)
        };
        let tokens = parse(
            &args.connector_capability_token,
            "--connector-capability-token",
            false,
        )?;
        let files = parse(
            &args.connector_capability_token_file,
            "--connector-capability-token-file",
            false,
        )?;
        let holders = parse(
            &args.connector_holder_key_file,
            "--connector-holder-key-file",
            false,
        )?;
        let approvals = parse(
            &args.connector_approval_token,
            "--connector-approval-token",
            true,
        )?;
        let approval_files = parse(
            &args.connector_approval_token_file,
            "--connector-approval-token-file",
            true,
        )?;
        let explicit = tokens
            .keys()
            .chain(files.keys())
            .chain(holders.keys())
            .chain(approvals.keys())
            .chain(approval_files.keys())
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut bindings = BTreeMap::new();
        for id in explicit {
            if tokens.contains_key(&id) == files.contains_key(&id) {
                return Err(invalid_mcp_auth(
                    "Each explicit MCP connector needs exactly one capability source; credential groups never inherit the default token, holder key or approvals.",
                ));
            }
            let auth = LiveAuthArgs {
                capability_token: tokens.get(&id).map(|values| values[0].clone()),
                capability_token_file: files.get(&id).map(|values| PathBuf::from(&values[0])),
                holder_key_file: holders.get(&id).map(|values| PathBuf::from(&values[0])),
                approval_token: approvals.get(&id).cloned().unwrap_or_default(),
                approval_token_file: approval_files
                    .get(&id)
                    .into_iter()
                    .flatten()
                    .map(PathBuf::from)
                    .collect(),
            };
            validate_mcp_credentials(&auth, zone, principal)?;
            bindings.insert(id, auth);
        }
        if defaults.is_present() {
            // Even unused supplied credentials must be valid. Defaults cannot
            // serve multiple independent, instance-bound connector runtimes.
            validate_mcp_credentials(defaults, zone, principal)?;
            let unassigned = eligible
                .iter()
                .filter(|id| !bindings.contains_key(**id))
                .copied()
                .collect::<Vec<_>>();
            if unassigned.len() > 1 {
                return Err(invalid_mcp_auth(
                    "Default MCP credentials require one unassigned connector. Select a connector or use --connector-capability-token-file CONNECTOR=PATH for independent connector credentials.",
                ));
            }
            if let Some(id) = unassigned.first() {
                bindings.insert((*id).to_owned(), defaults.clone());
            }
        }
        if bindings.is_empty() {
            return Err(invalid_mcp_auth(
                "No enabled selected connector has MCP credentials. Provide a connector capability binding or select one connector with default credentials.",
            ));
        }
        Ok(Self { bindings })
    }

    pub(crate) fn contains(&self, canonical_id: &str) -> bool {
        self.bindings.contains_key(canonical_id)
    }

    pub(crate) fn get(&self, canonical_id: &str) -> Option<&LiveAuthArgs> {
        self.bindings.get(canonical_id)
    }
}

fn invalid_mcp_auth(message: impl Into<String>) -> LiveAuthError {
    LiveAuthError::InvalidMcpAuth {
        message: message.into(),
    }
}

pub(crate) fn redacted_auth_error(error: &LiveAuthError) -> LiveAuthError {
    invalid_mcp_auth(format!(
        "MCP credentials are invalid ({}).",
        error.error_type()
    ))
}

fn parse_connector_bindings(
    values: &[String],
    flag: &str,
    repeated: bool,
    catalog: &HostConnectorCatalog,
    eligible: &BTreeSet<&str>,
) -> std::result::Result<BTreeMap<String, Vec<String>>, LiveAuthError> {
    let mut bindings: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for binding in values {
        let (selector, value) = binding
            .split_once('=')
            .ok_or_else(|| invalid_mcp_auth(format!("{flag} requires CONNECTOR=VALUE.")))?;
        if selector.trim().is_empty() || value.trim().is_empty() {
            return Err(invalid_mcp_auth(format!(
                "{flag} requires a nonempty connector and credential value."
            )));
        }
        // A malformed credential may itself contain '='. Never echo an unknown
        // selector, raw value, path or nested parser error into diagnostics.
        let connector = catalog.resolve_connector(selector).map_err(|_| {
            invalid_mcp_auth(format!("{flag} must select one discovered connector."))
        })?;
        let id = connector.summary.id.as_str();
        if !eligible.contains(id) {
            return Err(invalid_mcp_auth(format!(
                "{flag} must select an enabled connector within this MCP session."
            )));
        }
        let entries = bindings.entry(id.to_owned()).or_default();
        if !repeated && !entries.is_empty() {
            return Err(invalid_mcp_auth(format!(
                "{flag} was supplied more than once for the same canonical connector."
            )));
        }
        entries.push(value.to_owned());
    }
    Ok(bindings)
}

fn validate_mcp_credentials(
    args: &LiveAuthArgs,
    zone: &str,
    principal: Option<&str>,
) -> std::result::Result<(), LiveAuthError> {
    let auth = resolve_live_auth(args).map_err(|error| redacted_auth_error(&error))?;
    validate_invocation_scope(&auth, zone, principal)
        .map_err(|error| invalid_mcp_auth(error.to_string()))
}

fn validate_invocation_scope(
    auth: &ResolvedLiveAuth,
    zone: &str,
    principal: Option<&str>,
) -> Result<()> {
    let claims = auth
        .capability_token
        .raw()
        .claims_unverified()
        .map_err(|_| anyhow::anyhow!("Invalid MCP invocation capability claims"))?;
    // These checks reject inconsistent inputs, not authenticate tokens. The
    // host verifies signature, instance, grants, expiry and revocation.
    ensure!(
        claims.get_zone_id() == Some(zone),
        "MCP invocation capability must match the execution zone"
    );
    let owner = claims
        .get_subject()
        .or_else(|| claims.get_principal_id())
        .map(str::trim)
        .filter(|owner| !owner.is_empty());
    ensure!(
        principal.is_none_or(|principal| Some(principal.trim()) == owner),
        "MCP principal must match the invocation capability owner"
    );
    Ok(())
}

#[derive(Args, Clone, Debug, Default, Serialize)]
pub(crate) struct CancellationArgs {
    /// Owner's host.cancel-self capability without a holder-node binding.
    #[arg(
        long,
        value_name = "TOKEN",
        conflicts_with = "cancel_capability_token_file"
    )]
    #[serde(skip_serializing)]
    cancel_capability_token: Option<String>,

    /// Read the owner's host.cancel-self capability from a base64, JSON, or raw CBOR file (64 KiB maximum).
    #[arg(long, value_name = "PATH", conflicts_with = "cancel_capability_token")]
    cancel_capability_token_file: Option<PathBuf>,
}

impl CancellationArgs {
    pub(crate) fn resolve(&self) -> Result<Option<CapabilityToken>> {
        let token = match (
            self.cancel_capability_token.as_deref(),
            self.cancel_capability_token_file.as_deref(),
        ) {
            (None, None) => return Ok(None),
            (Some(_), Some(_)) => bail!("Specify one cancellation capability source"),
            (Some(raw), None) => {
                ensure!(
                    raw.len() <= MAX_CANCELLATION_TOKEN_BYTES,
                    "Cancellation capability exceeds the 64 KiB limit"
                );
                parse_capability_token_str(raw, "--cancel-capability-token")
            }
            (None, Some(path)) => {
                let file = std::fs::File::open(path)
                    .map_err(|_| anyhow::anyhow!("Cannot open cancellation capability file"))?;
                let mut bytes = zeroize::Zeroizing::new(Vec::new());
                file.take((MAX_CANCELLATION_TOKEN_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(|_| anyhow::anyhow!("Cannot read cancellation capability file"))?;
                ensure!(
                    bytes.len() <= MAX_CANCELLATION_TOKEN_BYTES,
                    "Cancellation capability exceeds the 64 KiB limit"
                );
                parse_capability_token_bytes(&bytes, "--cancel-capability-token-file")
            }
        }
        .map_err(|_| anyhow::anyhow!("Invalid cancellation capability encoding"))?;
        let claims = token
            .raw()
            .claims_unverified()
            .map_err(|_| anyhow::anyhow!("Invalid cancellation capability claims"))?;
        // These checks only reject inconsistent inputs. The selected host still
        // verifies signature, persisted issuance, expiry, revocation and owner.
        ensure!(
            claims.get_capability_id() == Some("host.cancel-self"),
            "Owner-scoped cancellation requires a host.cancel-self capability"
        );
        ensure!(
            claims.get_holder_node().is_none(),
            "The host cancellation endpoint does not accept holder-bound capabilities"
        );
        Ok(Some(token))
    }
}

pub(crate) struct McpInvocationControl {
    context: McpCallContext,
    scope_salt: String,
    cancellation_token: Option<CapabilityToken>,
}

impl McpInvocationControl {
    pub(crate) fn new(context: McpCallContext, args: &CancellationArgs) -> Result<Self> {
        let control = Self {
            context,
            // JSON-RPC IDs can be reused, and identical payloads are independent
            // tool calls. Neither is an execution identity or a replay key.
            scope_salt: format!("mcp:{}", uuid::Uuid::new_v4()),
            cancellation_token: args.resolve()?,
        };
        control.checkpoint()?;
        Ok(control)
    }

    pub(crate) fn scope_salt(&self) -> &str {
        &self.scope_salt
    }

    pub(crate) fn checkpoint(&self) -> Result<()> {
        ensure!(
            !self.context.is_cancelled(),
            "MCP tool call was cancelled before the next host phase"
        );
        Ok(())
    }

    pub(crate) fn validate_authority(
        &self,
        auth: &ResolvedLiveAuth,
        zone: &str,
        asserted_principal: Option<&str>,
    ) -> Result<()> {
        // Credential files may rotate after startup. Recheck scope on every
        // call even when owner-scoped cancellation was not configured.
        validate_invocation_scope(auth, zone, asserted_principal)?;
        let Some(token) = &self.cancellation_token else {
            return Ok(());
        };
        let cancel = token
            .raw()
            .claims_unverified()
            .map_err(|_| anyhow::anyhow!("Invalid MCP cancellation capability claims"))?;
        let invoke = auth
            .capability_token
            .raw()
            .claims_unverified()
            .map_err(|_| anyhow::anyhow!("Invalid MCP invocation capability claims"))?;
        let invoke_owner = invoke
            .get_subject()
            .or_else(|| invoke.get_principal_id())
            .map(str::trim)
            .filter(|owner| !owner.is_empty());
        let cancel_owner = cancel
            .get_subject()
            .or_else(|| cancel.get_principal_id())
            .map(str::trim)
            .filter(|owner| !owner.is_empty());
        ensure!(
            invoke_owner.is_some() && invoke_owner == cancel_owner,
            "MCP invocation and cancellation capabilities must have the same principal"
        );
        ensure!(
            asserted_principal.is_none_or(|principal| Some(principal.trim()) == invoke_owner),
            "MCP principal must match the invocation and cancellation capability owner"
        );
        // The host currently enforces owner-scoped cancellation. MCP narrows its
        // session further, so a token for another zone is never silently used.
        ensure!(
            invoke.get_zone_id() == Some(zone) && cancel.get_zone_id() == Some(zone),
            "MCP invocation and cancellation capabilities must match the execution zone"
        );
        Ok(())
    }

    pub(crate) fn invoke(
        &self,
        client: &HostAdminClient,
        request: &InvokeRequest,
    ) -> Result<InvokeResponse> {
        self.checkpoint()?;
        let Some(token) = &self.cancellation_token else {
            // Local cancellation still suppresses results and prevents queued
            // work. Remote execution is bounded by the existing host deadline.
            return client.invoke(request);
        };
        let cancellation_request = HostCancellationRequest {
            operation_id: request.id.to_string(),
            reason: CancelReason::AgentAbort {
                reason: "MCP client cancelled the call or closed the transport".to_owned(),
            },
            cleanup: CleanupBehavior::BestEffort,
            return_partial: false,
            capability_token: Some(token.clone()),
        };
        let deadline = Instant::now() + host_invoke_http_timeout(request.deadline_ms);
        let settlement = CancellationSettlement::default();
        cancellation::run(
            &self.context,
            || {
                // Close the race between preparation and sending the provider
                // invocation. A later cancellation is handled by the monitor.
                self.checkpoint()?;
                let result = client.invoke(request);
                if result.is_err() && self.context.is_cancelled() {
                    // An HTTP failure does not end the host-owned execution.
                    // Retain cancellation through admission/registration races
                    // until acknowledged, rejected, or the original bound ends.
                    settlement.wait_until(deadline);
                }
                result
            },
            || {
                let attempt = if Instant::now() >= deadline {
                    CancelAttempt::Terminal
                } else {
                    cancel_once(client, &cancellation_request)
                };
                if !matches!(attempt, CancelAttempt::Retry) {
                    settlement.finish();
                }
                attempt
            },
        )
    }
}

#[derive(Default)]
struct CancellationSettlement {
    finished: Mutex<bool>,
    changed: Condvar,
}

impl CancellationSettlement {
    fn finish(&self) {
        *self
            .finished
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        self.changed.notify_all();
    }

    fn wait_until(&self, deadline: Instant) {
        let mut finished = self
            .finished
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !*finished {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            let (next, timeout) = self
                .changed
                .wait_timeout(finished, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            finished = next;
            if timeout.timed_out() {
                break;
            }
        }
    }
}

fn cancel_once(client: &HostAdminClient, request: &HostCancellationRequest) -> CancelAttempt {
    let response = client
        .client
        .post(format!("{}{CANCEL_SELF_PATH}", client.base_url))
        .json(request)
        .timeout(CANCELLATION_ATTEMPT_TIMEOUT)
        .send();
    let Ok(response) = response else {
        return CancelAttempt::Retry;
    };
    let status = response.status();
    if status.as_u16() == 404 || status.as_u16() == 429 || status.is_server_error() {
        // Admission can still be running before cancellation registration. Keep
        // the same request ID and credential; never retry the invocation itself.
        return CancelAttempt::Retry;
    }
    if !status.is_success() {
        // Never forward raw bodies or transport errors: either may echo secrets.
        tracing::warn!(operation_id = %request.operation_id, status = status.as_u16(),
            "Host did not acknowledge MCP cancellation; execution may have effects");
        return CancelAttempt::Terminal;
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_CANCELLATION_RESPONSE_BYTES)
    {
        return CancelAttempt::Terminal;
    }
    let mut body = Vec::new();
    if response
        .take(MAX_CANCELLATION_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)
        .is_err()
    {
        return CancelAttempt::Retry;
    }
    if body.len() as u64 > MAX_CANCELLATION_RESPONSE_BYTES {
        return CancelAttempt::Terminal;
    }
    let Ok(response) = serde_json::from_slice::<HostCancellationResponse>(&body) else {
        return CancelAttempt::Terminal;
    };
    if response.operation_id != request.operation_id {
        return CancelAttempt::Terminal;
    }
    match response.outcome {
        fcp_host::CancellationOutcome::Cancelled | fcp_host::CancellationOutcome::Pending => {
            // This acknowledges a request, not completed provider cleanup or rollback.
            CancelAttempt::Accepted
        }
        fcp_host::CancellationOutcome::TooLate | fcp_host::CancellationOutcome::Failed => {
            CancelAttempt::Terminal
        }
    }
}
