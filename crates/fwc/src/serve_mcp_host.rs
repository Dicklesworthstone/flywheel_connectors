//! Bind one MCP tool call to one host invocation and its cancellation authority.

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
    HostCancellationResponse, InvokeRequest, InvokeResponse, ResolvedLiveAuth,
    host_invoke_http_timeout, parse_capability_token_bytes, parse_capability_token_str,
};

const MAX_CANCELLATION_TOKEN_BYTES: usize = 64 * 1024;
const MAX_CANCELLATION_RESPONSE_BYTES: u64 = 64 * 1024;
const CANCELLATION_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(1);
const CANCEL_SELF_PATH: &str = "/rpc/cancel-self";

#[cfg(test)]
#[path = "serve_mcp_host/tests.rs"]
mod tests;

#[derive(Args, Clone, Debug, Default, Serialize)]
pub(crate) struct CancellationArgs {
    /// Optional host.cancel-self token for the same principal and zone as tool calls.
    #[arg(
        long,
        value_name = "TOKEN",
        conflicts_with = "cancel_capability_token_file"
    )]
    #[serde(skip_serializing)]
    cancel_capability_token: Option<String>,

    /// Read a host.cancel-self token from a bounded base64, JSON, or raw CBOR file.
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
            (Some(_), Some(_)) => bail!("Specify one MCP cancellation capability source"),
            (Some(raw), None) => {
                ensure!(
                    raw.len() <= MAX_CANCELLATION_TOKEN_BYTES,
                    "MCP cancellation capability exceeds the 64 KiB limit"
                );
                parse_capability_token_str(raw, "--cancel-capability-token")
            }
            (None, Some(path)) => {
                let file = std::fs::File::open(path)
                    .map_err(|_| anyhow::anyhow!("Cannot open MCP cancellation capability file"))?;
                let mut bytes = zeroize::Zeroizing::new(Vec::new());
                file.take((MAX_CANCELLATION_TOKEN_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)
                    .map_err(|_| anyhow::anyhow!("Cannot read MCP cancellation capability file"))?;
                ensure!(
                    bytes.len() <= MAX_CANCELLATION_TOKEN_BYTES,
                    "MCP cancellation capability exceeds the 64 KiB limit"
                );
                parse_capability_token_bytes(&bytes, "--cancel-capability-token-file")
            }
        }
        .map_err(|_| anyhow::anyhow!("Invalid MCP cancellation capability encoding"))?;
        let claims = token
            .raw()
            .claims_unverified()
            .map_err(|_| anyhow::anyhow!("Invalid MCP cancellation capability claims"))?;
        // These checks only reject inconsistent inputs. The selected host still
        // verifies signature, persisted issuance, expiry, revocation and owner.
        ensure!(
            claims.get_capability_id() == Some("host.cancel-self"),
            "MCP remote cancellation requires a host.cancel-self capability"
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
