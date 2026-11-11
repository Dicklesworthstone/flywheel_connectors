//! Capability-authorized consumers for the native host's durable event journal.
//!
//! Polling is deliberately separate from acknowledgement: rendering output or
//! losing an HTTP response must never release provider credit. Stable request
//! and stream identities make explicit retries safe after an uncertain result.

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Result;
use clap::{Args, Subcommand};
use fcp_core::{
    CapabilityToken, ConnectorId, EventAck, EventEnvelope, HolderProof, InstanceId, RequestId,
    TailscaleNodeId, ZoneId,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::pipe::budget::ExecutionBudget;
use crate::{
    CliExitCode, CommandAvailability, CommandEnvelope, DispatchOutcome, HostAdminClient,
    parse_capability_token_bytes, resolve_host_config,
};

const MAX_TOKEN_BYTES: u64 = 64 * 1024;
const MAX_REQUEST_BYTES: usize = 64 * 1024;
const MAX_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(500);

#[derive(Args, Debug)]
pub(crate) struct StreamsArgs {
    #[command(subcommand)]
    command: StreamCommand,
}

#[derive(Subcommand, Debug)]
enum StreamCommand {
    /// Open a durable subscription, or resume the same stream with renewed authority.
    Open(OpenArgs),
    /// Read retained deliveries without acknowledging them or releasing provider credit.
    Poll(PollArgs),
    /// Commit the exact sequence/cursor pairs only after your processing succeeds.
    Ack(AckArgs),
    /// Stop new events while retaining every unacknowledged delivery.
    Close(RetainedArgs),
}

// Credentials are file-only, so command history, Debug, and parse errors cannot
// contain an inline bearer token. Never serialize the loaded authority object
// into a command result, error, or local resume artifact.
#[derive(Args, Debug)]
struct AuthorityArgs {
    /// Exact connector ID admitted by the selected host, for example fcp.telegram.
    #[arg(long, value_name = "CONNECTOR_ID")]
    connector: String,

    /// Exact zone authorized by the capability, for example z:work.
    #[arg(long, value_name = "ZONE_ID")]
    zone: String,

    /// One exact manifest event topic; wildcards are not supported.
    #[arg(long, value_name = "TOPIC")]
    topic: String,

    /// Stable request identity. Reuse it when retrying an open whose response was lost.
    #[arg(long, value_name = "REQUEST_ID")]
    request_id: String,

    /// Exact mesh node that owns this durable journal; reuse the open response's executor_node.
    #[arg(long, value_name = "NODE_ID")]
    executor_node: Option<TailscaleNodeId>,

    /// Read the signed capability from a regular file containing base64, JSON, or COSE CBOR.
    #[arg(long, value_name = "PATH")]
    capability_token_file: PathBuf,

    /// Node signing key for a holder-bound capability (32 raw bytes or 64 hexadecimal digits).
    #[arg(long, value_name = "PATH", requires = "subscription_operation")]
    holder_key_file: Option<PathBuf>,

    /// Exact manifest subscription operation signed by the holder, for example telegram.subscribe.
    #[arg(long, value_name = "OPERATION_ID", requires = "holder_key_file")]
    subscription_operation: Option<String>,

    /// Whole HTTP request deadline, including the response body (1-90 seconds).
    #[arg(long, default_value_t = 70, value_parser = clap::value_parser!(u64).range(1..=90))]
    timeout_seconds: u64,
}

#[derive(Args, Debug)]
struct OpenArgs {
    #[command(flatten)]
    auth: AuthorityArgs,

    /// Retained stream to resume. Omitted derives its identity from scope and request ID.
    #[arg(long, value_name = "STREAM_ID")]
    stream_id: Option<String>,

    /// Maximum outstanding events; resuming a stream must preserve its original window.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=64))]
    window_size: u32,
}

#[derive(Args, Debug)]
struct RetainedArgs {
    #[command(flatten)]
    auth: AuthorityArgs,

    /// Exact stream ID returned by open; this identifier is not authorization.
    #[arg(long, value_name = "STREAM_ID")]
    stream_id: String,
}

#[derive(Args, Debug)]
struct PollArgs {
    #[command(flatten)]
    retained: RetainedArgs,

    /// Maximum retained events to return in this batch.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..=64))]
    batch_size: u32,

    /// Wait up to this many seconds for the first nonempty batch (0-60).
    /// Only successful empty polls are repeated; no event is acknowledged.
    #[arg(long, default_value_t = 0, value_parser = clap::value_parser!(u64).range(0..=60))]
    wait_seconds: u64,
}

#[derive(Args, Debug)]
struct AckArgs {
    #[command(flatten)]
    retained: RetainedArgs,

    /// Delivered sequence number. Repeat together with --cursor for a batch.
    #[arg(long = "seq", required = true, value_name = "SEQUENCE")]
    seqs: Vec<u64>,

    /// Delivered cursor; entries pair with --seq in their respective order.
    #[arg(long = "cursor", required = true, value_name = "CURSOR")]
    cursors: Vec<String>,
}

/// Exact retained source for a bounded in-process consumer. The stream
/// capability is independent of any authority used to execute derived actions.
#[derive(Clone, Debug)]
pub(crate) struct NativeStreamConfig {
    pub(crate) connector: String,
    pub(crate) zone: String,
    pub(crate) topic: String,
    pub(crate) request_id: String,
    pub(crate) stream_id: String,
    pub(crate) executor_node: Option<TailscaleNodeId>,
    pub(crate) capability_token_file: PathBuf,
    pub(crate) holder_key_file: Option<PathBuf>,
    pub(crate) subscription_operation: Option<String>,
    pub(crate) timeout_seconds: u64,
}

pub(crate) struct NativeEventBatch {
    pub(crate) events: Vec<EventEnvelope>,
    pub(crate) closed: bool,
    pub(crate) wait_expired: bool,
}

pub(crate) struct NativeAckResult {
    /// Durable acknowledgement can succeed even when the original provider
    /// instance is absent. Never reinterpret this as a failed durable ACK.
    pub(crate) upstream_notified: bool,
}

#[derive(Clone)]
struct RetainedBinding {
    principal: String,
    window_size: u32,
    executor_node: Option<TailscaleNodeId>,
}

impl RetainedBinding {
    fn from_stream(stream: &StreamMetadata, executor_node: Option<TailscaleNodeId>) -> Self {
        Self {
            principal: stream.binding.principal.clone(),
            window_size: stream.window_size,
            executor_node,
        }
    }

    fn check(
        &self,
        stream: &StreamMetadata,
        executor_node: Option<&TailscaleNodeId>,
    ) -> std::result::Result<(), Failure> {
        if self.principal != stream.binding.principal
            || self.window_size != stream.window_size
            || self.executor_node.as_ref() != executor_node
        {
            return Err(Failure::InvalidResponse);
        }
        Ok(())
    }
}

/// A single selected gateway, journal executor and loaded capability for one retained stream.
///
/// Polling never acknowledges. An acknowledgement must be an exact subset of
/// the last validated poll, so processing code cannot accidentally release
/// credit for an event it did not receive. Failed ACKs retain those pairs for
/// explicit retry; starting another poll invalidates the old local batch.
pub(crate) struct NativeStreamClient {
    client: HostAdminClient,
    auth: Authority,
    stream_id: String,
    timeout: Duration,
    budget: ExecutionBudget,
    binding: Option<RetainedBinding>,
    delivered: BTreeMap<String, u64>,
}

impl NativeStreamClient {
    pub(crate) fn new(
        config: NativeStreamConfig,
        explicit_host: Option<&str>,
    ) -> std::result::Result<Self, StreamFailure> {
        if !valid_stream_id(&config.stream_id) {
            return Err(Failure::InvalidRequest);
        }
        let auth = load_authority(&AuthorityArgs {
            connector: config.connector,
            zone: config.zone,
            topic: config.topic,
            request_id: config.request_id,
            executor_node: config.executor_node,
            capability_token_file: config.capability_token_file,
            holder_key_file: config.holder_key_file,
            subscription_operation: config.subscription_operation,
            timeout_seconds: config.timeout_seconds,
        })?;
        let host = resolve_host_config(explicit_host)
            .map_err(|_| Failure::InvalidHost)?
            .ok_or(Failure::MissingHost)?;
        let client = HostAdminClient::new(&host.endpoint).map_err(|_| Failure::InvalidHost)?;
        Ok(Self {
            client,
            auth,
            stream_id: config.stream_id,
            timeout: Duration::from_secs(config.timeout_seconds),
            budget: ExecutionBudget::start(None, Instant::now()),
            binding: None,
            delivered: BTreeMap::new(),
        })
    }

    pub(crate) fn endpoint(&self) -> &str {
        &self.client.endpoint
    }

    pub(crate) fn set_budget(&mut self, budget: ExecutionBudget) {
        self.budget = budget;
    }

    pub(crate) fn stream_id(&self) -> &str {
        &self.stream_id
    }

    pub(crate) fn connector(&self) -> &str {
        self.auth.connector_id.as_str()
    }

    pub(crate) fn zone(&self) -> &str {
        self.auth.zone_id.as_str()
    }

    pub(crate) fn topic(&self) -> &str {
        &self.auth.topic
    }

    pub(crate) fn executor_node(&self) -> Option<&TailscaleNodeId> {
        self.binding
            .as_ref()
            .and_then(|binding| binding.executor_node.as_ref())
            .or(self.auth.executor_node.as_ref())
    }

    pub(crate) fn poll(
        &mut self,
        batch_size: u32,
        wait_seconds: u64,
    ) -> std::result::Result<NativeEventBatch, StreamFailure> {
        self.delivered.clear();
        let batch = poll_response(
            &self.client,
            &self.auth,
            &self.stream_id,
            batch_size,
            wait_seconds,
            self.timeout,
            self.budget,
            &mut self.binding,
        )?;
        for event in &batch.response.events {
            self.delivered.insert(event.cursor.clone(), event.seq);
        }
        Ok(NativeEventBatch {
            events: batch.response.events,
            closed: batch.response.stream.closed,
            wait_expired: batch.wait_expired,
        })
    }

    pub(crate) fn ack(
        &mut self,
        seqs: &[u64],
        cursors: &[String],
    ) -> std::result::Result<NativeAckResult, StreamFailure> {
        validate_ack_pairs(seqs, cursors)?;
        if !seqs
            .iter()
            .zip(cursors)
            .all(|(seq, cursor)| self.delivered.get(cursor) == Some(seq))
        {
            return Err(Failure::InvalidRequest);
        }
        let ack = EventAck::new(&self.auth.topic, seqs.to_vec()).with_cursors(cursors.to_vec());
        let response = acknowledge(
            &self.client,
            &self.auth,
            &self.stream_id,
            &ack,
            self.executor_node(),
            self.budget
                .preflight_timeout(self.timeout, Instant::now())
                .map_err(|_| Failure::Timeout)?,
        )?;
        self.binding
            .as_ref()
            .ok_or(Failure::InvalidRequest)?
            .check(&response.stream, response.executor_node.as_ref())?;
        for cursor in cursors {
            self.delivered.remove(cursor);
        }
        Ok(NativeAckResult {
            upstream_notified: response.upstream_notified,
        })
    }
}

impl StreamCommand {
    fn auth(&self) -> &AuthorityArgs {
        match self {
            Self::Open(args) => &args.auth,
            Self::Poll(args) => &args.retained.auth,
            Self::Ack(args) => &args.retained.auth,
            Self::Close(args) => &args.auth,
        }
    }

    fn name(&self) -> &'static str {
        match self {
            Self::Open(_) => "open",
            Self::Poll(_) => "poll",
            Self::Ack(_) => "ack",
            Self::Close(_) => "close",
        }
    }

    fn stream_id(&self) -> Option<&str> {
        match self {
            Self::Open(args) => args.stream_id.as_deref(),
            Self::Poll(args) => Some(&args.retained.stream_id),
            Self::Ack(args) => Some(&args.retained.stream_id),
            Self::Close(args) => Some(&args.stream_id),
        }
    }

    fn mutates_subscription(&self) -> bool {
        !matches!(self, Self::Poll(_))
    }
}

#[derive(Serialize)]
struct Authority {
    request_id: String,
    connector_id: ConnectorId,
    zone_id: ZoneId,
    topic: String,
    capability_token: CapabilityToken,
    #[serde(skip_serializing_if = "Option::is_none")]
    holder_proof: Option<HolderProof>,
    // Routing is a top-level host request field, never capability authority.
    #[serde(skip)]
    executor_node: Option<TailscaleNodeId>,
}

#[derive(Clone, Deserialize, Serialize)]
struct Binding {
    principal: String,
    connector_id: ConnectorId,
    zone_id: ZoneId,
    topic: String,
}

#[derive(Clone, Deserialize, Serialize)]
struct StreamMetadata {
    stream_id: String,
    binding: Binding,
    instance_id: InstanceId,
    window_size: u32,
    pending_events: usize,
    acknowledged_events: usize,
    closed: bool,
    durable: bool,
}

#[derive(Deserialize, Serialize)]
struct OpenResponse {
    executor_node: Option<TailscaleNodeId>,
    stream: StreamMetadata,
    attached: bool,
    replay_supported: bool,
}

#[derive(Deserialize, Serialize)]
struct PollResponse {
    executor_node: Option<TailscaleNodeId>,
    stream: StreamMetadata,
    events: Vec<EventEnvelope>,
}

#[derive(Deserialize, Serialize)]
struct AckResponse {
    executor_node: Option<TailscaleNodeId>,
    stream: StreamMetadata,
    acknowledged: bool,
    upstream_notified: bool,
}

#[derive(Deserialize, Serialize)]
struct CloseResponse {
    executor_node: Option<TailscaleNodeId>,
    stream: StreamMetadata,
    upstream_notified: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StreamFailure {
    InvalidRequest,
    MissingHost,
    InvalidHost,
    Credential,
    HolderProof,
    Transport,
    Timeout,
    Http(u16),
    InvalidResponse,
    ResponseTooLarge,
}

use StreamFailure as Failure;

impl Failure {
    pub(crate) fn details(self) -> (&'static str, &'static str, CliExitCode) {
        match self {
            Self::InvalidRequest => (
                "invalid-stream-request",
                "Stream scope, stable identities, window, deadline, or exact acknowledgement pairs are invalid or exceed their bounds.",
                CliExitCode::Validation,
            ),
            Self::MissingHost => (
                "missing-host-endpoint",
                "Native event consumption requires the host that owns the durable stream. Supply --host or configure a host context.",
                CliExitCode::Transport,
            ),
            Self::InvalidHost => (
                "invalid-stream-host",
                "The selected host endpoint or host client configuration could not be used.",
                CliExitCode::Validation,
            ),
            Self::Credential => (
                "invalid-stream-capability",
                "The capability file must be a readable regular file of at most 64 KiB containing a signed COSE capability in base64, JSON, or CBOR form.",
                CliExitCode::Validation,
            ),
            Self::HolderProof => (
                "invalid-stream-holder-proof",
                "A holder-bound stream capability needs its node signing key and exact manifest subscription operation. Use --holder-key-file and --subscription-operation for streams, or --stream-holder-key-file and --stream-subscription-operation for rules consume. The regular key file must contain 32 raw bytes or 64 hexadecimal digits; the capability must identify its holder and nonempty token JTI.",
                CliExitCode::Validation,
            ),
            Self::Transport => (
                "stream-transport-failed",
                "The selected host did not return a complete readable response. No producer acknowledgement is implied.",
                CliExitCode::Transport,
            ),
            Self::Timeout => (
                "stream-request-timeout",
                "The stream request exceeded its bounded deadline. Reconcile using the original request and stream identities.",
                CliExitCode::Transport,
            ),
            Self::Http(401 | 403) => (
                "stream-authority-denied",
                "The selected host rejected stream authority. Check the signed subject, grant, instance, zone, resource, and current policy.",
                CliExitCode::PolicyDenied,
            ),
            Self::Http(300..=399) => (
                "stream-redirect-refused",
                "The selected host returned a redirect. The capability was not forwarded to the redirect target.",
                CliExitCode::Transport,
            ),
            Self::Http(_) => (
                "stream-host-rejected",
                "The selected host returned an unsuccessful status. Its response body is omitted because it may echo credentials.",
                CliExitCode::Connector,
            ),
            Self::InvalidResponse => (
                "invalid-stream-response",
                "The host response did not match the requested journal executor, stream scope, or canonical event contract.",
                CliExitCode::Transport,
            ),
            Self::ResponseTooLarge => (
                "stream-response-too-large",
                "The selected host exceeded the 2 MiB stream response limit.",
                CliExitCode::Transport,
            ),
        }
    }

    fn may_have_reached_host(self) -> bool {
        matches!(
            self,
            Self::Transport
                | Self::Timeout
                | Self::Http(_)
                | Self::InvalidResponse
                | Self::ResponseTooLarge
        )
    }
}

impl std::fmt::Display for StreamFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.details().1)
    }
}

impl std::error::Error for StreamFailure {}

pub(crate) fn dispatch(args: &StreamsArgs, explicit_host: Option<&str>) -> Result<DispatchOutcome> {
    let command = &args.command;
    let auth = match authority(command) {
        Ok(auth) => auth,
        Err(error) => return Ok(failure(command, None, error)),
    };
    let host = match resolve_host_config(explicit_host) {
        Ok(Some(host)) => host,
        Ok(None) => return Ok(failure(command, None, Failure::MissingHost)),
        Err(_) => return Ok(failure(command, None, Failure::InvalidHost)),
    };
    // This existing client disables redirects and automatic retries for every
    // endpoint form, including Unix sockets. Do not use decode_response, which
    // intentionally exposes admin API error text unsuitable for bearer bodies.
    let client = match HostAdminClient::new(&host.endpoint) {
        Ok(client) => client,
        Err(_) => return Ok(failure(command, None, Failure::InvalidHost)),
    };
    match execute(command, &auth, &client) {
        Ok(mut payload) => {
            payload["status"] = json!("ok");
            payload["command"] = json!("streams");
            payload["subcommand"] = json!(command.name());
            payload["source"] = json!("selected-host-native-event-journal");
            payload["host"] = json!(client.endpoint);
            payload["request_id"] = json!(auth.request_id);
            CommandEnvelope::new(CommandAvailability::LiveRuntime, "streams")
                .inject_into(&mut payload);
            Ok(DispatchOutcome {
                payload,
                exit_code: CliExitCode::Success,
            })
        }
        Err(error) => Ok(failure(command, Some(&client.endpoint), error)),
    }
}

fn bounded_identity(value: &str, limit: usize) -> bool {
    !value.trim().is_empty() && value.len() <= limit && !value.chars().any(char::is_control)
}

fn valid_stream_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn authority(command: &StreamCommand) -> std::result::Result<Authority, Failure> {
    if command.stream_id().is_some_and(|id| !valid_stream_id(id)) {
        return Err(Failure::InvalidRequest);
    }
    match command {
        StreamCommand::Open(args) if !(1..=64).contains(&args.window_size) => {
            return Err(Failure::InvalidRequest);
        }
        StreamCommand::Poll(args)
            if !(1..=64).contains(&args.batch_size) || args.wait_seconds > 60 =>
        {
            return Err(Failure::InvalidRequest);
        }
        StreamCommand::Ack(args) => validate_ack_pairs(&args.seqs, &args.cursors)?,
        _ => {}
    }
    load_authority(command.auth())
}

fn load_authority(args: &AuthorityArgs) -> std::result::Result<Authority, Failure> {
    if !bounded_identity(&args.request_id, 128)
        || !bounded_identity(&args.topic, 256)
        || args.topic.chars().any(char::is_whitespace)
        || args.topic.contains('*')
        || !(1..=90).contains(&args.timeout_seconds)
    {
        return Err(Failure::InvalidRequest);
    }
    let connector_id = args
        .connector
        .parse()
        .map_err(|_| Failure::InvalidRequest)?;
    let zone_id = args.zone.parse().map_err(|_| Failure::InvalidRequest)?;
    let executor_node = args
        .executor_node
        .as_ref()
        .map(|node| node.as_str().parse::<TailscaleNodeId>())
        .transpose()
        .map_err(|_| Failure::InvalidRequest)?;
    let metadata =
        std::fs::metadata(&args.capability_token_file).map_err(|_| Failure::Credential)?;
    if !metadata.is_file() || metadata.len() > MAX_TOKEN_BYTES {
        return Err(Failure::Credential);
    }
    let file = File::open(&args.capability_token_file).map_err(|_| Failure::Credential)?;
    if !file.metadata().map_err(|_| Failure::Credential)?.is_file() {
        return Err(Failure::Credential);
    }
    let mut bytes = Vec::new();
    file.take(MAX_TOKEN_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Credential)?;
    if bytes.len() as u64 > MAX_TOKEN_BYTES {
        return Err(Failure::Credential);
    }
    let capability_token =
        parse_capability_token_bytes(&bytes, "capability file").map_err(|_| Failure::Credential)?;
    let holder_proof = stream_holder_proof(args, &capability_token)?;
    Ok(Authority {
        request_id: args.request_id.clone(),
        connector_id,
        zone_id,
        topic: args.topic.clone(),
        capability_token,
        holder_proof,
        executor_node,
    })
}

fn stream_holder_proof(
    args: &AuthorityArgs,
    capability_token: &CapabilityToken,
) -> std::result::Result<Option<HolderProof>, Failure> {
    // Unverified claims only select the caller's signing context. The host
    // independently verifies the capability and its current membership key.
    let claims = capability_token.raw().claims_unverified().ok();
    let holder = claims.as_ref().and_then(|claims| claims.get_holder_node());
    match (
        holder,
        args.holder_key_file.as_deref(),
        args.subscription_operation.as_deref(),
    ) {
        (None, None, None) => Ok(None),
        (Some(holder), Some(path), Some(operation)) => {
            if !bounded_identity(operation, 256)
                || !std::fs::metadata(path)
                    .is_ok_and(|metadata| metadata.is_file() && metadata.len() <= 128)
            {
                return Err(Failure::HolderProof);
            }
            let token_jti = claims
                .as_ref()
                .and_then(|claims| claims.get_jti())
                .filter(|jti| !jti.is_empty())
                .ok_or(Failure::HolderProof)?;
            let auth = crate::ResolvedLiveAuth {
                capability_token: capability_token.clone(),
                approval_tokens: Vec::new(),
                principal_hint: None,
                holder_signer: Some(crate::LiveHolderSigner {
                    key: crate::read_live_holder_signing_key(path)
                        .map_err(|_| Failure::HolderProof)?,
                    holder_node: TailscaleNodeId::new(holder),
                    token_jti: token_jti.to_vec(),
                }),
            };
            auth.holder_proof_for(&RequestId::new(args.request_id.clone()), operation)
                .map_err(|_| Failure::HolderProof)
        }
        _ => Err(Failure::HolderProof),
    }
}

fn validate_ack_pairs(seqs: &[u64], cursors: &[String]) -> std::result::Result<(), Failure> {
    let mut seen_cursors = HashSet::new();
    // Native sequences can restart across instances. The durable identity is
    // the exact sequence/cursor pair, so only duplicate cursors are ambiguous.
    if seqs.is_empty()
        || seqs.len() > 64
        || seqs.len() != cursors.len()
        || cursors
            .iter()
            .any(|cursor| !bounded_identity(cursor, 1024) || !seen_cursors.insert(cursor))
    {
        return Err(Failure::InvalidRequest);
    }
    Ok(())
}

fn check_stream(
    stream: &StreamMetadata,
    auth: &Authority,
    expected_id: Option<&str>,
) -> std::result::Result<(), Failure> {
    if !valid_stream_id(&stream.stream_id)
        || expected_id.is_some_and(|id| id != stream.stream_id)
        || stream.binding.connector_id != auth.connector_id
        || stream.binding.zone_id != auth.zone_id
        || stream.binding.topic != auth.topic
        || !bounded_identity(&stream.binding.principal, 1024)
        || !(1..=64).contains(&stream.window_size)
        || stream.pending_events > stream.window_size as usize
        || !stream.durable
    {
        return Err(Failure::InvalidResponse);
    }
    Ok(())
}

fn check_executor(
    expected: Option<&TailscaleNodeId>,
    actual: Option<&TailscaleNodeId>,
) -> std::result::Result<(), Failure> {
    if expected.is_some_and(|expected| Some(expected) != actual) {
        return Err(Failure::InvalidResponse);
    }
    Ok(())
}

fn routed_request(mut body: Value, executor_node: Option<&TailscaleNodeId>) -> Value {
    // Omission preserves the local request contract for older hosts that deny
    // unknown fields. A known executor is always sent explicitly thereafter.
    if let Some(executor_node) = executor_node {
        body["executor_node"] = json!(executor_node);
    }
    body
}

fn execute(
    command: &StreamCommand,
    auth: &Authority,
    client: &HostAdminClient,
) -> std::result::Result<Value, Failure> {
    let timeout = Duration::from_secs(command.auth().timeout_seconds);
    match command {
        StreamCommand::Open(args) => {
            let response: OpenResponse = post(
                client,
                "/rpc/streams/open",
                &routed_request(
                    json!({"auth": auth, "stream_id": args.stream_id, "window_size": args.window_size}),
                    auth.executor_node.as_ref(),
                ),
                timeout,
            )?;
            check_executor(auth.executor_node.as_ref(), response.executor_node.as_ref())?;
            check_stream(&response.stream, auth, args.stream_id.as_deref())?;
            if !response.attached
                || response.stream.closed
                || response.stream.window_size != args.window_size
            {
                return Err(Failure::InvalidResponse);
            }
            encode(response)
        }
        StreamCommand::Poll(args) => poll(client, auth, args, timeout),
        StreamCommand::Ack(args) => {
            let ack =
                EventAck::new(&auth.topic, args.seqs.clone()).with_cursors(args.cursors.clone());
            let response = acknowledge(
                client,
                auth,
                &args.retained.stream_id,
                &ack,
                auth.executor_node.as_ref(),
                timeout,
            )?;
            let mut payload = encode(response)?;
            payload["ack"] = encode(ack)?;
            Ok(payload)
        }
        StreamCommand::Close(args) => {
            let response: CloseResponse = post(
                client,
                "/rpc/streams/close",
                &routed_request(
                    json!({"auth": auth, "stream_id": args.stream_id}),
                    auth.executor_node.as_ref(),
                ),
                timeout,
            )?;
            check_executor(auth.executor_node.as_ref(), response.executor_node.as_ref())?;
            check_stream(&response.stream, auth, Some(&args.stream_id))?;
            if !response.stream.closed {
                return Err(Failure::InvalidResponse);
            }
            encode(response)
        }
    }
}

fn poll(
    client: &HostAdminClient,
    auth: &Authority,
    args: &PollArgs,
    timeout: Duration,
) -> std::result::Result<Value, Failure> {
    let mut binding = None;
    let batch = poll_response(
        client,
        auth,
        &args.retained.stream_id,
        args.batch_size,
        args.wait_seconds,
        timeout,
        ExecutionBudget::start(None, Instant::now()),
        &mut binding,
    )?;
    let ack = if batch.response.events.is_empty() {
        None
    } else {
        Some(
            EventAck::new(
                &auth.topic,
                batch
                    .response
                    .events
                    .iter()
                    .map(|event| event.seq)
                    .collect(),
            )
            .with_cursors(
                batch
                    .response
                    .events
                    .iter()
                    .map(|event| event.cursor.clone())
                    .collect(),
            ),
        )
    };
    let mut payload = encode(batch.response)?;
    payload["acknowledged"] = json!(false);
    payload["wait_expired"] = json!(batch.wait_expired);
    if let Some(ack) = ack {
        payload["ack_request"] = encode(ack)?;
    }
    Ok(payload)
}

struct PolledResponse {
    response: PollResponse,
    wait_expired: bool,
}

#[allow(clippy::too_many_arguments)]
fn poll_response(
    client: &HostAdminClient,
    auth: &Authority,
    stream_id: &str,
    batch_size: u32,
    wait_seconds: u64,
    timeout: Duration,
    budget: ExecutionBudget,
    binding: &mut Option<RetainedBinding>,
) -> std::result::Result<PolledResponse, Failure> {
    if !valid_stream_id(stream_id) || !(1..=64).contains(&batch_size) || wait_seconds > 60 {
        return Err(Failure::InvalidRequest);
    }
    let deadline = (wait_seconds > 0).then(|| Instant::now() + Duration::from_secs(wait_seconds));
    loop {
        // The first unpinned request selects the local journal. Once its
        // executor is known, every retry and ACK stays with that same node.
        let executor_node = binding
            .as_ref()
            .and_then(|binding| binding.executor_node.as_ref())
            .or(auth.executor_node.as_ref());
        let body = routed_request(
            json!({"auth": auth, "stream_id": stream_id, "limit": batch_size}),
            executor_node,
        );
        let remaining = deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
        let response: PollResponse = post(
            client,
            "/rpc/streams/poll",
            &body,
            budget
                .preflight_timeout(
                    remaining.map_or(timeout, |remaining| timeout.min(remaining)),
                    Instant::now(),
                )
                .map_err(|_| Failure::Timeout)?,
        )?;
        check_executor(executor_node, response.executor_node.as_ref())?;
        check_poll(&response, auth, stream_id, batch_size)?;
        if let Some(binding) = binding.as_ref() {
            binding.check(&response.stream, response.executor_node.as_ref())?;
        } else {
            *binding = Some(RetainedBinding::from_stream(
                &response.stream,
                response.executor_node.clone(),
            ));
        }
        let wait_expired = deadline.is_some_and(|deadline| Instant::now() >= deadline)
            || budget.remaining_ms(Instant::now()).is_err();
        if !response.events.is_empty()
            || response.stream.closed
            || deadline.is_none()
            || wait_expired
        {
            return Ok(PolledResponse {
                response,
                wait_expired,
            });
        }
        let mut remaining = deadline
            .expect("bounded wait")
            .saturating_duration_since(Instant::now());
        match budget.remaining_ms(Instant::now()) {
            Ok(Some(milliseconds)) => {
                remaining = remaining.min(Duration::from_millis(milliseconds))
            }
            Ok(None) => {}
            Err(_) => {
                return Ok(PolledResponse {
                    response,
                    wait_expired: true,
                });
            }
        }
        std::thread::sleep(POLL_INTERVAL.min(remaining));
        if deadline.is_some_and(|deadline| Instant::now() >= deadline)
            || budget.remaining_ms(Instant::now()).is_err()
        {
            // Preserve the last confirmed empty batch instead of starting a
            // zero-budget request when the waiting interval consumes the deadline.
            return Ok(PolledResponse {
                response,
                wait_expired: true,
            });
        }
    }
}

fn check_poll(
    response: &PollResponse,
    auth: &Authority,
    stream_id: &str,
    batch_size: u32,
) -> std::result::Result<(), Failure> {
    check_stream(&response.stream, auth, Some(stream_id))?;
    if response.events.len() > batch_size as usize
        || response.events.len() > response.stream.pending_events
    {
        return Err(Failure::InvalidResponse);
    }
    let mut seqs = Vec::new();
    let mut cursors = Vec::new();
    for event in &response.events {
        // Original pending payloads retain their original instance after
        // reattachment. Validate source scope, not old-instance equality.
        if event.topic != auth.topic
            || event.data.connector_id != auth.connector_id
            || event.data.zone_id != auth.zone_id
            || !event.requires_ack
        {
            return Err(Failure::InvalidResponse);
        }
        seqs.push(event.seq);
        cursors.push(event.cursor.clone());
    }
    if !seqs.is_empty() {
        validate_ack_pairs(&seqs, &cursors).map_err(|_| Failure::InvalidResponse)?;
    }
    Ok(())
}

fn acknowledge(
    client: &HostAdminClient,
    auth: &Authority,
    stream_id: &str,
    ack: &EventAck,
    executor_node: Option<&TailscaleNodeId>,
    timeout: Duration,
) -> std::result::Result<AckResponse, Failure> {
    validate_ack_pairs(&ack.seqs, &ack.cursors)?;
    let response: AckResponse = post(
        client,
        "/rpc/streams/ack",
        &routed_request(
            json!({"auth": auth, "stream_id": stream_id, "ack": ack}),
            executor_node,
        ),
        timeout,
    )?;
    check_executor(executor_node, response.executor_node.as_ref())?;
    check_stream(&response.stream, auth, Some(stream_id))?;
    if !response.acknowledged {
        return Err(Failure::InvalidResponse);
    }
    Ok(response)
}

fn encode(value: impl Serialize) -> std::result::Result<Value, Failure> {
    serde_json::to_value(value).map_err(|_| Failure::InvalidResponse)
}

fn post<B: Serialize, T: DeserializeOwned>(
    client: &HostAdminClient,
    path: &'static str,
    body: &B,
    timeout: Duration,
) -> std::result::Result<T, Failure> {
    let bytes = serde_json::to_vec(body).map_err(|_| Failure::InvalidRequest)?;
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(Failure::InvalidRequest);
    }
    if timeout.is_zero() {
        return Err(Failure::Timeout);
    }
    let response = client
        .client
        .post(format!("{}{}", client.base_url, path))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .timeout(timeout)
        .body(bytes)
        .send()
        .map_err(|error| {
            if error.is_timeout() {
                Failure::Timeout
            } else {
                Failure::Transport
            }
        })?;
    if !response.status().is_success() {
        return Err(Failure::Http(response.status().as_u16()));
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES)
    {
        return Err(Failure::ResponseTooLarge);
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::TimedOut
                || error
                    .get_ref()
                    .and_then(|cause| cause.downcast_ref::<reqwest::Error>())
                    .is_some_and(reqwest::Error::is_timeout)
            {
                Failure::Timeout
            } else {
                Failure::Transport
            }
        })?;
    if bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(Failure::ResponseTooLarge);
    }
    serde_json::from_slice(&bytes).map_err(|_| Failure::InvalidResponse)
}

fn failure(command: &StreamCommand, endpoint: Option<&str>, failure: Failure) -> DispatchOutcome {
    let (kind, message, exit_code) = failure.details();
    let mut payload = json!({
        "status": "error", "command": "streams", "subcommand": command.name(),
        "source": "selected-host-native-event-journal", "host": endpoint,
        "error": { "type": kind, "message": message },
        "outcome_unknown": command.mutates_subscription() && failure.may_have_reached_host(),
        "request_id": command.auth().request_id, "stream_id": command.stream_id(),
        "executor_node": command.auth().executor_node,
        "scope": { "connector_id": command.auth().connector, "zone_id": command.auth().zone, "topic": command.auth().topic },
        "next_actions": ["Keep the original host, executor node, request ID, stream ID, and delivered sequence/cursor pairs when retrying. Polling never acknowledges events; acknowledge only after processing succeeds."],
    });
    if let Failure::Http(status) = failure {
        payload["error"]["http_status"] = json!(status);
    }
    if let StreamCommand::Ack(args) = command {
        payload["ack"] = json!({"type": "ack", "topic": args.retained.auth.topic, "seqs": args.seqs, "cursors": args.cursors});
    }
    let availability = if matches!(failure, Failure::Http(401 | 403)) {
        CommandAvailability::Denied
    } else {
        CommandAvailability::Unavailable
    };
    let mut envelope = CommandEnvelope::new(availability, "streams");
    envelope.explanation = message.to_owned();
    envelope.next_actions = vec![
        "Reconcile this stream on the selected host with its original identities and valid authority."
            .to_owned(),
    ];
    envelope.inject_into(&mut payload);
    DispatchOutcome { payload, exit_code }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    // Structural COSE_Sign1 fixture only. The CLI parses it; the real host
    // remains responsible for signature, grant, timing, and instance checks.
    const TOKEN_CBOR: &[u8] = &[0x84, 0x40, 0xa0, 0x40, 0x40];
    const STREAM: &str = "stream-fixture";
    const TOPIC: &str = "telegram.message.new";
    const EXECUTOR: &str = "node-journal-owner";
    const HOLDER: &str = "node-stream-holder";
    const HOLDER_JTI: &[u8] = b"stream-holder-token-id";
    const SUBSCRIPTION_OPERATION: &str = "telegram.subscribe";

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        streams: StreamsArgs,
    }

    struct Captured {
        path: String,
        body: Value,
    }

    fn read_request(stream: &mut std::net::TcpStream) -> Captured {
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let path = line.split_whitespace().nth(1).unwrap().to_owned();
        let mut length = 0;
        loop {
            line.clear();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse().unwrap();
                }
            }
        }
        assert!(length <= MAX_REQUEST_BYTES);
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        Captured {
            path,
            body: serde_json::from_slice(&body).unwrap(),
        }
    }

    fn host(responses: Vec<Value>) -> (String, std::thread::JoinHandle<Vec<Captured>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().unwrap();
                requests.push(read_request(&mut stream));
                let body = response.to_string();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
            requests
        });
        (endpoint, task)
    }

    fn metadata(closed: bool, pending: usize, acknowledged: usize) -> Value {
        json!({
            "stream_id": STREAM,
            "binding": {"principal":"agent:alice", "connector_id":"fcp.telegram", "zone_id":"z:work", "topic":TOPIC},
            "instance_id":"inst_current", "window_size":1,
            "pending_events":pending, "acknowledged_events":acknowledged,
            "closed":closed, "durable":true,
        })
    }

    fn event() -> Value {
        json!({
            "topic":TOPIC, "timestamp":"2026-10-27T00:00:00Z", "seq":7,
            "cursor":"provider-7", "requires_ack":true,
            "data": {
                "connector_id":"fcp.telegram", "instance_id":"inst_predecessor", "zone_id":"z:work",
                "principal":{"kind":"provider_user", "id":"user-1", "trust":"untrusted", "display":null},
                "payload":{"message":"retained event"}, "resource_uris":[],
            },
        })
    }

    fn credential() -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(TOKEN_CBOR).unwrap();
        file
    }

    fn holder_credential(holder: Option<&str>, jti: Option<&[u8]>) -> tempfile::NamedTempFile {
        let issuer = fcp_crypto::Ed25519SigningKey::from_bytes(&[0x42; 32]).unwrap();
        let mut claims = CapabilityToken::test_token()
            .raw()
            .claims_unverified()
            .unwrap();
        if let Some(holder) = holder {
            claims = claims.holder_node(holder);
        }
        if let Some(jti) = jti {
            claims = claims.token_id(jti);
        }
        let token = fcp_crypto::cose::CoseToken::sign(&issuer, &claims).unwrap();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&token.to_cbor().unwrap()).unwrap();
        file
    }

    fn args(file: &std::path::Path, command: &str, extra: &[&str]) -> StreamsArgs {
        let mut argv = vec![
            "streams".to_owned(),
            command.to_owned(),
            "--connector".to_owned(),
            "fcp.telegram".to_owned(),
            "--zone".to_owned(),
            "z:work".to_owned(),
            "--topic".to_owned(),
            TOPIC.to_owned(),
            "--request-id".to_owned(),
            "consumer-stable-1".to_owned(),
            "--capability-token-file".to_owned(),
            file.to_string_lossy().into_owned(),
        ];
        argv.extend(extra.iter().map(|arg| (*arg).to_owned()));
        TestCli::try_parse_from(argv).unwrap().streams
    }

    fn consumer_config(file: &std::path::Path) -> NativeStreamConfig {
        NativeStreamConfig {
            connector: "fcp.telegram".to_owned(),
            zone: "z:work".to_owned(),
            topic: TOPIC.to_owned(),
            request_id: "consumer-stable-1".to_owned(),
            stream_id: STREAM.to_owned(),
            executor_node: None,
            capability_token_file: file.to_owned(),
            holder_key_file: None,
            subscription_operation: None,
            timeout_seconds: 3,
        }
    }

    #[test]
    fn explicit_executor_and_holder_proof_survive_open_resume_poll_ack_and_close() {
        let file = holder_credential(Some(HOLDER), Some(HOLDER_JTI));
        let mut key_file = tempfile::NamedTempFile::new().unwrap();
        key_file.write_all(&[0x77; 32]).unwrap();
        let holder = fcp_crypto::Ed25519SigningKey::from_bytes(&[0x77; 32]).unwrap();
        let opened = json!({
            "executor_node":EXECUTOR,"stream":metadata(false,0,0),
            "attached":true,"replay_supported":false,
        });
        let (endpoint, task) = host(vec![
            opened.clone(),
            opened,
            json!({"executor_node":EXECUTOR,"stream":metadata(false,1,0),"events":[event()]}),
            json!({"executor_node":EXECUTOR,"stream":metadata(false,0,1),"acknowledged":true,"upstream_notified":false}),
            json!({"executor_node":EXECUTOR,"stream":metadata(true,0,1),"upstream_notified":true}),
        ]);
        for (command, extra) in [
            ("open", vec![]),
            ("open", vec!["--stream-id", STREAM]),
            ("poll", vec!["--stream-id", STREAM]),
            (
                "ack",
                vec![
                    "--stream-id",
                    STREAM,
                    "--seq",
                    "7",
                    "--cursor",
                    "provider-7",
                ],
            ),
            ("close", vec!["--stream-id", STREAM]),
        ] {
            let mut extra = extra;
            extra.extend(["--executor-node", EXECUTOR]);
            extra.extend([
                "--holder-key-file",
                key_file.path().to_str().unwrap(),
                "--subscription-operation",
                SUBSCRIPTION_OPERATION,
            ]);
            let result = dispatch(&args(file.path(), command, &extra), Some(&endpoint)).unwrap();
            assert_eq!(result.exit_code, CliExitCode::Success);
            assert_eq!(result.payload["executor_node"], EXECUTOR);
            assert_eq!(result.payload["host"], endpoint);
            let rendered = result.payload.to_string();
            assert!(!rendered.contains("capability_token"));
            assert!(!rendered.contains("holder_proof"));
            assert!(!rendered.contains(&hex::encode(holder.to_bytes())));
        }
        let requests = task.join().unwrap();
        assert_eq!(requests.len(), 5);
        for request in requests {
            assert_eq!(request.body["executor_node"], EXECUTOR);
            assert!(request.body["auth"].get("executor_node").is_none());
            assert_eq!(request.body["auth"]["request_id"], "consumer-stable-1");
            let proof: HolderProof =
                serde_json::from_value(request.body["auth"]["holder_proof"].clone()).unwrap();
            assert_eq!(proof.holder_node.as_str(), HOLDER);
            assert!(
                request.body["auth"].get("subscription_operation").is_none(),
                "the executor derives the manifest operation independently"
            );
            let signature = fcp_crypto::Ed25519Signature::from_bytes(&proof.signature);
            for (request_id, operation, token_id, valid) in [
                (
                    "consumer-stable-1",
                    SUBSCRIPTION_OPERATION,
                    HOLDER_JTI,
                    true,
                ),
                ("another-request", SUBSCRIPTION_OPERATION, HOLDER_JTI, false),
                ("consumer-stable-1", "telegram.send", HOLDER_JTI, false),
                (
                    "consumer-stable-1",
                    SUBSCRIPTION_OPERATION,
                    b"renewed-token".as_slice(),
                    false,
                ),
            ] {
                let transcript = HolderProof::signable_bytes(
                    &RequestId::new(request_id),
                    &operation.parse().unwrap(),
                    token_id,
                );
                assert_eq!(
                    holder
                        .verifying_key()
                        .verify(&transcript, &signature)
                        .is_ok(),
                    valid
                );
            }
        }
    }

    #[test]
    fn incomplete_or_unbound_holder_authority_fails_before_any_network_request() {
        let mut key = tempfile::NamedTempFile::new().unwrap();
        key.write_all(&[0x77; 32]).unwrap();
        for (holder, jti, use_key, operation) in [
            (Some(HOLDER), Some(HOLDER_JTI), false, None),
            (Some(HOLDER), Some(HOLDER_JTI), true, None),
            (
                Some(HOLDER),
                Some(HOLDER_JTI),
                false,
                Some(SUBSCRIPTION_OPERATION),
            ),
            (Some(HOLDER), None, true, Some(SUBSCRIPTION_OPERATION)),
            (
                Some(HOLDER),
                Some(b"".as_slice()),
                true,
                Some(SUBSCRIPTION_OPERATION),
            ),
            (None, Some(HOLDER_JTI), true, Some(SUBSCRIPTION_OPERATION)),
            (
                Some(HOLDER),
                Some(HOLDER_JTI),
                true,
                Some("invalid\noperation"),
            ),
        ] {
            let token = holder_credential(holder, jti);
            let mut config = consumer_config(token.path());
            config.holder_key_file = use_key.then(|| key.path().to_owned());
            config.subscription_operation = operation.map(str::to_owned);
            assert!(
                matches!(
                    NativeStreamClient::new(config, Some("not-a-host")),
                    Err(StreamFailure::HolderProof)
                ),
                "holder inputs must fail before host setup"
            );
        }
        let token = holder_credential(Some(HOLDER), Some(HOLDER_JTI));
        for bytes in [vec![0x77; 129], b"private-invalid-key-sentinel".to_vec()] {
            let mut key = tempfile::NamedTempFile::new().unwrap();
            key.write_all(&bytes).unwrap();
            let mut config = consumer_config(token.path());
            config.holder_key_file = Some(key.path().to_owned());
            config.subscription_operation = Some(SUBSCRIPTION_OPERATION.to_owned());
            let error = NativeStreamClient::new(config, Some("not-a-host"))
                .err()
                .unwrap();
            assert!(matches!(error, StreamFailure::HolderProof));
            assert!(!error.to_string().contains("private-invalid-key-sentinel"));
            assert!(!error.to_string().contains(key.path().to_str().unwrap()));
        }
    }

    #[test]
    fn holder_stream_consumer_posts_proof_without_introspection_on_ack() {
        let token = holder_credential(Some(HOLDER), Some(HOLDER_JTI));
        let mut key = tempfile::NamedTempFile::new().unwrap();
        key.write_all(&[0x77; 32]).unwrap();
        let (endpoint, task) = host(vec![
            json!({"stream":metadata(false,1,0),"events":[event()]}),
            json!({"stream":metadata(false,0,1),"acknowledged":true,"upstream_notified":true}),
        ]);
        let mut config = consumer_config(token.path());
        config.holder_key_file = Some(key.path().to_owned());
        config.subscription_operation = Some(SUBSCRIPTION_OPERATION.to_owned());
        let mut client = NativeStreamClient::new(config, Some(&endpoint)).unwrap();
        let batch = client.poll(1, 0).unwrap();
        assert_eq!(batch.events.len(), 1);
        client
            .ack(&[batch.events[0].seq], &[batch.events[0].cursor.clone()])
            .unwrap();
        let requests = task.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].path, "/rpc/streams/poll");
        assert_eq!(requests[1].path, "/rpc/streams/ack");
        let expected = requests[0].body["auth"]["holder_proof"].clone();
        assert!(!expected.is_null());
        assert_eq!(requests[1].body["auth"]["holder_proof"], expected);
    }

    #[test]
    fn every_pinned_operation_rejects_missing_wrong_or_malformed_executor() {
        for executor in [
            None,
            Some(json!(null)),
            Some(json!("node-other")),
            Some(json!("bad node")),
        ] {
            for command in ["open", "poll", "ack", "close"] {
                let file = credential();
                let mut response = json!({
                    "stream":metadata(command == "close",usize::from(command == "poll"),0),
                    "attached":true,"replay_supported":false,"events":[event()],
                    "acknowledged":true,"upstream_notified":true,
                });
                if let Some(executor) = &executor {
                    response["executor_node"] = executor.clone();
                }
                let (endpoint, task) = host(vec![response]);
                let mut extra = vec!["--executor-node", EXECUTOR, "--stream-id", STREAM];
                if command == "ack" {
                    extra.extend(["--seq", "7", "--cursor", "provider-7"]);
                }
                let result =
                    dispatch(&args(file.path(), command, &extra), Some(&endpoint)).unwrap();
                assert_eq!(result.exit_code, CliExitCode::Transport);
                assert_eq!(result.payload["error"]["type"], "invalid-stream-response");
                assert_eq!(result.payload["executor_node"], EXECUTOR);
                assert_eq!(result.payload["outcome_unknown"], command != "poll");
                assert!(result.payload.get("events").is_none());
                assert_eq!(task.join().unwrap()[0].body["executor_node"], EXECUTOR);
            }
        }
    }

    #[test]
    fn consumer_adopts_local_executor_before_repolling_or_acknowledging() {
        let file = credential();
        let (endpoint, task) = host(vec![
            json!({"executor_node":EXECUTOR,"stream":metadata(false,0,0),"events":[]}),
            json!({"executor_node":EXECUTOR,"stream":metadata(false,1,0),"events":[event()]}),
            json!({"executor_node":EXECUTOR,"stream":metadata(false,0,1),"acknowledged":true,"upstream_notified":false}),
        ]);
        let mut client =
            NativeStreamClient::new(consumer_config(file.path()), Some(&endpoint)).unwrap();
        assert!(client.executor_node().is_none());
        assert_eq!(client.poll(1, 2).unwrap().events.len(), 1);
        assert_eq!(client.executor_node().unwrap().as_str(), EXECUTOR);
        client.ack(&[7], &["provider-7".to_owned()]).unwrap();
        let requests = task.join().unwrap();
        assert!(requests[0].body["executor_node"].is_null());
        assert_eq!(requests[1].body["executor_node"], EXECUTOR);
        assert_eq!(requests[2].body["executor_node"], EXECUTOR);
        assert_eq!(requests[2].path, "/rpc/streams/ack");
    }

    #[test]
    fn consumer_long_poll_inherits_the_watch_deadline_without_an_extra_request() {
        let file = credential();
        let (endpoint, task) = host(vec![
            json!({"executor_node":EXECUTOR,"stream":metadata(false,0,0),"events":[]}),
        ]);
        let mut client =
            NativeStreamClient::new(consumer_config(file.path()), Some(&endpoint)).unwrap();
        let started = Instant::now();
        client.set_budget(ExecutionBudget::start(Some(100), started));
        let batch = client.poll(1, 60).unwrap();
        assert!(batch.events.is_empty());
        assert!(batch.wait_expired);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(task.join().unwrap().len(), 1);
    }

    #[test]
    fn consumer_expired_watch_does_not_ack_or_release_delivered_pairs() {
        let file = credential();
        let (endpoint, task) = host(vec![
            json!({"stream":metadata(false,1,0),"events":[event()]}),
        ]);
        let mut client =
            NativeStreamClient::new(consumer_config(file.path()), Some(&endpoint)).unwrap();
        client.poll(1, 0).unwrap();
        client.set_budget(ExecutionBudget::start(
            Some(1),
            Instant::now() - Duration::from_secs(1),
        ));
        assert!(matches!(
            client.ack(&[7], &["provider-7".to_owned()]),
            Err(Failure::Timeout)
        ));
        assert_eq!(client.delivered.get("provider-7"), Some(&7));
        assert_eq!(task.join().unwrap().len(), 1);
    }

    #[test]
    fn consumer_refuses_owner_changes_without_releasing_delivered_pairs() {
        for reply_owner in [json!(null), json!("node-other")] {
            let file = credential();
            let (endpoint, task) = host(vec![
                json!({"executor_node":EXECUTOR,"stream":metadata(false,1,0),"events":[event()]}),
                json!({"executor_node":reply_owner,"stream":metadata(false,0,1),"acknowledged":true,"upstream_notified":true}),
                json!({"executor_node":EXECUTOR,"stream":metadata(false,0,1),"acknowledged":true,"upstream_notified":false}),
                json!({"executor_node":reply_owner,"stream":metadata(false,1,0),"events":[event()]}),
            ]);
            let mut config = consumer_config(file.path());
            config.executor_node = Some(EXECUTOR.parse().unwrap());
            let mut client = NativeStreamClient::new(config, Some(&endpoint)).unwrap();
            client.poll(1, 0).unwrap();
            let cursors = ["provider-7".to_owned()];
            assert!(matches!(
                client.ack(&[7], &cursors),
                Err(Failure::InvalidResponse)
            ));
            assert_eq!(client.delivered.get("provider-7"), Some(&7));
            assert!(!client.ack(&[7], &cursors).unwrap().upstream_notified);
            assert!(matches!(client.poll(1, 0), Err(Failure::InvalidResponse)));
            assert!(client.delivered.is_empty());
            assert_eq!(client.executor_node().unwrap().as_str(), EXECUTOR);
            let requests = task.join().unwrap();
            assert_eq!(requests[1].body, requests[2].body);
            assert!(
                requests
                    .iter()
                    .all(|request| request.body["executor_node"] == EXECUTOR)
            );
        }
    }

    #[test]
    fn failed_wait_keeps_the_owner_observed_before_the_failure() {
        let file = credential();
        let (endpoint, task) = host(vec![
            json!({"executor_node":EXECUTOR,"stream":metadata(false,0,0),"events":[]}),
            json!({"executor_node":"node-other","stream":metadata(false,1,0),"events":[event()]}),
            json!({"executor_node":EXECUTOR,"stream":metadata(false,1,0),"events":[event()]}),
        ]);
        let mut client =
            NativeStreamClient::new(consumer_config(file.path()), Some(&endpoint)).unwrap();
        assert!(matches!(client.poll(1, 2), Err(Failure::InvalidResponse)));
        assert_eq!(client.executor_node().unwrap().as_str(), EXECUTOR);
        assert!(client.delivered.is_empty());
        assert_eq!(client.poll(1, 0).unwrap().events.len(), 1);
        let requests = task.join().unwrap();
        assert!(requests[0].body["executor_node"].is_null());
        assert_eq!(requests[1].body["executor_node"], EXECUTOR);
        assert_eq!(requests[2].body["executor_node"], EXECUTOR);
    }

    #[test]
    fn invalid_executor_is_rejected_before_loading_authority_or_transport() {
        let file = credential();
        let mut config = consumer_config(file.path());
        config.executor_node = Some(TailscaleNodeId::new("bad node"));
        assert!(matches!(
            NativeStreamClient::new(config, Some("http://127.0.0.1:1")),
            Err(Failure::InvalidRequest)
        ));
        let mut command = args(file.path(), "open", &[]);
        let StreamCommand::Open(open) = &mut command.command else {
            unreachable!();
        };
        open.auth.executor_node = Some(TailscaleNodeId::new("bad node"));
        let result = dispatch(&command, Some("http://127.0.0.1:1")).unwrap();
        assert_eq!(result.exit_code, CliExitCode::Validation);
        assert_eq!(result.payload["outcome_unknown"], false);
    }

    #[test]
    fn native_consumer_freezes_authority_and_only_acknowledges_delivered_pairs() {
        let file = credential();
        let mut second = event();
        second["cursor"] = json!("provider-8");
        second["data"]["instance_id"] = json!("inst_current");
        let mut pending = metadata(false, 2, 0);
        pending["window_size"] = json!(2);
        let mut partial = metadata(false, 1, 1);
        partial["window_size"] = json!(2);
        let mut settled = metadata(false, 0, 2);
        settled["window_size"] = json!(2);
        let (endpoint, task) = host(vec![
            json!({"stream":pending,"events":[event(),second]}),
            json!({"stream":partial,"acknowledged":true,"upstream_notified":false}),
            json!({"stream":settled,"acknowledged":true,"upstream_notified":true}),
        ]);
        let mut client =
            NativeStreamClient::new(consumer_config(file.path()), Some(&endpoint)).unwrap();
        assert_eq!(client.endpoint(), endpoint);
        assert_eq!(client.stream_id(), STREAM);
        assert_eq!(client.connector(), "fcp.telegram");
        assert_eq!(client.zone(), "z:work");
        assert_eq!(client.topic(), TOPIC);
        assert!(matches!(
            client.ack(&[7], &["provider-7".to_owned()]),
            Err(Failure::InvalidRequest)
        ));
        let batch = client.poll(2, 0).unwrap();
        assert_eq!(batch.events.len(), 2);
        assert!(!batch.closed);
        assert!(!batch.wait_expired);
        assert_eq!(
            batch.events[0].data.instance_id.as_str(),
            "inst_predecessor"
        );

        // File replacement cannot silently switch the caller of an already
        // prepared batch. A future consumer must explicitly load new authority.
        std::fs::write(file.path(), "REPLACEMENT_CREDENTIAL_SENTINEL").unwrap();
        for (seqs, cursors) in [
            (vec![8], vec!["provider-8".to_owned()]),
            (vec![7], vec!["undelivered-cursor".to_owned()]),
            (
                vec![7, 7],
                vec!["provider-7".to_owned(), "provider-7".to_owned()],
            ),
        ] {
            assert!(matches!(
                client.ack(&seqs, &cursors),
                Err(Failure::InvalidRequest)
            ));
        }
        assert!(
            !client
                .ack(&[7], &["provider-8".to_owned()])
                .unwrap()
                .upstream_notified
        );
        assert!(matches!(
            client.ack(&[7], &["provider-8".to_owned()]),
            Err(Failure::InvalidRequest)
        ));
        assert!(
            client
                .ack(&[7], &["provider-7".to_owned()])
                .unwrap()
                .upstream_notified
        );

        let requests = task.join().unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].path, "/rpc/streams/poll");
        for request in &requests {
            assert_eq!(request.body["auth"], requests[0].body["auth"]);
            assert_eq!(request.body["stream_id"], STREAM);
            assert_eq!(request.body["auth"]["connector_id"], "fcp.telegram");
            assert_eq!(request.body["auth"]["zone_id"], "z:work");
            assert_eq!(request.body["auth"]["topic"], TOPIC);
            assert_eq!(request.body["auth"]["request_id"], "consumer-stable-1");
            assert!(
                !request
                    .body
                    .to_string()
                    .contains("REPLACEMENT_CREDENTIAL_SENTINEL")
            );
        }
        assert_eq!(requests[1].body["ack"]["seqs"], json!([7]));
        assert_eq!(requests[1].body["ack"]["cursors"], json!(["provider-8"]));
        assert_eq!(requests[2].body["ack"]["seqs"], json!([7]));
        assert_eq!(requests[2].body["ack"]["cursors"], json!(["provider-7"]));
    }

    #[test]
    fn native_consumer_rejects_changed_binding_and_invalidates_old_poll_pairs() {
        for (field, value) in [
            ("/binding/principal", json!("agent:mallory")),
            ("/binding/connector_id", json!("fcp.slack")),
            ("/binding/zone_id", json!("z:private")),
            ("/binding/topic", json!("telegram.callback_query")),
            ("/window_size", json!(2)),
            ("/stream_id", json!("another-stream")),
            ("/durable", json!(false)),
        ] {
            let file = credential();
            let mut changed = metadata(false, 1, 0);
            *changed.pointer_mut(field).unwrap() = value;
            let (endpoint, task) = host(vec![
                json!({"stream":metadata(false,1,0),"events":[event()]}),
                json!({"stream":changed,"events":[event()]}),
            ]);
            let mut client =
                NativeStreamClient::new(consumer_config(file.path()), Some(&endpoint)).unwrap();
            assert_eq!(client.poll(1, 0).unwrap().events.len(), 1);
            assert!(matches!(client.poll(1, 0), Err(Failure::InvalidResponse)));
            assert!(matches!(
                client.ack(&[7], &["provider-7".to_owned()]),
                Err(Failure::InvalidRequest)
            ));
            assert!(
                task.join()
                    .unwrap()
                    .iter()
                    .all(|request| request.path == "/rpc/streams/poll")
            );
        }
    }

    #[test]
    fn native_consumer_ack_rejects_changed_binding_without_claiming_settlement() {
        for (field, value) in [
            ("/binding/principal", json!("agent:mallory")),
            ("/window_size", json!(2)),
        ] {
            let file = credential();
            let mut changed = metadata(false, 0, 1);
            *changed.pointer_mut(field).unwrap() = value;
            let (endpoint, task) = host(vec![
                json!({"stream":metadata(false,1,0),"events":[event()]}),
                json!({"stream":changed,"acknowledged":true,"upstream_notified":true}),
            ]);
            let mut client =
                NativeStreamClient::new(consumer_config(file.path()), Some(&endpoint)).unwrap();
            client.poll(1, 0).unwrap();
            assert!(matches!(
                client.ack(&[7], &["provider-7".to_owned()]),
                Err(Failure::InvalidResponse)
            ));
            assert_eq!(client.delivered.get("provider-7"), Some(&7));
            assert_eq!(task.join().unwrap().len(), 2);
        }
    }

    #[test]
    fn native_consumer_rejects_unacknowledgeable_or_cross_scope_events() {
        for (field, value) in [
            ("/data/connector_id", json!("fcp.slack")),
            ("/data/zone_id", json!("z:private")),
            ("/topic", json!("telegram.callback_query")),
            ("/requires_ack", json!(false)),
            ("/cursor", json!("")),
            ("/cursor", json!("x".repeat(1025))),
            ("/cursor", json!("cursor\nforged")),
        ] {
            let file = credential();
            let mut changed = event();
            *changed.pointer_mut(field).unwrap() = value;
            let (endpoint, task) = host(vec![
                json!({"stream":metadata(false,1,0),"events":[changed]}),
            ]);
            let mut client =
                NativeStreamClient::new(consumer_config(file.path()), Some(&endpoint)).unwrap();
            assert!(matches!(client.poll(1, 0), Err(Failure::InvalidResponse)));
            assert!(client.delivered.is_empty());
            assert_eq!(task.join().unwrap()[0].path, "/rpc/streams/poll");
        }
    }

    #[test]
    fn native_consumer_validates_configuration_and_poll_limits_before_transport() {
        let file = credential();
        let original = consumer_config(file.path());
        let mut invalid = original.clone();
        invalid.stream_id = "../../other-stream".to_owned();
        assert!(matches!(
            NativeStreamClient::new(invalid, Some("http://127.0.0.1:1")),
            Err(Failure::InvalidRequest)
        ));
        for seconds in [0, 91, u64::MAX] {
            let mut invalid = original.clone();
            invalid.timeout_seconds = seconds;
            assert!(matches!(
                NativeStreamClient::new(invalid, Some("http://127.0.0.1:1")),
                Err(Failure::InvalidRequest)
            ));
        }
        let mut client = NativeStreamClient::new(original, Some("http://127.0.0.1:1")).unwrap();
        for (batch_size, wait_seconds) in [(0, 0), (65, 0), (1, 61), (1, u64::MAX)] {
            assert!(matches!(
                client.poll(batch_size, wait_seconds),
                Err(Failure::InvalidRequest)
            ));
        }
    }

    #[test]
    fn native_consumer_lost_ack_response_preserves_exact_retry_identity() {
        let file = credential();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = std::thread::spawn(move || {
            let mut requests = Vec::new();
            for step in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                requests.push(read_request(&mut stream));
                if step == 1 {
                    // The host may have committed this ACK. Dropping the
                    // response cannot cause an automatic retry or data loss.
                    continue;
                }
                let response = if step == 0 {
                    json!({"stream":metadata(false,1,0),"events":[event()]})
                } else {
                    json!({"stream":metadata(false,0,1),"acknowledged":true,"upstream_notified":false})
                };
                let body = response.to_string();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
            requests
        });
        let mut client =
            NativeStreamClient::new(consumer_config(file.path()), Some(&endpoint)).unwrap();
        client.poll(1, 0).unwrap();
        let cursors = ["provider-7".to_owned()];
        assert!(matches!(
            client.ack(&[7], &cursors),
            Err(Failure::Transport)
        ));
        assert_eq!(client.delivered.get("provider-7"), Some(&7));
        assert!(!client.ack(&[7], &cursors).unwrap().upstream_notified);
        assert!(client.delivered.is_empty());
        let requests = task.join().unwrap();
        assert_eq!(requests[1].path, "/rpc/streams/ack");
        assert_eq!(requests[2].path, "/rpc/streams/ack");
        assert_eq!(requests[1].body, requests[2].body);
    }

    #[test]
    fn native_consumer_errors_never_echo_credential_bearing_host_bodies() {
        let file = credential();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            let body = format!("SERVER_SECRET_ECHO {}", request.body);
            write!(
                stream,
                "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            request
        });
        let mut client =
            NativeStreamClient::new(consumer_config(file.path()), Some(&endpoint)).unwrap();
        let error = match client.poll(1, 0) {
            Ok(_) => panic!("host denied stream authority"),
            Err(error) => error,
        };
        assert_eq!(error.details().0, "stream-authority-denied");
        assert_eq!(error.details().2, CliExitCode::PolicyDenied);
        assert!(!error.to_string().contains("SERVER_SECRET_ECHO"));
        assert!(!error.to_string().contains("capability_token"));
        assert!(client.delivered.is_empty());
        assert_eq!(task.join().unwrap().path, "/rpc/streams/poll");
    }

    #[test]
    fn open_poll_ack_close_preserve_host_identity_and_exact_delivery_pairs() {
        let file = credential();
        let (endpoint, task) = host(vec![
            json!({"stream":metadata(false,0,0),"attached":true,"replay_supported":false,"capability_token":"SERVER_ECHO_SENTINEL"}),
            json!({"stream":metadata(false,1,0),"events":[event()]}),
            json!({"stream":metadata(false,0,1),"acknowledged":true,"upstream_notified":false}),
            json!({"stream":metadata(true,0,1),"upstream_notified":true}),
        ]);
        let opened = dispatch(&args(file.path(), "open", &[]), Some(&endpoint)).unwrap();
        assert_eq!(opened.exit_code, CliExitCode::Success);
        assert_eq!(opened.payload["host"], endpoint);
        assert_eq!(opened.payload["stream"]["stream_id"], STREAM);
        assert!(!opened.payload.to_string().contains("SERVER_ECHO_SENTINEL"));
        let polled = dispatch(
            &args(file.path(), "poll", &["--stream-id", STREAM]),
            Some(&endpoint),
        )
        .unwrap();
        assert_eq!(polled.exit_code, CliExitCode::Success);
        assert_eq!(polled.payload["acknowledged"], false);
        assert_eq!(
            polled.payload["events"][0]["data"]["instance_id"],
            "inst_predecessor"
        );
        assert_eq!(polled.payload["ack_request"]["seqs"], json!([7]));
        assert_eq!(
            polled.payload["ack_request"]["cursors"],
            json!(["provider-7"])
        );
        let acked = dispatch(
            &args(
                file.path(),
                "ack",
                &[
                    "--stream-id",
                    STREAM,
                    "--seq",
                    "7",
                    "--cursor",
                    "provider-7",
                ],
            ),
            Some(&endpoint),
        )
        .unwrap();
        assert_eq!(acked.exit_code, CliExitCode::Success);
        assert_eq!(acked.payload["acknowledged"], true);
        assert_eq!(acked.payload["upstream_notified"], false);
        let closed = dispatch(
            &args(file.path(), "close", &["--stream-id", STREAM]),
            Some(&endpoint),
        )
        .unwrap();
        assert_eq!(closed.exit_code, CliExitCode::Success);
        assert_eq!(closed.payload["stream"]["closed"], true);
        let requests = task.join().unwrap();
        assert_eq!(
            requests
                .iter()
                .map(|request| request.path.as_str())
                .collect::<Vec<_>>(),
            [
                "/rpc/streams/open",
                "/rpc/streams/poll",
                "/rpc/streams/ack",
                "/rpc/streams/close"
            ]
        );
        for request in &requests {
            assert_eq!(request.body["auth"]["request_id"], "consumer-stable-1");
            assert_eq!(request.body["auth"]["connector_id"], "fcp.telegram");
            assert!(request.body["auth"]["capability_token"].is_array());
            assert!(request.body.get("executor_node").is_none());
        }
        assert_eq!(requests[2].body["ack"]["seqs"], json!([7]));
        assert_eq!(requests[2].body["ack"]["cursors"], json!(["provider-7"]));
    }

    #[test]
    fn resume_reuses_stream_request_identity_and_declared_window() {
        let file = credential();
        let response =
            json!({"stream":metadata(false,0,0),"attached":true,"replay_supported":false});
        let (endpoint, task) = host(vec![response.clone(), response]);
        let args = args(file.path(), "open", &["--stream-id", STREAM]);
        for _ in 0..2 {
            assert_eq!(
                dispatch(&args, Some(&endpoint)).unwrap().exit_code,
                CliExitCode::Success
            );
        }
        let requests = task.join().unwrap();
        assert_eq!(requests[0].body, requests[1].body);
        assert_eq!(requests[0].body["stream_id"], STREAM);
        assert_eq!(requests[0].body["window_size"], 1);
    }

    #[test]
    fn bounded_wait_stops_at_first_batch_without_acknowledging() {
        let file = credential();
        let (endpoint, task) = host(vec![
            json!({"stream":metadata(false,0,0),"events":[]}),
            json!({"stream":metadata(false,1,0),"events":[event()]}),
        ]);
        let result = dispatch(
            &args(
                file.path(),
                "poll",
                &["--stream-id", STREAM, "--wait-seconds", "2"],
            ),
            Some(&endpoint),
        )
        .unwrap();
        assert_eq!(result.exit_code, CliExitCode::Success);
        assert_eq!(result.payload["events"].as_array().unwrap().len(), 1);
        assert_eq!(result.payload["acknowledged"], false);
        let requests = task.join().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(
            requests
                .iter()
                .all(|request| request.path == "/rpc/streams/poll")
        );
    }

    #[test]
    fn bounded_wait_returns_last_empty_batch_when_deadline_expires() {
        let file = credential();
        let empty = json!({"stream":metadata(false,0,0),"events":[]});
        let (endpoint, task) = host(vec![empty.clone(), empty]);
        let started = Instant::now();
        let result = dispatch(
            &args(
                file.path(),
                "poll",
                &["--stream-id", STREAM, "--wait-seconds", "1"],
            ),
            Some(&endpoint),
        )
        .unwrap();
        assert_eq!(result.exit_code, CliExitCode::Success);
        assert_eq!(result.payload["wait_expired"], true);
        assert_eq!(result.payload["acknowledged"], false);
        assert!(started.elapsed() < Duration::from_secs(3));
        assert_eq!(task.join().unwrap().len(), 2);
    }

    #[test]
    fn poll_rejects_wrong_scope_and_ambiguous_event_identities() {
        let file = credential();
        let mut wrong_zone = event();
        wrong_zone["data"]["zone_id"] = json!("z:owner");
        let mut wrong_topic = metadata(false, 1, 0);
        wrong_topic["binding"]["topic"] = json!("telegram.callback_query");
        let mut non_durable = metadata(false, 1, 0);
        non_durable["durable"] = json!(false);
        let mut two_pending = metadata(false, 2, 0);
        two_pending["window_size"] = json!(2);
        let (endpoint, task) = host(vec![
            json!({"stream":metadata(false,1,0),"events":[wrong_zone]}),
            json!({"stream":wrong_topic,"events":[event()]}),
            json!({"stream":non_durable,"events":[event()]}),
            json!({"stream":two_pending,"events":[event(),event()]}),
        ]);
        for _ in 0..4 {
            let result = dispatch(
                &args(
                    file.path(),
                    "poll",
                    &["--stream-id", STREAM, "--batch-size", "2"],
                ),
                Some(&endpoint),
            )
            .unwrap();
            assert_eq!(result.exit_code, CliExitCode::Transport);
            assert_eq!(result.payload["error"]["type"], "invalid-stream-response");
            assert!(result.payload.get("events").is_none());
        }
        task.join().unwrap();
    }

    #[test]
    fn restarted_instances_can_share_sequences_with_distinct_cursors() {
        let file = credential();
        let mut second = event();
        second["data"]["instance_id"] = json!("inst_current");
        second["cursor"] = json!("provider-8");
        let mut pending = metadata(false, 2, 0);
        pending["window_size"] = json!(2);
        let mut acknowledged = metadata(false, 0, 2);
        acknowledged["window_size"] = json!(2);
        let (endpoint, task) = host(vec![
            json!({"stream":pending,"events":[event(),second]}),
            json!({"stream":acknowledged,"acknowledged":true,"upstream_notified":true}),
        ]);
        let polled = dispatch(
            &args(
                file.path(),
                "poll",
                &["--stream-id", STREAM, "--batch-size", "2"],
            ),
            Some(&endpoint),
        )
        .unwrap();
        assert_eq!(polled.exit_code, CliExitCode::Success);
        assert_eq!(polled.payload["ack_request"]["seqs"], json!([7, 7]));
        assert_eq!(
            polled.payload["ack_request"]["cursors"],
            json!(["provider-7", "provider-8"])
        );
        let acked = dispatch(
            &args(
                file.path(),
                "ack",
                &[
                    "--stream-id",
                    STREAM,
                    "--seq",
                    "7",
                    "--cursor",
                    "provider-7",
                    "--seq",
                    "7",
                    "--cursor",
                    "provider-8",
                ],
            ),
            Some(&endpoint),
        )
        .unwrap();
        assert_eq!(acked.exit_code, CliExitCode::Success);
        let requests = task.join().unwrap();
        assert_eq!(requests[1].body["ack"]["seqs"], json!([7, 7]));
        assert_eq!(
            requests[1].body["ack"]["cursors"],
            json!(["provider-7", "provider-8"])
        );
    }

    #[test]
    fn invalid_ack_pairs_and_oversized_credentials_fail_before_transport() {
        for (seqs, cursors) in [
            (vec![], vec![]),
            (vec![1], vec![]),
            (vec![1, 2], vec!["a".into(), "a".into()]),
            (vec![1], vec!["".into()]),
        ] {
            assert!(validate_ack_pairs(&seqs, &cursors).is_err());
        }
        let mut file = credential();
        file.as_file_mut().set_len(MAX_TOKEN_BYTES + 1).unwrap();
        let result = dispatch(&args(file.path(), "open", &[]), Some("http://127.0.0.1:1")).unwrap();
        assert_eq!(result.exit_code, CliExitCode::Validation);
        assert_eq!(result.payload["error"]["type"], "invalid-stream-capability");
        assert_eq!(result.payload["outcome_unknown"], false);
    }

    #[test]
    fn redirect_never_forwards_capability_or_echoes_error_body() {
        let file = credential();
        let sink = TcpListener::bind("127.0.0.1:0").unwrap();
        sink.set_nonblocking(true).unwrap();
        let location = format!("http://{}/credential-sink", sink.local_addr().unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            let echo = format!("SERVER_SECRET_ECHO {}", request.body);
            write!(stream, "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{echo}", echo.len()).unwrap();
            request
        });
        let result = dispatch(&args(file.path(), "open", &[]), Some(&endpoint)).unwrap();
        assert_eq!(result.payload["error"]["type"], "stream-redirect-refused");
        assert_eq!(result.payload["outcome_unknown"], true);
        assert!(!result.payload.to_string().contains("SERVER_SECRET_ECHO"));
        assert!(!result.payload.to_string().contains("capability_token"));
        assert!(
            matches!(sink.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
        assert_eq!(task.join().unwrap().path, "/rpc/streams/open");
    }

    #[test]
    fn response_size_limit_applies_with_and_without_content_length() {
        for declared in [true, false] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = format!("http://{}", listener.local_addr().unwrap());
            let task = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                read_request(&mut stream);
                write!(stream, "HTTP/1.1 200 OK\r\nConnection: close\r\n").unwrap();
                if declared {
                    write!(stream, "Content-Length: {}\r\n\r\n", MAX_RESPONSE_BYTES + 1).unwrap();
                } else {
                    stream.write_all(b"\r\n").unwrap();
                    let _ = stream.write_all(&vec![b' '; MAX_RESPONSE_BYTES as usize + 1]);
                }
            });
            let client = HostAdminClient::new(&endpoint).unwrap();
            let result: std::result::Result<Value, _> = post(
                &client,
                "/rpc/streams/poll",
                &json!({}),
                Duration::from_secs(3),
            );
            assert!(matches!(result, Err(Failure::ResponseTooLarge)));
            task.join().unwrap();
        }
    }

    #[test]
    fn deadline_includes_slow_response_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let task = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request(&mut stream);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{")
                .unwrap();
            std::thread::sleep(Duration::from_millis(150));
            let _ = stream.write_all(b"}");
        });
        let client = HostAdminClient::new(&endpoint).unwrap();
        let result: std::result::Result<Value, _> = post(
            &client,
            "/rpc/streams/poll",
            &json!({}),
            Duration::from_millis(40),
        );
        assert!(matches!(result, Err(Failure::Timeout)));
        task.join().unwrap();
    }
}
