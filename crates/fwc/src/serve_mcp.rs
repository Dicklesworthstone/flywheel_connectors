//! MCP server module for exposing connectors as MCP tools via JSON-RPC 2.0.
//!
//! This module implements the data layer of `fwc serve-mcp`. It defines the
//! JSON-RPC protocol types, MCP server state, and request-handling logic. The
//! stdio transport stays small and delegates tool execution to a callback so
//! the CLI can reuse the existing invoke planning path.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use fcp_async_core::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::history::{HistoryFilter, HistoryStore};
use crate::mcp_resources::{
    self, McpPrompt as RegistryPrompt, McpResource as RegistryResource, McpResourceRegistry,
    ParsedUri,
};
use crate::readiness::DiscoveredConnector;
use crate::zone_scope::{
    ToolCapabilityToken, ViolationReason, ZoneId, ZoneRegistry, ZoneScopedTool, ZoneViolation,
    validate_tool_call,
};
use crate::{catalog, export_tools};

// ── JSON-RPC 2.0 Error Codes ────────────────────────────────────────────

/// Parse error: invalid JSON was received by the server.
pub const PARSE_ERROR: i32 = -32_700;
/// Invalid request: the JSON sent is not a valid request object.
pub const INVALID_REQUEST: i32 = -32_600;
/// Method not found: the method does not exist or is not available.
pub const METHOD_NOT_FOUND: i32 = -32_601;
/// Invalid params: invalid method parameters.
pub const INVALID_PARAMS: i32 = -32_602;
/// Internal error: internal JSON-RPC error.
pub const INTERNAL_ERROR: i32 = -32_603;

// ── JSON-RPC 2.0 Protocol Types ─────────────────────────────────────────

/// A JSON-RPC 2.0 request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// Protocol version, always `"2.0"`.
    pub jsonrpc: String,
    /// Request ID (may be null for notifications).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    /// Method name to invoke.
    pub method: String,
    /// Optional method parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// A JSON-RPC 2.0 response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// Protocol version, always `"2.0"`.
    pub jsonrpc: String,
    /// Request ID this response corresponds to.
    pub id: Value,
    /// Successful result (mutually exclusive with `error`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error result (mutually exclusive with `result`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    /// Create a success response.
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response.
    pub fn error(id: Value, error: JsonRpcError) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }

    /// Return the id.
    pub const fn id(&self) -> &Value {
        &self.id
    }

    /// Return the result if present.
    pub const fn result(&self) -> Option<&Value> {
        self.result.as_ref()
    }

    /// Return whether this response is an error.
    pub const fn is_error(&self) -> bool {
        self.error.is_some()
    }
}

/// A JSON-RPC 2.0 error object.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Error code.
    pub code: i32,
    /// Human-readable error message.
    pub message: String,
    /// Optional structured data about the error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcError {
    /// Create a new error with code and message.
    pub fn new(code: i32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            data: None,
        }
    }

    /// Builder: attach extra data to the error.
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }

    /// Create a parse error.
    pub fn parse_error(detail: impl Into<String>) -> Self {
        Self::new(PARSE_ERROR, detail)
    }

    /// Create an invalid request error.
    pub fn invalid_request(detail: impl Into<String>) -> Self {
        Self::new(INVALID_REQUEST, detail)
    }

    /// Create a method-not-found error.
    pub fn method_not_found(method: &str) -> Self {
        Self::new(METHOD_NOT_FOUND, format!("Method not found: {method}"))
    }

    /// Create an invalid-params error.
    pub fn invalid_params(detail: impl Into<String>) -> Self {
        Self::new(INVALID_PARAMS, detail)
    }

    /// Create an internal error.
    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(INTERNAL_ERROR, detail)
    }

    /// Return the error code.
    pub const fn code(&self) -> i32 {
        self.code
    }

    /// Return the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

// ── Transport Mode ──────────────────────────────────────────────────────

/// Transport mode for the MCP server.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    /// Standard I/O (newline-delimited JSON).
    #[default]
    Stdio,
    /// Server-Sent Events over HTTP.
    Sse {
        /// Port to listen on.
        port: u16,
    },
}

impl std::fmt::Display for TransportMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stdio => write!(f, "stdio"),
            Self::Sse { port } => write!(f, "sse:{port}"),
        }
    }
}

// ── MCP Server Configuration ────────────────────────────────────────────

/// Configuration for the MCP server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpServerConfig {
    /// Transport mode (stdio or SSE).
    pub transport: TransportMode,
    /// Optional zone filter — only expose connectors in this zone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone_filter: Option<String>,
    /// Optional connector filter — only expose this specific connector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector_filter: Option<String>,
    /// Optional risk ceiling — only expose tools at or below this risk level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_max: Option<String>,
    /// Whether to expose resources.
    #[serde(default = "default_true")]
    pub include_resources: bool,
    /// Whether to expose prompts.
    #[serde(default = "default_true")]
    pub include_prompts: bool,
}

const fn default_true() -> bool {
    true
}

impl Default for McpServerConfig {
    fn default() -> Self {
        Self {
            transport: TransportMode::default(),
            zone_filter: None,
            connector_filter: None,
            risk_max: None,
            include_resources: true,
            include_prompts: true,
        }
    }
}

impl McpServerConfig {
    /// Create a new config with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set transport mode.
    pub const fn with_transport(mut self, transport: TransportMode) -> Self {
        self.transport = transport;
        self
    }

    /// Builder: set zone filter.
    pub fn with_zone_filter(mut self, zone: impl Into<String>) -> Self {
        self.zone_filter = Some(zone.into());
        self
    }

    /// Builder: set connector filter.
    pub fn with_connector_filter(mut self, connector: impl Into<String>) -> Self {
        self.connector_filter = Some(connector.into());
        self
    }

    /// Builder: set the maximum risk level to expose (inclusive).
    pub fn with_risk_max(mut self, risk_max: impl Into<String>) -> Self {
        self.risk_max = Some(risk_max.into());
        self
    }

    /// Builder: disable resources.
    pub const fn without_resources(mut self) -> Self {
        self.include_resources = false;
        self
    }

    /// Builder: disable prompts.
    pub const fn without_prompts(mut self) -> Self {
        self.include_prompts = false;
        self
    }
}

// ── MCP Server Info ─────────────────────────────────────────────────────

/// Server identity and protocol version.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpServerInfo {
    /// Server name.
    pub name: String,
    /// Server version.
    pub version: String,
    /// MCP protocol version supported.
    pub protocol_version: String,
}

impl Default for McpServerInfo {
    fn default() -> Self {
        Self {
            name: "fwc".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: "2024-11-05".to_string(),
        }
    }
}

impl McpServerInfo {
    /// Return the server name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the server version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Return the protocol version.
    pub fn protocol_version(&self) -> &str {
        &self.protocol_version
    }
}

// ── MCP Tool Definition ─────────────────────────────────────────────────

/// An MCP tool registered with the server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpToolDefinition {
    /// Tool name (unique identifier for the tool).
    pub name: String,
    /// Human-readable description of what the tool does.
    pub description: String,
    /// JSON Schema describing the tool's input parameters.
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    /// Connector that provides this tool.
    pub connector_id: String,
    /// Operation within the connector.
    pub operation_id: String,
    /// Optional MCP annotations preserved from the export surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<export_tools::McpToolAnnotations>,
    /// Truthfulness metadata describing the inventory source for this tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<catalog::ExportedToolProvenance>,
    /// Zones where this tool may be exposed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_zones: Vec<String>,
}

impl McpToolDefinition {
    /// Create a new tool definition.
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        input_schema: Value,
        connector_id: impl Into<String>,
        operation_id: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            input_schema,
            connector_id: connector_id.into(),
            operation_id: operation_id.into(),
            annotations: None,
            provenance: None,
            supported_zones: Vec::new(),
        }
    }

    /// Return the tool name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the connector that provides this tool.
    pub fn connector_id(&self) -> &str {
        &self.connector_id
    }

    /// Return the operation id.
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Builder: attach supported zones to this tool.
    pub fn with_supported_zones(mut self, mut supported_zones: Vec<String>) -> Self {
        supported_zones.sort();
        supported_zones.dedup();
        self.supported_zones = supported_zones;
        self
    }

    /// Builder: attach MCP annotations to this tool.
    pub fn with_annotations(
        mut self,
        annotations: Option<export_tools::McpToolAnnotations>,
    ) -> Self {
        self.annotations = annotations;
        self
    }

    /// Builder: attach provenance metadata to this tool.
    pub fn with_provenance(mut self, provenance: catalog::ExportedToolProvenance) -> Self {
        self.provenance = Some(provenance);
        self
    }

    /// Return the supported zones.
    pub fn supported_zones(&self) -> &[String] {
        &self.supported_zones
    }

    /// Whether the tool can be exposed in the given zone.
    pub fn supports_zone(&self, zone: &str) -> bool {
        self.supported_zones.is_empty()
            || self
                .supported_zones
                .iter()
                .any(|candidate| zone_selector_matches(candidate, zone))
    }
}

fn zone_selector_matches(selector: &str, zone: &str) -> bool {
    selector == zone
        || (selector == fcp_manifest::ZonePattern::PROJECT_WILDCARD
            && zone
                .parse::<fcp_core::ZoneId>()
                .is_ok_and(|zone| zone.as_str().starts_with("z:project:")))
}

// ── MCP Resource Entry ──────────────────────────────────────────────────

/// A resource registered with the MCP server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpResourceEntry {
    /// Resource URI.
    pub uri: String,
    /// Human-readable name.
    pub name: String,
    /// Description of the resource.
    pub description: String,
    /// MIME type of the resource content.
    #[serde(rename = "mimeType")]
    pub mime_type: String,
}

impl McpResourceEntry {
    /// Create a new resource entry.
    pub fn new(
        uri: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
        mime_type: impl Into<String>,
    ) -> Self {
        Self {
            uri: uri.into(),
            name: name.into(),
            description: description.into(),
            mime_type: mime_type.into(),
        }
    }

    /// Return the resource URI.
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// Return the resource name.
    pub fn name(&self) -> &str {
        &self.name
    }

    fn from_registry(resource: &RegistryResource) -> Self {
        Self::new(
            resource.uri.clone(),
            resource.name.clone(),
            resource.description.clone(),
            resource.mime_type.clone(),
        )
    }
}

// ── MCP Prompt Entry ────────────────────────────────────────────────────

/// A prompt registered with the MCP server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpPromptEntry {
    /// Prompt name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Arguments accepted by this prompt.
    pub arguments: Vec<PromptArgDef>,
}

impl McpPromptEntry {
    /// Create a new prompt entry.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            arguments: Vec::new(),
        }
    }

    /// Builder: add an argument.
    pub fn with_argument(mut self, arg: PromptArgDef) -> Self {
        self.arguments.push(arg);
        self
    }

    /// Return the prompt name.
    pub fn name(&self) -> &str {
        &self.name
    }

    fn from_registry(prompt: &RegistryPrompt) -> Self {
        let mut entry = Self::new(prompt.uri.clone(), prompt.description.clone());
        for argument in &prompt.arguments {
            entry = entry.with_argument(if argument.required {
                PromptArgDef::required(argument.name.clone(), argument.description.clone())
            } else {
                PromptArgDef::optional(argument.name.clone(), argument.description.clone())
            });
        }
        entry
    }
}

/// A single prompt argument definition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromptArgDef {
    /// Argument name.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Whether this argument is required.
    pub required: bool,
}

impl PromptArgDef {
    /// Create a required argument.
    pub fn required(name: impl Into<String>, desc: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: desc.into(),
            required: true,
        }
    }

    /// Create an optional argument.
    pub fn optional(name: impl Into<String>, desc: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: desc.into(),
            required: false,
        }
    }
}

// ── Discovered Operation Entry ──────────────────────────────────────────

/// Minimal operation record used to populate MCP tools
/// without pulling in the full [`crate::readiness::DiscoveredOperation`]
/// dependency graph.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscoveredOperationEntry {
    /// Connector that owns this operation (e.g. `"github"`).
    pub connector_id: String,
    /// Operation identifier (e.g. `"list_issues"`).
    pub operation_id: String,
    /// Human-readable description.
    pub description: String,
    /// JSON Schema for the operation's input.
    pub input_schema: Value,
}

impl DiscoveredOperationEntry {
    /// Create a new operation entry.
    pub fn new(
        connector_id: impl Into<String>,
        operation_id: impl Into<String>,
        description: impl Into<String>,
        input_schema: Value,
    ) -> Self {
        Self {
            connector_id: connector_id.into(),
            operation_id: operation_id.into(),
            description: description.into(),
            input_schema,
        }
    }

    /// Return the fully-qualified tool name.
    pub fn tool_name(&self) -> String {
        format!("{}.{}", self.connector_id, self.operation_id)
    }
}

// ── MCP Server State ────────────────────────────────────────────────────

/// Holds the complete state for the MCP server: tools, resources, prompts,
/// configuration, and server identity.
#[derive(Clone, Debug, Default)]
pub struct McpServerState {
    /// Registered MCP tools.
    pub tools: Vec<McpToolDefinition>,
    /// Registered MCP resources.
    pub resources: Vec<McpResourceEntry>,
    /// Registered MCP prompts.
    pub prompts: Vec<McpPromptEntry>,
    /// Server configuration.
    pub config: McpServerConfig,
    /// Server identity info.
    pub server_info: McpServerInfo,
}

impl McpServerState {
    /// Create a new builder for `McpServerState`.
    pub fn builder() -> McpServerBuilder {
        McpServerBuilder::default()
    }

    /// Return the number of registered tools.
    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }

    /// Return the number of registered resources.
    pub fn resource_count(&self) -> usize {
        self.resources.len()
    }

    /// Return the number of registered prompts.
    pub fn prompt_count(&self) -> usize {
        self.prompts.len()
    }

    /// Look up a tool by name.
    pub fn find_tool(&self, name: &str) -> Option<&McpToolDefinition> {
        self.tools.iter().find(|t| t.name == name)
    }

    /// Look up a resource by URI.
    pub fn find_resource(&self, uri: &str) -> Option<&McpResourceEntry> {
        self.resources.iter().find(|r| r.uri == uri)
    }

    /// Look up a prompt by name.
    pub fn find_prompt(&self, name: &str) -> Option<&McpPromptEntry> {
        self.prompts.iter().find(|p| p.name == name)
    }

    /// Return tools filtered by connector id.
    pub fn tools_for_connector(&self, connector_id: &str) -> Vec<&McpToolDefinition> {
        self.tools
            .iter()
            .filter(|t| t.connector_id == connector_id)
            .collect()
    }
}

/// Convenience constructor: build an `McpServerState` from a list of
/// [`DiscoveredOperationEntry`] values.
pub fn from_operations(ops: &[DiscoveredOperationEntry]) -> McpServerState {
    let tools = ops.iter().map(|op| {
        McpToolDefinition::new(
            op.tool_name(),
            &op.description,
            op.input_schema.clone(),
            &op.connector_id,
            &op.operation_id,
        )
    });
    state_from_tools(tools, McpServerConfig::default())
}

/// Build an MCP server state from discovered connectors.
pub fn state_from_connectors(
    connectors: &[&DiscoveredConnector],
    config: McpServerConfig,
) -> Result<McpServerState> {
    let options = export_tools::ExportOptions::default();
    let tools = connectors
        .iter()
        .flat_map(|connector| {
            connector.operations.iter().map(|operation| {
                let tool = export_tools::try_to_mcp_tool(operation, &options)?;
                Ok(McpToolDefinition::new(
                    tool.name.clone(),
                    tool.description,
                    tool.input_schema,
                    connector.slug.clone(),
                    operation.preferred_selector.clone(),
                )
                .with_annotations(tool.annotations)
                .with_provenance(catalog::tool_provenance(
                    &tool.name,
                    &connector.slug,
                    catalog::ToolInventorySource::WorkspaceManifest,
                    catalog::ToolAvailability::Unknown,
                ))
                .with_supported_zones(connector.supported_zones.clone()))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(state_from_tools(tools, config))
}

/// Build an MCP server state from already-prepared tool definitions.
#[must_use]
pub fn state_from_tools<I>(tools: I, config: McpServerConfig) -> McpServerState
where
    I: IntoIterator<Item = McpToolDefinition>,
{
    let tools: Vec<McpToolDefinition> = tools.into_iter().collect();
    let registry = registry_from_tools(&tools);
    let mut builder = McpServerState::builder().with_config(config);
    for tool in &tools {
        builder = builder.with_tool(tool.clone());
    }
    for resource in registry.list_resources() {
        builder = builder.with_resource(McpResourceEntry::from_registry(resource));
    }
    for prompt in registry.list_prompts() {
        builder = builder.with_prompt(McpPromptEntry::from_registry(prompt));
    }
    builder.build()
}

fn registry_from_tools(tools: &[McpToolDefinition]) -> McpResourceRegistry {
    let mut operations_by_connector: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for tool in tools {
        operations_by_connector
            .entry(tool.connector_id.clone())
            .or_default()
            .insert(tool.operation_id.clone());
    }

    let mut registry = McpResourceRegistry::new();
    for (connector_id, operations) in &operations_by_connector {
        registry.register_connector(connector_id);
        for operation_id in operations {
            registry.register_operation_prompt(connector_id, operation_id);
        }
    }
    if !operations_by_connector.is_empty() {
        registry.register_global_resources();
    }
    registry
}

fn tool_matches_server_filters(tool: &McpToolDefinition, config: &McpServerConfig) -> bool {
    let connector_ok = config
        .connector_filter
        .as_deref()
        .is_none_or(|connector| tool.connector_id() == connector);
    let zone_ok = config
        .zone_filter
        .as_deref()
        .is_none_or(|zone| tool.supports_zone(zone));
    let risk_ok = tool_passes_risk_filter(tool, config.risk_max.as_deref());
    connector_ok && zone_ok && risk_ok
}

/// Same inclusive ceiling semantics as `export_tools::passes_risk_filter`. A
/// tool without declared risk metadata ranks above `critical`, so any
/// recognized ceiling excludes it (default deny).
fn tool_passes_risk_filter(tool: &McpToolDefinition, risk_max: Option<&str>) -> bool {
    let Some(max) = risk_max else {
        return true;
    };
    let level = tool
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.risk_level.as_deref())
        .unwrap_or("undeclared");
    export_tools::risk_filter_rank(level) <= export_tools::risk_filter_rank(max)
}

fn filtered_tools(state: &McpServerState) -> impl Iterator<Item = &McpToolDefinition> + '_ {
    state
        .tools
        .iter()
        .filter(|tool| tool_matches_server_filters(tool, &state.config))
}

fn filtered_tools_for_connector<'a>(
    state: &'a McpServerState,
    connector_id: &str,
) -> Vec<&'a McpToolDefinition> {
    filtered_tools(state)
        .filter(|tool| tool.connector_id() == connector_id)
        .collect()
}

fn resource_matches_server_filters(state: &McpServerState, resource: &McpResourceEntry) -> bool {
    match mcp_resources::parse_uri(resource.uri()) {
        ParsedUri::GlobalStatus => true,
        ParsedUri::ConnectorResource { connector_id, .. } => {
            !filtered_tools_for_connector(state, &connector_id).is_empty()
        }
        ParsedUri::ConnectorPrompt { .. } | ParsedUri::Unknown(_) => true,
    }
}

fn prompt_matches_server_filters(state: &McpServerState, prompt: &McpPromptEntry) -> bool {
    match mcp_resources::parse_uri(prompt.name()) {
        ParsedUri::ConnectorPrompt {
            connector_id,
            operation,
            ..
        } => {
            let connector_tools = filtered_tools_for_connector(state, &connector_id);
            if let Some(operation_id) = operation {
                connector_tools
                    .iter()
                    .any(|tool| tool.operation_id() == operation_id)
            } else {
                !connector_tools.is_empty()
            }
        }
        ParsedUri::ConnectorResource { .. } | ParsedUri::GlobalStatus | ParsedUri::Unknown(_) => {
            true
        }
    }
}

fn capability_token_from_params(
    params: &Value,
) -> Result<Option<ToolCapabilityToken>, JsonRpcError> {
    let meta = params.get("meta").and_then(Value::as_object);
    let candidates = [
        params.get("capability_token"),
        params.get("capabilityToken"),
        meta.and_then(|inner| inner.get("capability_token")),
        meta.and_then(|inner| inner.get("capabilityToken")),
    ];

    for candidate in candidates.into_iter().flatten() {
        let token = serde_json::from_value(candidate.clone()).map_err(|error| {
            JsonRpcError::invalid_params(format!("Invalid capability token: {error}"))
        })?;
        return Ok(Some(token));
    }

    Ok(None)
}

fn zone_registry_for_tools(tools: &[McpToolDefinition], default_zone: &str) -> ZoneRegistry {
    let mut registry = ZoneRegistry::new();
    for tool in tools {
        let mut scoped = ZoneScopedTool::new(tool.connector_id.clone(), tool.operation_id.clone())
            .with_description(tool.description.clone());
        if tool.supported_zones.is_empty() {
            scoped = scoped.with_zone(ZoneId::new(default_zone.to_owned()));
        } else {
            for zone in &tool.supported_zones {
                let scoped_zone = if zone_selector_matches(zone, default_zone) {
                    default_zone
                } else {
                    zone
                };
                scoped = scoped.with_zone(ZoneId::new(scoped_zone.to_owned()));
            }
        }
        registry.register_tool(scoped);
    }
    registry
}

fn zone_violation_error(
    tool: &McpToolDefinition,
    violation: ZoneViolation,
    token: Option<&ToolCapabilityToken>,
) -> JsonRpcError {
    let required_capability = tool
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.capability.as_deref());
    let available_zones = violation
        .available_in
        .iter()
        .map(|zone| zone.as_str().to_owned())
        .collect::<Vec<_>>();
    let available_capabilities = token
        .map(|current| {
            current
                .allowed_connectors
                .iter()
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    JsonRpcError::invalid_params(violation.message.clone()).with_data(json!({
        "type": "zone-violation",
        "tool": tool.name(),
        "connector_id": tool.connector_id(),
        "operation_id": tool.operation_id(),
        "zone_id": violation.zone.as_str(),
        "reason": violation.reason,
        "required_capability": required_capability,
        "available_capabilities": available_capabilities,
        "available_zones": available_zones,
    }))
}

fn validate_tool_access(
    state: &McpServerState,
    tool: &McpToolDefinition,
    params: &Value,
) -> Result<(), JsonRpcError> {
    if let Some(connector_filter) = state.config.connector_filter.as_deref()
        && tool.connector_id() != connector_filter
    {
        return Err(JsonRpcError::invalid_params(format!(
            "Tool `{}` is hidden by the active connector filter.",
            tool.name()
        ))
        .with_data(json!({
            "type": "connector-filter-mismatch",
            "tool": tool.name(),
            "connector_id": tool.connector_id(),
            "required_connector": connector_filter,
        })));
    }

    if !tool_passes_risk_filter(tool, state.config.risk_max.as_deref()) {
        return Err(JsonRpcError::invalid_params(format!(
            "Tool `{}` is hidden by the active risk ceiling.",
            tool.name()
        ))
        .with_data(json!({
            "type": "risk-ceiling-exceeded",
            "tool": tool.name(),
            "risk_level": tool
                .annotations
                .as_ref()
                .and_then(|annotations| annotations.risk_level.as_deref()),
            "risk_max": state.config.risk_max,
        })));
    }

    let Some(zone) = state.config.zone_filter.as_deref() else {
        return Ok(());
    };

    if !tool.supports_zone(zone) {
        let violation = ZoneViolation::new(
            tool.name().to_owned(),
            ZoneId::new(zone.to_owned()),
            ViolationReason::ConnectorNotInZone,
        )
        .with_available_in(
            tool.supported_zones()
                .iter()
                .cloned()
                .map(ZoneId::new)
                .collect(),
        );
        return Err(zone_violation_error(tool, violation, None));
    }

    let token = capability_token_from_params(params)?;
    let registry = zone_registry_for_tools(std::slice::from_ref(tool), zone);
    validate_tool_call(
        &registry,
        tool.name(),
        &ZoneId::new(zone.to_owned()),
        token.as_ref(),
    )
    .map_err(|violation| zone_violation_error(tool, violation, token.as_ref()))
}

// ── Builder ─────────────────────────────────────────────────────────────

/// Builder for [`McpServerState`].
#[derive(Clone, Debug, Default)]
pub struct McpServerBuilder {
    tools: Vec<McpToolDefinition>,
    resources: Vec<McpResourceEntry>,
    prompts: Vec<McpPromptEntry>,
    config: Option<McpServerConfig>,
    server_info: Option<McpServerInfo>,
}

impl McpServerBuilder {
    /// Set the server configuration.
    pub fn with_config(mut self, config: McpServerConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Set the server info.
    pub fn with_server_info(mut self, info: McpServerInfo) -> Self {
        self.server_info = Some(info);
        self
    }

    /// Register a tool.
    pub fn with_tool(mut self, tool: McpToolDefinition) -> Self {
        self.tools.push(tool);
        self
    }

    /// Register a resource.
    pub fn with_resource(mut self, resource: McpResourceEntry) -> Self {
        self.resources.push(resource);
        self
    }

    /// Register a prompt.
    pub fn with_prompt(mut self, prompt: McpPromptEntry) -> Self {
        self.prompts.push(prompt);
        self
    }

    /// Consume the builder and produce the server state.
    pub fn build(self) -> McpServerState {
        McpServerState {
            tools: self.tools,
            resources: self.resources,
            prompts: self.prompts,
            config: self.config.unwrap_or_default(),
            server_info: self.server_info.unwrap_or_default(),
        }
    }
}

// ── Request Handling ────────────────────────────────────────────────────

/// Route a JSON-RPC request to the appropriate MCP method handler.
///
/// This is a pure function: it reads the server state and the request,
/// and produces a response without performing any I/O.
pub fn handle_request(state: &McpServerState, request: &JsonRpcRequest) -> JsonRpcResponse {
    let id = request.id.clone().unwrap_or(Value::Null);

    match request.method.as_str() {
        "initialize" => handle_initialize(state, id),
        "notifications/initialized" => handle_initialized_notification(id),
        "tools/list" => handle_tools_list(state, id),
        "tools/call" => handle_tools_call(state, id, request.params.as_ref()),
        "resources/list" => handle_resources_list(state, id),
        "resources/read" => handle_resources_read(state, id, request.params.as_ref()),
        "prompts/list" => handle_prompts_list(state, id),
        "prompts/get" => handle_prompts_get(state, id, request.params.as_ref()),
        _ => JsonRpcResponse::error(id, JsonRpcError::method_not_found(&request.method)),
    }
}

fn parse_jsonrpc_request(raw: &str) -> Result<JsonRpcRequest, JsonRpcResponse> {
    let value: Value = match serde_json::from_str(raw) {
        Ok(value) => value,
        Err(error) => {
            return Err(JsonRpcResponse::error(
                Value::Null,
                JsonRpcError::parse_error(format!("Failed to parse request: {error}")),
            ));
        }
    };

    let id = value
        .get("id")
        .filter(|request_id| {
            request_id.is_null() || request_id.is_string() || request_id.is_number()
        })
        .cloned()
        .unwrap_or(Value::Null);
    let Some(object) = value.as_object() else {
        return Err(JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_request("JSON-RPC request must be an object."),
        ));
    };

    let jsonrpc = object.get("jsonrpc").and_then(Value::as_str);
    if jsonrpc != Some("2.0") {
        return Err(JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_request("`jsonrpc` must be the string \"2.0\"."),
        ));
    }

    if let Some(request_id) = object.get("id")
        && !(request_id.is_null() || request_id.is_string() || request_id.is_number())
    {
        return Err(JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_request("`id` must be null, a string, or a number."),
        ));
    }

    let method = object.get("method").and_then(Value::as_str);
    if method.is_none_or(str::is_empty) {
        return Err(JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_request(
                "JSON-RPC request is missing a non-empty string `method`.",
            ),
        ));
    }

    if let Some(params) = object.get("params")
        && !params.is_object()
        && !params.is_array()
    {
        return Err(JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_request("`params` must be an object or array if present."),
        ));
    }

    serde_json::from_value(value).map_err(|error| {
        JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_request(format!("Invalid JSON-RPC request object: {error}")),
        )
    })
}

/// Parse a raw JSON string into a request and route it.
///
/// Returns a response even if parsing fails (as a parse error).
pub fn handle_raw(state: &McpServerState, raw: &str) -> JsonRpcResponse {
    match parse_jsonrpc_request(raw) {
        Ok(request) => handle_request(state, &request),
        Err(response) => response,
    }
}

/// Run the newline-delimited JSON stdio transport for `fwc serve-mcp`.
///
/// # Errors
///
/// Returns an error if reading from stdin, writing to stdout, or serializing a
/// response fails.
pub async fn run_stdio_transport<R, W, F>(
    state: &McpServerState,
    reader: R,
    mut writer: W,
    mut tool_handler: F,
) -> Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnMut(&McpToolDefinition, Value, Value) -> JsonRpcResponse,
{
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let raw = line.trim();
        if raw.is_empty() {
            continue;
        }

        let response = match parse_jsonrpc_request(raw) {
            Ok(request) => {
                if request.id.is_none() {
                    if request.method.starts_with("notifications/") {
                        let _ = handle_request(state, &request);
                    }
                    continue;
                }
                if request.method == "tools/call" {
                    handle_stdio_tools_call(state, &request, &mut tool_handler)
                } else {
                    handle_request(state, &request)
                }
            }
            Err(response) => response,
        };

        let encoded = serde_json::to_string(&response)?;
        writer.write_all(encoded.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
    }

    Ok(())
}

/// Run the newline-delimited JSON stdio transport on blocking stdio handles.
///
/// # Errors
///
/// Returns an error if reading from stdin, writing to stdout, or serializing a
/// response fails.
pub fn run_stdio_transport_blocking<R, W, F>(
    state: &McpServerState,
    reader: R,
    mut writer: W,
    mut tool_handler: F,
) -> Result<()>
where
    R: std::io::BufRead,
    W: std::io::Write,
    F: FnMut(&McpToolDefinition, Value, Value) -> JsonRpcResponse,
{
    for line in reader.lines() {
        let line = line?;
        let raw = line.trim();
        if raw.is_empty() {
            continue;
        }

        let response = match parse_jsonrpc_request(raw) {
            Ok(request) => {
                if request.id.is_none() {
                    if request.method.starts_with("notifications/") {
                        let _ = handle_request(state, &request);
                    }
                    continue;
                }
                if request.method == "tools/call" {
                    handle_stdio_tools_call(state, &request, &mut tool_handler)
                } else {
                    handle_request(state, &request)
                }
            }
            Err(response) => response,
        };

        let encoded = serde_json::to_string(&response)?;
        writer.write_all(encoded.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }

    Ok(())
}

fn handle_stdio_tools_call<F>(
    state: &McpServerState,
    request: &JsonRpcRequest,
    tool_handler: &mut F,
) -> JsonRpcResponse
where
    F: FnMut(&McpToolDefinition, Value, Value) -> JsonRpcResponse,
{
    let id = request.id.clone().unwrap_or(Value::Null);
    let Some(params) = request.params.as_ref() else {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params("Missing params for tools/call"),
        );
    };

    let tool_name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();

    if tool_name.is_empty() {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params("Missing 'name' in tools/call params"),
        );
    }

    let Some(tool) = state.find_tool(tool_name) else {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params(format!("Tool not found: {tool_name}")),
        );
    };

    if let Err(error) = validate_tool_access(state, tool, params) {
        return JsonRpcResponse::error(id, error);
    }

    let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
    tool_handler(tool, id, arguments)
}

// ── Method Handlers ─────────────────────────────────────────────────────

fn handle_initialize(state: &McpServerState, id: Value) -> JsonRpcResponse {
    let mut capabilities = json!({
        "tools": {}
    });

    if state.config.include_resources && !state.resources.is_empty() {
        capabilities["resources"] = json!({});
    }
    if state.config.include_prompts && !state.prompts.is_empty() {
        capabilities["prompts"] = json!({});
    }

    JsonRpcResponse::success(
        id,
        json!({
            "protocolVersion": state.server_info.protocol_version,
            "capabilities": capabilities,
            "serverInfo": {
                "name": state.server_info.name,
                "version": state.server_info.version,
            }
        }),
    )
}

fn handle_initialized_notification(id: Value) -> JsonRpcResponse {
    // Acknowledgment — nothing to return beyond success.
    JsonRpcResponse::success(id, json!({}))
}

/// Top-level JSON-Schema keywords that OpenAI's / Codex's function-tool validator
/// rejects in a tool's `parameters` schema (HTTP 400 `invalid_function_parameters`).
/// A single offending tool fails the *entire* `tools` array, so one connector with a
/// top-level `anyOf` (e.g. `gmail.send_message`) makes every tool unusable from Codex.
const OPENAI_INCOMPATIBLE_TOP_LEVEL_KEYS: [&str; 5] = ["anyOf", "oneOf", "allOf", "enum", "not"];

/// Rewrite a tool input schema so it imports cleanly as an OpenAI/Codex function tool
/// while staying faithful to the connector's parameter surface.
///
/// Connector manifests legitimately use top-level `anyOf`/`oneOf`/`allOf` to express
/// XOR-style required-field constraints (`gmail.send_message` needs `raw` *or*
/// `to`+`subject`+`body`; `stripe.update_customer` needs `email` *or* `name`). These
/// are valid JSON Schema and remain enforced at invoke time against the connector's
/// stored schema — but OpenAI's stricter validator rejects them at the *top level*.
///
/// This flattens only the top level: it drops the offending keywords, guarantees
/// `type: "object"` with a `properties` map, and folds any `properties` declared
/// inside the combinator branches back up (top-level definitions win) so no parameter
/// is lost even if a manifest declares fields only inside branches. Nested combinators
/// inside individual properties are valid for OpenAI and are deliberately left intact.
///
/// The stored schema is never mutated — only the value emitted in `tools/list` is
/// rewritten — so the full constraint is preserved for runtime validation and for the
/// richer `resource://` inventory views.
fn sanitize_schema_for_openai_tool_import(schema: &Value) -> Value {
    let Some(obj) = schema.as_object() else {
        return schema.clone();
    };
    // Fast path: nothing OpenAI dislikes at the top level — emit verbatim and untouched.
    if !OPENAI_INCOMPATIBLE_TOP_LEVEL_KEYS
        .iter()
        .any(|key| obj.contains_key(*key))
    {
        return schema.clone();
    }

    let mut sanitized = obj.clone();

    // Salvage `properties` from combinator branches so schemas that declare fields only
    // inside branches don't lose them. `allOf` branches must all hold, so their
    // `required` is cumulative; `anyOf`/`oneOf` branches are alternatives, so folding
    // their `required` up would over-constrain the tool — we drop it (the real XOR is
    // still enforced at invoke time against the unmodified stored schema).
    let mut merged_properties = serde_json::Map::new();
    let mut required: Vec<Value> = match obj.get("required") {
        Some(Value::Array(reqs)) => reqs.clone(),
        _ => Vec::new(),
    };
    for key in ["allOf", "anyOf", "oneOf"] {
        let Some(Value::Array(branches)) = obj.get(key) else {
            continue;
        };
        for branch in branches {
            let Some(branch_obj) = branch.as_object() else {
                continue;
            };
            if let Some(Value::Object(props)) = branch_obj.get("properties") {
                for (name, value) in props {
                    merged_properties
                        .entry(name.clone())
                        .or_insert_with(|| value.clone());
                }
            }
            if key == "allOf" {
                if let Some(Value::Array(reqs)) = branch_obj.get("required") {
                    required.extend(reqs.iter().cloned());
                }
            }
        }
    }

    for key in OPENAI_INCOMPATIBLE_TOP_LEVEL_KEYS {
        sanitized.remove(key);
    }

    // Top-level `properties` win over branch-salvaged ones.
    if let Some(Value::Object(top_properties)) = sanitized.remove("properties") {
        for (name, value) in top_properties {
            merged_properties.insert(name, value);
        }
    }

    sanitized.insert("type".to_owned(), Value::String("object".to_owned()));
    sanitized.insert("properties".to_owned(), Value::Object(merged_properties));

    // De-duplicate `required` (preserving order); omit entirely if empty.
    if required.is_empty() {
        sanitized.remove("required");
    } else {
        let mut seen = std::collections::HashSet::new();
        required.retain(|value| match value.as_str() {
            Some(name) => seen.insert(name.to_owned()),
            None => true,
        });
        sanitized.insert("required".to_owned(), Value::Array(required));
    }

    Value::Object(sanitized)
}

fn handle_tools_list(state: &McpServerState, id: Value) -> JsonRpcResponse {
    let tools: Vec<Value> = filtered_tools(state)
        .map(|t| {
            let mut payload = json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": sanitize_schema_for_openai_tool_import(&t.input_schema),
            });
            if let Some(object) = payload.as_object_mut() {
                if let Some(annotations) = &t.annotations {
                    object.insert(
                        "annotations".to_owned(),
                        serde_json::to_value(annotations).unwrap_or(Value::Null),
                    );
                }
                if let Some(provenance) = &t.provenance {
                    object.insert(
                        "provenance".to_owned(),
                        serde_json::to_value(provenance).unwrap_or(Value::Null),
                    );
                }
                if !t.supported_zones.is_empty() {
                    object.insert("supportedZones".to_owned(), json!(t.supported_zones));
                }
            }
            payload
        })
        .collect();

    JsonRpcResponse::success(id, json!({ "tools": tools }))
}

fn handle_tools_call(state: &McpServerState, id: Value, params: Option<&Value>) -> JsonRpcResponse {
    let Some(params) = params else {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params("Missing params for tools/call"),
        );
    };

    let tool_name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();

    if tool_name.is_empty() {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params("Missing 'name' in tools/call params"),
        );
    }

    let Some(tool) = state.find_tool(tool_name) else {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params(format!("Tool not found: {tool_name}")),
        );
    };

    if let Err(error) = validate_tool_access(state, tool, params) {
        return JsonRpcResponse::error(id, error);
    }

    let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);

    JsonRpcResponse::error(
        id,
        JsonRpcError::internal(format!(
            "Direct tools/call handling is not available in the pure request router for `{}`. Use the transport-bound tool handler so invocations run for real.",
            tool.name
        ))
        .with_data(json!({
            "tool": tool.name,
            "connector_id": tool.connector_id,
            "operation_id": tool.operation_id,
            "arguments": arguments,
        })),
    )
}

fn handle_resources_list(state: &McpServerState, id: Value) -> JsonRpcResponse {
    if !state.config.include_resources {
        return JsonRpcResponse::success(id, json!({ "resources": [] }));
    }

    let resources: Vec<Value> = state
        .resources
        .iter()
        .filter(|resource| resource_matches_server_filters(state, resource))
        .map(|r| {
            json!({
                "uri": r.uri,
                "name": r.name,
                "description": r.description,
                "mimeType": r.mime_type,
            })
        })
        .collect();

    JsonRpcResponse::success(id, json!({ "resources": resources }))
}

fn handle_resources_read(
    state: &McpServerState,
    id: Value,
    params: Option<&Value>,
) -> JsonRpcResponse {
    let Some(params) = params else {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params("Missing params for resources/read"),
        );
    };

    let uri = params
        .get("uri")
        .and_then(Value::as_str)
        .unwrap_or_default();

    if uri.is_empty() {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params("Missing 'uri' in resources/read params"),
        );
    }

    if !state.config.include_resources {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params(format!("Resources are disabled; cannot read: {uri}")),
        );
    }

    let Some(resource) = state
        .find_resource(uri)
        .filter(|resource| resource_matches_server_filters(state, resource))
    else {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params(format!("Resource not found: {uri}")),
        );
    };

    let content = resolve_resource_content(state, uri).unwrap_or_else(|| {
        mcp_resources::ResourceContent::new(
            resource.uri.clone(),
            json!({
                "uri": resource.uri,
                "name": resource.name,
                "description": resource.description,
                "mimeType": resource.mime_type,
            }),
        )
    });
    JsonRpcResponse::success(
        id,
        json!({
            "contents": [{
                "uri": content.uri,
                "mimeType": content.mime_type,
                "text": serde_json::to_string_pretty(&content.content)
                    .unwrap_or_else(|_| content.content.to_string()),
            }],
        }),
    )
}

fn handle_prompts_list(state: &McpServerState, id: Value) -> JsonRpcResponse {
    if !state.config.include_prompts {
        return JsonRpcResponse::success(id, json!({ "prompts": [] }));
    }

    let prompts: Vec<Value> = state
        .prompts
        .iter()
        .filter(|prompt| prompt_matches_server_filters(state, prompt))
        .map(|p| {
            let args: Vec<Value> = p
                .arguments
                .iter()
                .map(|a| {
                    json!({
                        "name": a.name,
                        "description": a.description,
                        "required": a.required,
                    })
                })
                .collect();
            json!({
                "name": p.name,
                "description": p.description,
                "arguments": args,
            })
        })
        .collect();

    JsonRpcResponse::success(id, json!({ "prompts": prompts }))
}

fn handle_prompts_get(
    state: &McpServerState,
    id: Value,
    params: Option<&Value>,
) -> JsonRpcResponse {
    let Some(params) = params else {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params("Missing params for prompts/get"),
        );
    };

    let name = params
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();

    if name.is_empty() {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params("Missing 'name' in prompts/get params"),
        );
    }

    if !state.config.include_prompts {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params(format!("Prompts are disabled; cannot get: {name}")),
        );
    }

    let Some(prompt) = state
        .find_prompt(name)
        .filter(|prompt| prompt_matches_server_filters(state, prompt))
    else {
        return JsonRpcResponse::error(
            id,
            JsonRpcError::invalid_params(format!("Prompt not found: {name}")),
        );
    };

    let provided_args = params
        .get("arguments")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if let Some(content) = resolve_prompt_content(state, prompt, &provided_args) {
        let messages = content
            .messages
            .iter()
            .map(|message| {
                json!({
                    "role": message.role,
                    "content": {
                        "type": "text",
                        "text": message.content,
                    },
                })
            })
            .collect::<Vec<_>>();
        return JsonRpcResponse::success(
            id,
            json!({
                "description": prompt.description,
                "messages": messages,
            }),
        );
    }

    let rendered_arguments = if prompt.arguments.is_empty() {
        "No prompt arguments.".to_string()
    } else {
        prompt
            .arguments
            .iter()
            .map(|argument| {
                let value = provided_args
                    .get(&argument.name)
                    .map(Value::to_string)
                    .unwrap_or_else(|| {
                        if argument.required {
                            "<missing required value>".to_string()
                        } else {
                            "<optional omitted>".to_string()
                        }
                    });
                format!("- {}: {}", argument.name, value)
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let rendered_prompt = format!(
        "Prompt: {}\n\n{}\n\nArguments:\n{}",
        prompt.name, prompt.description, rendered_arguments
    );
    JsonRpcResponse::success(
        id,
        json!({
            "description": prompt.description,
            "messages": [{
                "role": "user",
                "content": {
                    "type": "text",
                    "text": rendered_prompt,
                },
            }],
        }),
    )
}

fn resolve_resource_content(
    state: &McpServerState,
    uri: &str,
) -> Option<mcp_resources::ResourceContent> {
    match mcp_resources::parse_uri(uri) {
        ParsedUri::GlobalStatus => Some(global_status_content(state)),
        ParsedUri::ConnectorResource {
            connector_id,
            resource_type,
        } => {
            let connector_tools = filtered_tools_for_connector(state, &connector_id);
            if connector_tools.is_empty() {
                return None;
            }
            match resource_type.as_str() {
                "health" => Some(connector_health_content(
                    uri,
                    &connector_id,
                    &connector_tools,
                )),
                "rate-limits" => Some(connector_rate_limits_content(
                    uri,
                    &connector_id,
                    &connector_tools,
                )),
                "operations" => Some(connector_operations_content(
                    uri,
                    &connector_id,
                    &connector_tools,
                )),
                "history" => Some(connector_history_content(uri, &connector_id)),
                _ => None,
            }
        }
        ParsedUri::ConnectorPrompt { .. } | ParsedUri::Unknown(_) => None,
    }
}

fn resolve_prompt_content(
    state: &McpServerState,
    prompt: &McpPromptEntry,
    provided_args: &serde_json::Map<String, Value>,
) -> Option<mcp_resources::PromptContent> {
    let args = prompt_arguments_as_strings(provided_args);
    match mcp_resources::parse_uri(prompt.name()) {
        ParsedUri::ConnectorPrompt {
            connector_id,
            prompt_type,
            operation,
        } => {
            let connector_tools = filtered_tools_for_connector(state, &connector_id);
            if connector_tools.is_empty() {
                return None;
            }
            match prompt_type.as_str() {
                "how-to-use" => {
                    let operations = connector_tools
                        .iter()
                        .map(|tool| tool.operation_id.clone())
                        .collect::<Vec<_>>();
                    Some(mcp_resources::generate_usage_guide(
                        &connector_id,
                        &operations,
                        &args,
                    ))
                }
                "troubleshoot" => Some(mcp_resources::generate_troubleshoot_guide(
                    &connector_id,
                    &args,
                )),
                "operation-example" => operation.and_then(|operation_id| {
                    connector_tools
                        .into_iter()
                        .find(|tool| tool.operation_id == operation_id)
                        .map(|tool| operation_example_prompt(prompt.name(), tool, &args))
                }),
                _ => None,
            }
        }
        ParsedUri::ConnectorResource { .. } | ParsedUri::GlobalStatus | ParsedUri::Unknown(_) => {
            None
        }
    }
}

fn prompt_arguments_as_strings(
    provided_args: &serde_json::Map<String, Value>,
) -> BTreeMap<String, String> {
    provided_args
        .iter()
        .map(|(key, value)| {
            let rendered = value
                .as_str()
                .map_or_else(|| value.to_string(), str::to_owned);
            (key.clone(), rendered)
        })
        .collect()
}

fn connector_health_content(
    uri: &str,
    connector_id: &str,
    tools: &[&McpToolDefinition],
) -> mcp_resources::ResourceContent {
    let inventory = inventory_truth_summary(tools);
    mcp_resources::ResourceContent::new(
        uri.to_owned(),
        json!({
            "connector_id": connector_id,
            "status": "unknown",
            "authoritative": false,
            "source": "serve-mcp-tool-inventory",
            "operation_count": tools.len(),
            "surface_state": inventory["surface_state"].clone(),
            "inventory": inventory,
            "message": "Live connector health telemetry is not yet attached to serve_mcp state. This resource only exposes tool inventory provenance.",
        }),
    )
}

fn connector_rate_limits_content(
    uri: &str,
    connector_id: &str,
    tools: &[&McpToolDefinition],
) -> mcp_resources::ResourceContent {
    let inventory = inventory_truth_summary(tools);
    mcp_resources::ResourceContent::new(
        uri.to_owned(),
        json!({
            "connector_id": connector_id,
            "status": "unknown",
            "authoritative": false,
            "source": "serve-mcp-tool-inventory",
            "surface_state": inventory["surface_state"].clone(),
            "inventory": inventory,
            "message": "Live rate-limit telemetry is not yet attached to serve_mcp state.",
        }),
    )
}

fn connector_operations_content(
    uri: &str,
    connector_id: &str,
    tools: &[&McpToolDefinition],
) -> mcp_resources::ResourceContent {
    let operations = tools
        .iter()
        .map(|tool| {
            json!({
                "tool_name": tool.name,
                "connector_id": tool.connector_id,
                "operation_id": tool.operation_id,
                "description": tool.description,
                "input_schema": tool.input_schema,
                "annotations": tool.annotations.clone(),
                "provenance": tool.provenance.clone(),
                "supported_zones": tool.supported_zones.clone(),
            })
        })
        .collect::<Vec<_>>();

    mcp_resources::ResourceContent::new(
        uri.to_owned(),
        json!({
            "connector_id": connector_id,
            "surface_state": inventory_truth_summary(tools)["surface_state"].clone(),
            "operation_count": operations.len(),
            "operations": operations,
        }),
    )
}

fn connector_history_content(uri: &str, connector_id: &str) -> mcp_resources::ResourceContent {
    match load_connector_history(connector_id, 10) {
        Ok((history_path, entries)) => mcp_resources::ResourceContent::new(
            uri.to_owned(),
            json!({
                "connector_id": connector_id,
                "source": "local-history-log",
                "history_path": history_path.display().to_string(),
                "entry_count": entries.len(),
                "entries": entries,
            }),
        ),
        Err(error) => mcp_resources::ResourceContent::new(
            uri.to_owned(),
            json!({
                "connector_id": connector_id,
                "source": "local-history-log",
                "status": "unavailable",
                "error": error.to_string(),
            }),
        ),
    }
}

fn global_status_content(state: &McpServerState) -> mcp_resources::ResourceContent {
    let connectors = filtered_tools(state)
        .fold(BTreeMap::<String, usize>::new(), |mut counts, tool| {
            *counts.entry(tool.connector_id.clone()).or_insert(0) += 1;
            counts
        })
        .into_iter()
        .map(|(connector_id, operation_count)| {
            let connector_tools = filtered_tools_for_connector(state, &connector_id);
            let inventory = inventory_truth_summary(&connector_tools);
            json!({
                "connector_id": connector_id,
                "status": inventory["status"].clone(),
                "authoritative": inventory["authoritative"].clone(),
                "source": "serve-mcp-tool-inventory",
                "operation_count": operation_count,
                "surface_state": inventory["surface_state"].clone(),
                "inventory": inventory,
            })
        })
        .collect::<Vec<_>>();

    mcp_resources::ResourceContent::new(
        "resource://connectors/status",
        json!({
            "connector_count": connectors.len(),
            "source": "serve-mcp-tool-inventory",
            "connectors": connectors,
        }),
    )
}

fn inventory_truth_summary(tools: &[&McpToolDefinition]) -> Value {
    let provenances = tools
        .iter()
        .filter_map(|tool| tool.provenance.as_ref())
        .collect::<Vec<_>>();

    let source = if provenances.is_empty() {
        catalog::ToolInventorySource::Unknown
    } else if provenances
        .iter()
        .all(|provenance| provenance.source == catalog::ToolInventorySource::LiveHostInventory)
    {
        catalog::ToolInventorySource::LiveHostInventory
    } else if provenances
        .iter()
        .all(|provenance| provenance.source == catalog::ToolInventorySource::WorkspaceManifest)
    {
        catalog::ToolInventorySource::WorkspaceManifest
    } else {
        catalog::ToolInventorySource::Unknown
    };

    let availability = if provenances.is_empty() {
        catalog::ToolAvailability::Unknown
    } else if provenances
        .iter()
        .all(|provenance| provenance.availability == catalog::ToolAvailability::Live)
    {
        catalog::ToolAvailability::Live
    } else if provenances
        .iter()
        .any(|provenance| provenance.availability == catalog::ToolAvailability::Withheld)
    {
        catalog::ToolAvailability::Withheld
    } else if provenances
        .iter()
        .any(|provenance| provenance.availability == catalog::ToolAvailability::Unavailable)
    {
        catalog::ToolAvailability::Unavailable
    } else if provenances
        .iter()
        .any(|provenance| provenance.availability == catalog::ToolAvailability::Unsupported)
    {
        catalog::ToolAvailability::Unsupported
    } else {
        catalog::ToolAvailability::Unknown
    };

    let surface_state = match source {
        catalog::ToolInventorySource::LiveHostInventory => catalog::McpSurfaceState::LiveServing,
        catalog::ToolInventorySource::WorkspaceManifest
        | catalog::ToolInventorySource::StaticCatalog => catalog::McpSurfaceState::OfflineServing,
        catalog::ToolInventorySource::Unknown => catalog::McpSurfaceState::Degraded {
            reason: "Tool inventory provenance is mixed or unknown.".to_owned(),
        },
    };

    json!({
        "source": source.tag(),
        "availability": availability.tag(),
        "authoritative": source.is_authoritative() && availability.is_usable(),
        "caveat": source.freshness_caveat(),
        "status": if availability.is_usable() { "live_inventory" } else { "unknown" },
        "surface_state": surface_state.tag(),
        "tool_count": tools.len(),
    })
}

fn load_connector_history(
    connector_id: &str,
    limit: usize,
) -> Result<(std::path::PathBuf, Vec<Value>)> {
    let history_path = HistoryStore::default_path()?;
    let store = HistoryStore::new(history_path.clone());
    let mut filter = HistoryFilter::new();
    filter.connector = Some(connector_id.to_owned());
    filter.limit = limit;

    let entries = store
        .query(&filter)
        .with_context(|| format!("failed to query history for connector `{connector_id}`"))?
        .into_iter()
        .map(serde_json::to_value)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to serialize history entries")?;

    Ok((history_path, entries))
}

fn operation_example_prompt(
    uri: &str,
    tool: &McpToolDefinition,
    args: &BTreeMap<String, String>,
) -> mcp_resources::PromptContent {
    let requested_format = args.get("format").map_or("json", String::as_str);
    let example_input = example_input_from_schema(&tool.input_schema);
    let example_json =
        serde_json::to_string_pretty(&example_input).unwrap_or_else(|_| example_input.to_string());
    let cli_snippet = format!(
        "fwc invoke {} {} --input '{}'",
        tool.connector_id,
        tool.operation_id,
        example_json.replace('\n', " ")
    );
    let guidance = match requested_format {
        "cli" => format!("CLI example:\n{cli_snippet}"),
        "toml" => format!(
            "Structured example (rendered from JSON schema because TOML-specific examples are not yet modeled):\n{example_json}"
        ),
        _ => format!("JSON example input:\n{example_json}"),
    };

    mcp_resources::PromptContent::new(uri.to_owned())
        .with_message(mcp_resources::PromptMessage::user(format!(
            "Show an example for {}.{}",
            tool.connector_id, tool.operation_id
        )))
        .with_message(mcp_resources::PromptMessage::assistant(format!(
            "Operation: {}.{}\nDescription: {}\n\n{}\n\nInput schema:\n{}",
            tool.connector_id,
            tool.operation_id,
            tool.description,
            guidance,
            serde_json::to_string_pretty(&tool.input_schema)
                .unwrap_or_else(|_| tool.input_schema.to_string()),
        )))
}

fn example_input_from_schema(schema: &Value) -> Value {
    if let Some(example) = schema.get("example") {
        return example.clone();
    }

    match schema.get("type").and_then(Value::as_str) {
        Some("string") => Value::String("<string>".to_owned()),
        Some("integer") => json!(0),
        Some("number") => json!(0.0),
        Some("boolean") => Value::Bool(true),
        Some("array") => {
            let item = schema.get("items").map_or(
                Value::String("<item>".to_owned()),
                example_input_from_schema,
            );
            Value::Array(vec![item])
        }
        Some("object") => {
            let mut object = serde_json::Map::new();
            if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
                for (key, property_schema) in properties {
                    object.insert(key.clone(), example_input_from_schema(property_schema));
                }
            }
            Value::Object(object)
        }
        _ => schema
            .get("properties")
            .and_then(Value::as_object)
            .map(|properties| {
                let mut object = serde_json::Map::new();
                for (key, property_schema) in properties {
                    object.insert(key.clone(), example_input_from_schema(property_schema));
                }
                Value::Object(object)
            })
            .unwrap_or_else(|| Value::String("<value>".to_owned())),
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_async_core::io::{AsyncReadExt, AsyncWriteExt, BufReader};
    use fcp_async_core::net::{TcpListener, TcpStream};

    // ── Helpers ─────────────────────────────────────────────────────

    fn sample_tool() -> McpToolDefinition {
        McpToolDefinition::new(
            "github.list_issues",
            "List issues in a repository",
            json!({
                "type": "object",
                "required": ["owner", "repo"],
                "properties": {
                    "owner": { "type": "string" },
                    "repo": { "type": "string" }
                }
            }),
            "github",
            "list_issues",
        )
        .with_supported_zones(vec!["z:work".to_owned()])
    }

    fn sample_private_tool() -> McpToolDefinition {
        McpToolDefinition::new(
            "vault.get_secret",
            "Read a secret from vault",
            json!({
                "type": "object",
                "required": ["path"],
                "properties": {
                    "path": { "type": "string" }
                }
            }),
            "vault",
            "get_secret",
        )
        .with_supported_zones(vec!["z:private".to_owned()])
    }

    fn sample_project_tool() -> McpToolDefinition {
        McpToolDefinition::new(
            "github.project_issue",
            "Read a project issue",
            json!({
                "type": "object",
                "properties": {
                    "project": { "type": "string" }
                }
            }),
            "github",
            "project_issue",
        )
        .with_supported_zones(vec!["z:project:*".to_owned()])
    }

    fn sample_live_tool() -> McpToolDefinition {
        sample_tool()
            .with_annotations(Some(export_tools::McpToolAnnotations {
                risk_level: Some("low".to_owned()),
                safety_tier: Some("safe".to_owned()),
                idempotency: Some("strict".to_owned()),
                capability: Some("github.read".to_owned()),
                read_only: Some(true),
                destructive: Some(false),
            }))
            .with_provenance(catalog::tool_provenance(
                "github.list_issues",
                "github",
                catalog::ToolInventorySource::LiveHostInventory,
                catalog::ToolAvailability::Live,
            ))
    }

    fn risk_annotated_tool(name: &str, risk_level: &str) -> McpToolDefinition {
        McpToolDefinition::new(
            name,
            "Risk-annotated fixture tool",
            json!({"type": "object"}),
            "github",
            name.rsplit('.').next().unwrap_or(name),
        )
        .with_annotations(Some(export_tools::McpToolAnnotations {
            risk_level: Some(risk_level.to_owned()),
            safety_tier: None,
            idempotency: None,
            capability: None,
            read_only: None,
            destructive: None,
        }))
    }

    fn sample_token(zone: &str) -> Value {
        serde_json::to_value(
            ToolCapabilityToken::new(ZoneId::new(zone.to_owned()), "agent:test")
                .with_connector("github"),
        )
        .expect("sample capability token")
    }

    fn sample_resource() -> McpResourceEntry {
        McpResourceEntry::new(
            "resource://connector/github/health",
            "GitHub Health",
            "Current health snapshot for the GitHub connector",
            "application/json",
        )
    }

    fn sample_prompt() -> McpPromptEntry {
        McpPromptEntry::new("how-to-use-github", "How to use the GitHub connector")
            .with_argument(PromptArgDef::required(
                "task",
                "What you want to accomplish",
            ))
            .with_argument(PromptArgDef::optional("style", "Output style preference"))
    }

    fn sample_state() -> McpServerState {
        McpServerState::builder()
            .with_tool(sample_tool())
            .with_resource(sample_resource())
            .with_prompt(sample_prompt())
            .build()
    }

    fn derived_connector_state() -> McpServerState {
        from_operations(&[
            DiscoveredOperationEntry::new(
                "github",
                "list_issues",
                "List issues",
                json!({
                    "type": "object",
                    "properties": {
                        "owner": { "type": "string" },
                        "repo": { "type": "string" }
                    },
                    "required": ["owner", "repo"]
                }),
            ),
            DiscoveredOperationEntry::new(
                "github",
                "create_issue",
                "Create issue",
                json!({
                    "type": "object",
                    "properties": {
                        "owner": { "type": "string" },
                        "repo": { "type": "string" },
                        "title": { "type": "string" }
                    },
                    "required": ["owner", "repo", "title"]
                }),
            ),
        ])
    }

    fn make_request(method: &str, params: Option<Value>) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(json!(1)),
            method: method.to_string(),
            params,
        }
    }

    async fn connected_tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind tcp pair listener");
        let addr = listener.local_addr().expect("listener addr");
        let accept_task = fcp_async_core::task::spawn(async move {
            listener.accept().await.expect("accept tcp pair").0
        });

        let client = TcpStream::connect(addr).await.expect("connect tcp pair");
        let server = accept_task.await.expect("tcp pair accept task");
        (client, server)
    }

    async fn drive_stdio_transport<F>(state: McpServerState, input: &str, callback: F) -> String
    where
        F: FnMut(&McpToolDefinition, Value, Value) -> JsonRpcResponse + Send + 'static,
    {
        let (mut client_input, server_input) = connected_tcp_pair().await;
        let (server_output, client_output) = connected_tcp_pair().await;

        let task = fcp_async_core::task::spawn(async move {
            run_stdio_transport(
                &state,
                BufReader::new(server_input),
                server_output,
                callback,
            )
            .await
            .unwrap();
        });

        client_input.write_all(input.as_bytes()).await.unwrap();
        client_input.shutdown(std::net::Shutdown::Write).unwrap();
        task.await.unwrap();

        let mut output = String::new();
        let mut reader = BufReader::new(client_output);
        reader.read_to_string(&mut output).await.unwrap();
        output
    }

    // ── JSON-RPC Serialization ──────────────────────────────────────

    #[test]
    fn request_roundtrip_with_params() {
        let req = make_request("tools/list", Some(json!({})));
        let serialized = serde_json::to_string(&req).unwrap();
        let deserialized: JsonRpcRequest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.method, "tools/list");
        assert_eq!(deserialized.jsonrpc, "2.0");
    }

    #[test]
    fn request_roundtrip_without_params() {
        let req = make_request("tools/list", None);
        let serialized = serde_json::to_string(&req).unwrap();
        let deserialized: JsonRpcRequest = serde_json::from_str(&serialized).unwrap();
        assert!(deserialized.params.is_none());
    }

    #[test]
    fn request_roundtrip_without_id() {
        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: None,
            method: "notifications/initialized".to_string(),
            params: None,
        };
        let serialized = serde_json::to_string(&req).unwrap();
        assert!(!serialized.contains("\"id\""));
        let deserialized: JsonRpcRequest = serde_json::from_str(&serialized).unwrap();
        assert!(deserialized.id.is_none());
    }

    #[test]
    fn response_success_roundtrip() {
        let resp = JsonRpcResponse::success(json!(1), json!({"status": "ok"}));
        let serialized = serde_json::to_string(&resp).unwrap();
        let deserialized: JsonRpcResponse = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.id, json!(1));
        assert!(deserialized.result.is_some());
        assert!(deserialized.error.is_none());
    }

    #[test]
    fn response_error_roundtrip() {
        let resp = JsonRpcResponse::error(json!(2), JsonRpcError::method_not_found("bogus"));
        let serialized = serde_json::to_string(&resp).unwrap();
        let deserialized: JsonRpcResponse = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.id, json!(2));
        assert!(deserialized.error.is_some());
        assert!(deserialized.result.is_none());
    }

    #[test]
    fn response_success_omits_error_field() {
        let resp = JsonRpcResponse::success(json!(1), json!("ok"));
        let serialized = serde_json::to_string(&resp).unwrap();
        assert!(!serialized.contains("\"error\""));
    }

    #[test]
    fn response_error_omits_result_field() {
        let resp = JsonRpcResponse::error(json!(1), JsonRpcError::internal("boom"));
        let serialized = serde_json::to_string(&resp).unwrap();
        assert!(!serialized.contains("\"result\""));
    }

    #[test]
    fn response_id_accessor() {
        let resp = JsonRpcResponse::success(json!(42), json!(null));
        assert_eq!(*resp.id(), json!(42));
    }

    #[test]
    fn response_result_accessor() {
        let resp = JsonRpcResponse::success(json!(1), json!("hello"));
        assert_eq!(resp.result(), Some(&json!("hello")));
    }

    #[test]
    fn response_is_error_true() {
        let resp = JsonRpcResponse::error(json!(1), JsonRpcError::internal("x"));
        assert!(resp.is_error());
    }

    #[test]
    fn response_is_error_false() {
        let resp = JsonRpcResponse::success(json!(1), json!(null));
        assert!(!resp.is_error());
    }

    // ── JSON-RPC Error Codes ────────────────────────────────────────

    #[test]
    fn error_code_parse_error() {
        assert_eq!(PARSE_ERROR, -32_700);
    }

    #[test]
    fn error_code_invalid_request() {
        assert_eq!(INVALID_REQUEST, -32_600);
    }

    #[test]
    fn error_code_method_not_found() {
        assert_eq!(METHOD_NOT_FOUND, -32_601);
    }

    #[test]
    fn error_code_invalid_params() {
        assert_eq!(INVALID_PARAMS, -32_602);
    }

    #[test]
    fn error_code_internal_error() {
        assert_eq!(INTERNAL_ERROR, -32_603);
    }

    #[test]
    fn error_factory_parse() {
        let e = JsonRpcError::parse_error("bad json");
        assert_eq!(e.code(), PARSE_ERROR);
        assert!(e.message().contains("bad json"));
    }

    #[test]
    fn error_factory_invalid_request() {
        let e = JsonRpcError::invalid_request("wrong shape");
        assert_eq!(e.code(), INVALID_REQUEST);
    }

    #[test]
    fn error_factory_method_not_found() {
        let e = JsonRpcError::method_not_found("bogus/method");
        assert_eq!(e.code(), METHOD_NOT_FOUND);
        assert!(e.message().contains("bogus/method"));
    }

    #[test]
    fn error_factory_invalid_params() {
        let e = JsonRpcError::invalid_params("missing name");
        assert_eq!(e.code(), INVALID_PARAMS);
    }

    #[test]
    fn error_factory_internal() {
        let e = JsonRpcError::internal("crash");
        assert_eq!(e.code(), INTERNAL_ERROR);
    }

    #[test]
    fn error_with_data() {
        let e = JsonRpcError::internal("fail").with_data(json!({"detail": "stack trace"}));
        assert!(e.data.is_some());
        assert_eq!(e.data.as_ref().unwrap()["detail"], "stack trace");
    }

    #[test]
    fn error_display_format() {
        let e = JsonRpcError::new(-32_000, "custom error");
        let display = format!("{e}");
        assert!(display.contains("-32000"));
        assert!(display.contains("custom error"));
    }

    // ── Transport Mode ──────────────────────────────────────────────

    #[test]
    fn transport_default_is_stdio() {
        assert_eq!(TransportMode::default(), TransportMode::Stdio);
    }

    #[test]
    fn transport_stdio_display() {
        assert_eq!(TransportMode::Stdio.to_string(), "stdio");
    }

    #[test]
    fn transport_sse_display() {
        let t = TransportMode::Sse { port: 8080 };
        assert_eq!(t.to_string(), "sse:8080");
    }

    #[test]
    fn transport_mode_serde_roundtrip_stdio() {
        let t = TransportMode::Stdio;
        let json = serde_json::to_string(&t).unwrap();
        let back: TransportMode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, TransportMode::Stdio);
    }

    #[test]
    fn transport_mode_serde_roundtrip_sse() {
        let t = TransportMode::Sse { port: 3000 };
        let json = serde_json::to_string(&t).unwrap();
        let back: TransportMode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, TransportMode::Sse { port: 3000 });
    }

    // ── Server Config ───────────────────────────────────────────────

    #[test]
    fn config_defaults() {
        let c = McpServerConfig::default();
        assert_eq!(c.transport, TransportMode::Stdio);
        assert!(c.zone_filter.is_none());
        assert!(c.connector_filter.is_none());
        assert!(c.risk_max.is_none());
        assert!(c.include_resources);
        assert!(c.include_prompts);
    }

    #[test]
    fn config_new_matches_default() {
        let a = McpServerConfig::new();
        let b = McpServerConfig::default();
        assert_eq!(a.transport, b.transport);
        assert_eq!(a.include_resources, b.include_resources);
    }

    #[test]
    fn config_builder_transport() {
        let c = McpServerConfig::new().with_transport(TransportMode::Sse { port: 9090 });
        assert_eq!(c.transport, TransportMode::Sse { port: 9090 });
    }

    #[test]
    fn config_builder_zone_filter() {
        let c = McpServerConfig::new().with_zone_filter("prod");
        assert_eq!(c.zone_filter.as_deref(), Some("prod"));
    }

    #[test]
    fn config_builder_connector_filter() {
        let c = McpServerConfig::new().with_connector_filter("github");
        assert_eq!(c.connector_filter.as_deref(), Some("github"));
    }

    #[test]
    fn config_builder_risk_max() {
        let c = McpServerConfig::new().with_risk_max("medium");
        assert_eq!(c.risk_max.as_deref(), Some("medium"));
    }

    #[test]
    fn config_builder_without_resources() {
        let c = McpServerConfig::new().without_resources();
        assert!(!c.include_resources);
    }

    #[test]
    fn config_builder_without_prompts() {
        let c = McpServerConfig::new().without_prompts();
        assert!(!c.include_prompts);
    }

    #[test]
    fn config_serde_roundtrip() {
        let c = McpServerConfig::new()
            .with_transport(TransportMode::Sse { port: 4000 })
            .with_zone_filter("staging")
            .with_risk_max("high");
        let json = serde_json::to_string(&c).unwrap();
        let back: McpServerConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.zone_filter.as_deref(), Some("staging"));
        assert_eq!(back.risk_max.as_deref(), Some("high"));
    }

    // ── Server Info ─────────────────────────────────────────────────

    #[test]
    fn server_info_defaults() {
        let info = McpServerInfo::default();
        assert_eq!(info.name(), "fwc");
        assert_eq!(info.protocol_version(), "2024-11-05");
        assert!(!info.version().is_empty());
    }

    #[test]
    fn server_info_serde_roundtrip() {
        let info = McpServerInfo::default();
        let json = serde_json::to_string(&info).unwrap();
        let back: McpServerInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name(), info.name());
        assert_eq!(back.protocol_version(), info.protocol_version());
    }

    // ── Tool Definition ─────────────────────────────────────────────

    #[test]
    fn tool_definition_accessors() {
        let t = sample_tool();
        assert_eq!(t.name(), "github.list_issues");
        assert_eq!(t.connector_id(), "github");
        assert_eq!(t.operation_id(), "list_issues");
    }

    #[test]
    fn tool_definition_serde_roundtrip() {
        let t = sample_tool();
        let json = serde_json::to_string(&t).unwrap();
        let back: McpToolDefinition = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, t.name);
        assert_eq!(back.connector_id, t.connector_id);
        assert_eq!(back.supported_zones, t.supported_zones);
    }

    #[test]
    fn tool_definition_input_schema_key_name() {
        let t = sample_tool();
        let val = serde_json::to_value(&t).unwrap();
        assert!(val.get("inputSchema").is_some());
        assert!(val.get("input_schema").is_none());
    }

    // ── Resource Entry ──────────────────────────────────────────────

    #[test]
    fn resource_entry_accessors() {
        let r = sample_resource();
        assert_eq!(r.uri(), "resource://connector/github/health");
        assert_eq!(r.name(), "GitHub Health");
    }

    #[test]
    fn resource_entry_serde_roundtrip() {
        let r = sample_resource();
        let json = serde_json::to_string(&r).unwrap();
        let back: McpResourceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.uri, r.uri);
    }

    #[test]
    fn resource_entry_mime_type_key_name() {
        let r = sample_resource();
        let val = serde_json::to_value(&r).unwrap();
        assert!(val.get("mimeType").is_some());
        assert!(val.get("mime_type").is_none());
    }

    // ── Prompt Entry ────────────────────────────────────────────────

    #[test]
    fn prompt_entry_accessors() {
        let p = sample_prompt();
        assert_eq!(p.name(), "how-to-use-github");
        assert_eq!(p.arguments.len(), 2);
    }

    #[test]
    fn prompt_entry_serde_roundtrip() {
        let p = sample_prompt();
        let json = serde_json::to_string(&p).unwrap();
        let back: McpPromptEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, p.name);
        assert_eq!(back.arguments.len(), 2);
    }

    #[test]
    fn prompt_arg_required() {
        let a = PromptArgDef::required("task", "what to do");
        assert!(a.required);
        assert_eq!(a.name, "task");
    }

    #[test]
    fn prompt_arg_optional() {
        let a = PromptArgDef::optional("style", "output style");
        assert!(!a.required);
        assert_eq!(a.name, "style");
    }

    // ── Discovered Operation Stub ───────────────────────────────────

    #[test]
    fn operation_entry_tool_name() {
        let entry = DiscoveredOperationEntry::new(
            "github",
            "list_issues",
            "List issues",
            json!({"type": "object"}),
        );
        assert_eq!(entry.tool_name(), "github.list_issues");
    }

    #[test]
    fn operation_entry_serde_roundtrip() {
        let entry = DiscoveredOperationEntry::new(
            "slack",
            "send_message",
            "Send a message",
            json!({"type": "object"}),
        );
        let json = serde_json::to_string(&entry).unwrap();
        let back: DiscoveredOperationEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.connector_id, "slack");
        assert_eq!(back.operation_id, "send_message");
    }

    // ── from_operations ─────────────────────────────────────────────

    #[test]
    fn from_operations_empty() {
        let state = from_operations(&[]);
        assert_eq!(state.tool_count(), 0);
    }

    #[test]
    fn from_operations_single() {
        let ops = vec![DiscoveredOperationEntry::new(
            "github",
            "list_issues",
            "List issues",
            json!({"type": "object"}),
        )];
        let state = from_operations(&ops);
        assert_eq!(state.tool_count(), 1);
        let tool = &state.tools[0];
        assert_eq!(tool.name, "github.list_issues");
        assert_eq!(tool.connector_id, "github");
        assert_eq!(tool.operation_id, "list_issues");
    }

    #[test]
    fn from_operations_multiple() {
        let ops = vec![
            DiscoveredOperationEntry::new("a", "op1", "desc1", json!({})),
            DiscoveredOperationEntry::new("a", "op2", "desc2", json!({})),
            DiscoveredOperationEntry::new("b", "op3", "desc3", json!({})),
        ];
        let state = from_operations(&ops);
        assert_eq!(state.tool_count(), 3);
    }

    #[test]
    fn from_operations_derives_resources_and_prompts() {
        let ops = vec![
            DiscoveredOperationEntry::new("github", "list_issues", "List issues", json!({})),
            DiscoveredOperationEntry::new("github", "create_issue", "Create issue", json!({})),
            DiscoveredOperationEntry::new("slack", "send_message", "Send a message", json!({})),
        ];
        let state = from_operations(&ops);

        assert!(
            state
                .find_resource("resource://connector/github/operations")
                .is_some()
        );
        assert!(
            state
                .find_resource("resource://connector/slack/history")
                .is_some()
        );
        assert!(
            state
                .find_resource("resource://connectors/status")
                .is_some()
        );

        assert!(
            state
                .find_prompt("prompt://connector/github/how-to-use")
                .is_some()
        );
        assert!(
            state
                .find_prompt("prompt://connector/github/op/list_issues/example")
                .is_some()
        );
        assert!(
            state
                .find_prompt("prompt://connector/slack/troubleshoot")
                .is_some()
        );
    }

    #[test]
    fn from_operations_preserves_input_schema() {
        let schema = json!({"type": "object", "required": ["x"]});
        let ops = vec![DiscoveredOperationEntry::new(
            "c",
            "op",
            "desc",
            schema.clone(),
        )];
        let state = from_operations(&ops);
        assert_eq!(state.tools[0].input_schema, schema);
    }

    // ── Builder API ─────────────────────────────────────────────────

    #[test]
    fn builder_default_state() {
        let state = McpServerState::builder().build();
        assert_eq!(state.tool_count(), 0);
        assert_eq!(state.resource_count(), 0);
        assert_eq!(state.prompt_count(), 0);
        assert_eq!(state.server_info.name(), "fwc");
    }

    #[test]
    fn builder_with_config() {
        let config = McpServerConfig::new().with_zone_filter("dev");
        let state = McpServerState::builder().with_config(config).build();
        assert_eq!(state.config.zone_filter.as_deref(), Some("dev"));
    }

    #[test]
    fn builder_with_server_info() {
        let info = McpServerInfo {
            name: "custom".to_string(),
            version: "1.2.3".to_string(),
            protocol_version: "2024-11-05".to_string(),
        };
        let state = McpServerState::builder().with_server_info(info).build();
        assert_eq!(state.server_info.name(), "custom");
        assert_eq!(state.server_info.version(), "1.2.3");
    }

    #[test]
    fn builder_with_tool() {
        let state = McpServerState::builder().with_tool(sample_tool()).build();
        assert_eq!(state.tool_count(), 1);
    }

    #[test]
    fn builder_with_resource() {
        let state = McpServerState::builder()
            .with_resource(sample_resource())
            .build();
        assert_eq!(state.resource_count(), 1);
    }

    #[test]
    fn builder_with_prompt() {
        let state = McpServerState::builder()
            .with_prompt(sample_prompt())
            .build();
        assert_eq!(state.prompt_count(), 1);
    }

    #[test]
    fn builder_chained() {
        let state = McpServerState::builder()
            .with_tool(sample_tool())
            .with_resource(sample_resource())
            .with_prompt(sample_prompt())
            .build();
        assert_eq!(state.tool_count(), 1);
        assert_eq!(state.resource_count(), 1);
        assert_eq!(state.prompt_count(), 1);
    }

    // ── State Lookups ───────────────────────────────────────────────

    #[test]
    fn find_tool_by_name() {
        let state = sample_state();
        assert!(state.find_tool("github.list_issues").is_some());
    }

    #[test]
    fn find_tool_missing() {
        let state = sample_state();
        assert!(state.find_tool("nonexistent").is_none());
    }

    #[test]
    fn find_resource_by_uri() {
        let state = sample_state();
        assert!(
            state
                .find_resource("resource://connector/github/health")
                .is_some()
        );
    }

    #[test]
    fn find_resource_missing() {
        let state = sample_state();
        assert!(state.find_resource("resource://missing").is_none());
    }

    #[test]
    fn find_prompt_by_name() {
        let state = sample_state();
        assert!(state.find_prompt("how-to-use-github").is_some());
    }

    #[test]
    fn find_prompt_missing() {
        let state = sample_state();
        assert!(state.find_prompt("nonexistent").is_none());
    }

    #[test]
    fn tools_for_connector() {
        let state = McpServerState::builder()
            .with_tool(McpToolDefinition::new(
                "github.list_issues",
                "d1",
                json!({}),
                "github",
                "list_issues",
            ))
            .with_tool(McpToolDefinition::new(
                "github.create_issue",
                "d2",
                json!({}),
                "github",
                "create_issue",
            ))
            .with_tool(McpToolDefinition::new(
                "slack.send",
                "d3",
                json!({}),
                "slack",
                "send",
            ))
            .build();
        assert_eq!(state.tools_for_connector("github").len(), 2);
        assert_eq!(state.tools_for_connector("slack").len(), 1);
        assert_eq!(state.tools_for_connector("missing").len(), 0);
    }

    // ── handle_request: initialize ──────────────────────────────────

    #[test]
    fn handle_initialize_returns_capabilities() {
        let state = sample_state();
        let req = make_request("initialize", None);
        let resp = handle_request(&state, &req);
        assert!(!resp.is_error());
        let result = resp.result().unwrap();
        assert_eq!(result["protocolVersion"], "2024-11-05");
        assert!(result["capabilities"]["tools"].is_object());
        assert!(result["serverInfo"]["name"].is_string());
    }

    #[test]
    fn handle_initialize_includes_resources_capability() {
        let state = sample_state();
        let req = make_request("initialize", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        assert!(result["capabilities"]["resources"].is_object());
    }

    #[test]
    fn handle_initialize_includes_prompts_capability() {
        let state = sample_state();
        let req = make_request("initialize", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        assert!(result["capabilities"]["prompts"].is_object());
    }

    #[test]
    fn handle_initialize_omits_resources_when_disabled() {
        let config = McpServerConfig::new().without_resources();
        let state = McpServerState::builder().with_config(config).build();
        let req = make_request("initialize", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        assert!(result["capabilities"].get("resources").is_none());
    }

    #[test]
    fn handle_initialize_omits_prompts_when_disabled() {
        let config = McpServerConfig::new().without_prompts();
        let state = McpServerState::builder().with_config(config).build();
        let req = make_request("initialize", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        assert!(result["capabilities"].get("prompts").is_none());
    }

    #[test]
    fn handle_initialize_omits_resources_when_empty() {
        let state = McpServerState::builder().build();
        let req = make_request("initialize", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        // No resources registered, so no resources capability.
        assert!(result["capabilities"].get("resources").is_none());
    }

    #[test]
    fn handle_initialize_server_info() {
        let state = sample_state();
        let req = make_request("initialize", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        assert_eq!(result["serverInfo"]["name"], "fwc");
    }

    // ── handle_request: notifications/initialized ───────────────────

    #[test]
    fn handle_initialized_notification_is_ok() {
        let state = sample_state();
        let req = make_request("notifications/initialized", None);
        let resp = handle_request(&state, &req);
        assert!(!resp.is_error());
    }

    // ── handle_request: tools/list ──────────────────────────────────

    #[test]
    fn handle_tools_list() {
        let state = sample_state();
        let req = make_request("tools/list", None);
        let resp = handle_request(&state, &req);
        assert!(!resp.is_error());
        let result = resp.result().unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "github.list_issues");
    }

    #[test]
    fn handle_tools_list_empty() {
        let state = McpServerState::builder().build();
        let req = make_request("tools/list", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert!(tools.is_empty());
    }

    #[test]
    fn handle_tools_list_includes_schema() {
        let state = sample_state();
        let req = make_request("tools/list", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        let tool = &result["tools"][0];
        assert!(tool["inputSchema"]["properties"]["owner"].is_object());
    }

    #[test]
    fn handle_tools_list_strips_top_level_combinators_for_openai_import() {
        // gmail.send_message-style schema: a top-level `anyOf` expressing a required
        // XOR (raw OR to+subject+body). OpenAI/Codex rejects top-level combinators.
        let schema = json!({
            "type": "object",
            "anyOf": [
                { "required": ["raw"] },
                { "required": ["to", "subject", "body"] }
            ],
            "properties": {
                "raw": { "type": "string" },
                "to": { "type": "string" },
                "subject": { "type": "string" },
                "body": { "type": "string" }
            },
            "additionalProperties": false
        });
        let state = McpServerState::builder()
            .with_tool(McpToolDefinition::new(
                "gmail.send_message",
                "Send a message",
                schema,
                "gmail",
                "gmail.send_message",
            ))
            .build();

        let req = make_request("tools/list", None);
        let resp = handle_request(&state, &req);
        let emitted = &resp.result().unwrap()["tools"][0]["inputSchema"];

        // Emitted schema is OpenAI/Codex-importable: a flat object, no top-level combinators.
        assert_eq!(emitted["type"], "object");
        assert!(emitted.get("anyOf").is_none());
        assert!(emitted.get("oneOf").is_none());
        assert!(emitted.get("allOf").is_none());
        // Every parameter is preserved, along with sibling keywords.
        assert!(emitted["properties"]["raw"].is_object());
        assert!(emitted["properties"]["to"].is_object());
        assert!(emitted["properties"]["subject"].is_object());
        assert!(emitted["properties"]["body"].is_object());
        assert_eq!(emitted["additionalProperties"], false);

        // The stored schema is untouched — the full XOR constraint is kept for runtime
        // validation and the resource:// inventory views.
        assert!(state.tools[0].input_schema.get("anyOf").is_some());
    }

    #[test]
    fn handle_tools_list_salvages_branch_properties_and_top_level_required() {
        // bluebubbles.send_media-style: top-level `required` + a `oneOf` whose branches
        // carry their own `required`/`properties`. Branch properties must survive.
        let schema = json!({
            "type": "object",
            "required": ["local_path"],
            "oneOf": [
                { "required": ["chat_guid"], "properties": { "chat_guid": { "type": "string" } } },
                { "required": ["chat_id"], "properties": { "chat_id": { "type": "integer" } } }
            ],
            "properties": {
                "local_path": { "type": "string" }
            }
        });
        let state = McpServerState::builder()
            .with_tool(McpToolDefinition::new(
                "bluebubbles.send_media",
                "Send media",
                schema,
                "bluebubbles",
                "bluebubbles.send_media",
            ))
            .build();

        let req = make_request("tools/list", None);
        let resp = handle_request(&state, &req);
        let emitted = &resp.result().unwrap()["tools"][0]["inputSchema"];

        assert_eq!(emitted["type"], "object");
        assert!(emitted.get("oneOf").is_none());
        // Top-level required is retained; alternative-branch required is dropped (the
        // XOR is enforced at invoke time, not advertised as universally required).
        assert_eq!(emitted["required"], json!(["local_path"]));
        // Properties from both the top level and the oneOf branches are present.
        assert!(emitted["properties"]["local_path"].is_object());
        assert!(emitted["properties"]["chat_guid"].is_object());
        assert!(emitted["properties"]["chat_id"].is_object());
    }

    #[test]
    fn handle_tools_list_preserves_nested_combinators() {
        // A combinator nested inside a property is valid for OpenAI and must NOT be
        // stripped; such a schema must pass through byte-for-byte (fast path).
        let schema = json!({
            "type": "object",
            "properties": {
                "thread": { "anyOf": [ { "type": "object" }, { "type": "null" } ] }
            }
        });
        let state = McpServerState::builder()
            .with_tool(McpToolDefinition::new(
                "demo.op",
                "demo",
                schema.clone(),
                "demo",
                "demo.op",
            ))
            .build();

        let req = make_request("tools/list", None);
        let resp = handle_request(&state, &req);
        let emitted = &resp.result().unwrap()["tools"][0]["inputSchema"];

        assert!(emitted["properties"]["thread"].get("anyOf").is_some());
        assert_eq!(emitted, &schema);
    }

    #[test]
    fn handle_tools_list_includes_annotations_provenance_and_supported_zones() {
        let state = McpServerState::builder()
            .with_tool(sample_live_tool())
            .build();
        let req = make_request("tools/list", None);
        let resp = handle_request(&state, &req);
        let tool = &resp.result().unwrap()["tools"][0];

        assert_eq!(tool["annotations"]["capability"], "github.read");
        assert_eq!(tool["provenance"]["source"], "live_host_inventory");
        assert_eq!(tool["provenance"]["availability"], "live");
        assert_eq!(tool["supportedZones"][0], "z:work");
    }

    #[test]
    fn handle_tools_list_respects_zone_filter() {
        let state = McpServerState::builder()
            .with_config(McpServerConfig::new().with_zone_filter("z:work"))
            .with_tool(sample_tool())
            .with_tool(sample_private_tool())
            .build();
        let req = make_request("tools/list", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "github.list_issues");
    }

    #[test]
    fn handle_tools_list_respects_project_wildcard_zone_filter() {
        let state = McpServerState::builder()
            .with_config(McpServerConfig::new().with_zone_filter("z:project:alpha"))
            .with_tool(sample_project_tool())
            .with_tool(sample_private_tool())
            .build();
        let req = make_request("tools/list", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "github.project_issue");
    }

    #[test]
    fn handle_tools_list_risk_max_is_inclusive_boundary() {
        let state = McpServerState::builder()
            .with_config(McpServerConfig::new().with_risk_max("medium"))
            .with_tool(risk_annotated_tool("github.read_issue", "low"))
            .with_tool(risk_annotated_tool("github.create_issue", "medium"))
            .with_tool(risk_annotated_tool("github.delete_repo", "high"))
            .with_tool(risk_annotated_tool("github.transfer_org", "critical"))
            .build();
        let req = make_request("tools/list", None);
        let resp = handle_request(&state, &req);
        let tools = resp.result().unwrap()["tools"].as_array().unwrap().clone();
        let names: Vec<_> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, vec!["github.read_issue", "github.create_issue"]);
    }

    #[test]
    fn handle_tools_list_risk_max_critical_includes_critical() {
        let state = McpServerState::builder()
            .with_config(McpServerConfig::new().with_risk_max("critical"))
            .with_tool(risk_annotated_tool("github.transfer_org", "critical"))
            .build();
        let req = make_request("tools/list", None);
        let resp = handle_request(&state, &req);
        let tools = resp.result().unwrap()["tools"].as_array().unwrap().clone();
        assert_eq!(tools.len(), 1);
    }

    #[test]
    fn handle_tools_list_risk_max_excludes_tools_without_risk_metadata() {
        let state = McpServerState::builder()
            .with_config(McpServerConfig::new().with_risk_max("critical"))
            .with_tool(sample_tool())
            .with_tool(risk_annotated_tool("github.read_issue", "low"))
            .build();
        let req = make_request("tools/list", None);
        let resp = handle_request(&state, &req);
        let tools = resp.result().unwrap()["tools"].as_array().unwrap().clone();
        let names: Vec<_> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, vec!["github.read_issue"]);
    }

    #[test]
    fn handle_tools_list_without_risk_max_includes_unannotated_tools() {
        let state = McpServerState::builder()
            .with_tool(sample_tool())
            .with_tool(risk_annotated_tool("github.delete_repo", "high"))
            .build();
        let req = make_request("tools/list", None);
        let resp = handle_request(&state, &req);
        let tools = resp.result().unwrap()["tools"].as_array().unwrap().clone();
        assert_eq!(tools.len(), 2);
    }

    // ── handle_request: tools/call ──────────────────────────────────

    #[test]
    fn handle_tools_call_requires_transport_handler() {
        let state = sample_state();
        let req = make_request(
            "tools/call",
            Some(json!({
                "name": "github.list_issues",
                "arguments": {"owner": "acme", "repo": "widgets"}
            })),
        );
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        let error = resp.error.as_ref().unwrap();
        assert_eq!(error.code, INTERNAL_ERROR);
        assert!(error.message.contains("transport-bound tool handler"));
    }

    #[test]
    fn handle_tools_call_refuses_tool_above_risk_ceiling() {
        let state = McpServerState::builder()
            .with_config(McpServerConfig::new().with_risk_max("medium"))
            .with_tool(risk_annotated_tool("github.delete_repo", "high"))
            .build();
        let req = make_request(
            "tools/call",
            Some(json!({
                "name": "github.delete_repo",
                "arguments": {}
            })),
        );
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        let error = resp.error.as_ref().unwrap();
        assert_eq!(error.code, INVALID_PARAMS);
        assert!(error.message.contains("risk ceiling"));
        let data = error.data.as_ref().unwrap();
        assert_eq!(data["type"], "risk-ceiling-exceeded");
        assert_eq!(data["risk_level"], "high");
        assert_eq!(data["risk_max"], "medium");
    }

    #[test]
    fn handle_tools_call_allows_tool_at_risk_ceiling() {
        let state = McpServerState::builder()
            .with_config(McpServerConfig::new().with_risk_max("medium"))
            .with_tool(risk_annotated_tool("github.create_issue", "medium"))
            .build();
        let req = make_request(
            "tools/call",
            Some(json!({
                "name": "github.create_issue",
                "arguments": {}
            })),
        );
        let resp = handle_request(&state, &req);
        // Passes the risk gate; fails only at the transport-handler boundary.
        assert!(resp.is_error());
        let error = resp.error.as_ref().unwrap();
        assert_eq!(error.code, INTERNAL_ERROR);
        assert!(error.message.contains("transport-bound tool handler"));
    }

    #[test]
    fn handle_tools_call_error_includes_arguments() {
        let state = sample_state();
        let req = make_request(
            "tools/call",
            Some(json!({"name": "github.list_issues", "arguments": {"owner": "x"}})),
        );
        let resp = handle_request(&state, &req);
        let data = resp.error.as_ref().unwrap().data.as_ref().unwrap();
        assert_eq!(data["arguments"]["owner"], "x");
    }

    #[test]
    fn handle_tools_call_missing_params() {
        let state = sample_state();
        let req = make_request("tools/call", None);
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        assert_eq!(resp.error.as_ref().unwrap().code(), INVALID_PARAMS);
    }

    #[test]
    fn handle_tools_call_missing_name() {
        let state = sample_state();
        let req = make_request("tools/call", Some(json!({})));
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        assert_eq!(resp.error.as_ref().unwrap().code(), INVALID_PARAMS);
    }

    #[test]
    fn handle_tools_call_unknown_tool() {
        let state = sample_state();
        let req = make_request("tools/call", Some(json!({"name": "nonexistent.tool"})));
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        let err = resp.error.as_ref().unwrap();
        assert_eq!(err.code(), INVALID_PARAMS);
        assert!(err.message().contains("Tool not found"));
    }

    #[test]
    fn handle_tools_call_no_arguments() {
        let state = sample_state();
        let req = make_request("tools/call", Some(json!({"name": "github.list_issues"})));
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        let error = resp.error.as_ref().unwrap();
        assert_eq!(error.code(), INTERNAL_ERROR);
        let data = error.data.as_ref().unwrap();
        assert_eq!(data["tool"], "github.list_issues");
        assert!(data["arguments"].is_null());
    }

    #[test]
    fn handle_tools_call_accepts_project_wildcard_supported_zone() {
        let state = McpServerState::builder()
            .with_config(McpServerConfig::new().with_zone_filter("z:project:alpha"))
            .with_tool(sample_project_tool())
            .build();
        let req = make_request(
            "tools/call",
            Some(json!({
                "name": "github.project_issue",
                "arguments": {"project": "alpha"},
                "capabilityToken": sample_token("z:project:alpha"),
            })),
        );
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        let error = resp.error.as_ref().unwrap();
        assert_eq!(error.code(), INTERNAL_ERROR);
        assert!(error.message().contains("transport-bound tool handler"));
    }

    #[test]
    fn handle_tools_call_returns_zone_violation_when_tool_not_in_active_zone() {
        let state = McpServerState::builder()
            .with_config(McpServerConfig::new().with_zone_filter("z:work"))
            .with_tool(sample_private_tool())
            .build();
        let req = make_request(
            "tools/call",
            Some(json!({
                "name": "vault.get_secret",
                "arguments": {"path": "prod/api"},
                "capabilityToken": sample_token("z:work"),
            })),
        );
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        let error = resp.error.as_ref().unwrap();
        assert_eq!(error.code(), INVALID_PARAMS);
        let data = error.data.as_ref().unwrap();
        assert_eq!(data["type"], "zone-violation");
        assert_eq!(data["zone_id"], "z:work");
        assert_eq!(data["reason"], "connector_not_in_zone");
        assert_eq!(data["available_zones"][0], "z:private");
    }

    #[test]
    fn handle_tools_call_zone_violation_reports_annotated_required_capability() {
        let state = McpServerState::builder()
            .with_config(McpServerConfig::new().with_zone_filter("z:work"))
            .with_tool(sample_private_tool().with_annotations(Some(
                export_tools::McpToolAnnotations {
                    risk_level: Some("low".to_owned()),
                    safety_tier: Some("safe".to_owned()),
                    idempotency: Some("strict".to_owned()),
                    capability: Some("vault.secret_read".to_owned()),
                    read_only: Some(true),
                    destructive: Some(false),
                },
            )))
            .build();
        let req = make_request(
            "tools/call",
            Some(json!({
                "name": "vault.get_secret",
                "arguments": {"path": "prod/api"},
                "capabilityToken": sample_token("z:work"),
            })),
        );
        let resp = handle_request(&state, &req);
        let error = resp
            .error
            .as_ref()
            .expect("zone violation should return an error");
        let data = error
            .data
            .as_ref()
            .expect("zone violation should include structured data");

        assert_eq!(data["type"], "zone-violation");
        assert_eq!(data["required_capability"], "vault.secret_read");
    }

    // ── handle_request: resources/list ──────────────────────────────

    #[test]
    fn handle_resources_list() {
        let state = sample_state();
        let req = make_request("resources/list", None);
        let resp = handle_request(&state, &req);
        assert!(!resp.is_error());
        let result = resp.result().unwrap();
        let resources = result["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0]["uri"], "resource://connector/github/health");
    }

    #[test]
    fn handle_resources_list_respects_zone_filter_for_derived_state() {
        let state = state_from_tools(
            [sample_tool(), sample_private_tool()],
            McpServerConfig::new().with_zone_filter("z:work"),
        );
        let req = make_request("resources/list", None);
        let resp = handle_request(&state, &req);
        let resources = resp.result().unwrap()["resources"].as_array().unwrap();
        let uris = resources
            .iter()
            .filter_map(|resource| resource["uri"].as_str())
            .collect::<Vec<_>>();

        assert!(uris.contains(&"resource://connector/github/health"));
        assert!(uris.contains(&"resource://connectors/status"));
        assert!(uris.iter().all(|uri| !uri.contains("/vault/")));
    }

    #[test]
    fn handle_resources_list_empty_when_disabled() {
        let config = McpServerConfig::new().without_resources();
        let state = McpServerState::builder()
            .with_config(config)
            .with_resource(sample_resource())
            .build();
        let req = make_request("resources/list", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        let resources = result["resources"].as_array().unwrap();
        assert!(resources.is_empty());
    }

    // ── handle_request: resources/read ──────────────────────────────

    #[test]
    fn handle_resources_read_success() {
        let state = sample_state();
        let req = make_request(
            "resources/read",
            Some(json!({"uri": "resource://connector/github/health"})),
        );
        let resp = handle_request(&state, &req);
        assert!(!resp.is_error());
        let result = resp.result().unwrap();
        let contents = result["contents"].as_array().unwrap();
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["mimeType"], "application/json");
    }

    #[test]
    fn handle_resources_read_health_reports_unknown_without_live_telemetry() {
        let state = state_from_tools([sample_live_tool()], McpServerConfig::default());
        let req = make_request(
            "resources/read",
            Some(json!({"uri": "resource://connector/github/health"})),
        );
        let resp = handle_request(&state, &req);
        let text = resp.result().unwrap()["contents"][0]["text"]
            .as_str()
            .expect("resource text should exist");
        let payload: Value = serde_json::from_str(text).expect("health payload should be valid");

        assert_eq!(payload["status"], "unknown");
        assert_eq!(payload["inventory"]["source"], "live_host_inventory");
        assert_eq!(payload["inventory"]["surface_state"], "live_serving");
    }

    #[test]
    fn handle_resources_read_rate_limits_omit_unknown_pool_data_without_live_telemetry() {
        let state = state_from_tools([sample_live_tool()], McpServerConfig::default());
        let req = make_request(
            "resources/read",
            Some(json!({"uri": "resource://connector/github/rate-limits"})),
        );
        let resp = handle_request(&state, &req);
        let text = resp.result().unwrap()["contents"][0]["text"]
            .as_str()
            .expect("resource text should exist");
        let payload: Value =
            serde_json::from_str(text).expect("rate-limit payload should be valid");

        assert_eq!(payload["status"], "unknown");
        assert_eq!(payload["inventory"]["source"], "live_host_inventory");
        assert_eq!(payload["inventory"]["surface_state"], "live_serving");
        assert!(
            payload.get("pools").is_none(),
            "unknown rate-limit state must not fabricate an empty pools list"
        );
    }

    #[test]
    fn handle_resources_read_operations_include_tool_provenance() {
        let state = state_from_tools([sample_live_tool()], McpServerConfig::default());
        let req = make_request(
            "resources/read",
            Some(json!({"uri": "resource://connector/github/operations"})),
        );
        let resp = handle_request(&state, &req);
        let text = resp.result().unwrap()["contents"][0]["text"]
            .as_str()
            .expect("resource text should exist");
        let payload: Value =
            serde_json::from_str(text).expect("operations payload should be valid");

        assert_eq!(
            payload["operations"][0]["provenance"]["source"],
            "live_host_inventory"
        );
        assert_eq!(
            payload["operations"][0]["annotations"]["capability"],
            "github.read"
        );
        assert_eq!(payload["operations"][0]["supported_zones"][0], "z:work");
    }

    #[test]
    fn handle_resources_read_operations_from_derived_state() {
        let state = from_operations(&[DiscoveredOperationEntry::new(
            "github",
            "list_issues",
            "List issues",
            json!({"type": "object"}),
        )]);
        let req = make_request(
            "resources/read",
            Some(json!({"uri": "resource://connector/github/operations"})),
        );
        let resp = handle_request(&state, &req);
        assert!(!resp.is_error());
        let result = resp.result().unwrap();
        let rendered = result["contents"][0]["text"].as_str().unwrap();
        assert!(rendered.contains("\"operation_id\": \"list_issues\""));
    }

    #[test]
    fn handle_resources_read_missing_params() {
        let state = sample_state();
        let req = make_request("resources/read", None);
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        assert_eq!(resp.error.as_ref().unwrap().code(), INVALID_PARAMS);
    }

    #[test]
    fn handle_resources_read_missing_uri() {
        let state = sample_state();
        let req = make_request("resources/read", Some(json!({})));
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
    }

    #[test]
    fn handle_resources_read_not_found() {
        let state = sample_state();
        let req = make_request("resources/read", Some(json!({"uri": "resource://missing"})));
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        assert!(
            resp.error
                .as_ref()
                .unwrap()
                .message()
                .contains("Resource not found")
        );
    }

    #[test]
    fn handle_resources_read_honors_active_filters() {
        let state = state_from_tools(
            [sample_tool(), sample_private_tool()],
            McpServerConfig::new().with_zone_filter("z:work"),
        );
        let req = make_request(
            "resources/read",
            Some(json!({"uri": "resource://connector/vault/health"})),
        );
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        assert!(
            resp.error
                .as_ref()
                .unwrap()
                .message()
                .contains("Resource not found")
        );
    }

    #[test]
    fn handle_resources_read_global_status_respects_connector_filter() {
        let state = state_from_tools(
            [sample_tool(), sample_private_tool()],
            McpServerConfig::new().with_connector_filter("github"),
        );
        let req = make_request(
            "resources/read",
            Some(json!({"uri": "resource://connectors/status"})),
        );
        let resp = handle_request(&state, &req);
        let text = resp.result().unwrap()["contents"][0]["text"]
            .as_str()
            .expect("resource text should exist");
        let payload: Value = serde_json::from_str(text).expect("status payload should be valid");

        assert_eq!(payload["connector_count"], 1);
        assert_eq!(payload["connectors"][0]["connector_id"], "github");
    }

    #[test]
    fn handle_resources_read_disabled() {
        let config = McpServerConfig::new().without_resources();
        let state = McpServerState::builder()
            .with_config(config)
            .with_resource(sample_resource())
            .build();
        let req = make_request(
            "resources/read",
            Some(json!({"uri": "resource://connector/github/health"})),
        );
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        assert!(resp.error.as_ref().unwrap().message().contains("disabled"));
    }

    // ── handle_request: prompts/list ────────────────────────────────

    #[test]
    fn handle_prompts_list() {
        let state = sample_state();
        let req = make_request("prompts/list", None);
        let resp = handle_request(&state, &req);
        assert!(!resp.is_error());
        let result = resp.result().unwrap();
        let prompts = result["prompts"].as_array().unwrap();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0]["name"], "how-to-use-github");
    }

    #[test]
    fn handle_prompts_list_includes_arguments() {
        let state = sample_state();
        let req = make_request("prompts/list", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        let args = result["prompts"][0]["arguments"].as_array().unwrap();
        assert_eq!(args.len(), 2);
        assert_eq!(args[0]["name"], "task");
        assert!(args[0]["required"].as_bool().unwrap());
        assert_eq!(args[1]["name"], "style");
        assert!(!args[1]["required"].as_bool().unwrap());
    }

    #[test]
    fn handle_prompts_list_respects_connector_filter_for_derived_state() {
        let state = state_from_tools(
            [sample_tool(), sample_private_tool()],
            McpServerConfig::new().with_connector_filter("github"),
        );
        let req = make_request("prompts/list", None);
        let resp = handle_request(&state, &req);
        let prompts = resp.result().unwrap()["prompts"].as_array().unwrap();
        let names = prompts
            .iter()
            .filter_map(|prompt| prompt["name"].as_str())
            .collect::<Vec<_>>();

        assert!(names.contains(&"prompt://connector/github/how-to-use"));
        assert!(names.iter().all(|name| !name.contains("/vault/")));
    }

    #[test]
    fn handle_prompts_list_empty_when_disabled() {
        let config = McpServerConfig::new().without_prompts();
        let state = McpServerState::builder()
            .with_config(config)
            .with_prompt(sample_prompt())
            .build();
        let req = make_request("prompts/list", None);
        let resp = handle_request(&state, &req);
        let result = resp.result().unwrap();
        let prompts = result["prompts"].as_array().unwrap();
        assert!(prompts.is_empty());
    }

    // ── handle_request: prompts/get ─────────────────────────────────

    #[test]
    fn handle_prompts_get_success() {
        let state = sample_state();
        let req = make_request("prompts/get", Some(json!({"name": "how-to-use-github"})));
        let resp = handle_request(&state, &req);
        assert!(!resp.is_error());
        let result = resp.result().unwrap();
        assert!(result["messages"].is_array());
        assert_eq!(result["messages"][0]["role"], "user");
    }

    #[test]
    fn handle_prompts_get_usage_guide_from_derived_state() {
        let state = from_operations(&[DiscoveredOperationEntry::new(
            "github",
            "list_issues",
            "List issues",
            json!({"type": "object"}),
        )]);
        let req = make_request(
            "prompts/get",
            Some(json!({"name": "prompt://connector/github/how-to-use"})),
        );
        let resp = handle_request(&state, &req);
        assert!(!resp.is_error());
        let result = resp.result().unwrap();
        let assistant = result["messages"][1]["content"]["text"].as_str().unwrap();
        assert!(assistant.contains("list_issues"));
        assert!(assistant.contains("fwc invoke github <operation>"));
    }

    #[test]
    fn handle_prompts_get_operation_example_from_derived_state() {
        let state = from_operations(&[DiscoveredOperationEntry::new(
            "github",
            "list_issues",
            "List issues",
            json!({
                "type": "object",
                "properties": {
                    "owner": { "type": "string" },
                    "repo": { "type": "string" }
                }
            }),
        )]);
        let req = make_request(
            "prompts/get",
            Some(json!({
                "name": "prompt://connector/github/op/list_issues/example",
                "arguments": { "format": "cli" }
            })),
        );
        let resp = handle_request(&state, &req);
        assert!(!resp.is_error());
        let result = resp.result().unwrap();
        let assistant = result["messages"][1]["content"]["text"].as_str().unwrap();
        assert!(assistant.contains("fwc invoke github list_issues"));
        assert!(assistant.contains("\"owner\": \"<string>\""));
    }

    #[test]
    fn handle_prompts_get_missing_params() {
        let state = sample_state();
        let req = make_request("prompts/get", None);
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        assert_eq!(resp.error.as_ref().unwrap().code(), INVALID_PARAMS);
    }

    #[test]
    fn handle_prompts_get_missing_name() {
        let state = sample_state();
        let req = make_request("prompts/get", Some(json!({})));
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
    }

    #[test]
    fn handle_prompts_get_not_found() {
        let state = sample_state();
        let req = make_request("prompts/get", Some(json!({"name": "nonexistent"})));
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        assert!(
            resp.error
                .as_ref()
                .unwrap()
                .message()
                .contains("Prompt not found")
        );
    }

    #[test]
    fn handle_prompts_get_honors_active_filters() {
        let state = state_from_tools(
            [sample_tool(), sample_private_tool()],
            McpServerConfig::new().with_zone_filter("z:work"),
        );
        let req = make_request(
            "prompts/get",
            Some(json!({"name": "prompt://connector/vault/how-to-use"})),
        );
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        assert!(
            resp.error
                .as_ref()
                .unwrap()
                .message()
                .contains("Prompt not found")
        );
    }

    #[test]
    fn handle_prompts_get_disabled() {
        let config = McpServerConfig::new().without_prompts();
        let state = McpServerState::builder()
            .with_config(config)
            .with_prompt(sample_prompt())
            .build();
        let req = make_request("prompts/get", Some(json!({"name": "how-to-use-github"})));
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        assert!(resp.error.as_ref().unwrap().message().contains("disabled"));
    }

    // ── handle_request: unknown method ──────────────────────────────

    #[test]
    fn handle_unknown_method() {
        let state = sample_state();
        let req = make_request("bogus/method", None);
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        let err = resp.error.as_ref().unwrap();
        assert_eq!(err.code(), METHOD_NOT_FOUND);
        assert!(err.message().contains("bogus/method"));
    }

    #[test]
    fn handle_empty_method() {
        let state = sample_state();
        let req = make_request("", None);
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        assert_eq!(resp.error.as_ref().unwrap().code(), METHOD_NOT_FOUND);
    }

    // ── handle_raw ──────────────────────────────────────────────────

    #[test]
    fn handle_raw_valid_request() {
        let state = sample_state();
        let raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let resp = handle_raw(&state, raw);
        assert!(!resp.is_error());
    }

    #[test]
    fn handle_raw_invalid_json() {
        let state = sample_state();
        let resp = handle_raw(&state, "not valid json");
        assert!(resp.is_error());
        assert_eq!(resp.error.as_ref().unwrap().code(), PARSE_ERROR);
    }

    #[test]
    fn handle_raw_missing_method() {
        let state = sample_state();
        let raw = r#"{"jsonrpc":"2.0","id":1}"#;
        let resp = handle_raw(&state, raw);
        assert!(resp.is_error());
        assert_eq!(resp.error.as_ref().unwrap().code(), INVALID_REQUEST);
    }

    #[test]
    fn handle_raw_invalid_jsonrpc_version() {
        let state = sample_state();
        let raw = r#"{"jsonrpc":"1.0","id":1,"method":"tools/list"}"#;
        let resp = handle_raw(&state, raw);
        assert!(resp.is_error());
        assert_eq!(resp.error.as_ref().unwrap().code(), INVALID_REQUEST);
    }

    #[test]
    fn handle_raw_rejects_structured_id() {
        let state = sample_state();
        let raw = r#"{"jsonrpc":"2.0","id":{"nested":true},"method":"tools/list"}"#;
        let resp = handle_raw(&state, raw);
        assert!(resp.is_error());
        assert_eq!(resp.id(), &Value::Null);
        assert_eq!(resp.error.as_ref().unwrap().code(), INVALID_REQUEST);
    }

    #[test]
    fn handle_raw_rejects_scalar_params() {
        let state = sample_state();
        let raw = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"bad"}"#;
        let resp = handle_raw(&state, raw);
        assert!(resp.is_error());
        assert_eq!(resp.error.as_ref().unwrap().code(), INVALID_REQUEST);
    }

    // ── Request ID propagation ──────────────────────────────────────

    #[test]
    fn response_preserves_numeric_id() {
        let state = sample_state();
        let req = make_request("tools/list", None);
        let resp = handle_request(&state, &req);
        assert_eq!(resp.id, json!(1));
    }

    #[test]
    fn response_preserves_string_id() {
        let state = sample_state();
        let mut req = make_request("tools/list", None);
        req.id = Some(json!("abc-123"));
        let resp = handle_request(&state, &req);
        assert_eq!(resp.id, json!("abc-123"));
    }

    #[test]
    fn response_null_id_for_notification() {
        let state = sample_state();
        let mut req = make_request("notifications/initialized", None);
        req.id = None;
        let resp = handle_request(&state, &req);
        assert_eq!(resp.id, Value::Null);
    }

    // ── McpServerState default ──────────────────────────────────────

    #[test]
    fn server_state_default_is_empty() {
        let state = McpServerState::default();
        assert_eq!(state.tool_count(), 0);
        assert_eq!(state.resource_count(), 0);
        assert_eq!(state.prompt_count(), 0);
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn tools_call_with_null_arguments() {
        let state = sample_state();
        let req = make_request(
            "tools/call",
            Some(json!({"name": "github.list_issues", "arguments": null})),
        );
        let resp = handle_request(&state, &req);
        assert!(resp.is_error());
        let error = resp.error.as_ref().unwrap();
        assert_eq!(error.code(), INTERNAL_ERROR);
        let data = error.data.as_ref().unwrap();
        assert_eq!(data["tool"], "github.list_issues");
        assert!(data["arguments"].is_null());
    }

    #[test]
    fn multiple_tools_in_list() {
        let state = McpServerState::builder()
            .with_tool(McpToolDefinition::new("a.op1", "d1", json!({}), "a", "op1"))
            .with_tool(McpToolDefinition::new("b.op2", "d2", json!({}), "b", "op2"))
            .build();
        let req = make_request("tools/list", None);
        let resp = handle_request(&state, &req);
        let tools = resp.result().unwrap()["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
    }

    #[test]
    fn multiple_resources_in_list() {
        let state = McpServerState::builder()
            .with_resource(McpResourceEntry::new(
                "resource://a",
                "A",
                "desc a",
                "application/json",
            ))
            .with_resource(McpResourceEntry::new(
                "resource://b",
                "B",
                "desc b",
                "text/plain",
            ))
            .build();
        let req = make_request("resources/list", None);
        let resp = handle_request(&state, &req);
        let resources = resp.result().unwrap()["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 2);
    }

    #[test]
    fn multiple_prompts_in_list() {
        let state = McpServerState::builder()
            .with_prompt(McpPromptEntry::new("p1", "prompt 1"))
            .with_prompt(McpPromptEntry::new("p2", "prompt 2"))
            .build();
        let req = make_request("prompts/list", None);
        let resp = handle_request(&state, &req);
        let prompts = resp.result().unwrap()["prompts"].as_array().unwrap();
        assert_eq!(prompts.len(), 2);
    }

    #[test]
    fn response_jsonrpc_version() {
        let state = sample_state();
        let req = make_request("tools/list", None);
        let resp = handle_request(&state, &req);
        assert_eq!(resp.jsonrpc, "2.0");
    }

    #[test]
    fn error_response_jsonrpc_version() {
        let state = sample_state();
        let req = make_request("bogus", None);
        let resp = handle_request(&state, &req);
        assert_eq!(resp.jsonrpc, "2.0");
    }

    #[test]
    fn handle_raw_with_params() {
        let state = sample_state();
        let raw = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"github.list_issues","arguments":{"owner":"x"}}}"#;
        let resp = handle_raw(&state, raw);
        assert!(resp.is_error());
        assert_eq!(resp.id, json!(5));
        let error = resp.error.as_ref().unwrap();
        assert_eq!(error.code(), INTERNAL_ERROR);
        let data = error.data.as_ref().unwrap();
        assert_eq!(data["tool"], "github.list_issues");
        assert_eq!(data["arguments"]["owner"], "x");
    }

    #[fcp_async_core::runtime::test]
    async fn stdio_transport_handles_initialize() {
        let output = drive_stdio_transport(
            sample_state(),
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n",
            |tool, id, _arguments| {
                JsonRpcResponse::success(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": format!("unexpected tool call: {}", tool.name()),
                        }],
                        "isError": true,
                    }),
                )
            },
        )
        .await;

        let response: JsonRpcResponse = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(response.id(), &json!(1));
        assert_eq!(
            response.result().unwrap()["serverInfo"]["name"],
            Value::String("fwc".to_string())
        );
    }

    #[fcp_async_core::runtime::test]
    async fn stdio_transport_initialize_advertises_resources_and_prompts() {
        let output = drive_stdio_transport(
            derived_connector_state(),
            "{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"initialize\"}\n",
            |tool, id, _arguments| {
                JsonRpcResponse::success(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": format!("unexpected tool call: {}", tool.name()),
                        }],
                        "isError": true,
                    }),
                )
            },
        )
        .await;

        let response: JsonRpcResponse = serde_json::from_str(output.trim()).unwrap();
        assert!(!response.is_error());
        let capabilities = &response.result().unwrap()["capabilities"];
        assert!(capabilities.get("tools").is_some());
        assert!(capabilities.get("resources").is_some());
        assert!(capabilities.get("prompts").is_some());
    }

    #[fcp_async_core::runtime::test]
    async fn stdio_transport_handles_tools_list() {
        let output = drive_stdio_transport(
            sample_state(),
            "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n",
            |tool, id, _arguments| {
                JsonRpcResponse::success(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": format!("unexpected tool call: {}", tool.name()),
                        }],
                        "isError": true,
                    }),
                )
            },
        )
        .await;

        let response: JsonRpcResponse = serde_json::from_str(output.trim()).unwrap();
        let tools = response.result().unwrap()["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "github.list_issues");
        assert!(tools[0]["inputSchema"].is_object());
    }

    #[fcp_async_core::runtime::test]
    async fn stdio_transport_handles_resources_list_from_derived_state() {
        let output = drive_stdio_transport(
            derived_connector_state(),
            "{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"resources/list\"}\n",
            |tool, id, _arguments| {
                JsonRpcResponse::success(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": format!("unexpected tool call: {}", tool.name()),
                        }],
                        "isError": true,
                    }),
                )
            },
        )
        .await;

        let response: JsonRpcResponse = serde_json::from_str(output.trim()).unwrap();
        assert!(!response.is_error());
        let resources = response.result().unwrap()["resources"].as_array().unwrap();
        assert_eq!(resources.len(), 5);
        let uris = resources
            .iter()
            .filter_map(|resource| resource["uri"].as_str())
            .collect::<Vec<_>>();
        assert!(uris.contains(&"resource://connector/github/health"));
        assert!(uris.contains(&"resource://connector/github/rate-limits"));
        assert!(uris.contains(&"resource://connector/github/operations"));
        assert!(uris.contains(&"resource://connector/github/history"));
        assert!(uris.contains(&"resource://connectors/status"));
    }

    #[fcp_async_core::runtime::test]
    async fn stdio_transport_handles_resources_read_from_derived_state() {
        let output = drive_stdio_transport(
            derived_connector_state(),
            "{\"jsonrpc\":\"2.0\",\"id\":13,\"method\":\"resources/read\",\"params\":{\"uri\":\"resource://connector/github/operations\"}}\n",
            |tool, id, _arguments| {
                JsonRpcResponse::success(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": format!("unexpected tool call: {}", tool.name()),
                        }],
                        "isError": true,
                    }),
                )
            },
        )
        .await;

        let response: JsonRpcResponse = serde_json::from_str(output.trim()).unwrap();
        assert!(!response.is_error());
        let text = response.result().unwrap()["contents"][0]["text"]
            .as_str()
            .expect("resource contents should include rendered text");
        let payload: Value = serde_json::from_str(text).expect("resource payload should be JSON");
        assert_eq!(payload["connector_id"], "github");
        assert_eq!(payload["operation_count"], 2);
        let operations = payload["operations"]
            .as_array()
            .expect("operations resource should render an operations array");
        assert_eq!(operations.len(), 2);
        assert!(
            operations
                .iter()
                .all(|operation| operation["connector_id"] == "github")
        );
        assert!(
            operations
                .iter()
                .any(|operation| operation["operation_id"] == "list_issues")
        );
        assert!(
            operations
                .iter()
                .any(|operation| operation["operation_id"] == "create_issue")
        );
    }

    #[fcp_async_core::runtime::test]
    async fn stdio_transport_handles_prompts_list_from_derived_state() {
        let output = drive_stdio_transport(
            derived_connector_state(),
            "{\"jsonrpc\":\"2.0\",\"id\":14,\"method\":\"prompts/list\"}\n",
            |tool, id, _arguments| {
                JsonRpcResponse::success(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": format!("unexpected tool call: {}", tool.name()),
                        }],
                        "isError": true,
                    }),
                )
            },
        )
        .await;

        let response: JsonRpcResponse = serde_json::from_str(output.trim()).unwrap();
        assert!(!response.is_error());
        let prompts = response.result().unwrap()["prompts"].as_array().unwrap();
        assert_eq!(prompts.len(), 4);
        let names = prompts
            .iter()
            .filter_map(|prompt| prompt["name"].as_str())
            .collect::<Vec<_>>();
        assert!(names.contains(&"prompt://connector/github/how-to-use"));
        assert!(names.contains(&"prompt://connector/github/troubleshoot"));
        assert!(names.contains(&"prompt://connector/github/op/list_issues/example"));
        assert!(names.contains(&"prompt://connector/github/op/create_issue/example"));
    }

    #[fcp_async_core::runtime::test]
    async fn stdio_transport_handles_prompts_get_from_derived_state() {
        let output = drive_stdio_transport(
            derived_connector_state(),
            "{\"jsonrpc\":\"2.0\",\"id\":15,\"method\":\"prompts/get\",\"params\":{\"name\":\"prompt://connector/github/op/create_issue/example\",\"arguments\":{\"format\":\"cli\"}}}\n",
            |tool, id, _arguments| {
                JsonRpcResponse::success(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": format!("unexpected tool call: {}", tool.name()),
                        }],
                        "isError": true,
                    }),
                )
            },
        )
        .await;

        let response: JsonRpcResponse = serde_json::from_str(output.trim()).unwrap();
        assert!(!response.is_error());
        let messages = response.result().unwrap()["messages"]
            .as_array()
            .expect("prompt response should include messages");
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], "user");
        let assistant = messages[1]["content"]["text"]
            .as_str()
            .expect("assistant message should contain rendered text");
        assert!(assistant.contains("fwc invoke github create_issue"));
        assert!(assistant.contains("\"title\": \"<string>\""));
    }

    #[fcp_async_core::runtime::test]
    async fn stdio_transport_routes_tools_call_through_callback() {
        let output = drive_stdio_transport(
            sample_state(),
            "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"github.list_issues\",\"arguments\":{\"owner\":\"openai\",\"repo\":\"gpt\"}}}\n",
            |tool, id, arguments| {
                assert_eq!(tool.connector_id(), "github");
                assert_eq!(tool.operation_id(), "list_issues");
                assert_eq!(arguments["owner"], "openai");
                JsonRpcResponse::success(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": format!("planned {} {}", tool.connector_id(), tool.operation_id()),
                        }],
                        "isError": false,
                    }),
                )
            },
        )
        .await;

        let response: JsonRpcResponse = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(
            response.result().unwrap()["content"][0]["text"],
            "planned github list_issues"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn stdio_transport_ignores_idless_non_notification_requests() {
        let output = drive_stdio_transport(
            sample_state(),
            "{\"jsonrpc\":\"2.0\",\"method\":\"tools/list\"}\n",
            |tool, id, _arguments| {
                JsonRpcResponse::success(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": format!("unexpected tool call: {}", tool.name()),
                        }],
                        "isError": true,
                    }),
                )
            },
        )
        .await;

        assert!(output.is_empty());
    }

    #[fcp_async_core::runtime::test]
    async fn stdio_transport_does_not_invoke_tools_for_idless_calls() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };

        let calls = Arc::new(AtomicUsize::new(0));
        let seen_calls = Arc::clone(&calls);
        let output = drive_stdio_transport(
            sample_state(),
            "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"github.list_issues\",\"arguments\":{\"owner\":\"openai\",\"repo\":\"gpt\"}}}\n",
            move |_tool, id, _arguments| {
                seen_calls.fetch_add(1, Ordering::SeqCst);
                JsonRpcResponse::success(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": "unexpected tool execution",
                        }],
                        "isError": false,
                    }),
                )
            },
        )
        .await;

        assert!(output.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[fcp_async_core::runtime::test]
    async fn stdio_transport_rejects_zone_scoped_call_without_capability_token() {
        let output = drive_stdio_transport(
            McpServerState::builder()
                .with_config(McpServerConfig::new().with_zone_filter("z:work"))
                .with_tool(sample_tool())
                .build(),
            "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"github.list_issues\",\"arguments\":{\"owner\":\"openai\",\"repo\":\"gpt\"}}}\n",
            |tool, id, _arguments| {
                JsonRpcResponse::success(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": format!("unexpected tool call: {}", tool.name()),
                        }],
                        "isError": true,
                    }),
                )
            },
        )
        .await;

        let response: JsonRpcResponse = serde_json::from_str(output.trim()).unwrap();
        let error = response.error.as_ref().unwrap();
        assert_eq!(error.code(), INVALID_PARAMS);
        let data = error.data.as_ref().unwrap();
        assert_eq!(data["type"], "zone-violation");
        assert_eq!(data["reason"], "no_token");
        assert_eq!(data["zone_id"], "z:work");
    }

    #[fcp_async_core::runtime::test]
    async fn stdio_transport_allows_zone_scoped_call_with_valid_capability_token() {
        let output = drive_stdio_transport(
            McpServerState::builder()
                .with_config(McpServerConfig::new().with_zone_filter("z:work"))
                .with_tool(sample_tool())
                .build(),
            &format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{{\"name\":\"github.list_issues\",\"arguments\":{{\"owner\":\"openai\",\"repo\":\"gpt\"}},\"capabilityToken\":{}}}}}\n",
                sample_token("z:work")
            ),
            |tool, id, arguments| {
                assert_eq!(tool.connector_id(), "github");
                assert_eq!(tool.operation_id(), "list_issues");
                assert_eq!(arguments["repo"], "gpt");
                JsonRpcResponse::success(
                    id,
                    json!({
                        "content": [{
                            "type": "text",
                            "text": format!("zone-ok {}", tool.name()),
                        }],
                        "isError": false,
                    }),
                )
            },
        )
        .await;

        let response: JsonRpcResponse = serde_json::from_str(output.trim()).unwrap();
        assert_eq!(
            response.result().unwrap()["content"][0]["text"],
            "zone-ok github.list_issues"
        );
    }

    #[fcp_async_core::runtime::test]
    async fn stdio_transport_returns_parse_errors() {
        let output = drive_stdio_transport(sample_state(), "not valid json\n", |tool, id, _| {
            JsonRpcResponse::success(
                id,
                json!({
                    "content": [{
                        "type": "text",
                        "text": format!("unexpected tool call: {}", tool.name()),
                    }],
                    "isError": true,
                }),
            )
        })
        .await;

        let response: JsonRpcResponse = serde_json::from_str(output.trim()).unwrap();
        let error = response.error.unwrap();
        assert_eq!(error.code(), PARSE_ERROR);
        assert!(error.message().contains("Failed to parse request"));
    }

    #[fcp_async_core::runtime::test]
    async fn stdio_transport_exits_cleanly_on_eof() {
        let output = drive_stdio_transport(sample_state(), "", |tool, id, _| {
            JsonRpcResponse::success(
                id,
                json!({
                    "content": [{
                        "type": "text",
                        "text": format!("unexpected tool call: {}", tool.name()),
                    }],
                    "isError": true,
                }),
            )
        })
        .await;

        assert!(output.is_empty());
    }
}
