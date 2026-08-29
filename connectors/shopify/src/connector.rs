//! Shopify connector implementation.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use fcp_prelude::{
    AgentHint, ApprovalMode, BaseConnector, CapabilityGrant, CapabilityId, CapabilityVerifier,
    ConnectorId, ConnectorMetrics, CredentialId, EventCaps, FcpConnector, FcpError, FcpResult,
    HandshakeRequest, HandshakeResponse, HealthSnapshot, IdempotencyClass, Introspection,
    InvokeRequest, InvokeResponse, OperationId, OperationInfo, RiskLevel, SafetyTier,
    SelfCheckReport, SessionId, ShutdownRequest, SimulateRequest, SimulateResponse,
    SubscribeRequest, SubscribeResponse, UnsubscribeRequest,
};
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tracing::info;

use crate::client::ShopifyClient;
use crate::types::{
    CreateLineItem, CreateOrder, CreateProduct, CreateVariant, ShopifyAuth, UpdateProduct,
};

const MANIFEST_TOML: &str = include_str!("../manifest.toml");
const DEFAULT_LIST_LIMIT: u64 = 50;
const SHOPIFY_IMPLEMENTATION_API: &str = "shopify_admin_rest";
const SHOPIFY_IMPLEMENTATION_STATUS: &str = "legacy";
const SHOPIFY_BINDING_MODEL: &str = "single_shop_single_app_install";
const SHOPIFY_AUTH_MODE_ACCESS_TOKEN: &str = "admin_api_access_token";
const SHOPIFY_AUTH_MODE_CREDENTIAL_ID: &str = "credential_id_proxy";
const SHOPIFY_ORDER_HISTORY_SCOPE: &str = "read_all_orders";
const SHOPIFY_FIRST_SLICE_NON_GOALS: &[&str] = &[
    "OAuth installation and token exchange",
    "Multi-shop routing or fan-out from a single connector instance",
    "GraphQL Admin API migration",
    "Webhook or streaming ingestion",
    "Fulfillment order lifecycle operations",
    "Cursor pagination or server-side filtering beyond the first fixed page",
];

const OP_PRODUCTS_LIST: &str = "shopify.products.list";
const OP_PRODUCTS_GET: &str = "shopify.products.get";
const OP_PRODUCTS_CREATE: &str = "shopify.products.create";
const OP_PRODUCTS_UPDATE: &str = "shopify.products.update";
const OP_PRODUCTS_DELETE: &str = "shopify.products.delete";
const OP_ORDERS_LIST: &str = "shopify.orders.list";
const OP_ORDERS_GET: &str = "shopify.orders.get";
const OP_ORDERS_CREATE: &str = "shopify.orders.create";
const OP_CUSTOMERS_LIST: &str = "shopify.customers.list";
const OP_CUSTOMERS_GET: &str = "shopify.customers.get";
const OP_INVENTORY_LIST: &str = "shopify.inventory.list";
const OP_HEALTH: &str = "shopify.health";

const CAP_PRODUCTS_READ: &str = "shopify.products.read";
const CAP_PRODUCTS_WRITE: &str = "shopify.products.write";
const CAP_ORDERS_READ: &str = "shopify.orders.read";
const CAP_ORDERS_WRITE: &str = "shopify.orders.write";
const CAP_CUSTOMERS_READ: &str = "shopify.customers.read";
const CAP_INVENTORY_READ: &str = "shopify.inventory.read";

#[derive(Clone)]
pub struct ShopifyConfig {
    pub shop_domain: String,
    pub auth: ShopifyAuth,
    pub api_version: String,
    pub retry: HttpRetryConfig,
    pub request_timeout_ms: u64,
}

#[derive(serde::Deserialize)]
struct ShopifyConfigInput {
    shop_domain: String,
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    credential_id: Option<String>,
    #[serde(default = "default_api_version")]
    api_version: String,
    #[serde(default)]
    retry: HttpRetryConfig,
    #[serde(default = "default_timeout_ms")]
    request_timeout_ms: u64,
}

fn default_api_version() -> String {
    "2026-01".into()
}

const fn default_timeout_ms() -> u64 {
    30_000
}

impl std::fmt::Debug for ShopifyConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShopifyConfig")
            .field("shop_domain", &self.shop_domain)
            .field("auth", &self.auth)
            .field("api_version", &self.api_version)
            .field("retry", &self.retry)
            .field("request_timeout_ms", &self.request_timeout_ms)
            .finish()
    }
}

impl ShopifyConfig {
    fn validate(&self) -> Result<(), String> {
        if self.shop_domain.is_empty() {
            return Err("shop_domain is required".into());
        }
        if self.shop_domain.contains("://")
            || self.shop_domain.contains('/')
            || self.shop_domain.contains('?')
            || self.shop_domain.contains('#')
        {
            return Err(
                "shop_domain must be a bare Shopify hostname like store.myshopify.com".into(),
            );
        }
        // `shop_domain` is interpolated directly into the request host
        // (`https://{shop_domain}/admin/...`). Beyond the separators rejected
        // above, a `\`, `@`, `:`, or whitespace can terminate or re-anchor the
        // authority under the WHATWG URL parser (e.g.
        // `attacker.com\x.myshopify.com` parses to host `attacker.com`),
        // redirecting the access-token-bearing request. Restrict to
        // bare-hostname characters.
        if self
            .shop_domain
            .bytes()
            .any(|b| !(b.is_ascii_alphanumeric() || b == b'.' || b == b'-'))
        {
            return Err(
                "shop_domain must be a bare Shopify hostname like store.myshopify.com".into(),
            );
        }
        if !self.shop_domain.ends_with(".myshopify.com")
            || self
                .shop_domain
                .strip_suffix(".myshopify.com")
                .is_none_or(str::is_empty)
        {
            return Err("shop_domain must end with .myshopify.com".into());
        }
        match &self.auth {
            ShopifyAuth::AccessToken { access_token } if access_token.is_empty() => {
                return Err("access_token must not be empty".into());
            }
            ShopifyAuth::AccessToken { .. } | ShopifyAuth::CredentialId { .. } => {}
        }
        if self.api_version.len() != 7
            || !self.api_version.chars().enumerate().all(|(idx, ch)| {
                if idx == 4 {
                    ch == '-'
                } else {
                    ch.is_ascii_digit()
                }
            })
        {
            return Err("api_version must look like YYYY-MM".into());
        }
        Ok(())
    }

    fn from_value(val: serde_json::Value) -> FcpResult<Self> {
        let config: ShopifyConfigInput =
            serde_json::from_value(val).map_err(|e| FcpError::InvalidRequest {
                code: 1001,
                message: format!("Invalid configuration: {e}"),
            })?;
        let shop_domain = config
            .shop_domain
            .trim()
            .trim_end_matches('/')
            .to_ascii_lowercase();
        let provided_auth_value = config
            .access_token
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let credential_id = config
            .credential_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let auth = match (provided_auth_value, credential_id) {
            (Some(_), Some(_)) => {
                return Err(FcpError::InvalidRequest {
                    code: 1001,
                    message: "Provide either access_token or credential_id, not both".into(),
                });
            }
            (Some(access_token), None) => ShopifyAuth::AccessToken { access_token },
            (None, Some(raw)) => {
                let credential_id =
                    CredentialId::parse(raw).map_err(|error| FcpError::InvalidRequest {
                        code: 1001,
                        message: format!("Invalid credential_id: {error}"),
                    })?;
                ShopifyAuth::CredentialId { credential_id }
            }
            (None, None) => {
                return Err(FcpError::InvalidRequest {
                    code: 1001,
                    message: "Missing access_token or credential_id".into(),
                });
            }
        };
        let config = Self {
            shop_domain,
            auth,
            api_version: config.api_version.trim().to_owned(),
            retry: config.retry,
            request_timeout_ms: config.request_timeout_ms,
        };
        config.validate().map_err(|e| FcpError::InvalidRequest {
            code: 1001,
            message: e,
        })?;
        Ok(config)
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DoctorStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorResult {
    pub ready: bool,
    pub status: DoctorStatus,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheck {
    name: String,
    passed: bool,
    message: Option<String>,
    critical: bool,
}

impl DoctorResult {
    fn from_checks(checks: Vec<DoctorCheck>) -> Self {
        let ready = checks.iter().filter(|c| c.critical).all(|c| c.passed);
        let status = if checks.iter().any(|c| c.critical && !c.passed) {
            DoctorStatus::Unhealthy
        } else if checks.iter().any(|c| !c.passed) {
            DoctorStatus::Degraded
        } else {
            DoctorStatus::Healthy
        };
        Self {
            ready,
            status,
            checks,
        }
    }
}

fn contract_details(config: Option<&ShopifyConfig>) -> serde_json::Value {
    json!({
        "implementation": {
            "api": SHOPIFY_IMPLEMENTATION_API,
            "status": SHOPIFY_IMPLEMENTATION_STATUS,
            "legacy_notes": [
                "Shopify marks the REST Admin API as legacy upstream.",
                "REST product CRUD remains a compatibility surface and should not be treated as the long-term Shopify contract."
            ],
        },
        "auth_boundary": {
            "binding": SHOPIFY_BINDING_MODEL,
            "supported_modes": [
                SHOPIFY_AUTH_MODE_ACCESS_TOKEN,
                SHOPIFY_AUTH_MODE_CREDENTIAL_ID,
            ],
            "configured_mode": config.map(|cfg| match &cfg.auth {
                ShopifyAuth::AccessToken { .. } => SHOPIFY_AUTH_MODE_ACCESS_TOKEN,
                ShopifyAuth::CredentialId { .. } => SHOPIFY_AUTH_MODE_CREDENTIAL_ID,
            }),
            "secretless_mode": config.map(|cfg| cfg.auth.is_secretless()),
            "configured_shop_domain": config.map(|cfg| cfg.shop_domain.clone()),
            "api_version": config.map(|cfg| cfg.api_version.clone()),
            "oauth_installation_supported": false,
            "multi_shop_supported": false,
            "credential_injection_supported": true,
        },
        "service_inventory": {
            "products": {
                "supported_operations": [
                    OP_PRODUCTS_LIST,
                    OP_PRODUCTS_GET,
                    OP_PRODUCTS_CREATE,
                    OP_PRODUCTS_UPDATE,
                    OP_PRODUCTS_DELETE,
                ],
                "notes": [
                    "Uses legacy REST Admin product endpoints against exactly one configured shop.",
                    "List operations currently return only the first fixed page of results."
                ],
            },
            "orders": {
                "supported_operations": [
                    OP_ORDERS_LIST,
                    OP_ORDERS_GET,
                    OP_ORDERS_CREATE,
                ],
                "notes": [
                    "Orders older than 60 days require Shopify-approved read_all_orders scope in addition to the normal order scopes.",
                    "Order creation writes an order record but does not run checkout, capture payment, or manage fulfillment."
                ],
            },
            "customers": {
                "supported_operations": [
                    OP_CUSTOMERS_LIST,
                    OP_CUSTOMERS_GET,
                ],
                "notes": [
                    "Read-only customer access in this first slice; no customer mutations are exposed.",
                    "List operations currently return only the first fixed page of results."
                ],
            },
            "inventory": {
                "supported_operations": [OP_INVENTORY_LIST],
                "notes": [
                    "Read-only inventory level lookup scoped to a single location_id.",
                    "No inventory mutation or location discovery operations are exposed in this slice."
                ],
            },
            "fulfillment": {
                "supported": false,
                "notes": [
                    "Fulfillment and fulfillment-order workflows are intentionally deferred.",
                    "Shopify fulfillment APIs use a more specialized scope and lifecycle model than this first slice."
                ],
            },
        },
        "non_goals": SHOPIFY_FIRST_SLICE_NON_GOALS,
    })
}

fn with_self_check_details(
    mut report: SelfCheckReport,
    config: Option<&ShopifyConfig>,
    probe: &serde_json::Value,
) -> SelfCheckReport {
    report.details = Some(json!({
        "contract": contract_details(config),
        "probe": probe,
    }));
    report
}

#[derive(Debug)]
pub struct ShopifyConnector {
    base: BaseConnector,
    config: Option<ShopifyConfig>,
    client: Option<ShopifyClient>,
    runtime: Option<ConnectorRuntime>,
    started_at: Instant,
    verifier: Option<CapabilityVerifier>,
}

impl ShopifyConnector {
    #[must_use]
    pub fn new() -> Self {
        Self {
            base: BaseConnector::new(ConnectorId::from_static("fcp.shopify")),
            config: None,
            client: None,
            runtime: None,
            started_at: Instant::now(),
            verifier: None,
        }
    }

    /// Connector instance ID used for bound capability-token verification.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        self.base.instance_id.as_str()
    }

    fn manifest_hash() -> String {
        let mut h = Sha256::new();
        h.update(MANIFEST_TOML.as_bytes());
        format!("sha256:{}", hex::encode(h.finalize()))
    }

    pub fn doctor(&self) -> DoctorResult {
        let mut checks = Vec::new();
        checks.push(DoctorCheck {
            name: "configuration".into(),
            passed: self.config.is_some(),
            message: if self.config.is_some() {
                self.config.as_ref().map(|cfg| {
                    format!(
                        "Bound to {} with Admin API version {} using {} auth.",
                        cfg.shop_domain,
                        cfg.api_version,
                        cfg.auth.redacted_label()
                    )
                })
            } else {
                Some(
                    "Not configured; provide one *.myshopify.com shop domain and exactly one auth mode: access_token or credential_id."
                        .into(),
                )
            },
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "client_initialized".into(),
            passed: self.client.is_some(),
            message: if self.client.is_some() {
                None
            } else {
                Some("HTTP client not initialized; re-run configure".into())
            },
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "runtime_initialized".into(),
            passed: self.runtime.is_some(),
            message: if self.runtime.is_some() {
                None
            } else {
                Some("ConnectorRuntime not initialized; re-run configure".into())
            },
            critical: true,
        });
        checks.push(DoctorCheck {
            name: "auth_boundary".into(),
            passed: self.config.is_some(),
            message: Some(
                "This connector is scoped to one shop/app install only; OAuth install, multi-shop fan-out, and delegated user auth are out of scope for the first slice. Secretless credential_id injection is supported through the egress proxy."
                    .into(),
            ),
            critical: false,
        });
        checks.push(DoctorCheck {
            name: "network_constraints".into(),
            passed: self.config.is_some(),
            message: self.config.as_ref().map(|cfg| {
                format!(
                    "Manifest egress should be pinned to {}:443 for every operation.",
                    cfg.shop_domain
                )
            }),
            critical: false,
        });
        checks.push(DoctorCheck {
            name: "implementation_substrate".into(),
            passed: true,
            message: Some(
                "Current implementation uses Shopify's legacy REST Admin API; GraphQL migration is intentionally deferred to a later bead."
                    .into(),
            ),
            critical: false,
        });
        checks.push(DoctorCheck {
            name: "first_slice_inventory".into(),
            passed: true,
            message: Some(
                "Supported today: products, orders, customers, and inventory-level reads plus limited product/order writes. Fulfillment, webhooks, and pagination beyond the first fixed page are non-goals."
                    .into(),
            ),
            critical: false,
        });
        DoctorResult::from_checks(checks)
    }

    fn require_str<'a>(input: &'a serde_json::Value, key: &str) -> FcpResult<&'a str> {
        let value =
            input
                .get(key)
                .and_then(|v| v.as_str())
                .ok_or_else(|| FcpError::InvalidRequest {
                    code: 1005,
                    message: format!("Missing: {key}"),
                })?;
        if value.trim().is_empty() {
            return Err(FcpError::InvalidRequest {
                code: 1005,
                message: format!("Field '{key}' must not be empty"),
            });
        }
        Ok(value)
    }

    fn require_u64(input: &serde_json::Value, key: &str) -> FcpResult<u64> {
        input
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| FcpError::InvalidRequest {
                code: 1005,
                message: format!("Missing or invalid integer: {key}"),
            })
    }
}

impl Default for ShopifyConnector {
    fn default() -> Self {
        Self::new()
    }
}

#[allow(clippy::too_many_lines)]
fn operations_info() -> Vec<OperationInfo> {
    let hint = |when: &str, mistakes: Vec<String>, related: Vec<&'static str>| -> AgentHint {
        AgentHint {
            when_to_use: when.into(),
            common_mistakes: mistakes,
            examples: vec![],
            related: related.into_iter().map(CapabilityId::from_static).collect(),
        }
    };
    let product_schema = || {
        json!({
            "type": "object",
            "required": ["id", "title", "variants"],
            "properties": {
                "id": { "type": "integer" },
                "title": { "type": "string" },
                "vendor": { "type": ["string", "null"] },
                "product_type": { "type": ["string", "null"] },
                "status": { "type": ["string", "null"] },
                "tags": { "type": ["string", "null"] },
                "variants": { "type": "array", "items": { "type": "object" } }
            }
        })
    };
    let order_schema = || {
        json!({
            "type": "object",
            "required": ["id", "line_items"],
            "properties": {
                "id": { "type": "integer" },
                "name": { "type": ["string", "null"] },
                "email": { "type": ["string", "null"] },
                "financial_status": { "type": ["string", "null"] },
                "fulfillment_status": { "type": ["string", "null"] },
                "line_items": { "type": "array", "items": { "type": "object" } }
            }
        })
    };
    let customer_schema = || {
        json!({
            "type": "object",
            "required": ["id"],
            "properties": {
                "id": { "type": "integer" },
                "first_name": { "type": ["string", "null"] },
                "last_name": { "type": ["string", "null"] },
                "email": { "type": ["string", "null"] },
                "phone": { "type": ["string", "null"] },
                "orders_count": { "type": ["integer", "null"] },
                "total_spent": { "type": ["string", "null"] }
            }
        })
    };
    let inventory_schema = || {
        json!({
            "type": "object",
            "properties": {
                "inventory_item_id": { "type": ["integer", "null"] },
                "location_id": { "type": ["integer", "null"] },
                "available": { "type": ["integer", "null"] },
                "updated_at": { "type": ["string", "null"] }
            }
        })
    };
    vec![
        OperationInfo {
            id: OperationId::from_static(OP_PRODUCTS_LIST),
            summary: "List products".into(),
            description: Some(
                "List the first page of products for the configured shop via Shopify's legacy REST Admin API."
                    .into(),
            ),
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array","items": product_schema()}),
            capability: CapabilityId::from_static(CAP_PRODUCTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "List products in the configured Shopify shop.",
                vec![
                    format!(
                        "This first slice returns only the first {} products and does not expose cursor pagination or server-side filtering.",
                        DEFAULT_LIST_LIMIT
                    ),
                    "Do not treat this as proof that GraphQL product-model coverage or bulk catalog sync exists.".into(),
                ],
                vec![CAP_PRODUCTS_WRITE],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PRODUCTS_GET),
            summary: "Get product by ID".into(),
            description: Some(
                "Fetch one product by numeric Shopify product ID from the configured shop.".into(),
            ),
            input_schema: json!({
                "type":"object",
                "required":["product_id"],
                "properties": {
                    "product_id": {
                        "type": "integer",
                        "description": "Numeric Shopify product ID."
                    }
                }
            }),
            output_schema: product_schema(),
            capability: CapabilityId::from_static(CAP_PRODUCTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Get details of a specific product",
                vec![
                    "Use numeric product_id, not a handle, slug, or GraphQL gid.".into(),
                    "REST product CRUD is a legacy compatibility surface upstream.".into(),
                ],
                vec![CAP_PRODUCTS_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PRODUCTS_CREATE),
            summary: "Create a product".into(),
            description: Some(
                "Create a product in the configured shop through the legacy REST Admin product resource."
                    .into(),
            ),
            input_schema: json!({
                "type":"object",
                "required":["title"],
                "properties": {
                    "title": { "type": "string" },
                    "body_html": { "type": "string" },
                    "vendor": { "type": "string" },
                    "product_type": { "type": "string" },
                    "status": { "type": "string" },
                    "tags": { "type": "string" },
                    "variants": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "title": { "type": "string" },
                                "price": { "type": "string" },
                                "sku": { "type": "string" }
                            }
                        }
                    }
                }
            }),
            output_schema: product_schema(),
            capability: CapabilityId::from_static(CAP_PRODUCTS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Create a new product",
                vec![
                    "title is required".into(),
                    "This is a real catalog mutation on the configured shop and should be treated as operator-visible state.".into(),
                ],
                vec![CAP_PRODUCTS_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PRODUCTS_UPDATE),
            summary: "Update a product".into(),
            description: Some(
                "Update mutable product fields for an existing Shopify product in the configured shop."
                    .into(),
            ),
            input_schema: json!({
                "type":"object",
                "required":["product_id"],
                "properties": {
                    "product_id": { "type": "integer" },
                    "title": { "type": "string" },
                    "body_html": { "type": "string" },
                    "vendor": { "type": "string" },
                    "product_type": { "type": "string" },
                    "status": { "type": "string" },
                    "tags": { "type": "string" }
                }
            }),
            output_schema: product_schema(),
            capability: CapabilityId::from_static(CAP_PRODUCTS_WRITE),
            risk_level: RiskLevel::Medium,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::BestEffort,
            ai_hints: hint(
                "Update an existing product",
                vec![
                    "product_id is required".into(),
                    "Shopify product updates are upstream best-effort mutations; repeated retries can still trigger webhooks or race with concurrent admin edits.".into(),
                ],
                vec![CAP_PRODUCTS_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_PRODUCTS_DELETE),
            summary: "Delete a product".into(),
            description: Some(
                "Delete a product from the configured shop through Shopify's legacy REST Admin API."
                    .into(),
            ),
            input_schema: json!({
                "type":"object",
                "required":["product_id"],
                "properties": {
                    "product_id": { "type": "integer" }
                }
            }),
            output_schema: json!({
                "type":"object",
                "required":["deleted"],
                "properties": {
                    "deleted": { "type": "boolean" }
                }
            }),
            capability: CapabilityId::from_static(CAP_PRODUCTS_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Dangerous,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Delete a product (irreversible)",
                vec![
                    "Verify product_id first".into(),
                    "Deletion is irreversible for the configured shop and REST product delete remains a legacy/deprecated upstream path.".into(),
                ],
                vec![CAP_PRODUCTS_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_ORDERS_LIST),
            summary: "List orders".into(),
            description: Some(
                "List the first page of orders visible to the configured app installation for the configured shop."
                    .into(),
            ),
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array","items": order_schema()}),
            capability: CapabilityId::from_static(CAP_ORDERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "List recent orders available to the configured shop auth context.",
                vec![
                    format!(
                        "This first slice returns only the first {} visible orders and does not expose cursor pagination or filters.",
                        DEFAULT_LIST_LIMIT
                    ),
                    format!(
                        "Orders older than 60 days require Shopify-approved {} scope in addition to normal order scopes.",
                        SHOPIFY_ORDER_HISTORY_SCOPE
                    ),
                ],
                vec![CAP_ORDERS_WRITE],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_ORDERS_GET),
            summary: "Get order by ID".into(),
            description: Some(
                "Fetch one order by numeric Shopify order ID from the configured shop.".into(),
            ),
            input_schema: json!({
                "type":"object",
                "required":["order_id"],
                "properties": {
                    "order_id": { "type": "integer" }
                }
            }),
            output_schema: order_schema(),
            capability: CapabilityId::from_static(CAP_ORDERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Get details of a specific order",
                vec![
                    "Use numeric order_id, not a human display name.".into(),
                    format!(
                        "Historical orders beyond the default 60-day window require {} scope on the underlying Shopify app.",
                        SHOPIFY_ORDER_HISTORY_SCOPE
                    ),
                ],
                vec![CAP_ORDERS_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_ORDERS_CREATE),
            summary: "Create an order".into(),
            description: Some(
                "Create an order record for the configured shop without running checkout, payment capture, or fulfillment orchestration."
                    .into(),
            ),
            input_schema: json!({
                "type":"object",
                "required":["line_items"],
                "properties": {
                    "line_items": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["variant_id"],
                            "properties": {
                                "variant_id": { "type": "integer" },
                                "quantity": { "type": "integer" }
                            }
                        }
                    },
                    "email": { "type": "string" },
                    "financial_status": { "type": "string" }
                }
            }),
            output_schema: order_schema(),
            capability: CapabilityId::from_static(CAP_ORDERS_WRITE),
            risk_level: RiskLevel::High,
            safety_tier: SafetyTier::Risky,
            idempotency: IdempotencyClass::None,
            ai_hints: hint(
                "Create a new order",
                vec![
                    "line_items with variant_id and quantity required".into(),
                    "Creating an order here does not charge a payment method, run checkout, or manage fulfillment.".into(),
                ],
                vec![CAP_ORDERS_READ, CAP_PRODUCTS_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::Interactive),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CUSTOMERS_LIST),
            summary: "List customers".into(),
            description: Some(
                "List the first page of customers visible to the configured shop auth context."
                    .into(),
            ),
            input_schema: json!({"type":"object"}),
            output_schema: json!({"type":"array","items": customer_schema()}),
            capability: CapabilityId::from_static(CAP_CUSTOMERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "List customer records for the configured shop.",
                vec![
                    format!(
                        "This first slice returns only the first {} customers and does not expose cursor pagination or filters.",
                        DEFAULT_LIST_LIMIT
                    ),
                    "Avoid echoing unnecessary customer PII into shared transcripts.".into(),
                ],
                vec![],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_CUSTOMERS_GET),
            summary: "Get customer by ID".into(),
            description: Some(
                "Fetch one customer by numeric Shopify customer ID from the configured shop."
                    .into(),
            ),
            input_schema: json!({
                "type":"object",
                "required":["customer_id"],
                "properties": {
                    "customer_id": { "type": "integer" }
                }
            }),
            output_schema: customer_schema(),
            capability: CapabilityId::from_static(CAP_CUSTOMERS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Get a specific customer",
                vec![
                    "Use numeric customer_id".into(),
                    "This slice is read-only for customers; there are no customer mutation operations yet.".into(),
                ],
                vec![],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_INVENTORY_LIST),
            summary: "List inventory levels".into(),
            description: Some(
                "List inventory levels for a single Shopify location_id in the configured shop."
                    .into(),
            ),
            input_schema: json!({
                "type":"object",
                "required":["location_id"],
                "properties": {
                    "location_id": { "type": "integer" }
                }
            }),
            output_schema: json!({"type":"array","items": inventory_schema()}),
            capability: CapabilityId::from_static(CAP_INVENTORY_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Check inventory at a location",
                vec![
                    "location_id is required".into(),
                    "This first slice does not discover locations or mutate inventory quantities.".into(),
                ],
                vec![CAP_PRODUCTS_READ],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
        OperationInfo {
            id: OperationId::from_static(OP_HEALTH),
            summary: "Check API credentials".into(),
            description: Some(
                "Probe /shop.json to verify that the configured Shopify auth mode can reach the configured shop."
                    .into(),
            ),
            input_schema: json!({"type":"object"}),
            output_schema: json!({
                "type":"object",
                "required":["healthy", "shop_id", "shop_name"],
                "properties": {
                    "healthy": { "type": "boolean" },
                    "shop_id": { "type": "integer" },
                    "shop_name": { "type": "string" },
                    "shop_domain": { "type": ["string", "null"] },
                    "plan_name": { "type": ["string", "null"] }
                }
            }),
            capability: CapabilityId::from_static(CAP_PRODUCTS_READ),
            risk_level: RiskLevel::Low,
            safety_tier: SafetyTier::Safe,
            idempotency: IdempotencyClass::Strict,
            ai_hints: hint(
                "Verify that the configured shop credentials can reach /shop.json.",
                vec![
                    "This validates the shop binding and credential reachability, not every optional scope used by every operation.".into(),
                ],
                vec![],
            ),
            rate_limit: None,
            requires_approval: Some(ApprovalMode::None),
        },
    ]
}

fcp_core::impl_fcp_sealed!(ShopifyConnector);

#[async_trait]
impl FcpConnector for ShopifyConnector {
    fn id(&self) -> &ConnectorId {
        &self.base.id
    }

    async fn configure(&mut self, config: serde_json::Value) -> FcpResult<()> {
        let cfg = ShopifyConfig::from_value(config)?;
        let runtime = ConnectorRuntime::new(
            ConnectorRuntimeConfig::default()
                .with_request_timeout(Duration::from_millis(cfg.request_timeout_ms)),
        );
        let client = ShopifyClient::new(
            &cfg.shop_domain,
            cfg.auth.clone(),
            &cfg.api_version,
            cfg.request_timeout_ms,
            cfg.retry.clone(),
        )
        .map_err(|e| FcpError::Internal {
            message: format!("Client init: {e}"),
        })?;
        let shop_domain = cfg.shop_domain.clone();
        let api_version = cfg.api_version.clone();
        let auth_mode = cfg.auth.redacted_label();
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown();
        }
        self.client = Some(client);
        self.config = Some(cfg);
        self.runtime = Some(runtime);
        self.verifier = None;
        self.base.set_configured(true);
        self.base.set_handshaken(false);
        info!(
            event = "shopify.configure",
            shop_domain = %shop_domain,
            api_version = %api_version,
            auth_mode = %auth_mode,
            "Configured Shopify connector"
        );
        Ok(())
    }

    async fn handshake(&mut self, req: HandshakeRequest) -> FcpResult<HandshakeResponse> {
        if self.config.is_none() || self.client.is_none() || self.runtime.is_none() {
            return Err(FcpError::NotConfigured);
        }

        self.base.set_handshaken(true);
        self.verifier = Some(CapabilityVerifier::new(
            req.host_public_key,
            req.zone.clone(),
            self.base.instance_id.clone(),
        ));
        let caps = req
            .capabilities_requested
            .into_iter()
            .map(|c| CapabilityGrant {
                capability: c,
                operation: None,
            })
            .collect();
        Ok(HandshakeResponse {
            status: "accepted".into(),
            capabilities_granted: caps,
            session_id: SessionId::new(),
            manifest_hash: Self::manifest_hash(),
            nonce: req.nonce,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
            auth_caps: None,
            op_catalog_hash: None,
        })
    }

    async fn health(&self) -> HealthSnapshot {
        let mut snap = match (&self.config, &self.client, &self.runtime) {
            (None, _, _) => HealthSnapshot::degraded("not configured"),
            (Some(_), None, _) => HealthSnapshot::error("client not initialized"),
            (Some(_), _, None) => HealthSnapshot::error("runtime not initialized"),
            (Some(_), Some(_), Some(_)) => HealthSnapshot::ready(),
        };
        snap.uptime_ms = u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX);
        snap.details = Some(json!({
            "configured": self.config.is_some(),
            "handshaken": self.base.handshaken.load(Ordering::Acquire),
            "manifest_hash": Self::manifest_hash(),
            "contract": contract_details(self.config.as_ref()),
        }));
        snap
    }

    async fn self_check(&self) -> FcpResult<SelfCheckReport> {
        let Some(config) = &self.config else {
            return Ok(with_self_check_details(
                SelfCheckReport::degraded("not_configured", "Connector is not configured"),
                None,
                &json!({
                    "reachable": false,
                    "reason": "configure one *.myshopify.com shop domain plus exactly one auth mode (access_token or credential_id) before running self_check"
                }),
            ));
        };

        let Some(client) = &self.client else {
            return Ok(with_self_check_details(
                SelfCheckReport::failed(
                    "client_missing",
                    "Shopify HTTP client not initialized; re-run configure",
                ),
                Some(config),
                &json!({
                    "reachable": false,
                    "reason": "client missing"
                }),
            ));
        };
        let Some(runtime) = &self.runtime else {
            return Ok(with_self_check_details(
                SelfCheckReport::failed(
                    "runtime_missing",
                    "ConnectorRuntime not initialized; re-run configure",
                ),
                Some(config),
                &json!({
                    "reachable": false,
                    "reason": "runtime missing"
                }),
            ));
        };

        match client.health_check(runtime).await {
            Ok(shop) => {
                info!(
                    event = "shopify.self_check",
                    shop_name = %shop.name,
                    "Shopify self_check passed"
                );
                Ok(with_self_check_details(
                    SelfCheckReport::ok(),
                    Some(config),
                    &json!({
                        "reachable": true,
                        "shop": {
                            "id": shop.id,
                            "name": shop.name,
                            "domain": shop.domain,
                            "plan_name": shop.plan_name,
                        }
                    }),
                ))
            }
            Err(error) if error.is_retryable() => Ok(with_self_check_details(
                SelfCheckReport::degraded("self_check_retryable", error.to_string()),
                Some(config),
                &json!({
                    "reachable": false,
                    "retryable": true,
                }),
            )),
            Err(error) => Ok(with_self_check_details(
                SelfCheckReport::failed("self_check_failed", error.to_string()),
                Some(config),
                &json!({
                    "reachable": false,
                    "retryable": false,
                }),
            )),
        }
    }

    async fn simulate(&self, req: SimulateRequest) -> FcpResult<SimulateResponse> {
        let capability = match Self::capability_for_operation(req.operation.as_str()) {
            Ok(capability) => capability,
            Err(error) => {
                return Ok(SimulateResponse::denied(
                    req.id,
                    error.to_string(),
                    error.error_code(),
                ));
            }
        };

        if let Err(error) = Self::validate_input_for_operation(req.operation.as_str(), &req.input) {
            return Ok(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ));
        }

        if self.config.is_none() || self.client.is_none() || self.runtime.is_none() {
            let error = FcpError::NotConfigured;
            return Ok(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ));
        }

        let Some(verifier) = &self.verifier else {
            let error = FcpError::NotHandshaken;
            return Ok(SimulateResponse::denied(
                req.id,
                error.to_string(),
                error.error_code(),
            ));
        };

        match verifier.verify_bound(req.capability_token, &capability, &req.operation, &[]) {
            Ok(_) => Ok(SimulateResponse::allowed(req.id)),
            Err(error) => {
                let mut response =
                    SimulateResponse::denied(req.id, error.to_string(), error.error_code());
                if matches!(
                    error,
                    FcpError::CapabilityDenied { .. } | FcpError::OperationNotGranted { .. }
                ) {
                    response =
                        response.with_missing_capabilities(vec![capability.as_str().to_string()]);
                }
                Ok(response)
            }
        }
    }

    fn metrics(&self) -> ConnectorMetrics {
        self.base.metrics()
    }

    async fn shutdown(&mut self, _req: ShutdownRequest) -> FcpResult<()> {
        if let Some(runtime) = &self.runtime {
            runtime.shutdown();
        }
        self.runtime = None;
        self.client = None;
        self.config = None;
        self.verifier = None;
        self.base.set_configured(false);
        self.base.set_handshaken(false);
        Ok(())
    }

    fn introspect(&self) -> Introspection {
        Introspection {
            operations: operations_info(),
            events: Vec::new(),
            resource_types: Vec::new(),
            auth_caps: None,
            event_caps: Some(EventCaps {
                streaming: false,
                replay: false,
                min_buffer_events: 0,
                requires_ack: false,
            }),
        }
    }

    async fn invoke(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        let result = self.invoke_inner(req).await;
        self.base.record_request(result.is_ok());
        result
    }

    async fn subscribe(&self, _req: SubscribeRequest) -> FcpResult<SubscribeResponse> {
        Err(FcpError::StreamingNotSupported)
    }
    async fn unsubscribe(&self, _req: UnsubscribeRequest) -> FcpResult<()> {
        Err(FcpError::StreamingNotSupported)
    }
}

impl ShopifyConnector {
    #[allow(clippy::too_many_lines)]
    async fn invoke_inner(&self, req: InvokeRequest) -> FcpResult<InvokeResponse> {
        self.base.check_ready()?;
        let operation = req.operation.as_str();
        if let Some(verifier) = &self.verifier {
            let cap = Self::capability_for_operation(operation)?;
            verifier.verify_bound(req.capability_token, &cap, &req.operation, &[])?;
        } else {
            return Err(FcpError::Internal {
                message: "connector ready state missing capability verifier".into(),
            });
        }

        let runtime = self.runtime.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing runtime".into(),
        })?;
        let client = self.client.as_ref().ok_or_else(|| FcpError::Internal {
            message: "connector ready state missing Shopify client".into(),
        })?;
        let idempotency_key = req.idempotency_key.as_deref();

        let output = match operation {
            OP_PRODUCTS_LIST => {
                let products = client
                    .list_products(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&products).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_PRODUCTS_GET => {
                let pid = Self::require_u64(&req.input, "product_id")?;
                let product = client
                    .get_product(runtime, pid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&product).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_PRODUCTS_CREATE => {
                let title = Self::require_str(&req.input, "title")?;
                let product = CreateProduct {
                    title: title.into(),
                    body_html: req
                        .input
                        .get("body_html")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    vendor: req
                        .input
                        .get("vendor")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    product_type: req
                        .input
                        .get("product_type")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    status: req
                        .input
                        .get("status")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    tags: req
                        .input
                        .get("tags")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    variants: req
                        .input
                        .get("variants")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .map(|v| CreateVariant {
                                    title: v
                                        .get("title")
                                        .and_then(|t| t.as_str())
                                        .map(String::from),
                                    price: v
                                        .get("price")
                                        .and_then(|p| p.as_str())
                                        .map(String::from),
                                    sku: v.get("sku").and_then(|s| s.as_str()).map(String::from),
                                })
                                .collect()
                        })
                        .unwrap_or_default(),
                };
                let created = client
                    .create_product(runtime, &product, idempotency_key)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&created).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_PRODUCTS_UPDATE => {
                let pid = Self::require_u64(&req.input, "product_id")?;
                let update = UpdateProduct {
                    title: req
                        .input
                        .get("title")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    body_html: req
                        .input
                        .get("body_html")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    vendor: req
                        .input
                        .get("vendor")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    product_type: req
                        .input
                        .get("product_type")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    status: req
                        .input
                        .get("status")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    tags: req
                        .input
                        .get("tags")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                };
                let updated = client
                    .update_product(runtime, pid, &update, idempotency_key)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&updated).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_PRODUCTS_DELETE => {
                let pid = Self::require_u64(&req.input, "product_id")?;
                client
                    .delete_product(runtime, pid)
                    .await
                    .map_err(|e| e.to_fcp_error())?
            }
            OP_ORDERS_LIST => {
                let orders = client
                    .list_orders(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&orders).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_ORDERS_GET => {
                let oid = Self::require_u64(&req.input, "order_id")?;
                let order = client
                    .get_order(runtime, oid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&order).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_ORDERS_CREATE => {
                let items = req
                    .input
                    .get("line_items")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing: line_items array".into(),
                    })?;
                let line_items: Vec<CreateLineItem> = items
                    .iter()
                    .map(|item| {
                        Ok(CreateLineItem {
                            variant_id: item
                                .get("variant_id")
                                .and_then(serde_json::Value::as_u64)
                                .ok_or_else(|| FcpError::InvalidRequest {
                                    code: 1005,
                                    message: "line_items[].variant_id required".into(),
                                })?,
                            quantity: item
                                .get("quantity")
                                .and_then(serde_json::Value::as_i64)
                                .unwrap_or(1),
                        })
                    })
                    .collect::<FcpResult<Vec<_>>>()?;
                let order = CreateOrder {
                    line_items,
                    email: req
                        .input
                        .get("email")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    financial_status: req
                        .input
                        .get("financial_status")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                };
                let created = client
                    .create_order(runtime, &order, idempotency_key)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&created).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_CUSTOMERS_LIST => {
                let customers = client
                    .list_customers(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&customers).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_CUSTOMERS_GET => {
                let cid = Self::require_u64(&req.input, "customer_id")?;
                let customer = client
                    .get_customer(runtime, cid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&customer).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_INVENTORY_LIST => {
                let lid = Self::require_u64(&req.input, "location_id")?;
                let levels = client
                    .list_inventory_levels(runtime, lid)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                serde_json::to_value(&levels).map_err(|e| FcpError::Internal {
                    message: e.to_string(),
                })?
            }
            OP_HEALTH => {
                let shop = client
                    .health_check(runtime)
                    .await
                    .map_err(|e| e.to_fcp_error())?;
                json!({
                    "healthy": true,
                    "shop_id": shop.id,
                    "shop_name": shop.name,
                    "shop_domain": shop.domain,
                    "plan_name": shop.plan_name,
                })
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        Ok(InvokeResponse::ok(req.id, output))
    }

    fn capability_for_operation(operation: &str) -> FcpResult<CapabilityId> {
        let capability = match operation {
            OP_PRODUCTS_LIST | OP_PRODUCTS_GET | OP_HEALTH => CAP_PRODUCTS_READ,
            OP_PRODUCTS_CREATE | OP_PRODUCTS_UPDATE | OP_PRODUCTS_DELETE => CAP_PRODUCTS_WRITE,
            OP_ORDERS_LIST | OP_ORDERS_GET => CAP_ORDERS_READ,
            OP_ORDERS_CREATE => CAP_ORDERS_WRITE,
            OP_CUSTOMERS_LIST | OP_CUSTOMERS_GET => CAP_CUSTOMERS_READ,
            OP_INVENTORY_LIST => CAP_INVENTORY_READ,
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        };
        Ok(CapabilityId::from_static(capability))
    }

    fn validate_input_for_operation(operation: &str, input: &serde_json::Value) -> FcpResult<()> {
        match operation {
            OP_PRODUCTS_LIST | OP_ORDERS_LIST | OP_CUSTOMERS_LIST | OP_HEALTH => {}
            OP_PRODUCTS_GET | OP_PRODUCTS_UPDATE | OP_PRODUCTS_DELETE => {
                Self::require_u64(input, "product_id")?;
            }
            OP_PRODUCTS_CREATE => {
                Self::require_str(input, "title")?;
            }
            OP_ORDERS_GET => {
                Self::require_u64(input, "order_id")?;
            }
            OP_ORDERS_CREATE => {
                let items = input
                    .get("line_items")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| FcpError::InvalidRequest {
                        code: 1005,
                        message: "Missing: line_items array".into(),
                    })?;
                for item in items {
                    item.get("variant_id")
                        .and_then(serde_json::Value::as_u64)
                        .ok_or_else(|| FcpError::InvalidRequest {
                            code: 1005,
                            message: "line_items[].variant_id required".into(),
                        })?;
                }
            }
            OP_CUSTOMERS_GET => {
                Self::require_u64(input, "customer_id")?;
            }
            OP_INVENTORY_LIST => {
                Self::require_u64(input, "location_id")?;
            }
            _ => {
                return Err(FcpError::InvalidRequest {
                    code: 1004,
                    message: format!("Unknown operation: {operation}"),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use chrono::{Duration, Utc};
    use fcp_crypto::cose::CapabilityTokenBuilder;
    use fcp_crypto::ed25519::Ed25519SigningKey;
    use fcp_manifest::ConnectorManifest;
    use fcp_prelude::{CapabilityConstraints, CapabilityToken, RequestId, ZoneId};

    fn tc() -> serde_json::Value {
        json!({
            "shop_domain": "test.myshopify.com",
            "access_token": "shpat_test123"
        })
    }

    fn tc_credential_id() -> serde_json::Value {
        json!({
            "shop_domain": "test.myshopify.com",
            "credential_id": "550e8400-e29b-41d4-a716-446655440000"
        })
    }

    fn handshake_req() -> HandshakeRequest {
        HandshakeRequest {
            protocol_version: "2.0.0".into(),
            zone: ZoneId::work(),
            zone_dir: None,
            host_public_key: [0u8; 32],
            nonce: [0u8; 32],
            capabilities_requested: vec![
                CapabilityId::from_static(CAP_PRODUCTS_READ),
                CapabilityId::from_static(CAP_PRODUCTS_WRITE),
                CapabilityId::from_static(CAP_ORDERS_READ),
            ],
            host: None,
            transport_caps: None,
            requested_instance_id: None,
        }
    }

    fn handshake_req_for(signing_key: &Ed25519SigningKey) -> HandshakeRequest {
        let mut req = handshake_req();
        req.host_public_key = signing_key.verifying_key().to_bytes();
        req
    }

    fn signed_token(
        signing_key: &Ed25519SigningKey,
        instance_id: &str,
        capability: &'static str,
        operation: &'static str,
    ) -> CapabilityToken {
        let now = Utc::now();
        let constraints = CapabilityConstraints {
            resource_allow: vec!["*".into()],
            ..Default::default()
        };
        let mut constraints_cbor = Vec::new();
        ciborium::into_writer(&constraints, &mut constraints_cbor).unwrap();
        let cose = CapabilityTokenBuilder::new()
            .capability_id(capability)
            .zone_id("z:work")
            .principal("user:test")
            .operations(&[operation])
            .issuer("node:test")
            .target_instance(instance_id)
            .validity(now, now + Duration::hours(1))
            .try_constraints_cbor(&constraints_cbor)
            .unwrap()
            .sign(signing_key)
            .unwrap();
        CapabilityToken::from_raw(cose)
    }

    fn simulate_req(
        operation: &'static str,
        input: serde_json::Value,
        token: CapabilityToken,
    ) -> SimulateRequest {
        SimulateRequest::new(
            ConnectorId::from_static("fcp.shopify"),
            OperationId::from_static(operation),
            ZoneId::work(),
            input,
            token,
        )
    }

    fn invoke_req(op: &'static str, input: serde_json::Value) -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId::new("r1"),
            connector_id: ConnectorId::from_static("fcp.shopify"),
            operation: OperationId::from_static(op),
            zone_id: ZoneId::work(),
            input,
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        }
    }

    #[test]
    fn new_ok() {
        assert!(ShopifyConnector::new().config.is_none());
    }

    #[test]
    fn default_ok() {
        assert!(ShopifyConnector::default().config.is_none());
    }

    #[test]
    fn manifest_hash_stable() {
        assert_eq!(
            ShopifyConnector::manifest_hash(),
            ShopifyConnector::manifest_hash()
        );
    }

    #[test]
    fn configure_valid() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await
            })
            .unwrap()
            .is_ok()
        );
    }

    #[test]
    fn configure_empty_domain() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(json!({"shop_domain":"","access_token":"t"}))
                    .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn configure_bad() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(json!("bad")).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn configure_accepts_credential_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc_credential_id()).await
            })
            .unwrap()
            .is_ok()
        );
    }

    #[test]
    fn configure_missing_auth() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(json!({"shop_domain":"test.myshopify.com"}))
                    .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn configure_rejects_both_auth_modes() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(json!({
                    "shop_domain":"test.myshopify.com",
                    "access_token":"shpat_test123",
                    "credential_id":"550e8400-e29b-41d4-a716-446655440000"
                }))
                .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn doctor_unconfigured() {
        assert!(!ShopifyConnector::new().doctor().ready);
    }

    #[test]
    fn doctor_configured() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await.unwrap();
                c.doctor()
            })
            .unwrap()
            .ready
        );
    }

    #[test]
    fn introspect_ops() {
        assert_eq!(ShopifyConnector::new().introspect().operations.len(), 12);
    }

    #[test]
    fn ops_all_have_hints() {
        for op in operations_info() {
            assert!(!op.ai_hints.when_to_use.is_empty(), "{}", op.id);
        }
    }

    #[test]
    fn dangerous_ops_need_approval() {
        for op in operations_info() {
            if op.safety_tier == SafetyTier::Dangerous {
                assert!(op.requires_approval.is_some(), "{}", op.id);
            }
        }
    }

    fn op(operation_id: &'static str) -> OperationInfo {
        operations_info()
            .into_iter()
            .find(|op| op.id.as_str() == operation_id)
            .expect("operation should exist in operation table")
    }

    #[test]
    fn invoke_unknown() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req("shopify.nope", json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_missing_product_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_PRODUCTS_GET, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_missing_order_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_ORDERS_GET, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_missing_customer_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_CUSTOMERS_GET, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_missing_location_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_INVENTORY_LIST, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_create_order_missing_line_items() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_ORDERS_CREATE, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_create_order_missing_variant_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(
                    OP_ORDERS_CREATE,
                    json!({"line_items": [{"quantity": 1}]}),
                ))
                .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn simulate_ok() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            let mut c = ShopifyConnector::new();
            let signing_key = Ed25519SigningKey::generate();
            c.configure(tc()).await.unwrap();
            c.handshake(handshake_req_for(&signing_key)).await.unwrap();
            let token = signed_token(
                &signing_key,
                c.instance_id(),
                CAP_PRODUCTS_READ,
                OP_PRODUCTS_LIST,
            );
            c.simulate(simulate_req(OP_PRODUCTS_LIST, json!({}), token))
                .await
        })
        .unwrap()
        .unwrap();
        assert!(r.would_succeed);
    }

    #[test]
    fn simulate_unconfigured_denied() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            ShopifyConnector::new()
                .simulate(simulate_req(
                    OP_PRODUCTS_LIST,
                    json!({}),
                    CapabilityToken::test_token(),
                ))
                .await
        })
        .unwrap()
        .unwrap();
        assert!(!r.would_succeed);
        assert_eq!(r.denial_code, Some(FcpError::NotConfigured.error_code()));
    }

    #[test]
    fn simulate_requires_handshake() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            let mut c = ShopifyConnector::new();
            c.configure(tc()).await.unwrap();
            c.simulate(simulate_req(
                OP_PRODUCTS_LIST,
                json!({}),
                CapabilityToken::test_token(),
            ))
            .await
        })
        .unwrap()
        .unwrap();
        assert!(!r.would_succeed);
        assert_eq!(r.denial_code, Some(FcpError::NotHandshaken.error_code()));
    }

    #[test]
    fn simulate_rejects_invalid_input() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            let mut c = ShopifyConnector::new();
            let signing_key = Ed25519SigningKey::generate();
            c.configure(tc()).await.unwrap();
            c.handshake(handshake_req_for(&signing_key)).await.unwrap();
            let token = signed_token(
                &signing_key,
                c.instance_id(),
                CAP_PRODUCTS_READ,
                OP_PRODUCTS_GET,
            );
            c.simulate(simulate_req(OP_PRODUCTS_GET, json!({}), token))
                .await
        })
        .unwrap()
        .unwrap();
        assert!(!r.would_succeed);
        assert!(
            r.failure_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("product_id"))
        );
    }

    #[test]
    fn simulate_rejects_wrong_capability() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            let mut c = ShopifyConnector::new();
            let signing_key = Ed25519SigningKey::generate();
            c.configure(tc()).await.unwrap();
            c.handshake(handshake_req_for(&signing_key)).await.unwrap();
            let token = signed_token(
                &signing_key,
                c.instance_id(),
                CAP_PRODUCTS_READ,
                OP_PRODUCTS_LIST,
            );
            c.simulate(simulate_req(
                OP_PRODUCTS_CREATE,
                json!({"title": "New product"}),
                token,
            ))
            .await
        })
        .unwrap()
        .unwrap();
        assert!(!r.would_succeed);
        assert_eq!(r.missing_capabilities, vec![CAP_PRODUCTS_WRITE.to_string()]);
    }

    #[test]
    fn subscribe_unsupported() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                ShopifyConnector::new()
                    .subscribe(SubscribeRequest {
                        r#type: "subscribe".into(),
                        id: RequestId::new("sub1"),
                        topics: vec![],
                        since: None,
                        max_events_per_sec: None,
                        batch_ms: None,
                        window_size: None,
                        capability_token: None,
                    })
                    .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn shutdown_ok() {
        fcp_async_core::runtime::block_on_sync(async {
            let mut c = ShopifyConnector::new();
            c.configure(tc()).await.unwrap();
            c.shutdown(ShutdownRequest {
                r#type: "shutdown".into(),
                deadline_ms: 10_000,
                drain: false,
                reason: None,
            })
            .await
            .unwrap();
        })
        .unwrap();
    }

    #[test]
    fn handshake_ok() {
        let r = fcp_async_core::runtime::block_on_sync(async {
            let mut c = ShopifyConnector::new();
            c.configure(tc()).await.unwrap();
            c.handshake(handshake_req()).await.unwrap()
        })
        .unwrap();
        assert_eq!(r.status, "accepted");
        assert_eq!(r.capabilities_granted.len(), 3);
    }

    #[test]
    fn handshake_requires_configuration() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                ShopifyConnector::new().handshake(handshake_req()).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn require_str_ok() {
        assert_eq!(
            ShopifyConnector::require_str(&json!({"k":"v"}), "k").unwrap(),
            "v"
        );
    }

    #[test]
    fn require_str_miss() {
        assert!(ShopifyConnector::require_str(&json!({}), "k").is_err());
    }

    #[test]
    fn require_str_empty() {
        assert!(ShopifyConnector::require_str(&json!({"k": ""}), "k").is_err());
        assert!(ShopifyConnector::require_str(&json!({"k": "  "}), "k").is_err());
    }

    #[test]
    fn require_u64_ok() {
        assert_eq!(
            ShopifyConnector::require_u64(&json!({"id": 42}), "id").unwrap(),
            42
        );
    }

    #[test]
    fn require_u64_miss() {
        assert!(ShopifyConnector::require_u64(&json!({}), "id").is_err());
    }

    #[test]
    fn health_unconfigured() {
        let h = fcp_async_core::runtime::block_on_sync(async {
            ShopifyConnector::new().health().await
        })
        .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Degraded { .. }));
    }

    #[test]
    fn health_configured() {
        let h = fcp_async_core::runtime::block_on_sync(async {
            let mut c = ShopifyConnector::new();
            c.configure(tc()).await.unwrap();
            c.health().await
        })
        .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Ready));
        assert_eq!(
            h.details.as_ref().and_then(|d| {
                d.get("contract")
                    .and_then(|contract| contract.get("auth_boundary"))
                    .and_then(|auth| auth.get("binding"))
                    .and_then(|value| value.as_str())
            }),
            Some(SHOPIFY_BINDING_MODEL)
        );
    }

    #[test]
    fn config_debug_redacts_token() {
        let cfg = ShopifyConfig {
            shop_domain: "test.myshopify.com".into(),
            auth: ShopifyAuth::AccessToken {
                access_token: "shpat_secret".into(),
            },
            api_version: "2024-01".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: 30_000,
        };
        let debug = format!("{cfg:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("shpat_secret"));
    }

    #[test]
    fn config_validate_rejects_host_injecting_shop_domain() {
        let cfg_with = |shop_domain: &str| ShopifyConfig {
            shop_domain: shop_domain.into(),
            auth: ShopifyAuth::AccessToken {
                access_token: "shpat_secret".into(),
            },
            api_version: "2024-01".into(),
            retry: HttpRetryConfig::default(),
            request_timeout_ms: 30_000,
        };

        // The `\` and `@` variants end with `.myshopify.com` and contain no `/`,
        // so they slip past the separator + suffix checks — the character
        // allowlist is what blocks them from re-anchoring the request host.
        for evil in [
            "attacker.com\\x.myshopify.com",
            "evil.com@x.myshopify.com",
            "x.myshopify.com:8080",
            "x .myshopify.com",
            "https://example.com",
        ] {
            assert!(
                cfg_with(evil).validate().is_err(),
                "shop_domain {evil:?} must be rejected"
            );
        }
        assert!(cfg_with("test-store.myshopify.com").validate().is_ok());
    }

    #[test]
    fn invoke_create_product_missing_title() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_PRODUCTS_CREATE, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_update_missing_product_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_PRODUCTS_UPDATE, json!({"title":"x"})))
                    .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn invoke_delete_missing_product_id() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(tc()).await.unwrap();
                c.handshake(handshake_req()).await.unwrap();
                c.invoke(invoke_req(OP_PRODUCTS_DELETE, json!({}))).await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn ops_count_matches_spec() {
        let ops = operations_info();
        assert_eq!(ops.len(), 12, "Expected 12 operations");
        let safe_count = ops
            .iter()
            .filter(|o| o.safety_tier == SafetyTier::Safe)
            .count();
        assert_eq!(safe_count, 8, "Expected 8 safe operations");
        let risky_count = ops
            .iter()
            .filter(|o| o.safety_tier == SafetyTier::Risky)
            .count();
        assert_eq!(risky_count, 3, "Expected 3 risky operations");
        let dangerous_count = ops
            .iter()
            .filter(|o| o.safety_tier == SafetyTier::Dangerous)
            .count();
        assert_eq!(dangerous_count, 1, "Expected 1 dangerous operation");
    }

    #[test]
    fn configure_rejects_non_shopify_hostname() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(json!({"shop_domain":"https://example.com","access_token":"t"}))
                    .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn configure_rejects_invalid_api_version() {
        assert!(
            fcp_async_core::runtime::block_on_sync(async {
                let mut c = ShopifyConnector::new();
                c.configure(json!({
                    "shop_domain":"test.myshopify.com",
                    "access_token":"t",
                    "api_version":"latest"
                }))
                .await
            })
            .unwrap()
            .is_err()
        );
    }

    #[test]
    fn product_list_contract_is_strict_and_page_limited() {
        let op = op(OP_PRODUCTS_LIST);
        assert_eq!(op.idempotency, IdempotencyClass::Strict);
        assert_eq!(op.requires_approval, Some(ApprovalMode::None));
        assert!(
            op.ai_hints
                .common_mistakes
                .iter()
                .any(|mistake| mistake.contains("first 50")),
        );
    }

    #[test]
    fn mutating_product_contract_is_truthful() {
        let create = op(OP_PRODUCTS_CREATE);
        assert_eq!(create.idempotency, IdempotencyClass::None);
        assert_eq!(create.requires_approval, Some(ApprovalMode::Interactive));

        let update = op(OP_PRODUCTS_UPDATE);
        assert_eq!(update.idempotency, IdempotencyClass::BestEffort);
        assert_eq!(update.requires_approval, Some(ApprovalMode::Interactive));

        let delete = op(OP_PRODUCTS_DELETE);
        assert_eq!(delete.idempotency, IdempotencyClass::Strict);
        assert_eq!(delete.requires_approval, Some(ApprovalMode::Interactive));
    }

    #[test]
    fn orders_contract_mentions_historical_scope_and_payment_boundary() {
        let list = op(OP_ORDERS_LIST);
        assert_eq!(list.idempotency, IdempotencyClass::Strict);
        assert!(
            list.ai_hints
                .common_mistakes
                .iter()
                .any(|mistake| mistake.contains(SHOPIFY_ORDER_HISTORY_SCOPE)),
        );

        let create = op(OP_ORDERS_CREATE);
        assert_eq!(create.idempotency, IdempotencyClass::None);
        assert_eq!(create.requires_approval, Some(ApprovalMode::Interactive));
        assert!(
            create
                .description
                .as_deref()
                .is_some_and(|description| description.contains("payment")),
        );
    }

    #[test]
    fn doctor_includes_non_goal_guidance() {
        let doctor = ShopifyConnector::new().doctor();
        assert!(doctor.checks.iter().any(|check| {
            check.name == "first_slice_inventory"
                && check
                    .message
                    .as_deref()
                    .is_some_and(|message| message.contains("Fulfillment"))
        }),);
    }

    #[test]
    fn health_secretless_configured_is_ready() {
        let h = fcp_async_core::runtime::block_on_sync(async {
            let mut c = ShopifyConnector::new();
            c.configure(tc_credential_id()).await.unwrap();
            c.health().await
        })
        .unwrap();
        assert!(matches!(h.status, fcp_core::HealthState::Ready));
    }

    #[test]
    fn manifest_interface_hash_is_deterministic() {
        let manifest_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("manifest.toml");
        if !manifest_path.exists() {
            eprintln!("manifest.toml missing; skipping interface_hash check");
            return;
        }

        let raw = std::fs::read_to_string(&manifest_path).expect("read manifest");
        let manifest = ConnectorManifest::parse_str(&raw).expect("manifest should validate");
        let computed = manifest
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(manifest.manifest.interface_hash, computed);

        let manifest2 = ConnectorManifest::parse_str_unchecked(&raw).expect("parse unchecked");
        let computed2 = manifest2
            .compute_interface_hash()
            .expect("compute interface hash");
        assert_eq!(computed, computed2);
    }
}
