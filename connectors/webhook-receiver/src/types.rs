//! Webhook Receiver types.

use std::{net::IpAddr, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A validated source address or CIDR range. Address families stay distinct:
/// a range for one family is a non-match for the other, not an invalid policy.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SourceIpRange {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
}

impl FromStr for SourceIpRange {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        let (address, prefix) = value
            .split_once('/')
            .map_or((value, None), |(address, prefix)| (address, Some(prefix)));
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| "must be an IP address or CIDR range")?;
        let width = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => {
                if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err("CIDR prefix must be an unsigned decimal integer");
                }
                prefix
                    .parse::<u8>()
                    .ok()
                    .filter(|prefix| *prefix <= width)
                    .ok_or("CIDR prefix exceeds the address-family width")?
            }
            None => width,
        };
        Ok(match address {
            IpAddr::V4(address) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                Self::V4 {
                    network: u32::from(address) & mask,
                    mask,
                }
            }
            IpAddr::V6(address) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                Self::V6 {
                    network: u128::from(address) & mask,
                    mask,
                }
            }
        })
    }
}

impl SourceIpRange {
    pub(crate) fn contains(self, address: IpAddr) -> bool {
        match (self, address) {
            (Self::V4 { network, mask }, IpAddr::V4(address)) => {
                u32::from(address) & mask == network
            }
            (Self::V6 { network, mask }, IpAddr::V6(address)) => {
                u128::from(address) & mask == network
            }
            _ => false,
        }
    }
}

/// Supported webhook provider presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum WebhookProvider {
    /// Generic webhook source with caller-specified verification settings.
    #[default]
    Generic,
    /// GitHub webhook delivery.
    GitHub,
    /// Stripe webhook delivery.
    Stripe,
    /// Slack webhook delivery.
    Slack,
    /// Twilio webhook delivery.
    Twilio,
}

impl WebhookProvider {
    /// Parse a user-facing provider label.
    #[must_use]
    pub fn from_label(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "generic" => Some(Self::Generic),
            "github" => Some(Self::GitHub),
            "stripe" => Some(Self::Stripe),
            "slack" => Some(Self::Slack),
            "twilio" => Some(Self::Twilio),
            _ => None,
        }
    }

    /// Stable provider label used in serialized payloads.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::GitHub => "github",
            Self::Stripe => "stripe",
            Self::Slack => "slack",
            Self::Twilio => "twilio",
        }
    }

    /// Default path suffix for the provider.
    #[must_use]
    pub const fn default_path_segment(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::GitHub => "github",
            Self::Stripe => "stripe",
            Self::Slack => "slack",
            Self::Twilio => "twilio",
        }
    }

    /// Default signature header for the provider.
    #[must_use]
    pub const fn default_signature_header(self) -> &'static str {
        match self {
            Self::Generic => "X-Signature",
            Self::GitHub => "X-Hub-Signature-256",
            Self::Stripe => "Stripe-Signature",
            Self::Slack => "X-Slack-Signature",
            Self::Twilio => "X-Twilio-Signature",
        }
    }

    /// Default signature algorithm for the provider.
    #[must_use]
    pub const fn default_signature_algorithm(self) -> &'static str {
        match self {
            Self::Generic => "hmac-sha256",
            Self::GitHub => "hmac-sha256",
            Self::Stripe => "stripe-signature-v1",
            Self::Slack => "slack-signature-v0",
            Self::Twilio => "twilio-hmac-sha1",
        }
    }

    /// Default signing-secret prefix for generated secrets.
    #[must_use]
    pub const fn secret_prefix(self) -> &'static str {
        match self {
            Self::Generic => "whsec_",
            Self::GitHub => "ghsec_",
            Self::Stripe => "whsec_",
            Self::Slack => "slksec_",
            Self::Twilio => "twsec_",
        }
    }

    /// Recommended event filters to register upstream.
    #[must_use]
    pub const fn recommended_events(self) -> &'static [&'static str] {
        match self {
            Self::Generic => &["*"],
            Self::GitHub => &["push", "pull_request"],
            Self::Stripe => &["payment_intent.succeeded", "invoice.payment_failed"],
            Self::Slack => &["event_callback", "url_verification"],
            Self::Twilio => &["message.received", "status_callback"],
        }
    }
}

/// A registered webhook endpoint.
#[derive(Clone, Serialize, Deserialize)]
pub struct WebhookEndpoint {
    /// Unique identifier for this endpoint.
    pub endpoint_id: String,
    /// URL path this endpoint listens on.
    pub path: String,
    /// HMAC signing secret for payload verification.
    #[serde(default, skip_serializing, skip_deserializing)]
    pub signing_secret: String,
    /// Optional IP CIDR ranges allowed to send webhooks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_sources: Vec<String>,
    /// Full URL where this endpoint is reachable.
    pub url: String,
    /// Provider preset used to generate verification guidance.
    #[serde(default)]
    pub provider: WebhookProvider,
    /// Signature header that the upstream provider should send.
    pub signature_header: String,
    /// Signature algorithm expected for verification.
    pub signature_algorithm: String,
    /// When this endpoint was created.
    pub created_at: DateTime<Utc>,
    /// When the signing secret was last rotated.
    pub secret_last_rotated_at: DateTime<Utc>,
    /// Whether this endpoint is currently active.
    pub active: bool,
}

impl std::fmt::Debug for WebhookEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookEndpoint")
            .field("endpoint_id", &self.endpoint_id)
            .field("path", &self.path)
            .field("signing_secret", &"[REDACTED]")
            .field("allowed_sources", &self.allowed_sources)
            .field("url", &self.url)
            .field("provider", &self.provider)
            .field("signature_header", &self.signature_header)
            .field("signature_algorithm", &self.signature_algorithm)
            .field("created_at", &self.created_at)
            .field("secret_last_rotated_at", &self.secret_last_rotated_at)
            .field("active", &self.active)
            .finish()
    }
}

impl WebhookEndpoint {
    /// Create a new webhook endpoint with a generated ID.
    pub fn new(
        path: String,
        signing_secret: String,
        allowed_sources: Vec<String>,
        public_base_url: &str,
        provider: WebhookProvider,
        signature_header: String,
        signature_algorithm: String,
    ) -> Self {
        let endpoint_id = format!("ep_{}", Uuid::new_v4());
        let url = format!("{}{}", public_base_url.trim_end_matches('/'), path);
        let now = Utc::now();
        Self {
            endpoint_id,
            path,
            signing_secret,
            allowed_sources,
            url,
            provider,
            signature_header,
            signature_algorithm,
            created_at: now,
            secret_last_rotated_at: now,
            active: true,
        }
    }

    /// Rebuild the externally visible endpoint URL after configuration changes.
    pub fn update_public_base_url(&mut self, public_base_url: &str) {
        self.url = format!("{}{}", public_base_url.trim_end_matches('/'), self.path);
    }

    /// Rotate the in-memory signing secret.
    pub fn rotate_signing_secret(&mut self, signing_secret: String) {
        self.signing_secret = signing_secret;
        self.secret_last_rotated_at = Utc::now();
    }

    /// Validate endpoint provisioning metadata.
    #[must_use]
    pub fn validation_issues(&self) -> Vec<String> {
        let mut issues = Vec::new();

        if !self.path.starts_with('/') {
            issues.push("path must begin with '/'".to_string());
        }

        if self.signing_secret.trim().is_empty() {
            issues.push("signing secret is empty".to_string());
        }

        if self.signature_header.trim().is_empty() {
            issues.push("signature header is empty".to_string());
        }

        if self.signature_algorithm.trim().is_empty() {
            issues.push("signature algorithm is empty".to_string());
        }

        for (index, source) in self.allowed_sources.iter().enumerate() {
            if let Err(reason) = source.parse::<SourceIpRange>() {
                issues.push(format!("allowed_sources[{index}] {reason}"));
            }
        }

        if self.provider != WebhookProvider::Generic {
            let expected_header = self.provider.default_signature_header();
            let expected_algorithm = self.provider.default_signature_algorithm();
            if self.signature_header != expected_header {
                issues.push(format!(
                    "provider {} expects signature header {}",
                    self.provider.label(),
                    expected_header
                ));
            }
            if self.signature_algorithm != expected_algorithm {
                issues.push(format!(
                    "provider {} expects signature algorithm {}",
                    self.provider.label(),
                    expected_algorithm
                ));
            }
        }

        issues
    }
}

/// A received webhook event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    /// Unique event identifier.
    pub event_id: String,
    /// The endpoint that received this event.
    pub endpoint_id: String,
    /// When the event was received.
    pub received_at: DateTime<Utc>,
    /// HTTP headers from the webhook request (selected).
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub headers: std::collections::HashMap<String, String>,
    /// The raw payload body.
    pub payload: serde_json::Value,
    /// Whether the signature was valid.
    pub signature_valid: bool,
    /// Source IP address if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<String>,
}

impl WebhookEvent {
    /// Create a new webhook event with a generated ID.
    pub fn new(
        endpoint_id: String,
        payload: serde_json::Value,
        signature_valid: bool,
        source_ip: Option<String>,
    ) -> Self {
        Self {
            event_id: format!("evt_{}", Uuid::new_v4()),
            endpoint_id,
            received_at: Utc::now(),
            headers: std::collections::HashMap::new(),
            payload,
            signature_valid,
            source_ip,
        }
    }
}

/// Summary of an endpoint for list operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointSummary {
    pub endpoint_id: String,
    pub path: String,
    pub url: String,
    pub provider: WebhookProvider,
    pub signature_header: String,
    pub signature_algorithm: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_sources: Vec<String>,
    pub secret_last_rotated_at: DateTime<Utc>,
    pub signing_secret_configured: bool,
    pub active: bool,
    pub created_at: DateTime<Utc>,
    pub event_count: usize,
}

impl EndpointSummary {
    /// Create a summary from an endpoint and its event count.
    pub fn from_endpoint(ep: &WebhookEndpoint, event_count: usize) -> Self {
        Self {
            endpoint_id: ep.endpoint_id.clone(),
            path: ep.path.clone(),
            url: ep.url.clone(),
            provider: ep.provider,
            signature_header: ep.signature_header.clone(),
            signature_algorithm: ep.signature_algorithm.clone(),
            allowed_sources: ep.allowed_sources.clone(),
            secret_last_rotated_at: ep.secret_last_rotated_at,
            signing_secret_configured: !ep.signing_secret.is_empty(),
            active: ep.active,
            created_at: ep.created_at,
            event_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn generic_endpoint() -> WebhookEndpoint {
        WebhookEndpoint::new(
            "/hooks/test".into(),
            "secret".into(),
            vec![],
            "https://hooks.flywheel.test",
            WebhookProvider::Generic,
            "X-Signature".into(),
            "hmac-sha256".into(),
        )
    }

    #[test]
    fn source_ip_ranges_cover_prefix_boundaries_and_exact_addresses() {
        for (pattern, included, excluded) in [
            ("203.0.113.9", "203.0.113.9", "203.0.113.10"),
            ("203.0.113.9/32", "203.0.113.9", "203.0.113.8"),
            ("203.0.113.9/31", "203.0.113.8", "203.0.113.10"),
            (" 203.0.113.9/24 ", "203.0.113.255", "203.0.112.255"),
            ("128.0.0.1/1", "255.255.255.255", "127.255.255.255"),
            ("203.0.113.9/0", "0.0.0.0", "::"),
            ("2001:db8::9", "2001:0db8:0:0:0:0:0:9", "2001:db8::a"),
            ("2001:db8::9/128", "2001:db8::9", "2001:db8::8"),
            ("2001:db8::9/127", "2001:db8::8", "2001:db8::a"),
            ("2001:db8::9/32", "2001:db8:ffff::1", "2001:db9::1"),
            ("8000::1/1", "ffff:ffff::1", "7fff:ffff::1"),
            ("2001:db8::9/0", "::", "0.0.0.0"),
        ] {
            let range = pattern.parse::<SourceIpRange>().unwrap();
            assert!(range.contains(included.parse().unwrap()), "{pattern}");
            assert!(!range.contains(excluded.parse().unwrap()), "{pattern}");
        }
    }

    #[test]
    fn source_ip_ranges_do_not_widen_across_address_families() {
        let ipv4 = "0.0.0.0/0".parse::<SourceIpRange>().unwrap();
        let ipv6 = "::/0".parse::<SourceIpRange>().unwrap();
        assert!(!ipv4.contains("2001:db8::1".parse().unwrap()));
        assert!(!ipv4.contains("::ffff:203.0.113.1".parse().unwrap()));
        assert!(!ipv6.contains("203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn source_ip_ranges_reject_malformed_and_out_of_range_prefixes() {
        for pattern in [
            "",
            " ",
            "hooks.example.com",
            "203.0.113.999",
            "203.0.113.0/33",
            "203.0.113.0/128",
            "2001:db8::/129",
            "::/256",
            "203.0.113.0/-1",
            "203.0.113.0/+1",
            "203.0.113.0/",
            "203.0.113.0/24/1",
            "203.0.113.0/ 24",
            "203.0.113.0 /24",
            "203.0.113.0/255.255.255.0",
            "203.0.113.0:443",
            "[2001:db8::1]",
        ] {
            assert!(pattern.parse::<SourceIpRange>().is_err(), "{pattern}");
        }
    }

    #[test]
    fn endpoint_validation_checks_every_source_range() {
        let mut endpoint = generic_endpoint();
        endpoint.allowed_sources = vec![
            "203.0.113.0/24".into(),
            "2001:db8::/129".into(),
            "not-an-address".into(),
        ];
        let issues = endpoint.validation_issues();
        assert_eq!(issues.len(), 2);
        assert!(issues[0].contains("allowed_sources[1]"));
        assert!(issues[1].contains("allowed_sources[2]"));
        endpoint.allowed_sources = vec!["203.0.113.0/24".into(), "2001:db8::/32".into()];
        assert!(endpoint.validation_issues().is_empty());
    }

    #[test]
    fn endpoint_new_generates_uuid() {
        let ep = WebhookEndpoint::new(
            "/hooks/github".into(),
            "whsec_abc123".into(),
            vec![],
            "https://hooks.flywheel.test",
            WebhookProvider::GitHub,
            "X-Hub-Signature-256".into(),
            "hmac-sha256".into(),
        );
        assert!(ep.endpoint_id.starts_with("ep_"));
        assert_eq!(ep.path, "/hooks/github");
        assert_eq!(ep.signing_secret, "whsec_abc123");
        assert_eq!(ep.provider, WebhookProvider::GitHub);
        assert!(ep.url.contains("/hooks/github"));
        assert!(ep.active);
        assert!(ep.allowed_sources.is_empty());
    }

    #[test]
    fn endpoint_new_with_allowed_sources() {
        let ep = WebhookEndpoint::new(
            "/hooks/stripe".into(),
            "whsec_xyz".into(),
            vec!["10.0.0.0/8".into()],
            "https://hooks.flywheel.test",
            WebhookProvider::Stripe,
            "Stripe-Signature".into(),
            "stripe-signature-v1".into(),
        );
        assert_eq!(ep.allowed_sources.len(), 1);
        assert_eq!(ep.allowed_sources[0], "10.0.0.0/8");
    }

    #[test]
    fn endpoint_ids_are_unique() {
        let a = generic_endpoint();
        let b = WebhookEndpoint::new(
            "/hooks/other".into(),
            "secret".into(),
            vec![],
            "https://hooks.flywheel.test",
            WebhookProvider::Generic,
            "X-Signature".into(),
            "hmac-sha256".into(),
        );
        assert_ne!(a.endpoint_id, b.endpoint_id);
    }

    #[test]
    fn endpoint_serialization_redacts_signing_secret() {
        let ep = generic_endpoint();
        let json = serde_json::to_value(&ep).unwrap();
        assert_eq!(json["path"], "/hooks/test");
        assert_eq!(json["active"], true);
        assert!(json.get("signing_secret").is_none());
    }

    #[test]
    fn endpoint_url_format_joins_base_and_path() {
        let ep = WebhookEndpoint::new(
            "/webhooks/v1".into(),
            "secret".into(),
            vec![],
            "https://hooks.flywheel.test/",
            WebhookProvider::Generic,
            "X-Signature".into(),
            "hmac-sha256".into(),
        );
        assert_eq!(ep.url, "https://hooks.flywheel.test/webhooks/v1");
    }

    #[test]
    fn endpoint_skips_empty_allowed_sources() {
        let ep = generic_endpoint();
        let json = serde_json::to_value(&ep).unwrap();
        assert!(json.get("allowed_sources").is_none());
    }

    #[test]
    fn endpoint_includes_nonempty_allowed_sources() {
        let ep = WebhookEndpoint::new(
            "/hooks/test".into(),
            "secret".into(),
            vec!["192.168.0.0/16".into()],
            "https://hooks.flywheel.test",
            WebhookProvider::Generic,
            "X-Signature".into(),
            "hmac-sha256".into(),
        );
        let json = serde_json::to_value(&ep).unwrap();
        assert_eq!(json["allowed_sources"][0], "192.168.0.0/16");
    }

    #[test]
    fn endpoint_rotation_updates_timestamp() {
        let mut ep = generic_endpoint();
        let before = ep.secret_last_rotated_at;
        ep.rotate_signing_secret("rotated".into());
        assert_eq!(ep.signing_secret, "rotated");
        assert!(ep.secret_last_rotated_at >= before);
    }

    #[test]
    fn endpoint_rebuilds_url_when_public_base_changes() {
        let mut ep = generic_endpoint();
        ep.update_public_base_url("https://new-hooks.flywheel.test/");
        assert_eq!(ep.url, "https://new-hooks.flywheel.test/hooks/test");
    }

    #[test]
    fn endpoint_validation_flags_provider_mismatch() {
        let ep = WebhookEndpoint::new(
            "/hooks/github".into(),
            "secret".into(),
            vec![],
            "https://hooks.flywheel.test",
            WebhookProvider::GitHub,
            "Stripe-Signature".into(),
            "stripe-signature-v1".into(),
        );
        let issues = ep.validation_issues();
        assert_eq!(issues.len(), 2);
    }

    #[test]
    fn endpoint_validation_accepts_generic_profile() {
        let ep = generic_endpoint();
        assert!(ep.validation_issues().is_empty());
    }

    #[test]
    fn event_new_generates_uuid() {
        let evt = WebhookEvent::new(
            "ep_abc".into(),
            json!({"type": "push"}),
            true,
            Some("1.2.3.4".into()),
        );
        assert!(evt.event_id.starts_with("evt_"));
        assert_eq!(evt.endpoint_id, "ep_abc");
        assert_eq!(evt.payload["type"], "push");
        assert!(evt.signature_valid);
        assert_eq!(evt.source_ip, Some("1.2.3.4".into()));
    }

    #[test]
    fn event_new_no_source_ip() {
        let evt = WebhookEvent::new("ep_abc".into(), json!({}), false, None);
        assert!(evt.source_ip.is_none());
        assert!(!evt.signature_valid);
    }

    #[test]
    fn event_ids_are_unique() {
        let a = WebhookEvent::new("ep_1".into(), json!({}), true, None);
        let b = WebhookEvent::new("ep_1".into(), json!({}), true, None);
        assert_ne!(a.event_id, b.event_id);
    }

    #[test]
    fn event_serialization_roundtrip() {
        let evt = WebhookEvent::new("ep_abc".into(), json!({"key": "value"}), true, None);
        let json = serde_json::to_value(&evt).unwrap();
        assert_eq!(json["endpoint_id"], "ep_abc");
        assert_eq!(json["payload"]["key"], "value");
        assert_eq!(json["signature_valid"], true);
        let deser: WebhookEvent = serde_json::from_value(json).unwrap();
        assert_eq!(deser.event_id, evt.event_id);
    }

    #[test]
    fn event_skips_null_source_ip() {
        let evt = WebhookEvent::new("ep_abc".into(), json!({}), true, None);
        let json = serde_json::to_value(&evt).unwrap();
        assert!(json.get("source_ip").is_none());
    }

    #[test]
    fn event_includes_source_ip_when_present() {
        let evt = WebhookEvent::new("ep_abc".into(), json!({}), true, Some("10.0.0.1".into()));
        let json = serde_json::to_value(&evt).unwrap();
        assert_eq!(json["source_ip"], "10.0.0.1");
    }

    #[test]
    fn event_skips_empty_headers() {
        let evt = WebhookEvent::new("ep_abc".into(), json!({}), true, None);
        let json = serde_json::to_value(&evt).unwrap();
        assert!(json.get("headers").is_none());
    }

    #[test]
    fn event_with_headers() {
        let mut evt = WebhookEvent::new("ep_abc".into(), json!({}), true, None);
        evt.headers
            .insert("content-type".into(), "application/json".into());
        let json = serde_json::to_value(&evt).unwrap();
        assert_eq!(json["headers"]["content-type"], "application/json");
    }

    #[test]
    fn endpoint_summary_from_endpoint() {
        let ep = generic_endpoint();
        let summary = EndpointSummary::from_endpoint(&ep, 42);
        assert_eq!(summary.endpoint_id, ep.endpoint_id);
        assert_eq!(summary.path, "/hooks/test");
        assert_eq!(summary.url, ep.url);
        assert_eq!(summary.provider, WebhookProvider::Generic);
        assert!(summary.signing_secret_configured);
        assert!(summary.active);
        assert_eq!(summary.event_count, 42);
    }

    #[test]
    fn endpoint_summary_serialization() {
        let ep = generic_endpoint();
        let summary = EndpointSummary::from_endpoint(&ep, 10);
        let json = serde_json::to_value(&summary).unwrap();
        assert_eq!(json["event_count"], 10);
        assert_eq!(json["active"], true);
        let deser: EndpointSummary = serde_json::from_value(json).unwrap();
        assert_eq!(deser.event_count, 10);
    }

    #[test]
    fn endpoint_summary_zero_events() {
        let ep = generic_endpoint();
        let summary = EndpointSummary::from_endpoint(&ep, 0);
        assert_eq!(summary.event_count, 0);
    }

    #[test]
    fn event_deserialization_from_json() {
        let json = json!({
            "event_id": "evt_test",
            "endpoint_id": "ep_abc",
            "received_at": "2026-01-15T10:30:00Z",
            "payload": {"action": "created"},
            "signature_valid": true,
        });
        let evt: WebhookEvent = serde_json::from_value(json).unwrap();
        assert_eq!(evt.event_id, "evt_test");
        assert_eq!(evt.endpoint_id, "ep_abc");
        assert_eq!(evt.payload["action"], "created");
    }

    #[test]
    fn endpoint_debug_format() {
        let ep = generic_endpoint();
        let dbg = format!("{ep:?}");
        assert!(dbg.contains("WebhookEndpoint"));
        assert!(dbg.contains("/hooks/test"));
    }

    #[test]
    fn endpoint_debug_redacts_signing_secret() {
        let ep = WebhookEndpoint::new(
            "/hooks/test".into(),
            "super_secret_signing_key".into(),
            vec![],
            "https://hooks.flywheel.test",
            WebhookProvider::Generic,
            "X-Signature".into(),
            "hmac-sha256".into(),
        );
        let dbg = format!("{ep:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("super_secret_signing_key"));
        assert!(dbg.contains("/hooks/test"));
    }

    #[test]
    fn event_debug_format() {
        let evt = WebhookEvent::new("ep_abc".into(), json!({"type": "push"}), true, None);
        let dbg = format!("{evt:?}");
        assert!(dbg.contains("WebhookEvent"));
        assert!(dbg.contains("ep_abc"));
    }

    #[test]
    fn endpoint_summary_debug_format() {
        let summary = EndpointSummary::from_endpoint(&generic_endpoint(), 1);
        let dbg = format!("{summary:?}");
        assert!(dbg.contains("EndpointSummary"));
    }

    #[test]
    fn provider_from_label_accepts_known_values() {
        assert_eq!(
            WebhookProvider::from_label("github"),
            Some(WebhookProvider::GitHub)
        );
        assert_eq!(
            WebhookProvider::from_label("stripe"),
            Some(WebhookProvider::Stripe)
        );
    }

    #[test]
    fn provider_from_label_rejects_unknown_values() {
        assert_eq!(WebhookProvider::from_label("unknown"), None);
    }

    #[test]
    fn provider_defaults_are_stable() {
        assert_eq!(
            WebhookProvider::GitHub.default_signature_header(),
            "X-Hub-Signature-256"
        );
        assert_eq!(
            WebhookProvider::Stripe.default_signature_algorithm(),
            "stripe-signature-v1"
        );
        assert_eq!(WebhookProvider::Slack.secret_prefix(), "slksec_");
    }

    #[test]
    fn provider_serde_uses_canonical_labels() {
        let serialized = serde_json::to_value(WebhookProvider::GitHub).unwrap();
        assert_eq!(serialized, json!("github"));

        let deserialized: WebhookProvider = serde_json::from_value(json!("github")).unwrap();
        assert_eq!(deserialized, WebhookProvider::GitHub);
    }
}
