//! HTTP client for Synology Chat webhook delivery.

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs},
};

use reqwest::header::RETRY_AFTER;
use serde::Serialize;
use serde_json::{Map, Value, json};
use url::Url;

use crate::error::{SynologyChatError, SynologyChatResult};
use crate::types::{SynologyChatConfig, SynologyChatDeliveryTarget};

const MAX_FILE_URL_LEN: usize = 2048;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SynologyChatResponseKind {
    Empty,
    Json,
    Text,
}

#[derive(Debug, Clone, Serialize)]
pub struct SynologyChatDispatchResult {
    pub status: &'static str,
    pub http_status: u16,
    pub response_kind: SynologyChatResponseKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_body: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynologyChatMessageRequest {
    text: String,
    user_ids: Vec<String>,
    bot_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynologyChatFileUrlRequest {
    file_url: String,
    user_ids: Vec<String>,
    bot_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SynologyChatFileUrlAudit {
    pub decision: &'static str,
    pub classification: &'static str,
    pub scheme: String,
    pub host: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    pub resolved_ip_count: usize,
    pub allowlisted_host: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynologyChatFileUrlPolicy {
    allowed_hosts: BTreeSet<String>,
    max_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SynologyChatValidatedFileUrl {
    url: String,
    audit: SynologyChatFileUrlAudit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SynologyChatPayload {
    payload: Map<String, Value>,
}

#[derive(Clone)]
pub struct SynologyChatClient {
    client: reqwest::Client,
    target: SynologyChatDeliveryTarget,
    incoming_url: String,
    file_url_policy: SynologyChatFileUrlPolicy,
}

impl std::fmt::Debug for SynologyChatClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SynologyChatClient")
            .field("target", &self.target)
            .field("incoming_url", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl SynologyChatDispatchResult {
    /// # Panics
    ///
    /// Panics if the dispatch result cannot be serialized into JSON.
    #[must_use]
    pub fn into_json(self) -> Value {
        serde_json::to_value(self).expect("SynologyChatDispatchResult must serialize")
    }
}

impl SynologyChatMessageRequest {
    pub fn new(
        text: &str,
        user_ids: &[String],
        bot_name: Option<&str>,
    ) -> SynologyChatResult<Self> {
        if text.trim().is_empty() {
            return Err(SynologyChatError::InvalidInput(
                "text must not be empty".into(),
            ));
        }

        Ok(Self {
            text: text.to_string(),
            user_ids: normalize_user_ids(user_ids)?,
            bot_name: normalize_bot_name(bot_name),
        })
    }

    #[must_use]
    pub fn as_payload(&self) -> Value {
        let mut body = json!({ "text": self.text });
        if !self.user_ids.is_empty() {
            body["user_ids"] = json!(self.user_ids);
        }
        if let Some(bot_name) = &self.bot_name {
            body["username"] = json!(bot_name);
        }
        body
    }
}

impl SynologyChatFileUrlRequest {
    pub fn new(
        file_url: &str,
        user_ids: &[String],
        bot_name: Option<&str>,
    ) -> SynologyChatResult<Self> {
        let trimmed = file_url.trim();
        if trimmed.is_empty() {
            return Err(SynologyChatError::InvalidInput(
                "file_url must not be empty".into(),
            ));
        }
        Ok(Self {
            file_url: trimmed.to_string(),
            user_ids: normalize_user_ids(user_ids)?,
            bot_name: normalize_bot_name(bot_name),
        })
    }

    #[must_use]
    pub fn as_payload(&self, validated_file_url: &str) -> Value {
        let mut body = json!({ "file_url": validated_file_url });
        if !self.user_ids.is_empty() {
            body["user_ids"] = json!(self.user_ids);
        }
        if let Some(bot_name) = &self.bot_name {
            body["username"] = json!(bot_name);
        }
        body
    }
}

impl SynologyChatFileUrlPolicy {
    #[must_use]
    pub fn from_allowed_hosts(hosts: &[String]) -> Self {
        Self {
            allowed_hosts: hosts
                .iter()
                .map(|host| host.trim().trim_end_matches('.').to_ascii_lowercase())
                .filter(|host| !host.is_empty())
                .collect(),
            max_len: MAX_FILE_URL_LEN,
        }
    }

    fn validate(&self, raw_url: &str) -> SynologyChatResult<SynologyChatValidatedFileUrl> {
        let parsed = parse_file_url(raw_url, self.max_len)?;
        let host = normalized_host(&parsed)?;
        if self.is_allowlisted_host(&host) {
            return Ok(validated_file_url(
                &parsed,
                &host,
                "allowlisted_host",
                &[],
                true,
            ));
        }
        let resolved_ips = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![ip]
        } else {
            resolve_file_url_host(&host, parsed.port_or_known_default())?
        };
        self.validate_with_resolved_ips(raw_url, &resolved_ips)
    }

    fn validate_with_resolved_ips(
        &self,
        raw_url: &str,
        resolved_ips: &[IpAddr],
    ) -> SynologyChatResult<SynologyChatValidatedFileUrl> {
        let parsed = parse_file_url(raw_url, self.max_len)?;
        let host = normalized_host(&parsed)?;
        if self.is_allowlisted_host(&host) {
            return Ok(validated_file_url(
                &parsed,
                &host,
                "allowlisted_host",
                &[],
                true,
            ));
        }
        reject_internal_hostname(&host)?;
        if resolved_ips.is_empty() {
            return Err(SynologyChatError::InvalidInput(
                "file_url host could not be resolved".into(),
            ));
        }
        if let Ok(host_ip) = host.parse::<IpAddr>()
            && !resolved_ips.contains(&host_ip)
        {
            return Err(SynologyChatError::InvalidInput(
                "file_url DNS pin mismatch".into(),
            ));
        }
        for ip in resolved_ips {
            reject_internal_ip(*ip)?;
        }
        let classification = if host.parse::<IpAddr>().is_ok() {
            "public_ip"
        } else {
            "public_dns"
        };
        Ok(validated_file_url(
            &parsed,
            &host,
            classification,
            resolved_ips,
            false,
        ))
    }

    fn is_allowlisted_host(&self, host: &str) -> bool {
        self.allowed_hosts.contains(host)
    }
}

impl Default for SynologyChatFileUrlPolicy {
    fn default() -> Self {
        Self::from_allowed_hosts(&[])
    }
}

impl SynologyChatPayload {
    pub fn from_value(payload: &Value) -> SynologyChatResult<Self> {
        let object = payload.as_object().ok_or_else(|| {
            SynologyChatError::InvalidInput("payload must be a JSON object".into())
        })?;
        Ok(Self {
            payload: object.clone(),
        })
    }

    #[must_use]
    pub fn as_value(&self) -> Value {
        Value::Object(self.payload.clone())
    }
}

impl SynologyChatClient {
    pub fn from_config(config: &SynologyChatConfig) -> SynologyChatResult<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_millis(
                config.request_timeout_ms(),
            ))
            .danger_accept_invalid_certs(config.allow_insecure_ssl())
            .build()?;
        Ok(Self {
            client,
            target: config.delivery_target(),
            incoming_url: config.normalized_incoming_url(),
            file_url_policy: SynologyChatFileUrlPolicy::from_allowed_hosts(
                config.allowed_file_url_hosts(),
            ),
        })
    }

    #[must_use]
    pub const fn target(&self) -> &SynologyChatDeliveryTarget {
        &self.target
    }

    pub async fn send_message(
        &self,
        request: &SynologyChatMessageRequest,
    ) -> SynologyChatResult<SynologyChatDispatchResult> {
        self.send_payload(&SynologyChatPayload::from_value(&request.as_payload())?)
            .await
    }

    pub async fn send_payload(
        &self,
        payload: &SynologyChatPayload,
    ) -> SynologyChatResult<SynologyChatDispatchResult> {
        let response = self
            .client
            .post(&self.incoming_url)
            .json(&payload.as_value())
            .send()
            .await?;
        self.normalize_response(response).await
    }

    pub async fn send_file_url(
        &self,
        request: &SynologyChatFileUrlRequest,
    ) -> SynologyChatResult<(SynologyChatDispatchResult, SynologyChatFileUrlAudit)> {
        let validated = self.file_url_policy.validate(&request.file_url)?;
        let payload = SynologyChatPayload::from_value(&request.as_payload(&validated.url))?;
        let result = self.send_payload(&payload).await?;
        Ok((result, validated.audit))
    }

    async fn normalize_response(
        &self,
        response: reqwest::Response,
    ) -> SynologyChatResult<SynologyChatDispatchResult> {
        let status = response.status();
        let retry_after_ms = response
            .headers()
            .get(RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_retry_after_ms);
        let body = response.text().await?;
        if !status.is_success() {
            return Err(SynologyChatError::Api {
                status: status.as_u16(),
                message: body,
                retry_after_ms,
            });
        }
        if body.trim().is_empty() {
            return Ok(SynologyChatDispatchResult {
                status: "ok",
                http_status: status.as_u16(),
                response_kind: SynologyChatResponseKind::Empty,
                body: None,
                raw_body: None,
            });
        }
        serde_json::from_str::<Value>(&body).map_or_else(
            |_| {
                Ok(SynologyChatDispatchResult {
                    status: "ok",
                    http_status: status.as_u16(),
                    response_kind: SynologyChatResponseKind::Text,
                    body: None,
                    raw_body: Some(body),
                })
            },
            |json_body| {
                Ok(SynologyChatDispatchResult {
                    status: "ok",
                    http_status: status.as_u16(),
                    response_kind: SynologyChatResponseKind::Json,
                    body: Some(json_body),
                    raw_body: None,
                })
            },
        )
    }
}

fn normalize_user_ids(user_ids: &[String]) -> SynologyChatResult<Vec<String>> {
    let mut normalized_user_ids = Vec::with_capacity(user_ids.len());
    for user_id in user_ids {
        let trimmed = user_id.trim();
        if trimmed.is_empty() {
            return Err(SynologyChatError::InvalidInput(
                "user_ids must not contain empty strings".into(),
            ));
        }
        if !normalized_user_ids
            .iter()
            .any(|existing| existing == trimmed)
        {
            normalized_user_ids.push(trimmed.to_string());
        }
    }
    Ok(normalized_user_ids)
}

fn normalize_bot_name(bot_name: Option<&str>) -> Option<String> {
    bot_name
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn parse_file_url(raw_url: &str, max_len: usize) -> SynologyChatResult<Url> {
    let trimmed = raw_url.trim();
    if trimmed.is_empty() {
        return Err(SynologyChatError::InvalidInput(
            "file_url must not be empty".into(),
        ));
    }
    if trimmed.len() > max_len {
        return Err(SynologyChatError::InvalidInput(format!(
            "file_url must be at most {max_len} bytes"
        )));
    }
    let parsed = Url::parse(trimmed)
        .map_err(|_| SynologyChatError::InvalidInput("file_url must be a valid URL".into()))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(SynologyChatError::InvalidInput(
            "file_url must use http or https".into(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(SynologyChatError::InvalidInput(
            "file_url must not include credentials".into(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(SynologyChatError::InvalidInput(
            "file_url must not include a fragment".into(),
        ));
    }
    if parsed.host_str().is_none() {
        return Err(SynologyChatError::InvalidInput(
            "file_url must include a host".into(),
        ));
    }
    Ok(parsed)
}

fn normalized_host(parsed: &Url) -> SynologyChatResult<String> {
    parsed
        .host_str()
        .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
        .filter(|host| !host.is_empty())
        .ok_or_else(|| SynologyChatError::InvalidInput("file_url must include a host".into()))
}

fn resolve_file_url_host(host: &str, port: Option<u16>) -> SynologyChatResult<Vec<IpAddr>> {
    let port = port.unwrap_or(443);
    let mut ips = Vec::new();
    for address in (host, port).to_socket_addrs().map_err(|_| {
        SynologyChatError::InvalidInput("file_url host could not be resolved".into())
    })? {
        if !ips.contains(&address.ip()) {
            ips.push(address.ip());
        }
    }
    if ips.is_empty() {
        return Err(SynologyChatError::InvalidInput(
            "file_url host could not be resolved".into(),
        ));
    }
    Ok(ips)
}

fn reject_internal_hostname(host: &str) -> SynologyChatResult<()> {
    if host == "localhost"
        || terminal_label_is(host, "localhost")
        || terminal_label_is(host, "local")
        || terminal_label_is(host, "internal")
        || terminal_label_is(host, "lan")
        || terminal_labels_are(host, "home", "arpa")
    {
        return Err(SynologyChatError::InvalidInput(
            "file_url host is internal and must be explicitly allowlisted".into(),
        ));
    }
    Ok(())
}

fn terminal_label_is(host: &str, label: &str) -> bool {
    host.len() > label.len() && host.rsplit('.').next() == Some(label)
}

fn terminal_labels_are(host: &str, penultimate: &str, terminal: &str) -> bool {
    let mut labels = host.rsplit('.');
    labels.next() == Some(terminal) && labels.next() == Some(penultimate)
}

fn reject_internal_ip(ip: IpAddr) -> SynologyChatResult<()> {
    if ip_is_internal(ip) {
        return Err(SynologyChatError::InvalidInput(
            "file_url host resolves to a private or internal address".into(),
        ));
    }
    Ok(())
}

const fn ip_is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ipv4_is_internal(ip),
        IpAddr::V6(ip) => ipv6_is_internal(ip),
    }
}

const fn ipv4_is_internal(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    matches!(
        octets,
        [0 | 10 | 127 | 224..=255, _, _, _]
            | [100, 64..=127, _, _]
            | [169, 254, _, _]
            | [172, 16..=31, _, _]
            | [192, 0, 0 | 2, _]
            | [192, 168, _, _]
            | [198, 18..=19, _, _]
            | [198, 51, 100, _]
            | [203, 0, 113, _]
    )
}

const fn ipv6_is_internal(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    ip.is_unspecified()
        || ip.is_loopback()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xff00) == 0xff00
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
}

fn validated_file_url(
    parsed: &Url,
    host: &str,
    classification: &'static str,
    resolved_ips: &[IpAddr],
    allowlisted_host: bool,
) -> SynologyChatValidatedFileUrl {
    SynologyChatValidatedFileUrl {
        url: parsed.to_string(),
        audit: SynologyChatFileUrlAudit {
            decision: "allowed",
            classification,
            scheme: parsed.scheme().to_string(),
            host: host.to_string(),
            port: parsed.port_or_known_default(),
            resolved_ip_count: resolved_ips.len(),
            allowlisted_host,
        },
    }
}

/// Stringify a JSON value that might be a string or integer.
fn stringify_json_value(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        serde_json::Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Normalize an inbound webhook payload into a stable event envelope.
///
/// This function converts a raw Synology Chat outgoing-webhook callback
/// into a [`NormalizedInboundEvent`](crate::types::NormalizedInboundEvent) with stringified identifiers and
/// optional token verification.
///
/// # Token verification
///
/// If `configured_token` is `Some`, the payload's `token` field is compared
/// against it. The result is recorded in `token_verified`:
/// - `Some(true)` if tokens match
/// - `Some(false)` if tokens mismatch or payload token is missing
/// - `None` if no `configured_token` is provided (verification skipped)
pub fn normalize_inbound_event(
    payload: &crate::types::InboundWebhookPayload,
    configured_token: Option<&str>,
    raw: serde_json::Value,
) -> (
    crate::types::NormalizedInboundEvent,
    crate::types::TokenVerification,
) {
    use crate::types::{NormalizedInboundEvent, TokenVerification};

    let channel_id = payload.channel_id.as_ref().and_then(stringify_json_value);
    let sender_id = payload.user_id.as_ref().and_then(stringify_json_value);
    let timestamp = payload.timestamp.as_ref().and_then(stringify_json_value);
    let thread_id = payload.thread_id.as_ref().and_then(stringify_json_value);
    let is_threaded = thread_id
        .as_deref()
        .is_some_and(|tid| !tid.is_empty() && tid != "0");

    let (token_verified, verification) = match (configured_token, payload.token.as_deref()) {
        (Some(expected), Some(actual)) => {
            if expected == actual {
                (Some(true), TokenVerification::Verified)
            } else {
                (Some(false), TokenVerification::Mismatch)
            }
        }
        (Some(_), None) => (Some(false), TokenVerification::MissingFromPayload),
        (None, _) => (None, TokenVerification::NotConfigured),
    };

    let event = NormalizedInboundEvent {
        event_type: "inbound_webhook".to_string(),
        channel_id,
        channel_name: payload
            .channel_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string),
        sender_id,
        sender_name: payload
            .username
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string),
        text: payload
            .text
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string),
        timestamp,
        trigger_word: payload
            .trigger_word
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string),
        is_threaded,
        thread_id,
        file_url: payload
            .file_url
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string),
        token_verified,
        raw,
    };

    (event, verification)
}

fn parse_retry_after_ms(value: &str) -> Option<u64> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .map(|seconds| seconds.saturating_mul(1000))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn message_request_normalizes_inputs() {
        let request = SynologyChatMessageRequest::new(
            "hello",
            &[
                String::from(" 123 "),
                String::from("123"),
                String::from("456"),
            ],
            Some("  Flywheel "),
        )
        .expect("message request should parse");
        assert_eq!(
            request.as_payload(),
            json!({
                "text": "hello",
                "user_ids": ["123", "456"],
                "username": "Flywheel"
            })
        );
    }

    #[test]
    fn file_url_request_preserves_user_targeting_payload_shape() {
        let request = SynologyChatFileUrlRequest::new(
            " https://cdn.example.com/report.pdf ",
            &[String::from(" 4 "), String::from("4"), String::from("7")],
            Some("  Build Bot "),
        )
        .expect("file URL request should parse");
        assert_eq!(
            request.as_payload("https://cdn.example.com/report.pdf"),
            json!({
                "file_url": "https://cdn.example.com/report.pdf",
                "user_ids": ["4", "7"],
                "username": "Build Bot"
            })
        );
    }

    #[test]
    fn file_url_policy_accepts_public_http_and_https_with_resolved_ips() {
        let policy = SynologyChatFileUrlPolicy::default();
        for raw_url in [
            "http://cdn.example.com/report.pdf",
            "https://cdn.example.com/report.pdf?download=1",
        ] {
            let validated = policy
                .validate_with_resolved_ips(raw_url, &["93.184.216.34".parse().unwrap()])
                .expect("public resolved URL should pass");
            assert_eq!(validated.audit.decision, "allowed");
            assert_eq!(validated.audit.classification, "public_dns");
            assert_eq!(validated.audit.host, "cdn.example.com");
            assert_eq!(validated.audit.resolved_ip_count, 1);
        }
    }

    #[test]
    fn file_url_policy_rejects_disallowed_schemes() {
        let policy = SynologyChatFileUrlPolicy::default();
        for raw_url in [
            "ftp://cdn.example.com/report.pdf",
            "file:///etc/passwd",
            "javascript:alert(1)",
        ] {
            let error = policy
                .validate_with_resolved_ips(raw_url, &["93.184.216.34".parse().unwrap()])
                .expect_err("scheme should be rejected");
            assert!(error.to_string().contains("http or https"));
        }
    }

    #[test]
    fn file_url_policy_rejects_credentials_fragments_and_oversized_urls() {
        let policy = SynologyChatFileUrlPolicy::default();
        for raw_url in [
            "https://user:secret@cdn.example.com/report.pdf",
            "https://cdn.example.com/report.pdf#fragment",
        ] {
            let error = policy
                .validate_with_resolved_ips(raw_url, &["93.184.216.34".parse().unwrap()])
                .expect_err("unsafe URL decoration should fail");
            let message = error.to_string();
            assert!(message.contains("credentials") || message.contains("fragment"));
        }

        let oversized = format!("https://cdn.example.com/{}", "a".repeat(MAX_FILE_URL_LEN));
        let error = policy
            .validate_with_resolved_ips(&oversized, &["93.184.216.34".parse().unwrap()])
            .expect_err("oversized URL should fail");
        assert!(error.to_string().contains("at most"));
    }

    #[test]
    fn file_url_policy_rejects_localhost_private_and_link_local_destinations() {
        let policy = SynologyChatFileUrlPolicy::default();
        for (raw_url, resolved_ip) in [
            ("https://localhost/report.pdf", "127.0.0.1"),
            ("https://nas.local/report.pdf", "192.168.1.20"),
            ("https://cdn.example.com/report.pdf", "10.0.0.5"),
            ("https://cdn.example.com/report.pdf", "169.254.1.10"),
            ("https://[fd00::1]/report.pdf", "fd00::1"),
            ("https://cdn.example.com/report.pdf", "fe80::1"),
        ] {
            let error = policy
                .validate_with_resolved_ips(raw_url, &[resolved_ip.parse().unwrap()])
                .expect_err("internal destination should fail");
            let message = error.to_string();
            assert!(
                message.contains("internal")
                    || message.contains("private")
                    || message.contains("DNS pin mismatch")
            );
        }
    }

    #[test]
    fn file_url_policy_rejects_unresolved_hosts_and_pin_mismatches() {
        let policy = SynologyChatFileUrlPolicy::default();
        let unresolved = policy
            .validate_with_resolved_ips("https://cdn.example.com/report.pdf", &[])
            .expect_err("unresolved host should fail");
        assert!(unresolved.to_string().contains("could not be resolved"));

        let mismatch = policy
            .validate_with_resolved_ips(
                "https://93.184.216.34/report.pdf",
                &["1.1.1.1".parse().unwrap()],
            )
            .expect_err("IP host must match pinned resolution");
        assert!(mismatch.to_string().contains("DNS pin mismatch"));
    }

    #[test]
    fn file_url_policy_allows_exact_host_override() {
        let policy = SynologyChatFileUrlPolicy::from_allowed_hosts(&["localhost".to_string()]);
        let validated = policy
            .validate_with_resolved_ips("http://localhost:12345/report.pdf", &[])
            .expect("exact allowlist override should permit private lab host");
        assert_eq!(validated.audit.classification, "allowlisted_host");
        assert!(validated.audit.allowlisted_host);
        assert_eq!(validated.audit.host, "localhost");
    }

    #[test]
    fn normalize_inbound_event_full_payload() {
        use crate::types::{InboundWebhookPayload, TokenVerification};

        let payload = InboundWebhookPayload {
            user_id: Some(json!(4)),
            username: Some("mikael".into()),
            post_id: Some(json!("146028888128")),
            channel_id: Some(json!(34)),
            channel_name: Some("Labb".into()),
            channel_type: Some(json!(1)),
            text: Some("Tjena".into()),
            timestamp: Some(json!("1646827836131")),
            token: Some("shared-secret".into()),
            trigger_word: Some("Tjena".into()),
            thread_id: Some(json!("0")),
            file_url: None,
        };

        let raw = serde_json::to_value(json!({
            "user_id": 4, "username": "mikael", "text": "Tjena"
        }))
        .unwrap();

        let (event, verification) = normalize_inbound_event(&payload, Some("shared-secret"), raw);

        assert_eq!(event.event_type, "inbound_webhook");
        assert_eq!(event.channel_id.as_deref(), Some("34"));
        assert_eq!(event.channel_name.as_deref(), Some("Labb"));
        assert_eq!(event.sender_id.as_deref(), Some("4"));
        assert_eq!(event.sender_name.as_deref(), Some("mikael"));
        assert_eq!(event.text.as_deref(), Some("Tjena"));
        assert_eq!(event.timestamp.as_deref(), Some("1646827836131"));
        assert_eq!(event.trigger_word.as_deref(), Some("Tjena"));
        assert!(!event.is_threaded);
        assert_eq!(event.thread_id.as_deref(), Some("0"));
        assert_eq!(event.token_verified, Some(true));
        assert_eq!(verification, TokenVerification::Verified);
    }

    #[test]
    fn normalize_inbound_event_token_mismatch() {
        use crate::types::{InboundWebhookPayload, TokenVerification};

        let payload = InboundWebhookPayload {
            user_id: Some(json!(4)),
            username: Some("mikael".into()),
            post_id: None,
            channel_id: Some(json!(34)),
            channel_name: None,
            channel_type: None,
            text: Some("Hello".into()),
            timestamp: None,
            token: Some("wrong-token".into()),
            trigger_word: None,
            thread_id: None,
            file_url: None,
        };

        let (event, verification) =
            normalize_inbound_event(&payload, Some("correct-token"), json!({}));

        assert_eq!(event.token_verified, Some(false));
        assert_eq!(verification, TokenVerification::Mismatch);
    }

    #[test]
    fn normalize_inbound_event_token_missing_from_payload() {
        use crate::types::{InboundWebhookPayload, TokenVerification};

        let payload = InboundWebhookPayload {
            user_id: None,
            username: None,
            post_id: None,
            channel_id: None,
            channel_name: None,
            channel_type: None,
            text: Some("Hello".into()),
            timestamp: None,
            token: None,
            trigger_word: None,
            thread_id: None,
            file_url: None,
        };

        let (event, verification) =
            normalize_inbound_event(&payload, Some("configured-token"), json!({}));

        assert_eq!(event.token_verified, Some(false));
        assert_eq!(verification, TokenVerification::MissingFromPayload);
    }

    #[test]
    fn normalize_inbound_event_no_configured_token() {
        use crate::types::{InboundWebhookPayload, TokenVerification};

        let payload = InboundWebhookPayload {
            user_id: Some(json!("user-99")),
            username: Some("alice".into()),
            post_id: None,
            channel_id: Some(json!("chan-1")),
            channel_name: Some("general".into()),
            channel_type: None,
            text: Some("Hi there".into()),
            timestamp: Some(json!(1_646_827_836_131_i64)),
            token: Some("some-token".into()),
            trigger_word: None,
            thread_id: None,
            file_url: None,
        };

        let (event, verification) = normalize_inbound_event(&payload, None, json!({}));

        assert_eq!(event.token_verified, None);
        assert_eq!(verification, TokenVerification::NotConfigured);
        assert_eq!(event.channel_id.as_deref(), Some("chan-1"));
        assert_eq!(event.sender_id.as_deref(), Some("user-99"));
    }

    #[test]
    fn normalize_inbound_event_minimal_payload() {
        use crate::types::{InboundWebhookPayload, TokenVerification};

        let payload = InboundWebhookPayload {
            user_id: None,
            username: None,
            post_id: None,
            channel_id: None,
            channel_name: None,
            channel_type: None,
            text: None,
            timestamp: None,
            token: None,
            trigger_word: None,
            thread_id: None,
            file_url: None,
        };

        let (event, verification) = normalize_inbound_event(&payload, None, json!({}));

        assert_eq!(event.event_type, "inbound_webhook");
        assert!(event.channel_id.is_none());
        assert!(event.channel_name.is_none());
        assert!(event.sender_id.is_none());
        assert!(event.sender_name.is_none());
        assert!(event.text.is_none());
        assert!(event.timestamp.is_none());
        assert!(!event.is_threaded);
        assert!(event.thread_id.is_none());
        assert!(event.token_verified.is_none());
        assert_eq!(verification, TokenVerification::NotConfigured);
    }

    #[test]
    fn normalize_inbound_event_threaded_message() {
        use crate::types::InboundWebhookPayload;

        let payload = InboundWebhookPayload {
            user_id: Some(json!(7)),
            username: Some("bob".into()),
            post_id: Some(json!("post-123")),
            channel_id: Some(json!(42)),
            channel_name: Some("dev".into()),
            channel_type: Some(json!(1)),
            text: Some("Reply in thread".into()),
            timestamp: Some(json!("1700000000000")),
            token: None,
            trigger_word: None,
            thread_id: Some(json!("thread-456")),
            file_url: Some("https://nas.local/file.pdf".into()),
        };

        let (event, _verification) = normalize_inbound_event(&payload, None, json!({}));

        assert!(event.is_threaded);
        assert_eq!(event.thread_id.as_deref(), Some("thread-456"));
        assert_eq!(
            event.file_url.as_deref(),
            Some("https://nas.local/file.pdf")
        );
        assert_eq!(event.text.as_deref(), Some("Reply in thread"));
    }

    #[test]
    fn normalize_inbound_event_trims_whitespace() {
        use crate::types::InboundWebhookPayload;

        let payload = InboundWebhookPayload {
            user_id: None,
            username: Some("  alice  ".into()),
            post_id: None,
            channel_id: None,
            channel_name: Some("  general  ".into()),
            channel_type: None,
            text: Some("  hello  ".into()),
            timestamp: None,
            token: None,
            trigger_word: Some("  hello  ".into()),
            thread_id: None,
            file_url: Some("  https://example.com/file  ".into()),
        };

        let (event, _) = normalize_inbound_event(&payload, None, json!({}));

        assert_eq!(event.sender_name.as_deref(), Some("alice"));
        assert_eq!(event.channel_name.as_deref(), Some("general"));
        assert_eq!(event.text.as_deref(), Some("hello"));
        assert_eq!(event.trigger_word.as_deref(), Some("hello"));
        assert_eq!(event.file_url.as_deref(), Some("https://example.com/file"));
    }

    #[test]
    fn normalize_inbound_event_empty_strings_become_none() {
        use crate::types::InboundWebhookPayload;

        let payload = InboundWebhookPayload {
            user_id: None,
            username: Some(String::new()),
            post_id: None,
            channel_id: None,
            channel_name: Some("   ".into()),
            channel_type: None,
            text: Some(String::new()),
            timestamp: None,
            token: None,
            trigger_word: Some("  ".into()),
            thread_id: None,
            file_url: Some(String::new()),
        };

        let (event, _) = normalize_inbound_event(&payload, None, json!({}));

        assert!(event.sender_name.is_none());
        assert!(event.channel_name.is_none());
        assert!(event.text.is_none());
        assert!(event.trigger_word.is_none());
        assert!(event.file_url.is_none());
    }
}
