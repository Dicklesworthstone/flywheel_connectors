//! `WhatsApp` webhook handler with signature verification.
//!
//! Implements Meta's webhook verification protocol:
//! - Challenge-response for endpoint registration
//! - HMAC-SHA256 signature verification (X-Hub-Signature-256)
//! - Payload parsing into typed events with replay detection
//! - Dead letter queue for failed events
//!
//! Security invariants:
//! - App secret never appears in logs or error messages
//! - Phone numbers are partially redacted in log output
//! - All payloads are signature-verified before processing
//! - Replay detection via message ID deduplication

use std::collections::HashMap;

use fcp_webhook::{
    DeadLetterQueue, HmacSha256Verifier, SignatureVerifier, WebhookConfig, WebhookError,
    WebhookEvent, WebhookHandler, WebhookResult,
};
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use crate::types::{
    IncomingMessage, MessageStatus, WebhookChange, WebhookNotification, WebhookValue,
};

/// Default dead letter queue capacity.
const DEFAULT_DLQ_MAX_SIZE: usize = 1000;
const SIGNATURE_HEADER: &str = "x-hub-signature-256";

/// `WhatsApp` webhook handler.
///
/// Provides:
/// - Challenge-response verification for Meta webhook registration
/// - HMAC-SHA256 signature verification (X-Hub-Signature-256 header)
/// - Typed event parsing from `WebhookNotification` payloads
/// - Message-ID-based replay detection
/// - Dead letter queue for events that fail processing
#[derive(Debug)]
pub struct WhatsAppWebhook {
    verifier: HmacSha256Verifier,
    handler: WebhookHandler<HmacSha256Verifier>,
    verify_token: String,
    dlq: DeadLetterQueue,
}

impl WhatsAppWebhook {
    /// Create a new `WhatsApp` webhook handler.
    ///
    /// # Arguments
    /// - `app_secret`: Meta app secret for HMAC-SHA256 signature verification
    /// - `verify_token`: Token for challenge-response verification
    #[must_use]
    pub fn new(app_secret: impl AsRef<[u8]>, verify_token: String) -> Self {
        let verifier = HmacSha256Verifier::new(app_secret.as_ref());
        let handler_verifier = HmacSha256Verifier::new(app_secret.as_ref());
        let config = WebhookConfig::default().with_idempotency(true);
        let handler = WebhookHandler::with_config(handler_verifier, "whatsapp", config);
        Self {
            verifier,
            handler,
            verify_token,
            dlq: DeadLetterQueue::new(DEFAULT_DLQ_MAX_SIZE),
        }
    }

    /// Create with custom dead letter queue capacity.
    #[must_use]
    pub fn with_dlq_capacity(mut self, max_size: usize) -> Self {
        self.dlq = DeadLetterQueue::new(max_size);
        self
    }

    /// Handle Meta's challenge-response verification.
    ///
    /// When registering a webhook URL, Meta sends a GET request with:
    /// - `hub.mode` = "subscribe"
    /// - `hub.verify_token` = the token configured in Meta's dashboard
    /// - `hub.challenge` = a random string to echo back
    ///
    /// Returns the challenge string if verification passes.
    ///
    /// # Errors
    /// Returns `WebhookError::InvalidSignature` if the mode or token doesn't match.
    pub fn verify_challenge(
        &self,
        mode: &str,
        token: &str,
        challenge: &str,
    ) -> WebhookResult<String> {
        if mode != "subscribe" {
            warn!("webhook challenge with unexpected mode: {mode}");
            return Err(WebhookError::InvalidPayload(format!(
                "unexpected hub.mode: {mode}"
            )));
        }

        // Constant-time comparison for verify_token
        if !constant_time_eq(token.as_bytes(), self.verify_token.as_bytes()) {
            warn!("webhook challenge with invalid verify_token");
            return Err(WebhookError::InvalidSignature);
        }

        debug!("webhook challenge verified successfully");
        Ok(challenge.to_string())
    }

    /// Verify signature and parse a `WhatsApp` webhook notification.
    ///
    /// Meta sends POST requests with:
    /// - `X-Hub-Signature-256` header: `sha256=<hex>` HMAC-SHA256 of the body
    /// - JSON body: `WebhookNotification` envelope
    ///
    /// Returns a list of parsed `WebhookEvent`s (one per message/status).
    ///
    /// # Errors
    /// Returns an error if signature verification fails or the payload is malformed.
    pub fn verify_and_parse(
        &self,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> WebhookResult<Vec<WebhookEvent>> {
        // Check payload size
        if body.len() > self.handler.config().max_payload_size {
            return Err(WebhookError::PayloadTooLarge {
                size: body.len(),
                limit: self.handler.config().max_payload_size,
            });
        }

        // Get and verify signature
        let signature = single_header_value_case_insensitive(headers, SIGNATURE_HEADER)?;

        self.verifier.verify(body, signature)?;

        // Parse notification envelope
        let notification: WebhookNotification = serde_json::from_slice(body)
            .map_err(|e| WebhookError::InvalidPayload(e.to_string()))?;

        if notification.object != "whatsapp_business_account" {
            return Err(WebhookError::InvalidPayload(format!(
                "unexpected object type: {}",
                notification.object
            )));
        }

        // Extract events from all entries/changes
        let mut events = Vec::new();
        for entry in &notification.entry {
            for change in &entry.changes {
                let change_events = self.parse_change(change, &entry.id, headers, body)?;
                events.extend(change_events);
            }
        }

        debug!(
            event_count = events.len(),
            "parsed WhatsApp webhook notification"
        );
        Ok(events)
    }

    /// Check if an event has already been processed (replay detection).
    ///
    /// Returns `Ok(())` if the event is new, or `Err(ReplayDetected)` if already seen.
    ///
    /// # Errors
    /// Returns `WebhookError::ReplayDetected` if the event ID was already claimed.
    pub fn claim_event(&self, event_id: &str) -> WebhookResult<()> {
        self.handler.claim_event(event_id)
    }

    /// Send a failed event to the dead letter queue.
    pub fn dead_letter(&self, event: WebhookEvent) {
        self.dlq.push(event);
    }

    /// Get all events in the dead letter queue.
    #[must_use]
    pub fn dead_letters(&self) -> Vec<WebhookEvent> {
        self.dlq.all()
    }

    /// Remove and return an event from the dead letter queue by ID.
    pub fn remove_dead_letter(&self, event_id: &str) -> Option<WebhookEvent> {
        self.dlq.remove(event_id)
    }

    /// Get the dead letter queue size.
    #[must_use]
    pub fn dead_letter_count(&self) -> usize {
        self.dlq.len()
    }

    /// Redact a phone number for safe logging.
    ///
    /// Keeps first 2 and last 2 digits, replaces middle with asterisks.
    /// Numbers shorter than 6 chars are fully redacted.
    #[must_use]
    pub fn redact_phone(phone: &str) -> String {
        let digits: Vec<char> = phone.chars().filter(char::is_ascii_digit).collect();
        if digits.len() < 6 {
            return "***".to_string();
        }
        let prefix: String = digits[..2].iter().collect();
        let suffix: String = digits[digits.len() - 2..].iter().collect();
        let stars = "*".repeat(digits.len() - 4);
        format!("{prefix}{stars}{suffix}")
    }

    /// Parse a single webhook change into events.
    #[allow(clippy::unused_self, clippy::unnecessary_wraps)]
    fn parse_change(
        &self,
        change: &WebhookChange,
        entry_id: &str,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> WebhookResult<Vec<WebhookEvent>> {
        let mut events = Vec::new();
        let value = &change.value;

        // Parse incoming messages
        for (message_index, msg) in value.messages.iter().enumerate() {
            let event = self.message_to_event(msg, message_index, value, entry_id, headers, body);
            events.push(event);
        }

        // Parse status updates
        for (status_index, status) in value.statuses.iter().enumerate() {
            let event = self.status_to_event(status, status_index, value, entry_id, headers, body);
            events.push(event);
        }

        Ok(events)
    }

    /// Convert an incoming message to a `WebhookEvent`.
    #[allow(clippy::unused_self)]
    fn message_to_event(
        &self,
        msg: &IncomingMessage,
        message_index: usize,
        value: &WebhookValue,
        entry_id: &str,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> WebhookEvent {
        let event_type = format!("message.{}", msg.message_type);
        let fallback_discriminator = format!("message:{entry_id}:{message_index}");
        let event_id = if msg.id.is_empty() {
            deterministic_event_id(
                "whatsapp",
                &event_type,
                body,
                fallback_discriminator.as_bytes(),
            )
        } else {
            msg.id.clone()
        };

        let phone_number_id = value
            .metadata
            .as_ref()
            .map_or("", |m| m.phone_number_id.as_str());

        let payload = serde_json::json!({
            "message": {
                "from": msg.from,
                "id": msg.id,
                "timestamp": msg.timestamp,
                "type": msg.message_type,
                "text": msg.text,
                "image": msg.image,
                "location": msg.location,
            },
            "metadata": {
                "phone_number_id": phone_number_id,
                "display_phone_number": value.metadata.as_ref().map_or("", |m| m.display_phone_number.as_str()),
                "entry_id": entry_id,
            }
        });

        debug!(
            event_type = %event_type,
            event_id = %event_id,
            from = %Self::redact_phone(&msg.from),
            "parsed incoming WhatsApp message"
        );

        WebhookEvent::new(event_id, event_type, "whatsapp")
            .with_default_webhook_taint()
            .with_payload(payload)
            .with_headers(headers.clone())
    }

    /// Convert a status update to a `WebhookEvent`.
    #[allow(clippy::unused_self)]
    fn status_to_event(
        &self,
        status: &MessageStatus,
        status_index: usize,
        value: &WebhookValue,
        entry_id: &str,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> WebhookEvent {
        let event_type = format!("status.{}", status.status);
        let fallback_discriminator = format!("status:{entry_id}:{status_index}");
        let event_id = if status.id.is_empty() {
            deterministic_event_id(
                "whatsapp",
                &event_type,
                body,
                fallback_discriminator.as_bytes(),
            )
        } else {
            format!("{}:status:{}", status.id, status.status)
        };

        let phone_number_id = value
            .metadata
            .as_ref()
            .map_or("", |m| m.phone_number_id.as_str());

        let payload = serde_json::json!({
            "status": {
                "id": status.id,
                "status": status.status,
                "timestamp": status.timestamp,
                "recipient_id": status.recipient_id,
            },
            "metadata": {
                "phone_number_id": phone_number_id,
                "display_phone_number": value.metadata.as_ref().map_or("", |m| m.display_phone_number.as_str()),
                "entry_id": entry_id,
            }
        });

        debug!(
            event_type = %event_type,
            event_id = %event_id,
            recipient = %Self::redact_phone(&status.recipient_id),
            "parsed WhatsApp status update"
        );

        WebhookEvent::new(event_id, event_type, "whatsapp")
            .with_default_webhook_taint()
            .with_payload(payload)
            .with_headers(headers.clone())
    }
}

fn single_header_value_case_insensitive<'a>(
    headers: &'a HashMap<String, String>,
    name: &str,
) -> WebhookResult<&'a str> {
    let mut matches = headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str());

    let Some(value) = matches.next() else {
        return Err(WebhookError::MissingSignature("X-Hub-Signature-256".into()));
    };
    if matches.next().is_some() {
        return Err(WebhookError::InvalidPayload(format!(
            "duplicate logical header: {name}"
        )));
    }

    Ok(value)
}

/// Generate a deterministic event ID from provider, event type, payload, and
/// an event-local discriminator so distinct empty-ID events in the same
/// webhook body do not collapse onto one replay key.
fn deterministic_event_id(
    provider: &str,
    event_type: &str,
    body: &[u8],
    discriminator: &[u8],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(provider.as_bytes());
    hasher.update([0]);
    hasher.update(event_type.as_bytes());
    hasher.update([0]);
    hasher.update(discriminator);
    hasher.update([0]);
    hasher.update(body);
    let digest = hasher.finalize();
    format!("{provider}:{}", hex::encode(digest))
}

/// Constant-time byte comparison to prevent timing attacks.
///
/// The early return on length mismatch is acceptable here because:
/// - For HMAC signature verification (the primary security use), both inputs are
///   always 32 bytes (SHA-256 output), so the branch is never taken.
/// - For `verify_token` comparison, the token length is not a meaningful secret
///   (it's configured in Meta's dashboard and sent as a query parameter).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &[u8] = b"test_app_secret_12345";
    const TEST_VERIFY_TOKEN: &str = "my_verify_token_xyz";

    fn make_webhook() -> WhatsAppWebhook {
        WhatsAppWebhook::new(TEST_SECRET, TEST_VERIFY_TOKEN.to_string())
    }

    fn sign_payload(body: &[u8]) -> String {
        let verifier = HmacSha256Verifier::new(TEST_SECRET);
        let sig = verifier.compute(body);
        format!("sha256={sig}")
    }

    fn sample_text_notification() -> serde_json::Value {
        serde_json::json!({
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "WHATSAPP_BUSINESS_ACCOUNT_ID",
                "changes": [{
                    "value": {
                        "messaging_product": "whatsapp",
                        "metadata": {
                            "display_phone_number": "15551234567",
                            "phone_number_id": "PHONE_NUMBER_ID"
                        },
                        "messages": [{
                            "from": "15559876543",
                            "id": "wamid.HBgLMTU1NTk4NzY1NDMVAgASGBQzQUY5MTcxMkFCRTY1RTM5REI0MAA=",
                            "timestamp": "1677000000",
                            "type": "text",
                            "text": { "body": "Hello from WhatsApp!", "preview_url": false }
                        }]
                    },
                    "field": "messages"
                }]
            }]
        })
    }

    fn sample_status_notification() -> serde_json::Value {
        serde_json::json!({
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "WHATSAPP_BUSINESS_ACCOUNT_ID",
                "changes": [{
                    "value": {
                        "messaging_product": "whatsapp",
                        "metadata": {
                            "display_phone_number": "15551234567",
                            "phone_number_id": "PHONE_NUMBER_ID"
                        },
                        "statuses": [{
                            "id": "wamid.STATUS123",
                            "status": "delivered",
                            "timestamp": "1677000100",
                            "recipient_id": "15559876543"
                        }]
                    },
                    "field": "messages"
                }]
            }]
        })
    }

    fn sample_mixed_notification() -> serde_json::Value {
        serde_json::json!({
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "BIZ_ACCOUNT_1",
                "changes": [{
                    "value": {
                        "messaging_product": "whatsapp",
                        "metadata": {
                            "display_phone_number": "15551234567",
                            "phone_number_id": "PHONE_ID_1"
                        },
                        "messages": [
                            {
                                "from": "15559876543",
                                "id": "wamid.MSG1",
                                "timestamp": "1677000000",
                                "type": "text",
                                "text": { "body": "Hi!", "preview_url": false }
                            },
                            {
                                "from": "15551112222",
                                "id": "wamid.MSG2",
                                "timestamp": "1677000001",
                                "type": "image",
                                "image": { "id": "img_123", "caption": "Photo" }
                            }
                        ],
                        "statuses": [{
                            "id": "wamid.STATUS_A",
                            "status": "read",
                            "timestamp": "1677000050",
                            "recipient_id": "15553334444"
                        }]
                    },
                    "field": "messages"
                }]
            }]
        })
    }

    // ─── Challenge-response tests ───────────────────────────────────────────

    #[test]
    fn challenge_success() {
        let wh = make_webhook();
        let result = wh.verify_challenge("subscribe", TEST_VERIFY_TOKEN, "challenge_abc");
        assert_eq!(result.unwrap(), "challenge_abc");
    }

    #[test]
    fn challenge_wrong_token() {
        let wh = make_webhook();
        let result = wh.verify_challenge("subscribe", "wrong_token", "challenge_abc");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            WebhookError::InvalidSignature
        ));
    }

    #[test]
    fn challenge_wrong_mode() {
        let wh = make_webhook();
        let result = wh.verify_challenge("unsubscribe", TEST_VERIFY_TOKEN, "challenge_abc");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            WebhookError::InvalidPayload(_)
        ));
    }

    #[test]
    fn challenge_empty_token() {
        let wh = make_webhook();
        let result = wh.verify_challenge("subscribe", "", "challenge_abc");
        assert!(result.is_err());
    }

    #[test]
    fn challenge_preserves_challenge_string() {
        let wh = make_webhook();
        let challenge = "1234567890abcdef_challenge";
        let result = wh.verify_challenge("subscribe", TEST_VERIFY_TOKEN, challenge);
        assert_eq!(result.unwrap(), challenge);
    }

    // ─── Signature verification tests ───────────────────────────────────────

    #[test]
    fn verify_valid_text_message() {
        let wh = make_webhook();
        let body = serde_json::to_vec(&sample_text_notification()).unwrap();
        let sig = sign_payload(&body);
        let headers = HashMap::from([("x-hub-signature-256".to_string(), sig)]);

        let events = wh.verify_and_parse(&headers, &body).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "message.text");
        assert_eq!(events[0].provider, "whatsapp");
        assert_eq!(
            events[0].id,
            "wamid.HBgLMTU1NTk4NzY1NDMVAgASGBQzQUY5MTcxMkFCRTY1RTM5REI0MAA="
        );
    }

    #[test]
    fn verify_valid_status_update() {
        let wh = make_webhook();
        let body = serde_json::to_vec(&sample_status_notification()).unwrap();
        let sig = sign_payload(&body);
        let headers = HashMap::from([("X-Hub-Signature-256".to_string(), sig)]);

        let events = wh.verify_and_parse(&headers, &body).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "status.delivered");
        assert_eq!(events[0].id, "wamid.STATUS123:status:delivered");
    }

    #[test]
    fn verify_mixed_notification() {
        let wh = make_webhook();
        let body = serde_json::to_vec(&sample_mixed_notification()).unwrap();
        let sig = sign_payload(&body);
        let headers = HashMap::from([("x-hub-signature-256".to_string(), sig)]);

        let events = wh.verify_and_parse(&headers, &body).unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].event_type, "message.text");
        assert_eq!(events[0].id, "wamid.MSG1");
        assert_eq!(events[1].event_type, "message.image");
        assert_eq!(events[1].id, "wamid.MSG2");
        assert_eq!(events[2].event_type, "status.read");
    }

    #[test]
    fn verify_invalid_signature() {
        let wh = make_webhook();
        let body = serde_json::to_vec(&sample_text_notification()).unwrap();
        let headers = HashMap::from([(
            "x-hub-signature-256".to_string(),
            "sha256=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        )]);

        let result = wh.verify_and_parse(&headers, &body);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            WebhookError::InvalidSignature
        ));
    }

    #[test]
    fn verify_missing_signature_header() {
        let wh = make_webhook();
        let body = serde_json::to_vec(&sample_text_notification()).unwrap();
        let headers = HashMap::new();

        let result = wh.verify_and_parse(&headers, &body);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            WebhookError::MissingSignature(_)
        ));
    }

    #[test]
    fn verify_duplicate_logical_signature_headers_rejected() {
        let wh = make_webhook();
        let body = serde_json::to_vec(&sample_text_notification());
        assert!(body.is_ok(), "sample notification must serialize: {body:?}");
        let body = body.unwrap_or_default();
        let sig = sign_payload(&body);
        let headers = HashMap::from([
            ("x-hub-signature-256".to_string(), sig),
            (
                "X-Hub-Signature-256".to_string(),
                "sha256=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                    .to_string(),
            ),
        ]);

        let result = wh.verify_and_parse(&headers, &body);

        assert!(matches!(
            result,
            Err(WebhookError::InvalidPayload(message))
                if message.contains("duplicate logical header")
        ));
    }

    #[test]
    fn verify_malformed_json() {
        let wh = make_webhook();
        let body = b"not valid json at all";
        let sig = sign_payload(body);
        let headers = HashMap::from([("x-hub-signature-256".to_string(), sig)]);

        let result = wh.verify_and_parse(&headers, body);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            WebhookError::InvalidPayload(_)
        ));
    }

    #[test]
    fn verify_wrong_object_type() {
        let wh = make_webhook();
        let body = serde_json::to_vec(&serde_json::json!({
            "object": "page",
            "entry": []
        }))
        .unwrap();
        let sig = sign_payload(&body);
        let headers = HashMap::from([("x-hub-signature-256".to_string(), sig)]);

        let result = wh.verify_and_parse(&headers, &body);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            WebhookError::InvalidPayload(_)
        ));
    }

    #[test]
    fn verify_empty_entry_list() {
        let wh = make_webhook();
        let body = serde_json::to_vec(&serde_json::json!({
            "object": "whatsapp_business_account",
            "entry": []
        }))
        .unwrap();
        let sig = sign_payload(&body);
        let headers = HashMap::from([("x-hub-signature-256".to_string(), sig)]);

        let events = wh.verify_and_parse(&headers, &body).unwrap();
        assert!(events.is_empty());
    }

    // ─── Replay detection tests ─────────────────────────────────────────────

    #[test]
    fn claim_event_success() {
        let wh = make_webhook();
        assert!(wh.claim_event("unique_id_1").is_ok());
    }

    #[test]
    fn claim_event_duplicate_rejected() {
        let wh = make_webhook();
        wh.claim_event("dup_id").unwrap();
        let result = wh.claim_event("dup_id");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            WebhookError::ReplayDetected { .. }
        ));
    }

    #[test]
    fn claim_different_events_ok() {
        let wh = make_webhook();
        assert!(wh.claim_event("id_a").is_ok());
        assert!(wh.claim_event("id_b").is_ok());
        assert!(wh.claim_event("id_c").is_ok());
    }

    // ─── Dead letter queue tests ────────────────────────────────────────────

    #[test]
    fn dlq_push_and_retrieve() {
        let wh = make_webhook();
        let event = WebhookEvent::new("dlq_1", "message.text", "whatsapp");
        wh.dead_letter(event);
        assert_eq!(wh.dead_letter_count(), 1);
        let letters = wh.dead_letters();
        assert_eq!(letters.len(), 1);
        assert_eq!(letters[0].id, "dlq_1");
    }

    #[test]
    fn dlq_remove_by_id() {
        let wh = make_webhook();
        let event = WebhookEvent::new("dlq_rm", "status.failed", "whatsapp");
        wh.dead_letter(event);
        let removed = wh.remove_dead_letter("dlq_rm");
        assert!(removed.is_some());
        assert_eq!(wh.dead_letter_count(), 0);
    }

    #[test]
    fn dlq_remove_nonexistent() {
        let wh = make_webhook();
        assert!(wh.remove_dead_letter("nonexistent").is_none());
    }

    #[test]
    fn dlq_capacity_limit() {
        let wh =
            WhatsAppWebhook::new(TEST_SECRET, TEST_VERIFY_TOKEN.to_string()).with_dlq_capacity(3);
        for i in 0..5 {
            let event = WebhookEvent::new(format!("cap_{i}"), "message.text", "whatsapp");
            wh.dead_letter(event);
        }
        // FIFO eviction: oldest evicted first
        assert!(wh.dead_letter_count() <= 3);
    }

    // ─── Phone redaction tests ──────────────────────────────────────────────

    #[test]
    fn redact_standard_phone() {
        let redacted = WhatsAppWebhook::redact_phone("15551234567");
        // 11 digits: 2 prefix + 7 stars + 2 suffix
        assert_eq!(redacted, "15*******67");
        assert!(!redacted.contains("5512345"));
    }

    #[test]
    fn redact_short_phone() {
        let redacted = WhatsAppWebhook::redact_phone("12345");
        assert_eq!(redacted, "***");
    }

    #[test]
    fn redact_empty_phone() {
        let redacted = WhatsAppWebhook::redact_phone("");
        assert_eq!(redacted, "***");
    }

    #[test]
    fn redact_with_plus_prefix() {
        let redacted = WhatsAppWebhook::redact_phone("+15551234567");
        // + is stripped, 11 digits remain
        assert_eq!(redacted, "15*******67");
    }

    #[test]
    fn redact_with_dashes() {
        let redacted = WhatsAppWebhook::redact_phone("1-555-123-4567");
        // Dashes stripped, 11 digits remain
        assert_eq!(redacted, "15*******67");
    }

    #[test]
    fn redact_minimum_length() {
        // Exactly 6 digits: shows 2 prefix + 2 suffix + 2 stars
        let redacted = WhatsAppWebhook::redact_phone("123456");
        assert_eq!(redacted, "12**56");
    }

    // ─── Event payload structure tests ──────────────────────────────────────

    #[test]
    fn event_contains_metadata() {
        let wh = make_webhook();
        let body = serde_json::to_vec(&sample_text_notification()).unwrap();
        let sig = sign_payload(&body);
        let headers = HashMap::from([("x-hub-signature-256".to_string(), sig)]);

        let events = wh.verify_and_parse(&headers, &body).unwrap();
        let payload = &events[0].payload;
        assert_eq!(
            payload
                .get("metadata")
                .unwrap()
                .get("phone_number_id")
                .unwrap(),
            "PHONE_NUMBER_ID"
        );
        assert_eq!(
            payload.get("message").unwrap().get("from").unwrap(),
            "15559876543"
        );
    }

    #[test]
    fn event_has_taint_flags() {
        let wh = make_webhook();
        let body = serde_json::to_vec(&sample_text_notification()).unwrap();
        let sig = sign_payload(&body);
        let headers = HashMap::from([("x-hub-signature-256".to_string(), sig)]);

        let events = wh.verify_and_parse(&headers, &body).unwrap();
        // with_default_webhook_taint sets WebhookInjected + PublicInput
        assert!(!events[0].metadata.taint_flags.is_empty());
    }

    #[test]
    fn event_preserves_headers() {
        let wh = make_webhook();
        let body = serde_json::to_vec(&sample_text_notification()).unwrap();
        let sig = sign_payload(&body);
        let headers = HashMap::from([
            ("x-hub-signature-256".to_string(), sig),
            ("content-type".to_string(), "application/json".to_string()),
        ]);

        let events = wh.verify_and_parse(&headers, &body).unwrap();
        assert!(events[0].headers.contains_key("content-type"));
    }

    // ─── Message type routing tests ─────────────────────────────────────────

    #[test]
    fn location_message_event_type() {
        let wh = make_webhook();
        let body = serde_json::to_vec(&serde_json::json!({
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "BIZ_1",
                "changes": [{
                    "value": {
                        "messaging_product": "whatsapp",
                        "messages": [{
                            "from": "15551234567",
                            "id": "wamid.LOC1",
                            "timestamp": "1677000000",
                            "type": "location",
                            "location": { "longitude": -122.4, "latitude": 37.7, "name": "SF" }
                        }]
                    },
                    "field": "messages"
                }]
            }]
        }))
        .unwrap();
        let sig = sign_payload(&body);
        let headers = HashMap::from([("x-hub-signature-256".to_string(), sig)]);

        let events = wh.verify_and_parse(&headers, &body).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "message.location");
    }

    #[test]
    fn interactive_message_event_type() {
        let wh = make_webhook();
        let body = serde_json::to_vec(&serde_json::json!({
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "BIZ_1",
                "changes": [{
                    "value": {
                        "messaging_product": "whatsapp",
                        "messages": [{
                            "from": "15551234567",
                            "id": "wamid.INT1",
                            "timestamp": "1677000000",
                            "type": "interactive"
                        }]
                    },
                    "field": "messages"
                }]
            }]
        }))
        .unwrap();
        let sig = sign_payload(&body);
        let headers = HashMap::from([("x-hub-signature-256".to_string(), sig)]);

        let events = wh.verify_and_parse(&headers, &body).unwrap();
        assert_eq!(events[0].event_type, "message.interactive");
    }

    #[test]
    fn status_sent_event_type() {
        let wh = make_webhook();
        let body = serde_json::to_vec(&serde_json::json!({
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "BIZ_1",
                "changes": [{
                    "value": {
                        "messaging_product": "whatsapp",
                        "statuses": [{
                            "id": "wamid.S1",
                            "status": "sent",
                            "timestamp": "1677000000",
                            "recipient_id": "15551234567"
                        }]
                    },
                    "field": "messages"
                }]
            }]
        }))
        .unwrap();
        let sig = sign_payload(&body);
        let headers = HashMap::from([("x-hub-signature-256".to_string(), sig)]);

        let events = wh.verify_and_parse(&headers, &body).unwrap();
        assert_eq!(events[0].event_type, "status.sent");
    }

    #[test]
    fn status_failed_event_type() {
        let wh = make_webhook();
        let body = serde_json::to_vec(&serde_json::json!({
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "BIZ_1",
                "changes": [{
                    "value": {
                        "messaging_product": "whatsapp",
                        "statuses": [{
                            "id": "wamid.S2",
                            "status": "failed",
                            "timestamp": "1677000000",
                            "recipient_id": "15551234567"
                        }]
                    },
                    "field": "messages"
                }]
            }]
        }))
        .unwrap();
        let sig = sign_payload(&body);
        let headers = HashMap::from([("x-hub-signature-256".to_string(), sig)]);

        let events = wh.verify_and_parse(&headers, &body).unwrap();
        assert_eq!(events[0].event_type, "status.failed");
    }

    // ─── Multiple entries test ──────────────────────────────────────────────

    #[test]
    fn multiple_entries_all_parsed() {
        let wh = make_webhook();
        let body = serde_json::to_vec(&serde_json::json!({
            "object": "whatsapp_business_account",
            "entry": [
                {
                    "id": "ACCT_1",
                    "changes": [{
                        "value": {
                            "messaging_product": "whatsapp",
                            "messages": [{
                                "from": "15551111111",
                                "id": "wamid.E1",
                                "timestamp": "1677000000",
                                "type": "text",
                                "text": { "body": "One", "preview_url": false }
                            }]
                        },
                        "field": "messages"
                    }]
                },
                {
                    "id": "ACCT_2",
                    "changes": [{
                        "value": {
                            "messaging_product": "whatsapp",
                            "messages": [{
                                "from": "15552222222",
                                "id": "wamid.E2",
                                "timestamp": "1677000001",
                                "type": "text",
                                "text": { "body": "Two", "preview_url": false }
                            }]
                        },
                        "field": "messages"
                    }]
                }
            ]
        }))
        .unwrap();
        let sig = sign_payload(&body);
        let headers = HashMap::from([("x-hub-signature-256".to_string(), sig)]);

        let events = wh.verify_and_parse(&headers, &body).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].id, "wamid.E1");
        assert_eq!(events[1].id, "wamid.E2");
    }

    // ─── Deterministic ID fallback test ─────────────────────────────────────

    #[test]
    fn empty_message_id_gets_deterministic_fallback() {
        let wh = make_webhook();
        let body = serde_json::to_vec(&serde_json::json!({
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "BIZ_1",
                "changes": [{
                    "value": {
                        "messaging_product": "whatsapp",
                        "messages": [{
                            "from": "15551234567",
                            "id": "",
                            "timestamp": "1677000000",
                            "type": "text",
                            "text": { "body": "No ID", "preview_url": false }
                        }]
                    },
                    "field": "messages"
                }]
            }]
        }))
        .unwrap();
        let sig = sign_payload(&body);
        let headers = HashMap::from([("x-hub-signature-256".to_string(), sig)]);

        let events = wh.verify_and_parse(&headers, &body).unwrap();
        assert!(events[0].id.starts_with("whatsapp:"));
        assert_eq!(events[0].id.len(), 73); // "whatsapp:" + 64 hex chars
    }

    // ─── Constant-time comparison test ──────────────────────────────────────

    #[test]
    fn constant_time_eq_same() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_eq_different() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn constant_time_eq_different_length() {
        assert!(!constant_time_eq(b"short", b"longer_string"));
    }

    #[test]
    fn constant_time_eq_empty() {
        assert!(constant_time_eq(b"", b""));
    }

    // ─── Case-insensitive header handling ───────────────────────────────────

    #[test]
    fn uppercase_signature_header_works() {
        let wh = make_webhook();
        let body = serde_json::to_vec(&sample_text_notification()).unwrap();
        let sig = sign_payload(&body);
        let headers = HashMap::from([("X-HUB-SIGNATURE-256".to_string(), sig)]);

        let result = wh.verify_and_parse(&headers, &body);
        assert!(result.is_ok());
    }

    #[test]
    fn multiple_empty_message_ids_get_distinct_fallbacks() {
        let wh = make_webhook();
        let body = serde_json::to_vec(&serde_json::json!({
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "BIZ_1",
                "changes": [{
                    "value": {
                        "messaging_product": "whatsapp",
                        "messages": [
                            {
                                "from": "15551234567",
                                "id": "",
                                "timestamp": "1677000000",
                                "type": "text",
                                "text": { "body": "First", "preview_url": false }
                            },
                            {
                                "from": "15557654321",
                                "id": "",
                                "timestamp": "1677000001",
                                "type": "text",
                                "text": { "body": "Second", "preview_url": false }
                            }
                        ]
                    },
                    "field": "messages"
                }]
            }]
        }))
        .unwrap();
        let sig = sign_payload(&body);
        let headers = HashMap::from([("x-hub-signature-256".to_string(), sig)]);

        let events = wh.verify_and_parse(&headers, &body).unwrap();
        assert_eq!(events.len(), 2);
        assert!(events[0].id.starts_with("whatsapp:"));
        assert!(events[1].id.starts_with("whatsapp:"));
        assert_ne!(events[0].id, events[1].id);
    }

    #[test]
    fn multiple_empty_status_ids_get_distinct_fallbacks() {
        let wh = make_webhook();
        let body = serde_json::to_vec(&serde_json::json!({
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "BIZ_1",
                "changes": [{
                    "value": {
                        "messaging_product": "whatsapp",
                        "statuses": [
                            {
                                "id": "",
                                "status": "sent",
                                "timestamp": "1677000000",
                                "recipient_id": "15551234567"
                            },
                            {
                                "id": "",
                                "status": "delivered",
                                "timestamp": "1677000001",
                                "recipient_id": "15557654321"
                            }
                        ]
                    },
                    "field": "messages"
                }]
            }]
        }))
        .unwrap();
        let sig = sign_payload(&body);
        let headers = HashMap::from([("x-hub-signature-256".to_string(), sig)]);

        let events = wh.verify_and_parse(&headers, &body).unwrap();
        assert_eq!(events.len(), 2);
        assert!(events[0].id.starts_with("whatsapp:"));
        assert!(events[1].id.starts_with("whatsapp:"));
        assert_ne!(events[0].id, events[1].id);
    }
}
