//! `WhatsApp` Business API types.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Outbound message types
// ─────────────────────────────────────────────────────────────────────────────

/// Top-level send message request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageRequest {
    pub messaging_product: String,
    pub recipient_type: String,
    pub to: String,
    #[serde(flatten)]
    pub content: MessageContent,
}

/// Message content variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum MessageContent {
    #[serde(rename = "text")]
    Text { text: TextBody },
    #[serde(rename = "image")]
    Image { image: MediaBody },
    #[serde(rename = "document")]
    Document { document: MediaBody },
    #[serde(rename = "audio")]
    Audio { audio: MediaBody },
    #[serde(rename = "video")]
    Video { video: MediaBody },
    #[serde(rename = "location")]
    Location { location: LocationBody },
    #[serde(rename = "contacts")]
    Contacts { contacts: Vec<ContactBody> },
    #[serde(rename = "template")]
    Template { template: TemplateBody },
    #[serde(rename = "interactive")]
    Interactive { interactive: serde_json::Value },
}

/// Text message body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextBody {
    pub body: String,
    #[serde(default)]
    pub preview_url: bool,
}

/// Media message body (image, document, audio, video).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
}

/// Location message body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationBody {
    pub longitude: f64,
    pub latitude: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
}

/// Contact message body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactBody {
    pub name: ContactName,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub phones: Vec<ContactPhone>,
}

/// Contact name fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactName {
    pub formatted_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
}

/// Contact phone entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactPhone {
    pub phone: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
}

/// Template message body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateBody {
    pub name: String,
    pub language: TemplateLanguage,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<serde_json::Value>,
}

/// Template language specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateLanguage {
    pub code: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// API response types
// ─────────────────────────────────────────────────────────────────────────────

/// Response from sending a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageResponse {
    pub messaging_product: String,
    pub contacts: Vec<ContactRef>,
    pub messages: Vec<MessageRef>,
}

/// Contact reference in send response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactRef {
    pub input: String,
    pub wa_id: String,
}

/// Message reference in send response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageRef {
    pub id: String,
}

/// `WhatsApp` API error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    pub error: ApiErrorDetail,
}

/// Error detail from the `WhatsApp` API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorDetail {
    pub message: String,
    #[serde(rename = "type")]
    pub error_type: String,
    pub code: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_subcode: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fbtrace_id: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Webhook (inbound) types
// ─────────────────────────────────────────────────────────────────────────────

/// Webhook notification envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookNotification {
    pub object: String,
    pub entry: Vec<WebhookEntry>,
}

/// Single webhook entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEntry {
    pub id: String,
    pub changes: Vec<WebhookChange>,
}

/// Single change within an entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookChange {
    pub value: WebhookValue,
    pub field: String,
}

/// Webhook change value (message or status update).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookValue {
    pub messaging_product: String,
    #[serde(default)]
    pub messages: Vec<IncomingMessage>,
    #[serde(default)]
    pub statuses: Vec<MessageStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<WebhookMetadata>,
}

/// Webhook metadata (phone number info).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookMetadata {
    pub display_phone_number: String,
    pub phone_number_id: String,
}

/// Incoming message from a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncomingMessage {
    pub from: String,
    pub id: String,
    pub timestamp: String,
    #[serde(rename = "type")]
    pub message_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<TextBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<MediaBody>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<LocationBody>,
}

/// Message delivery/read status update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageStatus {
    pub id: String,
    pub status: String,
    pub timestamp: String,
    pub recipient_id: String,
}

/// Business profile response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileResponse {
    pub data: Vec<BusinessProfile>,
}

/// Business profile data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusinessProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vertical: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_message_serialization() {
        let msg = SendMessageRequest {
            messaging_product: "whatsapp".into(),
            recipient_type: "individual".into(),
            to: "15551234567".into(),
            content: MessageContent::Text {
                text: TextBody {
                    body: "Hello!".into(),
                    preview_url: false,
                },
            },
        };
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["to"], "15551234567");
        assert_eq!(json["type"], "text");
    }

    #[test]
    fn location_message_serialization() {
        let loc = LocationBody {
            longitude: -122.4194,
            latitude: 37.7749,
            name: Some("San Francisco".into()),
            address: None,
        };
        let json = serde_json::to_value(&loc).unwrap();
        assert!(json["longitude"].as_f64().unwrap() < -122.0);
    }

    #[test]
    fn api_error_deserialization() {
        let json = serde_json::json!({
            "error": {
                "message": "Invalid parameter",
                "type": "OAuthException",
                "code": 100,
                "error_subcode": 2_018_001,
                "fbtrace_id": "abc123"
            }
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.error.code, 100);
        assert_eq!(err.error.error_subcode, Some(2_018_001));
    }

    #[test]
    fn webhook_notification_deserialization() {
        let json = serde_json::json!({
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "123",
                "changes": [{
                    "value": {
                        "messaging_product": "whatsapp",
                        "messages": [{
                            "from": "15551234567",
                            "id": "wamid.abc",
                            "timestamp": "1234567890",
                            "type": "text",
                            "text": { "body": "Hello", "preview_url": false }
                        }],
                        "statuses": []
                    },
                    "field": "messages"
                }]
            }]
        });
        let notif: WebhookNotification = serde_json::from_value(json).unwrap();
        assert_eq!(notif.entry.len(), 1);
        assert_eq!(notif.entry[0].changes[0].value.messages.len(), 1);
    }

    #[test]
    fn send_response_deserialization() {
        let json = serde_json::json!({
            "messaging_product": "whatsapp",
            "contacts": [{"input": "15551234567", "wa_id": "15551234567"}],
            "messages": [{"id": "wamid.abc123"}]
        });
        let resp: SendMessageResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.messages[0].id, "wamid.abc123");
    }
}
