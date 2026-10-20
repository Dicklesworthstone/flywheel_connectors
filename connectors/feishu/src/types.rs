//! Feishu/Lark API types.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Auth types
// ─────────────────────────────────────────────────────────────────────────────

/// Tenant access token request.
#[derive(Clone, Serialize)]
pub struct TenantAccessTokenRequest {
    pub app_id: String,
    pub app_secret: String,
}

impl std::fmt::Debug for TenantAccessTokenRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantAccessTokenRequest")
            .field("app_id", &self.app_id)
            .field("app_secret", &"[REDACTED]")
            .finish()
    }
}

/// Tenant access token response.
#[derive(Clone, Deserialize)]
pub struct TenantAccessTokenResponse {
    pub code: i32,
    pub msg: String,
    pub tenant_access_token: Option<String>,
    pub expire: Option<i64>,
}

impl std::fmt::Debug for TenantAccessTokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TenantAccessTokenResponse")
            .field("code", &self.code)
            .field("msg", &self.msg)
            .field(
                "tenant_access_token",
                &self.tenant_access_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expire", &self.expire)
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Message types
// ─────────────────────────────────────────────────────────────────────────────

/// Send message request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendMessageRequest {
    pub receive_id: String,
    pub msg_type: String,
    pub content: String,
}

/// Message response from Feishu.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageResponse {
    pub message_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msg_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<MessageBody>,
}

/// Message body content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageBody {
    pub content: String,
}

/// Reply message request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplyMessageRequest {
    pub msg_type: String,
    pub content: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Chat types
// ─────────────────────────────────────────────────────────────────────────────

/// Chat info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatInfo {
    pub chat_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chat_type: Option<String>,
}

/// Chat list response items.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatListItem {
    pub chat_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
}

/// Paginated chat list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatListResponse {
    pub items: Vec<ChatListItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
    pub has_more: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// User types
// ─────────────────────────────────────────────────────────────────────────────

/// User info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub en_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mobile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<AvatarInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<UserStatus>,
}

/// Avatar info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvatarInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_72: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_240: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_640: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_origin: Option<String>,
}

/// User status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserStatus {
    #[serde(default)]
    pub is_frozen: bool,
    #[serde(default)]
    pub is_resigned: bool,
    #[serde(default)]
    pub is_activated: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Document types
// ─────────────────────────────────────────────────────────────────────────────

/// Document info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revision_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

/// Document content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocumentContent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document: Option<DocumentInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Spreadsheet types
// ─────────────────────────────────────────────────────────────────────────────

/// Spreadsheet info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpreadsheetInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spreadsheet_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default)]
    pub sheets: Vec<SheetInfo>,
}

/// Sheet info within a spreadsheet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SheetInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sheet_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<i32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Calendar types
// ─────────────────────────────────────────────────────────────────────────────

/// Calendar event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalendarEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<EventTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_time: Option<EventTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

/// Event time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventTime {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
}

/// Calendar events list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalendarEventsResponse {
    pub items: Vec<CalendarEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
    pub has_more: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Drive comment types
// ─────────────────────────────────────────────────────────────────────────────

/// Feishu Drive document metadata returned by batch query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveDocumentMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Feishu Drive metadata batch query response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveMetaBatchQueryResponse {
    #[serde(default)]
    pub metas: Vec<DriveDocumentMeta>,
}

/// A reply inside a Feishu Drive comment thread.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveCommentReply {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<serde_json::Value>,
}

/// Inline reply list embedded in a Feishu Drive comment card.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DriveCommentReplyList {
    #[serde(default)]
    pub replies: Vec<DriveCommentReply>,
}

/// A Feishu Drive comment card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveCommentCard {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_solved: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_whole: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_more: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply_list: Option<DriveCommentReplyList>,
}

/// Feishu Drive comment batch-query response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveCommentBatchQueryResponse {
    #[serde(default)]
    pub items: Vec<DriveCommentCard>,
}

/// Paginated Feishu Drive comment replies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriveCommentRepliesResponse {
    #[serde(default)]
    pub items: Vec<DriveCommentReply>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub page_token: Option<String>,
    #[serde(default)]
    pub has_more: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// Common API response wrapper
// ─────────────────────────────────────────────────────────────────────────────

/// Standard Feishu API response envelope.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiResponse<T> {
    pub code: i32,
    pub msg: String,
    pub data: Option<T>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_message_request_serialization() {
        let req = SendMessageRequest {
            receive_id: "ou_abc123".into(),
            msg_type: "text".into(),
            content: r#"{"text":"Hello"}"#.into(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["receive_id"], "ou_abc123");
        assert_eq!(json["msg_type"], "text");
    }

    #[test]
    fn message_response_deserialization() {
        let json = serde_json::json!({
            "message_id": "om_abc123",
            "root_id": "om_root",
            "msg_type": "text",
            "create_time": "1672531200",
            "chat_id": "oc_123"
        });
        let resp: MessageResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.message_id, "om_abc123");
        assert_eq!(resp.chat_id, Some("oc_123".into()));
    }

    #[test]
    fn chat_list_response_deserialization() {
        let json = serde_json::json!({
            "items": [
                { "chat_id": "oc_1", "name": "Chat 1" },
                { "chat_id": "oc_2", "name": "Chat 2" }
            ],
            "page_token": "next_page",
            "has_more": true
        });
        let resp: ChatListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.items.len(), 2);
        assert!(resp.has_more);
    }

    #[test]
    fn user_info_deserialization() {
        let json = serde_json::json!({
            "user_id": "uid_123",
            "open_id": "ou_abc",
            "name": "Test User",
            "email": "test@example.com",
            "status": { "is_frozen": false, "is_resigned": false, "is_activated": true }
        });
        let user: UserInfo = serde_json::from_value(json).unwrap();
        assert_eq!(user.name, Some("Test User".into()));
        assert!(user.status.unwrap().is_activated);
    }

    #[test]
    fn document_content_deserialization() {
        let json = serde_json::json!({
            "document": {
                "document_id": "doc_123",
                "revision_id": 5,
                "title": "Test Doc"
            },
            "body": { "blocks": [] }
        });
        let doc: DocumentContent = serde_json::from_value(json).unwrap();
        assert_eq!(
            doc.document.as_ref().unwrap().title,
            Some("Test Doc".into())
        );
    }

    #[test]
    fn spreadsheet_info_deserialization() {
        let json = serde_json::json!({
            "spreadsheet_token": "shtk_123",
            "title": "Test Sheet",
            "sheets": [
                { "sheet_id": "s1", "title": "Sheet1", "index": 0 }
            ]
        });
        let sheet: SpreadsheetInfo = serde_json::from_value(json).unwrap();
        assert_eq!(sheet.sheets.len(), 1);
    }

    #[test]
    fn calendar_event_deserialization() {
        let json = serde_json::json!({
            "event_id": "evt_123",
            "summary": "Meeting",
            "start_time": { "timestamp": "1672531200", "timezone": "Asia/Shanghai" },
            "end_time": { "timestamp": "1672534800", "timezone": "Asia/Shanghai" },
            "status": "confirmed"
        });
        let event: CalendarEvent = serde_json::from_value(json).unwrap();
        assert_eq!(event.summary, Some("Meeting".into()));
    }

    #[test]
    fn api_response_deserialization() {
        let json = serde_json::json!({
            "code": 0,
            "msg": "success",
            "data": { "message_id": "om_abc" }
        });
        let resp: ApiResponse<MessageResponse> = serde_json::from_value(json).unwrap();
        assert_eq!(resp.code, 0);
        assert!(resp.data.is_some());
    }

    #[test]
    fn api_response_error() {
        let json = serde_json::json!({
            "code": 99_991_663,
            "msg": "tenant access token is expired"
        });
        let resp: ApiResponse<serde_json::Value> = serde_json::from_value(json).unwrap();
        assert_ne!(resp.code, 0);
        assert!(resp.data.is_none());
    }

    #[test]
    fn tenant_access_token_response() {
        let json = serde_json::json!({
            "code": 0,
            "msg": "ok",
            "tenant_access_token": "t-abc123",
            "expire": 7200
        });
        let resp: TenantAccessTokenResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.tenant_access_token, Some("t-abc123".into()));
    }

    #[test]
    fn chat_info_deserialization() {
        let json = serde_json::json!({
            "chat_id": "oc_123",
            "name": "Team Chat",
            "chat_mode": "group",
            "chat_type": "private"
        });
        let chat: ChatInfo = serde_json::from_value(json).unwrap();
        assert_eq!(chat.name, Some("Team Chat".into()));
    }

    #[test]
    fn calendar_events_response() {
        let json = serde_json::json!({
            "items": [
                { "event_id": "e1", "summary": "Meeting 1" },
                { "event_id": "e2", "summary": "Meeting 2" }
            ],
            "has_more": false
        });
        let resp: CalendarEventsResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.items.len(), 2);
        assert!(!resp.has_more);
    }

    #[test]
    fn user_info_minimal() {
        let json = serde_json::json!({});
        let user: UserInfo = serde_json::from_value(json).unwrap();
        assert!(user.user_id.is_none());
        assert!(user.name.is_none());
    }

    #[test]
    fn reply_message_request_serialization() {
        let req = ReplyMessageRequest {
            msg_type: "text".into(),
            content: r#"{"text":"Reply"}"#.into(),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["msg_type"], "text");
    }
}
