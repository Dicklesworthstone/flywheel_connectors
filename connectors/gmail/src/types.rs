//! Gmail API types.

use serde::{Deserialize, Serialize};

/// Gmail message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GmailMessage {
    pub id: String,
    #[serde(default)]
    pub thread_id: Option<String>,
    #[serde(default)]
    pub label_ids: Vec<String>,
    #[serde(default)]
    pub snippet: String,
    #[serde(default)]
    pub history_id: Option<String>,
    #[serde(default)]
    pub internal_date: Option<String>,
    #[serde(default)]
    pub size_estimate: u64,
    #[serde(default)]
    pub payload: Option<MessagePart>,
}

/// Gmail message part (MIME structure).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagePart {
    #[serde(default)]
    pub part_id: String,
    #[serde(default)]
    pub mime_type: String,
    #[serde(default)]
    pub filename: String,
    #[serde(default)]
    pub headers: Vec<Header>,
    #[serde(default)]
    pub body: Option<MessagePartBody>,
    #[serde(default)]
    pub parts: Option<Vec<Self>>,
}

/// Gmail message part body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagePartBody {
    #[serde(default)]
    pub attachment_id: Option<String>,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub data: Option<String>,
}

/// Retrieved attachment bytes, encoded with Gmail's URL-safe base64 alphabet.
/// Both fields are required; an absent body must not become a fabricated empty file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmailAttachment {
    pub size: u64,
    pub data: String,
}

/// Gmail header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// Gmail thread.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GmailThread {
    pub id: String,
    #[serde(default)]
    pub history_id: Option<String>,
    #[serde(default)]
    pub messages: Vec<GmailMessage>,
    #[serde(default)]
    pub snippet: String,
}

/// Gmail label.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GmailLabel {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub message_list_visibility: Option<String>,
    #[serde(default)]
    pub label_list_visibility: Option<String>,
    #[serde(default, rename = "type")]
    pub label_type: Option<String>,
    #[serde(default)]
    pub messages_total: u32,
    #[serde(default)]
    pub messages_unread: u32,
    #[serde(default)]
    pub threads_total: u32,
    #[serde(default)]
    pub threads_unread: u32,
}

/// Gmail draft.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GmailDraft {
    pub id: String,
    #[serde(default)]
    pub message: Option<GmailMessage>,
}

/// Messages list response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessagesListResponse {
    #[serde(default)]
    pub messages: Vec<MessageRef>,
    #[serde(default)]
    pub next_page_token: Option<String>,
    #[serde(default)]
    pub result_size_estimate: u32,
}

/// Minimal message reference (from list endpoints).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageRef {
    pub id: String,
    #[serde(default)]
    pub thread_id: Option<String>,
}

/// Labels list response.
#[derive(Debug, Clone, Deserialize)]
pub struct LabelsListResponse {
    #[serde(default)]
    pub labels: Vec<GmailLabel>,
}

/// Threads list response.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadsListResponse {
    #[serde(default)]
    pub threads: Vec<ThreadRef>,
    #[serde(default)]
    pub next_page_token: Option<String>,
    #[serde(default)]
    pub result_size_estimate: u32,
}

/// Minimal thread reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ThreadRef {
    pub id: String,
    #[serde(default)]
    pub snippet: String,
    #[serde(default)]
    pub history_id: Option<String>,
}

/// History list response for incremental sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryListResponse {
    #[serde(default)]
    pub history: Vec<serde_json::Value>,
    #[serde(default)]
    pub next_page_token: Option<String>,
    #[serde(default)]
    pub history_id: Option<String>,
}

/// Gmail API error response.
#[derive(Debug, Clone, Deserialize)]
pub struct GmailApiError {
    pub error: GmailErrorDetail,
}

/// Gmail API error detail.
#[derive(Debug, Clone, Deserialize)]
pub struct GmailErrorDetail {
    pub code: u32,
    pub message: String,
    #[serde(default)]
    pub errors: Vec<GmailErrorItem>,
}

/// Individual error item.
#[derive(Debug, Clone, Deserialize)]
pub struct GmailErrorItem {
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- GmailMessage serde ----

    #[test]
    fn gmail_message_serde_roundtrip() {
        let msg = GmailMessage {
            id: "msg-1".into(),
            thread_id: Some("thread-1".into()),
            label_ids: vec!["INBOX".into(), "UNREAD".into()],
            snippet: "Hello world".into(),
            history_id: Some("12345".into()),
            internal_date: Some("1709294400000".into()),
            size_estimate: 2048,
            payload: Some(MessagePart {
                part_id: "0".into(),
                mime_type: "text/plain".into(),
                filename: String::new(),
                headers: vec![Header {
                    name: "Subject".into(),
                    value: "Test Subject".into(),
                }],
                body: Some(MessagePartBody {
                    attachment_id: None,
                    size: 100,
                    data: Some("SGVsbG8=".into()),
                }),
                parts: None,
            }),
        };
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["id"], "msg-1");
        assert_eq!(json["threadId"], "thread-1");
        assert_eq!(json["sizeEstimate"], 2048);

        let back: GmailMessage = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, "msg-1");
        assert_eq!(back.thread_id.as_deref(), Some("thread-1"));
        assert_eq!(back.label_ids.len(), 2);
    }

    #[test]
    fn gmail_message_minimal_deserializes() {
        let json = serde_json::json!({"id": "msg-2"});
        let msg: GmailMessage = serde_json::from_value(json).unwrap();
        assert_eq!(msg.id, "msg-2");
        assert!(msg.thread_id.is_none());
        assert!(msg.label_ids.is_empty());
        assert!(msg.snippet.is_empty());
        assert!(msg.payload.is_none());
        assert_eq!(msg.size_estimate, 0);
    }

    // ---- MessagePart serde ----

    #[test]
    fn message_part_with_nested_parts() {
        let part = MessagePart {
            part_id: "0".into(),
            mime_type: "multipart/alternative".into(),
            filename: String::new(),
            headers: vec![],
            body: None,
            parts: Some(vec![
                MessagePart {
                    part_id: "0.1".into(),
                    mime_type: "text/plain".into(),
                    filename: String::new(),
                    headers: vec![],
                    body: Some(MessagePartBody {
                        attachment_id: None,
                        size: 50,
                        data: Some("dGV4dA==".into()),
                    }),
                    parts: None,
                },
                MessagePart {
                    part_id: "0.2".into(),
                    mime_type: "text/html".into(),
                    filename: String::new(),
                    headers: vec![],
                    body: Some(MessagePartBody {
                        attachment_id: None,
                        size: 100,
                        data: Some("PGh0bWw+".into()),
                    }),
                    parts: None,
                },
            ]),
        };
        let json = serde_json::to_value(&part).unwrap();
        assert_eq!(json["mimeType"], "multipart/alternative");
        let nested = json["parts"].as_array().unwrap();
        assert_eq!(nested.len(), 2);
        assert_eq!(nested[0]["mimeType"], "text/plain");
    }

    // ---- MessagePartBody serde ----

    #[test]
    fn message_part_body_with_attachment() {
        let body = MessagePartBody {
            attachment_id: Some("att-1".into()),
            size: 5000,
            data: None,
        };
        let json = serde_json::to_value(&body).unwrap();
        assert_eq!(json["attachmentId"], "att-1");
        assert_eq!(json["size"], 5000);
        assert!(json["data"].is_null());
    }

    #[test]
    fn message_part_body_minimal_deserializes() {
        let json = serde_json::json!({});
        let body: MessagePartBody = serde_json::from_value(json).unwrap();
        assert!(body.attachment_id.is_none());
        assert_eq!(body.size, 0);
        assert!(body.data.is_none());
    }

    // ---- Header serde ----

    #[test]
    fn header_serde_roundtrip() {
        let header = Header {
            name: "From".into(),
            value: "user@example.com".into(),
        };
        let json = serde_json::to_value(&header).unwrap();
        assert_eq!(json["name"], "From");
        let back: Header = serde_json::from_value(json).unwrap();
        assert_eq!(back.value, "user@example.com");
    }

    // ---- GmailThread serde ----

    #[test]
    fn gmail_thread_serde_roundtrip() {
        let thread = GmailThread {
            id: "thread-1".into(),
            history_id: Some("999".into()),
            messages: vec![GmailMessage {
                id: "msg-in-thread".into(),
                thread_id: Some("thread-1".into()),
                label_ids: vec![],
                snippet: "Thread message".into(),
                history_id: None,
                internal_date: None,
                size_estimate: 0,
                payload: None,
            }],
            snippet: "Thread snippet".into(),
        };
        let json = serde_json::to_value(&thread).unwrap();
        assert_eq!(json["id"], "thread-1");
        assert_eq!(json["historyId"], "999");
        assert_eq!(json["messages"].as_array().unwrap().len(), 1);

        let back: GmailThread = serde_json::from_value(json).unwrap();
        assert_eq!(back.messages.len(), 1);
        assert_eq!(back.snippet, "Thread snippet");
    }

    #[test]
    fn gmail_thread_minimal_deserializes() {
        let json = serde_json::json!({"id": "t-2"});
        let thread: GmailThread = serde_json::from_value(json).unwrap();
        assert_eq!(thread.id, "t-2");
        assert!(thread.messages.is_empty());
        assert!(thread.snippet.is_empty());
    }

    // ---- GmailLabel serde ----

    #[test]
    fn gmail_label_serde_roundtrip() {
        let label = GmailLabel {
            id: "Label_1".into(),
            name: "Work".into(),
            message_list_visibility: Some("show".into()),
            label_list_visibility: Some("labelShow".into()),
            label_type: Some("user".into()),
            messages_total: 42,
            messages_unread: 5,
            threads_total: 30,
            threads_unread: 3,
        };
        let json = serde_json::to_value(&label).unwrap();
        assert_eq!(json["id"], "Label_1");
        assert_eq!(json["name"], "Work");
        assert_eq!(json["messageListVisibility"], "show");
        assert_eq!(json["type"], "user");
        assert_eq!(json["messagesTotal"], 42);
        assert_eq!(json["threadsUnread"], 3);

        let back: GmailLabel = serde_json::from_value(json).unwrap();
        assert_eq!(back.messages_unread, 5);
    }

    #[test]
    fn gmail_label_minimal_deserializes() {
        let json = serde_json::json!({"id": "INBOX", "name": "INBOX"});
        let label: GmailLabel = serde_json::from_value(json).unwrap();
        assert_eq!(label.id, "INBOX");
        assert_eq!(label.messages_total, 0);
        assert!(label.label_type.is_none());
    }

    // ---- GmailDraft serde ----

    #[test]
    fn gmail_draft_serde_roundtrip() {
        let draft = GmailDraft {
            id: "draft-1".into(),
            message: Some(GmailMessage {
                id: "msg-draft".into(),
                thread_id: None,
                label_ids: vec!["DRAFT".into()],
                snippet: "Draft content".into(),
                history_id: None,
                internal_date: None,
                size_estimate: 0,
                payload: None,
            }),
        };
        let json = serde_json::to_value(&draft).unwrap();
        assert_eq!(json["id"], "draft-1");
        assert!(json["message"].is_object());

        let back: GmailDraft = serde_json::from_value(json).unwrap();
        assert!(back.message.is_some());
    }

    #[test]
    fn gmail_draft_without_message() {
        let json = serde_json::json!({"id": "draft-2"});
        let draft: GmailDraft = serde_json::from_value(json).unwrap();
        assert_eq!(draft.id, "draft-2");
        assert!(draft.message.is_none());
    }

    // ---- MessagesListResponse serde ----

    #[test]
    fn messages_list_response_with_pagination() {
        let json = serde_json::json!({
            "messages": [
                {"id": "m1", "threadId": "t1"},
                {"id": "m2"}
            ],
            "nextPageToken": "token-abc",
            "resultSizeEstimate": 100
        });
        let resp: MessagesListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.messages.len(), 2);
        assert_eq!(resp.next_page_token.as_deref(), Some("token-abc"));
        assert_eq!(resp.result_size_estimate, 100);
    }

    #[test]
    fn messages_list_response_empty() {
        let json = serde_json::json!({});
        let resp: MessagesListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.messages.is_empty());
        assert!(resp.next_page_token.is_none());
        assert_eq!(resp.result_size_estimate, 0);
    }

    // ---- MessageRef serde ----

    #[test]
    fn message_ref_serde_roundtrip() {
        let msg_ref = MessageRef {
            id: "m1".into(),
            thread_id: Some("t1".into()),
        };
        let json = serde_json::to_value(&msg_ref).unwrap();
        assert_eq!(json["id"], "m1");
        assert_eq!(json["threadId"], "t1");

        let back: MessageRef = serde_json::from_value(json).unwrap();
        assert_eq!(back.thread_id.as_deref(), Some("t1"));
    }

    // ---- LabelsListResponse serde ----

    #[test]
    fn labels_list_response_deserializes() {
        let json = serde_json::json!({
            "labels": [
                {"id": "INBOX", "name": "INBOX"},
                {"id": "SENT", "name": "SENT"}
            ]
        });
        let resp: LabelsListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.labels.len(), 2);
    }

    #[test]
    fn labels_list_response_empty() {
        let json = serde_json::json!({});
        let resp: LabelsListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.labels.is_empty());
    }

    // ---- ThreadsListResponse serde ----

    #[test]
    fn threads_list_response_with_pagination() {
        let json = serde_json::json!({
            "threads": [
                {"id": "t1", "snippet": "Hello"},
                {"id": "t2"}
            ],
            "nextPageToken": "next-token",
            "resultSizeEstimate": 50
        });
        let resp: ThreadsListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.threads.len(), 2);
        assert_eq!(resp.next_page_token.as_deref(), Some("next-token"));
        assert_eq!(resp.result_size_estimate, 50);
    }

    // ---- ThreadRef serde ----

    #[test]
    fn thread_ref_serde_roundtrip() {
        let tref = ThreadRef {
            id: "t1".into(),
            snippet: "Thread preview".into(),
            history_id: Some("500".into()),
        };
        let json = serde_json::to_value(&tref).unwrap();
        assert_eq!(json["id"], "t1");
        assert_eq!(json["historyId"], "500");

        let back: ThreadRef = serde_json::from_value(json).unwrap();
        assert_eq!(back.snippet, "Thread preview");
    }

    // ---- HistoryListResponse serde ----

    #[test]
    fn history_list_response_roundtrip() {
        let resp = HistoryListResponse {
            history: vec![serde_json::json!({"id": "101"})],
            next_page_token: Some("page2".into()),
            history_id: Some("101".into()),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["historyId"], "101");
        assert_eq!(json["nextPageToken"], "page2");
        assert_eq!(json["history"].as_array().unwrap().len(), 1);

        let back: HistoryListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(back.history.len(), 1);
    }

    #[test]
    fn history_list_response_empty() {
        let json = serde_json::json!({});
        let resp: HistoryListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.history.is_empty());
        assert!(resp.next_page_token.is_none());
        assert!(resp.history_id.is_none());
    }

    // ---- GmailApiError serde ----

    #[test]
    fn gmail_api_error_deserializes() {
        let json = serde_json::json!({
            "error": {
                "code": 404,
                "message": "Requested entity was not found.",
                "errors": [
                    {
                        "domain": "global",
                        "reason": "notFound",
                        "message": "Requested entity was not found."
                    }
                ]
            }
        });
        let err: GmailApiError = serde_json::from_value(json).unwrap();
        assert_eq!(err.error.code, 404);
        assert!(err.error.message.contains("not found"));
        assert_eq!(err.error.errors.len(), 1);
        assert_eq!(err.error.errors[0].reason, "notFound");
    }

    #[test]
    fn gmail_api_error_without_error_items() {
        let json = serde_json::json!({
            "error": {
                "code": 500,
                "message": "Backend Error"
            }
        });
        let err: GmailApiError = serde_json::from_value(json).unwrap();
        assert_eq!(err.error.code, 500);
        assert!(err.error.errors.is_empty());
    }

    // ---- GmailErrorItem serde ----

    #[test]
    fn gmail_error_item_defaults() {
        let json = serde_json::json!({});
        let item: GmailErrorItem = serde_json::from_value(json).unwrap();
        assert!(item.domain.is_empty());
        assert!(item.reason.is_empty());
        assert!(item.message.is_empty());
    }

    // ── Additional GmailMessage coverage ────────────────────────────

    #[test]
    fn gmail_message_clone_preserves_fields() {
        let msg = GmailMessage {
            id: "msg-c".into(),
            thread_id: Some("t-c".into()),
            label_ids: vec!["INBOX".into()],
            snippet: "cloneable".into(),
            history_id: Some("999".into()),
            internal_date: Some("1709000000".into()),
            size_estimate: 4096,
            payload: None,
        };
        let cloned = msg.clone();
        assert_eq!(msg.id, "msg-c");
        assert_eq!(cloned.snippet, "cloneable");
        assert_eq!(cloned.size_estimate, 4096);
        assert_eq!(cloned.history_id.as_deref(), Some("999"));
    }

    #[test]
    fn gmail_message_debug_format() {
        let msg = GmailMessage {
            id: "msg-d".into(),
            thread_id: None,
            label_ids: vec![],
            snippet: "debug test".into(),
            history_id: None,
            internal_date: None,
            size_estimate: 0,
            payload: None,
        };
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("GmailMessage"));
        assert!(dbg.contains("debug test"));
    }

    #[test]
    fn gmail_message_with_multiple_labels() {
        let json = serde_json::json!({
            "id": "msg-labels",
            "labelIds": ["INBOX", "UNREAD", "STARRED", "IMPORTANT"]
        });
        let msg: GmailMessage = serde_json::from_value(json).unwrap();
        assert_eq!(msg.label_ids.len(), 4);
        assert!(msg.label_ids.contains(&"STARRED".to_string()));
    }

    // ── MessagePart additional coverage ─────────────────────────────

    #[test]
    fn message_part_clone_debug() {
        let part = MessagePart {
            part_id: "0".into(),
            mime_type: "text/plain".into(),
            filename: String::new(),
            headers: vec![Header {
                name: "Subject".into(),
                value: "Test".into(),
            }],
            body: None,
            parts: None,
        };
        let cloned = part.clone();
        assert_eq!(part.mime_type, "text/plain");
        assert_eq!(cloned.headers.len(), 1);
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("MessagePart"));
    }

    #[test]
    fn message_part_body_clone_debug() {
        let body = MessagePartBody {
            attachment_id: Some("att-clone".into()),
            size: 2048,
            data: Some("data123".into()),
        };
        let cloned = body.clone();
        assert_eq!(body.attachment_id.as_deref(), Some("att-clone"));
        assert_eq!(cloned.size, 2048);
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("MessagePartBody"));
    }

    // ── Header additional coverage ──────────────────────────────────

    #[test]
    fn header_clone_debug() {
        let h = Header {
            name: "To".into(),
            value: "bob@example.com".into(),
        };
        let cloned = h.clone();
        assert_eq!(h.name, "To");
        assert_eq!(cloned.value, "bob@example.com");
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("Header"));
    }

    // ── GmailThread additional coverage ─────────────────────────────

    #[test]
    fn gmail_thread_clone_debug() {
        let thread = GmailThread {
            id: "t-clone".into(),
            history_id: None,
            messages: vec![],
            snippet: "thread snip".into(),
        };
        let cloned = thread.clone();
        assert_eq!(thread.id, "t-clone");
        assert_eq!(cloned.snippet, "thread snip");
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("GmailThread"));
    }

    // ── GmailLabel additional coverage ──────────────────────────────

    #[test]
    fn gmail_label_clone_debug() {
        let label = GmailLabel {
            id: "Label_clone".into(),
            name: "CloneTest".into(),
            message_list_visibility: None,
            label_list_visibility: None,
            label_type: None,
            messages_total: 10,
            messages_unread: 2,
            threads_total: 8,
            threads_unread: 1,
        };
        let cloned = label.clone();
        assert_eq!(label.name, "CloneTest");
        assert_eq!(cloned.messages_total, 10);
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("GmailLabel"));
    }

    // ── GmailDraft additional coverage ──────────────────────────────

    #[test]
    fn gmail_draft_clone_debug() {
        let draft = GmailDraft {
            id: "draft-clone".into(),
            message: None,
        };
        let cloned = draft.clone();
        assert_eq!(draft.id, "draft-clone");
        assert!(cloned.message.is_none());
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("GmailDraft"));
    }

    // ── MessagesListResponse additional coverage ────────────────────

    #[test]
    fn messages_list_response_clone_debug() {
        let resp: MessagesListResponse = serde_json::from_value(serde_json::json!({
            "messages": [{"id": "m1"}],
            "resultSizeEstimate": 1
        }))
        .unwrap();
        let cloned = resp.clone();
        assert_eq!(resp.messages.len(), 1);
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("MessagesListResponse"));
    }

    // ── MessageRef additional coverage ───────────────────────────────

    #[test]
    fn message_ref_clone_debug() {
        let mref = MessageRef {
            id: "mref-1".into(),
            thread_id: None,
        };
        let cloned = mref.clone();
        assert_eq!(mref.id, "mref-1");
        assert!(cloned.thread_id.is_none());
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("MessageRef"));
    }

    #[test]
    fn message_ref_without_thread() {
        let json = serde_json::json!({"id": "m-no-thread"});
        let mref: MessageRef = serde_json::from_value(json).unwrap();
        assert_eq!(mref.id, "m-no-thread");
        assert!(mref.thread_id.is_none());
    }

    // ── ThreadRef additional coverage ───────────────────────────────

    #[test]
    fn thread_ref_clone_debug() {
        let tref = ThreadRef {
            id: "t-clone".into(),
            snippet: "snip".into(),
            history_id: Some("500".into()),
        };
        let cloned = tref.clone();
        assert_eq!(tref.id, "t-clone");
        assert_eq!(cloned.snippet, "snip");
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("ThreadRef"));
    }

    #[test]
    fn thread_ref_minimal() {
        let json = serde_json::json!({"id": "t-min"});
        let tref: ThreadRef = serde_json::from_value(json).unwrap();
        assert_eq!(tref.id, "t-min");
        assert!(tref.snippet.is_empty());
        assert!(tref.history_id.is_none());
    }

    // ── GmailApiError additional coverage ───────────────────────────

    #[test]
    fn gmail_api_error_clone_debug() {
        let json = serde_json::json!({
            "error": {
                "code": 429,
                "message": "Rate Limit Exceeded"
            }
        });
        let err: GmailApiError = serde_json::from_value(json).unwrap();
        let cloned = err.clone();
        assert_eq!(err.error.code, 429);
        let dbg = format!("{cloned:?}");
        assert!(dbg.contains("GmailApiError"));
    }

    // ── GmailErrorDetail additional coverage ────────────────────────

    #[test]
    fn gmail_error_detail_clone_debug() {
        let detail = GmailErrorDetail {
            code: 403,
            message: "Insufficient Permission".into(),
            errors: vec![],
        };
        let cloned = detail.clone();
        assert_eq!(cloned.code, 403);
        assert_eq!(cloned.message, "Insufficient Permission");
        let dbg = format!("{detail:?}");
        assert!(dbg.contains("GmailErrorDetail"));
    }

    // ── GmailErrorItem additional coverage ──────────────────────────

    #[test]
    fn gmail_error_item_clone_debug() {
        let item = GmailErrorItem {
            domain: "global".into(),
            reason: "notFound".into(),
            message: "Not Found".into(),
        };
        let cloned = item.clone();
        assert_eq!(cloned.domain, "global");
        let dbg = format!("{item:?}");
        assert!(dbg.contains("GmailErrorItem"));
    }

    #[test]
    fn gmail_error_item_populated() {
        let json = serde_json::json!({
            "domain": "usageLimits",
            "reason": "rateLimitExceeded",
            "message": "Rate Limit Exceeded"
        });
        let item: GmailErrorItem = serde_json::from_value(json).unwrap();
        assert_eq!(item.domain, "usageLimits");
        assert_eq!(item.reason, "rateLimitExceeded");
    }
}
