//! Mastodon API types.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Account types
// ─────────────────────────────────────────────────────────────────────────────

/// A Mastodon account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: String,
    pub username: String,
    pub acct: String,
    pub display_name: String,
    #[serde(default)]
    pub note: String,
    pub url: String,
    pub avatar: String,
    pub header: String,
    pub followers_count: u64,
    pub following_count: u64,
    pub statuses_count: u64,
    #[serde(default)]
    pub locked: bool,
    #[serde(default)]
    pub bot: bool,
    pub created_at: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Status types
// ─────────────────────────────────────────────────────────────────────────────

/// A Mastodon status (toot).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub id: String,
    pub uri: String,
    pub url: Option<String>,
    pub content: String,
    pub created_at: String,
    pub account: Account,
    #[serde(default)]
    pub reblogs_count: u64,
    #[serde(default)]
    pub favourites_count: u64,
    #[serde(default)]
    pub replies_count: u64,
    pub visibility: String,
    #[serde(default)]
    pub sensitive: bool,
    pub spoiler_text: String,
    #[serde(default)]
    pub media_attachments: Vec<MediaAttachment>,
    #[serde(default)]
    pub reblog: Option<Box<Self>>,
    #[serde(default)]
    pub favourited: Option<bool>,
    #[serde(default)]
    pub reblogged: Option<bool>,
    pub application: Option<Application>,
    pub in_reply_to_id: Option<String>,
    pub in_reply_to_account_id: Option<String>,
}

/// Media attachment on a status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaAttachment {
    pub id: String,
    #[serde(rename = "type")]
    pub media_type: String,
    pub url: String,
    pub preview_url: Option<String>,
    pub description: Option<String>,
}

/// Application that posted a status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Application {
    pub name: String,
    pub website: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Notification types
// ─────────────────────────────────────────────────────────────────────────────

/// A Mastodon notification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    #[serde(rename = "type")]
    pub notification_type: String,
    pub created_at: String,
    pub account: Account,
    pub status: Option<Status>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Search types
// ─────────────────────────────────────────────────────────────────────────────

/// Search results from Mastodon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResults {
    pub accounts: Vec<Account>,
    pub statuses: Vec<Status>,
    pub hashtags: Vec<Tag>,
}

/// A Mastodon hashtag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tag {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub history: Vec<TagHistory>,
}

/// Daily usage history for a tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagHistory {
    pub day: String,
    pub uses: String,
    pub accounts: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// API error types
// ─────────────────────────────────────────────────────────────────────────────

/// Mastodon API error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
    #[serde(default)]
    pub error_description: Option<String>,
}

/// Instance info (used for health check).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instance {
    pub uri: Option<String>,
    pub domain: Option<String>,
    pub title: String,
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_deserialization() {
        let json = serde_json::json!({
            "id": "123456",
            "username": "alice",
            "acct": "alice",
            "display_name": "Alice",
            "note": "<p>Hello world</p>",
            "url": "https://mastodon.social/@alice",
            "avatar": "https://mastodon.social/avatars/alice.png",
            "header": "https://mastodon.social/headers/alice.png",
            "followers_count": 100,
            "following_count": 50,
            "statuses_count": 200,
            "locked": false,
            "bot": false,
            "created_at": "2024-01-01T00:00:00.000Z"
        });
        let account: Account = serde_json::from_value(json).unwrap();
        assert_eq!(account.id, "123456");
        assert_eq!(account.username, "alice");
        assert_eq!(account.followers_count, 100);
    }

    #[test]
    fn status_deserialization() {
        let json = serde_json::json!({
            "id": "status_1",
            "uri": "https://mastodon.social/users/alice/statuses/1",
            "url": "https://mastodon.social/@alice/1",
            "content": "<p>Hello Mastodon!</p>",
            "created_at": "2024-01-01T12:00:00.000Z",
            "account": {
                "id": "123",
                "username": "alice",
                "acct": "alice",
                "display_name": "Alice",
                "url": "https://mastodon.social/@alice",
                "avatar": "https://example.com/a.png",
                "header": "https://example.com/h.png",
                "followers_count": 10,
                "following_count": 5,
                "statuses_count": 3,
                "created_at": "2024-01-01T00:00:00Z"
            },
            "reblogs_count": 5,
            "favourites_count": 10,
            "replies_count": 2,
            "visibility": "public",
            "sensitive": false,
            "spoiler_text": "",
            "media_attachments": [],
            "in_reply_to_id": null,
            "in_reply_to_account_id": null,
            "application": null,
            "reblog": null
        });
        let status: Status = serde_json::from_value(json).unwrap();
        assert_eq!(status.id, "status_1");
        assert_eq!(status.visibility, "public");
        assert_eq!(status.favourites_count, 10);
    }

    #[test]
    fn notification_deserialization() {
        let json = serde_json::json!({
            "id": "notif_1",
            "type": "favourite",
            "created_at": "2024-01-01T12:00:00.000Z",
            "account": {
                "id": "456",
                "username": "bob",
                "acct": "bob",
                "display_name": "Bob",
                "url": "https://mastodon.social/@bob",
                "avatar": "https://example.com/b.png",
                "header": "https://example.com/bh.png",
                "followers_count": 5,
                "following_count": 3,
                "statuses_count": 1,
                "created_at": "2024-01-01T00:00:00Z"
            },
            "status": null
        });
        let notif: Notification = serde_json::from_value(json).unwrap();
        assert_eq!(notif.notification_type, "favourite");
    }

    #[test]
    fn search_results_deserialization() {
        let json = serde_json::json!({
            "accounts": [],
            "statuses": [],
            "hashtags": [{
                "name": "rust",
                "url": "https://mastodon.social/tags/rust",
                "history": [{
                    "day": "1704067200",
                    "uses": "42",
                    "accounts": "15"
                }]
            }]
        });
        let results: SearchResults = serde_json::from_value(json).unwrap();
        assert_eq!(results.hashtags.len(), 1);
        assert_eq!(results.hashtags[0].name, "rust");
    }

    #[test]
    fn api_error_deserialization() {
        let json = serde_json::json!({
            "error": "Record not found",
            "error_description": "The requested resource could not be found"
        });
        let err: ApiError = serde_json::from_value(json).unwrap();
        assert_eq!(err.error, "Record not found");
    }

    #[test]
    fn instance_deserialization() {
        let json = serde_json::json!({
            "uri": "mastodon.social",
            "title": "Mastodon",
            "version": "4.2.0"
        });
        let instance: Instance = serde_json::from_value(json).unwrap();
        assert_eq!(instance.title, "Mastodon");
        assert_eq!(instance.version, "4.2.0");
    }

    #[test]
    fn media_attachment_deserialization() {
        let json = serde_json::json!({
            "id": "media_1",
            "type": "image",
            "url": "https://mastodon.social/media/1.png",
            "preview_url": "https://mastodon.social/media/1_small.png",
            "description": "A photo"
        });
        let media: MediaAttachment = serde_json::from_value(json).unwrap();
        assert_eq!(media.media_type, "image");
    }

    #[test]
    fn status_with_reblog() {
        let json = serde_json::json!({
            "id": "reblog_1",
            "uri": "https://mastodon.social/users/bob/statuses/2",
            "url": null,
            "content": "",
            "created_at": "2024-01-02T00:00:00Z",
            "account": {
                "id": "456",
                "username": "bob",
                "acct": "bob",
                "display_name": "Bob",
                "url": "https://mastodon.social/@bob",
                "avatar": "https://example.com/b.png",
                "header": "https://example.com/bh.png",
                "followers_count": 5,
                "following_count": 3,
                "statuses_count": 1,
                "created_at": "2024-01-01T00:00:00Z"
            },
            "reblogs_count": 0,
            "favourites_count": 0,
            "replies_count": 0,
            "visibility": "public",
            "sensitive": false,
            "spoiler_text": "",
            "media_attachments": [],
            "reblog": {
                "id": "original_1",
                "uri": "https://mastodon.social/users/alice/statuses/1",
                "url": "https://mastodon.social/@alice/1",
                "content": "<p>Original toot</p>",
                "created_at": "2024-01-01T00:00:00Z",
                "account": {
                    "id": "123",
                    "username": "alice",
                    "acct": "alice",
                    "display_name": "Alice",
                    "url": "https://mastodon.social/@alice",
                    "avatar": "https://example.com/a.png",
                    "header": "https://example.com/h.png",
                    "followers_count": 10,
                    "following_count": 5,
                    "statuses_count": 3,
                    "created_at": "2024-01-01T00:00:00Z"
                },
                "reblogs_count": 1,
                "favourites_count": 0,
                "replies_count": 0,
                "visibility": "public",
                "sensitive": false,
                "spoiler_text": "",
                "media_attachments": []
            }
        });
        let status: Status = serde_json::from_value(json).unwrap();
        assert!(status.reblog.is_some());
        assert_eq!(status.reblog.unwrap().id, "original_1");
    }
}
