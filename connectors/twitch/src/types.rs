//! Twitch Helix API types.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// OAuth token types
// ─────────────────────────────────────────────────────────────────────────────

/// `OAuth2` client credentials token response.
#[derive(Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub token_type: String,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("expires_in", &self.expires_in)
            .field("token_type", &self.token_type)
            .finish()
    }
}

/// OAuth token validation response from Twitch's /validate endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct ValidatedToken {
    pub client_id: String,
    #[serde(default)]
    pub login: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    pub expires_in: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helix API response wrapper
// ─────────────────────────────────────────────────────────────────────────────

/// Generic Helix API response wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelixResponse<T> {
    pub data: Vec<T>,
    #[serde(default)]
    pub pagination: Option<Pagination>,
}

/// Pagination cursor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pagination {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Stream types
// ─────────────────────────────────────────────────────────────────────────────

/// A live stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stream {
    pub id: String,
    pub user_id: String,
    pub user_login: String,
    pub user_name: String,
    pub game_id: String,
    pub game_name: String,
    #[serde(rename = "type")]
    pub stream_type: String,
    pub title: String,
    pub viewer_count: u64,
    pub started_at: String,
    pub language: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub is_mature: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
// User types
// ─────────────────────────────────────────────────────────────────────────────

/// A Twitch user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub login: String,
    pub display_name: String,
    #[serde(rename = "type")]
    pub user_type: String,
    pub broadcaster_type: String,
    pub description: String,
    pub profile_image_url: String,
    pub offline_image_url: String,
    pub view_count: u64,
    pub created_at: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Channel types
// ─────────────────────────────────────────────────────────────────────────────

/// Channel information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub broadcaster_id: String,
    pub broadcaster_login: String,
    pub broadcaster_name: String,
    pub broadcaster_language: String,
    pub game_name: String,
    pub game_id: String,
    pub title: String,
    pub delay: u32,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub content_classification_labels: Vec<String>,
    #[serde(default)]
    pub is_branded_content: bool,
}

/// Channel modification request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModifyChannelRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub game_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broadcaster_language: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Clip types
// ─────────────────────────────────────────────────────────────────────────────

/// A clip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Clip {
    pub id: String,
    pub url: String,
    pub embed_url: String,
    pub broadcaster_id: String,
    pub broadcaster_name: String,
    pub creator_id: String,
    pub creator_name: String,
    pub game_id: String,
    pub language: String,
    pub title: String,
    pub view_count: u64,
    pub created_at: String,
    pub duration: f64,
}

/// Response from creating a clip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateClipResponse {
    pub id: String,
    pub edit_url: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Chat types
// ─────────────────────────────────────────────────────────────────────────────

/// Chat message send request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendChatMessageRequest {
    pub broadcaster_id: String,
    pub sender_id: String,
    pub message: String,
}

/// Chat message send response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendChatMessageResponse {
    pub message_id: String,
    pub is_sent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drop_reason: Option<DropReason>,
}

/// Reason a chat message was dropped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DropReason {
    pub code: String,
    pub message: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Game types
// ─────────────────────────────────────────────────────────────────────────────

/// A game/category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Game {
    pub id: String,
    pub name: String,
    pub box_art_url: String,
    #[serde(default)]
    pub igdb_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_deserialization() {
        let json = serde_json::json!({
            "id": "123",
            "user_id": "456",
            "user_login": "testuser",
            "user_name": "TestUser",
            "game_id": "789",
            "game_name": "Just Chatting",
            "type": "live",
            "title": "Test Stream",
            "viewer_count": 1000,
            "started_at": "2026-03-21T10:00:00Z",
            "language": "en",
            "tags": ["English"],
            "is_mature": false
        });
        let stream: Stream = serde_json::from_value(json).unwrap();
        assert_eq!(stream.id, "123");
        assert_eq!(stream.viewer_count, 1000);
        assert_eq!(stream.stream_type, "live");
    }

    #[test]
    fn validated_token_deserialization() {
        let json = serde_json::json!({
            "client_id": "test-client",
            "scopes": ["clips:edit"],
            "expires_in": 3600
        });
        let token: ValidatedToken = serde_json::from_value(json).unwrap();
        assert_eq!(token.client_id, "test-client");
        assert_eq!(token.scopes, vec!["clips:edit"]);
        assert_eq!(token.login, None);
        assert_eq!(token.user_id, None);
    }

    #[test]
    fn user_deserialization() {
        let json = serde_json::json!({
            "id": "123",
            "login": "testuser",
            "display_name": "TestUser",
            "type": "",
            "broadcaster_type": "partner",
            "description": "Test description",
            "profile_image_url": "https://example.com/img.jpg",
            "offline_image_url": "https://example.com/offline.jpg",
            "view_count": 50000,
            "created_at": "2020-01-01T00:00:00Z"
        });
        let user: User = serde_json::from_value(json).unwrap();
        assert_eq!(user.login, "testuser");
        assert_eq!(user.broadcaster_type, "partner");
    }

    #[test]
    fn channel_deserialization() {
        let json = serde_json::json!({
            "broadcaster_id": "123",
            "broadcaster_login": "testuser",
            "broadcaster_name": "TestUser",
            "broadcaster_language": "en",
            "game_name": "Just Chatting",
            "game_id": "789",
            "title": "My Channel",
            "delay": 0,
            "tags": ["English"],
            "content_classification_labels": [],
            "is_branded_content": false
        });
        let channel: Channel = serde_json::from_value(json).unwrap();
        assert_eq!(channel.broadcaster_id, "123");
    }

    #[test]
    fn clip_deserialization() {
        let json = serde_json::json!({
            "id": "clip123",
            "url": "https://clips.twitch.tv/clip123",
            "embed_url": "https://clips.twitch.tv/embed?clip=clip123",
            "broadcaster_id": "456",
            "broadcaster_name": "TestUser",
            "creator_id": "789",
            "creator_name": "Clipper",
            "game_id": "111",
            "language": "en",
            "title": "Amazing clip",
            "view_count": 500,
            "created_at": "2026-03-21T12:00:00Z",
            "duration": 30.5
        });
        let clip: Clip = serde_json::from_value(json).unwrap();
        assert_eq!(clip.id, "clip123");
        assert!((clip.duration - 30.5).abs() < f64::EPSILON);
    }

    #[test]
    fn modify_channel_serialization() {
        let req = ModifyChannelRequest {
            game_id: Some("789".into()),
            broadcaster_language: None,
            title: Some("New Title".into()),
            delay: None,
            tags: Some(vec!["English".into()]),
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["game_id"], "789");
        assert_eq!(json["title"], "New Title");
        assert!(json.get("broadcaster_language").is_none());
        assert!(json.get("delay").is_none());
    }

    #[test]
    fn game_deserialization() {
        let json = serde_json::json!({
            "id": "33214",
            "name": "Fortnite",
            "box_art_url": "https://example.com/fortnite.jpg",
            "igdb_id": "1905"
        });
        let game: Game = serde_json::from_value(json).unwrap();
        assert_eq!(game.name, "Fortnite");
    }

    #[test]
    fn chat_message_response_deserialization() {
        let json = serde_json::json!({
            "message_id": "msg123",
            "is_sent": true
        });
        let resp: SendChatMessageResponse = serde_json::from_value(json).unwrap();
        assert!(resp.is_sent);
        assert!(resp.drop_reason.is_none());
    }

    #[test]
    fn chat_message_dropped() {
        let json = serde_json::json!({
            "message_id": "msg456",
            "is_sent": false,
            "drop_reason": {
                "code": "channel_settings",
                "message": "Message was blocked by channel settings"
            }
        });
        let resp: SendChatMessageResponse = serde_json::from_value(json).unwrap();
        assert!(!resp.is_sent);
        assert!(resp.drop_reason.is_some());
    }

    #[test]
    fn token_response_debug_redacted() {
        let resp = TokenResponse {
            access_token: "super_secret".into(),
            expires_in: 3600,
            token_type: "bearer".into(),
        };
        let debug = format!("{resp:?}");
        assert!(!debug.contains("super_secret"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn helix_response_with_pagination() {
        let json = serde_json::json!({
            "data": [{"id": "1", "name": "Game", "box_art_url": "", "igdb_id": ""}],
            "pagination": {"cursor": "abc123"}
        });
        let resp: HelixResponse<Game> = serde_json::from_value(json).unwrap();
        assert_eq!(resp.data.len(), 1);
        assert_eq!(
            resp.pagination.as_ref().and_then(|p| p.cursor.as_deref()),
            Some("abc123")
        );
    }

    #[test]
    fn helix_response_no_pagination() {
        let json = serde_json::json!({
            "data": []
        });
        let resp: HelixResponse<Game> = serde_json::from_value(json).unwrap();
        assert!(resp.data.is_empty());
        assert!(resp.pagination.is_none());
    }

    #[test]
    fn create_clip_response() {
        let json = serde_json::json!({
            "id": "clip_id",
            "edit_url": "https://clips.twitch.tv/edit/clip_id"
        });
        let resp: CreateClipResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.id, "clip_id");
    }
}
