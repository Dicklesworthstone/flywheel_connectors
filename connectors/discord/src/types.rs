//! Discord API types.

use serde::{Deserialize, Serialize};

/// Doctor diagnostic report.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub ready: bool,
    pub checks: Vec<DoctorCheck>,
}

/// A single doctor check result.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorCheck {
    pub name: String,
    pub passed: bool,
    pub message: String,
}

/// Discord user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// User ID
    pub id: String,

    /// Username
    pub username: String,

    /// Discriminator (legacy)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discriminator: Option<String>,

    /// Global display name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_name: Option<String>,

    /// Avatar hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,

    /// Whether this is a bot
    #[serde(default)]
    pub bot: bool,
}

/// Discord guild (server).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Guild {
    /// Guild ID
    pub id: String,

    /// Guild name
    pub name: String,

    /// Icon hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,

    /// Owner ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
}

/// Discord channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    /// Channel ID
    pub id: String,

    /// Channel type
    #[serde(rename = "type")]
    pub channel_type: i32,

    /// Guild ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guild_id: Option<String>,

    /// Channel name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Topic
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
}

/// Discord message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    /// Message ID
    pub id: String,

    /// Channel ID
    pub channel_id: String,

    /// Author
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<User>,

    /// Message content
    pub content: String,

    /// Timestamp
    pub timestamp: String,

    /// Whether this message is TTS
    #[serde(default)]
    pub tts: bool,

    /// Whether this mentions everyone
    #[serde(default)]
    pub mention_everyone: bool,

    /// Attachments
    #[serde(default)]
    pub attachments: Vec<Attachment>,

    /// Embeds
    #[serde(default)]
    pub embeds: Vec<Embed>,

    /// Guild ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guild_id: Option<String>,
}

/// Discord attachment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    /// Attachment ID
    pub id: String,

    /// Filename
    pub filename: String,

    /// File size
    pub size: u64,

    /// URL
    pub url: String,

    /// Proxy URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<String>,

    /// Content type
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
}

/// Discord embed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Embed {
    /// Title
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// Description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Color
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<u32>,

    /// Fields
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<EmbedField>,

    /// Footer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub footer: Option<EmbedFooter>,

    /// Image
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<EmbedImage>,

    /// Thumbnail
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail: Option<EmbedThumbnail>,

    /// Author
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<EmbedAuthor>,
}

/// Embed field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedField {
    /// Field name
    pub name: String,

    /// Field value
    pub value: String,

    /// Inline display
    #[serde(default)]
    pub inline: bool,
}

/// Embed footer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedFooter {
    /// Footer text
    pub text: String,

    /// Icon URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
}

/// Embed image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedImage {
    /// Image URL
    pub url: String,
}

/// Embed thumbnail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedThumbnail {
    /// Thumbnail URL
    pub url: String,
}

/// Embed author.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedAuthor {
    /// Author name
    pub name: String,

    /// Author URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Icon URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
}

/// Gateway event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayPayload {
    /// Opcode
    pub op: i32,

    /// Event data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<serde_json::Value>,

    /// Sequence number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s: Option<u64>,

    /// Event name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub t: Option<String>,
}

/// Gateway identify payload.
#[derive(Clone, Serialize, Deserialize)]
pub struct GatewayIdentify {
    /// Bot token
    pub token: String,

    /// Gateway intents
    pub intents: u64,

    /// Connection properties
    pub properties: GatewayProperties,

    /// Shard info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shard: Option<[u32; 2]>,
}

impl std::fmt::Debug for GatewayIdentify {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayIdentify")
            .field("token", &"[REDACTED]")
            .field("intents", &self.intents)
            .field("properties", &self.properties)
            .field("shard", &self.shard)
            .finish()
    }
}

/// Gateway connection properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayProperties {
    /// OS
    pub os: String,

    /// Browser
    pub browser: String,

    /// Device
    pub device: String,
}

/// Gateway ready event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayReady {
    /// API version
    pub v: i32,

    /// Bot user
    pub user: User,

    /// Session ID
    pub session_id: String,

    /// Resume gateway URL
    pub resume_gateway_url: String,

    /// Guilds (unavailable)
    #[serde(default)]
    pub guilds: Vec<serde_json::Value>,
}

/// Gateway hello event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayHello {
    /// Heartbeat interval in milliseconds
    pub heartbeat_interval: u64,
}

/// Smallest accepted Discord Gateway heartbeat interval.
pub const MIN_GATEWAY_HEARTBEAT_INTERVAL_MS: u64 = 1;

/// Largest accepted Discord Gateway heartbeat interval.
///
/// Real Discord gateway intervals are tens of seconds. Five minutes keeps the
/// parser tolerant while preventing hostile frames from driving unbounded timer
/// arithmetic in the gateway loop.
pub const MAX_GATEWAY_HEARTBEAT_INTERVAL_MS: u64 = 5 * 60 * 1000;

/// Validation failure for a parsed Discord Gateway Hello frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayHelloValidationError {
    /// A zero interval would create a hot heartbeat loop.
    ZeroHeartbeatInterval,
    /// An oversized interval can overflow or stall timer arithmetic.
    HeartbeatIntervalTooLarge { interval_ms: u64, max_ms: u64 },
}

impl std::fmt::Display for GatewayHelloValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroHeartbeatInterval => {
                f.write_str("gateway Hello heartbeat_interval must be greater than zero")
            }
            Self::HeartbeatIntervalTooLarge {
                interval_ms,
                max_ms,
            } => write!(
                f,
                "gateway Hello heartbeat_interval {interval_ms}ms exceeds the {max_ms}ms limit"
            ),
        }
    }
}

impl std::error::Error for GatewayHelloValidationError {}

/// Validate an untrusted Discord Gateway Hello frame before timer use.
///
/// The WebSocket peer controls this value, so parsing alone is not enough: the
/// gateway loop later converts it into a [`std::time::Duration`] and schedules
/// heartbeat deadlines from it.
pub const fn validate_gateway_hello(
    hello: GatewayHello,
) -> Result<GatewayHello, GatewayHelloValidationError> {
    match hello.heartbeat_interval {
        0 => Err(GatewayHelloValidationError::ZeroHeartbeatInterval),
        interval_ms if interval_ms > MAX_GATEWAY_HEARTBEAT_INTERVAL_MS => {
            Err(GatewayHelloValidationError::HeartbeatIntervalTooLarge {
                interval_ms,
                max_ms: MAX_GATEWAY_HEARTBEAT_INTERVAL_MS,
            })
        }
        _ => Ok(hello),
    }
}

/// Gateway resume payload.
#[derive(Clone, Serialize, Deserialize)]
pub struct GatewayResume {
    /// Bot token
    pub token: String,
    /// Session ID from READY event
    pub session_id: String,
    /// Last sequence number received
    pub seq: u64,
}

impl std::fmt::Debug for GatewayResume {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayResume")
            .field("token", &"[REDACTED]")
            .field("session_id", &self.session_id)
            .field("seq", &self.seq)
            .finish()
    }
}

/// Create message request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CreateMessage {
    /// Message content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    /// TTS
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tts: Option<bool>,

    /// Embeds
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub embeds: Vec<Embed>,

    /// Message reference (for replies)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_reference: Option<MessageReference>,
}

/// Message reference for replies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageReference {
    /// Message ID to reply to
    pub message_id: String,

    /// Channel ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_id: Option<String>,

    /// Guild ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guild_id: Option<String>,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::redundant_clone,
        reason = "clone-focused tests intentionally exercise the Clone impls"
    )]

    use super::*;
    use serde_json::json;

    // ---- User ----

    #[test]
    fn user_serde_roundtrip() {
        let user = User {
            id: "123".to_string(),
            username: "testbot".to_string(),
            discriminator: Some("0001".to_string()),
            global_name: Some("Test Bot".to_string()),
            avatar: None,
            bot: true,
        };
        let json = serde_json::to_string(&user).unwrap();
        let back: User = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "123");
        assert!(back.bot);
    }

    #[test]
    fn user_minimal_deserialize() {
        let json = r#"{"id":"456","username":"human"}"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert_eq!(user.id, "456");
        assert!(!user.bot); // default false
        assert!(user.discriminator.is_none());
    }

    // ---- Guild ----

    #[test]
    fn guild_serde_roundtrip() {
        let guild = Guild {
            id: "g1".to_string(),
            name: "Test Server".to_string(),
            icon: Some("abc".to_string()),
            owner_id: Some("123".to_string()),
        };
        let json = serde_json::to_string(&guild).unwrap();
        let back: Guild = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "Test Server");
    }

    // ---- Channel ----

    #[test]
    fn channel_serde_roundtrip() {
        let channel = Channel {
            id: "ch1".to_string(),
            channel_type: 0,
            guild_id: Some("g1".to_string()),
            name: Some("general".to_string()),
            topic: Some("Welcome!".to_string()),
        };
        let json = serde_json::to_string(&channel).unwrap();
        assert!(json.contains("\"type\":0"));
        let back: Channel = serde_json::from_str(&json).unwrap();
        assert_eq!(back.channel_type, 0);
    }

    // ---- Message ----

    #[test]
    fn message_serde_with_defaults() {
        let json = json!({
            "id": "m1",
            "channel_id": "ch1",
            "content": "Hello!",
            "timestamp": "2026-03-03T00:00:00Z"
        });
        let msg: Message = serde_json::from_value(json).unwrap();
        assert_eq!(msg.id, "m1");
        assert!(!msg.tts);
        assert!(!msg.mention_everyone);
        assert!(msg.attachments.is_empty());
        assert!(msg.embeds.is_empty());
        assert!(msg.author.is_none());
    }

    #[test]
    fn message_full_roundtrip() {
        let msg = Message {
            id: "m2".to_string(),
            channel_id: "ch1".to_string(),
            author: Some(User {
                id: "u1".to_string(),
                username: "bot".to_string(),
                discriminator: None,
                global_name: None,
                avatar: None,
                bot: true,
            }),
            content: "Test".to_string(),
            timestamp: "2026-03-03T00:00:00Z".to_string(),
            tts: false,
            mention_everyone: false,
            attachments: vec![],
            embeds: vec![],
            guild_id: Some("g1".to_string()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: Message = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "m2");
        assert!(back.author.unwrap().bot);
    }

    // ---- Embed ----

    #[test]
    fn embed_default() {
        let embed = Embed::default();
        assert!(embed.title.is_none());
        assert!(embed.fields.is_empty());
        assert!(embed.color.is_none());
    }

    #[test]
    fn embed_full_serde() {
        let embed = Embed {
            title: Some("Title".to_string()),
            description: Some("Desc".to_string()),
            url: None,
            color: Some(0xFF_0000),
            fields: vec![EmbedField {
                name: "Field".to_string(),
                value: "Value".to_string(),
                inline: true,
            }],
            footer: Some(EmbedFooter {
                text: "Footer".to_string(),
                icon_url: None,
            }),
            image: Some(EmbedImage {
                url: "https://example.com/img.png".to_string(),
            }),
            thumbnail: None,
            author: Some(EmbedAuthor {
                name: "Author".to_string(),
                url: None,
                icon_url: None,
            }),
        };
        let json = serde_json::to_string(&embed).unwrap();
        let back: Embed = serde_json::from_str(&json).unwrap();
        assert_eq!(back.title.as_deref(), Some("Title"));
        assert_eq!(back.color, Some(0xFF_0000));
        assert_eq!(back.fields.len(), 1);
        assert!(back.fields[0].inline);
    }

    // ---- Attachment ----

    #[test]
    fn attachment_serde() {
        let att = Attachment {
            id: "a1".to_string(),
            filename: "test.txt".to_string(),
            size: 1024,
            url: "https://cdn.example.com/test.txt".to_string(),
            proxy_url: None,
            content_type: Some("text/plain".to_string()),
        };
        let json = serde_json::to_string(&att).unwrap();
        let back: Attachment = serde_json::from_str(&json).unwrap();
        assert_eq!(back.size, 1024);
    }

    // ---- GatewayPayload ----

    #[test]
    fn gateway_payload_dispatch_serde() {
        let payload = GatewayPayload {
            op: 0,
            d: Some(json!({"content": "hello"})),
            s: Some(42),
            t: Some("MESSAGE_CREATE".to_string()),
        };
        let json = serde_json::to_string(&payload).unwrap();
        let back: GatewayPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(back.op, 0);
        assert_eq!(back.s, Some(42));
        assert_eq!(back.t.as_deref(), Some("MESSAGE_CREATE"));
    }

    #[test]
    fn gateway_payload_heartbeat() {
        let payload = GatewayPayload {
            op: 1,
            d: Some(json!(42)),
            s: None,
            t: None,
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(!json.contains("\"s\""));
        assert!(!json.contains("\"t\""));
    }

    // ---- GatewayHello ----

    #[test]
    fn gateway_hello_serde() {
        let hello = GatewayHello {
            heartbeat_interval: 41250,
        };
        let json = serde_json::to_string(&hello).unwrap();
        let back: GatewayHello = serde_json::from_str(&json).unwrap();
        assert_eq!(back.heartbeat_interval, 41250);
    }

    #[test]
    fn validate_gateway_hello_accepts_normal_interval() {
        let hello = validate_gateway_hello(GatewayHello {
            heartbeat_interval: 45_000,
        })
        .expect("normal gateway heartbeat interval should validate");

        assert_eq!(hello.heartbeat_interval, 45_000);
    }

    #[test]
    fn validate_gateway_hello_rejects_zero_interval() {
        let err = validate_gateway_hello(GatewayHello {
            heartbeat_interval: 0,
        })
        .expect_err("zero heartbeat interval should be rejected");

        assert_eq!(err, GatewayHelloValidationError::ZeroHeartbeatInterval);
    }

    #[test]
    fn validate_gateway_hello_rejects_oversized_interval() {
        let err = validate_gateway_hello(GatewayHello {
            heartbeat_interval: MAX_GATEWAY_HEARTBEAT_INTERVAL_MS + 1,
        })
        .expect_err("oversized heartbeat interval should be rejected");

        assert_eq!(
            err,
            GatewayHelloValidationError::HeartbeatIntervalTooLarge {
                interval_ms: MAX_GATEWAY_HEARTBEAT_INTERVAL_MS + 1,
                max_ms: MAX_GATEWAY_HEARTBEAT_INTERVAL_MS,
            }
        );
    }

    // ---- GatewayResume ----

    #[test]
    fn gateway_resume_serde() {
        let resume = GatewayResume {
            token: "tok".to_string(),
            session_id: "sess".to_string(),
            seq: 100,
        };
        let json = serde_json::to_string(&resume).unwrap();
        let back: GatewayResume = serde_json::from_str(&json).unwrap();
        assert_eq!(back.seq, 100);
    }

    // ---- CreateMessage ----

    #[test]
    fn create_message_default() {
        let msg = CreateMessage::default();
        assert!(msg.content.is_none());
        assert!(msg.embeds.is_empty());
        assert!(msg.message_reference.is_none());
    }

    #[test]
    fn create_message_with_reply() {
        let msg = CreateMessage {
            content: Some("Reply".to_string()),
            tts: None,
            embeds: vec![],
            message_reference: Some(MessageReference {
                message_id: "m1".to_string(),
                channel_id: None,
                guild_id: None,
            }),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("message_reference"));
        let back: CreateMessage = serde_json::from_str(&json).unwrap();
        assert!(back.message_reference.is_some());
    }

    // ---- User skip_serializing_if ----

    #[test]
    fn user_none_fields_omitted_from_json() {
        let user = User {
            id: "1".into(),
            username: "alice".into(),
            discriminator: None,
            global_name: None,
            avatar: None,
            bot: false,
        };
        let json = serde_json::to_string(&user).unwrap();
        assert!(!json.contains("discriminator"));
        assert!(!json.contains("global_name"));
        assert!(!json.contains("avatar"));
    }

    #[test]
    fn user_some_fields_present_in_json() {
        let user = User {
            id: "2".into(),
            username: "bob".into(),
            discriminator: Some("1234".into()),
            global_name: Some("Bobby".into()),
            avatar: Some("abcdef".into()),
            bot: true,
        };
        let json = serde_json::to_string(&user).unwrap();
        assert!(json.contains("\"discriminator\":\"1234\""));
        assert!(json.contains("\"global_name\":\"Bobby\""));
        assert!(json.contains("\"avatar\":\"abcdef\""));
    }

    #[test]
    fn user_clone_and_debug() {
        let user = User {
            id: "3".into(),
            username: "carol".into(),
            discriminator: None,
            global_name: None,
            avatar: None,
            bot: false,
        };
        let cloned = user.clone();
        assert_eq!(cloned.id, "3");
        let dbg = format!("{user:?}");
        assert!(dbg.contains("carol"));
    }

    // ---- Guild ----

    #[test]
    fn guild_no_optional_fields() {
        let json = r#"{"id":"g2","name":"Minimal Guild"}"#;
        let guild: Guild = serde_json::from_str(json).unwrap();
        assert_eq!(guild.id, "g2");
        assert_eq!(guild.name, "Minimal Guild");
        assert!(guild.icon.is_none());
        assert!(guild.owner_id.is_none());
    }

    #[test]
    fn guild_none_fields_omitted() {
        let guild = Guild {
            id: "g3".into(),
            name: "TestGuild".into(),
            icon: None,
            owner_id: None,
        };
        let json = serde_json::to_string(&guild).unwrap();
        assert!(!json.contains("icon"));
        assert!(!json.contains("owner_id"));
    }

    #[test]
    fn guild_clone_and_debug() {
        let guild = Guild {
            id: "g4".into(),
            name: "Debug Guild".into(),
            icon: Some("icon_hash".into()),
            owner_id: None,
        };
        let cloned = guild.clone();
        assert_eq!(cloned.name, "Debug Guild");
        let dbg = format!("{guild:?}");
        assert!(dbg.contains("Debug Guild"));
    }

    // ---- Channel minimal ----

    #[test]
    fn channel_minimal_fields() {
        let json = r#"{"id":"ch2","type":2}"#;
        let channel: Channel = serde_json::from_str(json).unwrap();
        assert_eq!(channel.id, "ch2");
        assert_eq!(channel.channel_type, 2);
        assert!(channel.guild_id.is_none());
        assert!(channel.name.is_none());
        assert!(channel.topic.is_none());
    }

    #[test]
    fn channel_none_fields_omitted() {
        let channel = Channel {
            id: "ch3".into(),
            channel_type: 0,
            guild_id: None,
            name: None,
            topic: None,
        };
        let json = serde_json::to_string(&channel).unwrap();
        assert!(!json.contains("guild_id"));
        assert!(!json.contains("name"));
        assert!(!json.contains("topic"));
        // "type" must always be present
        assert!(json.contains("\"type\":0"));
    }

    #[test]
    fn channel_clone_and_debug() {
        let ch = Channel {
            id: "ch4".into(),
            channel_type: 4,
            guild_id: Some("g5".into()),
            name: Some("voice".into()),
            topic: None,
        };
        let cloned = ch.clone();
        assert_eq!(cloned.channel_type, 4);
        let dbg = format!("{ch:?}");
        assert!(dbg.contains("voice"));
    }

    // ---- Message with attachments and embeds ----

    #[test]
    fn message_with_attachments_and_embeds() {
        let msg = Message {
            id: "m3".into(),
            channel_id: "ch1".into(),
            author: None,
            content: "Rich message".into(),
            timestamp: "2026-03-05T00:00:00Z".into(),
            tts: false,
            mention_everyone: false,
            attachments: vec![Attachment {
                id: "a1".into(),
                filename: "photo.png".into(),
                size: 2048,
                url: "https://cdn.example.com/photo.png".into(),
                proxy_url: Some("https://proxy.example.com/photo.png".into()),
                content_type: Some("image/png".into()),
            }],
            embeds: vec![Embed {
                title: Some("Embed Title".into()),
                description: Some("Some description".into()),
                url: None,
                color: Some(0x00FF00),
                fields: vec![],
                footer: None,
                image: None,
                thumbnail: None,
                author: None,
            }],
            guild_id: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: Message = serde_json::from_str(&json).unwrap();
        assert_eq!(back.attachments.len(), 1);
        assert_eq!(back.attachments[0].filename, "photo.png");
        assert_eq!(back.embeds.len(), 1);
        assert_eq!(back.embeds[0].title.as_deref(), Some("Embed Title"));
    }

    #[test]
    fn message_empty_vecs_omit_when_default() {
        // When attachments and embeds are empty, they should still
        // be present in serialized output (no skip_serializing_if on Message vecs)
        let msg = Message {
            id: "m4".into(),
            channel_id: "ch1".into(),
            author: None,
            content: "plain".into(),
            timestamp: "2026-03-05T00:00:00Z".into(),
            tts: false,
            mention_everyone: false,
            attachments: vec![],
            embeds: vec![],
            guild_id: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        // Message vecs use #[serde(default)] but no skip_serializing_if,
        // so they appear as empty arrays in output
        assert!(json.contains("\"attachments\":[]"));
        assert!(json.contains("\"embeds\":[]"));
    }

    #[test]
    fn message_clone_and_debug() {
        let msg = Message {
            id: "m5".into(),
            channel_id: "ch2".into(),
            author: None,
            content: "debug test".into(),
            timestamp: "2026-03-05T00:00:00Z".into(),
            tts: true,
            mention_everyone: true,
            attachments: vec![],
            embeds: vec![],
            guild_id: None,
        };
        let cloned = msg.clone();
        assert!(cloned.tts);
        assert!(cloned.mention_everyone);
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("debug test"));
    }

    // ---- Embed with thumbnail ----

    #[test]
    fn embed_with_thumbnail() {
        let embed = Embed {
            title: Some("Thumb".into()),
            description: None,
            url: None,
            color: None,
            fields: vec![],
            footer: None,
            image: None,
            thumbnail: Some(EmbedThumbnail {
                url: "https://example.com/thumb.png".into(),
            }),
            author: None,
        };
        let json = serde_json::to_string(&embed).unwrap();
        assert!(json.contains("thumbnail"));
        assert!(json.contains("thumb.png"));
        let back: Embed = serde_json::from_str(&json).unwrap();
        assert_eq!(back.thumbnail.unwrap().url, "https://example.com/thumb.png");
    }

    #[test]
    fn embed_empty_fields_omitted() {
        let embed = Embed {
            title: None,
            description: None,
            url: None,
            color: None,
            fields: vec![],
            footer: None,
            image: None,
            thumbnail: None,
            author: None,
        };
        let json = serde_json::to_string(&embed).unwrap();
        assert!(!json.contains("fields"));
        assert!(!json.contains("title"));
        assert!(!json.contains("footer"));
        assert!(!json.contains("image"));
        assert!(!json.contains("thumbnail"));
        assert!(!json.contains("author"));
    }

    #[test]
    fn embed_clone_and_debug() {
        let embed = Embed {
            title: Some("Clone Test".into()),
            ..Default::default()
        };
        let cloned = embed.clone();
        assert_eq!(cloned.title.as_deref(), Some("Clone Test"));
        let dbg = format!("{embed:?}");
        assert!(dbg.contains("Clone Test"));
    }

    // ---- EmbedField inline default ----

    #[test]
    fn embed_field_inline_defaults_false() {
        let json = r#"{"name":"F","value":"V"}"#;
        let field: EmbedField = serde_json::from_str(json).unwrap();
        assert_eq!(field.name, "F");
        assert_eq!(field.value, "V");
        assert!(!field.inline);
    }

    #[test]
    fn embed_field_inline_true_roundtrip() {
        let field = EmbedField {
            name: "N".into(),
            value: "Val".into(),
            inline: true,
        };
        let json = serde_json::to_string(&field).unwrap();
        let back: EmbedField = serde_json::from_str(&json).unwrap();
        assert!(back.inline);
    }

    #[test]
    fn embed_field_clone_and_debug() {
        let field = EmbedField {
            name: "Test".into(),
            value: "Data".into(),
            inline: false,
        };
        let cloned = field.clone();
        assert_eq!(cloned.name, "Test");
        let dbg = format!("{field:?}");
        assert!(dbg.contains("Test"));
    }

    // ---- EmbedFooter with icon_url ----

    #[test]
    fn embed_footer_with_icon_url() {
        let footer = EmbedFooter {
            text: "Footer text".into(),
            icon_url: Some("https://example.com/icon.png".into()),
        };
        let json = serde_json::to_string(&footer).unwrap();
        assert!(json.contains("icon_url"));
        let back: EmbedFooter = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.icon_url.as_deref(),
            Some("https://example.com/icon.png")
        );
    }

    #[test]
    fn embed_footer_without_icon_url() {
        let footer = EmbedFooter {
            text: "Just text".into(),
            icon_url: None,
        };
        let json = serde_json::to_string(&footer).unwrap();
        assert!(!json.contains("icon_url"));
    }

    #[test]
    fn embed_footer_clone_and_debug() {
        let footer = EmbedFooter {
            text: "Foot".into(),
            icon_url: None,
        };
        let cloned = footer.clone();
        assert_eq!(cloned.text, "Foot");
        let dbg = format!("{footer:?}");
        assert!(dbg.contains("Foot"));
    }

    // ---- EmbedImage ----

    #[test]
    fn embed_image_roundtrip() {
        let img = EmbedImage {
            url: "https://example.com/image.jpg".into(),
        };
        let json = serde_json::to_string(&img).unwrap();
        let back: EmbedImage = serde_json::from_str(&json).unwrap();
        assert_eq!(back.url, "https://example.com/image.jpg");
    }

    #[test]
    fn embed_image_clone_and_debug() {
        let img = EmbedImage {
            url: "https://img.test".into(),
        };
        let cloned = img.clone();
        assert_eq!(cloned.url, "https://img.test");
        let dbg = format!("{img:?}");
        assert!(dbg.contains("img.test"));
    }

    // ---- EmbedThumbnail ----

    #[test]
    fn embed_thumbnail_roundtrip() {
        let thumb = EmbedThumbnail {
            url: "https://example.com/thumb.jpg".into(),
        };
        let json = serde_json::to_string(&thumb).unwrap();
        let back: EmbedThumbnail = serde_json::from_str(&json).unwrap();
        assert_eq!(back.url, "https://example.com/thumb.jpg");
    }

    #[test]
    fn embed_thumbnail_clone_and_debug() {
        let thumb = EmbedThumbnail {
            url: "https://thumb.test".into(),
        };
        let cloned = thumb.clone();
        assert_eq!(cloned.url, "https://thumb.test");
        let dbg = format!("{thumb:?}");
        assert!(dbg.contains("thumb.test"));
    }

    // ---- EmbedAuthor with url and icon_url ----

    #[test]
    fn embed_author_with_url_and_icon_url() {
        let author = EmbedAuthor {
            name: "Author Name".into(),
            url: Some("https://author.example.com".into()),
            icon_url: Some("https://author.example.com/icon.png".into()),
        };
        let json = serde_json::to_string(&author).unwrap();
        assert!(json.contains("\"url\":\"https://author.example.com\""));
        assert!(json.contains("icon_url"));
        let back: EmbedAuthor = serde_json::from_str(&json).unwrap();
        assert_eq!(back.url.as_deref(), Some("https://author.example.com"));
        assert_eq!(
            back.icon_url.as_deref(),
            Some("https://author.example.com/icon.png")
        );
    }

    #[test]
    fn embed_author_none_fields_omitted() {
        let author = EmbedAuthor {
            name: "Just Name".into(),
            url: None,
            icon_url: None,
        };
        let json = serde_json::to_string(&author).unwrap();
        assert!(!json.contains("\"url\""));
        assert!(!json.contains("icon_url"));
    }

    #[test]
    fn embed_author_clone_and_debug() {
        let author = EmbedAuthor {
            name: "Auth".into(),
            url: None,
            icon_url: None,
        };
        let cloned = author.clone();
        assert_eq!(cloned.name, "Auth");
        let dbg = format!("{author:?}");
        assert!(dbg.contains("Auth"));
    }

    // ---- Attachment ----

    #[test]
    fn attachment_none_fields_omitted() {
        let att = Attachment {
            id: "a2".into(),
            filename: "doc.pdf".into(),
            size: 512,
            url: "https://cdn.example.com/doc.pdf".into(),
            proxy_url: None,
            content_type: None,
        };
        let json = serde_json::to_string(&att).unwrap();
        assert!(!json.contains("proxy_url"));
        assert!(!json.contains("content_type"));
    }

    #[test]
    fn attachment_clone_and_debug() {
        let att = Attachment {
            id: "a3".into(),
            filename: "img.png".into(),
            size: 4096,
            url: "https://cdn.example.com/img.png".into(),
            proxy_url: None,
            content_type: Some("image/png".into()),
        };
        let cloned = att.clone();
        assert_eq!(cloned.filename, "img.png");
        let dbg = format!("{att:?}");
        assert!(dbg.contains("img.png"));
    }

    // ---- GatewayPayload ----

    #[test]
    fn gateway_payload_none_fields_omitted() {
        let payload = GatewayPayload {
            op: 11,
            d: None,
            s: None,
            t: None,
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"op\":11"));
        assert!(!json.contains("\"d\""));
        assert!(!json.contains("\"s\""));
        assert!(!json.contains("\"t\""));
    }

    #[test]
    fn gateway_payload_clone_and_debug() {
        let payload = GatewayPayload {
            op: 0,
            d: Some(json!(null)),
            s: Some(1),
            t: Some("TEST".into()),
        };
        let cloned = payload.clone();
        assert_eq!(cloned.op, 0);
        assert_eq!(cloned.t.as_deref(), Some("TEST"));
        let dbg = format!("{payload:?}");
        assert!(dbg.contains("TEST"));
    }

    // ---- GatewayIdentify ----

    #[test]
    fn gateway_identify_without_shard() {
        let identify = GatewayIdentify {
            token: "Bot TOKEN".into(),
            intents: 513,
            properties: GatewayProperties {
                os: "linux".into(),
                browser: "fcp-discord".into(),
                device: "fcp-discord".into(),
            },
            shard: None,
        };
        let json = serde_json::to_string(&identify).unwrap();
        assert!(!json.contains("shard"));
        assert!(json.contains("\"intents\":513"));
        let back: GatewayIdentify = serde_json::from_str(&json).unwrap();
        assert!(back.shard.is_none());
        assert_eq!(back.intents, 513);
    }

    #[test]
    fn gateway_identify_with_shard() {
        let identify = GatewayIdentify {
            token: "Bot TOKEN".into(),
            intents: 32767,
            properties: GatewayProperties {
                os: "linux".into(),
                browser: "fcp-discord".into(),
                device: "fcp-discord".into(),
            },
            shard: Some([0, 4]),
        };
        let json = serde_json::to_string(&identify).unwrap();
        assert!(json.contains("\"shard\":[0,4]"));
        let back: GatewayIdentify = serde_json::from_str(&json).unwrap();
        assert_eq!(back.shard, Some([0, 4]));
    }

    #[test]
    fn gateway_identify_clone_and_debug() {
        let identify = GatewayIdentify {
            token: "secret".into(),
            intents: 1,
            properties: GatewayProperties {
                os: "macos".into(),
                browser: "test".into(),
                device: "test".into(),
            },
            shard: None,
        };
        let cloned = identify.clone();
        assert_eq!(cloned.token, "secret");
        let dbg = format!("{identify:?}");
        assert!(
            !dbg.contains("secret"),
            "Debug output must not contain the raw token"
        );
        assert!(
            dbg.contains("[REDACTED]"),
            "Debug output should show [REDACTED] for token"
        );
    }

    // ---- GatewayProperties ----

    #[test]
    fn gateway_properties_roundtrip() {
        let props = GatewayProperties {
            os: "windows".into(),
            browser: "chrome".into(),
            device: "desktop".into(),
        };
        let json = serde_json::to_string(&props).unwrap();
        let back: GatewayProperties = serde_json::from_str(&json).unwrap();
        assert_eq!(back.os, "windows");
        assert_eq!(back.browser, "chrome");
        assert_eq!(back.device, "desktop");
    }

    #[test]
    fn gateway_properties_clone_and_debug() {
        let props = GatewayProperties {
            os: "linux".into(),
            browser: "fcp".into(),
            device: "fcp".into(),
        };
        let cloned = props.clone();
        assert_eq!(cloned.os, "linux");
        let dbg = format!("{props:?}");
        assert!(dbg.contains("linux"));
    }

    // ---- GatewayReady ----

    #[test]
    fn gateway_ready_with_empty_guilds() {
        let ready = GatewayReady {
            v: 10,
            user: User {
                id: "bot1".into(),
                username: "mybot".into(),
                discriminator: None,
                global_name: None,
                avatar: None,
                bot: true,
            },
            session_id: "sess123".into(),
            resume_gateway_url: "wss://gateway.discord.gg".into(),
            guilds: vec![],
        };
        let json = serde_json::to_string(&ready).unwrap();
        let back: GatewayReady = serde_json::from_str(&json).unwrap();
        assert_eq!(back.v, 10);
        assert_eq!(back.guilds, [] as [serde_json::Value; 0]);
        assert_eq!(back.session_id, "sess123");
    }

    #[test]
    fn gateway_ready_guilds_default() {
        // guilds has #[serde(default)], so it can be omitted
        let json = json!({
            "v": 10,
            "user": {"id": "u1", "username": "bot"},
            "session_id": "s1",
            "resume_gateway_url": "wss://gw.test"
        });
        let ready: GatewayReady = serde_json::from_value(json).unwrap();
        assert_eq!(ready.guilds, [] as [serde_json::Value; 0]);
    }

    #[test]
    fn gateway_ready_clone_and_debug() {
        let ready = GatewayReady {
            v: 9,
            user: User {
                id: "u".into(),
                username: "b".into(),
                discriminator: None,
                global_name: None,
                avatar: None,
                bot: true,
            },
            session_id: "s".into(),
            resume_gateway_url: "wss://test".into(),
            guilds: vec![json!({"id": "g1", "unavailable": true})],
        };
        let cloned = ready.clone();
        assert_eq!(cloned.guilds.len(), 1);
        let dbg = format!("{ready:?}");
        assert!(dbg.contains("GatewayReady"));
    }

    // ---- GatewayHello ----

    #[test]
    fn gateway_hello_clone_and_debug() {
        let hello = GatewayHello {
            heartbeat_interval: 45000,
        };
        let cloned = hello.clone();
        assert_eq!(cloned.heartbeat_interval, 45000);
        let dbg = format!("{hello:?}");
        assert!(dbg.contains("45000"));
    }

    // ---- GatewayResume ----

    #[test]
    fn gateway_resume_clone_and_debug() {
        let resume = GatewayResume {
            token: "tok".into(),
            session_id: "sid".into(),
            seq: 55,
        };
        let cloned = resume.clone();
        assert_eq!(cloned.seq, 55);
        let dbg = format!("{resume:?}");
        assert!(dbg.contains("55"));
    }

    // ---- MessageReference ----

    #[test]
    fn message_reference_all_none_optionals() {
        let mref = MessageReference {
            message_id: "m10".into(),
            channel_id: None,
            guild_id: None,
        };
        let json = serde_json::to_string(&mref).unwrap();
        assert!(!json.contains("channel_id"));
        assert!(!json.contains("guild_id"));
        let back: MessageReference = serde_json::from_str(&json).unwrap();
        assert_eq!(back.message_id, "m10");
        assert!(back.channel_id.is_none());
        assert!(back.guild_id.is_none());
    }

    #[test]
    fn message_reference_full_roundtrip() {
        let mref = MessageReference {
            message_id: "m11".into(),
            channel_id: Some("ch99".into()),
            guild_id: Some("g99".into()),
        };
        let json = serde_json::to_string(&mref).unwrap();
        assert!(json.contains("channel_id"));
        assert!(json.contains("guild_id"));
        let back: MessageReference = serde_json::from_str(&json).unwrap();
        assert_eq!(back.channel_id.as_deref(), Some("ch99"));
        assert_eq!(back.guild_id.as_deref(), Some("g99"));
    }

    #[test]
    fn message_reference_clone_and_debug() {
        let mref = MessageReference {
            message_id: "m12".into(),
            channel_id: None,
            guild_id: None,
        };
        let cloned = mref.clone();
        assert_eq!(cloned.message_id, "m12");
        let dbg = format!("{mref:?}");
        assert!(dbg.contains("m12"));
    }

    // ---- CreateMessage skip_serializing_if ----

    #[test]
    fn create_message_empty_embeds_omitted() {
        let msg = CreateMessage {
            content: Some("Hi".into()),
            tts: None,
            embeds: vec![],
            message_reference: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        // embeds use skip_serializing_if = "Vec::is_empty"
        assert!(!json.contains("embeds"));
        assert!(!json.contains("tts"));
        assert!(!json.contains("message_reference"));
    }

    #[test]
    fn create_message_with_embeds_present() {
        let msg = CreateMessage {
            content: None,
            tts: Some(true),
            embeds: vec![Embed {
                title: Some("E".into()),
                ..Default::default()
            }],
            message_reference: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"embeds\""));
        assert!(json.contains("\"tts\":true"));
        assert!(!json.contains("content"));
    }

    #[test]
    fn create_message_clone_and_debug() {
        let msg = CreateMessage {
            content: Some("test".into()),
            tts: None,
            embeds: vec![],
            message_reference: None,
        };
        let cloned = msg.clone();
        assert_eq!(cloned.content.as_deref(), Some("test"));
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("test"));
    }

    // ---- Roundtrip for types not yet tested ----

    #[test]
    fn embed_roundtrip_all_fields() {
        let embed = Embed {
            title: Some("T".into()),
            description: Some("D".into()),
            url: Some("https://example.com".into()),
            color: Some(0x123456),
            fields: vec![
                EmbedField {
                    name: "F1".into(),
                    value: "V1".into(),
                    inline: false,
                },
                EmbedField {
                    name: "F2".into(),
                    value: "V2".into(),
                    inline: true,
                },
            ],
            footer: Some(EmbedFooter {
                text: "foot".into(),
                icon_url: Some("https://foot.icon".into()),
            }),
            image: Some(EmbedImage {
                url: "https://img".into(),
            }),
            thumbnail: Some(EmbedThumbnail {
                url: "https://thumb".into(),
            }),
            author: Some(EmbedAuthor {
                name: "auth".into(),
                url: Some("https://auth".into()),
                icon_url: Some("https://auth.icon".into()),
            }),
        };
        let json = serde_json::to_string(&embed).unwrap();
        let back: Embed = serde_json::from_str(&json).unwrap();
        assert_eq!(back.title.as_deref(), Some("T"));
        assert_eq!(back.url.as_deref(), Some("https://example.com"));
        assert_eq!(back.fields.len(), 2);
        assert!(!back.fields[0].inline);
        assert!(back.fields[1].inline);
        assert_eq!(
            back.footer.unwrap().icon_url.as_deref(),
            Some("https://foot.icon")
        );
        assert_eq!(back.thumbnail.unwrap().url, "https://thumb");
        assert_eq!(back.author.unwrap().url.as_deref(), Some("https://auth"));
    }

    #[test]
    fn attachment_full_roundtrip() {
        let att = Attachment {
            id: "a5".into(),
            filename: "report.xlsx".into(),
            size: 999_999,
            url: "https://cdn.example.com/report.xlsx".into(),
            proxy_url: Some("https://proxy.example.com/report.xlsx".into()),
            content_type: Some(
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet".into(),
            ),
        };
        let json = serde_json::to_string(&att).unwrap();
        let back: Attachment = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "a5");
        assert_eq!(back.size, 999_999);
        assert!(back.proxy_url.is_some());
        assert!(back.content_type.unwrap().contains("spreadsheetml"));
    }

    #[test]
    fn gateway_resume_roundtrip() {
        let resume = GatewayResume {
            token: "Bot abc123".into(),
            session_id: "session_xyz".into(),
            seq: 42,
        };
        let json = serde_json::to_string(&resume).unwrap();
        let back: GatewayResume = serde_json::from_str(&json).unwrap();
        assert_eq!(back.token, "Bot abc123");
        assert_eq!(back.session_id, "session_xyz");
        assert_eq!(back.seq, 42);
    }

    // ── User additional tests ─────────────────────────────────────

    #[test]
    fn user_minimal_deser() {
        let json = json!({"id": "u1", "username": "bot"});
        let user: User = serde_json::from_value(json).unwrap();
        assert_eq!(user.id, "u1");
        assert!(!user.bot);
        assert!(user.discriminator.is_none());
        assert!(user.global_name.is_none());
        assert!(user.avatar.is_none());
    }

    #[test]
    fn user_full_roundtrip() {
        let user = User {
            id: "123".into(),
            username: "testuser".into(),
            discriminator: Some("0001".into()),
            global_name: Some("Test User".into()),
            avatar: Some("abc123hash".into()),
            bot: true,
        };
        let json = serde_json::to_string(&user).unwrap();
        let back: User = serde_json::from_str(&json).unwrap();
        assert_eq!(back.discriminator.as_deref(), Some("0001"));
        assert_eq!(back.global_name.as_deref(), Some("Test User"));
        assert!(back.bot);
    }

    #[test]
    fn user_skip_serializing_none() {
        let user = User {
            id: "1".into(),
            username: "u".into(),
            discriminator: None,
            global_name: None,
            avatar: None,
            bot: false,
        };
        let json = serde_json::to_string(&user).unwrap();
        assert!(!json.contains("discriminator"));
        assert!(!json.contains("global_name"));
        assert!(!json.contains("avatar"));
    }

    // ── Guild tests ───────────────────────────────────────────────

    #[test]
    fn guild_minimal_deser() {
        let json = json!({"id": "g1", "name": "Test Guild"});
        let guild: Guild = serde_json::from_value(json).unwrap();
        assert_eq!(guild.id, "g1");
        assert!(guild.icon.is_none());
        assert!(guild.owner_id.is_none());
    }

    #[test]
    fn guild_full_roundtrip() {
        let guild = Guild {
            id: "g2".into(),
            name: "My Server".into(),
            icon: Some("iconhash".into()),
            owner_id: Some("u99".into()),
        };
        let json = serde_json::to_string(&guild).unwrap();
        let back: Guild = serde_json::from_str(&json).unwrap();
        assert_eq!(back.owner_id.as_deref(), Some("u99"));
    }

    #[test]
    fn guild_clone_and_debug_no_icon() {
        let guild = Guild {
            id: "g3".into(),
            name: "Clone Guild".into(),
            icon: None,
            owner_id: None,
        };
        let cloned = guild.clone();
        assert_eq!(cloned.name, "Clone Guild");
        let dbg = format!("{guild:?}");
        assert!(dbg.contains("Clone Guild"));
    }

    // ── Channel tests ─────────────────────────────────────────────

    #[test]
    fn channel_minimal_deser() {
        let json = json!({"id": "c1", "type": 0});
        let ch: Channel = serde_json::from_value(json).unwrap();
        assert_eq!(ch.id, "c1");
        assert_eq!(ch.channel_type, 0);
        assert!(ch.name.is_none());
        assert!(ch.topic.is_none());
    }

    #[test]
    fn channel_full_roundtrip() {
        let ch = Channel {
            id: "c2".into(),
            channel_type: 2,
            guild_id: Some("g1".into()),
            name: Some("voice-chat".into()),
            topic: Some("Voice channel".into()),
        };
        let json = serde_json::to_string(&ch).unwrap();
        let back: Channel = serde_json::from_str(&json).unwrap();
        assert_eq!(back.channel_type, 2);
        assert_eq!(back.topic.as_deref(), Some("Voice channel"));
    }

    #[test]
    fn channel_clone_and_debug_text_channel() {
        let ch = Channel {
            id: "c3".into(),
            channel_type: 0,
            guild_id: None,
            name: Some("general".into()),
            topic: None,
        };
        let cloned = ch.clone();
        assert_eq!(cloned.name.as_deref(), Some("general"));
        let dbg = format!("{ch:?}");
        assert!(dbg.contains("general"));
    }

    // ── Embed default test ────────────────────────────────────────

    #[test]
    fn embed_default_all_none() {
        let embed = Embed::default();
        assert!(embed.title.is_none());
        assert!(embed.description.is_none());
        assert!(embed.url.is_none());
        assert!(embed.color.is_none());
        assert!(embed.fields.is_empty());
        assert!(embed.footer.is_none());
        assert!(embed.image.is_none());
        assert!(embed.thumbnail.is_none());
        assert!(embed.author.is_none());
    }

    #[test]
    fn embed_field_clone_and_debug_inline() {
        let field = EmbedField {
            name: "Key".into(),
            value: "Val".into(),
            inline: true,
        };
        let cloned = field.clone();
        assert_eq!(cloned.name, "Key");
        assert!(cloned.inline);
        let dbg = format!("{field:?}");
        assert!(dbg.contains("EmbedField"));
    }

    #[test]
    fn embed_footer_clone_and_debug_full_text() {
        let footer = EmbedFooter {
            text: "Footer text".into(),
            icon_url: None,
        };
        let cloned = footer.clone();
        assert_eq!(cloned.text, "Footer text");
        let dbg = format!("{footer:?}");
        assert!(dbg.contains("EmbedFooter"));
    }

    #[test]
    fn gateway_hello_roundtrip() {
        let hello = GatewayHello {
            heartbeat_interval: 41250,
        };
        let json = serde_json::to_string(&hello).unwrap();
        let back: GatewayHello = serde_json::from_str(&json).unwrap();
        assert_eq!(back.heartbeat_interval, 41250);
    }

    #[test]
    fn embed_image_clone_and_debug_full_url() {
        let img = EmbedImage {
            url: "https://img.example.com/pic.png".into(),
        };
        let cloned = img.clone();
        assert_eq!(cloned.url, "https://img.example.com/pic.png");
        let dbg = format!("{img:?}");
        assert!(dbg.contains("EmbedImage"));
    }

    #[test]
    fn embed_thumbnail_clone_and_debug_jpg() {
        let thumb = EmbedThumbnail {
            url: "https://thumb.example.com/t.jpg".into(),
        };
        let cloned = thumb.clone();
        assert_eq!(cloned.url, "https://thumb.example.com/t.jpg");
        let dbg = format!("{thumb:?}");
        assert!(dbg.contains("EmbedThumbnail"));
    }

    #[test]
    fn embed_author_clone_and_debug_with_url() {
        let author = EmbedAuthor {
            name: "Author Name".into(),
            url: Some("https://author.com".into()),
            icon_url: None,
        };
        let cloned = author.clone();
        assert_eq!(cloned.name, "Author Name");
        let dbg = format!("{author:?}");
        assert!(dbg.contains("EmbedAuthor"));
    }

    #[test]
    fn user_missing_id_fails() {
        let json = json!({"username": "test"});
        assert!(serde_json::from_value::<User>(json).is_err());
    }

    #[test]
    fn guild_missing_name_fails() {
        let json = json!({"id": "g1"});
        assert!(serde_json::from_value::<Guild>(json).is_err());
    }

    #[test]
    fn channel_missing_type_fails() {
        let json = json!({"id": "c1"});
        assert!(serde_json::from_value::<Channel>(json).is_err());
    }
}
