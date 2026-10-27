//! Slack API types.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Slack message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    #[serde(rename = "type", default)]
    pub message_type: String,
    #[serde(default)]
    pub user: Option<String>,
    pub text: String,
    pub ts: String,
    #[serde(default)]
    pub thread_ts: Option<String>,
    #[serde(default)]
    pub reply_count: Option<u32>,
    #[serde(default)]
    pub reactions: Option<Vec<Reaction>>,
    #[serde(default)]
    pub files: Option<Vec<SlackFile>>,
    #[serde(default)]
    pub bot_id: Option<String>,
    #[serde(default)]
    pub blocks: Option<Vec<Value>>,
}

/// Slack reaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reaction {
    pub name: String,
    pub count: u32,
    #[serde(default)]
    pub users: Vec<String>,
}

/// Slack channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct Channel {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub is_channel: bool,
    #[serde(default)]
    pub is_group: bool,
    #[serde(default)]
    pub is_im: bool,
    #[serde(default)]
    pub is_archived: bool,
    #[serde(default)]
    pub is_private: bool,
    #[serde(default)]
    pub num_members: u32,
    #[serde(default)]
    pub topic: Option<TopicPurpose>,
    #[serde(default)]
    pub purpose: Option<TopicPurpose>,
}

/// Slack channel topic or purpose.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopicPurpose {
    pub value: String,
    #[serde(default)]
    pub creator: String,
    #[serde(default)]
    pub last_set: u64,
}

/// Slack user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub real_name: Option<String>,
    #[serde(default)]
    pub is_bot: bool,
    #[serde(default)]
    pub is_admin: bool,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub profile: Option<UserProfile>,
}

/// Slack user profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub image_48: Option<String>,
    #[serde(default)]
    pub status_text: Option<String>,
    #[serde(default)]
    pub status_emoji: Option<String>,
}

/// Slack file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackFile {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub mimetype: Option<String>,
    #[serde(default)]
    pub filetype: Option<String>,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub url_private: Option<String>,
    #[serde(default)]
    pub url_private_download: Option<String>,
}

/// Slack API envelope for responses.
#[derive(Debug, Clone, Deserialize)]
pub struct SlackApiResponse<T> {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(flatten)]
    pub data: Option<T>,
}

/// Conversations.history response data.
#[derive(Debug, Clone, Deserialize)]
pub struct HistoryData {
    pub messages: Vec<Message>,
    #[serde(default)]
    pub has_more: bool,
    #[serde(default)]
    pub response_metadata: Option<ResponseMetadata>,
}

/// Search response data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchData {
    pub messages: SearchMatches,
}

/// Search matches container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchMatches {
    pub total: u32,
    pub matches: Vec<Message>,
}

/// Channel list response data.
#[derive(Debug, Clone, Deserialize)]
pub struct ChannelListData {
    pub channels: Vec<Channel>,
    #[serde(default)]
    pub response_metadata: Option<ResponseMetadata>,
}

/// User info response data.
#[derive(Debug, Clone, Deserialize)]
pub struct UserInfoData {
    pub user: User,
}

/// File upload response data.
#[derive(Debug, Clone, Deserialize)]
pub struct FileUploadData {
    pub file: SlackFile,
}

/// Upload reservation returned by `files.getUploadURLExternal`.
///
/// The URL is a bearer capability and must never be logged or returned to callers.
#[derive(Deserialize)]
pub struct ExternalUploadData {
    pub upload_url: String,
    pub file_id: String,
}

/// Files finalized by `files.completeUploadExternal`.
#[derive(Debug, Clone, Deserialize)]
pub struct CompleteUploadData {
    pub files: Vec<SlackFile>,
}

/// Topic set response data.
#[derive(Debug, Clone, Deserialize)]
pub struct TopicSetData {
    pub topic: String,
}

/// Post message response data.
#[derive(Debug, Clone, Deserialize)]
pub struct PostMessageData {
    pub channel: String,
    pub ts: String,
    pub message: Message,
}

/// Response metadata (pagination cursor).
#[derive(Debug, Clone, Deserialize)]
pub struct ResponseMetadata {
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// Result of Slack `auth.test` — identifies the token holder.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthTestInfo {
    pub url: String,
    pub team: String,
    pub user: String,
    pub team_id: String,
    pub user_id: String,
    #[serde(default)]
    pub bot_id: Option<String>,
    #[serde(default)]
    pub is_enterprise_install: bool,
}

/// auth.test response wrapper.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthTestData {
    pub url: String,
    pub team: String,
    pub user: String,
    pub team_id: String,
    pub user_id: String,
    #[serde(default)]
    pub bot_id: Option<String>,
    #[serde(default)]
    pub is_enterprise_install: bool,
}

/// apps.connections.open response data for Socket Mode.
#[derive(Debug, Clone, Deserialize)]
pub struct SocketModeOpenData {
    pub url: String,
}

/// Audit receipt for side-effecting operations.
#[derive(Debug, Clone, Serialize)]
pub struct OperationReceipt {
    pub operation: String,
    pub effect: String,
    pub resource: String,
    pub timestamp: String,
}

/// Provisioning doctor report for readiness validation.
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ---- Message ----

    #[test]
    fn message_serde_roundtrip() {
        let msg = Message {
            message_type: "message".to_string(),
            user: Some("U123".to_string()),
            text: "Hello!".to_string(),
            ts: "1234567890.123456".to_string(),
            thread_ts: None,
            reply_count: None,
            reactions: None,
            files: None,
            bot_id: None,
            blocks: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: Message = serde_json::from_str(&json).unwrap();
        assert_eq!(back.text, "Hello!");
        assert_eq!(back.user, Some("U123".to_string()));
    }

    #[test]
    fn message_deserialize_minimal() {
        let json = r#"{"text":"hi","ts":"123.456"}"#;
        let msg: Message = serde_json::from_str(json).unwrap();
        assert_eq!(msg.text, "hi");
        assert!(msg.user.is_none());
        assert!(msg.reactions.is_none());
        assert!(msg.files.is_none());
    }

    // ---- Channel ----

    #[test]
    fn channel_serde_with_booleans() {
        let ch = Channel {
            id: "C123".to_string(),
            name: "general".to_string(),
            is_channel: true,
            is_group: false,
            is_im: false,
            is_archived: false,
            is_private: false,
            num_members: 42,
            topic: Some(TopicPurpose {
                value: "Welcome".to_string(),
                creator: "U001".to_string(),
                last_set: 1_000_000,
            }),
            purpose: None,
        };
        let json = serde_json::to_string(&ch).unwrap();
        let back: Channel = serde_json::from_str(&json).unwrap();
        assert!(back.is_channel);
        assert_eq!(back.num_members, 42);
        assert!(back.topic.is_some());
    }

    #[test]
    fn channel_deserialize_defaults() {
        let json = r#"{"id":"C1","name":"test"}"#;
        let ch: Channel = serde_json::from_str(json).unwrap();
        assert!(!ch.is_channel);
        assert!(!ch.is_archived);
        assert_eq!(ch.num_members, 0);
    }

    // ---- User ----

    #[test]
    fn user_serde_roundtrip() {
        let user = User {
            id: "U123".to_string(),
            name: "testuser".to_string(),
            real_name: Some("Test User".to_string()),
            is_bot: false,
            is_admin: true,
            deleted: false,
            profile: Some(UserProfile {
                display_name: "Test".to_string(),
                email: Some("test@example.com".to_string()),
                image_48: None,
                status_text: None,
                status_emoji: None,
            }),
        };
        let json = serde_json::to_string(&user).unwrap();
        let back: User = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, "U123");
        assert!(back.is_admin);
        assert!(back.profile.is_some());
    }

    #[test]
    fn user_deserialize_minimal() {
        let json = r#"{"id":"U1","text":"unused","name":"","real_name":null}"#;
        let user: User = serde_json::from_str(json).unwrap();
        assert!(!user.is_bot);
        assert!(!user.deleted);
        assert!(user.profile.is_none());
    }

    // ---- Reaction ----

    #[test]
    fn reaction_serde() {
        let reaction = Reaction {
            name: "thumbsup".to_string(),
            count: 5,
            users: vec!["U1".to_string(), "U2".to_string()],
        };
        let json = serde_json::to_string(&reaction).unwrap();
        let back: Reaction = serde_json::from_str(&json).unwrap();
        assert_eq!(back.count, 5);
        assert_eq!(back.users.len(), 2);
    }

    // ---- SlackFile ----

    #[test]
    fn slack_file_serde() {
        let file = SlackFile {
            id: "F123".to_string(),
            name: Some("report.pdf".to_string()),
            title: Some("Q1 Report".to_string()),
            mimetype: Some("application/pdf".to_string()),
            filetype: Some("pdf".to_string()),
            size: 1_048_576,
            url_private: Some("https://files.slack.com/...".to_string()),
            url_private_download: None,
        };
        let json = serde_json::to_string(&file).unwrap();
        let back: SlackFile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.size, 1_048_576);
    }

    // ---- SlackApiResponse ----

    #[test]
    fn slack_api_response_ok() {
        let json =
            r#"{"ok":true,"channel":"C1","ts":"123.456","message":{"text":"hi","ts":"123.456"}}"#;
        let resp: SlackApiResponse<PostMessageData> = serde_json::from_str(json).unwrap();
        assert!(resp.ok);
        assert!(resp.error.is_none());
    }

    #[test]
    fn slack_api_response_error() {
        let json = r#"{"ok":false,"error":"channel_not_found"}"#;
        let resp: SlackApiResponse<PostMessageData> = serde_json::from_str(json).unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.error.as_deref(), Some("channel_not_found"));
    }

    // ---- AuthTestInfo ----

    #[test]
    fn auth_test_info_serde() {
        let info = AuthTestInfo {
            url: "https://team.slack.com/".to_string(),
            team: "Test Team".to_string(),
            user: "testbot".to_string(),
            team_id: "T123".to_string(),
            user_id: "U123".to_string(),
            bot_id: Some("B123".to_string()),
            is_enterprise_install: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: AuthTestInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.team_id, "T123");
        assert_eq!(back.bot_id, Some("B123".to_string()));
    }

    // ---- SearchData ----

    #[test]
    fn search_data_serde() {
        let data = SearchData {
            messages: SearchMatches {
                total: 1,
                matches: vec![Message {
                    message_type: "message".to_string(),
                    user: Some("U1".to_string()),
                    text: "found it".to_string(),
                    ts: "123.456".to_string(),
                    thread_ts: None,
                    reply_count: None,
                    reactions: None,
                    files: None,
                    bot_id: None,
                    blocks: None,
                }],
            },
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: SearchData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.messages.total, 1);
        assert_eq!(back.messages.matches.len(), 1);
    }

    // ---- ResponseMetadata ----

    #[test]
    fn response_metadata_with_cursor() {
        let json = r#"{"next_cursor":"abc123"}"#;
        let meta: ResponseMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.next_cursor.as_deref(), Some("abc123"));
    }

    #[test]
    fn response_metadata_empty() {
        let json = "{}";
        let meta: ResponseMetadata = serde_json::from_str(json).unwrap();
        assert!(meta.next_cursor.is_none());
    }

    // ---- OperationReceipt ----

    #[test]
    fn operation_receipt_serialize() {
        let receipt = OperationReceipt {
            operation: "post_message".to_string(),
            effect: "created".to_string(),
            resource: "message".to_string(),
            timestamp: "2026-03-03T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("post_message"));
    }

    // ---- DoctorReport ----

    #[test]
    fn doctor_report_serialize() {
        let report = DoctorReport {
            ready: true,
            checks: vec![DoctorCheck {
                name: "auth".to_string(),
                passed: true,
                message: "Token valid".to_string(),
            }],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"ready\":true"));
        assert!(json.contains("\"passed\":true"));
    }

    // ---- Message with all optional fields ----

    #[test]
    fn message_with_reactions_and_files() {
        let msg = Message {
            message_type: "message".to_string(),
            user: Some("U123".to_string()),
            text: "Check this out".to_string(),
            ts: "1700000000.000001".to_string(),
            thread_ts: Some("1700000000.000000".to_string()),
            reply_count: Some(5),
            reactions: Some(vec![
                Reaction {
                    name: "thumbsup".to_string(),
                    count: 3,
                    users: vec!["U1".into(), "U2".into(), "U3".into()],
                },
                Reaction {
                    name: "heart".to_string(),
                    count: 1,
                    users: vec!["U4".into()],
                },
            ]),
            files: Some(vec![SlackFile {
                id: "F001".to_string(),
                name: Some("doc.pdf".to_string()),
                title: None,
                mimetype: Some("application/pdf".to_string()),
                filetype: Some("pdf".to_string()),
                size: 2048,
                url_private: None,
                url_private_download: None,
            }]),
            bot_id: Some("B999".to_string()),
            blocks: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let back: Message = serde_json::from_str(&json).unwrap();
        assert_eq!(back.thread_ts, Some("1700000000.000000".to_string()));
        assert_eq!(back.reply_count, Some(5));
        assert_eq!(back.reactions.as_ref().unwrap().len(), 2);
        assert_eq!(back.files.as_ref().unwrap().len(), 1);
        assert_eq!(back.bot_id, Some("B999".to_string()));
    }

    #[test]
    fn message_clone() {
        let msg = Message {
            message_type: "message".to_string(),
            user: Some("U1".to_string()),
            text: "clone me".to_string(),
            ts: "100.001".to_string(),
            thread_ts: None,
            reply_count: None,
            reactions: None,
            files: None,
            bot_id: None,
            blocks: None,
        };
        let cloned = msg.clone();
        assert_eq!(cloned.text, msg.text);
        assert_eq!(cloned.ts, msg.ts);
    }

    #[test]
    fn message_debug() {
        let msg = Message {
            message_type: "message".to_string(),
            user: None,
            text: "debug test".to_string(),
            ts: "1.0".to_string(),
            thread_ts: None,
            reply_count: None,
            reactions: None,
            files: None,
            bot_id: None,
            blocks: None,
        };
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("Message"));
        assert!(dbg.contains("debug test"));
    }

    #[test]
    fn message_with_bot_id_no_user() {
        let json = r#"{"text":"bot msg","ts":"1.0","bot_id":"B001"}"#;
        let msg: Message = serde_json::from_str(json).unwrap();
        assert!(msg.user.is_none());
        assert_eq!(msg.bot_id, Some("B001".to_string()));
    }

    // ---- Reaction edge cases ----

    #[test]
    fn reaction_empty_users() {
        let reaction = Reaction {
            name: "wave".to_string(),
            count: 0,
            users: vec![],
        };
        let json = serde_json::to_string(&reaction).unwrap();
        let back: Reaction = serde_json::from_str(&json).unwrap();
        assert!(back.users.is_empty());
        assert_eq!(back.count, 0);
    }

    #[test]
    fn reaction_clone() {
        let reaction = Reaction {
            name: "fire".to_string(),
            count: 10,
            users: vec!["U1".into()],
        };
        #[allow(clippy::redundant_clone)]
        let cloned = reaction.clone();
        assert_eq!(cloned.name, "fire");
        assert_eq!(cloned.count, 10);
        assert_eq!(cloned.users, vec!["U1".to_string()]);
    }

    #[test]
    fn reaction_deserialize_default_users() {
        let json = r#"{"name":"smile","count":2}"#;
        let r: Reaction = serde_json::from_str(json).unwrap();
        assert!(r.users.is_empty());
    }

    // ---- Channel with purpose ----

    #[test]
    fn channel_with_both_topic_and_purpose() {
        let ch = Channel {
            id: "C200".to_string(),
            name: "design".to_string(),
            is_channel: true,
            is_group: false,
            is_im: false,
            is_archived: false,
            is_private: true,
            num_members: 7,
            topic: Some(TopicPurpose {
                value: "Design discussions".to_string(),
                creator: "U001".to_string(),
                last_set: 1_700_000_000,
            }),
            purpose: Some(TopicPurpose {
                value: "For all design work".to_string(),
                creator: "U002".to_string(),
                last_set: 1_600_000_000,
            }),
        };
        let json = serde_json::to_string(&ch).unwrap();
        let back: Channel = serde_json::from_str(&json).unwrap();
        assert!(back.topic.is_some());
        assert!(back.purpose.is_some());
        assert_eq!(back.purpose.unwrap().value, "For all design work");
        assert!(back.is_private);
    }

    #[test]
    fn channel_clone() {
        let ch = Channel {
            id: "C1".to_string(),
            name: "test".to_string(),
            is_channel: false,
            is_group: true,
            is_im: false,
            is_archived: true,
            is_private: false,
            num_members: 3,
            topic: None,
            purpose: None,
        };
        let cloned = ch.clone();
        assert_eq!(cloned.id, ch.id);
        assert!(cloned.is_group);
        assert!(cloned.is_archived);
    }

    #[test]
    fn channel_debug() {
        let ch = Channel {
            id: "CDBG".to_string(),
            name: "dbg-chan".to_string(),
            is_channel: false,
            is_group: false,
            is_im: false,
            is_archived: false,
            is_private: false,
            num_members: 0,
            topic: None,
            purpose: None,
        };
        let dbg = format!("{ch:?}");
        assert!(dbg.contains("Channel"));
        assert!(dbg.contains("CDBG"));
    }

    // ---- TopicPurpose ----

    #[test]
    fn topic_purpose_roundtrip() {
        let tp = TopicPurpose {
            value: "Our topic".to_string(),
            creator: "U100".to_string(),
            last_set: 1_234_567_890,
        };
        let json = serde_json::to_string(&tp).unwrap();
        let back: TopicPurpose = serde_json::from_str(&json).unwrap();
        assert_eq!(back.value, "Our topic");
        assert_eq!(back.creator, "U100");
        assert_eq!(back.last_set, 1_234_567_890);
    }

    #[test]
    fn topic_purpose_defaults() {
        let json = r#"{"value":"minimal"}"#;
        let tp: TopicPurpose = serde_json::from_str(json).unwrap();
        assert_eq!(tp.value, "minimal");
        assert_eq!(tp.creator, "");
        assert_eq!(tp.last_set, 0);
    }

    // ---- User clone/debug ----

    #[test]
    fn user_clone() {
        let user = User {
            id: "UCLONE".to_string(),
            name: "cloneuser".to_string(),
            real_name: Some("Clone User".to_string()),
            is_bot: true,
            is_admin: false,
            deleted: true,
            profile: None,
        };
        #[allow(clippy::redundant_clone)]
        let cloned = user.clone();
        assert_eq!(cloned.id, "UCLONE");
        assert!(cloned.is_bot);
        assert!(cloned.deleted);
    }

    #[test]
    fn user_debug() {
        let user = User {
            id: "UDBG".to_string(),
            name: "dbguser".to_string(),
            real_name: None,
            is_bot: false,
            is_admin: false,
            deleted: false,
            profile: None,
        };
        let dbg = format!("{user:?}");
        assert!(dbg.contains("User"));
        assert!(dbg.contains("UDBG"));
    }

    // ---- UserProfile ----

    #[test]
    fn user_profile_all_fields_populated() {
        let profile = UserProfile {
            display_name: "Display Name".to_string(),
            email: Some("user@example.com".to_string()),
            image_48: Some("https://avatars.slack.com/img48.png".to_string()),
            status_text: Some("On vacation".to_string()),
            status_emoji: Some(":palm_tree:".to_string()),
        };
        let json = serde_json::to_string(&profile).unwrap();
        let back: UserProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.display_name, "Display Name");
        assert_eq!(back.email, Some("user@example.com".to_string()));
        assert_eq!(
            back.image_48,
            Some("https://avatars.slack.com/img48.png".to_string())
        );
        assert_eq!(back.status_text, Some("On vacation".to_string()));
        assert_eq!(back.status_emoji, Some(":palm_tree:".to_string()));
    }

    #[test]
    fn user_profile_all_defaults() {
        let json = "{}";
        let profile: UserProfile = serde_json::from_str(json).unwrap();
        assert_eq!(profile.display_name, "");
        assert!(profile.email.is_none());
        assert!(profile.image_48.is_none());
        assert!(profile.status_text.is_none());
        assert!(profile.status_emoji.is_none());
    }

    #[test]
    fn user_profile_roundtrip() {
        let profile = UserProfile {
            display_name: "Test".to_string(),
            email: None,
            image_48: None,
            status_text: Some("busy".to_string()),
            status_emoji: None,
        };
        let json = serde_json::to_string(&profile).unwrap();
        let back: UserProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.display_name, "Test");
        assert_eq!(back.status_text, Some("busy".to_string()));
    }

    // ---- SlackFile minimal ----

    #[test]
    fn slack_file_minimal() {
        let json = r#"{"id":"F_ONLY"}"#;
        let file: SlackFile = serde_json::from_str(json).unwrap();
        assert_eq!(file.id, "F_ONLY");
        assert!(file.name.is_none());
        assert!(file.title.is_none());
        assert!(file.mimetype.is_none());
        assert!(file.filetype.is_none());
        assert_eq!(file.size, 0);
        assert!(file.url_private.is_none());
        assert!(file.url_private_download.is_none());
    }

    #[test]
    fn slack_file_clone() {
        let file = SlackFile {
            id: "FCLONE".to_string(),
            name: Some("file.txt".to_string()),
            title: None,
            mimetype: None,
            filetype: None,
            size: 100,
            url_private: None,
            url_private_download: None,
        };
        #[allow(clippy::redundant_clone)]
        let cloned = file.clone();
        assert_eq!(cloned.id, "FCLONE");
        assert_eq!(cloned.size, 100);
    }

    #[test]
    fn slack_file_debug() {
        let file = SlackFile {
            id: "FDBG".to_string(),
            name: None,
            title: None,
            mimetype: None,
            filetype: None,
            size: 0,
            url_private: None,
            url_private_download: None,
        };
        let dbg = format!("{file:?}");
        assert!(dbg.contains("SlackFile"));
        assert!(dbg.contains("FDBG"));
    }

    // ---- SlackApiResponse with HistoryData ----

    #[test]
    fn slack_api_response_with_history_data() {
        let json = r#"{
            "ok": true,
            "messages": [
                {"text": "hello", "ts": "1.0"},
                {"text": "world", "ts": "2.0"}
            ],
            "has_more": true,
            "response_metadata": {"next_cursor": "cursor_abc"}
        }"#;
        let resp: SlackApiResponse<HistoryData> = serde_json::from_str(json).unwrap();
        assert!(resp.ok);
        let data = resp.data.unwrap();
        assert_eq!(data.messages.len(), 2);
        assert!(data.has_more);
        assert_eq!(
            data.response_metadata.unwrap().next_cursor.as_deref(),
            Some("cursor_abc")
        );
    }

    // ---- HistoryData ----

    #[test]
    fn history_data_with_messages_and_pagination() {
        let json = r#"{
            "messages": [
                {"text": "msg1", "ts": "100.0"},
                {"text": "msg2", "ts": "101.0"},
                {"text": "msg3", "ts": "102.0"}
            ],
            "has_more": true,
            "response_metadata": {"next_cursor": "next_page_token"}
        }"#;
        let data: HistoryData = serde_json::from_str(json).unwrap();
        assert_eq!(data.messages.len(), 3);
        assert!(data.has_more);
        assert_eq!(
            data.response_metadata.unwrap().next_cursor.as_deref(),
            Some("next_page_token")
        );
    }

    #[test]
    fn history_data_no_pagination() {
        let json = r#"{"messages": [{"text": "only", "ts": "1.0"}], "has_more": false}"#;
        let data: HistoryData = serde_json::from_str(json).unwrap();
        assert_eq!(data.messages.len(), 1);
        assert!(!data.has_more);
        assert!(data.response_metadata.is_none());
    }

    // ---- ChannelListData ----

    #[test]
    fn channel_list_data_with_channels() {
        let json = r#"{
            "channels": [
                {"id": "C1", "name": "general"},
                {"id": "C2", "name": "random"}
            ],
            "response_metadata": {"next_cursor": "pg2"}
        }"#;
        let data: ChannelListData = serde_json::from_str(json).unwrap();
        assert_eq!(data.channels.len(), 2);
        assert_eq!(data.channels[0].name, "general");
        assert_eq!(data.channels[1].name, "random");
        assert_eq!(
            data.response_metadata.unwrap().next_cursor.as_deref(),
            Some("pg2")
        );
    }

    #[test]
    fn channel_list_data_empty() {
        let json = r#"{"channels": []}"#;
        let data: ChannelListData = serde_json::from_str(json).unwrap();
        assert!(data.channels.is_empty());
        assert!(data.response_metadata.is_none());
    }

    // ---- UserInfoData ----

    #[test]
    fn user_info_data_roundtrip() {
        let json = r#"{
            "user": {
                "id": "U555",
                "name": "infouser",
                "is_bot": false,
                "is_admin": true,
                "deleted": false
            }
        }"#;
        let data: UserInfoData = serde_json::from_str(json).unwrap();
        assert_eq!(data.user.id, "U555");
        assert_eq!(data.user.name, "infouser");
        assert!(data.user.is_admin);
    }

    // ---- FileUploadData ----

    #[test]
    fn file_upload_data_roundtrip() {
        let json = r#"{
            "file": {
                "id": "F_UPLOAD",
                "name": "upload.txt",
                "size": 512
            }
        }"#;
        let data: FileUploadData = serde_json::from_str(json).unwrap();
        assert_eq!(data.file.id, "F_UPLOAD");
        assert_eq!(data.file.name, Some("upload.txt".to_string()));
        assert_eq!(data.file.size, 512);
    }

    // ---- TopicSetData ----

    #[test]
    fn topic_set_data_roundtrip() {
        let json = r#"{"topic": "New channel topic"}"#;
        let data: TopicSetData = serde_json::from_str(json).unwrap();
        assert_eq!(data.topic, "New channel topic");
    }

    // ---- PostMessageData ----

    #[test]
    fn post_message_data_roundtrip() {
        let json = r#"{
            "channel": "C_POST",
            "ts": "999.001",
            "message": {
                "text": "posted!",
                "ts": "999.001",
                "user": "U_POST"
            }
        }"#;
        let data: PostMessageData = serde_json::from_str(json).unwrap();
        assert_eq!(data.channel, "C_POST");
        assert_eq!(data.ts, "999.001");
        assert_eq!(data.message.text, "posted!");
        assert_eq!(data.message.user, Some("U_POST".to_string()));
    }

    // ---- AuthTestInfo without bot_id ----

    #[test]
    fn auth_test_info_no_bot_id() {
        let info = AuthTestInfo {
            url: "https://t.slack.com/".to_string(),
            team: "Team".to_string(),
            user: "user".to_string(),
            team_id: "T1".to_string(),
            user_id: "U1".to_string(),
            bot_id: None,
            is_enterprise_install: false,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: AuthTestInfo = serde_json::from_str(&json).unwrap();
        assert!(back.bot_id.is_none());
        assert!(!back.is_enterprise_install);
    }

    #[test]
    fn auth_test_info_clone() {
        let info = AuthTestInfo {
            url: "https://x.slack.com/".to_string(),
            team: "X".to_string(),
            user: "u".to_string(),
            team_id: "T0".to_string(),
            user_id: "U0".to_string(),
            bot_id: Some("B0".to_string()),
            is_enterprise_install: true,
        };
        let cloned = info.clone();
        assert_eq!(cloned.url, info.url);
        assert_eq!(cloned.bot_id, Some("B0".to_string()));
        assert!(cloned.is_enterprise_install);
    }

    #[test]
    fn auth_test_info_debug() {
        let info = AuthTestInfo {
            url: "https://dbg.slack.com/".to_string(),
            team: "DBG".to_string(),
            user: "dbg".to_string(),
            team_id: "TDBG".to_string(),
            user_id: "UDBG".to_string(),
            bot_id: None,
            is_enterprise_install: false,
        };
        let dbg = format!("{info:?}");
        assert!(dbg.contains("AuthTestInfo"));
        assert!(dbg.contains("TDBG"));
    }

    // ---- AuthTestData ----

    #[test]
    fn auth_test_data_roundtrip() {
        let json = r#"{
            "url": "https://auth.slack.com/",
            "team": "AuthTeam",
            "user": "authuser",
            "team_id": "T_AUTH",
            "user_id": "U_AUTH",
            "bot_id": "B_AUTH",
            "is_enterprise_install": true
        }"#;
        let data: AuthTestData = serde_json::from_str(json).unwrap();
        assert_eq!(data.url, "https://auth.slack.com/");
        assert_eq!(data.team, "AuthTeam");
        assert_eq!(data.user, "authuser");
        assert_eq!(data.team_id, "T_AUTH");
        assert_eq!(data.user_id, "U_AUTH");
        assert_eq!(data.bot_id, Some("B_AUTH".to_string()));
        assert!(data.is_enterprise_install);
    }

    #[test]
    fn auth_test_data_minimal() {
        let json = r#"{
            "url": "https://min.slack.com/",
            "team": "Min",
            "user": "min",
            "team_id": "T_MIN",
            "user_id": "U_MIN"
        }"#;
        let data: AuthTestData = serde_json::from_str(json).unwrap();
        assert!(data.bot_id.is_none());
        assert!(!data.is_enterprise_install);
    }

    // ---- SocketModeOpenData ----

    #[test]
    fn socket_mode_open_data_roundtrip() {
        let json = r#"{"url": "wss://wss-primary.slack.com/link/?ticket=abc123"}"#;
        let data: SocketModeOpenData = serde_json::from_str(json).unwrap();
        assert!(data.url.starts_with("wss://"));
        assert!(data.url.contains("abc123"));
    }

    // ---- OperationReceipt clone/debug ----

    #[test]
    fn operation_receipt_clone() {
        let receipt = OperationReceipt {
            operation: "delete_message".to_string(),
            effect: "deleted".to_string(),
            resource: "message".to_string(),
            timestamp: "2026-03-05T10:00:00Z".to_string(),
        };
        let cloned = receipt.clone();
        assert_eq!(cloned.operation, "delete_message");
        assert_eq!(cloned.effect, "deleted");
        assert_eq!(cloned.resource, "message");
        assert_eq!(cloned.timestamp, receipt.timestamp);
    }

    #[test]
    fn operation_receipt_debug() {
        let receipt = OperationReceipt {
            operation: "set_topic".to_string(),
            effect: "updated".to_string(),
            resource: "channel".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
        };
        let dbg = format!("{receipt:?}");
        assert!(dbg.contains("OperationReceipt"));
        assert!(dbg.contains("set_topic"));
    }

    // ---- DoctorReport with multiple checks ----

    #[test]
    fn doctor_report_multiple_checks() {
        let report = DoctorReport {
            ready: false,
            checks: vec![
                DoctorCheck {
                    name: "auth".to_string(),
                    passed: true,
                    message: "Token valid".to_string(),
                },
                DoctorCheck {
                    name: "scopes".to_string(),
                    passed: true,
                    message: "All required scopes present".to_string(),
                },
                DoctorCheck {
                    name: "connectivity".to_string(),
                    passed: false,
                    message: "Cannot reach Slack API".to_string(),
                },
            ],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"ready\":false"));
        assert!(json.contains("connectivity"));
        // One check failed, so not ready
        let failing: Vec<_> = report.checks.iter().filter(|c| !c.passed).collect();
        assert_eq!(failing.len(), 1);
        assert_eq!(failing[0].name, "connectivity");
    }

    #[test]
    fn doctor_report_empty_checks() {
        let report = DoctorReport {
            ready: true,
            checks: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"checks\":[]"));
    }

    // ---- DoctorCheck clone/debug ----

    #[test]
    fn doctor_check_clone() {
        let check = DoctorCheck {
            name: "rate_limit".to_string(),
            passed: true,
            message: "Under rate limit".to_string(),
        };
        #[allow(clippy::redundant_clone)]
        let cloned = check.clone();
        assert_eq!(cloned.name, "rate_limit");
        assert!(cloned.passed);
        assert_eq!(cloned.message, "Under rate limit");
    }

    #[test]
    fn doctor_check_debug() {
        let check = DoctorCheck {
            name: "token_expiry".to_string(),
            passed: false,
            message: "Token expires in 5 minutes".to_string(),
        };
        let dbg = format!("{check:?}");
        assert!(dbg.contains("DoctorCheck"));
        assert!(dbg.contains("token_expiry"));
        assert!(dbg.contains("false"));
    }

    // ---- SearchData additional ----

    #[test]
    fn search_data_empty_matches() {
        let data = SearchData {
            messages: SearchMatches {
                total: 0,
                matches: vec![],
            },
        };
        let json = serde_json::to_string(&data).unwrap();
        let back: SearchData = serde_json::from_str(&json).unwrap();
        assert_eq!(back.messages.total, 0);
        assert!(back.messages.matches.is_empty());
    }

    // ---- SlackApiResponse error with no data ----

    #[test]
    fn slack_api_response_error_has_no_data() {
        let json = r#"{"ok":false,"error":"invalid_auth"}"#;
        let resp: SlackApiResponse<HistoryData> = serde_json::from_str(json).unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.error.as_deref(), Some("invalid_auth"));
        // data field should fail to deserialize into HistoryData (no messages), so None
        assert!(resp.data.is_none());
    }

    // ---- Message type field rename ----

    #[test]
    fn message_type_field_renamed_from_type() {
        let json = r#"{"type":"message","text":"typed","ts":"1.0"}"#;
        let msg: Message = serde_json::from_str(json).unwrap();
        assert_eq!(msg.message_type, "message");
    }

    #[test]
    fn message_type_field_defaults_to_empty() {
        let json = r#"{"text":"no type","ts":"1.0"}"#;
        let msg: Message = serde_json::from_str(json).unwrap();
        assert_eq!(msg.message_type, "");
    }

    // ---- SlackFile with all URLs ----

    #[test]
    fn slack_file_all_urls() {
        let file = SlackFile {
            id: "F_ALL".to_string(),
            name: Some("image.png".to_string()),
            title: Some("Screenshot".to_string()),
            mimetype: Some("image/png".to_string()),
            filetype: Some("png".to_string()),
            size: 4_194_304,
            url_private: Some("https://files.slack.com/private/img.png".to_string()),
            url_private_download: Some("https://files.slack.com/download/img.png".to_string()),
        };
        let json = serde_json::to_string(&file).unwrap();
        let back: SlackFile = serde_json::from_str(&json).unwrap();
        assert_eq!(back.size, 4_194_304);
        assert!(back.url_private.is_some());
        assert!(back.url_private_download.is_some());
    }

    // ---- ResponseMetadata with empty cursor ----

    #[test]
    fn response_metadata_empty_cursor_string() {
        let json = r#"{"next_cursor":""}"#;
        let meta: ResponseMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.next_cursor.as_deref(), Some(""));
    }

    // ── Message additional tests ──────────────────────────────────

    #[test]
    fn message_minimal_deser() {
        let json = r#"{"text":"hi","ts":"1.0"}"#;
        let msg: Message = serde_json::from_str(json).unwrap();
        assert_eq!(msg.text, "hi");
        assert_eq!(msg.ts, "1.0");
        assert!(msg.user.is_none());
        assert!(msg.thread_ts.is_none());
    }

    #[test]
    fn message_with_all_fields() {
        let json = r#"{
            "type":"message",
            "text":"hello",
            "ts":"100.001",
            "user":"U123",
            "thread_ts":"100.000",
            "reply_count":5,
            "reactions":[{"name":"thumbsup","count":2,"users":["U1","U2"]}],
            "files":[{"id":"F1","name":"test.txt","size":100}]
        }"#;
        let msg: Message = serde_json::from_str(json).unwrap();
        assert_eq!(msg.user.as_deref(), Some("U123"));
        assert_eq!(msg.thread_ts.as_deref(), Some("100.000"));
        assert_eq!(msg.reply_count, Some(5));
        assert_eq!(msg.reactions.as_ref().unwrap().len(), 1);
        assert_eq!(msg.files.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn message_clone_and_debug() {
        let msg = Message {
            message_type: "message".into(),
            text: "test".into(),
            ts: "1.0".into(),
            user: Some("U1".into()),
            thread_ts: None,
            reply_count: None,
            reactions: Some(vec![]),
            files: Some(vec![]),
            bot_id: None,
            blocks: None,
        };
        let cloned = msg.clone();
        assert_eq!(cloned.text, "test");
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("Message"));
    }

    // ── Reaction tests ────────────────────────────────────────────

    #[test]
    fn reaction_roundtrip() {
        let reaction = Reaction {
            name: "heart".into(),
            count: 3,
            users: vec!["U1".into(), "U2".into(), "U3".into()],
        };
        let json = serde_json::to_string(&reaction).unwrap();
        let back: Reaction = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "heart");
        assert_eq!(back.count, 3);
        assert_eq!(back.users.len(), 3);
    }

    #[test]
    fn reaction_clone_and_debug() {
        let reaction = Reaction {
            name: "smile".into(),
            count: 1,
            users: vec!["U1".into()],
        };
        let cloned = reaction.clone();
        assert_eq!(cloned.name, "smile");
        let dbg = format!("{reaction:?}");
        assert!(dbg.contains("Reaction"));
    }

    // ── SlackFile tests ───────────────────────────────────────────

    #[test]
    fn slack_file_minimal_deser() {
        let json = r#"{"id":"F1","size":0}"#;
        let file: SlackFile = serde_json::from_str(json).unwrap();
        assert_eq!(file.id, "F1");
        assert!(file.name.is_none());
        assert!(file.title.is_none());
    }

    #[test]
    fn slack_file_clone_and_debug() {
        let file = SlackFile {
            id: "F2".into(),
            name: Some("doc.pdf".into()),
            title: Some("Doc".into()),
            mimetype: Some("application/pdf".into()),
            filetype: Some("pdf".into()),
            size: 5000,
            url_private: None,
            url_private_download: None,
        };
        let cloned = file.clone();
        assert_eq!(cloned.name.as_deref(), Some("doc.pdf"));
        let dbg = format!("{file:?}");
        assert!(dbg.contains("SlackFile"));
    }

    // ── DoctorReport serde roundtrip ──────────────────────────────

    #[test]
    fn doctor_report_serde_serialize() {
        let report = DoctorReport {
            ready: true,
            checks: vec![DoctorCheck {
                name: "auth".into(),
                passed: true,
                message: "OK".into(),
            }],
        };
        let json = serde_json::to_string(&report).unwrap();
        let val: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(val["ready"], true);
        assert_eq!(val["checks"][0]["name"], "auth");
        assert_eq!(val["checks"][0]["passed"], true);
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn doctor_report_clone() {
        let report = DoctorReport {
            ready: false,
            checks: vec![],
        };
        let cloned = report.clone();
        assert!(!cloned.ready);
        assert!(cloned.checks.is_empty());
    }

    #[test]
    fn doctor_report_debug() {
        let report = DoctorReport {
            ready: true,
            checks: vec![],
        };
        let dbg = format!("{report:?}");
        assert!(dbg.contains("DoctorReport"));
    }

    // ── Channel edge cases ─────────────────────────────────────

    #[test]
    fn channel_with_topic_and_purpose() {
        let json = json!({
            "id": "CFULL",
            "name": "dev",
            "is_channel": true,
            "is_group": false,
            "is_im": false,
            "is_archived": true,
            "is_private": true,
            "num_members": 42,
            "topic": {"value": "Development", "creator": "U1", "last_set": 100},
            "purpose": {"value": "Dev chat", "creator": "U2", "last_set": 200}
        });
        let ch: Channel = serde_json::from_value(json).unwrap();
        assert!(ch.is_channel);
        assert!(ch.is_archived);
        assert!(ch.is_private);
        assert_eq!(ch.num_members, 42);
        assert_eq!(ch.topic.as_ref().unwrap().value, "Development");
        assert_eq!(ch.purpose.as_ref().unwrap().value, "Dev chat");
    }

    #[test]
    fn channel_unicode_name() {
        let json = json!({
            "id": "CUNI",
            "name": "日本語チャンネル"
        });
        let ch: Channel = serde_json::from_value(json).unwrap();
        assert_eq!(ch.name, "日本語チャンネル");
    }

    #[test]
    fn channel_large_num_members() {
        let json = json!({
            "id": "CBIG",
            "name": "bigchan",
            "num_members": 999_999
        });
        let ch: Channel = serde_json::from_value(json).unwrap();
        assert_eq!(ch.num_members, 999_999);
    }

    // ── User edge cases ──────────────────────────────────────────

    #[test]
    fn user_with_full_profile() {
        let json = json!({
            "id": "UPROF",
            "name": "profuser",
            "real_name": "Profile User",
            "is_bot": true,
            "is_admin": true,
            "deleted": false,
            "profile": {
                "display_name": "PU",
                "email": "pu@example.com",
                "image_48": "https://img.example.com/48.png",
                "status_text": "Working",
                "status_emoji": ":computer:"
            }
        });
        let user: User = serde_json::from_value(json).unwrap();
        assert!(user.is_bot);
        assert!(user.is_admin);
        let profile = user.profile.unwrap();
        assert_eq!(profile.display_name, "PU");
        assert_eq!(profile.email.as_deref(), Some("pu@example.com"));
    }

    #[test]
    fn user_deleted_flag() {
        let json = json!({
            "id": "UDEL",
            "deleted": true
        });
        let user: User = serde_json::from_value(json).unwrap();
        assert!(user.deleted);
        assert!(!user.is_bot);
    }

    // ── TopicPurpose edge cases ──────────────────────────────────

    #[test]
    fn topic_purpose_unicode_value() {
        let tp = TopicPurpose {
            value: "Diskussion auf Deutsch".into(),
            creator: "U100".into(),
            last_set: 0,
        };
        let json = serde_json::to_value(&tp).unwrap();
        let back: TopicPurpose = serde_json::from_value(json).unwrap();
        assert_eq!(back.value, "Diskussion auf Deutsch");
        assert_eq!(back.last_set, 0);
    }

    // ── AuthTestInfo edge cases ──────────────────────────────────

    #[test]
    fn auth_test_info_enterprise_install() {
        let info = AuthTestInfo {
            url: "https://ent.slack.com/".into(),
            team: "Enterprise".into(),
            user: "admin".into(),
            team_id: "E123".into(),
            user_id: "UE1".into(),
            bot_id: None,
            is_enterprise_install: true,
        };
        let json = serde_json::to_value(&info).unwrap();
        let back: AuthTestInfo = serde_json::from_value(json).unwrap();
        assert!(back.is_enterprise_install);
    }

    // ── OperationReceipt edge cases ──────────────────────────────

    #[test]
    fn operation_receipt_long_resource() {
        let long_res = "C".to_string() + &"X".repeat(200);
        let receipt = OperationReceipt {
            operation: "slack.upload_file".into(),
            effect: "file_uploaded".into(),
            resource: long_res.clone(),
            timestamp: "2026-03-07T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&receipt).unwrap();
        assert_eq!(json["resource"], long_res);
    }

    // ── SearchData / SearchMatches tests ─────────────────────────

    #[test]
    fn search_data_empty_matches_from_json() {
        let json = json!({
            "messages": {
                "total": 0,
                "matches": []
            }
        });
        let sd: SearchData = serde_json::from_value(json).unwrap();
        assert_eq!(sd.messages.total, 0);
        assert!(sd.messages.matches.is_empty());
    }

    #[test]
    fn search_matches_with_results() {
        let json = json!({
            "total": 2,
            "matches": [
                {"type": "message", "text": "hello", "ts": "1.0"},
                {"type": "message", "text": "world", "ts": "2.0"}
            ]
        });
        let sm: SearchMatches = serde_json::from_value(json).unwrap();
        assert_eq!(sm.total, 2);
        assert_eq!(sm.matches.len(), 2);
    }
}
