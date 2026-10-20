//! Zoom API types.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// OAuth token types
// ─────────────────────────────────────────────────────────────────────────────

/// OAuth token response from Zoom Server-to-Server OAuth.
#[derive(Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("token_type", &self.token_type)
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Meeting types
// ─────────────────────────────────────────────────────────────────────────────

/// Paginated list of meetings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeetingList {
    pub page_count: Option<u32>,
    pub page_number: Option<u32>,
    pub page_size: Option<u32>,
    pub total_records: Option<u32>,
    #[serde(default)]
    pub meetings: Vec<Meeting>,
    pub next_page_token: Option<String>,
}

/// A single meeting.
#[derive(Clone, Serialize, Deserialize)]
pub struct Meeting {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub meeting_type: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agenda: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub join_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

impl std::fmt::Debug for Meeting {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Meeting")
            .field("id", &self.id)
            .field("uuid", &self.uuid)
            .field("topic", &self.topic)
            .field("meeting_type", &self.meeting_type)
            .field("start_time", &self.start_time)
            .field("duration", &self.duration)
            .field("timezone", &self.timezone)
            .field("agenda", &self.agenda)
            .field("status", &self.status)
            .field("join_url", &self.join_url)
            .field("start_url", &self.start_url)
            .field("password", &"[REDACTED]")
            .field("host_id", &self.host_id)
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Request to create a meeting.
#[derive(Clone, Serialize, Deserialize)]
pub struct CreateMeetingRequest {
    pub topic: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub meeting_type: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agenda: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl std::fmt::Debug for CreateMeetingRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateMeetingRequest")
            .field("topic", &self.topic)
            .field("meeting_type", &self.meeting_type)
            .field("start_time", &self.start_time)
            .field("duration", &self.duration)
            .field("timezone", &self.timezone)
            .field("agenda", &self.agenda)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// Request to update a meeting.
#[derive(Clone, Serialize, Deserialize)]
pub struct UpdateMeetingRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub meeting_type: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agenda: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl std::fmt::Debug for UpdateMeetingRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateMeetingRequest")
            .field("topic", &self.topic)
            .field("meeting_type", &self.meeting_type)
            .field("start_time", &self.start_time)
            .field("duration", &self.duration)
            .field("timezone", &self.timezone)
            .field("agenda", &self.agenda)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// User types
// ─────────────────────────────────────────────────────────────────────────────

/// Paginated list of users.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserList {
    pub page_count: Option<u32>,
    pub page_number: Option<u32>,
    pub page_size: Option<u32>,
    pub total_records: Option<u32>,
    #[serde(default)]
    pub users: Vec<User>,
    pub next_page_token: Option<String>,
}

/// A single Zoom user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub user_type: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Recording types
// ─────────────────────────────────────────────────────────────────────────────

/// Paginated list of recordings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingList {
    #[serde(default)]
    pub meetings: Vec<RecordingMeeting>,
    pub next_page_token: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub total_records: Option<u32>,
}

/// A meeting with recordings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingMeeting {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<u32>,
    #[serde(default)]
    pub recording_files: Vec<RecordingFile>,
}

/// A single recording file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingFile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meeting_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recording_start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recording_end: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Webinar types
// ─────────────────────────────────────────────────────────────────────────────

/// Paginated list of webinars.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebinarList {
    pub page_count: Option<u32>,
    pub page_size: Option<u32>,
    pub total_records: Option<u32>,
    #[serde(default)]
    pub webinars: Vec<Webinar>,
    pub next_page_token: Option<String>,
}

/// A single webinar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Webinar {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agenda: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_id: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub webinar_type: Option<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// API error types
// ─────────────────────────────────────────────────────────────────────────────

/// Zoom API error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    #[serde(default)]
    pub code: u32,
    #[serde(default)]
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meeting_list_deserialization() {
        let json = serde_json::json!({
            "page_count": 1,
            "page_number": 1,
            "page_size": 30,
            "total_records": 2,
            "meetings": [
                {
                    "id": 123_456_789,
                    "topic": "Stand-up",
                    "type": 2,
                    "start_time": "2026-03-21T10:00:00Z",
                    "duration": 30,
                    "status": "waiting"
                },
                {
                    "id": 987_654_321,
                    "topic": "Sprint Planning",
                    "type": 2,
                    "duration": 60
                }
            ]
        });
        let list: MeetingList = serde_json::from_value(json).unwrap();
        assert_eq!(list.meetings.len(), 2);
        assert_eq!(list.total_records, Some(2));
        assert_eq!(list.meetings[0].topic.as_deref(), Some("Stand-up"));
    }

    #[test]
    fn meeting_serialization_roundtrip() {
        let meeting = Meeting {
            id: Some(12345),
            uuid: Some("abc-123".into()),
            topic: Some("Test".into()),
            meeting_type: Some(2),
            start_time: Some("2026-03-21T10:00:00Z".into()),
            duration: Some(30),
            timezone: Some("America/New_York".into()),
            agenda: None,
            status: None,
            join_url: None,
            start_url: None,
            password: None,
            host_id: None,
            created_at: None,
        };
        let json = serde_json::to_value(&meeting).unwrap();
        assert_eq!(json["id"], 12345);
        assert!(json.get("agenda").is_none()); // skip_serializing_if = None
    }

    #[test]
    fn create_meeting_request() {
        let req = CreateMeetingRequest {
            topic: "Team Sync".into(),
            meeting_type: Some(2),
            start_time: Some("2026-03-22T14:00:00Z".into()),
            duration: Some(60),
            timezone: Some("UTC".into()),
            agenda: Some("Discuss roadmap".into()),
            password: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["topic"], "Team Sync");
        assert_eq!(json["type"], 2);
    }

    #[test]
    fn update_meeting_request_partial() {
        let req = UpdateMeetingRequest {
            topic: Some("Updated Topic".into()),
            meeting_type: None,
            start_time: None,
            duration: Some(90),
            timezone: None,
            agenda: None,
            password: None,
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["topic"], "Updated Topic");
        assert_eq!(json["duration"], 90);
        assert!(json.get("type").is_none());
    }

    #[test]
    fn user_list_deserialization() {
        let json = serde_json::json!({
            "page_count": 1,
            "page_number": 1,
            "page_size": 30,
            "total_records": 1,
            "users": [{
                "id": "user-abc-123",
                "first_name": "Jane",
                "last_name": "Doe",
                "email": "jane@example.com",
                "type": 2,
                "status": "active"
            }]
        });
        let list: UserList = serde_json::from_value(json).unwrap();
        assert_eq!(list.users.len(), 1);
        assert_eq!(list.users[0].email.as_deref(), Some("jane@example.com"));
    }

    #[test]
    fn user_deserialization() {
        let json = serde_json::json!({
            "id": "user-123",
            "first_name": "John",
            "last_name": "Smith",
            "email": "john@example.com",
            "type": 1,
            "status": "active",
            "timezone": "America/Los_Angeles",
            "created_at": "2026-01-01T00:00:00Z"
        });
        let user: User = serde_json::from_value(json).unwrap();
        assert_eq!(user.id.as_deref(), Some("user-123"));
        assert_eq!(user.user_type, Some(1));
    }

    #[test]
    fn recording_list_deserialization() {
        let json = serde_json::json!({
            "from": "2026-03-01",
            "to": "2026-03-21",
            "total_records": 1,
            "meetings": [{
                "uuid": "rec-uuid-1",
                "id": 111_222_333,
                "topic": "Recorded Meeting",
                "start_time": "2026-03-15T09:00:00Z",
                "duration": 45,
                "recording_files": [{
                    "id": "file-1",
                    "file_type": "MP4",
                    "file_size": 1_048_576,
                    "status": "completed"
                }]
            }]
        });
        let list: RecordingList = serde_json::from_value(json).unwrap();
        assert_eq!(list.meetings.len(), 1);
        assert_eq!(list.meetings[0].recording_files.len(), 1);
    }

    #[test]
    fn webinar_list_deserialization() {
        let json = serde_json::json!({
            "page_count": 1,
            "page_size": 30,
            "total_records": 1,
            "webinars": [{
                "id": 999_888_777,
                "topic": "Product Launch",
                "start_time": "2026-04-01T18:00:00Z",
                "duration": 120,
                "type": 5
            }]
        });
        let list: WebinarList = serde_json::from_value(json).unwrap();
        assert_eq!(list.webinars.len(), 1);
        assert_eq!(list.webinars[0].topic.as_deref(), Some("Product Launch"));
    }

    #[test]
    fn api_error_deserialization() {
        let json = serde_json::json!({
            "code": 3001,
            "message": "Meeting does not exist: 123456789"
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.code, 3001);
        assert!(err.message.contains("Meeting does not exist"));
    }

    #[test]
    fn token_response_deserialization() {
        let json = serde_json::json!({
            "access_token": "eyJ...",
            "token_type": "bearer",
            "expires_in": 3600
        });
        let resp: TokenResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.token_type, "bearer");
        assert_eq!(resp.expires_in, 3600);
    }

    #[test]
    fn empty_meeting_list() {
        let json = serde_json::json!({
            "page_count": 0,
            "page_size": 30,
            "total_records": 0
        });
        let list: MeetingList = serde_json::from_value(json).unwrap();
        assert!(list.meetings.is_empty());
    }

    #[test]
    fn recording_file_optional_fields() {
        let json = serde_json::json!({
            "id": "file-1",
            "file_type": "MP4"
        });
        let file: RecordingFile = serde_json::from_value(json).unwrap();
        assert_eq!(file.id.as_deref(), Some("file-1"));
        assert!(file.download_url.is_none());
    }

    #[test]
    fn token_response_debug_redacts_access_token() {
        let resp = TokenResponse {
            access_token: "super_secret_token".into(),
            token_type: "bearer".into(),
            expires_in: 3600,
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("super_secret_token"));
        assert!(dbg.contains("bearer"));
    }

    #[test]
    fn meeting_debug_redacts_password() {
        let meeting = Meeting {
            id: Some(123),
            uuid: None,
            topic: Some("Test".into()),
            meeting_type: None,
            start_time: None,
            duration: None,
            timezone: None,
            agenda: None,
            status: None,
            join_url: None,
            start_url: None,
            password: Some("secret_pass".into()),
            host_id: None,
            created_at: None,
        };
        let dbg = format!("{meeting:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("secret_pass"));
        assert!(dbg.contains("Test"));
    }

    #[test]
    fn create_meeting_request_debug_redacts_password() {
        let req = CreateMeetingRequest {
            topic: "Sync".into(),
            meeting_type: None,
            start_time: None,
            duration: None,
            timezone: None,
            agenda: None,
            password: Some("my_password".into()),
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("my_password"));
        assert!(dbg.contains("Sync"));
    }

    #[test]
    fn update_meeting_request_debug_redacts_password() {
        let req = UpdateMeetingRequest {
            topic: Some("Updated".into()),
            meeting_type: None,
            start_time: None,
            duration: None,
            timezone: None,
            agenda: None,
            password: Some("update_pass".into()),
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("update_pass"));
        assert!(dbg.contains("Updated"));
    }
}
