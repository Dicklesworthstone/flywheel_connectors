//! Calendly API types.

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Common pagination
// ─────────────────────────────────────────────────────────────────────────────

/// Pagination info from Calendly API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pagination {
    pub count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_page: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// User types
// ─────────────────────────────────────────────────────────────────────────────

/// Current user response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentUserResponse {
    pub resource: User,
}

/// Calendly user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub uri: String,
    pub name: String,
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduling_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Event types
// ─────────────────────────────────────────────────────────────────────────────

/// Event type list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventTypeListResponse {
    pub collection: Vec<EventType>,
    pub pagination: Pagination,
}

/// Calendly event type definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventType {
    pub uri: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scheduling_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description_plain: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Event (scheduled) types
// ─────────────────────────────────────────────────────────────────────────────

/// Scheduled events list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventListResponse {
    pub collection: Vec<Event>,
    pub pagination: Pagination,
}

/// Single event response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventResponse {
    pub resource: Event,
}

/// A scheduled event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub uri: String,
    pub name: String,
    pub status: String,
    pub start_time: String,
    pub end_time: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<EventLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancellation: Option<Cancellation>,
    #[serde(default)]
    pub event_memberships: Vec<EventMembership>,
    #[serde(default)]
    pub event_guests: Vec<EventGuest>,
}

/// Event location info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLocation {
    #[serde(rename = "type")]
    pub location_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub join_url: Option<String>,
}

/// Event membership (who is scheduled).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventMembership {
    pub user: String,
}

/// Event guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventGuest {
    pub email: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

/// Cancellation details.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cancellation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canceled_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Invitee types
// ─────────────────────────────────────────────────────────────────────────────

/// Invitee list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteeListResponse {
    pub collection: Vec<Invitee>,
    pub pagination: Pagination,
}

/// An event invitee.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invitee {
    pub uri: String,
    pub email: String,
    pub name: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub canceled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cancellation: Option<Cancellation>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Scheduling link types
// ─────────────────────────────────────────────────────────────────────────────

/// Scheduling link create response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulingLinkResponse {
    pub resource: SchedulingLink,
}

/// A scheduling link.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulingLink {
    pub booking_url: String,
    pub owner: String,
    pub owner_type: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Availability types
// ─────────────────────────────────────────────────────────────────────────────

/// User availability schedules response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailabilityScheduleListResponse {
    pub collection: Vec<AvailabilitySchedule>,
}

/// An availability schedule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailabilitySchedule {
    pub uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default = "default_false")]
    pub default: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    #[serde(default)]
    pub rules: Vec<AvailabilityRule>,
}

const fn default_false() -> bool {
    false
}

/// A single availability rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AvailabilityRule {
    #[serde(rename = "type")]
    pub rule_type: String,
    #[serde(default)]
    pub intervals: Vec<TimeInterval>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wday: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
}

/// A time interval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeInterval {
    pub from: String,
    pub to: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Error response
// ─────────────────────────────────────────────────────────────────────────────

/// Calendly API error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default)]
    pub details: Vec<ApiErrorDetail>,
}

/// Error detail.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiErrorDetail {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_deserialization() {
        let json = serde_json::json!({
            "resource": {
                "uri": "https://api.calendly.com/users/abc123",
                "name": "Test User",
                "email": "test@example.com",
                "scheduling_url": "https://calendly.com/testuser",
                "timezone": "America/New_York",
                "current_organization": "https://api.calendly.com/organizations/org123"
            }
        });
        let resp: CurrentUserResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.resource.name, "Test User");
        assert_eq!(resp.resource.email, "test@example.com");
    }

    #[test]
    fn event_type_deserialization() {
        let json = serde_json::json!({
            "collection": [{
                "uri": "https://api.calendly.com/event_types/abc",
                "name": "30 Minute Meeting",
                "active": true,
                "slug": "30min",
                "duration": 30,
                "kind": "solo",
                "scheduling_url": "https://calendly.com/testuser/30min"
            }],
            "pagination": {
                "count": 1,
                "next_page": null
            }
        });
        let resp: EventTypeListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.collection.len(), 1);
        assert_eq!(resp.collection[0].name, "30 Minute Meeting");
        assert_eq!(resp.collection[0].duration, Some(30));
    }

    #[test]
    fn event_deserialization() {
        let json = serde_json::json!({
            "resource": {
                "uri": "https://api.calendly.com/scheduled_events/evt123",
                "name": "30 Minute Meeting",
                "status": "active",
                "start_time": "2026-03-21T10:00:00.000000Z",
                "end_time": "2026-03-21T10:30:00.000000Z",
                "event_type": "https://api.calendly.com/event_types/abc",
                "event_memberships": [{"user": "https://api.calendly.com/users/abc123"}],
                "event_guests": []
            }
        });
        let resp: EventResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.resource.status, "active");
        assert_eq!(resp.resource.event_memberships.len(), 1);
    }

    #[test]
    fn event_list_deserialization() {
        let json = serde_json::json!({
            "collection": [
                {
                    "uri": "https://api.calendly.com/scheduled_events/evt1",
                    "name": "Meeting 1",
                    "status": "active",
                    "start_time": "2026-03-21T10:00:00Z",
                    "end_time": "2026-03-21T10:30:00Z",
                    "event_memberships": [],
                    "event_guests": []
                },
                {
                    "uri": "https://api.calendly.com/scheduled_events/evt2",
                    "name": "Meeting 2",
                    "status": "canceled",
                    "start_time": "2026-03-22T14:00:00Z",
                    "end_time": "2026-03-22T15:00:00Z",
                    "cancellation": { "canceled_by": "host", "reason": "Conflict" },
                    "event_memberships": [],
                    "event_guests": []
                }
            ],
            "pagination": { "count": 2 }
        });
        let resp: EventListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.collection.len(), 2);
        assert!(resp.collection[1].cancellation.is_some());
    }

    #[test]
    fn invitee_deserialization() {
        let json = serde_json::json!({
            "collection": [{
                "uri": "https://api.calendly.com/scheduled_events/evt1/invitees/inv1",
                "email": "invitee@example.com",
                "name": "Jane Doe",
                "status": "active",
                "timezone": "America/Los_Angeles"
            }],
            "pagination": { "count": 1 }
        });
        let resp: InviteeListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.collection[0].email, "invitee@example.com");
    }

    #[test]
    fn scheduling_link_deserialization() {
        let json = serde_json::json!({
            "resource": {
                "booking_url": "https://calendly.com/d/abc-123/30min",
                "owner": "https://api.calendly.com/event_types/abc",
                "owner_type": "EventType"
            }
        });
        let resp: SchedulingLinkResponse = serde_json::from_value(json).unwrap();
        assert!(resp.resource.booking_url.starts_with("https://"));
    }

    #[test]
    fn availability_schedule_deserialization() {
        let json = serde_json::json!({
            "collection": [{
                "uri": "https://api.calendly.com/user_availability_schedules/sched1",
                "name": "Working Hours",
                "default": true,
                "timezone": "America/New_York",
                "rules": [{
                    "type": "wday",
                    "wday": "monday",
                    "intervals": [{ "from": "09:00", "to": "17:00" }]
                }]
            }]
        });
        let resp: AvailabilityScheduleListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.collection.len(), 1);
        assert!(resp.collection[0].default);
        assert_eq!(resp.collection[0].rules[0].intervals.len(), 1);
    }

    #[test]
    fn api_error_deserialization() {
        let json = serde_json::json!({
            "title": "Not Found",
            "message": "The resource could not be found",
            "details": [{ "parameter": "event_uuid", "message": "not found" }]
        });
        let err: ApiErrorResponse = serde_json::from_value(json).unwrap();
        assert_eq!(err.title, Some("Not Found".into()));
        assert_eq!(err.details.len(), 1);
    }

    #[test]
    fn event_with_location() {
        let json = serde_json::json!({
            "resource": {
                "uri": "https://api.calendly.com/scheduled_events/evt1",
                "name": "Zoom Meeting",
                "status": "active",
                "start_time": "2026-03-21T10:00:00Z",
                "end_time": "2026-03-21T10:30:00Z",
                "location": {
                    "type": "zoom",
                    "join_url": "https://zoom.us/j/123456"
                },
                "event_memberships": [],
                "event_guests": []
            }
        });
        let resp: EventResponse = serde_json::from_value(json).unwrap();
        let loc = resp.resource.location.unwrap();
        assert_eq!(loc.location_type, "zoom");
        assert!(loc.join_url.is_some());
    }

    #[test]
    fn event_with_guests() {
        let json = serde_json::json!({
            "resource": {
                "uri": "https://api.calendly.com/scheduled_events/evt1",
                "name": "Team Meeting",
                "status": "active",
                "start_time": "2026-03-21T10:00:00Z",
                "end_time": "2026-03-21T10:30:00Z",
                "event_memberships": [],
                "event_guests": [
                    { "email": "guest1@example.com" },
                    { "email": "guest2@example.com" }
                ]
            }
        });
        let resp: EventResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.resource.event_guests.len(), 2);
    }

    #[test]
    fn pagination_with_next_page() {
        let json = serde_json::json!({
            "count": 25,
            "next_page": "https://api.calendly.com/scheduled_events?page_token=abc",
            "next_page_token": "abc"
        });
        let pag: Pagination = serde_json::from_value(json).unwrap();
        assert_eq!(pag.count, 25);
        assert!(pag.next_page.is_some());
        assert!(pag.next_page_token.is_some());
    }

    #[test]
    fn user_minimal_fields() {
        let json = serde_json::json!({
            "uri": "https://api.calendly.com/users/abc",
            "name": "Minimal",
            "email": "min@example.com"
        });
        let user: User = serde_json::from_value(json).unwrap();
        assert_eq!(user.name, "Minimal");
        assert!(user.timezone.is_none());
        assert!(user.avatar_url.is_none());
    }
}
