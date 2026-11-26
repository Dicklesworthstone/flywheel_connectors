//! Google Calendar API types.

use serde::{Deserialize, Serialize};

/// A calendar entry from the calendar list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CalendarEntry {
    pub id: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub time_zone: Option<String>,
    #[serde(default)]
    pub primary: bool,
}

/// A calendar event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub location: Option<String>,
    #[serde(default)]
    pub start: Option<EventDateTime>,
    #[serde(default)]
    pub end: Option<EventDateTime>,
    #[serde(default)]
    pub creator: Option<EventPerson>,
    #[serde(default)]
    pub organizer: Option<EventPerson>,
    #[serde(default)]
    pub attendees: Vec<Attendee>,
    #[serde(default)]
    pub html_link: Option<String>,
    #[serde(default)]
    pub hangout_link: Option<String>,
    #[serde(default)]
    pub recurrence: Vec<String>,
}

/// Date/time for an event (either date-time or all-day date).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventDateTime {
    #[serde(default)]
    pub date_time: Option<String>,
    #[serde(default)]
    pub date: Option<String>,
    #[serde(default)]
    pub time_zone: Option<String>,
}

/// A person associated with an event (creator or organizer).
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventPerson {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(rename = "self", default)]
    pub self_: bool,
}

/// An event attendee.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attendee {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub response_status: Option<String>,
    #[serde(default)]
    pub optional: bool,
}

/// Response from the calendar list endpoint.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CalendarListResponse {
    #[serde(default)]
    pub items: Vec<CalendarEntry>,
    #[serde(default)]
    pub next_page_token: Option<String>,
}

/// Response from the events list endpoint.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventsListResponse {
    #[serde(default)]
    pub items: Vec<Event>,
    #[serde(default)]
    pub next_page_token: Option<String>,
    #[serde(default)]
    pub next_sync_token: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
}

/// A calendar item in a freebusy request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreeBusyRequestItem {
    pub id: String,
}

/// Request body for the freebusy query.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FreeBusyRequest {
    pub time_min: String,
    pub time_max: String,
    pub items: Vec<FreeBusyRequestItem>,
}

/// A busy time range within a calendar's freebusy response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BusyTime {
    pub start: String,
    pub end: String,
}

/// Per-calendar freebusy information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalendarFreeBusy {
    #[serde(default)]
    pub busy: Vec<BusyTime>,
}

/// Response from the freebusy endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FreeBusyResponse {
    #[serde(default)]
    pub calendars: std::collections::HashMap<String, CalendarFreeBusy>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ═══════════════════════════════════════════════════════════════════════
    // CalendarEntry tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn calendar_entry_full_serde() {
        let json = json!({
            "id": "primary",
            "summary": "My Calendar",
            "description": "Personal events",
            "timeZone": "America/New_York",
            "primary": true
        });
        let cal: CalendarEntry = serde_json::from_value(json).unwrap();
        assert_eq!(cal.id, "primary");
        assert_eq!(cal.summary.as_deref(), Some("My Calendar"));
        assert_eq!(cal.description.as_deref(), Some("Personal events"));
        assert_eq!(cal.time_zone.as_deref(), Some("America/New_York"));
        assert!(cal.primary);
    }

    #[test]
    fn calendar_entry_defaults_missing_optionals() {
        let json = json!({"id": "test"});
        let cal: CalendarEntry = serde_json::from_value(json).unwrap();
        assert_eq!(cal.id, "test");
        assert!(!cal.primary);
        assert!(cal.summary.is_none());
        assert!(cal.description.is_none());
        assert!(cal.time_zone.is_none());
    }

    #[test]
    fn calendar_entry_roundtrip() {
        let original = CalendarEntry {
            id: "cal-001".into(),
            summary: Some("Work".into()),
            description: None,
            time_zone: Some("UTC".into()),
            primary: false,
        };
        let serialized = serde_json::to_value(&original).unwrap();
        let deserialized: CalendarEntry = serde_json::from_value(serialized).unwrap();
        assert_eq!(deserialized.id, original.id);
        assert_eq!(deserialized.summary, original.summary);
        assert_eq!(deserialized.description, original.description);
        assert_eq!(deserialized.time_zone, original.time_zone);
        assert_eq!(deserialized.primary, original.primary);
    }

    #[test]
    fn calendar_entry_clone() {
        let cal = CalendarEntry {
            id: "c1".into(),
            summary: Some("Clone me".into()),
            description: Some("desc".into()),
            time_zone: Some("US/Pacific".into()),
            primary: true,
        };
        let cloned = cal.clone();
        assert_eq!(cloned.id, cal.id);
        assert_eq!(cloned.summary, cal.summary);
        assert_eq!(cloned.description, cal.description);
        assert_eq!(cloned.time_zone, cal.time_zone);
        assert_eq!(cloned.primary, cal.primary);
    }

    #[test]
    fn calendar_entry_debug() {
        let cal = CalendarEntry {
            id: "dbg".into(),
            summary: None,
            description: None,
            time_zone: None,
            primary: false,
        };
        let dbg = format!("{cal:?}");
        assert!(dbg.contains("CalendarEntry"), "got: {dbg}");
        assert!(dbg.contains("dbg"), "got: {dbg}");
    }

    #[test]
    fn calendar_entry_camel_case_serialization() {
        let cal = CalendarEntry {
            id: "x".into(),
            summary: None,
            description: None,
            time_zone: Some("Europe/London".into()),
            primary: false,
        };
        let json_str = serde_json::to_string(&cal).unwrap();
        assert!(
            json_str.contains("timeZone"),
            "should use camelCase: {json_str}"
        );
        assert!(
            !json_str.contains("time_zone"),
            "should not use snake_case: {json_str}"
        );
    }

    #[test]
    fn calendar_entry_primary_false_default() {
        // Explicit false should also roundtrip correctly
        let json = json!({"id": "x", "primary": false});
        let cal: CalendarEntry = serde_json::from_value(json).unwrap();
        assert!(!cal.primary);
    }

    #[test]
    fn calendar_entry_null_optionals() {
        let json = json!({
            "id": "x",
            "summary": null,
            "description": null,
            "timeZone": null
        });
        let cal: CalendarEntry = serde_json::from_value(json).unwrap();
        assert!(cal.summary.is_none());
        assert!(cal.description.is_none());
        assert!(cal.time_zone.is_none());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Event tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn event_full_serde() {
        let json = json!({
            "id": "evt1",
            "status": "confirmed",
            "summary": "Meeting",
            "description": "A description",
            "location": "Room 42",
            "start": {"dateTime": "2026-03-03T10:00:00-05:00", "timeZone": "America/New_York"},
            "end": {"dateTime": "2026-03-03T11:00:00-05:00"},
            "creator": {"email": "creator@example.com", "displayName": "Creator"},
            "organizer": {"email": "org@example.com", "self": true},
            "attendees": [
                {"email": "alice@example.com", "responseStatus": "accepted"},
                {"email": "bob@example.com", "responseStatus": "tentative", "optional": true}
            ],
            "htmlLink": "https://calendar.google.com/event?eid=xxx",
            "hangoutLink": "https://meet.google.com/xxx",
            "recurrence": ["RRULE:FREQ=WEEKLY;COUNT=10"]
        });
        let event: Event = serde_json::from_value(json).unwrap();
        assert_eq!(event.id.as_deref(), Some("evt1"));
        assert_eq!(event.status.as_deref(), Some("confirmed"));
        assert_eq!(event.summary.as_deref(), Some("Meeting"));
        assert_eq!(event.description.as_deref(), Some("A description"));
        assert_eq!(event.location.as_deref(), Some("Room 42"));
        assert!(event.start.is_some());
        assert!(event.end.is_some());
        assert!(event.creator.is_some());
        assert!(event.organizer.is_some());
        assert_eq!(event.attendees.len(), 2);
        assert_eq!(
            event.html_link.as_deref(),
            Some("https://calendar.google.com/event?eid=xxx")
        );
        assert_eq!(
            event.hangout_link.as_deref(),
            Some("https://meet.google.com/xxx")
        );
        assert_eq!(event.recurrence.len(), 1);
        assert_eq!(event.recurrence[0], "RRULE:FREQ=WEEKLY;COUNT=10");
    }

    #[test]
    fn event_minimal_empty_object() {
        let json = json!({});
        let event: Event = serde_json::from_value(json).unwrap();
        assert!(event.id.is_none());
        assert!(event.status.is_none());
        assert!(event.summary.is_none());
        assert!(event.description.is_none());
        assert!(event.location.is_none());
        assert!(event.start.is_none());
        assert!(event.end.is_none());
        assert!(event.creator.is_none());
        assert!(event.organizer.is_none());
        assert!(event.attendees.is_empty());
        assert!(event.html_link.is_none());
        assert!(event.hangout_link.is_none());
        assert!(event.recurrence.is_empty());
    }

    #[test]
    fn event_roundtrip() {
        let original = Event {
            id: Some("rt-evt".into()),
            status: Some("confirmed".into()),
            summary: Some("Roundtrip".into()),
            description: None,
            location: Some("Home".into()),
            start: Some(EventDateTime {
                date_time: Some("2026-03-05T09:00:00Z".into()),
                date: None,
                time_zone: Some("UTC".into()),
            }),
            end: Some(EventDateTime {
                date_time: Some("2026-03-05T10:00:00Z".into()),
                date: None,
                time_zone: None,
            }),
            creator: None,
            organizer: None,
            attendees: vec![Attendee {
                email: Some("test@example.com".into()),
                display_name: None,
                response_status: Some("needsAction".into()),
                optional: false,
            }],
            html_link: None,
            hangout_link: None,
            recurrence: vec![],
        };
        let serialized = serde_json::to_value(&original).unwrap();
        let deserialized: Event = serde_json::from_value(serialized).unwrap();
        assert_eq!(deserialized.id, original.id);
        assert_eq!(deserialized.summary, original.summary);
        assert_eq!(deserialized.location, original.location);
        assert_eq!(deserialized.attendees.len(), 1);
        assert_eq!(deserialized.attendees[0].email, original.attendees[0].email);
    }

    #[test]
    fn event_clone() {
        let event = Event {
            id: Some("c-evt".into()),
            status: None,
            summary: Some("Clone".into()),
            description: None,
            location: None,
            start: None,
            end: None,
            creator: None,
            organizer: None,
            attendees: vec![],
            html_link: None,
            hangout_link: None,
            recurrence: vec!["RRULE:FREQ=DAILY".into()],
        };
        let cloned = event.clone();
        assert_eq!(cloned.id, event.id);
        assert_eq!(cloned.summary, event.summary);
        assert_eq!(cloned.recurrence, event.recurrence);
    }

    #[test]
    fn event_debug() {
        let event = Event {
            id: Some("dbg-evt".into()),
            status: None,
            summary: None,
            description: None,
            location: None,
            start: None,
            end: None,
            creator: None,
            organizer: None,
            attendees: vec![],
            html_link: None,
            hangout_link: None,
            recurrence: vec![],
        };
        let dbg = format!("{event:?}");
        assert!(dbg.contains("Event"), "got: {dbg}");
        assert!(dbg.contains("dbg-evt"), "got: {dbg}");
    }

    #[test]
    fn event_camel_case_keys() {
        let event = Event {
            id: Some("x".into()),
            status: None,
            summary: None,
            description: None,
            location: None,
            start: None,
            end: None,
            creator: None,
            organizer: None,
            attendees: vec![],
            html_link: Some("https://example.com".into()),
            hangout_link: Some("https://meet.google.com/abc".into()),
            recurrence: vec![],
        };
        let json_str = serde_json::to_string(&event).unwrap();
        assert!(
            json_str.contains("htmlLink"),
            "should use camelCase: {json_str}"
        );
        assert!(
            json_str.contains("hangoutLink"),
            "should use camelCase: {json_str}"
        );
        assert!(
            !json_str.contains("html_link"),
            "should not use snake_case: {json_str}"
        );
        assert!(
            !json_str.contains("hangout_link"),
            "should not use snake_case: {json_str}"
        );
    }

    #[test]
    fn event_null_optionals() {
        let json = json!({
            "id": null,
            "status": null,
            "summary": null,
            "description": null,
            "location": null,
            "start": null,
            "end": null,
            "creator": null,
            "organizer": null,
            "htmlLink": null,
            "hangoutLink": null
        });
        let event: Event = serde_json::from_value(json).unwrap();
        assert!(event.id.is_none());
        assert!(event.status.is_none());
        assert!(event.summary.is_none());
        assert!(event.start.is_none());
        assert!(event.creator.is_none());
    }

    #[test]
    fn event_multiple_attendees() {
        let json = json!({
            "attendees": [
                {"email": "a@test.com", "responseStatus": "accepted"},
                {"email": "b@test.com", "responseStatus": "declined", "optional": true},
                {"email": "c@test.com", "displayName": "Charlie"}
            ]
        });
        let event: Event = serde_json::from_value(json).unwrap();
        assert_eq!(event.attendees.len(), 3);
        assert_eq!(event.attendees[0].email.as_deref(), Some("a@test.com"));
        assert!(!event.attendees[0].optional);
        assert!(event.attendees[1].optional);
        assert_eq!(event.attendees[2].display_name.as_deref(), Some("Charlie"));
    }

    #[test]
    fn event_multiple_recurrence_rules() {
        let json = json!({
            "recurrence": [
                "RRULE:FREQ=WEEKLY;BYDAY=MO,WE,FR",
                "EXDATE:20260310T090000Z"
            ]
        });
        let event: Event = serde_json::from_value(json).unwrap();
        assert_eq!(event.recurrence.len(), 2);
        assert!(event.recurrence[0].starts_with("RRULE:"));
        assert!(event.recurrence[1].starts_with("EXDATE:"));
    }

    // ═══════════════════════════════════════════════════════════════════════
    // EventDateTime tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn event_date_time_timed_event() {
        let json = json!({
            "dateTime": "2026-03-05T14:30:00-05:00",
            "timeZone": "America/New_York"
        });
        let dt: EventDateTime = serde_json::from_value(json).unwrap();
        assert_eq!(dt.date_time.as_deref(), Some("2026-03-05T14:30:00-05:00"));
        assert!(dt.date.is_none());
        assert_eq!(dt.time_zone.as_deref(), Some("America/New_York"));
    }

    #[test]
    fn event_date_time_all_day() {
        let json = json!({"date": "2026-03-03"});
        let dt: EventDateTime = serde_json::from_value(json).unwrap();
        assert_eq!(dt.date.as_deref(), Some("2026-03-03"));
        assert!(dt.date_time.is_none());
        assert!(dt.time_zone.is_none());
    }

    #[test]
    fn event_date_time_empty_object() {
        let json = json!({});
        let dt: EventDateTime = serde_json::from_value(json).unwrap();
        assert!(dt.date_time.is_none());
        assert!(dt.date.is_none());
        assert!(dt.time_zone.is_none());
    }

    #[test]
    fn event_date_time_roundtrip() {
        let original = EventDateTime {
            date_time: Some("2026-01-01T00:00:00Z".into()),
            date: None,
            time_zone: Some("UTC".into()),
        };
        let serialized = serde_json::to_value(&original).unwrap();
        let deserialized: EventDateTime = serde_json::from_value(serialized).unwrap();
        assert_eq!(deserialized.date_time, original.date_time);
        assert_eq!(deserialized.date, original.date);
        assert_eq!(deserialized.time_zone, original.time_zone);
    }

    #[test]
    fn event_date_time_clone() {
        let dt = EventDateTime {
            date_time: Some("2026-06-15T08:00:00Z".into()),
            date: None,
            time_zone: Some("Asia/Tokyo".into()),
        };
        let cloned = dt.clone();
        assert_eq!(cloned.date_time, dt.date_time);
        assert_eq!(cloned.time_zone, dt.time_zone);
    }

    #[test]
    fn event_date_time_debug() {
        let dt = EventDateTime {
            date_time: None,
            date: Some("2026-12-25".into()),
            time_zone: None,
        };
        let dbg = format!("{dt:?}");
        assert!(dbg.contains("EventDateTime"), "got: {dbg}");
        assert!(dbg.contains("2026-12-25"), "got: {dbg}");
    }

    #[test]
    fn event_date_time_camel_case() {
        let dt = EventDateTime {
            date_time: Some("2026-03-05T10:00:00Z".into()),
            date: None,
            time_zone: Some("UTC".into()),
        };
        let json_str = serde_json::to_string(&dt).unwrap();
        assert!(
            json_str.contains("dateTime"),
            "should use camelCase: {json_str}"
        );
        assert!(
            json_str.contains("timeZone"),
            "should use camelCase: {json_str}"
        );
        assert!(
            !json_str.contains("date_time"),
            "should not contain snake_case: {json_str}"
        );
        assert!(
            !json_str.contains("time_zone"),
            "should not contain snake_case: {json_str}"
        );
    }

    #[test]
    fn event_date_time_null_fields() {
        let json = json!({
            "dateTime": null,
            "date": null,
            "timeZone": null
        });
        let dt: EventDateTime = serde_json::from_value(json).unwrap();
        assert!(dt.date_time.is_none());
        assert!(dt.date.is_none());
        assert!(dt.time_zone.is_none());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // EventPerson tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn event_person_full() {
        let json = json!({
            "email": "me@example.com",
            "displayName": "Me",
            "self": true
        });
        let person: EventPerson = serde_json::from_value(json).unwrap();
        assert_eq!(person.email.as_deref(), Some("me@example.com"));
        assert_eq!(person.display_name.as_deref(), Some("Me"));
        assert!(person.self_);
    }

    #[test]
    fn event_person_defaults() {
        let json = json!({});
        let person: EventPerson = serde_json::from_value(json).unwrap();
        assert!(person.email.is_none());
        assert!(person.display_name.is_none());
        assert!(!person.self_);
    }

    #[test]
    fn event_person_self_false() {
        let json = json!({"email": "other@example.com", "self": false});
        let person: EventPerson = serde_json::from_value(json).unwrap();
        assert!(!person.self_);
    }

    #[test]
    fn event_person_self_rename_roundtrip() {
        let person = EventPerson {
            email: Some("test@test.com".into()),
            display_name: None,
            self_: true,
        };
        let serialized = serde_json::to_value(&person).unwrap();
        // The "self" field should be serialized as "self" (not "self_")
        assert!(
            serialized.get("self").is_some(),
            "should serialize as 'self'"
        );
        assert!(serialized.get("self_").is_none(), "should not use 'self_'");
        assert_eq!(serialized["self"], true);

        let deserialized: EventPerson = serde_json::from_value(serialized).unwrap();
        assert!(deserialized.self_);
        assert_eq!(deserialized.email.as_deref(), Some("test@test.com"));
    }

    #[test]
    fn event_person_clone() {
        let person = EventPerson {
            email: Some("clone@test.com".into()),
            display_name: Some("Clone Person".into()),
            self_: false,
        };
        let cloned = person.clone();
        assert_eq!(cloned.email, person.email);
        assert_eq!(cloned.display_name, person.display_name);
        assert_eq!(cloned.self_, person.self_);
    }

    #[test]
    fn event_person_debug() {
        let person = EventPerson {
            email: Some("dbg@test.com".into()),
            display_name: None,
            self_: true,
        };
        let dbg = format!("{person:?}");
        assert!(dbg.contains("EventPerson"), "got: {dbg}");
        assert!(dbg.contains("dbg@test.com"), "got: {dbg}");
    }

    #[test]
    fn event_person_camel_case() {
        let person = EventPerson {
            email: None,
            display_name: Some("Test".into()),
            self_: false,
        };
        let json_str = serde_json::to_string(&person).unwrap();
        assert!(
            json_str.contains("displayName"),
            "should use camelCase: {json_str}"
        );
        assert!(
            !json_str.contains("display_name"),
            "should not use snake_case: {json_str}"
        );
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Attendee tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn attendee_full() {
        let json = json!({
            "email": "attendee@example.com",
            "displayName": "Attendee",
            "responseStatus": "accepted",
            "optional": true
        });
        let att: Attendee = serde_json::from_value(json).unwrap();
        assert_eq!(att.email.as_deref(), Some("attendee@example.com"));
        assert_eq!(att.display_name.as_deref(), Some("Attendee"));
        assert_eq!(att.response_status.as_deref(), Some("accepted"));
        assert!(att.optional);
    }

    #[test]
    fn attendee_defaults() {
        let json = json!({});
        let att: Attendee = serde_json::from_value(json).unwrap();
        assert!(att.email.is_none());
        assert!(att.display_name.is_none());
        assert!(att.response_status.is_none());
        assert!(!att.optional);
    }

    #[test]
    fn attendee_roundtrip() {
        let original = Attendee {
            email: Some("rt@example.com".into()),
            display_name: Some("RT".into()),
            response_status: Some("tentative".into()),
            optional: false,
        };
        let serialized = serde_json::to_value(&original).unwrap();
        let deserialized: Attendee = serde_json::from_value(serialized).unwrap();
        assert_eq!(deserialized.email, original.email);
        assert_eq!(deserialized.display_name, original.display_name);
        assert_eq!(deserialized.response_status, original.response_status);
        assert_eq!(deserialized.optional, original.optional);
    }

    #[test]
    fn attendee_clone() {
        let att = Attendee {
            email: Some("c@test.com".into()),
            display_name: None,
            response_status: Some("declined".into()),
            optional: true,
        };
        let cloned = att.clone();
        assert_eq!(cloned.email, att.email);
        assert_eq!(cloned.optional, att.optional);
    }

    #[test]
    fn attendee_debug() {
        let att = Attendee {
            email: Some("dbg@test.com".into()),
            display_name: None,
            response_status: None,
            optional: false,
        };
        let dbg = format!("{att:?}");
        assert!(dbg.contains("Attendee"), "got: {dbg}");
    }

    #[test]
    fn attendee_camel_case() {
        let att = Attendee {
            email: None,
            display_name: Some("Test".into()),
            response_status: Some("needsAction".into()),
            optional: false,
        };
        let json_str = serde_json::to_string(&att).unwrap();
        assert!(json_str.contains("displayName"), "camelCase: {json_str}");
        assert!(json_str.contains("responseStatus"), "camelCase: {json_str}");
        assert!(!json_str.contains("display_name"), "snake_case: {json_str}");
        assert!(
            !json_str.contains("response_status"),
            "snake_case: {json_str}"
        );
    }

    #[test]
    fn attendee_all_response_statuses() {
        for status in ["needsAction", "declined", "tentative", "accepted"] {
            let json = json!({"responseStatus": status});
            let att: Attendee = serde_json::from_value(json).unwrap();
            assert_eq!(att.response_status.as_deref(), Some(status));
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CalendarListResponse tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn calendar_list_response_with_items() {
        let json = json!({
            "items": [
                {"id": "primary", "summary": "Primary", "primary": true},
                {"id": "secondary", "summary": "Work"}
            ],
            "nextPageToken": "calendar-page-2+/=&?"
        });
        let resp: CalendarListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.items.len(), 2);
        assert_eq!(resp.items[0].id, "primary");
        assert!(resp.items[0].primary);
        assert_eq!(resp.items[1].id, "secondary");
        assert!(!resp.items[1].primary);
        assert_eq!(
            resp.next_page_token.as_deref(),
            Some("calendar-page-2+/=&?")
        );
    }

    #[test]
    fn calendar_list_response_empty() {
        let json = json!({});
        let resp: CalendarListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.items.is_empty());
        assert!(resp.next_page_token.is_none());
    }

    #[test]
    fn calendar_list_response_empty_items() {
        let json = json!({"items": []});
        let resp: CalendarListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.items.is_empty());
        assert!(resp.next_page_token.is_none());
    }

    #[test]
    fn calendar_list_response_clone() {
        let resp = CalendarListResponse {
            items: vec![CalendarEntry {
                id: "x".into(),
                summary: None,
                description: None,
                time_zone: None,
                primary: false,
            }],
            next_page_token: Some("calendar-page-2".into()),
        };
        let cloned = resp.clone();
        assert_eq!(cloned.items.len(), 1);
        assert_eq!(cloned.items[0].id, "x");
        assert_eq!(resp.items.len(), 1);
        assert_eq!(cloned.next_page_token, resp.next_page_token);
    }

    #[test]
    fn calendar_list_response_debug() {
        let resp = CalendarListResponse {
            items: vec![],
            next_page_token: None,
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("CalendarListResponse"), "got: {dbg}");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // EventsListResponse tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn events_list_response_full() {
        let json = json!({
            "items": [{"id": "e1", "summary": "Event 1"}],
            "nextPageToken": "token123",
            "nextSyncToken": "sync456",
            "summary": "My Calendar"
        });
        let resp: EventsListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.items.len(), 1);
        assert_eq!(resp.next_page_token.as_deref(), Some("token123"));
        assert_eq!(resp.next_sync_token.as_deref(), Some("sync456"));
        assert_eq!(resp.summary.as_deref(), Some("My Calendar"));
    }

    #[test]
    fn events_list_response_empty() {
        let json = json!({});
        let resp: EventsListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.items.is_empty());
        assert!(resp.next_page_token.is_none());
        assert!(resp.next_sync_token.is_none());
        assert!(resp.summary.is_none());
    }

    #[test]
    fn events_list_response_only_sync_token() {
        // Last page of incremental sync: has sync token but no page token
        let json = json!({
            "items": [],
            "nextSyncToken": "new-sync-token"
        });
        let resp: EventsListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.next_page_token.is_none());
        assert_eq!(resp.next_sync_token.as_deref(), Some("new-sync-token"));
    }

    #[test]
    fn events_list_response_only_page_token() {
        // Middle page: has page token but no sync token
        let json = json!({
            "items": [{"id": "e1"}],
            "nextPageToken": "page2"
        });
        let resp: EventsListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.next_page_token.as_deref(), Some("page2"));
        assert!(resp.next_sync_token.is_none());
    }

    #[test]
    fn events_list_response_clone() {
        let resp = EventsListResponse {
            items: vec![],
            next_page_token: Some("pt".into()),
            next_sync_token: None,
            summary: Some("Test".into()),
        };
        let cloned = resp.clone();
        assert_eq!(cloned.next_page_token, resp.next_page_token);
        assert_eq!(cloned.summary, resp.summary);
    }

    #[test]
    fn events_list_response_debug() {
        let resp = EventsListResponse {
            items: vec![],
            next_page_token: None,
            next_sync_token: None,
            summary: None,
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("EventsListResponse"), "got: {dbg}");
    }

    #[test]
    fn events_list_response_null_fields() {
        let json = json!({
            "items": [],
            "nextPageToken": null,
            "nextSyncToken": null,
            "summary": null
        });
        let resp: EventsListResponse = serde_json::from_value(json).unwrap();
        assert!(resp.next_page_token.is_none());
        assert!(resp.next_sync_token.is_none());
        assert!(resp.summary.is_none());
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FreeBusyRequestItem tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn free_busy_request_item_serde() {
        let item = FreeBusyRequestItem {
            id: "primary".into(),
        };
        let json = serde_json::to_value(&item).unwrap();
        assert_eq!(json["id"], "primary");

        let deserialized: FreeBusyRequestItem = serde_json::from_value(json).unwrap();
        assert_eq!(deserialized.id, "primary");
    }

    #[test]
    fn free_busy_request_item_clone() {
        let item = FreeBusyRequestItem {
            id: "cal-123".into(),
        };
        let cloned = item.clone();
        assert_eq!(cloned.id, "cal-123");
        assert_eq!(item.id, "cal-123");
    }

    #[test]
    fn free_busy_request_item_debug() {
        let item = FreeBusyRequestItem { id: "test".into() };
        let dbg = format!("{item:?}");
        assert!(dbg.contains("FreeBusyRequestItem"), "got: {dbg}");
        assert!(dbg.contains("test"), "got: {dbg}");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FreeBusyRequest tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn free_busy_request_serialize_camel_case() {
        let req = FreeBusyRequest {
            time_min: "2026-03-03T00:00:00Z".into(),
            time_max: "2026-03-04T00:00:00Z".into(),
            items: vec![FreeBusyRequestItem {
                id: "primary".into(),
            }],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("timeMin").is_some(), "should use timeMin");
        assert!(json.get("timeMax").is_some(), "should use timeMax");
        assert!(json.get("time_min").is_none(), "should not use snake_case");
        assert!(json.get("time_max").is_none(), "should not use snake_case");
        assert_eq!(json["timeMin"], "2026-03-03T00:00:00Z");
        assert_eq!(json["timeMax"], "2026-03-04T00:00:00Z");
        assert_eq!(json["items"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn free_busy_request_multiple_items() {
        let req = FreeBusyRequest {
            time_min: "2026-01-01T00:00:00Z".into(),
            time_max: "2026-01-02T00:00:00Z".into(),
            items: vec![
                FreeBusyRequestItem {
                    id: "primary".into(),
                },
                FreeBusyRequestItem {
                    id: "work@group.calendar.google.com".into(),
                },
                FreeBusyRequestItem {
                    id: "holidays@group.calendar.google.com".into(),
                },
            ],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["items"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn free_busy_request_empty_items() {
        let req = FreeBusyRequest {
            time_min: "2026-01-01T00:00:00Z".into(),
            time_max: "2026-01-02T00:00:00Z".into(),
            items: vec![],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert!(json["items"].as_array().unwrap().is_empty());
    }

    #[test]
    fn free_busy_request_clone() {
        let req = FreeBusyRequest {
            time_min: "a".into(),
            time_max: "b".into(),
            items: vec![FreeBusyRequestItem { id: "c".into() }],
        };
        let cloned = req.clone();
        assert_eq!(cloned.time_min, "a");
        assert_eq!(cloned.time_max, "b");
        assert_eq!(cloned.items.len(), 1);
        assert_eq!(req.time_min, "a");
    }

    #[test]
    fn free_busy_request_debug() {
        let req = FreeBusyRequest {
            time_min: "x".into(),
            time_max: "y".into(),
            items: vec![],
        };
        let dbg = format!("{req:?}");
        assert!(dbg.contains("FreeBusyRequest"), "got: {dbg}");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // BusyTime tests
    // ═══════════════════════════════════════════════════════════════════════

    // ═══════════════════════════════════════════════════════════════════════
    // Additional serde edge-case and coverage tests (2026-03-07)
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn calendar_entry_non_primary_defaults_false() {
        let json = json!({"id": "c1"});
        let entry: CalendarEntry = serde_json::from_value(json).unwrap();
        assert!(!entry.primary);
        assert!(entry.summary.is_none());
        assert!(entry.description.is_none());
        assert!(entry.time_zone.is_none());
    }

    #[test]
    fn calendar_entry_roundtrip_all_fields() {
        let entry = CalendarEntry {
            id: "cal@example.com".into(),
            summary: Some("Work".into()),
            description: Some("Work calendar".into()),
            time_zone: Some("America/New_York".into()),
            primary: true,
        };
        let json = serde_json::to_value(&entry).unwrap();
        let back: CalendarEntry = serde_json::from_value(json).unwrap();
        assert_eq!(back.id, "cal@example.com");
        assert_eq!(back.summary.as_deref(), Some("Work"));
        assert_eq!(back.description.as_deref(), Some("Work calendar"));
        assert_eq!(back.time_zone.as_deref(), Some("America/New_York"));
        assert!(back.primary);
    }

    #[test]
    fn calendar_entry_debug_contains_fields() {
        let entry = CalendarEntry {
            id: "debug-cal".into(),
            summary: Some("My Cal".into()),
            description: None,
            time_zone: None,
            primary: false,
        };
        let dbg = format!("{entry:?}");
        assert!(dbg.contains("CalendarEntry"), "got: {dbg}");
        assert!(dbg.contains("debug-cal"), "got: {dbg}");
    }

    #[test]
    fn calendar_entry_clone_uses_original() {
        let entry = CalendarEntry {
            id: "orig".into(),
            summary: Some("S".into()),
            description: None,
            time_zone: None,
            primary: true,
        };
        let _cloned = entry.clone();
        assert_eq!(entry.id, "orig");
        assert!(entry.primary);
    }

    #[test]
    fn event_empty_all_defaults() {
        let json = json!({});
        let evt: Event = serde_json::from_value(json).unwrap();
        assert!(evt.id.is_none());
        assert!(evt.status.is_none());
        assert!(evt.summary.is_none());
        assert!(evt.description.is_none());
        assert!(evt.location.is_none());
        assert!(evt.start.is_none());
        assert!(evt.end.is_none());
        assert!(evt.creator.is_none());
        assert!(evt.organizer.is_none());
        assert!(evt.attendees.is_empty());
        assert!(evt.html_link.is_none());
        assert!(evt.hangout_link.is_none());
        assert!(evt.recurrence.is_empty());
    }

    #[test]
    fn event_with_recurrence_rules() {
        let json = json!({
            "id": "rec1",
            "recurrence": ["RRULE:FREQ=WEEKLY;BYDAY=MO", "EXDATE:20260310T100000Z"]
        });
        let evt: Event = serde_json::from_value(json).unwrap();
        assert_eq!(evt.recurrence.len(), 2);
        assert!(evt.recurrence[0].contains("WEEKLY"));
    }

    #[test]
    fn event_multiple_attendees_with_options() {
        let json = json!({
            "id": "multi-att",
            "attendees": [
                {"email": "a@test.com"},
                {"email": "b@test.com", "responseStatus": "accepted"},
                {"email": "c@test.com", "optional": true}
            ]
        });
        let evt: Event = serde_json::from_value(json).unwrap();
        assert_eq!(evt.attendees.len(), 3);
        assert_eq!(evt.attendees[0].email.as_deref(), Some("a@test.com"));
        assert!(evt.attendees[2].optional);
    }

    #[test]
    fn event_clone_uses_original() {
        let evt = Event {
            id: Some("e-orig".into()),
            status: Some("confirmed".into()),
            summary: Some("Meeting".into()),
            description: None,
            location: None,
            start: None,
            end: None,
            creator: None,
            organizer: None,
            attendees: vec![],
            html_link: None,
            hangout_link: None,
            recurrence: vec![],
        };
        let _cloned = evt.clone();
        assert_eq!(evt.id.as_deref(), Some("e-orig"));
        assert_eq!(evt.status.as_deref(), Some("confirmed"));
    }

    #[test]
    fn event_date_time_date_only() {
        let json = json!({"date": "2026-03-15"});
        let edt: EventDateTime = serde_json::from_value(json).unwrap();
        assert!(edt.date_time.is_none());
        assert_eq!(edt.date.as_deref(), Some("2026-03-15"));
        assert!(edt.time_zone.is_none());
    }

    #[test]
    fn event_date_time_with_timezone() {
        let edt = EventDateTime {
            date_time: Some("2026-03-15T14:00:00".into()),
            date: None,
            time_zone: Some("Europe/London".into()),
        };
        let json = serde_json::to_value(&edt).unwrap();
        assert_eq!(json["timeZone"], "Europe/London");
        assert_eq!(json["dateTime"], "2026-03-15T14:00:00");
    }

    #[test]
    fn event_date_time_clone_uses_original() {
        let edt = EventDateTime {
            date_time: Some("2026-01-01T00:00:00Z".into()),
            date: None,
            time_zone: None,
        };
        let _cloned = edt.clone();
        assert_eq!(edt.date_time.as_deref(), Some("2026-01-01T00:00:00Z"));
    }

    #[test]
    fn event_person_all_none() {
        let json = json!({});
        let person: EventPerson = serde_json::from_value(json).unwrap();
        assert!(person.email.is_none());
        assert!(person.display_name.is_none());
        assert!(!person.self_);
    }

    #[test]
    fn attendee_serialize_optional_false_included() {
        let att = Attendee {
            email: Some("test@test.com".into()),
            display_name: None,
            response_status: None,
            optional: false,
        };
        let json = serde_json::to_value(&att).unwrap();
        // optional=false should be explicitly serialized (not skipped)
        assert_eq!(json["optional"], false);
    }

    #[test]
    fn free_busy_response_deserialize() {
        let json = json!({"calendars": {"primary": {"busy": [{"start": "a", "end": "b"}]}}});
        let resp: FreeBusyResponse = serde_json::from_value(json).unwrap();
        assert!(!resp.calendars.is_empty());
        assert!(resp.calendars.contains_key("primary"));
    }

    #[test]
    fn free_busy_response_empty() {
        let json = json!({});
        let resp: FreeBusyResponse = serde_json::from_value(json).unwrap();
        assert!(resp.calendars.is_empty());
    }

    #[test]
    fn free_busy_response_empty_calendars() {
        let json = json!({"calendars": {}});
        let resp: FreeBusyResponse = serde_json::from_value(json).unwrap();
        assert!(resp.calendars.is_empty());
    }

    #[test]
    fn free_busy_request_serialize() {
        let req = FreeBusyRequest {
            time_min: "2026-06-01T00:00:00Z".into(),
            time_max: "2026-06-02T00:00:00Z".into(),
            items: vec![FreeBusyRequestItem { id: "cal1".into() }],
        };
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["timeMin"], "2026-06-01T00:00:00Z");
        assert_eq!(json["items"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn event_with_links() {
        let json = json!({
            "id": "linked",
            "htmlLink": "https://calendar.google.com/event?eid=abc",
            "hangoutLink": "https://meet.google.com/xyz-abc-def"
        });
        let evt: Event = serde_json::from_value(json).unwrap();
        assert!(
            evt.html_link
                .as_deref()
                .unwrap()
                .contains("calendar.google.com")
        );
        assert!(
            evt.hangout_link
                .as_deref()
                .unwrap()
                .contains("meet.google.com")
        );
    }

    #[test]
    fn event_with_creator_and_organizer() {
        let json = json!({
            "id": "org-event",
            "creator": {"email": "creator@test.com", "displayName": "Creator"},
            "organizer": {"email": "org@test.com", "self": true}
        });
        let evt: Event = serde_json::from_value(json).unwrap();
        assert_eq!(
            evt.creator.as_ref().unwrap().email.as_deref(),
            Some("creator@test.com")
        );
        assert!(evt.organizer.as_ref().unwrap().self_);
    }

    #[test]
    fn free_busy_request_item_empty_id() {
        let item = FreeBusyRequestItem { id: String::new() };
        let json = serde_json::to_value(&item).unwrap();
        assert_eq!(json["id"], "");
    }

    #[test]
    fn busy_time_serde() {
        let json = json!({
            "start": "2026-03-05T10:00:00Z",
            "end": "2026-03-05T11:00:00Z"
        });
        let bt: BusyTime = serde_json::from_value(json).unwrap();
        assert_eq!(bt.start, "2026-03-05T10:00:00Z");
        assert_eq!(bt.end, "2026-03-05T11:00:00Z");
    }

    #[test]
    fn busy_time_roundtrip() {
        let original = BusyTime {
            start: "2026-03-05T09:00:00Z".into(),
            end: "2026-03-05T09:30:00Z".into(),
        };
        let serialized = serde_json::to_value(&original).unwrap();
        let deserialized: BusyTime = serde_json::from_value(serialized).unwrap();
        assert_eq!(deserialized.start, original.start);
        assert_eq!(deserialized.end, original.end);
    }

    #[test]
    fn busy_time_clone() {
        let bt = BusyTime {
            start: "a".into(),
            end: "b".into(),
        };
        let cloned = bt.clone();
        assert_eq!(cloned.start, "a");
        assert_eq!(cloned.end, "b");
        assert_eq!(bt.start, "a");
    }

    #[test]
    fn busy_time_debug() {
        let bt = BusyTime {
            start: "s".into(),
            end: "e".into(),
        };
        let dbg = format!("{bt:?}");
        assert!(dbg.contains("BusyTime"), "got: {dbg}");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // CalendarFreeBusy tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn calendar_free_busy_with_busy_times() {
        let json = json!({
            "busy": [
                {"start": "2026-03-05T10:00:00Z", "end": "2026-03-05T11:00:00Z"},
                {"start": "2026-03-05T14:00:00Z", "end": "2026-03-05T15:00:00Z"}
            ]
        });
        let cfb: CalendarFreeBusy = serde_json::from_value(json).unwrap();
        assert_eq!(cfb.busy.len(), 2);
    }

    #[test]
    fn calendar_free_busy_empty_busy() {
        let json = json!({"busy": []});
        let cfb: CalendarFreeBusy = serde_json::from_value(json).unwrap();
        assert!(cfb.busy.is_empty());
    }

    #[test]
    fn calendar_free_busy_default_missing_busy() {
        let json = json!({});
        let cfb: CalendarFreeBusy = serde_json::from_value(json).unwrap();
        assert!(cfb.busy.is_empty());
    }

    #[test]
    fn calendar_free_busy_roundtrip() {
        let original = CalendarFreeBusy {
            busy: vec![BusyTime {
                start: "2026-03-05T08:00:00Z".into(),
                end: "2026-03-05T08:30:00Z".into(),
            }],
        };
        let serialized = serde_json::to_value(&original).unwrap();
        let deserialized: CalendarFreeBusy = serde_json::from_value(serialized).unwrap();
        assert_eq!(deserialized.busy.len(), 1);
        assert_eq!(deserialized.busy[0].start, original.busy[0].start);
    }

    #[test]
    fn calendar_free_busy_clone() {
        let cfb = CalendarFreeBusy {
            busy: vec![BusyTime {
                start: "s".into(),
                end: "e".into(),
            }],
        };
        let cloned = cfb.clone();
        assert_eq!(cloned.busy.len(), 1);
        assert_eq!(cfb.busy.len(), 1);
    }

    #[test]
    fn calendar_free_busy_debug() {
        let cfb = CalendarFreeBusy { busy: vec![] };
        let dbg = format!("{cfb:?}");
        assert!(dbg.contains("CalendarFreeBusy"), "got: {dbg}");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // FreeBusyResponse tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn free_busy_response_single_calendar() {
        let json = json!({
            "calendars": {
                "primary": {
                    "busy": [
                        {"start": "2026-03-03T10:00:00Z", "end": "2026-03-03T11:00:00Z"}
                    ]
                }
            }
        });
        let resp: FreeBusyResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.calendars.len(), 1);
        assert_eq!(resp.calendars["primary"].busy.len(), 1);
    }

    #[test]
    fn free_busy_response_multiple_calendars() {
        let json = json!({
            "calendars": {
                "primary": {
                    "busy": [{"start": "2026-03-05T10:00:00Z", "end": "2026-03-05T11:00:00Z"}]
                },
                "work@group.calendar.google.com": {
                    "busy": [
                        {"start": "2026-03-05T09:00:00Z", "end": "2026-03-05T09:30:00Z"},
                        {"start": "2026-03-05T14:00:00Z", "end": "2026-03-05T16:00:00Z"}
                    ]
                },
                "holidays": {
                    "busy": []
                }
            }
        });
        let resp: FreeBusyResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.calendars.len(), 3);
        assert_eq!(resp.calendars["primary"].busy.len(), 1);
        assert_eq!(
            resp.calendars["work@group.calendar.google.com"].busy.len(),
            2
        );
        assert!(resp.calendars["holidays"].busy.is_empty());
    }

    #[test]
    fn free_busy_response_default_missing_calendars() {
        let json = json!({});
        let resp: FreeBusyResponse = serde_json::from_value(json).unwrap();
        assert!(resp.calendars.is_empty());
    }

    #[test]
    fn free_busy_response_roundtrip() {
        let mut calendars = std::collections::HashMap::new();
        calendars.insert(
            "primary".into(),
            CalendarFreeBusy {
                busy: vec![BusyTime {
                    start: "2026-01-01T00:00:00Z".into(),
                    end: "2026-01-01T01:00:00Z".into(),
                }],
            },
        );
        let original = FreeBusyResponse { calendars };
        let serialized = serde_json::to_value(&original).unwrap();
        let deserialized: FreeBusyResponse = serde_json::from_value(serialized).unwrap();
        assert_eq!(deserialized.calendars.len(), 1);
        assert!(deserialized.calendars.contains_key("primary"));
    }

    #[test]
    fn free_busy_response_clone() {
        let resp = FreeBusyResponse {
            calendars: std::collections::HashMap::new(),
        };
        let cloned = resp.clone();
        assert!(cloned.calendars.is_empty());
        assert!(resp.calendars.is_empty());
    }

    #[test]
    fn free_busy_response_debug() {
        let resp = FreeBusyResponse {
            calendars: std::collections::HashMap::new(),
        };
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("FreeBusyResponse"), "got: {dbg}");
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Cross-type integration / edge case tests
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn event_with_nested_types_roundtrip() {
        let event = Event {
            id: Some("nested-test".into()),
            status: Some("confirmed".into()),
            summary: Some("Nested roundtrip".into()),
            description: Some("Testing nested structs".into()),
            location: Some("Virtual".into()),
            start: Some(EventDateTime {
                date_time: Some("2026-06-01T10:00:00Z".into()),
                date: None,
                time_zone: Some("America/Chicago".into()),
            }),
            end: Some(EventDateTime {
                date_time: Some("2026-06-01T11:00:00Z".into()),
                date: None,
                time_zone: None,
            }),
            creator: Some(EventPerson {
                email: Some("creator@test.com".into()),
                display_name: Some("Creator".into()),
                self_: true,
            }),
            organizer: Some(EventPerson {
                email: Some("org@test.com".into()),
                display_name: None,
                self_: false,
            }),
            attendees: vec![
                Attendee {
                    email: Some("a1@test.com".into()),
                    display_name: Some("Attendee One".into()),
                    response_status: Some("accepted".into()),
                    optional: false,
                },
                Attendee {
                    email: Some("a2@test.com".into()),
                    display_name: None,
                    response_status: Some("tentative".into()),
                    optional: true,
                },
            ],
            html_link: Some("https://calendar.google.com/event?eid=abc".into()),
            hangout_link: Some("https://meet.google.com/abc-defg-hij".into()),
            recurrence: vec!["RRULE:FREQ=WEEKLY;COUNT=4".into()],
        };

        let json = serde_json::to_value(&event).unwrap();
        let restored: Event = serde_json::from_value(json).unwrap();

        assert_eq!(restored.id, event.id);
        assert_eq!(restored.summary, event.summary);
        assert!(restored.creator.is_some());
        assert!(restored.creator.as_ref().unwrap().self_);
        assert_eq!(restored.attendees.len(), 2);
        assert!(restored.attendees[1].optional);
        assert_eq!(restored.recurrence.len(), 1);
    }

    #[test]
    fn events_list_response_with_cancelled_event() {
        // Incremental sync can return cancelled events
        let json = json!({
            "items": [
                {"id": "e1", "status": "cancelled"},
                {"id": "e2", "status": "confirmed", "summary": "Active"}
            ],
            "nextSyncToken": "new-token"
        });
        let resp: EventsListResponse = serde_json::from_value(json).unwrap();
        assert_eq!(resp.items.len(), 2);
        assert_eq!(resp.items[0].status.as_deref(), Some("cancelled"));
        assert_eq!(resp.items[1].status.as_deref(), Some("confirmed"));
    }

    #[test]
    fn deserialize_extra_fields_are_ignored() {
        // Google API may return fields not in our struct - they should be ignored
        let json = json!({
            "id": "test",
            "unknownField": "should be ignored",
            "anotherUnknown": 42
        });
        let cal: CalendarEntry = serde_json::from_value(json).unwrap();
        assert_eq!(cal.id, "test");
    }

    #[test]
    fn event_with_empty_strings() {
        let json = json!({
            "id": "",
            "summary": "",
            "description": "",
            "location": ""
        });
        let event: Event = serde_json::from_value(json).unwrap();
        assert_eq!(event.id.as_deref(), Some(""));
        assert_eq!(event.summary.as_deref(), Some(""));
        assert_eq!(event.description.as_deref(), Some(""));
        assert_eq!(event.location.as_deref(), Some(""));
    }

    #[test]
    fn event_with_unicode() {
        let json = json!({
            "summary": "Meeting avec équipe",
            "location": "東京タワー",
            "description": "Обсуждение проекта 🚀"
        });
        let event: Event = serde_json::from_value(json).unwrap();
        assert_eq!(event.summary.as_deref(), Some("Meeting avec équipe"));
        assert_eq!(event.location.as_deref(), Some("東京タワー"));
        assert!(event.description.as_ref().unwrap().contains("🚀"));
    }
}
