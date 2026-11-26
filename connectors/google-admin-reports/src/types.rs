//! Google Admin Reports API types.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// An activity record from the Admin Activities report.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Activity {
    pub kind: Option<String>,
    pub id: Option<ActivityId>,
    pub actor: Option<Actor>,
    pub events: Option<Vec<ActivityEvent>>,
    #[serde(rename = "ipAddress")]
    pub ip_address: Option<String>,
}

/// Activity identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityId {
    pub time: Option<String>,
    pub unique_qualifier: Option<String>,
    pub application_name: Option<String>,
    pub customer_id: Option<String>,
}

/// Actor who performed the activity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Actor {
    pub email: Option<String>,
    pub profile_id: Option<String>,
    pub caller_type: Option<String>,
    pub key: Option<String>,
}

/// An event within an activity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityEvent {
    #[serde(rename = "type")]
    pub event_type: Option<String>,
    pub name: Option<String>,
    pub parameters: Option<Vec<EventParameter>>,
}

/// A parameter on an activity event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventParameter {
    pub name: Option<String>,
    pub value: Option<String>,
    pub bool_value: Option<bool>,
    pub int_value: Option<String>,
    pub multi_value: Option<Vec<String>>,
}

/// Activities list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivitiesListResponse {
    pub kind: Option<String>,
    pub etag: Option<String>,
    pub next_page_token: Option<String>,
    #[serde(default)]
    pub items: Vec<Activity>,
}

impl ActivitiesListResponse {
    /// Map only the collection envelope to the connector's public contract.
    /// Embedded activity fields retain Google's provider spelling.
    pub(crate) fn into_public_response(self) -> Value {
        let mut response = json!({
            "items": self.items,
            "next_page_token": self.next_page_token,
        });
        if let Some(kind) = self.kind {
            response["kind"] = json!(kind);
        }
        if let Some(etag) = self.etag {
            response["etag"] = json!(etag);
        }
        response
    }
}

/// Usage report entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageReport {
    pub kind: Option<String>,
    pub date: Option<String>,
    pub entity: Option<serde_json::Value>,
    pub parameters: Option<Vec<UsageParameter>>,
}

/// A parameter in a usage report.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageParameter {
    pub name: Option<String>,
    pub string_value: Option<String>,
    pub int_value: Option<String>,
    pub bool_value: Option<bool>,
    pub datetime_value: Option<String>,
}

/// Usage reports list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageReportsListResponse {
    pub kind: Option<String>,
    pub etag: Option<String>,
    pub next_page_token: Option<String>,
    pub warnings: Option<Vec<Value>>,
    #[serde(default)]
    pub usage_reports: Vec<UsageReport>,
}

impl UsageReportsListResponse {
    /// Preserve report resources and partial-data warnings while exposing a
    /// consistent collection name and continuation token to connector callers.
    pub(crate) fn into_public_response(self) -> Value {
        let mut response = json!({
            "usage_reports": self.usage_reports,
            "next_page_token": self.next_page_token,
        });
        if let Some(kind) = self.kind {
            response["kind"] = json!(kind);
        }
        if let Some(etag) = self.etag {
            response["etag"] = json!(etag);
        }
        if let Some(warnings) = self.warnings {
            response["warnings"] = json!(warnings);
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn activity_serde_roundtrip() {
        let json_val = json!({
            "kind": "admin#reports#activity",
            "id": {
                "time": "2026-03-14T00:00:00Z",
                "applicationName": "login"
            },
            "actor": {
                "email": "admin@example.com"
            },
            "events": [{
                "type": "login",
                "name": "login_success"
            }]
        });
        let activity: Activity = serde_json::from_value(json_val).unwrap();
        assert_eq!(activity.actor.unwrap().email.unwrap(), "admin@example.com");
    }

    #[test]
    fn activities_list_response_empty() {
        let json_val = json!({ "kind": "admin#reports#activities", "items": [] });
        let resp: ActivitiesListResponse = serde_json::from_value(json_val).unwrap();
        assert!(resp.items.is_empty());
    }

    #[test]
    fn usage_report_serde() {
        let json_val = json!({
            "kind": "admin#reports#usageReport",
            "date": "2026-03-13",
            "parameters": [{
                "name": "accounts:num_users",
                "intValue": "150"
            }]
        });
        let report: UsageReport = serde_json::from_value(json_val).unwrap();
        assert_eq!(report.date.unwrap(), "2026-03-13");
    }

    #[test]
    fn public_activity_page_preserves_resource_fields_and_provider_metadata() {
        let wire: ActivitiesListResponse = serde_json::from_value(json!({
            "kind": "admin#reports#activities",
            "etag": "audit-etag",
            "nextPageToken": "opaque+/=&?",
            "items": [{
                "id": { "uniqueQualifier": "17", "applicationName": "login" },
                "actor": { "profileId": "123" },
                "ipAddress": "192.0.2.1"
            }]
        }))
        .unwrap();
        let response = wire.into_public_response();
        assert_eq!(response["next_page_token"], "opaque+/=&?");
        assert!(response.get("nextPageToken").is_none());
        assert_eq!(response["kind"], "admin#reports#activities");
        assert_eq!(response["etag"], "audit-etag");
        assert_eq!(response["items"][0]["id"]["uniqueQualifier"], "17");
        assert_eq!(response["items"][0]["actor"]["profileId"], "123");
        assert_eq!(response["items"][0]["ipAddress"], "192.0.2.1");
    }

    #[test]
    fn public_usage_page_preserves_partial_data_warnings_and_terminal_cursor() {
        let warnings = json!([{
            "code": "200",
            "message": "Partial data is available",
            "data": [{ "key": "application", "value": "gmail" }]
        }]);
        let wire: UsageReportsListResponse = serde_json::from_value(json!({
            "usageReports": [{
                "date": "2026-03-13",
                "entity": { "userEmail": "ada@example.test" },
                "parameters": [{ "name": "gmail:num_emails_sent", "intValue": "7" }]
            }],
            "warnings": warnings
        }))
        .unwrap();
        let response = wire.into_public_response();
        assert_eq!(response.get("next_page_token"), Some(&Value::Null));
        assert!(response.get("nextPageToken").is_none());
        assert!(response.get("usageReports").is_none());
        assert!(response.get("kind").is_none());
        assert_eq!(response["warnings"], warnings);
        assert_eq!(
            response["usage_reports"][0]["entity"]["userEmail"],
            "ada@example.test"
        );
        assert_eq!(
            response["usage_reports"][0]["parameters"][0]["intValue"],
            "7"
        );
        let empty: UsageReportsListResponse = serde_json::from_value(json!({})).unwrap();
        assert_eq!(empty.into_public_response()["usage_reports"], json!([]));
    }
}
