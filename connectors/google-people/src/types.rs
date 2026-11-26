//! Google People API response wrappers used by the connector.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Response from `people.connections.list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListConnectionsResponse {
    #[serde(default)]
    pub connections: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_sync_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_people: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_items: Option<u32>,
}

/// Response from `people.searchContacts`, whose entries wrap a `person`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchResultsResponse {
    #[serde(default)]
    pub results: Vec<Value>,
}

/// Response from `people.searchDirectoryPeople`, which returns people directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchDirectoryPeopleResponse {
    #[serde(default)]
    pub people: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_size: Option<u32>,
}

/// Response from `otherContacts.list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListOtherContactsResponse {
    #[serde(default)]
    pub other_contacts: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_size: Option<u32>,
}

/// Response from `contactGroups.list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListContactGroupsResponse {
    #[serde(default)]
    pub contact_groups: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_items: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn list_connections_response_serde_roundtrip() {
        let response = ListConnectionsResponse {
            connections: vec![json!({"resourceName": "people/c1"})],
            next_page_token: Some("next".into()),
            next_sync_token: None,
            total_people: Some(1),
            total_items: Some(1),
        };
        let encoded = serde_json::to_string(&response).unwrap();
        let decoded: ListConnectionsResponse = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.connections.len(), 1);
        assert_eq!(decoded.next_page_token.as_deref(), Some("next"));
    }

    #[test]
    fn list_contact_groups_response_defaults_empty() {
        let decoded: ListContactGroupsResponse =
            serde_json::from_value(json!({ "contactGroups": [] })).unwrap();
        assert!(decoded.contact_groups.is_empty());
        assert!(decoded.next_page_token.is_none());
    }

    #[test]
    fn directory_response_decodes_people_and_continuation_metadata() {
        let response: SearchDirectoryPeopleResponse = serde_json::from_value(json!({
            "people": [{
                "resourceName": "people/directory-1",
                "emailAddresses": [{ "value": "ada@example.com" }]
            }],
            "nextPageToken": "directory-page-2",
            "totalSize": 2
        }))
        .unwrap();

        assert_eq!(response.people[0]["resourceName"], "people/directory-1");
        assert_eq!(
            response.next_page_token.as_deref(),
            Some("directory-page-2")
        );
        assert_eq!(response.total_size, Some(2));

        let empty: SearchDirectoryPeopleResponse = serde_json::from_value(json!({})).unwrap();
        assert!(empty.people.is_empty());
        assert!(empty.next_page_token.is_none());
        assert!(empty.total_size.is_none());
    }
}
