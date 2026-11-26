//! Connector-local no-mock Google People integration proof.
//!
//! These tests exercise the real Google People client against a local HTTP
//! server. No live Google People API service is called.

#![allow(clippy::too_many_lines)]

use std::collections::BTreeSet;
use std::time::Duration;

use fcp_async_core::AsyncError;
use fcp_google_discovery::auth::{
    GOOGLE_AUTHORIZATION_HEADER, GoogleAuthSourceKind, GoogleMaterializedAuth,
};
use fcp_google_people::client::GooglePeopleClient;
use fcp_google_people::connector::GooglePeopleConnector;
use fcp_google_people::error::GooglePeopleError;
use fcp_prelude::FcpError;
use fcp_sdk::ConnectorErrorMapping;
use serde_json::{Value, json};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_TOKEN: &str = "ya29.google-people-test-token";
const AUTH_HEADER_VALUE: &str = "Bearer ya29.google-people-test-token";
const PEOPLE_OPERATIONS: &[&str] = &[
    "people.list_connections",
    "people.get_person",
    "people.search_contacts",
    "people.list_other_contacts",
    "people.search_directory_people",
    "people.list_contact_groups",
    "people.create_contact",
    "people.update_contact",
    "people.delete_contact",
];

fn materialized_test_auth() -> GoogleMaterializedAuth {
    GoogleMaterializedAuth::BearerToken {
        access_token: TEST_TOKEN.to_string(),
        source: GoogleAuthSourceKind::AccessToken,
        granted_scopes: Vec::new(),
        quota_project_id: None,
    }
}

fn client(server: &MockServer) -> GooglePeopleClient {
    GooglePeopleClient::new_with_auth(materialized_test_auth())
        .expect("test auth should build a Google People client")
        .with_base_url(&format!("{}/v1", server.uri()))
}

async fn configured_connector(server: &MockServer) -> GooglePeopleConnector {
    let mut connector = GooglePeopleConnector::new();
    connector
        .handle_configure(json!({
            "access_token": TEST_TOKEN,
            "base_url": format!("{}/v1", server.uri()),
            "scope_triggers": [
                "User enables contact create, update, photo update, or group-membership mutation workflows.",
                "User enables Google Workspace directory search or lookup workflows.",
                "User enables reads from Google-suggested other contacts."
            ]
        }))
        .await
        .expect("loopback base_url and in-memory bearer token should configure");
    connector
}

fn field<'a>(value: &'a Value, name: &str) -> &'a Value {
    value.get(name).expect("missing expected JSON field")
}

fn array_field<'a>(value: &'a Value, name: &str) -> &'a Vec<Value> {
    field(value, name)
        .as_array()
        .expect("expected JSON field to be an array")
}

fn operation_ids(introspection: &Value) -> Vec<&str> {
    array_field(introspection, "operations")
        .iter()
        .filter_map(|operation| field(operation, "id").as_str())
        .collect()
}

fn operation<'a>(introspection: &'a Value, id: &str) -> &'a Value {
    array_field(introspection, "operations")
        .iter()
        .find(|operation| field(operation, "id") == id)
        .expect("introspection should contain requested operation")
}

fn manifest_declares_operation(manifest: &str, id: &str) -> bool {
    manifest
        .lines()
        .any(|line| line.starts_with("[provides.operations.") && line.contains(id))
}

fn manifest_capability_section() -> &'static str {
    let manifest = include_str!("../manifest.toml");
    let (_, capabilities) = manifest
        .split_once("[capabilities]")
        .expect("Google People manifest should define capabilities");
    let (capability_section, _) = capabilities
        .split_once("[provides.operations.")
        .expect("Google People manifest should separate capabilities from operations");
    capability_section
}

#[test]
fn manifest_ai_hints_cover_all_operations() {
    let manifest: toml::Value = toml::from_str(include_str!("../manifest.toml"))
        .expect("Google People manifest should parse");
    let operations = manifest
        .get("provides")
        .and_then(|provides| provides.get("operations"))
        .and_then(toml::Value::as_table)
        .expect("Google People manifest should declare operations");

    let expected = PEOPLE_OPERATIONS.iter().copied().collect::<BTreeSet<_>>();
    let actual = operations
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual, expected,
        "manifest operation inventory changed; update ai_hints coverage expectations"
    );

    for &operation_id in PEOPLE_OPERATIONS {
        let operation = operations
            .get(operation_id)
            .and_then(toml::Value::as_table)
            .expect("operation should be a TOML table");
        let ai_hints = operation
            .get("ai_hints")
            .and_then(toml::Value::as_table)
            .expect("operation should declare ai_hints");

        let when_to_use = ai_hints
            .get("when_to_use")
            .and_then(toml::Value::as_str)
            .map(str::trim)
            .unwrap_or_default();
        assert!(
            !when_to_use.is_empty(),
            "operation {operation_id} should explain when to use it"
        );

        let common_mistakes = ai_hints
            .get("common_mistakes")
            .and_then(toml::Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        assert!(
            common_mistakes.len() >= 2
                && common_mistakes
                    .iter()
                    .filter_map(toml::Value::as_str)
                    .all(|mistake| !mistake.trim().is_empty()),
            "operation {operation_id} should document at least two common mistakes"
        );

        let examples = ai_hints
            .get("examples")
            .and_then(toml::Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        assert!(
            !examples.is_empty(),
            "operation {operation_id} should include at least one JSON example"
        );
        for example in examples {
            let example_text = example
                .as_str()
                .expect("operation example should be a string")
                .trim();
            assert!(
                !example_text.is_empty(),
                "operation {operation_id} should not contain empty examples"
            );
            let parsed_example = serde_json::from_str::<Value>(example_text);
            assert!(
                parsed_example.is_ok(),
                "operation {operation_id} example must be JSON: {parsed_example:?}"
            );

            let lower = example_text.to_ascii_lowercase();
            for forbidden in ["api_key", "bearer", "password", "secret", "token"] {
                assert!(
                    !lower.contains(forbidden),
                    "operation {operation_id} example contains secret-shaped text: {forbidden}"
                );
            }
        }
    }
}

#[fcp_async_core::runtime::test]
async fn contacts_directory_groups_and_mutations_use_people_contracts() {
    tracing::info!(
        scenario = "google_people_success_contracts",
        "starting Google People success-path integration proof",
    );

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/people/me/connections"))
        .and(query_param("personFields", "names,emailAddresses"))
        .and(query_param("pageSize", "2"))
        .and(query_param("pageToken", "contacts-page-1"))
        .and(query_param("sortOrder", "LAST_MODIFIED_ASCENDING"))
        .and(header(GOOGLE_AUTHORIZATION_HEADER, AUTH_HEADER_VALUE))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "connections": [{
                "resourceName": "people/contact-1",
                "etag": "%EgUBAQMEBQY=",
                "names": [{ "displayName": "Alice Ng" }],
                "emailAddresses": [{ "value": "alice@example.com" }]
            }],
            "nextPageToken": "contacts-page-2",
            "totalPeople": 1,
            "totalItems": 1
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/people:searchDirectoryPeople"))
        .and(query_param("query", "alice"))
        .and(query_param(
            "readMask",
            "names,emailAddresses,organizations",
        ))
        .and(query_param("pageSize", "5"))
        .and(query_param(
            "sources",
            "DIRECTORY_SOURCE_TYPE_DOMAIN_PROFILE",
        ))
        .and(header(GOOGLE_AUTHORIZATION_HEADER, AUTH_HEADER_VALUE))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "people": [{
                "resourceName": "people/directory-1",
                "names": [{ "displayName": "Alice Directory" }],
                "organizations": [{ "name": "Example Engineering" }]
            }],
            "nextPageToken": "directory-page-2",
            "totalSize": 2
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/contactGroups"))
        .and(query_param("groupFields", "name,memberCount"))
        .and(query_param("pageSize", "10"))
        .and(query_param("pageToken", "groups-page-1"))
        .and(header(GOOGLE_AUTHORIZATION_HEADER, AUTH_HEADER_VALUE))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "contactGroups": [{
                "resourceName": "contactGroups/friends",
                "name": "Friends",
                "memberCount": 3
            }],
            "nextPageToken": "groups-page-2",
            "totalItems": 1
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/people:createContact"))
        .and(header(GOOGLE_AUTHORIZATION_HEADER, AUTH_HEADER_VALUE))
        .and(body_json(json!({
            "names": [{ "givenName": "Alice", "familyName": "Ng" }],
            "emailAddresses": [{ "value": "alice@example.com" }]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "resourceName": "people/contact-created",
            "etag": "%created",
            "names": [{ "displayName": "Alice Ng" }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("PATCH"))
        .and(path("/v1/people/contact-created:updateContact"))
        .and(query_param("updatePersonFields", "emailAddresses,names"))
        .and(header(GOOGLE_AUTHORIZATION_HEADER, AUTH_HEADER_VALUE))
        .and(body_json(json!({
            "resourceName": "people/contact-created",
            "etag": "%created",
            "names": [{ "displayName": "Alice N." }],
            "emailAddresses": [{ "value": "alice.n@example.com" }]
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "resourceName": "people/contact-created",
            "etag": "%updated",
            "names": [{ "displayName": "Alice N." }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/v1/people/contact-created:deleteContact"))
        .and(header(GOOGLE_AUTHORIZATION_HEADER, AUTH_HEADER_VALUE))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/contactGroups"))
        .and(query_param("groupFields", "name"))
        .and(query_param("pageSize", "1"))
        .and(header(GOOGLE_AUTHORIZATION_HEADER, AUTH_HEADER_VALUE))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "contactGroups": [{ "resourceName": "contactGroups/all", "name": "All Contacts" }]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);
    let connections = client
        .list_connections(
            &["names".into(), "emailAddresses".into()],
            Some(2),
            Some("contacts-page-1"),
            Some("LAST_MODIFIED_ASCENDING"),
        )
        .await
        .expect("connections list should decode");
    assert_eq!(
        connections.next_page_token.as_deref(),
        Some("contacts-page-2")
    );
    assert_eq!(connections.connections.len(), 1);

    let directory = client
        .search_directory_people(
            "alice",
            &[
                "names".into(),
                "emailAddresses".into(),
                "organizations".into(),
            ],
            Some(5),
            None,
            &["DIRECTORY_SOURCE_TYPE_DOMAIN_PROFILE".into()],
        )
        .await
        .expect("directory search should decode");
    assert_eq!(directory.people[0]["resourceName"], "people/directory-1");
    assert_eq!(
        directory.next_page_token.as_deref(),
        Some("directory-page-2")
    );
    assert_eq!(directory.total_size, Some(2));

    let groups = client
        .list_contact_groups(
            &["name".into(), "memberCount".into()],
            Some(10),
            Some("groups-page-1"),
        )
        .await
        .expect("contact group listing should decode");
    assert_eq!(groups.next_page_token.as_deref(), Some("groups-page-2"));
    assert_eq!(groups.contact_groups.len(), 1);

    let created = client
        .create_contact(&json!({
            "names": [{ "givenName": "Alice", "familyName": "Ng" }],
            "emailAddresses": [{ "value": "alice@example.com" }]
        }))
        .await
        .expect("contact creation should decode");
    assert_eq!(created["resourceName"], "people/contact-created");

    let updated = client
        .update_contact(
            "people/contact-created",
            &["emailAddresses".into(), "names".into()],
            &json!({
                "resourceName": "people/contact-created",
                "etag": "%created",
                "names": [{ "displayName": "Alice N." }],
                "emailAddresses": [{ "value": "alice.n@example.com" }]
            }),
        )
        .await
        .expect("contact update should decode");
    assert_eq!(updated["etag"], "%updated");

    client
        .delete_contact("people/contact-created")
        .await
        .expect("contact deletion should accept an empty success response");

    client
        .health_check()
        .await
        .expect("health check should use a lightweight contact-groups probe");
}

#[fcp_async_core::runtime::test]
async fn auth_rate_limit_malformed_json_and_fcp_mapping_are_typed() {
    tracing::info!(
        scenario = "google_people_error_taxonomy",
        "starting Google People error-taxonomy integration proof",
    );

    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/v1/people/bad-auth"))
        .and(query_param("personFields", "names"))
        .and(header(GOOGLE_AUTHORIZATION_HEADER, AUTH_HEADER_VALUE))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": {
                "code": 401,
                "message": "invalid credentials",
                "status": "UNAUTHENTICATED"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/contactGroups"))
        .and(query_param("groupFields", "name"))
        .and(query_param("pageSize", "2"))
        .and(header(GOOGLE_AUTHORIZATION_HEADER, AUTH_HEADER_VALUE))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "0")
                .set_body_json(json!({
                    "error": {
                        "code": 429,
                        "message": "quota exhausted",
                        "status": "RESOURCE_EXHAUSTED"
                    }
                })),
        )
        .expect(4)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/people/malformed"))
        .and(query_param("personFields", "names"))
        .and(header(GOOGLE_AUTHORIZATION_HEADER, AUTH_HEADER_VALUE))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string("{this is not json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let client = client(&server);

    let unauthorized = client
        .get_person("people/bad-auth", &["names".into()], &[])
        .await
        .expect_err("401 should map to Google People unauthorized");
    assert!(matches!(unauthorized, GooglePeopleError::Unauthorized));
    assert!(!unauthorized.is_retryable());
    assert!(matches!(
        unauthorized.to_fcp_error(),
        FcpError::Unauthorized { code: 2001, .. }
    ));

    let rate_limited = client
        .list_contact_groups(&["name".into()], Some(2), None)
        .await
        .expect_err("429 should map to Google People rate limit");
    assert!(matches!(
        rate_limited,
        GooglePeopleError::RateLimited {
            retry_after_secs: 0
        }
    ));
    assert_eq!(rate_limited.retry_after(), Some(Duration::ZERO));
    assert!(matches!(
        rate_limited.to_fcp_error(),
        FcpError::RateLimited {
            retry_after_ms: 0,
            ..
        }
    ));

    let nonzero_retry_after = GooglePeopleError::RateLimited {
        retry_after_secs: 7,
    };
    assert!(matches!(
        nonzero_retry_after.to_fcp_error(),
        FcpError::RateLimited {
            retry_after_ms: 7_000,
            ..
        }
    ));

    let malformed = client
        .get_person("people/malformed", &["names".into()], &[])
        .await
        .expect_err("malformed JSON should be surfaced as a JSON error");
    assert!(matches!(malformed, GooglePeopleError::Json(_)));
    assert!(matches!(
        malformed.to_fcp_error(),
        FcpError::Internal { .. }
    ));
}

#[test]
fn async_timeout_and_cancellation_mapping_is_bounded() {
    let timeout = GooglePeopleError::from_async_error(AsyncError::Timeout { timeout_ms: 250 });
    assert!(matches!(
        &timeout,
        GooglePeopleError::Api {
            status_code: 408,
            message,
        } if message.contains("250ms")
    ));
    assert!(!timeout.is_retryable());
    assert!(matches!(
        timeout.to_fcp_error(),
        FcpError::External {
            service,
            status_code: Some(408),
            retryable: false,
            ..
        } if service == "google_people"
    ));

    let cancelled = GooglePeopleError::from_async_error(AsyncError::Cancelled);
    assert!(matches!(
        &cancelled,
        GooglePeopleError::Api {
            status_code: 0,
            message,
        } if message == "request cancelled"
    ));
    assert!(!cancelled.is_retryable());
}

#[fcp_async_core::runtime::test]
async fn operation_catalog_manifest_and_redaction_preserve_security_posture() {
    let server = MockServer::start().await;
    let connector = configured_connector(&server).await;
    let introspection = connector
        .handle_introspect()
        .await
        .expect("introspection should serialize");
    let ids = operation_ids(&introspection);
    for &id in PEOPLE_OPERATIONS {
        assert!(ids.contains(&id), "introspection missing operation {id}");
    }

    let list_connections = operation(&introspection, "people.list_connections");
    assert_eq!(
        field(list_connections, "capability"),
        "people.contacts.read"
    );
    assert_eq!(field(list_connections, "safety_tier"), "safe");
    assert_eq!(field(list_connections, "idempotency"), "strict");
    assert_eq!(field(list_connections, "requires_approval"), "policy");

    let create_contact = operation(&introspection, "people.create_contact");
    assert_eq!(field(create_contact, "capability"), "people.contacts.write");
    assert_eq!(field(create_contact, "safety_tier"), "risky");
    assert_eq!(field(create_contact, "requires_approval"), "policy");

    let delete_contact = operation(&introspection, "people.delete_contact");
    assert_eq!(
        field(delete_contact, "capability"),
        "people.contacts.delete"
    );
    assert_eq!(field(delete_contact, "safety_tier"), "dangerous");
    assert_eq!(field(delete_contact, "requires_approval"), "interactive");

    let manifest = include_str!("../manifest.toml");
    for id in ids {
        assert!(
            manifest_declares_operation(manifest, id),
            "manifest missing introspected operation {id}"
        );
    }
    assert!(manifest.contains("deny_localhost = true"));
    assert!(manifest.contains("require_sni = true"));
    assert!(manifest.contains("deny_ip_literals = true"));
    assert!(manifest.contains("[sandbox]"));
    assert!(manifest.contains("profile = \"strict\""));
    assert!(manifest.contains("memory_mb = 128"));
    assert!(manifest.contains("cpu_percent = 25"));
    assert!(manifest.contains("wall_clock_timeout_ms = 30000"));
    assert!(manifest.contains("fs_writable_paths = [\"$CONNECTOR_STATE\"]"));
    assert!(manifest.contains("deny_exec = true"));
    assert!(manifest.contains("deny_ptrace = true"));

    let capability_section = manifest_capability_section();
    assert!(capability_section.contains("\"network.dns\""));
    assert!(capability_section.contains("\"network.egress\""));
    assert!(capability_section.contains("\"network.tls.sni\""));
    assert!(capability_section.contains("\"storage.state\""));
    assert!(capability_section.contains("\"system.exec\""));
    assert!(capability_section.contains("\"network.listen\""));

    let health = connector
        .handle_health()
        .await
        .expect("health should serialize configured metadata");
    let health_auth_mode = field(&health, "auth_mode")
        .as_str()
        .expect("health auth_mode should be a string");
    assert_eq!(health_auth_mode, "google_auth:bearer:redacted");
    assert!(!health.to_string().contains(TEST_TOKEN));

    let mut fresh_connector = GooglePeopleConnector::new();
    let configure_details = field(
        &fresh_connector
            .handle_configure(json!({
                "access_token": TEST_TOKEN,
                "base_url": format!("{}/v1", server.uri())
            }))
            .await
            .expect("configure should serialize redacted auth details"),
        "details",
    )
    .clone();
    assert_eq!(
        field(&configure_details, "auth_mode"),
        "google_auth:bearer:redacted"
    );
    assert!(!configure_details.to_string().contains(TEST_TOKEN));

    let client = client(&server);
    let debug_output = format!("{client:?}");
    assert!(!debug_output.contains(TEST_TOKEN));
    assert!(debug_output.contains("google_auth:bearer:redacted"));
}
