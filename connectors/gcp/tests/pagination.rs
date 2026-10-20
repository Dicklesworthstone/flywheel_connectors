//! Provider-boundary contracts for complete GCP inventories. No live credentials
//! or cloud resources are used; each assertion observes actual HTTP requests.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fcp_gcp::client::GcpClient;
use fcp_gcp::error::GcpError;
use fcp_gcp::types::GcpAuth;
use fcp_prelude::FcpError;
use fcp_sdk::migration::HttpRetryConfig;
use fcp_sdk::{ConnectorRuntime, ConnectorRuntimeConfig};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

const COMPUTE_PATH: &str = "/compute/v1/projects/project/zones/us-central1-a/instances";
const STORAGE_PATH: &str = "/storage/v1/b/bucket/o";
const RUN_PATH: &str = "/v2/projects/project/locations/us-central1/services";

async fn client(server: &MockServer, retries: u32) -> GcpClient {
    let base = server.uri();
    GcpClient::new(
        "project",
        GcpAuth::AccessToken { access_token: "private-access-token".into() },
        HttpRetryConfig {
            max_retries: retries,
            initial_delay_ms: 1,
            max_delay_ms: 1,
            jitter_enabled: false,
        },
        Some(&base),
        Some(&base),
        Some(&base),
        Some(&base),
    )
    .await
    .unwrap()
}

fn runtime() -> ConnectorRuntime {
    ConnectorRuntime::new(
        ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(10)),
    )
}

fn cursor(request: &Request) -> Option<String> {
    let parameters = request.url.query_pairs().collect::<Vec<_>>();
    assert!(parameters.len() <= 1, "a cursor must not inject extra parameters");
    parameters.first().map(|(name, value)| {
        assert_eq!(name, "pageToken");
        value.to_string()
    })
}

fn assert_incomplete(error: &GcpError) {
    assert!(matches!(error, GcpError::IncompleteListing { .. }));
    assert!(!error.is_retryable());
    assert!(matches!(
        error.to_fcp_error(),
        FcpError::External { retryable: false, retry_after: None, .. }
    ));
    for text in [error.to_string(), format!("{error:?}"), error.to_fcp_error().to_string()] {
        assert!(!text.contains("private-cursor"));
        assert!(!text.contains("private-access-token"));
    }
}

#[fcp_async_core::runtime::test]
async fn compute_inventory_traverses_every_page_in_provider_order() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(COMPUTE_PATH))
        .respond_with(|request: &Request| {
            assert_eq!(request.headers.get("authorization").unwrap(), "Bearer private-access-token");
            match cursor(request).as_deref() {
                None => ResponseTemplate::new(200).set_body_json(json!({
                    "items": [{"name": "vm-1"}], "nextPageToken": "page-2"
                })),
                Some("page-2") => ResponseTemplate::new(200).set_body_json(json!({
                    "items": [{"name": "vm-2"}], "nextPageToken": "page-3"
                })),
                Some("page-3") => ResponseTemplate::new(200).set_body_json(json!({
                    "items": [{"name": "vm-3"}]
                })),
                other => panic!("unexpected page: {other:?}"),
            }
        })
        .expect(3)
        .mount(&server)
        .await;
    let items = client(&server, 1).await.list_instances(&runtime(), "us-central1-a").await.unwrap();
    assert_eq!(items.into_iter().map(|item| item.name).collect::<Vec<_>>(), ["vm-1", "vm-2", "vm-3"]);
}

#[fcp_async_core::runtime::test]
async fn storage_follows_a_continuation_after_an_empty_page() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(STORAGE_PATH))
        .respond_with(|request: &Request| match cursor(request).as_deref() {
            None => ResponseTemplate::new(200).set_body_json(json!({
                "items": [{"name": "a"}], "nextPageToken": "empty-page"
            })),
            Some("empty-page") => ResponseTemplate::new(200).set_body_json(json!({
                "nextPageToken": "last-page"
            })),
            Some("last-page") => ResponseTemplate::new(200).set_body_json(json!({
                "items": [{"name": "z"}], "nextPageToken": ""
            })),
            other => panic!("unexpected page: {other:?}"),
        })
        .expect(3)
        .mount(&server)
        .await;
    let items = client(&server, 1).await.list_objects(&runtime(), "bucket").await.unwrap();
    assert_eq!(items.into_iter().map(|item| item.name).collect::<Vec<_>>(), ["a", "z"]);
}

#[fcp_async_core::runtime::test]
async fn cloud_run_services_use_the_services_envelope_on_every_page() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(RUN_PATH))
        .respond_with(|request: &Request| match cursor(request).as_deref() {
            None => ResponseTemplate::new(200).set_body_json(json!({
                "services": [{"name": "first-service"}], "nextPageToken": "second"
            })),
            Some("second") => ResponseTemplate::new(200).set_body_json(json!({
                "services": [{"name": "second-service"}]
            })),
            other => panic!("unexpected page: {other:?}"),
        })
        .expect(2)
        .mount(&server)
        .await;
    let items = client(&server, 1).await.list_services(&runtime(), "us-central1").await.unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].name.as_deref(), Some("first-service"));
    assert_eq!(items[1].name.as_deref(), Some("second-service"));
}

#[fcp_async_core::runtime::test]
async fn opaque_cursors_cannot_rewrite_the_endpoint_or_query_parameters() {
    const TOKEN: &str = " https://elsewhere.invalid/../?alt=media&key=private-cursor+#%é ";
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(STORAGE_PATH))
        .respond_with(|request: &Request| match cursor(request) {
            None => ResponseTemplate::new(200).set_body_json(json!({"nextPageToken": TOKEN})),
            Some(token) => {
                assert_eq!(token, TOKEN, "do not trim, decode or normalize a cursor");
                assert!(request.url.fragment().is_none());
                ResponseTemplate::new(200).set_body_json(json!({"items": [{"name": "found"}]}))
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let items = client(&server, 1).await.list_objects(&runtime(), "bucket").await.unwrap();
    assert_eq!(items[0].name, "found");
}

#[fcp_async_core::runtime::test]
async fn transient_errors_repeat_only_the_failed_page_without_duplicate_items() {
    for status in [429, 503] {
        let server = MockServer::start().await;
        let second_page_attempts = AtomicUsize::new(0);
        Mock::given(method("GET"))
            .and(path(COMPUTE_PATH))
            .respond_with(move |request: &Request| {
                if cursor(request).is_none() {
                    return ResponseTemplate::new(200).set_body_json(json!({
                        "items": [{"name": "vm-first"}], "nextPageToken": "private-cursor"
                    }));
                }
                assert_eq!(cursor(request).as_deref(), Some("private-cursor"));
                if second_page_attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(status).insert_header("Retry-After", "0")
                } else {
                    ResponseTemplate::new(200).set_body_json(json!({"items": [{"name": "vm-last"}]}))
                }
            })
            .expect(3)
            .mount(&server)
            .await;
        let items = client(&server, 1).await.list_instances(&runtime(), "us-central1-a").await.unwrap();
        assert_eq!(items.into_iter().map(|item| item.name).collect::<Vec<_>>(), ["vm-first", "vm-last"]);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.iter().map(cursor).collect::<Vec<_>>(), [
            None, Some("private-cursor".into()), Some("private-cursor".into())
        ]);
    }
}

#[fcp_async_core::runtime::test]
async fn exhausted_later_page_returns_an_error_not_the_first_page() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(STORAGE_PATH))
        .respond_with(|request: &Request| {
            if cursor(request).is_none() {
                ResponseTemplate::new(200).set_body_json(json!({
                    "items": [{"name": "not-a-complete-list"}], "nextPageToken": "private-cursor"
                }))
            } else {
                ResponseTemplate::new(503).set_body_string("provider echoed private-cursor")
            }
        })
        .expect(3)
        .mount(&server)
        .await;
    let error = client(&server, 1).await.list_objects(&runtime(), "bucket").await.unwrap_err();
    assert!(matches!(error, GcpError::Api { code: 503, .. }));
    assert!(!error.to_string().contains("private-cursor"));
}

#[fcp_async_core::runtime::test]
async fn cursor_cycles_are_terminal_and_redacted() {
    for longer_cycle in [false, true] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(STORAGE_PATH))
            .respond_with(move |request: &Request| {
                let next = match cursor(request).as_deref() {
                    Some("private-cursor-a") if longer_cycle => "private-cursor-b",
                    _ => "private-cursor-a",
                };
                ResponseTemplate::new(200).set_body_json(json!({
                    "items": [], "nextPageToken": next
                }))
            })
            .expect(if longer_cycle { 3 } else { 2 })
            .mount(&server)
            .await;
        let error = client(&server, 3).await.list_objects(&runtime(), "bucket").await.unwrap_err();
        assert_incomplete(&error);
    }
}

#[fcp_async_core::runtime::test]
async fn oversized_cursors_are_rejected_before_the_next_request() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(STORAGE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [{"name": "prefix"}], "nextPageToken": "x".repeat(8 * 1024 + 1)
        })))
        .expect(1)
        .mount(&server)
        .await;
    let error = client(&server, 3).await.list_objects(&runtime(), "bucket").await.unwrap_err();
    assert_incomplete(&error);
}

#[fcp_async_core::runtime::test]
async fn malformed_later_pages_are_not_silently_dropped() {
    for body in ["{broken", r#"{"items":[{"name":"later"}],"nextPageToken":17}"#] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(STORAGE_PATH))
            .respond_with(move |request: &Request| {
                if cursor(request).is_none() {
                    ResponseTemplate::new(200).set_body_json(json!({
                        "items": [{"name": "first"}], "nextPageToken": "private-cursor"
                    }))
                } else {
                    ResponseTemplate::new(200).set_body_string(body)
                }
            })
            .expect(2)
            .mount(&server)
            .await;
        let error = client(&server, 3).await.list_objects(&runtime(), "bucket").await.unwrap_err();
        assert_incomplete(&error);
    }
}

#[fcp_async_core::runtime::test]
async fn provider_partial_success_never_masquerades_as_a_complete_inventory() {
    for partial in [
        json!({"services": [{"name": "visible"}], "unreachable": ["private-cursor-region"]}),
        json!({"services": [{"name": "visible"}], "error": {"message": "private-cursor-detail"}}),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(RUN_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(partial))
            .expect(1)
            .mount(&server)
            .await;
        let error = client(&server, 3).await.list_services(&runtime(), "us-central1").await.unwrap_err();
        assert_incomplete(&error);
    }
}

#[fcp_async_core::runtime::test]
async fn later_page_redirect_is_not_followed_and_does_not_expose_the_cursor() {
    let server = MockServer::start().await;
    let destination = MockServer::start().await;
    let location = format!("{}/collect?token=private-cursor", destination.uri());
    Mock::given(method("GET"))
        .and(path(STORAGE_PATH))
        .respond_with(move |request: &Request| {
            if cursor(request).is_none() {
                ResponseTemplate::new(200).set_body_json(json!({"nextPageToken": "private-cursor"}))
            } else {
                ResponseTemplate::new(307).insert_header("Location", location.as_str())
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let error = client(&server, 3).await.list_objects(&runtime(), "bucket").await.unwrap_err();
    assert!(matches!(error, GcpError::Api { code: 307, .. }));
    assert!(!error.is_retryable());
    assert!(!error.to_string().contains("private-cursor"));
    assert!(destination.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn page_response_size_is_bounded_before_decoding() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(STORAGE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_string(" ".repeat(8 * 1024 * 1024 + 1)))
        .expect(1)
        .mount(&server)
        .await;
    let error = client(&server, 3).await.list_objects(&runtime(), "bucket").await.unwrap_err();
    assert_incomplete(&error);
    assert!(error.to_string().contains("page byte limit"));
}

#[fcp_async_core::runtime::test]
async fn shutdown_does_not_allow_fetching_another_page() {
    let server = MockServer::start().await;
    let runtime = Arc::new(runtime());
    let shutdown = Arc::clone(&runtime);
    Mock::given(method("GET"))
        .and(path(STORAGE_PATH))
        .respond_with(move |_: &Request| {
            shutdown.shutdown();
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(2))
                .set_body_json(json!({"nextPageToken": "must-not-fetch"}))
        })
        .expect(1)
        .mount(&server)
        .await;
    let error = client(&server, 3).await.list_objects(&runtime, "bucket").await.unwrap_err();
    assert!(matches!(error, GcpError::Async(_)));
}

#[fcp_async_core::runtime::test]
async fn pagination_does_not_reset_the_deadline_for_each_page() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(STORAGE_PATH))
        .respond_with(|request: &Request| {
            let body = if cursor(request).is_none() {
                json!({"items": [{"name": "first"}], "nextPageToken": "later"})
            } else {
                json!({"items": [{"name": "second"}]})
            };
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(650))
                .set_body_json(body)
        })
        .expect(2)
        .mount(&server)
        .await;
    let runtime = ConnectorRuntime::new(
        ConnectorRuntimeConfig::default().with_request_timeout(Duration::from_secs(1)),
    );
    let error = client(&server, 0).await.list_objects(&runtime, "bucket").await.unwrap_err();
    assert!(matches!(error, GcpError::Async(_)));
}

#[fcp_async_core::runtime::test]
async fn genuinely_empty_inventories_complete_without_an_extra_request() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(STORAGE_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;
    let items = client(&server, 1).await.list_objects(&runtime(), "bucket").await.unwrap();
    assert!(items.is_empty());
}
