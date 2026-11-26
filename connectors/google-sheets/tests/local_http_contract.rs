use fcp_google_discovery::auth::{
    FCP_CREDENTIAL_ID_HEADER, GOOGLE_AUTHORIZATION_HEADER, GoogleAuthSourceKind,
    GoogleMaterializedAuth,
};
use fcp_google_sheets::client::SheetsClient;
use serde_json::json;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{header, method, path},
};

#[fcp_async_core::runtime::test]
async fn bearer_token_requests_use_authorization_header() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v4/spreadsheets/sheet123"))
        .and(header(GOOGLE_AUTHORIZATION_HEADER, "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "spreadsheetId": "sheet123",
            "properties": { "title": "Auth Header" },
            "sheets": [],
            "spreadsheetUrl": "https://docs.google.com/spreadsheets/d/sheet123"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = SheetsClient::new_with_auth(GoogleMaterializedAuth::BearerToken {
        access_token: "test-token".into(),
        source: GoogleAuthSourceKind::AccessToken,
        granted_scopes: Vec::new(),
        quota_project_id: None,
    })
    .expect("client")
    .with_base_url(format!("{}/v4", server.uri()));

    let spreadsheet = client
        .get_spreadsheet("sheet123")
        .await
        .expect("spreadsheet response");
    assert_eq!(spreadsheet.spreadsheet_id, "sheet123");
}

#[fcp_async_core::runtime::test]
async fn credential_reference_requests_use_fcp_credential_header() {
    let server = MockServer::start().await;
    let credential_id = fcp_core::CredentialId::new();
    Mock::given(method("GET"))
        .and(path("/v4/spreadsheets/sheet123"))
        .and(header(FCP_CREDENTIAL_ID_HEADER, credential_id.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "spreadsheetId": "sheet123",
            "properties": { "title": "Credential Header" },
            "sheets": [],
            "spreadsheetUrl": "https://docs.google.com/spreadsheets/d/sheet123"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = SheetsClient::new_with_auth(GoogleMaterializedAuth::CredentialReference {
        credential_id,
        quota_project_id: None,
    })
    .expect("client")
    .with_base_url(format!("{}/v4", server.uri()));

    let spreadsheet = client
        .get_spreadsheet("sheet123")
        .await
        .expect("spreadsheet response");
    assert_eq!(spreadsheet.spreadsheet_id, "sheet123");
}

fn loopback_client(server: &MockServer) -> SheetsClient {
    SheetsClient::new_with_auth(GoogleMaterializedAuth::CredentialReference {
        credential_id: fcp_core::CredentialId::new(),
        quota_project_id: None,
    })
    .unwrap()
    .with_base_url(format!("{}/v4", server.uri()))
}

#[fcp_async_core::runtime::test]
async fn writes_with_unknown_outcomes_never_advertise_a_retry() {
    for (method_name, status, body) in [
        (
            "POST",
            500_u16,
            r#"{"error":{"code":429,"message":"upstream failed"}}"#,
        ),
        ("POST", 200, "truncated receipt"),
        (
            "PUT",
            503,
            r#"{"error":{"code":401,"message":"backend unavailable"}}"#,
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(method(method_name))
            .respond_with(ResponseTemplate::new(status).set_body_string(body))
            .expect(1)
            .mount(&server)
            .await;
        let client = loopback_client(&server);
        let values = vec![vec![json!("one row")]];
        let error = if method_name == "POST" {
            client.append_values("id", "A1", values).await.unwrap_err()
        } else {
            client.update_values("id", "A1", values).await.unwrap_err()
        };
        assert!(!error.is_retryable());
        let wire_error = error.to_fcp_error();
        assert!(
            matches!(wire_error, fcp_core::FcpError::External {
            status_code: Some(actual), retryable: false, retry_after: None, ref message, ..
        } if actual == status && message.contains("Check the affected range"))
        );
        server.verify().await;
    }
}

#[fcp_async_core::runtime::test]
async fn actual_throttling_returns_the_provider_wait_even_when_body_code_disagrees() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("Retry-After", "125")
                .set_body_json(json!({"error": {"code": 500, "message": "try later"}})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let error = loopback_client(&server)
        .append_values("id", "A1", vec![vec![json!("one row")]])
        .await
        .unwrap_err()
        .to_fcp_error();
    assert!(matches!(
        error,
        fcp_core::FcpError::RateLimited {
            retry_after_ms: 125_000,
            ..
        }
    ));
    server.verify().await;
}

#[fcp_async_core::runtime::test]
async fn redirect_cannot_reissue_an_append() {
    let server = MockServer::start().await;
    let redirected = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(307).insert_header("Location", redirected.uri()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"spreadsheetId": "id"})))
        .expect(0)
        .mount(&redirected)
        .await;
    let error = loopback_client(&server)
        .append_values("id", "A1", vec![vec![json!(1)]])
        .await
        .unwrap_err()
        .to_fcp_error();
    assert!(matches!(
        error,
        fcp_core::FcpError::External {
            status_code: Some(307),
            retryable: false,
            ..
        }
    ));
    server.verify().await;
    redirected.verify().await;
}

#[fcp_async_core::runtime::test]
async fn reads_and_strictly_idempotent_clear_keep_transient_retry_classification() {
    let server = MockServer::start().await;
    for method_name in ["GET", "POST"] {
        Mock::given(method(method_name))
            .respond_with(
                ResponseTemplate::new(503)
                    .insert_header("Retry-After", "73")
                    .set_body_json(json!({
                        "error": {"code": 404, "message": "busy"}
                    })),
            )
            .expect(1)
            .mount(&server)
            .await;
    }
    let client = loopback_client(&server);
    for error in [
        client.get_values("id", "A1").await.unwrap_err(),
        client.clear_values("id", "A1").await.unwrap_err(),
    ] {
        assert!(
            matches!(error.to_fcp_error(), fcp_core::FcpError::External {
            status_code: Some(503), retryable: true, retry_after: Some(delay), message, ..
        } if message == "busy" && delay == std::time::Duration::from_secs(73))
        );
    }
    server.verify().await;
}
