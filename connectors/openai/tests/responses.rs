//! Deterministic Responses API HTTP and function-continuation coverage.
//!
//! Every request targets a local server. The model marker deliberately lies
//! outside the connector's legacy chat model enum; no live model is invoked.

#![allow(clippy::too_many_lines)]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use fcp_openai::{
    client::{OpenAIAuth, OpenAIClient},
    error::OpenAIError,
    types::{ResponsesRequest, ResponsesResponse, RetrieveResponseRequest},
};
use fcp_prelude::CredentialId;
use serde_json::{Value, json};
use wiremock::{
    Mock, MockServer, Request, ResponseTemplate,
    matchers::{body_json, header, method, path, query_param},
};

const MODEL: &str = "model-from-provider-catalog";

fn request(value: Value) -> ResponsesRequest {
    serde_json::from_value(value).expect("Responses request should deserialize")
}

fn provider_response(id: &str, output: Value, usage: Value) -> Value {
    json!({
        "id": id,
        "object": "response",
        "created_at": 1_800_000_000,
        "status": "completed",
        "model": MODEL,
        "output": output,
        "usage": usage,
        "error": null,
        "incomplete_details": null,
        "future_response_field": {"retained": ["provider", "metadata"]}
    })
}

fn reported_usage(input: u64, output: u64) -> Value {
    json!({
        "input_tokens": input,
        "output_tokens": output,
        "total_tokens": input + output,
        "input_tokens_details": {"cached_tokens": 3},
        "output_tokens_details": {"reasoning_tokens": 2},
        "future_usage_field": "retained"
    })
}

#[fcp_async_core::runtime::test]
async fn responses_preserve_function_calls_and_previous_response_continuation() {
    let server = MockServer::start().await;
    let tools = json!([{
        "type": "function",
        "name": "weather",
        "description": "Read the weather for a city",
        "parameters": {
            "type": "object",
            "properties": {"city": {"type": "string"}},
            "required": ["city"],
            "additionalProperties": false
        },
        "strict": true
    }]);
    let first_input = json!({
        "model": MODEL,
        "input": "What is the weather in Paris?",
        "instructions": "Use the supplied weather function.",
        "tools": tools,
        "tool_choice": {"type": "function", "name": "weather"},
        "max_output_tokens": 256,
        "reasoning": {"effort": "low", "summary": "auto"},
        "text": {"format": {"type": "text"}},
        "store": true,
        "include": ["reasoning.encrypted_content"],
        "parallel_tool_calls": false,
        "metadata": {"scenario": "function-continuation"},
        "stream": false,
        "background": false
    });
    let raw_arguments = "{ \"city\" : \"Paris\" }";
    let first_payload = provider_response(
        "resp-first",
        json!([
            {"id": "reasoning-first", "type": "reasoning", "summary": [], "encrypted_content": "opaque-history"},
            {
                "id": "item-weather",
                "type": "function_call",
                "call_id": "call-weather",
                "name": "weather",
                "arguments": raw_arguments,
                "status": "completed",
                "future_call_field": {"retained": true}
            }
        ]),
        reported_usage(17, 9),
    );
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .and(header("authorization", "Bearer responses-test-key"))
        .and(header("openai-organization", "org-responses-test"))
        .and(body_json(first_input.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_json(first_payload.clone()))
        .expect(1)
        .mount(&server)
        .await;
    let client = OpenAIClient::new("responses-test-key")
        .unwrap()
        .with_base_url(server.uri())
        .with_organization("org-responses-test")
        .with_retry_config(0, 1, 1);
    let first = client.create_response(&request(first_input)).await.unwrap();
    assert_eq!(serde_json::to_value(&first).unwrap(), first_payload);
    assert_eq!(first.output_text(), "");
    let calls: Vec<_> = first.function_calls().collect();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["arguments"], raw_arguments);
    assert_eq!(calls[0]["call_id"], "call-weather");
    assert_ne!(calls[0]["id"], calls[0]["call_id"]);

    let continuation = json!({
        "model": MODEL,
        "previous_response_id": first.id,
        "input": [{
            "type": "function_call_output",
            "call_id": calls[0]["call_id"],
            "output": "{\"temperature_c\":18}"
        }],
        "instructions": "Explain the weather result.",
        "tools": tools,
        "tool_choice": "auto",
        "max_output_tokens": 128,
        "text": {
            "format": {
                "type": "json_schema",
                "name": "weather_summary",
                "strict": true,
                "schema": {
                    "type": "object",
                    "properties": {"summary": {"type": "string"}},
                    "required": ["summary"],
                    "additionalProperties": false
                }
            }
        },
        "store": true
    });
    let second_payload = provider_response(
        "resp-second",
        json!([
            {
                "id": "message-second",
                "type": "message",
                "role": "assistant",
                "status": "completed",
                "content": [
                    {"type": "output_text", "text": "{\"summary\":", "annotations": [{"type": "future_annotation", "retained": true}]},
                    {"type": "output_text", "text": "\"Mild weather\"}", "annotations": []}
                ]
            },
            {"type": "future_output_item", "opaque": {"retained": true}}
        ]),
        reported_usage(24, 11),
    );
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .and(body_json(continuation.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_json(second_payload.clone()))
        .expect(1)
        .mount(&server)
        .await;
    let second = client
        .create_response(&request(continuation))
        .await
        .unwrap();
    assert_eq!(second.output_text(), "{\"summary\":\"Mild weather\"}");
    assert_eq!(serde_json::to_value(&second).unwrap(), second_payload);
    assert_eq!(client.total_prompt_tokens(), 41);
    assert_eq!(client.total_completion_tokens(), 20);
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[fcp_async_core::runtime::test]
async fn stateless_continuation_replays_output_items_without_rewriting_arguments() {
    let server = MockServer::start().await;
    let history = json!([
        {"role": "user", "content": [
            {"type": "input_text", "text": "Read the file."},
            {"type": "input_file", "file_id": "file-instructions"},
            {"type": "input_image", "image_url": "data:image/png;base64,AA=="}
        ]},
        {"type": "item_reference", "id": "item-remembered"},
        {"id": "reasoning-history", "type": "reasoning", "summary": [], "encrypted_content": "opaque-history"},
        {"id": "item-read", "type": "function_call", "call_id": "call-read", "name": "read_file", "arguments": "{ \"path\" : \"notes.txt\" }"},
        {
            "type": "function_call_output",
            "call_id": "call-read",
            "output": [
                {"type": "input_text", "text": "File content"},
                {"type": "input_file", "file_id": "file-tool-result"},
                {"type": "input_file", "file_url": "https://example.invalid/document.pdf"},
                {"type": "input_image", "image_url": "https://example.invalid/image.png"}
            ]
        }
    ]);
    let input = json!({
        "model": MODEL,
        "input": history,
        "store": false,
        "include": ["reasoning.encrypted_content"]
    });
    let payload = provider_response(
        "resp-stateless",
        json!([{
            "id": "message-stateless",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "output_text", "text": "File reviewed.", "annotations": []}]
        }]),
        Value::Null,
    );
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .and(body_json(input.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_json(payload.clone()))
        .expect(1)
        .mount(&server)
        .await;
    let client = OpenAIClient::new("test-key")
        .unwrap()
        .with_base_url(server.uri())
        .with_retry_config(0, 1, 1);
    let response = client.create_response(&request(input)).await.unwrap();
    assert_eq!(response.output_text(), "File reviewed.");
    assert_eq!(serde_json::to_value(&response).unwrap(), payload);
    assert!(response.usage.is_none());
    assert_eq!(client.total_prompt_tokens(), 0);
    assert_eq!(client.total_completion_tokens(), 0);
    let captured = server.received_requests().await.unwrap();
    let sent: Value = serde_json::from_slice(&captured[0].body).unwrap();
    assert_eq!(sent["input"], history);
    assert!(sent.get("previous_response_id").is_none());
}

#[fcp_async_core::runtime::test]
async fn unsupported_modes_and_invalid_continuations_fail_before_http() {
    let server = MockServer::start().await;
    let client = OpenAIClient::new("test-key")
        .unwrap()
        .with_base_url(server.uri())
        .with_retry_config(0, 1, 1);
    for invalid in [
        json!({"model": " ", "input": "Hello"}),
        json!({"model": " padded-model ", "input": "Hello"}),
        json!({"model": MODEL, "input": "Hello", "stream": true}),
        json!({"model": MODEL, "input": "Hello", "max_output_tokens": 15}),
        json!({"model": MODEL, "input": "Hello", "previous_response_id": ""}),
        json!({"model": MODEL, "input": "Hello", "previous_response_id": " resp-previous "}),
        json!({"model": MODEL, "input": "Hello", "reasoning": "high"}),
        json!({"model": MODEL, "input": "Hello", "text": {"format": "json_schema"}}),
        json!({"model": MODEL, "input": "Hello", "temperature": 2.5}),
        json!({"model": MODEL, "input": "Hello", "top_p": -0.1}),
        json!({"model": MODEL, "input": "Hello", "tools": [{"type": "function", "function": {"name": "chat-shape"}}]}),
        json!({"model": MODEL, "input": "Hello", "tool_choice": {"type": "function", "function": {"name": "chat-shape"}}}),
        json!({"model": MODEL, "input": "Hello", "tools": [{"type": "mcp", "server_label": "remote", "server_url": "https://example.invalid/mcp"}]}),
        json!({"model": MODEL, "input": "Hello", "tools": [{"type": "web_search"}]}),
        json!({"model": MODEL, "input": "Hello", "tools": [{"type": "computer_use_preview", "display_width": 800, "display_height": 600, "environment": "browser"}]}),
        json!({"model": MODEL, "input": "Hello", "tool_choice": {"type": "web_search"}}),
        json!({"model": MODEL, "input": "Hello", "tool_choice": {"type": "allowed_tools", "mode": "auto", "tools": [{"type": "function", "name": "weather"}]}}),
        json!({"model": MODEL, "input": [{"type": "mcp_approval_response", "approval_request_id": "approval-1", "approve": true}]}),
        json!({"model": MODEL, "input": [{"type": "computer_call_output", "call_id": "call-1", "output": {"type": "computer_screenshot", "image_url": "https://example.invalid/screenshot.png"}}]}),
        json!({"model": MODEL, "input": [{"type": "future_active_tool", "execute": true}]}),
        json!({"model": MODEL, "input": [{"type": "item_reference"}]}),
        json!({"model": MODEL, "input": [{"type": "item_reference", "id": ""}]}),
        json!({"model": MODEL, "input": [{"type": "item_reference", "id": " item-padded "}]}),
        json!({"model": MODEL, "input": [{"id": " message-padded ", "role": "assistant", "content": "History"}]}),
        json!({"model": MODEL, "input": [{"id": null, "type": "function_call", "call_id": "call-test", "name": "weather", "arguments": "{}"}]}),
        json!({"model": MODEL, "input": [{"id": 42, "type": "reasoning", "summary": []}]}),
        json!({"model": MODEL, "input": [null]}),
        json!({"model": MODEL, "input": [{}]}),
        json!({"model": MODEL, "input": [{"role": "user"}]}),
        json!({"model": MODEL, "input": [{"type": "function_call_output", "output": "Result"}]}),
        json!({"model": MODEL, "input": [{"type": "function_call_output", "call_id": "", "output": "Result"}]}),
        json!({"model": MODEL, "input": [{"type": "function_call_output", "call_id": " call-padded ", "output": "Result"}]}),
        json!({"model": MODEL, "input": [{"type": "function_call_output", "call_id": "call-test", "output": 7}]}),
        json!({"model": MODEL, "input": [{"type": "function_call", "call_id": "call-test", "name": "weather", "arguments": {}}]}),
    ] {
        let input = request(invalid);
        assert!(matches!(
            client.create_response(&input).await,
            Err(OpenAIError::InvalidInput { .. })
        ));
    }
    for invalid_part in [
        json!({"type": "input_file", "file_id": ""}),
        json!({"type": "input_file", "file_id": " file-padded "}),
        json!({"type": "input_file", "file_id": 42}),
        json!({"type": "input_file", "file_url": " https://example.invalid/document.pdf "}),
        json!({"type": "input_file", "file_url": "https://user:secret@example.invalid/document.pdf"}),
        json!({"type": "input_file", "file_url": "file:///private/document.pdf"}),
        json!({"type": "input_file", "file_url": "data:application/pdf;base64,AA=="}),
        json!({"type": "input_file", "file_url": 42}),
        json!({"type": "input_image", "image_url": "https://user@example.invalid/image.png"}),
        json!({"type": "input_image", "image_url": "https://example.invalid/image\n.png"}),
        json!({"type": "input_image", "image_url": "/relative/image.png"}),
        json!({"type": "input_image", "image_url": "ftp://example.invalid/image.png"}),
        json!({"type": "input_image", "image_url": "data:text/html,content"}),
        json!({"type": "input_image", "image_url": "data:image/png;base64,"}),
        json!({"type": "input_image", "image_url": null}),
    ] {
        for item in [
            json!({"role": "user", "content": [invalid_part.clone()]}),
            json!({"type": "function_call_output", "call_id": "call-test", "output": [invalid_part]}),
        ] {
            let input = request(json!({"model": MODEL, "input": [item]}));
            assert!(input.validate().is_err());
            assert!(matches!(
                client.create_response(&input).await,
                Err(OpenAIError::InvalidInput { .. })
            ));
        }
    }
    for invalid in [
        json!({"model": MODEL, "input": "Hello", "unknown_provider_field": true}),
        json!({"model": MODEL, "input": "Hello", "response_format": {"type": "json_object"}}),
        json!({"model": MODEL, "input": "Hello", "stream_options": {"include_obfuscation": false}}),
        json!({"model": MODEL, "input": 42}),
    ] {
        assert!(serde_json::from_value::<ResponsesRequest>(invalid).is_err());
    }
    assert!(server.received_requests().await.unwrap().is_empty());
    assert_eq!(client.total_prompt_tokens(), 0);
    assert_eq!(client.total_completion_tokens(), 0);
}

#[fcp_async_core::runtime::test]
async fn responses_reuse_secretless_auth_and_retries_without_duplicate_usage() {
    let server = MockServer::start().await;
    let attempts = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&attempts);
    let payload = provider_response("resp-retried", json!([]), reported_usage(77, 5));
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .and(header(
            "x-fcp-credential-id",
            "550e8400-e29b-41d4-a716-446655440000",
        ))
        .respond_with(move |_: &Request| {
            if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                ResponseTemplate::new(429)
                    .insert_header("retry-after", "0")
                    .set_body_json(
                        json!({"error": {"type": "rate_limit_exceeded", "message": "Retry test"}}),
                    )
            } else {
                ResponseTemplate::new(200).set_body_json(payload.clone())
            }
        })
        .expect(2)
        .mount(&server)
        .await;
    let client = OpenAIClient::new_with_auth(OpenAIAuth::CredentialId(
        CredentialId::parse("550e8400-e29b-41d4-a716-446655440000").unwrap(),
    ))
    .unwrap()
    .with_base_url(server.uri())
    .with_retry_config(1, 1, 1);
    let response = client
        .create_response(&request(json!({
            "model": MODEL, "input": "Retry once", "max_output_tokens": 16
        })))
        .await
        .unwrap();
    assert_eq!(response.id, "resp-retried");
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert_eq!(client.total_prompt_tokens(), 77);
    assert_eq!(client.total_completion_tokens(), 5);
    let captured = server.received_requests().await.unwrap();
    assert!(
        captured
            .iter()
            .all(|request| request.headers.get("authorization").is_none())
    );
}

#[fcp_async_core::runtime::test]
async fn provider_failed_and_incomplete_results_keep_status_and_error_details() {
    let server = MockServer::start().await;
    let client = OpenAIClient::new("test-key")
        .unwrap()
        .with_base_url(server.uri())
        .with_retry_config(0, 1, 1);
    for status in ["failed", "incomplete"] {
        let input = json!({"model": MODEL, "input": status});
        let mut payload = provider_response("resp-terminal", json!([]), Value::Null);
        payload["status"] = json!(status);
        if status == "failed" {
            payload["error"] = json!({"code": "provider_error", "message": "Structured failure", "future_detail": 7});
        } else {
            payload["incomplete_details"] = json!({"reason": "max_output_tokens"});
        }
        Mock::given(method("POST"))
            .and(path("/v1/responses"))
            .and(body_json(input.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(payload.clone()))
            .expect(1)
            .mount(&server)
            .await;
        let response: ResponsesResponse = client.create_response(&request(input)).await.unwrap();
        assert_eq!(response.status, status);
        assert_eq!(serde_json::to_value(&response).unwrap(), payload);
        assert_eq!(response.output_text(), "");
    }
    assert_eq!(client.total_prompt_tokens(), 0);
    assert_eq!(client.total_completion_tokens(), 0);
}

#[fcp_async_core::runtime::test]
async fn background_response_lifecycle_preserves_job_identity_without_regeneration() {
    let server = MockServer::start().await;
    let input =
        json!({"model": MODEL, "input": "Long reasoning task", "background": true, "store": true});
    let mut queued = provider_response("resp-job", json!([]), Value::Null);
    queued["status"] = json!("queued");
    queued["background"] = json!(true);
    Mock::given(method("POST"))
        .and(path("/v1/responses"))
        .and(body_json(input.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_json(queued))
        .expect(1)
        .mount(&server)
        .await;
    let complete = provider_response(
        "resp-job",
        json!([
            {"type":"reasoning", "id":"reasoning-job", "summary":[], "encrypted_content":"opaque"},
            {"type":"message", "role":"assistant", "content":[{"type":"output_text", "text":"Done"}]}
        ]),
        reported_usage(12, 8),
    );
    Mock::given(method("GET"))
        .and(path("/v1/responses/resp-job"))
        .and(query_param("include[]", "reasoning.encrypted_content"))
        .respond_with(ResponseTemplate::new(200).set_body_json(complete.clone()))
        .expect(2)
        .mount(&server)
        .await;
    // Cancellation can return an already completed response without changing it.
    Mock::given(method("POST"))
        .and(path("/v1/responses/resp-job/cancel"))
        .respond_with(ResponseTemplate::new(200).set_body_json(complete.clone()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/v1/responses/resp-job"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id":"resp-job", "object":"response.deleted", "deleted":true
        })))
        .expect(1)
        .mount(&server)
        .await;
    let client = OpenAIClient::new("test-key")
        .unwrap()
        .with_base_url(server.uri());
    let accepted = client.create_response(&request(input)).await.unwrap();
    assert_eq!(accepted.id, "resp-job");
    assert_eq!(accepted.status, "queued");
    let retrieval = RetrieveResponseRequest {
        response_id: accepted.id.clone(),
        include: Some(vec!["reasoning.encrypted_content".into()]),
    };
    for _ in 0..2 {
        let received = client.get_response(&retrieval).await.unwrap();
        assert_eq!(received.output_text(), "Done");
        assert_eq!(serde_json::to_value(received).unwrap(), complete);
    }
    let cancelled = client.cancel_response(&accepted.id).await.unwrap();
    assert_eq!(cancelled.status, "completed");
    assert_eq!(
        client.delete_response(&accepted.id).await.unwrap().id,
        accepted.id
    );
    assert_eq!(
        client.total_prompt_tokens(),
        0,
        "polling must not repeatedly bill usage"
    );
    assert_eq!(client.total_completion_tokens(), 0);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 5);
    assert!(
        requests
            .iter()
            .all(|request| request.headers.get("authorization").is_some())
    );
}

#[fcp_async_core::runtime::test]
async fn lifecycle_rejects_unsafe_ids_and_invalid_selectors_before_http() {
    let server = MockServer::start().await;
    let client = OpenAIClient::new("test-key")
        .unwrap()
        .with_base_url(server.uri());
    for id in [
        "",
        " resp-job",
        "resp-job ",
        "../responses",
        "resp/x",
        "resp?x=1",
        "resp#x",
        "resp%2Fx",
        "resp*",
        "réponse",
    ] {
        let request = RetrieveResponseRequest {
            response_id: id.into(),
            include: None,
        };
        assert!(matches!(
            client.get_response(&request).await,
            Err(OpenAIError::InvalidInput { .. })
        ));
        assert!(matches!(
            client.cancel_response(id).await,
            Err(OpenAIError::InvalidInput { .. })
        ));
        assert!(matches!(
            client.delete_response(id).await,
            Err(OpenAIError::InvalidInput { .. })
        ));
    }
    for include in [
        vec![String::new()],
        vec![" padded ".into()],
        vec!["x".repeat(129)],
        vec!["x".into(); 17],
    ] {
        let request = RetrieveResponseRequest {
            response_id: "resp-job".into(),
            include: Some(include),
        };
        assert!(matches!(
            client.get_response(&request).await,
            Err(OpenAIError::InvalidInput { .. })
        ));
    }
    let request = RetrieveResponseRequest {
        response_id: "x".repeat(513),
        include: None,
    };
    assert!(client.get_response(&request).await.is_err());
    assert!(
        serde_json::from_value::<RetrieveResponseRequest>(
            json!({"response_id":"resp-job", "stream":true})
        )
        .is_err()
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[fcp_async_core::runtime::test]
async fn lifecycle_refuses_mismatched_provider_identity_and_false_deletion_acknowledgements() {
    let server = MockServer::start().await;
    let wrong = provider_response("resp-someone-else", json!([]), Value::Null);
    Mock::given(method("GET"))
        .and(path("/v1/responses/resp-requested"))
        .respond_with(ResponseTemplate::new(200).set_body_json(wrong.clone()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/responses/resp-requested/cancel"))
        .respond_with(ResponseTemplate::new(200).set_body_json(wrong))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/v1/responses/resp-requested"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"id":"resp-requested", "object":"response.deleted", "deleted":false}),
        ))
        .expect(1)
        .mount(&server)
        .await;
    let client = OpenAIClient::new("test-key")
        .unwrap()
        .with_base_url(server.uri())
        .with_retry_config(3, 1, 1);
    let retrieval = RetrieveResponseRequest {
        response_id: "resp-requested".into(),
        include: None,
    };
    let errors = [
        client.get_response(&retrieval).await.unwrap_err(),
        client.cancel_response("resp-requested").await.unwrap_err(),
        client.delete_response("resp-requested").await.unwrap_err(),
    ];
    for error in errors {
        assert!(
            matches!(&error, OpenAIError::Api { error_type, .. } if error_type == "response_identity_mismatch")
        );
        assert!(!error.is_retryable());
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}

#[fcp_async_core::runtime::test]
async fn response_delete_accepts_empty_204_and_propagates_missing_job_without_replay() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/v1/responses/resp-job"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/responses/resp-missing"))
        .respond_with(ResponseTemplate::new(404).set_body_json(
            json!({"error":{"type":"invalid_request_error", "message":"Not found"}}),
        ))
        .expect(1)
        .mount(&server)
        .await;
    let client = OpenAIClient::new("test-key")
        .unwrap()
        .with_base_url(server.uri())
        .with_retry_config(3, 1, 1);
    let deleted = client.delete_response("resp-job").await.unwrap();
    assert!(deleted.deleted);
    assert_eq!(deleted.object, "response.deleted");
    assert_eq!(deleted.id, "resp-job");
    let error = client
        .get_response(&RetrieveResponseRequest {
            response_id: "resp-missing".into(),
            include: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        OpenAIError::Api {
            status_code: Some(404),
            ..
        }
    ));
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}
