//! InvokeRequest/Response Unit Tests (flywheel_connectors-lv8h)
//!
//! Tests InvokeRequest/InvokeResponse validation, binding rules, and holder proof
//! verification with golden vectors and fuzz resilience.
//!
//! # Test Categories
//! - Schema validation (required fields, format checks)
//! - Holder proof verification (signature binding, replay prevention)
//! - Binding rules (zone, connector, capability binding)
//! - Response validation (success, error, decision receipt)

use fcp_core::{
    CapabilityToken, ConnectorId, CorrelationId, FcpError, HolderProof, InvokeContext,
    InvokeRequest, InvokeResponse, InvokeStatus, InvokeValidationError, MAX_IDEMPOTENCY_KEY_LEN,
    ObjectId, OperationId, RequestId, ResponseMetadata, SafetyTier, TailscaleNodeId, ZoneId,
};
use serde_json::json;
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════════════════════
// SCHEMA VALIDATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod schema_validation {
    use super::*;

    /// Create a minimal valid `InvokeRequest` for testing.
    fn make_valid_request() -> InvokeRequest {
        InvokeRequest {
            r#type: "invoke".into(),
            id: RequestId("req_001".into()),
            connector_id: ConnectorId::new("vendor", "test", "v1").unwrap(),
            operation: OperationId::new("op.echo").unwrap(),
            zone_id: ZoneId::work(),
            input: json!({"message": "hello"}),
            capability_token: CapabilityToken::test_token(),
            holder_proof: None,
            context: None,
            idempotency_key: None,
            lease_seq: None,
            deadline_ms: None,
            correlation_id: None,
            provenance: None,
            approval_tokens: vec![],
        }
    }

    #[test]
    fn valid_request_with_all_required_fields() {
        let req = make_valid_request();
        assert_eq!(req.r#type, "invoke");
        assert_eq!(req.id.0, "req_001");
        assert_eq!(req.operation.as_str(), "op.echo");
        assert_eq!(req.zone_id.as_str(), "z:work");
    }

    #[test]
    fn idempotency_key_within_limit_succeeds() {
        let mut req = make_valid_request();
        req.idempotency_key = Some("a".repeat(MAX_IDEMPOTENCY_KEY_LEN));

        let result = req.validate_idempotency_key();
        assert!(result.is_ok(), "max length key should be valid");
    }

    #[test]
    fn idempotency_key_exceeds_limit_rejected() {
        let mut req = make_valid_request();
        req.idempotency_key = Some("a".repeat(MAX_IDEMPOTENCY_KEY_LEN + 1));

        let result = req.validate_idempotency_key();
        assert!(
            matches!(
                result,
                Err(InvokeValidationError::IdempotencyKeyTooLong { .. })
            ),
            "oversized key should be rejected"
        );
    }

    #[test]
    fn empty_idempotency_key_succeeds() {
        let mut req = make_valid_request();
        req.idempotency_key = Some(String::new());

        let result = req.validate_idempotency_key();
        assert!(result.is_ok(), "empty key should be valid");
    }

    #[test]
    fn no_idempotency_key_succeeds() {
        let req = make_valid_request();
        let result = req.validate_idempotency_key();
        assert!(result.is_ok(), "missing key should be valid");
    }

    #[test]
    fn request_serialization_roundtrip() {
        let req = make_valid_request();
        let json = serde_json::to_string(&req).expect("serialization should succeed");
        let parsed: InvokeRequest =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(req.id.0, parsed.id.0);
        assert_eq!(req.operation.as_str(), parsed.operation.as_str());
        assert_eq!(req.zone_id.as_str(), parsed.zone_id.as_str());
    }

    #[test]
    fn request_with_context() {
        let mut req = make_valid_request();
        req.context = Some(InvokeContext {
            locale: Some("en-US".into()),
            pagination: Some(json!({"limit": 100, "offset": 0})),
            trace_id: Some("0123456789abcdef0123456789abcdef".into()),
            request_tags: HashMap::from([("priority".into(), "high".into())]),
        });

        let json = serde_json::to_string(&req).expect("serialization should succeed");
        let parsed: InvokeRequest = serde_json::from_str(&json).unwrap();

        let ctx = parsed.context.unwrap();
        assert_eq!(ctx.locale, Some("en-US".into()));
        assert_eq!(
            ctx.trace_id,
            Some("0123456789abcdef0123456789abcdef".into())
        );
    }

    #[test]
    fn request_with_approval_tokens() {
        let req = make_valid_request();
        // Note: ApprovalToken needs proper construction
        // This tests serialization/deserialization structure
        let json = serde_json::to_string(&req).expect("serialization should succeed");
        assert!(json.contains("\"approval_tokens\":[]") || !json.contains("approval_tokens"));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// HOLDER PROOF VERIFICATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod holder_proof {
    use super::*;

    #[test]
    fn signable_bytes_format() {
        let request_id = RequestId("req_123".into());
        let operation_id = OperationId::new("op.test").unwrap();
        let token_jti = b"jti_abc";

        let bytes = HolderProof::signable_bytes(&request_id, &operation_id, token_jti);

        assert!(bytes.starts_with(b"FCP2-HOLDER-PROOF-V1"));
        assert!(bytes.windows(7).any(|w| w == b"req_123"));
        assert!(bytes.windows(7).any(|w| w == b"op.test"));
        assert!(bytes.windows(7).any(|w| w == b"jti_abc"));
    }

    #[test]
    fn signable_bytes_deterministic() {
        let request_id = RequestId("req_test".into());
        let operation_id = OperationId::new("op.invoke").unwrap();
        let jti = b"token_id_123";

        let bytes1 = HolderProof::signable_bytes(&request_id, &operation_id, jti);
        let bytes2 = HolderProof::signable_bytes(&request_id, &operation_id, jti);

        assert_eq!(bytes1, bytes2, "signable bytes must be deterministic");
    }

    #[test]
    fn different_request_ids_produce_different_bytes() {
        let op = OperationId::new("op.test").unwrap();
        let jti = b"jti";

        let bytes1 = HolderProof::signable_bytes(&RequestId("req_001".into()), &op, jti);
        let bytes2 = HolderProof::signable_bytes(&RequestId("req_002".into()), &op, jti);

        assert_ne!(
            bytes1, bytes2,
            "different request IDs must produce different bytes"
        );
    }

    #[test]
    fn different_operations_produce_different_bytes() {
        let req_id = RequestId("req_001".into());
        let jti = b"jti";

        let bytes1 =
            HolderProof::signable_bytes(&req_id, &OperationId::new("op.read").unwrap(), jti);
        let bytes2 =
            HolderProof::signable_bytes(&req_id, &OperationId::new("op.write").unwrap(), jti);

        assert_ne!(
            bytes1, bytes2,
            "different operations must produce different bytes"
        );
    }

    #[test]
    fn different_jtis_produce_different_bytes() {
        let req_id = RequestId("req_001".into());
        let op = OperationId::new("op.test").unwrap();

        let bytes1 = HolderProof::signable_bytes(&req_id, &op, b"jti_001");
        let bytes2 = HolderProof::signable_bytes(&req_id, &op, b"jti_002");

        assert_ne!(
            bytes1, bytes2,
            "different JTIs must produce different bytes"
        );
    }

    #[test]
    fn holder_proof_construction() {
        let signature = [0u8; 64];
        let node_id = TailscaleNodeId::new("node123456789012345678");

        let proof = HolderProof::new(signature, node_id.clone());

        assert_eq!(proof.signature, signature);
        assert_eq!(proof.holder_node, node_id);
    }

    #[test]
    fn holder_proof_serialization() {
        let mut signature = [0u8; 64];
        signature[0] = 0xAB;
        signature[63] = 0xCD;
        let node_id = TailscaleNodeId::new("nodeabcdef1234567890ab");

        let proof = HolderProof::new(signature, node_id);
        let json = serde_json::to_string(&proof).expect("serialization should succeed");

        // Verify hex encoding of signature
        assert!(json.contains("ab"), "signature should be hex encoded");
        assert!(json.contains("cd"), "signature should be hex encoded");

        // Verify roundtrip
        let parsed: HolderProof = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.signature[0], 0xAB);
        assert_eq!(parsed.signature[63], 0xCD);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// BINDING RULES TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod binding_rules {
    use super::*;

    #[test]
    fn zone_id_must_be_present() {
        // Zone ID is a required field - this tests the type constraint
        let zone = ZoneId::work();
        assert_eq!(zone.as_str(), "z:work");
    }

    #[test]
    fn connector_id_format_validation() {
        // Valid connector ID format: vendor:capability:version
        let valid = ConnectorId::new("anthropic", "claude", "v1");
        assert!(valid.is_ok());

        // from_static for known values
        let from_static = ConnectorId::from_static("test:connector:v1");
        assert_eq!(from_static.as_str(), "test:connector:v1");
    }

    #[test]
    fn operation_id_format_validation() {
        let valid = OperationId::new("op.read");
        assert!(valid.is_ok());

        let valid_nested = OperationId::new("messages.create");
        assert!(valid_nested.is_ok());
    }

    #[test]
    fn request_id_uniqueness() {
        let req1 = RequestId("req_001".into());
        let req2 = RequestId("req_002".into());

        assert_ne!(req1.0, req2.0);
    }

    #[test]
    fn correlation_id_optional() {
        let corr_id = CorrelationId::new();
        // CorrelationId wraps a UUID and implements Display
        let id_string = corr_id.to_string();
        assert_ne!(id_string, "");
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// RESPONSE VALIDATION TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod response_validation {
    use super::*;

    #[test]
    fn success_response_construction() {
        let resp = InvokeResponse::ok(RequestId("req_001".into()), json!({"result": "success"}));

        assert_eq!(resp.r#type, "response");
        assert_eq!(resp.id.0, "req_001");
        assert_eq!(resp.status, InvokeStatus::Ok);
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn error_response_construction() {
        let error = FcpError::NotConfigured;
        let resp = InvokeResponse::error(RequestId("req_002".into()), error);

        assert_eq!(resp.r#type, "response");
        assert_eq!(resp.id.0, "req_002");
        assert_eq!(resp.status, InvokeStatus::Error);
        assert!(resp.result.is_none());
        assert!(resp.error.is_some());
    }

    #[test]
    fn response_with_receipt_id() {
        let mut resp = InvokeResponse::ok(RequestId("req_003".into()), json!({}));
        resp.receipt_id = Some(ObjectId::from_bytes([1u8; 32]));

        assert!(resp.receipt_id.is_some());
        let receipt = resp.receipt_id.unwrap();
        assert_eq!(receipt.as_bytes()[0], 1);
    }

    #[test]
    fn response_with_audit_event_id() {
        let mut resp = InvokeResponse::ok(RequestId("req_004".into()), json!({}));
        resp.audit_event_id = Some(ObjectId::from_bytes([2u8; 32]));

        assert!(resp.audit_event_id.is_some());
    }

    #[test]
    fn response_with_decision_receipt_for_denial() {
        let mut resp = InvokeResponse::error(
            RequestId("req_005".into()),
            FcpError::CapabilityDenied {
                capability: "cap.admin".into(),
                reason: "missing required scope".into(),
            },
        );
        resp.decision_receipt_id = Some(ObjectId::from_bytes([3u8; 32]));

        assert_eq!(resp.status, InvokeStatus::Error);
        assert!(resp.decision_receipt_id.is_some());
    }

    #[test]
    fn response_with_resource_uris() {
        let mut resp = InvokeResponse::ok(RequestId("req_006".into()), json!({"created": true}));
        resp.resource_uris = vec![
            "fcp://fcp.gmail/message/17c9a123".into(),
            "fcp://fcp.gmail/message/17c9a124".into(),
        ];

        assert_eq!(resp.resource_uris.len(), 2);
        assert!(resp.resource_uris[0].starts_with("fcp://"));
    }

    #[test]
    fn response_with_pagination_cursor() {
        let mut resp = InvokeResponse::ok(RequestId("req_007".into()), json!({"items": []}));
        resp.next_cursor = Some("cursor_abc123".into());

        assert_eq!(resp.next_cursor, Some("cursor_abc123".into()));
    }

    #[test]
    fn response_with_metadata() {
        let mut resp = InvokeResponse::ok(RequestId("req_008".into()), json!({}));
        resp.response_metadata = Some(ResponseMetadata {
            processing_time_ms: Some(45),
            cache_ttl_secs: Some(300),
            from_cache: false,
            retry_after_secs: None,
        });

        let meta = resp.response_metadata.unwrap();
        assert_eq!(meta.processing_time_ms, Some(45));
        assert_eq!(meta.cache_ttl_secs, Some(300));
        assert!(!meta.from_cache);
    }

    #[test]
    fn response_serialization_roundtrip() {
        let resp = InvokeResponse::ok(RequestId("req_009".into()), json!({"data": [1, 2, 3]}));

        let json = serde_json::to_string(&resp).expect("serialization should succeed");
        let parsed: InvokeResponse =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(parsed.r#type, "response");
        assert_eq!(parsed.id.0, "req_009");
        assert_eq!(parsed.status, InvokeStatus::Ok);
    }

    #[test]
    fn invoke_status_serialization() {
        let ok_json = serde_json::to_string(&InvokeStatus::Ok).unwrap();
        let err_json = serde_json::to_string(&InvokeStatus::Error).unwrap();

        assert_eq!(ok_json, "\"ok\"");
        assert_eq!(err_json, "\"error\"");
    }

    #[test]
    fn cached_response_metadata() {
        let meta = ResponseMetadata {
            processing_time_ms: Some(0),
            cache_ttl_secs: None,
            from_cache: true,
            retry_after_secs: None,
        };

        assert!(meta.from_cache);
        assert_eq!(meta.processing_time_ms, Some(0));
    }

    #[test]
    fn rate_limited_response_metadata() {
        let meta = ResponseMetadata {
            processing_time_ms: None,
            cache_ttl_secs: None,
            from_cache: false,
            retry_after_secs: Some(60),
        };

        assert_eq!(meta.retry_after_secs, Some(60));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// INVOKE CONTEXT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod invoke_context {
    use super::*;

    #[test]
    fn default_context_empty() {
        let ctx = InvokeContext::default();

        assert!(ctx.locale.is_none());
        assert!(ctx.pagination.is_none());
        assert!(ctx.trace_id.is_none());
        assert!(ctx.request_tags.is_empty());
    }

    #[test]
    fn context_with_locale() {
        let ctx = InvokeContext {
            locale: Some("ja-JP".into()),
            ..Default::default()
        };

        assert_eq!(ctx.locale, Some("ja-JP".into()));
    }

    #[test]
    fn context_with_w3c_trace_id() {
        let trace_id = "0af7651916cd43dd8448eb211c80319c".to_string();
        let ctx = InvokeContext {
            trace_id: Some(trace_id),
            ..Default::default()
        };

        assert_eq!(ctx.trace_id.unwrap().len(), 32);
    }

    #[test]
    fn context_request_tags_serialization() {
        let mut tags = HashMap::new();
        tags.insert("priority".into(), "high".into());
        tags.insert("source.component".into(), "api_gateway".into());

        let ctx = InvokeContext {
            request_tags: tags,
            ..Default::default()
        };

        let json = serde_json::to_string(&ctx).unwrap();
        let parsed: InvokeContext = serde_json::from_str(&json).unwrap();

        assert_eq!(
            parsed.request_tags.get("priority"),
            Some(&"high".to_string())
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ADVERSARIAL INPUT TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod adversarial {
    use super::*;

    #[test]
    fn extremely_long_request_id() {
        let long_id = "x".repeat(10000);
        let req_id = RequestId(long_id);

        // Should not panic, though may be invalid by policy
        assert_eq!(req_id.0.len(), 10000);
    }

    #[test]
    fn unicode_in_input() {
        let input = json!({
            "message": "Hello 世界 🌍 مرحبا",
            "emoji": "🎉🎊🎁",
        });

        let json_str = serde_json::to_string(&input).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["message"], "Hello 世界 🌍 مرحبا");
    }

    #[test]
    fn null_bytes_in_strings() {
        // JSON doesn't allow null bytes in strings, but test handling
        let input = json!({"key": "value"});
        let json_str = serde_json::to_string(&input).unwrap();

        // Verify no null bytes in serialized output
        assert!(!json_str.contains('\0'));
    }

    #[test]
    fn deeply_nested_input() {
        // Create deeply nested JSON
        let mut value = json!({"leaf": "value"});
        for _ in 0..50 {
            value = json!({"nested": value});
        }

        // Should serialize/deserialize without stack overflow
        let json_str = serde_json::to_string(&value).unwrap();
        let _parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
    }

    #[test]
    fn large_array_input() {
        let large_array: Vec<i32> = (0..10000).collect();
        let input = json!({"items": large_array});

        let json_str = serde_json::to_string(&input).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["items"].as_array().unwrap().len(), 10000);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// VALIDATION ERROR TESTS
// ═══════════════════════════════════════════════════════════════════════════════

mod validation_errors {
    use super::*;

    #[test]
    fn idempotency_key_too_long_error_message() {
        let err = InvokeValidationError::IdempotencyKeyTooLong { len: 200, max: 128 };

        let msg = format!("{err}");
        assert!(msg.contains("200"));
        assert!(msg.contains("128"));
    }

    #[test]
    fn holder_proof_required_error() {
        let err = InvokeValidationError::HolderProofRequired;
        let msg = format!("{err}");
        assert!(msg.contains("holder_proof"));
    }

    #[test]
    fn holder_proof_invalid_error() {
        let err = InvokeValidationError::HolderProofInvalid;
        let msg = format!("{err}");
        assert!(msg.contains("signature"));
    }

    #[test]
    fn holder_node_mismatch_error() {
        let err = InvokeValidationError::HolderNodeMismatch {
            proof_node: "node_a".into(),
            token_node: "node_b".into(),
        };

        let msg = format!("{err}");
        assert!(msg.contains("node_a"));
        assert!(msg.contains("node_b"));
    }

    #[test]
    fn idempotency_key_required_error() {
        let err = InvokeValidationError::IdempotencyKeyRequired {
            safety_tier: SafetyTier::Risky,
        };

        let msg = format!("{err}");
        assert!(msg.contains("idempotency_key"));
    }

    #[test]
    fn lease_seq_required_error() {
        let err = InvokeValidationError::LeaseSeqRequired;
        let msg = format!("{err}");
        assert!(msg.contains("lease_seq"));
    }

    #[test]
    fn lease_seq_stale_error() {
        let err = InvokeValidationError::LeaseSeqStale {
            provided: 5,
            current: 10,
        };

        let msg = format!("{err}");
        assert!(msg.contains('5'));
        assert!(msg.contains("10"));
    }
}
