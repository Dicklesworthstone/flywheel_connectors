//! Compiled, local-only operation contracts for connector process boundaries.
//!
//! A manifest advertises schemas, not just capability names. Validate input
//! before admission and successful output before releasing a response. These
//! checks do not grant authority, reserve quota, or establish replay safety.

use std::{collections::BTreeMap, sync::Arc};

use fcp_core::{FcpError, FcpResult, InvokeResponse, InvokeStatus, OperationId, RequestId};
use fcp_manifest::ConnectorManifest;
use jsonschema::{Retrieve, Uri, Validator};
use serde_json::Value;

/// Immutable validators compiled from a strictly validated embedded manifest.
///
/// Compilation can resolve in-document references and built-in meta-schemas,
/// but cannot fetch HTTP URLs, read files, or consult ambient schema resources.
/// Validation is non-mutating: defaults, coercions and schema annotations never
/// rewrite caller input or provider output. Errors exclude instance values,
/// property paths, schema constants and external reference URLs.
///
/// Call [`Self::validate_input`] before signed admission, and
/// [`Self::validate_response`] before publishing or settling an admitted reply.
/// These are contract checks, not authorization or execution-budget enforcement.
#[derive(Clone)]
pub struct OperationContractSet {
    operations: BTreeMap<String, CompiledOperation>,
}

#[derive(Clone)]
struct CompiledOperation {
    input: Arc<Validator>,
    output: Arc<Validator>,
}

impl std::fmt::Debug for OperationContractSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OperationContractSet")
            .field("operation_count", &self.operations.len())
            .finish_non_exhaustive()
    }
}

impl OperationContractSet {
    /// Compile the input and output contracts of every declared operation.
    ///
    /// Compilation is all-or-nothing and intended for process construction,
    /// not per-invocation use. Interface-hash validation remains mandatory.
    ///
    /// # Errors
    /// Returns a redacted internal error for an invalid manifest, invalid
    /// schema, or reference that would require external retrieval. No partially
    /// compiled contract set is returned.
    pub fn from_manifest_toml(manifest_toml: &str) -> FcpResult<Self> {
        let manifest = ConnectorManifest::parse_str(manifest_toml)
            .map_err(|_| invalid_contract())?;
        let operations = manifest.provides.operations.into_iter()
            .map(|(id, operation)| {
                CompiledOperation::compile(&operation.input_schema, &operation.output_schema)
                    .map(|contract| (id, contract))
            })
            .collect::<FcpResult<BTreeMap<_, _>>>()?;
        Ok(Self { operations })
    }

    /// Check the exact operation input before spending quota or doing work.
    ///
    /// # Errors
    /// Rejects undeclared operations and inputs that violate their declared
    /// schema. Does not include validation paths or instance data in errors.
    pub fn validate_input(&self, operation: &OperationId, input: &Value) -> FcpResult<()> {
        let contract = self.operations.get(operation.as_str()).ok_or_else(|| {
            FcpError::InvalidRequest {
                code: 1002,
                message: "Operation is not declared by this connector".into(),
            }
        })?;
        // Boolean validation stops on a failure instead of allocating an
        // unbounded list of errors containing caller-controlled property paths.
        if !contract.input.is_valid(input) {
            return Err(FcpError::InvalidRequest {
                code: 1003,
                message: "Operation input does not match its declared schema".into(),
            });
        }
        Ok(())
    }

    /// Check a complete admitted reply without rewriting it.
    ///
    /// The response must correlate with the original request and have one
    /// consistent outcome. Only successful result data is checked against the
    /// operation's output schema; a valid error is not a success-shaped value.
    ///
    /// # Errors
    /// Returns a non-retryable outcome-unknown error for any invalid envelope,
    /// undeclared operation, or schema-violating success. The provider may have
    /// performed external effects: callers must withhold its payload, retain
    /// admission charges, and never interpret this error as a retry permit.
    pub fn validate_response(
        &self,
        operation: &OperationId,
        expected_id: &RequestId,
        response: &InvokeResponse,
    ) -> FcpResult<()> {
        let contract = self.operations.get(operation.as_str()).ok_or_else(invalid_outcome)?;
        if response.r#type != "response" || response.id != *expected_id {
            return Err(invalid_outcome());
        }
        let valid = match response.status {
            InvokeStatus::Ok => response.error.is_none()
                && response.result.as_ref().is_some_and(|result| contract.output.is_valid(result)),
            InvokeStatus::Error => response.error.is_some() && response.result.is_none(),
        };
        if !valid {
            return Err(invalid_outcome());
        }
        Ok(())
    }
}

impl CompiledOperation {
    fn compile(input: &Value, output: &Value) -> FcpResult<Self> {
        Ok(Self { input: compile_schema(input)?, output: compile_schema(output)? })
    }
}

/// The default jsonschema retriever permits HTTP and filesystem access. Never
/// use it for process-boundary contracts, even for an embedded manifest.
struct LocalOnly;

impl Retrieve for LocalOnly {
    fn retrieve(&self, _uri: &Uri<String>) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "External operation schema retrieval is disabled",
        ).into())
    }
}

fn compile_schema(schema: &Value) -> FcpResult<Arc<Validator>> {
    jsonschema::options().with_retriever(LocalOnly).build(schema)
        .map(Arc::new)
        .map_err(|_| invalid_contract())
}

fn invalid_contract() -> FcpError {
    FcpError::Internal {
        message: "Embedded operation contracts are invalid or require external schema retrieval".into(),
    }
}

fn invalid_outcome() -> FcpError {
    FcpError::External {
        service: "standalone".into(),
        message: "Invocation response violates its admitted operation contract; outcome is unknown; reconcile external effects before retry".into(),
        status_code: None,
        retryable: false,
        retry_after: None,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn operation() -> OperationId { OperationId::from_static("fixture.write") }
    fn id() -> RequestId { RequestId::new("request-1") }

    fn contracts(input: Value, output: Value) -> OperationContractSet {
        OperationContractSet {
            operations: BTreeMap::from([(
                operation().as_str().to_owned(),
                CompiledOperation::compile(&input, &output).unwrap(),
            )]),
        }
    }

    fn strict() -> OperationContractSet {
        contracts(
            json!({"type":"object", "required":["name"], "additionalProperties":false,
                "properties":{"name":{"type":"string","minLength":1}}}),
            json!({"type":"object", "required":["accepted"],
                "properties":{"accepted":{"const":true}}}),
        )
    }

    fn assert_unknown(error: FcpError) {
        assert!(error.to_string().contains("outcome is unknown"));
        assert!(matches!(error, FcpError::External { retryable:false, retry_after:None, .. }));
    }

    #[test]
    fn input_contract_rejects_missing_wrong_typed_and_extra_fields_without_coercion() {
        let set = strict();
        for input in [Value::Null, json!([]), json!({}), json!({"name":""}),
            json!({"name":42}), json!({"name":"ok","extra":true})]
        {
            assert!(set.validate_input(&operation(), &input).is_err());
        }
        let input = json!({"name":"  exact/雪  "});
        let before = input.clone();
        set.validate_input(&operation(), &input).unwrap();
        assert_eq!(input, before);
    }

    #[test]
    fn defaults_do_not_invent_missing_required_arguments() {
        let set = contracts(json!({"type":"object", "required":["name"],
            "properties":{"name":{"type":"string","default":"not-authorized"}}}), json!(true));
        assert!(set.validate_input(&operation(), &json!({})).is_err());
    }

    #[test]
    fn response_schema_checks_the_result_not_the_outer_envelope_or_metadata() {
        let set = strict();
        let mut response = InvokeResponse::ok(id(), json!({"accepted":true,"opaque":{"keep":true}}));
        response.next_cursor = Some("opaque-cursor".into());
        let before = serde_json::to_value(&response).unwrap();
        set.validate_response(&operation(), &id(), &response).unwrap();
        assert_eq!(serde_json::to_value(response).unwrap(), before);
        for result in [Value::Null, json!([]), json!({}), json!({"accepted":false})] {
            assert_unknown(set.validate_response(&operation(), &id(), &InvokeResponse::ok(id(), result)).unwrap_err());
        }
    }

    #[test]
    fn valid_provider_error_does_not_need_a_success_shaped_result() {
        let set = strict();
        let response = InvokeResponse::error(id(), FcpError::NotConfigured);
        let before = serde_json::to_value(&response).unwrap();
        set.validate_response(&operation(), &id(), &response).unwrap();
        assert_eq!(serde_json::to_value(response).unwrap(), before);
    }

    #[test]
    fn malformed_response_envelopes_and_correlation_fail_as_unknown_outcomes() {
        let set = strict();
        let valid = || InvokeResponse::ok(id(), json!({"accepted":true}));
        let mut wrong_id = valid(); wrong_id.id = RequestId::new("other");
        let mut wrong_type = valid(); wrong_type.r#type = "invoke".into();
        let mut mixed = valid(); mixed.error = Some(FcpError::NotConfigured);
        let mut absent = valid(); absent.result = None;
        let mut wrong_status = valid(); wrong_status.status = InvokeStatus::Error;
        let mut no_error = InvokeResponse::error(id(), FcpError::NotConfigured); no_error.error = None;
        for response in [wrong_id, wrong_type, mixed, absent, wrong_status, no_error] {
            assert_unknown(set.validate_response(&operation(), &id(), &response).unwrap_err());
        }
    }

    #[test]
    fn errors_do_not_echo_input_keys_values_schema_constants_or_debug_contracts() {
        let set = contracts(json!({"const":"secret-schema"}), json!({"const":"secret-result"}));
        let input_error = set.validate_input(&operation(), &json!({"secret-key":"secret-input"})).unwrap_err();
        let output_error = set.validate_response(&operation(), &id(),
            &InvokeResponse::ok(id(), json!({"secret-key":"secret-output"}))).unwrap_err();
        for text in [input_error.to_string(), output_error.to_string(), format!("{set:?}")] {
            assert!(!text.contains("secret"));
        }
    }

    #[test]
    fn internal_references_and_literal_ref_property_names_are_supported() {
        let set = contracts(json!({"type":"object", "required":["$ref"],
            "$defs":{"value":{"type":"integer","minimum":1}},
            "properties":{"$ref":{"$ref":"#/$defs/value"}}}), json!(true));
        set.validate_input(&operation(), &json!({"$ref":1})).unwrap();
        assert!(set.validate_input(&operation(), &json!({"$ref":0})).is_err());
    }

    #[test]
    fn remote_file_and_relative_references_fail_closed_without_retrieval() {
        for reference in ["https://uncontacted.invalid/private-schema", "http://127.0.0.1:1/private-schema",
            "file:///private-schema", "relative-private-schema.json"]
        {
            let error = compile_schema(&json!({"$ref":reference})).err().expect("external reference must fail");
            assert!(!error.to_string().contains("private-schema"));
        }
        assert!(compile_schema(&json!({"$schema":"https://uncontacted.invalid/meta"})).is_err());
    }

    #[test]
    fn invalid_schema_or_manifest_never_produces_a_contract_set() {
        assert!(CompiledOperation::compile(&json!({"type":42}), &json!(true)).is_err());
        assert!(CompiledOperation::compile(&json!(true), &json!({"required":42})).is_err());
        assert!(OperationContractSet::from_manifest_toml("not a manifest").is_err());
    }

    #[test]
    fn undeclared_operation_cannot_borrow_another_contract() {
        let set = strict();
        let missing = OperationId::from_static("fixture.other");
        assert!(matches!(set.validate_input(&missing, &json!({"name":"valid"})),
            Err(FcpError::InvalidRequest {code:1002,..})));
        assert_unknown(set.validate_response(&missing, &id(),
            &InvokeResponse::ok(id(), json!({"accepted":true}))).unwrap_err());
    }

    #[test]
    fn combinators_and_closed_nested_arguments_are_enforced() {
        let set = contracts(json!({"oneOf":[
            {"type":"object","required":["count"],"additionalProperties":false,
                "properties":{"count":{"type":"integer","minimum":1}}},
            {"type":"object","required":["names"],"additionalProperties":false,
                "properties":{"names":{"type":"array","minItems":1,"items":{"type":"string"}}}}
        ]}), json!(true));
        for input in [json!({"count":2}), json!({"names":["one"]})] {
            set.validate_input(&operation(), &input).unwrap();
        }
        for input in [json!({"count":"2"}), json!({"count":0}), json!({"names":[]}),
            json!({"names":[42]}), json!({"count":2,"names":["one"]})]
        {
            assert!(set.validate_input(&operation(), &input).is_err());
        }
    }

    #[test]
    fn permissive_contract_preserves_null_success_but_false_contract_denies_it() {
        let response = InvokeResponse::ok(id(), Value::Null);
        contracts(json!(true), json!(true)).validate_response(&operation(), &id(), &response).unwrap();
        assert_unknown(contracts(json!(true), json!(false))
            .validate_response(&operation(), &id(), &response).unwrap_err());
    }
}
