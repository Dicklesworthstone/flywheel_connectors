//! Typed envelopes for the existing operation fixtures. Native-host tests build
//! their own wire requests and exercise the public boundary without this helper.

use fcp_prelude::{InvokeRequest, RequestId};
use serde_json::Value;

macro_rules! invoke_request {
    ($($json:tt)*) => {
        crate::test_support::typed_request(serde_json::json!($($json)*))
    };
}

pub fn typed_request(mut fields: Value) -> Value {
    let request_id = fields
        .get("id")
        .or_else(|| fields.get("operation_id"))
        .or_else(|| fields.get("request_id"))
        .and_then(Value::as_str)
        .map_or_else(RequestId::random, |id| RequestId(id.to_owned()));
    let request: InvokeRequest = serde_json::from_value(serde_json::json!({
        "type": "invoke",
        "id": request_id,
        "connector_id": "fcp.stripe",
        "zone_id": "z:private",
        "operation": fields["operation"].take(),
        "input": fields["input"].take(),
        "capability_token": fields["capability_token"].take(),
        "idempotency_key": fields["idempotency_key"].take(),
        "deadline_ms": fields["deadline_ms"].take(),
    }))
    .expect("complete typed fixture request");
    serde_json::to_value(request).unwrap()
}

pub fn capabilities(operations: &[&str]) -> Vec<&'static str> {
    let mut capabilities = Vec::new();
    for operation in operations {
        let capability = match *operation {
            "stripe.create_customer" | "stripe.update_customer" | "stripe.delete_customer" => {
                "stripe.write"
            }
            "stripe.create_payment_intent"
            | "stripe.confirm_payment_intent"
            | "stripe.capture_payment_intent"
            | "stripe.cancel_payment_intent"
            | "stripe.create_refund"
            | "stripe.create_subscription"
            | "stripe.cancel_subscription" => "stripe.payment",
            "stripe.ingest_webhook_event" => "stripe.webhook",
            _ => "stripe.read",
        };
        if !capabilities.contains(&capability) {
            capabilities.push(capability);
        }
    }
    capabilities
}
