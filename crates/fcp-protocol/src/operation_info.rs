//! Operation metadata and I-CONFLUENCE [`CoordinationClass`] protocol definitions
//! (`flywheel_connectors-angoc.11.1.1`).

pub use fcp_core::{CoordinationClass, CoordinationClassError, OperationInfo};

#[cfg(test)]
mod tests {
    use fcp_core::{
        AgentHint, CapabilityId, IdempotencyClass, OperationId, RiskLevel, SafetyTier,
    };
    use serde_json::json;

    use super::*;

    fn sample_op(id: &str, safety_tier: SafetyTier, idempotency: IdempotencyClass) -> OperationInfo {
        OperationInfo {
            id: OperationId::new(id).expect("valid operation id"),
            summary: format!("Sample {id}"),
            description: None,
            input_schema: json!({"type": "object"}),
            output_schema: json!({"type": "object"}),
            capability: CapabilityId::new("test.cap").expect("valid capability id"),
            risk_level: RiskLevel::Low,
            safety_tier,
            idempotency,
            ai_hints: AgentHint::default(),
            rate_limit: None,
            requires_approval: None,
        }
    }

    #[test]
    fn operation_info_derives_and_serializes_coordination_class() {
        let read_op = sample_op("stripe.list_charges", SafetyTier::Safe, IdempotencyClass::Strict);
        assert_eq!(read_op.coordination_class(), CoordinationClass::IConfluent);
        let read_json = serde_json::to_value(&read_op).expect("serializes");
        assert_eq!(read_json["coordination_class"], "i_confluent");

        let quorum_op = sample_op(
            "stripe.create_charge",
            SafetyTier::Risky,
            IdempotencyClass::Strict,
        );
        assert_eq!(
            quorum_op.coordination_class(),
            CoordinationClass::RequiresQuorum
        );
        let quorum_json = serde_json::to_value(&quorum_op).expect("serializes");
        assert_eq!(quorum_json["coordination_class"], "requires_quorum");

        let fencing_op = sample_op(
            "stripe.refund_charge",
            SafetyTier::Dangerous,
            IdempotencyClass::Strict,
        );
        assert_eq!(
            fencing_op.coordination_class(),
            CoordinationClass::RequiresFencing
        );
        let fencing_json = serde_json::to_value(&fencing_op).expect("serializes");
        assert_eq!(fencing_json["coordination_class"], "requires_fencing");
    }
}
