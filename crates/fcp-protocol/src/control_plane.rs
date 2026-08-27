//! Control-plane object model and retention classification.
//!
//! Implements the normative control-plane object model from `FCP_Specification_V3.md`
//! §9.2.1 (Control-Plane Object Model).
//! Control-plane objects wrap protocol messages with canonical serialization and retention
//! classification for auditability.

use fcp_cbor::SchemaId;
use fcp_prelude::{ObjectHeader, ObjectId, ObjectIdKey};
use serde::{Deserialize, Serialize};

/// Retention requirement for control-plane objects (NORMATIVE).
///
/// Some control-plane messages MUST be stored for auditability; others MAY be ephemeral.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ControlPlaneRetention {
    /// MUST be stored for auditability and replay.
    ///
    /// Examples: invoke/response, receipts, approvals, secret access, revocations, audit events.
    Required,
    /// MAY be dropped after processing.
    ///
    /// Examples: health, handshake, `decode_status`, `symbol_ack`, introspect, configure, simulate.
    Ephemeral,
}

/// Control-plane object with canonical representation (NORMATIVE).
///
/// All control-plane message types MUST have a canonical CBOR object representation.
/// The `ControlPlaneObject` wraps the header and body for transmission over FCPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPlaneObject {
    /// Object header with schema, zone, provenance, etc.
    pub header: ObjectHeader,
    /// Canonical payload bytes: `schema_hash` (32 bytes) || `canonical_cbor(body)`.
    pub body: Vec<u8>,
}

impl ControlPlaneObject {
    /// Create a new control-plane object from a header and body.
    ///
    /// The body should be pre-serialized as: `schema_hash || canonical_cbor(payload)`.
    #[must_use]
    pub const fn new(header: ObjectHeader, body: Vec<u8>) -> Self {
        Self { header, body }
    }

    /// Derive the object ID for this control-plane object.
    ///
    /// # Errors
    /// Returns an error if canonical bytes cannot be constructed.
    pub fn derive_id(&self, key: &ObjectIdKey) -> Result<ObjectId, fcp_cbor::SerializationError> {
        fcp_core::StoredObject::derive_id(&self.header, &self.body, key)
    }

    /// Get the schema for this object.
    #[must_use]
    pub const fn schema(&self) -> &SchemaId {
        &self.header.schema
    }

    /// Determine the retention requirement for this object based on its schema.
    #[must_use]
    pub fn retention(&self) -> ControlPlaneRetention {
        retention_for_schema(&self.header.schema)
    }
}

/// Well-known schema patterns for retention classification.
mod schema_patterns {
    /// Required retention schemas (must be stored for auditability).
    pub const REQUIRED_PREFIXES: &[&str] = &[
        "fcp.invoke",     // InvokeRequest/Response
        "fcp.receipt",    // Receipts
        "fcp.approval",   // Approvals
        "fcp.secret",     // Secret access
        "fcp.revoke",     // Revocations
        "fcp.audit",      // Audit events/heads
        "fcp.grant",      // Capability grants
        "fcp.membership", // Membership changes
    ];

    /// Ephemeral schemas (may be dropped after processing).
    pub const EPHEMERAL_PREFIXES: &[&str] = &[
        "fcp.health",     // Health checks
        "fcp.handshake",  // Handshake objects
        "fcp.status",     // Decode status, symbol ack
        "fcp.introspect", // Introspection
        "fcp.configure",  // Configuration
        "fcp.simulate",   // Simulation
        "fcp.ping",       // Ping/pong
        "fcp.heartbeat",  // Heartbeat
    ];
}

/// Match a schema namespace against a well-known prefix using dot-delimited
/// semantics: either an exact match or `{prefix}.{suffix}`. Prevents a
/// pathological namespace like `fcp.heartbeat-evil` from matching the
/// `fcp.heartbeat` ephemeral prefix via plain `starts_with` and evading the
/// default-required audit retention.
fn namespace_matches_prefix(ns: &str, prefix: &str) -> bool {
    if ns == prefix {
        return true;
    }
    if let Some(rest) = ns.strip_prefix(prefix) {
        return rest.starts_with('.');
    }
    false
}

/// Determine retention requirement for a schema (NORMATIVE).
///
/// Default is `Required` for unknown schemas (fail-safe toward auditability).
#[must_use]
pub fn retention_for_schema(schema: &SchemaId) -> ControlPlaneRetention {
    let ns = schema.namespace.as_str();

    // Check explicit required prefixes first.
    for prefix in schema_patterns::REQUIRED_PREFIXES {
        if namespace_matches_prefix(ns, prefix) {
            return ControlPlaneRetention::Required;
        }
    }

    // Check ephemeral patterns next (explicit opt-out of storage).
    for prefix in schema_patterns::EPHEMERAL_PREFIXES {
        if namespace_matches_prefix(ns, prefix) {
            return ControlPlaneRetention::Ephemeral;
        }
    }

    // Default to Required for auditability
    ControlPlaneRetention::Required
}

/// Check if a schema requires storage (convenience helper).
#[must_use]
pub fn requires_storage(schema: &SchemaId) -> bool {
    retention_for_schema(schema) == ControlPlaneRetention::Required
}

#[cfg(test)]
mod tests {
    use super::*;
    use fcp_prelude::{Provenance, ZoneId};
    use semver::Version;

    fn test_schema(namespace: &str, name: &str) -> SchemaId {
        SchemaId::new(namespace, name, Version::new(1, 0, 0))
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ControlPlaneRetention Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn retention_subnamespace_with_dot_inherits_retention() {
        // Legitimate nested sub-namespaces with a proper dot separator must
        // still resolve under the parent's retention class.
        assert_eq!(
            retention_for_schema(&test_schema("fcp.invoke.v2", "Request")),
            ControlPlaneRetention::Required
        );
        assert_eq!(
            retention_for_schema(&test_schema("fcp.heartbeat.sub", "P")),
            ControlPlaneRetention::Ephemeral
        );
    }

    #[test]
    fn retention_near_prefix_does_not_inherit_retention() {
        // Namespace that shares a byte-prefix but lacks a dot delimiter MUST
        // NOT inherit the ephemeral class — otherwise an attacker can craft
        // `fcp.heartbeat-exfil` to evade audit retention.
        assert_eq!(
            retention_for_schema(&test_schema("fcp.heartbeat-evil", "P")),
            ControlPlaneRetention::Required,
            "non-dot suffix must default to Required (fail-safe)"
        );
        assert_eq!(
            retention_for_schema(&test_schema("fcp.healthy", "P")),
            ControlPlaneRetention::Required,
            "fcp.healthy must not inherit fcp.health Ephemeral retention"
        );
        // Same property in the Required direction — here the fail-safe
        // naturally aligns (unknown => Required) so behavior is unchanged,
        // but we lock it in so future refactors can't silently regress.
        assert_eq!(
            retention_for_schema(&test_schema("fcp.invoker", "P")),
            ControlPlaneRetention::Required
        );
    }

    #[test]
    fn retention_invoke_is_required() {
        let schema = test_schema("fcp.invoke", "Request");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Required
        );
    }

    #[test]
    fn retention_receipt_is_required() {
        let schema = test_schema("fcp.receipt", "ExecutionReceipt");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Required
        );
    }

    #[test]
    fn retention_approval_is_required() {
        let schema = test_schema("fcp.approval", "CapabilityApproval");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Required
        );
    }

    #[test]
    fn retention_audit_is_required() {
        let schema = test_schema("fcp.audit", "AuditHead");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Required
        );
    }

    #[test]
    fn retention_health_is_ephemeral() {
        let schema = test_schema("fcp.health", "Ping");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Ephemeral
        );
    }

    #[test]
    fn retention_handshake_is_ephemeral() {
        let schema = test_schema("fcp.handshake", "Hello");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Ephemeral
        );
    }

    #[test]
    fn retention_status_is_ephemeral() {
        let schema = test_schema("fcp.status", "DecodeStatus");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Ephemeral
        );
    }

    #[test]
    fn retention_introspect_is_ephemeral() {
        let schema = test_schema("fcp.introspect", "Query");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Ephemeral
        );
    }

    #[test]
    fn retention_simulate_is_ephemeral() {
        let schema = test_schema("fcp.simulate", "CostEstimate");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Ephemeral
        );
    }

    #[test]
    fn retention_unknown_defaults_to_required() {
        // Unknown schemas should default to Required for fail-safe auditability
        let schema = test_schema("fcp.custom", "UnknownType");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Required
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // requires_storage Helper Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn requires_storage_true_for_required() {
        let schema = test_schema("fcp.invoke", "Request");
        assert!(requires_storage(&schema));
    }

    #[test]
    fn requires_storage_false_for_ephemeral() {
        let schema = test_schema("fcp.health", "Ping");
        assert!(!requires_storage(&schema));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ControlPlaneObject Tests
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn control_plane_object_creation() {
        let header = ObjectHeader {
            schema: test_schema("fcp.invoke", "Request"),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = vec![0x00; 64]; // Dummy body

        let obj = ControlPlaneObject::new(header, body.clone());

        assert_eq!(obj.body, body);
        assert_eq!(obj.schema().namespace, "fcp.invoke");
        assert_eq!(obj.retention(), ControlPlaneRetention::Required);
    }

    #[test]
    fn control_plane_object_derive_id() {
        let header = ObjectHeader {
            schema: test_schema("fcp.invoke", "Request"),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = b"test body content".to_vec();
        let key = ObjectIdKey::from_bytes([0_u8; 32]);

        let obj = ControlPlaneObject::new(header, body);
        let id = obj.derive_id(&key).expect("derive_id should succeed");

        // Verify determinism
        let id2 = obj.derive_id(&key).expect("derive_id should succeed");
        assert_eq!(id, id2);
    }

    #[test]
    fn control_plane_object_retention_ephemeral() {
        let header = ObjectHeader {
            schema: test_schema("fcp.health", "Heartbeat"),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = vec![];

        let obj = ControlPlaneObject::new(header, body);
        assert_eq!(obj.retention(), ControlPlaneRetention::Ephemeral);
    }

    #[test]
    fn control_plane_object_serialization_roundtrip() {
        let header = ObjectHeader {
            schema: test_schema("fcp.invoke", "Request"),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = b"serialization test".to_vec();

        let obj = ControlPlaneObject::new(header, body.clone());
        let json = serde_json::to_string(&obj).expect("serialize should succeed");
        let deserialized: ControlPlaneObject =
            serde_json::from_str(&json).expect("deserialize should succeed");

        assert_eq!(deserialized.body, body);
        assert_eq!(deserialized.schema().namespace, "fcp.invoke");
    }

    // ── Batch 4: SunnyMoose deep-coverage expansion ──

    #[test]
    fn retention_secret_is_required() {
        let schema = test_schema("fcp.secret", "AccessLog");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Required
        );
    }

    #[test]
    fn retention_revoke_is_required() {
        let schema = test_schema("fcp.revoke", "TokenRevocation");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Required
        );
    }

    #[test]
    fn retention_grant_is_required() {
        let schema = test_schema("fcp.grant", "CapGrant");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Required
        );
    }

    #[test]
    fn retention_membership_is_required() {
        let schema = test_schema("fcp.membership", "Join");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Required
        );
    }

    #[test]
    fn retention_configure_is_ephemeral() {
        let schema = test_schema("fcp.configure", "SetParam");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Ephemeral
        );
    }

    #[test]
    fn retention_ping_is_ephemeral() {
        let schema = test_schema("fcp.ping", "Ping");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Ephemeral
        );
    }

    #[test]
    fn retention_heartbeat_is_ephemeral() {
        let schema = test_schema("fcp.heartbeat", "Beat");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Ephemeral
        );
    }

    #[test]
    fn retention_debug_clone_copy_eq_hash() {
        let r = ControlPlaneRetention::Required;
        let cloned = r;
        assert_eq!(r, cloned);
        let dbg = format!("{r:?}");
        assert!(dbg.contains("Required"));

        let e = ControlPlaneRetention::Ephemeral;
        assert_ne!(r, e);
        let dbg_e = format!("{e:?}");
        assert!(dbg_e.contains("Ephemeral"));
    }

    #[test]
    fn retention_hash_in_hashset() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ControlPlaneRetention::Required);
        set.insert(ControlPlaneRetention::Ephemeral);
        set.insert(ControlPlaneRetention::Required); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn retention_serde_roundtrip() {
        let r = ControlPlaneRetention::Required;
        let json = serde_json::to_string(&r).expect("serialize");
        let back: ControlPlaneRetention = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, r);

        let e = ControlPlaneRetention::Ephemeral;
        let json = serde_json::to_string(&e).expect("serialize");
        let back: ControlPlaneRetention = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, e);
    }

    #[test]
    fn requires_storage_for_all_required_schemas() {
        let schemas = [
            "fcp.invoke",
            "fcp.receipt",
            "fcp.approval",
            "fcp.secret",
            "fcp.revoke",
            "fcp.audit",
            "fcp.grant",
            "fcp.membership",
        ];
        for ns in schemas {
            let schema = test_schema(ns, "Test");
            assert!(
                requires_storage(&schema),
                "schema {ns} should require storage"
            );
        }
    }

    #[test]
    fn requires_storage_false_for_all_ephemeral_schemas() {
        let schemas = [
            "fcp.health",
            "fcp.handshake",
            "fcp.status",
            "fcp.introspect",
            "fcp.configure",
            "fcp.simulate",
            "fcp.ping",
            "fcp.heartbeat",
        ];
        for ns in schemas {
            let schema = test_schema(ns, "Test");
            assert!(
                !requires_storage(&schema),
                "schema {ns} should be ephemeral"
            );
        }
    }

    #[test]
    fn control_plane_object_debug_clone() {
        let header = ObjectHeader {
            schema: test_schema("fcp.invoke", "Request"),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let obj = ControlPlaneObject::new(header, vec![1, 2, 3]);
        let cloned = obj.clone();
        assert_eq!(cloned.body, obj.body);
        let dbg = format!("{obj:?}");
        assert!(dbg.contains("ControlPlaneObject"));
    }

    #[test]
    fn control_plane_object_schema_accessor() {
        let header = ObjectHeader {
            schema: test_schema("fcp.audit", "Head"),
            zone_id: ZoneId::work(),
            created_at: 0,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let obj = ControlPlaneObject::new(header, vec![]);
        assert_eq!(obj.schema().namespace, "fcp.audit");
        assert_eq!(obj.schema().name, "Head");
    }

    #[test]
    fn control_plane_object_empty_body() {
        let header = ObjectHeader {
            schema: test_schema("fcp.health", "Empty"),
            zone_id: ZoneId::work(),
            created_at: 0,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let obj = ControlPlaneObject::new(header, vec![]);
        assert_eq!(obj.body, [] as [u8; 0]);
        assert_eq!(obj.retention(), ControlPlaneRetention::Ephemeral);
    }

    #[test]
    fn control_plane_object_large_body() {
        let header = ObjectHeader {
            schema: test_schema("fcp.invoke", "BigPayload"),
            zone_id: ZoneId::work(),
            created_at: 0,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = vec![0xAB; 8192];
        let obj = ControlPlaneObject::new(header, body);
        assert_eq!(obj.body.len(), 8192);
        assert_eq!(obj.retention(), ControlPlaneRetention::Required);
    }

    #[test]
    fn control_plane_object_derive_id_deterministic() {
        let header = ObjectHeader {
            schema: test_schema("fcp.receipt", "Exec"),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = b"determinism check".to_vec();
        let key = ObjectIdKey::from_bytes([0x42; 32]);
        let obj = ControlPlaneObject::new(header, body);
        let id1 = obj.derive_id(&key).expect("derive 1");
        let id2 = obj.derive_id(&key).expect("derive 2");
        assert_eq!(id1, id2);
    }

    #[test]
    fn control_plane_object_derive_id_differs_with_different_key() {
        let header = ObjectHeader {
            schema: test_schema("fcp.receipt", "Exec"),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body = b"key diff".to_vec();
        let key_a = ObjectIdKey::from_bytes([0x11; 32]);
        let key_b = ObjectIdKey::from_bytes([0x22; 32]);
        let obj = ControlPlaneObject::new(header, body);
        let id_a = obj.derive_id(&key_a).expect("derive a");
        let id_b = obj.derive_id(&key_b).expect("derive b");
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn control_plane_object_derive_id_differs_with_different_body() {
        let header = ObjectHeader {
            schema: test_schema("fcp.invoke", "Req"),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let key = ObjectIdKey::from_bytes([0x33; 32]);
        let obj_a = ControlPlaneObject::new(header.clone(), vec![1, 2, 3]);
        let obj_b = ControlPlaneObject::new(header, vec![4, 5, 6]);
        let id_a = obj_a.derive_id(&key).expect("derive a");
        let id_b = obj_b.derive_id(&key).expect("derive b");
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn retention_subnamespace_matching() {
        // fcp.invoke.sub should still match "fcp.invoke" prefix
        let schema = test_schema("fcp.invoke.sub", "Sub");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Required
        );
        let schema = test_schema("fcp.health.sub", "Sub");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Ephemeral
        );
    }

    // ── Batch 5: SunnyMoose additional edge-case coverage ──

    #[test]
    fn retention_empty_namespace_defaults_to_required() {
        let schema = test_schema("", "Empty");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Required
        );
    }

    #[test]
    fn retention_partial_prefix_no_match() {
        // "fcp.inv" is NOT "fcp.invoke" prefix — should default to required
        let schema = test_schema("fcp.inv", "Partial");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Required
        );
    }

    #[test]
    fn retention_case_sensitive() {
        // Uppercase should NOT match lowercase prefixes
        let schema = test_schema("FCP.INVOKE", "Upper");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Required
        );
        let schema = test_schema("FCP.HEALTH", "Upper");
        // Does not match "fcp.health" so defaults to Required
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Required
        );
    }

    #[test]
    fn retention_unicode_namespace_defaults_to_required() {
        let schema = test_schema("fcp.\u{00e9}moji", "Unicode");
        assert_eq!(
            retention_for_schema(&schema),
            ControlPlaneRetention::Required
        );
    }

    #[test]
    fn control_plane_object_body_with_binary_data() {
        let header = ObjectHeader {
            schema: test_schema("fcp.invoke", "Binary"),
            zone_id: ZoneId::work(),
            created_at: 0,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let body: Vec<u8> = (0..=255).collect();
        let obj = ControlPlaneObject::new(header, body.clone());
        assert_eq!(obj.body.len(), 256);
        assert_eq!(obj.body, body);
    }

    #[test]
    fn control_plane_object_retention_matches_schema() {
        // Verify a few schemas go through the object's retention method correctly
        let schemas_required = ["fcp.invoke", "fcp.receipt", "fcp.grant"];
        let schemas_ephemeral = ["fcp.health", "fcp.ping", "fcp.simulate"];

        for ns in schemas_required {
            let header = ObjectHeader {
                schema: test_schema(ns, "Test"),
                zone_id: ZoneId::work(),
                created_at: 0,
                provenance: Provenance::new(ZoneId::work()),
                refs: vec![],
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            };
            let obj = ControlPlaneObject::new(header, vec![]);
            assert_eq!(
                obj.retention(),
                ControlPlaneRetention::Required,
                "schema {ns} should be required"
            );
        }

        for ns in schemas_ephemeral {
            let header = ObjectHeader {
                schema: test_schema(ns, "Test"),
                zone_id: ZoneId::work(),
                created_at: 0,
                provenance: Provenance::new(ZoneId::work()),
                refs: vec![],
                foreign_refs: vec![],
                ttl_secs: None,
                placement: None,
            };
            let obj = ControlPlaneObject::new(header, vec![]);
            assert_eq!(
                obj.retention(),
                ControlPlaneRetention::Ephemeral,
                "schema {ns} should be ephemeral"
            );
        }
    }

    #[test]
    fn control_plane_object_serde_cbor_roundtrip() {
        let header = ObjectHeader {
            schema: test_schema("fcp.receipt", "Exec"),
            zone_id: ZoneId::work(),
            created_at: 1_700_000_000,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: Some(3600),
            placement: None,
        };
        let body = b"cbor roundtrip body".to_vec();
        let obj = ControlPlaneObject::new(header, body.clone());
        // CBOR roundtrip
        let cbor_bytes = fcp_cbor::to_canonical_cbor(&obj).expect("cbor encode");
        let decoded: ControlPlaneObject =
            ciborium::from_reader(&cbor_bytes[..]).expect("cbor decode");
        assert_eq!(decoded.body, body);
        assert_eq!(decoded.schema().namespace, "fcp.receipt");
    }

    #[test]
    fn control_plane_object_derive_id_different_schemas_differ() {
        let key = ObjectIdKey::from_bytes([0x44; 32]);
        let body = b"same body".to_vec();

        let header_a = ObjectHeader {
            schema: test_schema("fcp.invoke", "Req"),
            zone_id: ZoneId::work(),
            created_at: 0,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let header_b = ObjectHeader {
            schema: test_schema("fcp.receipt", "Resp"),
            zone_id: ZoneId::work(),
            created_at: 0,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let obj_a = ControlPlaneObject::new(header_a, body.clone());
        let obj_b = ControlPlaneObject::new(header_b, body);
        let id_a = obj_a.derive_id(&key).expect("derive a");
        let id_b = obj_b.derive_id(&key).expect("derive b");
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn retention_serde_cbor_roundtrip() {
        use fcp_cbor::to_canonical_cbor;
        let r = ControlPlaneRetention::Required;
        let cbor = to_canonical_cbor(&r).expect("encode");
        let back: ControlPlaneRetention = ciborium::from_reader(&cbor[..]).expect("decode");
        assert_eq!(back, r);

        let e = ControlPlaneRetention::Ephemeral;
        let cbor = to_canonical_cbor(&e).expect("encode");
        let back: ControlPlaneRetention = ciborium::from_reader(&cbor[..]).expect("decode");
        assert_eq!(back, e);
    }

    #[test]
    fn requires_storage_consistency_with_retention() {
        // Verify requires_storage is always == (retention == Required)
        let all_schemas = [
            "fcp.invoke",
            "fcp.receipt",
            "fcp.approval",
            "fcp.secret",
            "fcp.revoke",
            "fcp.audit",
            "fcp.grant",
            "fcp.membership",
            "fcp.health",
            "fcp.handshake",
            "fcp.status",
            "fcp.introspect",
            "fcp.configure",
            "fcp.simulate",
            "fcp.ping",
            "fcp.heartbeat",
            "fcp.custom.unknown",
        ];
        for ns in all_schemas {
            let schema = test_schema(ns, "Test");
            let retention = retention_for_schema(&schema);
            let storage = requires_storage(&schema);
            assert_eq!(
                storage,
                retention == ControlPlaneRetention::Required,
                "mismatch for {ns}"
            );
        }
    }

    #[test]
    fn control_plane_object_schema_version_preserved() {
        let header = ObjectHeader {
            schema: SchemaId::new("fcp.test", "Versioned", Version::new(2, 3, 4)),
            zone_id: ZoneId::work(),
            created_at: 0,
            provenance: Provenance::new(ZoneId::work()),
            refs: vec![],
            foreign_refs: vec![],
            ttl_secs: None,
            placement: None,
        };
        let obj = ControlPlaneObject::new(header, vec![]);
        assert_eq!(obj.schema().version, Version::new(2, 3, 4));
        assert_eq!(obj.schema().name, "Versioned");
    }
}
