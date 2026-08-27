//! `fcp_mesh::node` `MeshNodeConfig` builder + `MeshNodeError` variant
//! Display contract conformance.
//!
//! `MeshNode` is the orchestration surface that integrates admission,
//! gossip, symbol-request, raptorq, trace-capture, and enforcement.
//! Its config + error taxonomy are the cross-crate contract that
//! every operator audit pipeline reads.
//!
//! Properties pinned (NORMATIVE):
//!
//! 1. **`MeshNodeConfig::new(node_id)`** initialises with documented
//!    defaults (admission/gossip/symbol-request/raptorq/trace_capture
//!    all `default()`, `sender_instance_id` is randomly generated,
//!    `trace_capture_zones=None`).
//! 2. **Builder methods** (`with_admission_policy`,
//!    `with_gossip_config`, `with_symbol_request_policy`,
//!    `with_raptorq_config`, `with_sender_instance_id`,
//!    `with_trace_capture_config`, `with_trace_capture_zones`)
//!    preserve the `node_id` and other untouched fields.
//! 3. **`sender_instance_id` is non-deterministic by default** —

#![allow(clippy::unreadable_literal)]

//!    two fresh configs MAY differ (UUID/random per-construction,
//!    reboot-safety).
//! 4. **`MeshNodeError` Display literal substrings** for the 14
//!    documented variants — operator audit log greps depend on
//!    these strings.
//! 5. **`MeshNodeError` is `std::error::Error`**.
//!
//! Audit-log Display invariants pinned for every variant:
//!
//! - `PeerSigningKeyMissing` → "missing peer signing key for ..."
//! - `PeerSignatureInvalid` → "invalid {kind} signature from ..."
//! - `RecipientMismatch` → "{kind} recipient mismatch: expected ..."
//! - `UnauthorizedZone` → "..."
//! - `UnknownPeer` → "peer ... has no registered peer state ..."
//! - `UnknownZoneOwner` → "no zone-owner key registered for zone ..."
//! - `MissingOwnerSignature` → "revocation push from ... missing owner signature ..."
//! - `InvalidOwnerSignature` → "revocation push from ... has invalid owner signature ..."
//! - `TraceNotEnabled` → "trace capture not enabled"
//! - `GossipDecode` → "gossip payload decode error: ..."
//! - `GossipPayloadTooLarge` → "gossip payload too large: ..."

use fcp_mesh::{GossipConfig, MeshNodeConfig, MeshNodeError};

// ─── MeshNodeConfig::new ───────────────────────────────────────────

#[test]
fn mesh_node_config_new_preserves_node_id() {
    let cfg = MeshNodeConfig::new("test-node");
    assert_eq!(cfg.node_id, "test-node");
}

#[test]
fn mesh_node_config_new_sender_instance_id_is_random_per_construction() {
    // Two fresh configs MAY differ (random u64 default per
    // br-reboot-safety contract). Pin via not-deterministic check.
    let a = MeshNodeConfig::new("a");
    let b = MeshNodeConfig::new("b");
    // Probabilistically these will differ — the contract is "random"
    // not a specific seed. If they happen to collide, retry once.
    if a.sender_instance_id == b.sender_instance_id {
        let c = MeshNodeConfig::new("c");
        assert_ne!(
            a.sender_instance_id, c.sender_instance_id,
            "sender_instance_id MUST be random per construction \
             (3-way collision improbable enough to flag a bug)"
        );
    }
}

#[test]
fn mesh_node_config_new_trace_capture_zones_default_is_none() {
    let cfg = MeshNodeConfig::new("test-node");
    assert!(
        cfg.trace_capture_zones.is_none(),
        "default trace_capture_zones MUST be None — capture all zones until allowlist is set"
    );
}

// ─── Builder methods preserve unrelated fields ─────────────────────

#[test]
fn with_gossip_config_preserves_node_id() {
    let cfg = MeshNodeConfig::new("nx").with_gossip_config(GossipConfig::default());
    assert_eq!(cfg.node_id, "nx");
}

#[test]
fn with_sender_instance_id_overrides_default() {
    let cfg = MeshNodeConfig::new("nx").with_sender_instance_id(0xDEADBEEF);
    assert_eq!(cfg.sender_instance_id, 0xDEADBEEF);
    assert_eq!(cfg.node_id, "nx", "node_id MUST be preserved");
}

#[test]
fn builder_chain_preserves_node_id_through_multiple_overrides() {
    let cfg = MeshNodeConfig::new("orig-node")
        .with_gossip_config(GossipConfig::default())
        .with_sender_instance_id(42);
    assert_eq!(cfg.node_id, "orig-node");
    assert_eq!(cfg.sender_instance_id, 42);
}

// ─── MeshNodeError Display contract ───────────────────────────────

#[test]
fn mesh_node_error_peer_signing_key_missing_display() {
    let e = MeshNodeError::PeerSigningKeyMissing {
        peer: "node-a".into(),
    };
    let s = format!("{e}");
    assert!(
        s.contains("missing peer signing key"),
        "Display MUST include literal substring; got {s}"
    );
    assert!(s.contains("node-a"));
}

#[test]
fn mesh_node_error_peer_signature_invalid_display() {
    let e = MeshNodeError::PeerSignatureInvalid {
        peer: "node-b".into(),
        message_kind: "gossip summary",
    };
    let s = format!("{e}");
    assert!(s.contains("invalid"), "got {s}");
    assert!(s.contains("gossip summary"), "got {s}");
    assert!(s.contains("node-b"), "got {s}");
}

#[test]
fn mesh_node_error_recipient_mismatch_display() {
    let e = MeshNodeError::RecipientMismatch {
        message_kind: "revocation push",
        expected: "node-a".into(),
        actual: "node-b".into(),
    };
    let s = format!("{e}");
    assert!(s.contains("recipient mismatch"), "got {s}");
    assert!(s.contains("revocation push"), "got {s}");
    assert!(s.contains("expected node-a"), "got {s}");
    assert!(s.contains("got node-b"), "got {s}");
}

#[test]
fn mesh_node_error_unauthorized_zone_display() {
    let e = MeshNodeError::UnauthorizedZone {
        peer: "peer-x".into(),
        zone_id: "z:work".into(),
    };
    let s = format!("{e}");
    assert!(s.contains("peer-x"), "got {s}");
    assert!(s.contains("z:work"), "got {s}");
}

#[test]
fn mesh_node_error_unknown_peer_display_includes_handshake_literal() {
    let e = MeshNodeError::UnknownPeer {
        peer: "peer-z".into(),
        message_kind: "gossip summary",
    };
    let s = format!("{e}");
    assert!(s.contains("peer peer-z"), "got {s}");
    assert!(
        s.contains("no registered peer state"),
        "Display MUST include 'no registered peer state' substring; got {s}"
    );
    assert!(s.contains("handshake/enrollment incomplete"), "got {s}");
}

#[test]
fn mesh_node_error_unknown_zone_owner_display() {
    let e = MeshNodeError::UnknownZoneOwner {
        zone_id: "z:work".into(),
    };
    let s = format!("{e}");
    assert!(
        s.contains("no zone-owner key registered"),
        "Display MUST include security-audit substring; got {s}"
    );
    assert!(s.contains("z:work"));
    assert!(s.contains("revocation push"));
}

#[test]
fn mesh_node_error_missing_owner_signature_display() {
    let e = MeshNodeError::MissingOwnerSignature {
        peer: "peer-mal".into(),
        zone_id: "z:work".into(),
    };
    let s = format!("{e}");
    assert!(
        s.contains("missing owner signature"),
        "Display MUST include 'missing owner signature' for the br-uxsnk audit contract; got {s}"
    );
    assert!(s.contains("peer-mal"));
    assert!(s.contains("z:work"));
}

#[test]
fn mesh_node_error_invalid_owner_signature_display() {
    let e = MeshNodeError::InvalidOwnerSignature {
        peer: "peer-mal".into(),
        zone_id: "z:work".into(),
    };
    let s = format!("{e}");
    assert!(
        s.contains("invalid owner signature"),
        "Display MUST include 'invalid owner signature'; got {s}"
    );
}

#[test]
fn mesh_node_error_trace_not_enabled_is_specific() {
    let e = MeshNodeError::TraceNotEnabled;
    let s = format!("{e}");
    assert_eq!(
        s, "trace capture not enabled",
        "TraceNotEnabled Display MUST be exactly the documented literal"
    );
}

#[test]
fn mesh_node_error_gossip_decode_display_includes_inner_message() {
    let e = MeshNodeError::GossipDecode("malformed cbor".into());
    let s = format!("{e}");
    assert!(s.contains("gossip payload decode error"), "got {s}");
    assert!(s.contains("malformed cbor"), "got {s}");
}

#[test]
fn mesh_node_error_gossip_payload_too_large_display_includes_byte_counts() {
    let e = MeshNodeError::GossipPayloadTooLarge {
        len: 4_000_000,
        max: 1_048_576,
    };
    let s = format!("{e}");
    assert!(s.contains("gossip payload too large"), "got {s}");
    assert!(s.contains("4000000"), "got {s}");
    assert!(s.contains("1048576"), "got {s}");
}

// ─── std::error::Error trait ───────────────────────────────────────

#[test]
fn mesh_node_error_is_std_error() {
    let e = MeshNodeError::TraceNotEnabled;
    let _: &dyn std::error::Error = &e;
}

#[test]
fn mesh_node_error_debug_is_non_empty_for_every_variant() {
    let cases = vec![
        MeshNodeError::PeerSigningKeyMissing { peer: "x".into() },
        MeshNodeError::PeerSignatureInvalid {
            peer: "x".into(),
            message_kind: "k",
        },
        MeshNodeError::RecipientMismatch {
            message_kind: "k",
            expected: "x".into(),
            actual: "y".into(),
        },
        MeshNodeError::UnauthorizedZone {
            peer: "x".into(),
            zone_id: "z".into(),
        },
        MeshNodeError::UnknownPeer {
            peer: "x".into(),
            message_kind: "k",
        },
        MeshNodeError::UnknownZoneOwner {
            zone_id: "z".into(),
        },
        MeshNodeError::MissingOwnerSignature {
            peer: "x".into(),
            zone_id: "z".into(),
        },
        MeshNodeError::InvalidOwnerSignature {
            peer: "x".into(),
            zone_id: "z".into(),
        },
        MeshNodeError::TraceNotEnabled,
        MeshNodeError::GossipDecode("x".into()),
        MeshNodeError::GossipPayloadTooLarge { len: 1, max: 0 },
    ];
    for e in cases {
        let dbg = format!("{e:?}");
        assert_ne!(dbg, "");
        let display = format!("{e}");
        assert_ne!(display, "");
    }
}
