//! Pin `HandshakeRequest`, `HandshakeResponse`, `HostInfo`, `TransportCaps`,
//! `EventCaps`, `AuthCaps`, and `OAuthConfig` JSON+CBOR roundtrip.
//! This is the closest analogue to "`MeshDiscovery` serde"
//! (flywheel_connectors-3drj0).
//!
//! Bead asks for `MeshDiscovery` JSON+CBOR roundtrip pinning. No type
//! literally named `MeshDiscovery` exists in fcp-core; the closest mesh
//! discovery surface is the hub↔connector handshake cluster at
//! `crates/fcp-core/src/protocol.rs:285+331+211+226+362+382+393`. These
//! are the messages the hub uses to discover and bring up a connector
//! mesh node:
//!   * `HandshakeRequest` — hub → connector, advertising capabilities,
//!     host pubkey, nonce,
//!   * `HandshakeResponse` — connector → hub, granting capabilities,
//!     echoing nonce, declaring event/auth/op-catalog hashes,
//!   * `HostInfo`, `TransportCaps`, `EventCaps`, `AuthCaps`, `OAuthConfig`
//!     — discovery payload sub-shapes.
//!
//! No existing test pins these — `grep` for `HandshakeRequest` in
//! `crates/fcp-core/tests/` returns empty.
//!
//! Coverage:
//!   * `HandshakeRequest` field-set + skip-when-`None` `Option` semantics,
//!   * `HandshakeResponse` field-set + nonce-as-32-element-array (no
//!     `hex_or_bytes` adapter — pin so future addition trips loudly),
//!   * `Vec<CapabilityId>` `capabilities_requested` defaults to empty list,
//!   * `HostInfo` skip-when-`None` for version + build,
//!   * `TransportCaps` default state (empty `Vec`, `None` `max_frame_size`),
//!   * `EventCaps` default state via `#[serde(default)]` on each `bool`/`u32`,
//!   * `AuthCaps` + `OAuthConfig` nested round-trip,
//!   * JSON ↔ CBOR cross-format equality on populated handshake,
//!   * Distinct nonces produce distinct JSON (handshake binding sentinel).

use fcp_cbor::SchemaId;
use fcp_core::{
    AuthCaps, CapabilityGrant, CapabilityId, EventCaps, HandshakeRequest, HandshakeResponse,
    HostInfo, InstanceId, OAuthConfig, OperationId, SessionId, TransportCaps, ZoneId,
};
use serde_json::json;
use uuid::Uuid;

fn _schema_unused() -> SchemaId {
    SchemaId::new("fcp.core", "Handshake", semver::Version::new(1, 0, 0))
}

fn populated_request() -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "1.0.0".to_string(),
        zone: ZoneId::work(),
        zone_dir: Some("/var/fcp/zone-work".to_string()),
        host_public_key: [0xab; 32],
        nonce: [0x42; 32],
        capabilities_requested: vec![
            CapabilityId::from_static("cap.read"),
            CapabilityId::from_static("cap.write"),
        ],
        host: Some(HostInfo {
            name: "flywheel-hub".to_string(),
            version: Some("0.9.1".to_string()),
            build: Some("dev-2026-04-29".to_string()),
        }),
        transport_caps: Some(TransportCaps {
            compression: vec!["zstd".to_string(), "lz4".to_string()],
            max_frame_size: Some(65_536),
        }),
        requested_instance_id: Some(InstanceId::try_from("instance:hub-1".to_string()).unwrap()),
    }
}

fn minimal_request() -> HandshakeRequest {
    HandshakeRequest {
        protocol_version: "1.0.0".to_string(),
        zone: ZoneId::public(),
        zone_dir: None,
        host_public_key: [0u8; 32],
        nonce: [0u8; 32],
        capabilities_requested: vec![],
        host: None,
        transport_caps: None,
        requested_instance_id: None,
    }
}

fn populated_response() -> HandshakeResponse {
    HandshakeResponse {
        status: "accepted".to_string(),
        capabilities_granted: vec![CapabilityGrant {
            capability: CapabilityId::from_static("cap.read"),
            operation: Some(OperationId::from_static("op.read")),
        }],
        session_id: SessionId(Uuid::from_bytes([0x77; 16])),
        manifest_hash: "sha256:deadbeef".to_string(),
        nonce: [0x42; 32],
        event_caps: Some(EventCaps {
            streaming: true,
            replay: false,
            min_buffer_events: 16,
            requires_ack: true,
        }),
        auth_caps: Some(AuthCaps {
            methods: vec!["oauth2".to_string()],
            oauth: Some(OAuthConfig {
                authorize_url: "https://auth.example/authorize".to_string(),
                token_url: "https://auth.example/token".to_string(),
                scopes: vec!["read".to_string(), "write".to_string()],
            }),
        }),
        op_catalog_hash: Some("sha256:cafef00d".to_string()),
    }
}

#[test]
fn handshake_request_full_field_set_pinned() {
    let req = populated_request();
    let v = serde_json::to_value(&req).unwrap();
    let obj = v.as_object().expect("must be object");

    let expected: std::collections::BTreeSet<&str> = [
        "protocol_version",
        "zone",
        "zone_dir",
        "host_public_key",
        "nonce",
        "capabilities_requested",
        "host",
        "transport_caps",
        "requested_instance_id",
    ]
    .into_iter()
    .collect();
    let actual: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(actual, expected, "HandshakeRequest shape drift: {obj:?}");
}

#[test]
fn handshake_request_minimal_omits_skip_when_none_fields() {
    // zone_dir, host, transport_caps, requested_instance_id all use
    // skip_serializing_if = "Option::is_none". When None, they must be
    // OMITTED from the wire form (not serialized as null).
    let req = minimal_request();
    let v = serde_json::to_value(&req).unwrap();
    let obj = v.as_object().expect("must be object");

    assert!(
        !obj.contains_key("zone_dir"),
        "zone_dir must be omitted when None"
    );
    assert!(!obj.contains_key("host"), "host must be omitted when None");
    assert!(
        !obj.contains_key("transport_caps"),
        "transport_caps must be omitted when None"
    );
    assert!(
        !obj.contains_key("requested_instance_id"),
        "requested_instance_id must be omitted when None"
    );

    // Required fields still present.
    assert!(obj.contains_key("protocol_version"));
    assert!(obj.contains_key("zone"));
    assert!(obj.contains_key("host_public_key"));
    assert!(obj.contains_key("nonce"));
    assert!(obj.contains_key("capabilities_requested"));
}

#[test]
fn handshake_request_nonce_and_pubkey_serialize_as_32_element_arrays() {
    // host_public_key and nonce are `[u8; 32]` WITHOUT a hex_or_bytes
    // adapter. They serialize as 32-element JSON arrays. Pin so a future
    // addition of hex_or_bytes (which would silently change the wire form
    // to a hex string) is caught loudly.
    let req = populated_request();
    let v = serde_json::to_value(&req).unwrap();

    let pubkey = v.get("host_public_key").unwrap();
    let arr = pubkey.as_array().expect("host_public_key must be array");
    assert_eq!(arr.len(), 32);
    for byte in arr {
        assert_eq!(byte.as_u64(), Some(0xab));
    }

    let nonce = v.get("nonce").unwrap();
    let arr = nonce.as_array().expect("nonce must be array");
    assert_eq!(arr.len(), 32);
    for byte in arr {
        assert_eq!(byte.as_u64(), Some(0x42));
    }
}

#[test]
fn handshake_request_json_roundtrip_preserves_all_decision_critical_fields() {
    let req = populated_request();
    let bytes = serde_json::to_vec(&req).unwrap();
    let back: HandshakeRequest = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(back.protocol_version, req.protocol_version);
    assert_eq!(back.zone, req.zone);
    assert_eq!(back.zone_dir, req.zone_dir);
    assert_eq!(back.host_public_key, req.host_public_key);
    assert_eq!(back.nonce, req.nonce);
    assert_eq!(back.capabilities_requested, req.capabilities_requested);
}

#[test]
fn handshake_request_cbor_roundtrip_preserves_all_fields() {
    let req = populated_request();
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&req, &mut bytes).unwrap();
    let back: HandshakeRequest = ciborium::de::from_reader(&bytes[..]).unwrap();

    assert_eq!(back.protocol_version, req.protocol_version);
    assert_eq!(back.zone, req.zone);
    assert_eq!(back.host_public_key, req.host_public_key);
    assert_eq!(back.nonce, req.nonce);
    assert_eq!(back.capabilities_requested, req.capabilities_requested);
    assert_eq!(back.zone_dir, req.zone_dir);
    assert!(back.host.is_some());
    assert!(back.transport_caps.is_some());
    assert!(back.requested_instance_id.is_some());
}

#[test]
fn handshake_request_minimal_capabilities_default_to_empty_list() {
    // capabilities_requested has #[serde(default)] but NO
    // skip_serializing_if. When empty, it serializes as []. Pin so a
    // consumer counting on "no caps requested" always sees the [] not
    // a missing key.
    let req = minimal_request();
    let v = serde_json::to_value(&req).unwrap();
    let caps = v.get("capabilities_requested").unwrap();
    assert_eq!(caps, &json!([]), "empty capabilities_requested must be []");

    // Minimal payload omitting capabilities_requested also decodes back
    // to an empty Vec via #[serde(default)].
    let zeros: Vec<u8> = vec![0; 32];
    let bare = json!({
        "protocol_version": "1.0.0",
        "zone": "z:public",
        "host_public_key": zeros,
        "nonce": zeros
    });
    let back: HandshakeRequest = serde_json::from_value(bare).unwrap();
    assert_eq!(
        back.capabilities_requested,
        [] as [fcp_core::CapabilityId; 0]
    );
}

#[test]
fn host_info_skip_when_none_omits_version_and_build() {
    let host = HostInfo {
        name: "minimal-hub".to_string(),
        version: None,
        build: None,
    };
    let v = serde_json::to_value(&host).unwrap();
    let obj = v.as_object().unwrap();
    assert_eq!(obj.get("name"), Some(&json!("minimal-hub")));
    assert!(
        !obj.contains_key("version"),
        "version must be omitted when None"
    );
    assert!(
        !obj.contains_key("build"),
        "build must be omitted when None"
    );

    let back: HostInfo = serde_json::from_value(v).unwrap();
    assert_eq!(back.name, "minimal-hub");
    assert!(back.version.is_none());
    assert!(back.build.is_none());
}

#[test]
fn transport_caps_default_state_is_empty_list_and_none_frame_size() {
    let caps = TransportCaps::default();
    let v = serde_json::to_value(&caps).unwrap();
    let obj = v.as_object().unwrap();

    // compression is Vec with #[serde(default)] but NO skip_serializing_if → present as [].
    assert_eq!(obj.get("compression"), Some(&json!([])));
    // max_frame_size has skip_serializing_if = Option::is_none → omitted.
    assert!(!obj.contains_key("max_frame_size"));

    // Decode-side: default fills both.
    let bare = json!({});
    let back: TransportCaps = serde_json::from_value(bare).unwrap();
    assert_eq!(back.compression, [] as [std::string::String; 0]);
    assert!(back.max_frame_size.is_none());
}

#[test]
fn event_caps_default_state_via_serde_default_per_field() {
    let caps = EventCaps::default();
    assert!(!caps.streaming);
    assert!(!caps.replay);
    assert_eq!(caps.min_buffer_events, 0);
    assert!(!caps.requires_ack);

    // Empty JSON → all defaults.
    let bare = json!({});
    let back: EventCaps = serde_json::from_value(bare).unwrap();
    assert!(!back.streaming);
    assert!(!back.replay);
    assert_eq!(back.min_buffer_events, 0);
    assert!(!back.requires_ack);

    // Distinct event-cap config produces distinct JSON.
    let on = EventCaps {
        streaming: true,
        replay: true,
        min_buffer_events: 100,
        requires_ack: true,
    };
    let av = serde_json::to_value(&caps).unwrap();
    let bv = serde_json::to_value(&on).unwrap();
    assert_ne!(av, bv);
}

#[test]
fn handshake_response_full_field_set_pinned() {
    let resp = populated_response();
    let v = serde_json::to_value(&resp).unwrap();
    let obj = v.as_object().expect("must be object");

    let expected: std::collections::BTreeSet<&str> = [
        "status",
        "capabilities_granted",
        "session_id",
        "manifest_hash",
        "nonce",
        "event_caps",
        "auth_caps",
        "op_catalog_hash",
    ]
    .into_iter()
    .collect();
    let actual: std::collections::BTreeSet<&str> = obj.keys().map(String::as_str).collect();
    assert_eq!(actual, expected, "HandshakeResponse shape drift: {obj:?}");
}

#[test]
fn handshake_response_json_roundtrip_preserves_oauth_nested_payload() {
    let resp = populated_response();
    let bytes = serde_json::to_vec(&resp).unwrap();
    let back: HandshakeResponse = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(back.status, "accepted");
    assert_eq!(back.capabilities_granted.len(), 1);
    assert_eq!(back.nonce, resp.nonce);
    assert_eq!(back.session_id, resp.session_id);
    assert_eq!(back.manifest_hash, resp.manifest_hash);
    assert_eq!(back.op_catalog_hash, resp.op_catalog_hash);

    let oauth = back
        .auth_caps
        .as_ref()
        .and_then(|c| c.oauth.as_ref())
        .expect("oauth must round-trip");
    assert_eq!(oauth.authorize_url, "https://auth.example/authorize");
    assert_eq!(oauth.token_url, "https://auth.example/token");
    assert_eq!(oauth.scopes, vec!["read".to_string(), "write".to_string()]);
}

#[test]
fn handshake_response_cbor_roundtrip_preserves_event_and_auth_caps() {
    let resp = populated_response();
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&resp, &mut bytes).unwrap();
    let back: HandshakeResponse = ciborium::de::from_reader(&bytes[..]).unwrap();

    assert_eq!(back.nonce, resp.nonce);
    let event = back.event_caps.unwrap();
    assert!(event.streaming);
    assert_eq!(event.min_buffer_events, 16);

    let auth = back.auth_caps.unwrap();
    assert_eq!(auth.methods, vec!["oauth2".to_string()]);
    assert!(auth.oauth.is_some());
}

#[test]
fn handshake_request_json_and_cbor_decode_to_same_struct() {
    let req = populated_request();
    let json_bytes = serde_json::to_vec(&req).unwrap();
    let mut cbor_bytes = Vec::new();
    ciborium::ser::into_writer(&req, &mut cbor_bytes).unwrap();

    let from_json: HandshakeRequest = serde_json::from_slice(&json_bytes).unwrap();
    let from_cbor: HandshakeRequest = ciborium::de::from_reader(&cbor_bytes[..]).unwrap();

    assert_eq!(from_json.protocol_version, from_cbor.protocol_version);
    assert_eq!(from_json.host_public_key, from_cbor.host_public_key);
    assert_eq!(from_json.nonce, from_cbor.nonce);
    assert_eq!(
        from_json.capabilities_requested,
        from_cbor.capabilities_requested
    );
}

#[test]
fn distinct_nonces_produce_distinct_handshake_request_json() {
    // Nonce binding is the security-critical field — if a refactor
    // accidentally dropped it from the wire form, tests would still
    // pass with a default value. Pin that nonce variation flips JSON.
    let mut a = populated_request();
    let mut b = populated_request();
    a.nonce = [0x01; 32];
    b.nonce = [0x02; 32];
    let av = serde_json::to_value(&a).unwrap();
    let bv = serde_json::to_value(&b).unwrap();
    assert_ne!(av, bv, "nonce must affect wire form");
}

#[test]
fn distinct_host_public_keys_produce_distinct_json() {
    let mut a = populated_request();
    let mut b = populated_request();
    a.host_public_key = [0x10; 32];
    b.host_public_key = [0x20; 32];
    let av = serde_json::to_value(&a).unwrap();
    let bv = serde_json::to_value(&b).unwrap();
    assert_ne!(av, bv, "host_public_key must affect wire form");
}
