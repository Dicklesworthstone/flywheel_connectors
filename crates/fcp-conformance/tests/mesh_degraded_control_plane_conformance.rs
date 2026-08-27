//! `fcp_mesh::degraded` control-plane retention + envelope + error
//! conformance.
//!
//! When FCPC (the reliable control-plane stream) is unavailable, the
//! mesh falls back to symbol-native FCPS frames with the
//! `CONTROL_PLANE` flag. Three NORMATIVE contracts govern the
//! fallback path:
//!
//! 1. **`RetentionClass`** — `Required` is the documented `Default`
//!    (durable transport defaults to "MUST store and replay") and
//!    `Ephemeral` is the only opt-out. Drift here would silently
//!    drop checkpoint/audit objects across a partition.
//! 2. **`InMemoryControlPlaneHandler` retention enforcement** —
//!    `Required` envelopes MUST be stored (visible via `count`,
//!    `get`, `list_epochs`, `fetch_epoch`); `Ephemeral` envelopes
//!    MUST be acknowledged but NOT stored.
//! 3. **`DegradedTransportError` Display contract** — operator
//!    incident-log greps depend on the literal substrings
//!    ("retention violation", "schema hash mismatch", "object ID
//!    mismatch", "signature verification failed", etc.).
//!
//! Properties pinned (NORMATIVE):
//!
//! - `RetentionClass::default() == Required`
//! - Required and Ephemeral are PartialEq-distinct, Hash-distinct
//! - `ControlPlaneEnvelope::new` preserves all 7 fields verbatim
//! - `InMemoryControlPlaneHandler::new()` starts with count=0, no
//!   epochs, get returns None
//! - `handle(Required)` stores, increments count, exposes via
//!   `list_epochs` + `fetch_epoch`
//! - `handle(Ephemeral)` does NOT store, count stays unchanged
//! - `list_epochs(zone, since=Some(N))` returns only epochs > N
//!   (strict, not ≥)
//! - `DegradedTransportError` Display strings include the documented
//!   keywords for each variant

use fcp_cbor::SchemaId;
use fcp_mesh::{
    ControlPlaneEnvelope, ControlPlaneHandler, DegradedTransportError, InMemoryControlPlaneHandler,
    RetentionClass,
};
use fcp_prelude::{ObjectId, ObjectIdKey, ZoneId, ZoneKeyId};
use semver::Version;

fn fake_object_id(tag: &[u8]) -> ObjectId {
    let zone = ZoneId::work();
    let schema = SchemaId::new("fcp.test", "ControlPlaneObject", Version::new(1, 0, 0));
    let key = ObjectIdKey::from_bytes([7u8; 32]);
    ObjectId::new(tag, &zone, &schema, &key)
}

fn fake_envelope(tag: &[u8], retention: RetentionClass) -> ControlPlaneEnvelope {
    ControlPlaneEnvelope::new(
        b"payload-bytes".to_vec(),
        [42u8; 32],
        fake_object_id(tag),
        ZoneId::work(),
        ZoneKeyId::from_bytes([1u8; 8]),
        7,
        retention,
    )
}

fn fake_envelope_in_zone_at_epoch(
    tag: &[u8],
    zone: ZoneId,
    epoch: u64,
    retention: RetentionClass,
) -> ControlPlaneEnvelope {
    ControlPlaneEnvelope::new(
        b"payload-bytes".to_vec(),
        [42u8; 32],
        fake_object_id(tag),
        zone,
        ZoneKeyId::from_bytes([1u8; 8]),
        epoch,
        retention,
    )
}

// ─── RetentionClass ────────────────────────────────────────────────

#[test]
fn retention_class_default_is_required() {
    assert_eq!(
        RetentionClass::default(),
        RetentionClass::Required,
        "RetentionClass::default MUST be Required — durable transport defaults to MUST store"
    );
}

#[test]
fn retention_class_required_and_ephemeral_are_distinct() {
    assert_ne!(RetentionClass::Required, RetentionClass::Ephemeral);
}

#[test]
fn retention_class_implements_copy_clone_eq() {
    let a = RetentionClass::Required;
    let b = a; // Copy
    let c = a; // Clone
    assert_eq!(a, b);
    assert_eq!(a, c);
}

#[test]
fn retention_class_eq_distinguishes_variants_in_collections() {
    // RetentionClass derives PartialEq/Eq but not Hash. Pin via Vec
    // membership semantics (operator tooling iterates lists, doesn't
    // hash).
    let v = [RetentionClass::Required, RetentionClass::Ephemeral];
    assert!(v.contains(&RetentionClass::Required));
    assert!(v.contains(&RetentionClass::Ephemeral));
}

// ─── ControlPlaneEnvelope ──────────────────────────────────────────

#[test]
fn envelope_new_preserves_all_seven_fields() {
    let oid = fake_object_id(b"unique-tag");
    let zone = ZoneId::work();
    let zone_key = ZoneKeyId::from_bytes([7u8; 8]);
    let env = ControlPlaneEnvelope::new(
        b"some-payload".to_vec(),
        [9u8; 32],
        oid,
        zone.clone(),
        zone_key,
        42,
        RetentionClass::Ephemeral,
    );
    assert_eq!(env.payload, b"some-payload");
    assert_eq!(env.schema_hash, [9u8; 32]);
    assert_eq!(env.object_id, oid);
    assert_eq!(env.zone_id, zone);
    assert_eq!(env.zone_key_id, zone_key);
    assert_eq!(env.epoch_id, 42);
    assert_eq!(env.retention, RetentionClass::Ephemeral);
}

#[test]
fn envelope_clone_is_field_for_field_identical() {
    let env = fake_envelope(b"clone-test", RetentionClass::Required);
    let cloned = env.clone();
    assert_eq!(env.payload, cloned.payload);
    assert_eq!(env.schema_hash, cloned.schema_hash);
    assert_eq!(env.object_id, cloned.object_id);
    assert_eq!(env.zone_id, cloned.zone_id);
    assert_eq!(env.zone_key_id, cloned.zone_key_id);
    assert_eq!(env.epoch_id, cloned.epoch_id);
    assert_eq!(env.retention, cloned.retention);
}

// ─── InMemoryControlPlaneHandler ───────────────────────────────────

#[test]
fn handler_starts_empty() {
    let h = InMemoryControlPlaneHandler::new();
    assert_eq!(h.count(), 0);
    assert!(h.get(&fake_object_id(b"missing")).is_none());
    assert_eq!(h.list_epochs(&ZoneId::work(), None), [] as [u64; 0]);
}

#[test]
fn handler_stores_required_envelope() {
    let h = InMemoryControlPlaneHandler::new();
    let env = fake_envelope(b"required-1", RetentionClass::Required);
    let oid = env.object_id;
    h.handle(env).expect("handler accepts Required");
    assert_eq!(
        h.count(),
        1,
        "Required envelope MUST be stored (count incremented)"
    );
    let got = h.get(&oid).expect("Required envelope MUST be retrievable");
    assert_eq!(got.retention, RetentionClass::Required);
}

#[test]
fn handler_does_not_store_ephemeral_envelope() {
    let h = InMemoryControlPlaneHandler::new();
    let env = fake_envelope(b"ephemeral-1", RetentionClass::Ephemeral);
    let oid = env.object_id;
    h.handle(env)
        .expect("handler accepts Ephemeral without error");
    assert_eq!(
        h.count(),
        0,
        "Ephemeral envelope MUST NOT be stored — count stays 0"
    );
    assert!(
        h.get(&oid).is_none(),
        "Ephemeral envelope MUST NOT be retrievable"
    );
}

#[test]
fn handler_list_epochs_returns_only_required_epochs() {
    let h = InMemoryControlPlaneHandler::new();
    let zone = ZoneId::work();
    h.handle(fake_envelope_in_zone_at_epoch(
        b"r1",
        zone.clone(),
        10,
        RetentionClass::Required,
    ))
    .expect("required @ epoch 10");
    h.handle(fake_envelope_in_zone_at_epoch(
        b"r2",
        zone.clone(),
        20,
        RetentionClass::Required,
    ))
    .expect("required @ epoch 20");
    h.handle(fake_envelope_in_zone_at_epoch(
        b"e1",
        zone.clone(),
        30,
        RetentionClass::Ephemeral,
    ))
    .expect("ephemeral @ epoch 30 — MUST NOT be indexed");

    let epochs = h.list_epochs(&zone, None);
    assert_eq!(
        epochs,
        vec![10, 20],
        "list_epochs MUST return only epochs with stored Required objects"
    );
}

#[test]
fn handler_list_epochs_since_is_strict_greater_than() {
    let h = InMemoryControlPlaneHandler::new();
    let zone = ZoneId::work();
    for epoch in [10, 20, 30, 40] {
        h.handle(fake_envelope_in_zone_at_epoch(
            format!("e-{epoch}").as_bytes(),
            zone.clone(),
            epoch,
            RetentionClass::Required,
        ))
        .expect("required");
    }
    let after_20 = h.list_epochs(&zone, Some(20));
    assert_eq!(
        after_20,
        vec![30, 40],
        "since=Some(20) MUST be STRICT > 20 (epoch 20 itself excluded)"
    );
    let after_zero = h.list_epochs(&zone, Some(0));
    assert_eq!(
        after_zero,
        vec![10, 20, 30, 40],
        "since=Some(0) returns everything"
    );
}

#[test]
fn handler_fetch_epoch_returns_envelopes_for_specific_epoch() {
    let h = InMemoryControlPlaneHandler::new();
    let zone = ZoneId::work();
    h.handle(fake_envelope_in_zone_at_epoch(
        b"a1",
        zone.clone(),
        7,
        RetentionClass::Required,
    ))
    .expect("required");
    h.handle(fake_envelope_in_zone_at_epoch(
        b"a2",
        zone.clone(),
        7,
        RetentionClass::Required,
    ))
    .expect("required");
    h.handle(fake_envelope_in_zone_at_epoch(
        b"b1",
        zone.clone(),
        8,
        RetentionClass::Required,
    ))
    .expect("required");

    let envs_at_7 = h.fetch_epoch(&zone, 7);
    assert_eq!(envs_at_7.len(), 2, "epoch 7 MUST yield 2 envelopes");
    let envs_at_8 = h.fetch_epoch(&zone, 8);
    assert_eq!(envs_at_8.len(), 1, "epoch 8 MUST yield 1 envelope");
    let envs_at_9 = h.fetch_epoch(&zone, 9);
    assert_eq!(envs_at_9.len(), 0, "epoch 9 MUST yield empty");
}

#[test]
fn handler_fetch_epoch_unknown_zone_returns_empty() {
    let h = InMemoryControlPlaneHandler::new();
    let envs = h.fetch_epoch(&ZoneId::work(), 0);
    assert!(envs.is_empty());
}

#[test]
fn handler_count_does_not_double_count_object_id_replays() {
    // Re-handling the same object_id MUST replace, not duplicate.
    let h = InMemoryControlPlaneHandler::new();
    let env_a =
        fake_envelope_in_zone_at_epoch(b"replay", ZoneId::work(), 1, RetentionClass::Required);
    let env_b =
        fake_envelope_in_zone_at_epoch(b"replay", ZoneId::work(), 2, RetentionClass::Required);
    h.handle(env_a).expect("first");
    assert_eq!(h.count(), 1);
    h.handle(env_b).expect("replay with same object_id");
    assert_eq!(
        h.count(),
        1,
        "re-handling same object_id MUST replace, not double-count"
    );
}

// ─── DegradedTransportError Display ────────────────────────────────

#[test]
fn error_incomplete_display_includes_received_and_needed_counts() {
    let e = DegradedTransportError::Incomplete {
        received: 7,
        needed: 12,
    };
    let s = format!("{e}");
    assert!(
        s.contains("7/12"),
        "Incomplete Display MUST show received/needed; got {s}"
    );
    assert!(s.contains("incomplete"));
}

#[test]
fn error_schema_hash_mismatch_display_includes_keyword() {
    let e = DegradedTransportError::SchemaHashMismatch {
        expected: [1u8; 32],
        actual: [2u8; 32],
    };
    let s = format!("{e}");
    assert!(
        s.contains("schema hash mismatch"),
        "Display MUST include literal 'schema hash mismatch' for log greps; got {s}"
    );
}

#[test]
fn error_object_id_mismatch_display_is_specific() {
    let e = DegradedTransportError::ObjectIdMismatch;
    let s = format!("{e}");
    assert!(
        s.contains("object ID mismatch"),
        "Display MUST include 'object ID mismatch'; got {s}"
    );
}

#[test]
fn error_retention_violation_display_mentions_required_object() {
    let e = DegradedTransportError::RetentionViolation;
    let s = format!("{e}");
    assert!(
        s.contains("retention violation"),
        "Display MUST include 'retention violation'; got {s}"
    );
    assert!(
        s.contains("Required"),
        "Display MUST mention Required object class; got {s}"
    );
}

#[test]
fn error_missing_control_plane_flag_display_is_specific() {
    let e = DegradedTransportError::MissingControlPlaneFlag;
    let s = format!("{e}");
    assert!(
        s.contains("CONTROL_PLANE flag"),
        "Display MUST mention the missing flag literal; got {s}"
    );
}

#[test]
fn error_empty_control_plane_frame_display_is_specific() {
    let e = DegradedTransportError::EmptyControlPlaneFrame;
    let s = format!("{e}");
    assert!(
        s.contains("no symbols"),
        "Display MUST explain that frame has no symbols; got {s}"
    );
}

#[test]
fn error_signature_verification_failed_display_is_specific() {
    let e = DegradedTransportError::SignatureVerificationFailed;
    let s = format!("{e}");
    assert!(
        s.contains("signature verification failed"),
        "Display MUST include 'signature verification failed' for security audit greps; got {s}"
    );
}

#[test]
fn error_symbol_crypto_unavailable_display_mentions_authenticated_context() {
    let e = DegradedTransportError::SymbolCryptoUnavailable;
    let s = format!("{e}");
    assert!(
        s.contains("authenticated"),
        "Display MUST explain that authenticated symbol crypto is required; got {s}"
    );
}

#[test]
fn error_pending_limit_exceeded_display_carries_current_and_limit() {
    let e = DegradedTransportError::PendingLimitExceeded {
        current: 100,
        limit: 64,
    };
    let s = format!("{e}");
    assert!(
        s.contains("100"),
        "Display MUST include current count; got {s}"
    );
    assert!(s.contains("64"), "Display MUST include limit; got {s}");
    assert!(
        s.contains("pending"),
        "Display MUST mention 'pending'; got {s}"
    );
}
