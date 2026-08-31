//! Frozen-byte golden tests for fcp-mesh symbol-exchange messages.
//!
//! `AmberLark`, 2026-05-02 — testing-golden-artifacts alpha-domain sweep.
//!
//! Companion to `wire_format_goldens.rs` (which pins `GossipSummary`
//! and `RevocationPushMessage`). This file pins the OTHER two
//! signed control-plane messages the mesh emits:
//!
//! - [`SymbolAck`]      — terminal acknowledgement of a symbol
//!                        exchange (Complete / Cancelled / Duplicate
//!                        / `BudgetExceeded`)
//! - [`DecodeStatus`]   — incremental decode-progress signal
//!
//! Both messages cross peers and are signed; their `transcript_bytes`
//! is what gets fed to `Ed25519::sign`. A field-order or
//! length-encoding refactor would invalidate every signature in
//! flight without breaking any existing round-trip serde test.
//!
//! When you intentionally change the schema:
//!
//!     UPDATE_GOLDENS=1 cargo insta test -p fcp-mesh
//!     cargo insta review        # human reviews every diff
//!     git add crates/fcp-mesh/tests/snapshots/
//!
//! Any other change MUST fail these tests.

#![allow(clippy::doc_overindented_list_items)]

use std::fmt::Write as _;

use fcp_cbor::SchemaId;
use fcp_crypto::Ed25519Signature;
use fcp_prelude::{ObjectHeader, ObjectId, Provenance, TailscaleNodeId, ZoneId, ZoneKeyId};
use fcp_protocol::{DecodeStatus, SymbolAck, SymbolAckReason};
use semver::Version;

/// Render bytes as a hex dump with section labels for human review.
/// Mirrors the helper in fcp-mesh/tests/wire_format_goldens.rs so the
/// snapshot format is consistent across the workspace.
fn dump(label: &str, bytes: &[u8]) -> String {
    let mut out = String::new();
    out.push_str(label);
    out.push('\n');
    writeln!(&mut out, "len = {}", bytes.len()).expect("writing to String cannot fail");
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let hex: String = chunk
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String = chunk
            .iter()
            .map(|b| {
                if b.is_ascii_graphic() || *b == b' ' {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect();
        writeln!(&mut out, "{:04x}  {:48}  {}", i * 16, hex, ascii)
            .expect("writing to String cannot fail");
    }
    out
}

fn fixture_zone() -> ZoneId {
    ZoneId::work()
}

fn fixture_header(schema_name: &str) -> ObjectHeader {
    ObjectHeader {
        encryption_kind: Default::default(),
        schema: SchemaId::new("fcp.protocol", schema_name, Version::new(1, 0, 0)),
        zone_id: fixture_zone(),
        created_at: 1_700_000_000,
        provenance: Provenance::new(fixture_zone()),
        refs: vec![],
        foreign_refs: vec![],
        ttl_secs: None,
        placement: None,
    }
}

/// Fixture: minimal `SymbolAck` — `Complete` reason, no missing hints.
/// The most common terminal-ack shape on the wire today.
fn complete_symbol_ack() -> SymbolAck {
    SymbolAck {
        header: fixture_header("SymbolAck"),
        object_id: ObjectId::from_bytes([0x11; 32]),
        zone_id: fixture_zone(),
        zone_key_id: ZoneKeyId::from_bytes([0x22; 8]),
        epoch_id: 1_000,
        recipient_node_id: TailscaleNodeId::new("100.64.0.1"),
        request_nonce: 0xDEAD_BEEF,
        reason: SymbolAckReason::Complete,
        final_symbol_count: 1_000,
        signature: Ed25519Signature::from_bytes(&[0u8; 64]),
    }
}

/// Fixture: `SymbolAck` with the `BudgetExceeded` terminal reason.
/// Pins the enum-variant tag layout so a future rename or
/// re-ordering of `SymbolAckReason` is caught at test time.
fn budget_exceeded_symbol_ack() -> SymbolAck {
    SymbolAck {
        header: fixture_header("SymbolAck"),
        object_id: ObjectId::from_bytes([0x33; 32]),
        zone_id: fixture_zone(),
        zone_key_id: ZoneKeyId::from_bytes([0x44; 8]),
        epoch_id: 0xC0FE,
        recipient_node_id: TailscaleNodeId::new("100.64.0.2"),
        request_nonce: 0x0102_0304_0506_0708,
        reason: SymbolAckReason::BudgetExceeded,
        final_symbol_count: 250,
        signature: Ed25519Signature::from_bytes(&[0u8; 64]),
    }
}

/// Fixture: `DecodeStatus` mid-decode (incomplete) with a
/// `missing_hint` populated. Pins both the integer encoding for
/// `received_unique`/`needed` AND the optional-vector encoding for
/// `missing_hint`.
fn mid_decode_status() -> DecodeStatus {
    DecodeStatus {
        header: fixture_header("DecodeStatus"),
        object_id: ObjectId::from_bytes([0x55; 32]),
        zone_id: fixture_zone(),
        zone_key_id: ZoneKeyId::from_bytes([0x66; 8]),
        epoch_id: 7_777,
        recipient_node_id: TailscaleNodeId::new("100.64.0.3"),
        request_nonce: 0xCAFE_F00D,
        received_unique: 500,
        needed: 1_003,
        complete: false,
        missing_hint: Some(vec![10, 20, 30, 40]),
        signature: Ed25519Signature::from_bytes(&[0u8; 64]),
    }
}

/// Fixture: `DecodeStatus` terminal (complete=true), no `missing_hint`.
/// Pins the `complete=true + None hint` shape for the success branch.
fn complete_decode_status() -> DecodeStatus {
    DecodeStatus {
        header: fixture_header("DecodeStatus"),
        object_id: ObjectId::from_bytes([0x77; 32]),
        zone_id: fixture_zone(),
        zone_key_id: ZoneKeyId::from_bytes([0x88; 8]),
        epoch_id: 8_888,
        recipient_node_id: TailscaleNodeId::new("100.64.0.4"),
        request_nonce: 0xFEED_FACE,
        received_unique: 1_003,
        needed: 1_003,
        complete: true,
        missing_hint: None,
        signature: Ed25519Signature::from_bytes(&[0u8; 64]),
    }
}

#[test]
fn symbol_ack_complete_transcript_bytes_layout() {
    let bytes = complete_symbol_ack().transcript_bytes();
    insta::assert_snapshot!(dump(
        "SymbolAck::transcript_bytes (Complete fixture, no missing hint)",
        &bytes,
    ));
}

#[test]
fn symbol_ack_budget_exceeded_transcript_bytes_layout() {
    let bytes = budget_exceeded_symbol_ack().transcript_bytes();
    insta::assert_snapshot!(dump(
        "SymbolAck::transcript_bytes (BudgetExceeded fixture)",
        &bytes,
    ));
}

#[test]
fn decode_status_mid_decode_transcript_bytes_layout() {
    let bytes = mid_decode_status().transcript_bytes();
    insta::assert_snapshot!(dump(
        "DecodeStatus::transcript_bytes (mid-decode, missing_hint populated)",
        &bytes,
    ));
}

#[test]
fn decode_status_complete_transcript_bytes_layout() {
    let bytes = complete_decode_status().transcript_bytes();
    insta::assert_snapshot!(dump(
        "DecodeStatus::transcript_bytes (complete=true, no missing_hint)",
        &bytes,
    ));
}
