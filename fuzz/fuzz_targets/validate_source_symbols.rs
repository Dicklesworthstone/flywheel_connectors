#![no_main]
//! Fuzz target for the `fcp_store::validate_source_symbols` range gate.
//!
//! This is the DoS-resistance guard before symbol metadata can drive
//! preallocation under the symbol-store write lock.

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{ObjectId, ZoneId};
use fcp_store::{
    ObjectSymbolMeta, ObjectTransmissionInfo, SymbolStoreError, validate_source_symbols,
};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const MAX_SOURCE_SYMBOLS: u32 = 56_403;

static BOUNDARY_ANCHORS: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct ValidateSourceSymbolsInput {
    source_symbols: u32,
    object_id_byte: u8,
    first_symbol_at: u64,
}

fn meta(input: &ValidateSourceSymbolsInput) -> ObjectSymbolMeta {
    ObjectSymbolMeta {
        object_id: ObjectId::from_bytes([input.object_id_byte; 32]),
        zone_id: ZoneId::work(),
        oti: ObjectTransmissionInfo {
            transfer_length: u64::from(input.source_symbols) * 128,
            symbol_size: 128,
            source_blocks: 1,
            sub_blocks: 1,
            alignment: 8,
            payload_hash: None,
        },
        source_symbols: input.source_symbols,
        first_symbol_at: input.first_symbol_at,
    }
}

fn assert_validation(input: &ValidateSourceSymbolsInput) {
    let meta = meta(input);
    let first = validate_source_symbols(&meta);
    let second = validate_source_symbols(&meta);

    match input.source_symbols {
        1..=MAX_SOURCE_SYMBOLS => {
            assert!(first.is_ok(), "valid source_symbols rejected: {first:?}");
            assert!(second.is_ok(), "validation is not deterministic: {second:?}");
        }
        rejected => {
            let Err(SymbolStoreError::InvalidSymbol { reason }) = first else {
                panic!("invalid source_symbols {rejected} accepted or returned wrong error");
            };
            assert!(
                reason.contains(&rejected.to_string()),
                "error reason must include rejected count {rejected}: {reason}"
            );
            assert!(
                reason.contains(&MAX_SOURCE_SYMBOLS.to_string()),
                "error reason must include max bound {MAX_SOURCE_SYMBOLS}: {reason}"
            );
            assert_eq!(
                format!("{second:?}"),
                format!("{:?}", Err::<(), _>(SymbolStoreError::InvalidSymbol { reason })),
                "validation result changed between identical calls"
            );
        }
    }
}

fn assert_boundary_anchors() {
    for source_symbols in [
        0,
        1,
        MAX_SOURCE_SYMBOLS - 1,
        MAX_SOURCE_SYMBOLS,
        MAX_SOURCE_SYMBOLS + 1,
        u32::MAX,
    ] {
        assert_validation(&ValidateSourceSymbolsInput {
            source_symbols,
            object_id_byte: source_symbols as u8,
            first_symbol_at: u64::from(source_symbols),
        });
    }
}

fuzz_target!(|data: &[u8]| {
    BOUNDARY_ANCHORS.call_once(assert_boundary_anchors);

    let mut unstructured = Unstructured::new(data);
    let Ok(input) = ValidateSourceSymbolsInput::arbitrary(&mut unstructured) else {
        return;
    };

    assert_validation(&input);
});
