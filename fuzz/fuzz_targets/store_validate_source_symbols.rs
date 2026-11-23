#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fcp_core::{ObjectId, ZoneId};
use fcp_store::{
    ObjectSymbolMeta, ObjectTransmissionInfo, SymbolStoreError, validate_source_symbols,
};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

const MAX_SOURCE_SYMBOLS: u32 = 56_403;

static SOURCE_SYMBOLS_ANCHOR: Once = Once::new();

#[derive(Arbitrary, Debug)]
struct Input {
    object_id: [u8; 32],
    source_symbols: u32,
    transfer_length: u64,
    symbol_size: u16,
    source_blocks: u8,
    sub_blocks: u16,
    alignment: u8,
    payload_hash: Option<[u8; 32]>,
    first_symbol_at: u64,
}

fn meta(input: &Input, source_symbols: u32) -> ObjectSymbolMeta {
    ObjectSymbolMeta {
        object_id: ObjectId::from_bytes(input.object_id),
        zone_id: ZoneId::work(),
        oti: ObjectTransmissionInfo {
            transfer_length: input.transfer_length,
            symbol_size: input.symbol_size,
            source_blocks: input.source_blocks,
            sub_blocks: input.sub_blocks,
            alignment: input.alignment,
            payload_hash: input.payload_hash,
        },
        source_symbols,
        first_symbol_at: input.first_symbol_at,
    }
}

fn outcome_text(result: Result<(), SymbolStoreError>) -> String {
    match result {
        Ok(()) => "ok".to_string(),
        Err(SymbolStoreError::InvalidSymbol { reason }) => format!("invalid:{reason}"),
        Err(other) => format!("other:{other}"),
    }
}

fn assert_validation(input: &Input, source_symbols: u32) {
    let meta = meta(input, source_symbols);
    let first = validate_source_symbols(&meta);
    let second = validate_source_symbols(&meta);
    let first_text = outcome_text(first);
    let second_text = outcome_text(second);
    assert_eq!(first_text, second_text, "validation must be deterministic");

    let count_in_range = (1..=MAX_SOURCE_SYMBOLS).contains(&source_symbols);
    let supported_oti = input.symbol_size != 0
        && input.source_blocks == 1
        && input.sub_blocks == 1
        && input.alignment == 8;
    // An independent interval oracle also covers a partial final symbol:
    // (K - 1) * T < F <= K * T. Both products fit u64 for u32/u16 inputs.
    let lower = u64::from(source_symbols.saturating_sub(1)) * u64::from(input.symbol_size);
    let upper = u64::from(source_symbols) * u64::from(input.symbol_size);
    let consistent_length = input.transfer_length > lower && input.transfer_length <= upper;

    if count_in_range && supported_oti && consistent_length {
        assert_eq!(first_text, "ok", "valid source block should be accepted");
    } else {
        assert!(
            first_text.starts_with("invalid:"),
            "malformed source block should be InvalidSymbol, got {first_text}"
        );
        if !count_in_range {
            assert!(
                first_text.contains(&format!("source_symbols={source_symbols}")),
                "InvalidSymbol reason must carry rejected source_symbols count: {first_text}"
            );
            assert!(
                first_text.contains(&MAX_SOURCE_SYMBOLS.to_string()),
                "InvalidSymbol reason must carry max source_symbols bound: {first_text}"
            );
        }
    }
}

fuzz_target!(|data: &[u8]| {
    SOURCE_SYMBOLS_ANCHOR.call_once(assert_boundary_anchors);

    let mut unstructured = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut unstructured) else {
        return;
    };

    assert_validation(&input, input.source_symbols);
});

fn assert_boundary_anchors() {
    let mut input = Input {
        object_id: [0xA5; 32],
        source_symbols: 1,
        transfer_length: 1024,
        symbol_size: 64,
        source_blocks: 1,
        sub_blocks: 1,
        alignment: 8,
        payload_hash: Some([0x5A; 32]),
        first_symbol_at: 42,
    };

    for source_symbols in [
        0,
        1,
        MAX_SOURCE_SYMBOLS - 1,
        MAX_SOURCE_SYMBOLS,
        MAX_SOURCE_SYMBOLS + 1,
        u32::MAX,
    ] {
        input.transfer_length = u64::from(source_symbols) * u64::from(input.symbol_size);
        assert_validation(&input, source_symbols);
    }

    input.transfer_length = 65;
    assert_validation(&input, 2);
    assert_validation(&input, 1);
    input.symbol_size = 0;
    assert_validation(&input, 2);
}
