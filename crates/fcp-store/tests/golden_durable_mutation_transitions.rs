//! Golden vector for `DurableSymbolStore` mutation state transitions
//! (br-38cd93962, follow-up to commit 38cd93962 read-validate /
//! write-publish split).
//!
//! Records the FULL state-transition diff for a canonical mutation
//! script. Each step in the script (open / `put_object_meta` /
//! `put_symbol` / idempotent duplicate / `delete_symbol` / `delete_object`)
//! emits a one-line probe of the observable state — `storage_used`,
//! per-object `symbol_count`, `list_zone` size — so a single golden
//! file captures every observable side-effect of every WAL operation
//! type.
//!
//! Pre-fix the durable mutation behavior was covered by per-mutation
//! unit tests scattered across `durable.rs`. This golden gives an
//! operator one diffable artifact that pins:
//!
//! - the EXACT `storage_used` delta after each mutation
//! - that idempotent `put_symbol` with byte-equal data produces zero
//!   delta (the load-bearing invariant the metamorphic test pinned;
//!   here it shows as a `storage_used` line that doesn't change
//!   between two consecutive put rows)
//! - that `delete_symbol` releases the right number of bytes
//! - that `delete_object` releases its metadata and remaining symbols
//!
//! Any future refactor that double-counts a duplicate, leaks bytes
//! on a failed put, or shifts the WAL apply order would surface as
//! a per-line diff in this file. The diff IS the operator-readable
//! evidence trail.
//!
//! Update flow:
//!   `UPDATE_GOLDENS=1` cargo test -p fcp-store --test `golden_durable_mutation_transitions`
//!   cargo insta review
//!   git diff crates/fcp-store/tests/snapshots/

use bytes::Bytes;
use fcp_async_core::runtime::Runtime;
use fcp_prelude::{ObjectId, ZoneId};
use fcp_store::{
    DurableSymbolStore, DurableSymbolStoreConfig, ObjectSymbolMeta, ObjectTransmissionInfo,
    StoredSymbol, SymbolMeta, SymbolStore, SymbolStoreError,
};
use tempfile::TempDir;

const SYMBOL_SIZE: u16 = 128;

fn zone() -> ZoneId {
    ZoneId::work()
}

fn meta(seed: u8, source_symbols: u32) -> ObjectSymbolMeta {
    ObjectSymbolMeta {
        object_id: ObjectId::from_bytes([seed; 32]),
        zone_id: zone(),
        oti: ObjectTransmissionInfo {
            transfer_length: u64::from(SYMBOL_SIZE) * u64::from(source_symbols),
            symbol_size: SYMBOL_SIZE,
            source_blocks: 1,
            sub_blocks: 1,
            alignment: 8,
            payload_hash: None,
        },
        source_symbols,
        first_symbol_at: 100,
    }
}

fn symbol(seed: u8, esi: u32, fill: u8) -> StoredSymbol {
    StoredSymbol {
        meta: SymbolMeta {
            object_id: ObjectId::from_bytes([seed; 32]),
            esi,
            zone_id: zone(),
            source_node: Some(u64::from(esi).wrapping_add(1)),
            stored_at: 100 + u64::from(esi),
        },
        data: Bytes::from(vec![fill; usize::from(SYMBOL_SIZE)]),
    }
}

async fn probe(store: &DurableSymbolStore) -> String {
    let used = store.storage_used().await;
    let zone = zone();
    let zone_objects = store.list_zone(&zone).await.len();
    let count_a = store.symbol_count(&ObjectId::from_bytes([0xA1; 32])).await;
    let count_b = store.symbol_count(&ObjectId::from_bytes([0xB2; 32])).await;
    format!(
        "  used={used:>6}  zone_objects={zone_objects}  count(a1)={count_a}  count(b2)={count_b}"
    )
}

async fn run_script(temp: &TempDir) -> String {
    let config = DurableSymbolStoreConfig::new(temp.path().join("symbols"));
    let store = DurableSymbolStore::open(config).expect("open durable store");

    let mut log = Vec::new();
    log.push("# DurableSymbolStore canonical mutation script golden".to_string());
    log.push("# br-38cd93962: read-validate / write-publish split".to_string());
    log.push("# Each step emits one probe line of observable state.".to_string());
    log.push(
        "# 'used' = storage_used (bytes); 'zone_objects' = list_zone(work).len();".to_string(),
    );
    log.push(
        "# count(a1) = symbol_count for object 0xA1...; count(b2) = ditto for 0xB2...".to_string(),
    );
    log.push("#".to_string());
    log.push("# Load-bearing invariants visible in the diff:".to_string());
    log.push("#   1. each symbol contributes 192 bytes to used (128 data +".to_string());
    log.push("#      64 metadata overhead per Self::symbol_size). A drift in".to_string());
    log.push("#      this constant becomes visible as a per-row delta change.".to_string());
    log.push("#      Each object also contributes 262 bytes (256 bookkeeping +".to_string());
    log.push("#      6 zone identifier bytes), even before any symbols arrive.".to_string());
    log.push(
        "#   2. idempotent duplicate put leaves used unchanged (zero double-count)".to_string(),
    );
    log.push("#      — visible as steps 02/03 producing identical lines.".to_string());
    log.push(
        "#   3. delete_symbol releases the symbol's bytes; delete_object releases".to_string(),
    );
    log.push("#      its metadata and the sum of its remaining symbols.".to_string());
    log.push("#   4. failed validate (conflicting bytes) leaves state byte-identical".to_string());
    log.push(
        "#      to pre-attempt — visible as steps 03/04 producing identical lines.".to_string(),
    );
    log.push("#   5. reopen-from-disk recovers the full applied state — step 10's".to_string());
    log.push("#      line MUST match step 09's line. Pre-fix the read-validate /".to_string());
    log.push("#      write-publish split could (under refactor) advance next_seq".to_string());
    log.push("#      on validate failure and corrupt the WAL — the reopen-floor".to_string());
    log.push("#      check is the only structural proof of 'no WAL gap'.".to_string());
    log.push(String::new());

    log.push("step 00 open                              ".to_string());
    log.push(probe(&store).await);

    log.push("step 01 put_object_meta(a1, K=4)          ".to_string());
    store.put_object_meta(meta(0xA1, 4)).await.expect("meta a1");
    log.push(probe(&store).await);

    log.push("step 02 put_symbol(a1, esi=0, fill=AA)    ".to_string());
    store
        .put_symbol(symbol(0xA1, 0, 0xAA))
        .await
        .expect("put a1/0");
    log.push(probe(&store).await);

    log.push("step 03 put_symbol(a1, esi=0, fill=AA) (dup)".to_string());
    store
        .put_symbol(symbol(0xA1, 0, 0xAA))
        .await
        .expect("byte-equal duplicate must remain idempotent");
    log.push(probe(&store).await);

    log.push("step 04 put_symbol(a1, esi=0, fill=BB) (forged)".to_string());
    let forged = symbol(0xA1, 0, 0xBB);
    let result = store.put_symbol(forged).await;
    assert!(
        matches!(&result, Err(SymbolStoreError::InvalidSymbol { .. })),
        "step 04: forged conflicting bytes must reject as InvalidSymbol; got {result:?}"
    );
    log.push(probe(&store).await);

    log.push("step 05 put_symbol(a1, esi=1, fill=CC)    ".to_string());
    store
        .put_symbol(symbol(0xA1, 1, 0xCC))
        .await
        .expect("put a1/1");
    log.push(probe(&store).await);

    log.push("step 06 put_object_meta(b2, K=2)          ".to_string());
    store.put_object_meta(meta(0xB2, 2)).await.expect("meta b2");
    log.push(probe(&store).await);

    log.push("step 07 put_symbol(b2, esi=0, fill=DD)    ".to_string());
    store
        .put_symbol(symbol(0xB2, 0, 0xDD))
        .await
        .expect("put b2/0");
    log.push(probe(&store).await);

    log.push("step 08 delete_symbol(a1, esi=1)          ".to_string());
    store
        .delete_symbol(&ObjectId::from_bytes([0xA1; 32]), 1)
        .await
        .expect("delete a1/1");
    log.push(probe(&store).await);

    log.push("step 09 delete_object(a1)                 ".to_string());
    store
        .delete_object(&ObjectId::from_bytes([0xA1; 32]))
        .await
        .expect("delete a1");
    log.push(probe(&store).await);

    log.push("step 10 reopen + probe (recovery floor)   ".to_string());
    drop(store);
    let reopened =
        DurableSymbolStore::open(DurableSymbolStoreConfig::new(temp.path().join("symbols")))
            .expect("reopen");
    log.push(probe(&reopened).await);

    log.join("\n") + "\n"
}

#[test]
fn golden_durable_mutation_transitions_canonical_script() {
    let temp = TempDir::new().expect("temp dir");
    let rt = Runtime::new().expect("runtime");
    let actual = rt.block_on(async { run_script(&temp).await });
    insta::assert_snapshot!("durable_mutation_transitions_canonical_script", actual);
}
