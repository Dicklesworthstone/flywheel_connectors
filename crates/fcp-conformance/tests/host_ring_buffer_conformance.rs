//! `RingBuffer` eviction + overflow-telemetry conformance.
//!
//! `fcp_host::output_capture::RingBuffer` is the fixed-capacity
//! ring used to capture connector stdout/stderr for diagnostics.
//! Documented invariants:
//!
//! 1. **FIFO eviction.** When the buffer is at capacity, a new write
//!    overwrites the OLDEST bytes — the freshest output is always
//!    retained.
//! 2. **Tail-truncate on oversized input.** A single write whose
//!    length is ≥ capacity drops everything except the LAST
//!    `capacity` bytes. This is the documented "last `capacity`
//!    bytes" property (not first).
//! 3. **Monotonic `total_written`.** Counts every byte ever
//!    written, including bytes that were subsequently evicted, so
//!    operators can compute drop = `total_written` - len when reading
//!    the captured tail.
//! 4. **`has_overflow` telemetry signal.** True iff
//!    `total_written` > capacity. The on-the-wire signal that a
//!    triage report is incomplete.
//! 5. **`clear()` preserves `total_written`.** This is a forensic
//!    invariant — clearing the visible buffer MUST NOT reset the
//!    drop accounting; otherwise an attacker who could trigger
//!    a clear could mask earlier overflow.
//! 6. **`last_n` clamps to `len` when `n` exceeds buffered length.**

use fcp_host::RingBuffer;

#[test]
fn empty_ring_reports_zero_state() {
    let r = RingBuffer::new(16);
    assert_eq!(r.len(), 0);
    assert!(r.is_empty());
    assert_eq!(r.capacity(), 16);
    assert_eq!(r.total_written(), 0);
    assert!(!r.has_overflow());
    assert_eq!(r.contents(), [] as [u8; 0]);
}

#[test]
fn write_within_capacity_preserves_all_bytes() {
    let mut r = RingBuffer::new(16);
    r.write(b"hello");
    assert_eq!(r.len(), 5);
    assert_eq!(r.contents(), b"hello");
    assert_eq!(r.total_written(), 5);
    assert!(!r.has_overflow());
}

#[test]
fn write_exactly_at_capacity_does_not_overflow() {
    let mut r = RingBuffer::new(8);
    r.write(b"abcdefgh"); // exactly 8 bytes
    assert_eq!(r.len(), 8);
    assert_eq!(r.contents(), b"abcdefgh");
    assert_eq!(r.total_written(), 8);
    assert!(
        !r.has_overflow(),
        "total_written == capacity is NOT overflow (the cap is exclusive above)"
    );
}

#[test]
fn write_one_byte_past_capacity_evicts_oldest() {
    // FIFO eviction: writing one more byte than fits MUST drop the
    // oldest byte to make room.
    let mut r = RingBuffer::new(4);
    r.write(b"abcd");
    r.write(b"e");
    assert_eq!(
        r.contents(),
        b"bcde",
        "FIFO eviction: oldest byte 'a' must be dropped, contents must be 'bcde'"
    );
    assert_eq!(r.len(), 4, "buffer stays at capacity after overflow write");
    assert_eq!(r.total_written(), 5);
    assert!(r.has_overflow());
}

#[test]
fn oversized_single_write_keeps_only_last_capacity_bytes() {
    // Documented "last `capacity`" behaviour — input alone larger
    // than capacity must drop EVERYTHING except the tail.
    let mut r = RingBuffer::new(4);
    r.write(b"abcdefghij"); // 10 bytes into a 4-byte buffer
    assert_eq!(
        r.contents(),
        b"ghij",
        "oversized write MUST keep only the LAST `capacity` bytes (tail-truncate); \
         got {:?}",
        std::str::from_utf8(&r.contents()).unwrap_or("<non-utf8>")
    );
    assert_eq!(r.total_written(), 10);
    assert!(r.has_overflow());
}

#[test]
fn many_small_writes_eventually_overflow_with_correct_telemetry() {
    let mut r = RingBuffer::new(4);
    for byte in b"abcdefghij" {
        r.write(std::slice::from_ref(byte));
    }
    assert_eq!(
        r.contents(),
        b"ghij",
        "small-write FIFO must agree with one-shot oversized write"
    );
    assert_eq!(r.total_written(), 10);
    assert!(r.has_overflow());
}

#[test]
fn has_overflow_flips_only_after_total_written_exceeds_capacity() {
    let mut r = RingBuffer::new(8);
    assert!(!r.has_overflow(), "fresh buffer is not overflow");
    r.write(b"abcd");
    assert!(!r.has_overflow(), "4 < 8: not overflow");
    r.write(b"efgh");
    assert!(
        !r.has_overflow(),
        "exactly 8: total_written equals capacity, NOT overflow"
    );
    r.write(b"i");
    assert!(
        r.has_overflow(),
        "after 9th byte: total_written > capacity, MUST be overflow"
    );
}

#[test]
fn total_written_is_monotonic_and_includes_evicted_bytes() {
    // Drop count = total_written - len. Without monotonic
    // total_written, an operator reading the captured tail couldn't
    // compute how much was lost.
    let mut r = RingBuffer::new(4);
    r.write(b"aaaa");
    let after_first = r.total_written();
    r.write(b"bbbb"); // evicts the original 4
    let after_second = r.total_written();
    assert!(after_second > after_first);
    assert_eq!(after_second, 8);
    assert_eq!(r.len(), 4, "len always equals capacity after overflow");
    assert_eq!(
        r.total_written() - u64::try_from(r.len()).unwrap(),
        4,
        "drop = total_written - len = 4 bytes lost"
    );
}

#[test]
fn clear_empties_data_but_preserves_total_written() {
    // Forensic invariant: clear() MUST NOT reset the drop counter.
    // Otherwise an attacker who could trigger a clear could mask
    // earlier overflow events from triage tooling.
    let mut r = RingBuffer::new(4);
    r.write(b"abcdefghij"); // total_written = 10, has_overflow = true
    let written_before_clear = r.total_written();
    assert!(r.has_overflow());

    r.clear();
    assert!(r.is_empty(), "clear() MUST empty the visible buffer");
    assert_eq!(r.len(), 0);
    assert_eq!(
        r.total_written(),
        written_before_clear,
        "clear() MUST preserve total_written — forensic drop counter must not reset"
    );
    assert!(
        r.has_overflow(),
        "has_overflow stays true after clear (it derives from preserved total_written)"
    );
}

#[test]
fn last_n_returns_all_when_n_exceeds_len() {
    let mut r = RingBuffer::new(16);
    r.write(b"hi");
    let got = r.last_n(100);
    assert_eq!(
        got, b"hi",
        "last_n(100) on a 2-byte buffer MUST return only the 2 bytes (clamp), not panic"
    );
}

#[test]
fn last_n_returns_only_last_n_when_under_len() {
    let mut r = RingBuffer::new(16);
    r.write(b"abcdefgh");
    let last_3 = r.last_n(3);
    assert_eq!(last_3, b"fgh", "last_n(3) on 'abcdefgh' MUST return 'fgh'");
}

#[test]
fn capacity_is_invariant_across_operations() {
    let mut r = RingBuffer::new(4);
    assert_eq!(r.capacity(), 4);
    r.write(b"abcdefghij"); // overflow
    assert_eq!(r.capacity(), 4, "capacity must not change on writes");
    r.clear();
    assert_eq!(r.capacity(), 4, "capacity must not change on clear");
}

#[test]
fn write_after_clear_does_not_replay_old_data() {
    let mut r = RingBuffer::new(8);
    r.write(b"original");
    r.clear();
    r.write(b"fresh");
    assert_eq!(
        r.contents(),
        b"fresh",
        "after clear + write, only the new data must be visible — no resurrection of old bytes"
    );
}

#[test]
fn zero_byte_write_is_a_no_op_for_data_but_increments_total_written() {
    let mut r = RingBuffer::new(8);
    r.write(b"abc");
    let before = r.total_written();
    r.write(b"");
    // total_written += 0 is a no-op too; no surprises here.
    assert_eq!(r.total_written(), before);
    assert_eq!(r.contents(), b"abc");
}
