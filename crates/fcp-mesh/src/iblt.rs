//! Production IBLT support for bounded mesh set reconciliation.
//!
//! The mesh gossip layer needs a compact way to describe small set differences
//! without exchanging full object inventories. An Invertible Bloom Lookup Table
//! (IBLT) provides O(d) communication in the common case where two nodes differ
//! by only a handful of objects.

pub mod layered_filter;
pub mod masked;

use std::collections::{BTreeSet, VecDeque};

use fcp_prelude::ObjectId;
use serde::{Deserialize, Serialize};

pub use layered_filter::{LayeredFilterConfig, LayeredReconciliationFilter};
pub use masked::{IbltMask, MaskedIblt, MaskedIbltError};

/// The production IBLT uses three independent hash positions per key.
pub const IBLT_HASH_COUNT: usize = 3;

/// Recommended minimum cell budget for production reconciliation.
pub const MIN_RECOMMENDED_IBLT_CELLS: usize = 64;

const INDEX_HASH_DOMAINS: [&[u8]; IBLT_HASH_COUNT] =
    [b"fcp-iblt-h0", b"fcp-iblt-h1", b"fcp-iblt-h2"];
const HASH_CHECK_DOMAIN: &[u8] = b"fcp-iblt-hc";

/// A single IBLT cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct IbltCell {
    /// Signed item count accumulated in this cell.
    pub count: i32,
    /// XOR of all keys hashed into this cell.
    pub key_sum: [u8; 32],
    /// XOR of 32-bit hash checks for all keys hashed into this cell.
    pub hash_check: u32,
}

impl IbltCell {
    fn apply(&mut self, object_id: ObjectId, delta: i32) {
        // Saturating: `count` is `Deserialize`, so a peer can transmit any
        // `i32` and drive this toward the bounds. A wrapping `+=` panics in
        // debug builds (overflow) and silently corrupts the count in release.
        // A saturated count can never equal ±1, so `pure_key` simply ignores
        // the cell — same defensive stance as `pure_key` (see below).
        self.count = self.count.saturating_add(delta);
        xor_into(&mut self.key_sum, object_id.as_bytes());
        self.hash_check ^= hash_check_for(object_id);
    }

    fn subtract(&self, other: &Self) -> Self {
        let mut key_sum = self.key_sum;
        xor_into(&mut key_sum, &other.key_sum);
        Self {
            // Saturating for the same reason as `apply`: `other.count` is
            // attacker-controlled, so `0 - i32::MIN` must not overflow.
            count: self.count.saturating_sub(other.count),
            key_sum,
            hash_check: self.hash_check ^ other.hash_check,
        }
    }

    fn is_zero(&self) -> bool {
        self.count == 0 && self.key_sum == [0_u8; 32] && self.hash_check == 0
    }

    fn pure_key(&self) -> Option<(ObjectId, i32)> {
        // Compare against ±1 directly rather than `count.abs() != 1`:
        // `i32::MIN.abs()` panics in debug builds (overflow), and `IbltCell`
        // is `Deserialize`, so a peer can transmit `count: i32::MIN` and
        // crash any node that decodes the gossiped sketch.
        if self.count != 1 && self.count != -1 {
            return None;
        }

        let object_id = ObjectId::from_bytes(self.key_sum);
        if self.hash_check == hash_check_for(object_id) {
            Some((object_id, self.count.signum()))
        } else {
            None
        }
    }
}

/// Errors returned by production IBLT operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IbltError {
    /// Cell count must be at least `IBLT_HASH_COUNT` (3).
    #[error("iblt cell count must be at least 3 (IBLT_HASH_COUNT), got {got}")]
    InvalidCellCount {
        /// The invalid cell count that was provided.
        got: usize,
    },
    /// Two sketches must use the same cell budget before subtraction.
    #[error("iblt cell count mismatch: left={left}, right={right}")]
    CellCountMismatch { left: usize, right: usize },
}

/// Result of decoding an IBLT difference sketch.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IbltDecodeResult {
    /// Objects present only in the left-hand sketch.
    pub only_left: BTreeSet<ObjectId>,
    /// Objects present only in the right-hand sketch.
    pub only_right: BTreeSet<ObjectId>,
    /// `true` when the sketch peeled completely.
    pub complete: bool,
    /// Non-zero cells left over after peeling stalled.
    pub remaining_nonzero_cells: usize,
}

impl IbltDecodeResult {
    /// Whether the decode finished without requiring a fallback exchange.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }
}

/// Production IBLT for mesh object reconciliation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Iblt {
    cells: Vec<IbltCell>,
}

impl Default for Iblt {
    fn default() -> Self {
        Self::with_expected_difference(0)
    }
}

impl Iblt {
    /// Build an IBLT sized for an expected difference set.
    ///
    /// # Panics
    ///
    /// Panics if the recommended cell count for the given difference is zero.
    #[must_use]
    pub fn with_expected_difference(expected_difference: usize) -> Self {
        Self::with_cell_count(Self::recommended_cell_count(expected_difference))
            .expect("recommended IBLT cell count must be non-zero")
    }

    /// Build an IBLT with an explicit cell count.
    ///
    /// The cell count must be at least [`IBLT_HASH_COUNT`] (3). Smaller values
    /// cause [`Self::indices_for`] to silently produce duplicate hash positions,
    /// which breaks the peeling invariant — a single insert would apply to the
    /// same cell multiple times and decode would not recover.
    ///
    /// # Errors
    /// Returns [`IbltError::InvalidCellCount`] when `cell_count < IBLT_HASH_COUNT`.
    pub fn with_cell_count(cell_count: usize) -> Result<Self, IbltError> {
        if cell_count < IBLT_HASH_COUNT {
            return Err(IbltError::InvalidCellCount { got: cell_count });
        }

        Ok(Self {
            cells: vec![IbltCell::default(); cell_count],
        })
    }

    /// Recommended cell budget for an expected difference size.
    #[must_use]
    pub const fn recommended_cell_count(expected_difference: usize) -> usize {
        let scaled = expected_difference.saturating_mul(3).saturating_add(1) / 2;
        if scaled < MIN_RECOMMENDED_IBLT_CELLS {
            MIN_RECOMMENDED_IBLT_CELLS
        } else {
            scaled
        }
    }

    /// Number of cells in the sketch.
    #[must_use]
    pub fn cell_count(&self) -> usize {
        self.cells.len()
    }

    /// Borrow the raw cell slice.
    #[must_use]
    pub fn cells(&self) -> &[IbltCell] {
        &self.cells
    }

    /// Insert an object into the sketch.
    pub fn insert(&mut self, object_id: ObjectId) {
        self.apply(object_id, 1);
    }

    /// Delete an object from the sketch.
    pub fn delete(&mut self, object_id: ObjectId) {
        self.apply(object_id, -1);
    }

    /// Subtract `other` from `self` to form an A-B difference sketch.
    ///
    /// # Errors
    /// Returns [`IbltError::CellCountMismatch`] when the sketches use different
    /// cell budgets.
    pub fn subtract(&self, other: &Self) -> Result<Self, IbltError> {
        if self.cells.len() != other.cells.len() {
            return Err(IbltError::CellCountMismatch {
                left: self.cells.len(),
                right: other.cells.len(),
            });
        }

        let cells = self
            .cells
            .iter()
            .zip(&other.cells)
            .map(|(left, right)| left.subtract(right))
            .collect();
        Ok(Self { cells })
    }

    /// Decode the sketch by repeatedly peeling pure cells.
    pub fn decode(&self) -> IbltDecodeResult {
        let mut working = self.cells.clone();
        let mut pending = VecDeque::new();
        let mut only_left = BTreeSet::new();
        let mut only_right = BTreeSet::new();

        for (index, cell) in working.iter().enumerate() {
            if cell.pure_key().is_some() {
                pending.push_back(index);
            }
        }

        // Bound the peel loop. A legitimate difference sketch peels each of its
        // items once (touching `IBLT_HASH_COUNT` cells apiece), so a clean
        // decode performs O(cells) pops. An *inconsistent* sketch, which a
        // hostile peer can craft — `subtract` runs on attacker-controlled peer
        // cells and the `ReconcileRequest` carrying them is not content-signed —
        // can oscillate forever: peeling one cell re-purifies its neighbours,
        // which re-purify it, so `pending` never drains and a core pins at 100%.
        // The cap is comfortably above any real decode (which needs < 4×cells
        // pops); exceeding it means the sketch is undecodable, correctly
        // surfaced as `complete == false` so callers fall back to list exchange.
        let max_pops = working
            .len()
            .saturating_mul(IBLT_HASH_COUNT)
            .saturating_add(working.len());
        let mut pops = 0_usize;

        while let Some(index) = pending.pop_front() {
            if pops >= max_pops {
                break;
            }
            pops += 1;

            let Some((object_id, sign)) = working[index].pure_key() else {
                continue;
            };

            if sign > 0 {
                only_left.insert(object_id);
            } else {
                only_right.insert(object_id);
            }

            for peer_index in Self::indices_for(object_id, working.len()) {
                working[peer_index].apply(object_id, -sign);
                if working[peer_index].pure_key().is_some() {
                    pending.push_back(peer_index);
                }
            }
        }

        let remaining_nonzero_cells = working.iter().filter(|cell| !cell.is_zero()).count();

        IbltDecodeResult {
            only_left,
            only_right,
            complete: remaining_nonzero_cells == 0,
            remaining_nonzero_cells,
        }
    }

    fn apply(&mut self, object_id: ObjectId, delta: i32) {
        for index in Self::indices_for(object_id, self.cells.len()) {
            self.cells[index].apply(object_id, delta);
        }
    }

    fn indices_for(object_id: ObjectId, cell_count: usize) -> [usize; IBLT_HASH_COUNT] {
        let mut indices = [0_usize; IBLT_HASH_COUNT];

        for (position, domain) in INDEX_HASH_DOMAINS.iter().enumerate() {
            let mut index = hash_index(domain, object_id.as_bytes(), cell_count);
            let mut steps = 0;
            while steps < cell_count && indices[..position].contains(&index) {
                index = (index + 1) % cell_count;
                steps += 1;
            }
            indices[position] = index;
        }

        indices
    }
}

fn hash_index(domain: &[u8], key: &[u8; 32], cell_count: usize) -> usize {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(key);
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&digest.as_bytes()[..8]);
    let value = u64::from_le_bytes(bytes);
    (value % u64::try_from(cell_count).expect("cell count fits into u64")) as usize
}

fn hash_check_for(object_id: ObjectId) -> u32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(HASH_CHECK_DOMAIN);
    hasher.update(object_id.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 4];
    bytes.copy_from_slice(&digest.as_bytes()[..4]);
    u32::from_le_bytes(bytes)
}

fn xor_into(target: &mut [u8; 32], value: &[u8; 32]) {
    for (target_byte, value_byte) in target.iter_mut().zip(value) {
        *target_byte ^= value_byte;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object_id(label: &str) -> ObjectId {
        ObjectId::from_unscoped_bytes(label.as_bytes())
    }

    #[test]
    fn recommended_cell_count_uses_floor_and_growth_factor() {
        assert_eq!(Iblt::recommended_cell_count(0), MIN_RECOMMENDED_IBLT_CELLS);
        assert_eq!(Iblt::recommended_cell_count(1), MIN_RECOMMENDED_IBLT_CELLS);
        assert_eq!(Iblt::recommended_cell_count(50), 75);
    }

    #[test]
    fn subtract_rejects_mismatched_cell_counts() {
        let left = Iblt::with_cell_count(64).expect("valid left cell count");
        let right = Iblt::with_cell_count(65).expect("valid right cell count");
        let error = left
            .subtract(&right)
            .expect_err("mismatched cell counts must fail");
        assert_eq!(
            error,
            IbltError::CellCountMismatch {
                left: 64,
                right: 65
            }
        );
    }

    #[test]
    fn subtract_and_decode_recovers_bidirectional_difference() {
        let mut left = Iblt::with_expected_difference(4);
        let mut right = Iblt::with_expected_difference(4);

        let shared_a = object_id("shared-a");
        let shared_b = object_id("shared-b");
        let left_only = object_id("left-only");
        let right_only = object_id("right-only");

        for object_id in [shared_a, shared_b, left_only] {
            left.insert(object_id);
        }
        for object_id in [shared_a, shared_b, right_only] {
            right.insert(object_id);
        }

        let difference = left.subtract(&right).expect("same-sized sketches subtract");
        let decoded = difference.decode();

        assert!(decoded.is_complete(), "well-sized sketch should peel fully");
        assert_eq!(decoded.remaining_nonzero_cells, 0);
        assert_eq!(decoded.only_left, BTreeSet::from([left_only]));
        assert_eq!(decoded.only_right, BTreeSet::from([right_only]));
    }

    #[test]
    fn delete_cancels_insert_for_same_object() {
        let mut iblt = Iblt::with_expected_difference(2);
        let object_id = object_id("same-object");

        iblt.insert(object_id);
        iblt.delete(object_id);

        let decoded = iblt.decode();
        assert!(decoded.is_complete());
        assert!(decoded.only_left.is_empty());
        assert!(decoded.only_right.is_empty());
        assert_eq!(decoded.remaining_nonzero_cells, 0);
    }

    #[test]
    fn decode_reports_partial_when_no_pure_cells_exist() {
        let first = object_id("first");
        let second = object_id("second");

        let mut key_sum = *first.as_bytes();
        xor_into(&mut key_sum, second.as_bytes());

        let iblt = Iblt {
            cells: vec![
                IbltCell {
                    count: 2,
                    key_sum,
                    hash_check: hash_check_for(first) ^ hash_check_for(second),
                },
                IbltCell::default(),
                IbltCell::default(),
            ],
        };

        let decoded = iblt.decode();
        assert!(!decoded.is_complete(), "decoder must signal a fallback");
        assert_eq!(decoded.remaining_nonzero_cells, 1);
        assert!(decoded.only_left.is_empty());
        assert!(decoded.only_right.is_empty());
    }

    #[test]
    fn explicit_zero_cell_count_is_rejected() {
        let error = Iblt::with_cell_count(0).expect_err("zero cells must be rejected");
        assert_eq!(error, IbltError::InvalidCellCount { got: 0 });
    }

    #[test]
    fn cell_count_below_hash_count_is_rejected() {
        // Cell counts 1 and 2 would cause indices_for() to silently return
        // duplicate hash positions, breaking the peeling invariant.
        for bad in 1..IBLT_HASH_COUNT {
            let error = Iblt::with_cell_count(bad)
                .expect_err("cell counts below IBLT_HASH_COUNT must be rejected");
            assert_eq!(error, IbltError::InvalidCellCount { got: bad });
        }
    }

    #[test]
    fn decode_does_not_panic_on_extreme_attacker_supplied_count() {
        // Regression: `IbltCell` is Deserialize, so a malicious peer can
        // transmit `count: i32::MIN`. The decoder previously called
        // `count.abs()` inside `pure_key`, which panics in debug builds
        // (i32::MIN cannot be negated). After the fix, decoding such a
        // sketch must complete without panicking and report it as a
        // non-pure cell that prevents complete peeling.
        let iblt = Iblt {
            cells: vec![
                IbltCell {
                    count: i32::MIN,
                    key_sum: [0xff_u8; 32],
                    hash_check: 0xdead_beef,
                },
                IbltCell::default(),
                IbltCell::default(),
            ],
        };

        let decoded = iblt.decode();
        assert!(!decoded.is_complete());
        assert!(decoded.only_left.is_empty());
        assert!(decoded.only_right.is_empty());
        assert_eq!(decoded.remaining_nonzero_cells, 1);

        // i32::MAX must also be accepted as a non-pure count.
        let iblt_max = Iblt {
            cells: vec![
                IbltCell {
                    count: i32::MAX,
                    key_sum: [0x01_u8; 32],
                    hash_check: 0,
                },
                IbltCell::default(),
                IbltCell::default(),
            ],
        };
        let decoded_max = iblt_max.decode();
        assert!(!decoded_max.is_complete());
        assert_eq!(decoded_max.remaining_nonzero_cells, 1);
    }

    #[test]
    fn decode_terminates_on_inconsistent_oscillating_sketch() {
        // Regression (CPU-exhaustion DoS): a hostile peer can craft a sketch
        // whose cells correspond to no real set. Here a single cell claims
        // object X as a pure (+1) entry while the other two cells X hashes to
        // stay empty. Peeling X from the pure cell re-purifies its two
        // neighbours; peeling those re-purifies the first — an infinite cycle
        // with counts trapped in {-1, 0, +1}. Without the peel-loop bound this
        // `decode()` never returns and pins a core at 100% CPU. It must instead
        // terminate and report the sketch as undecodable so the caller falls
        // back to a paginated list exchange.
        let cell_count = 64;
        let mut sketch = Iblt::with_cell_count(cell_count).expect("valid cell count");
        let x = object_id("oscillator-target");
        let indices = Iblt::indices_for(x, cell_count);
        sketch.cells[indices[0]] = IbltCell {
            count: 1,
            key_sum: *x.as_bytes(),
            hash_check: hash_check_for(x),
        };

        // The assertion is secondary — the load-bearing property is that this
        // call *returns at all*. A regression would hang the test (and the
        // node) forever.
        let decoded = sketch.decode();
        assert!(
            !decoded.is_complete(),
            "an inconsistent oscillating sketch must decode as incomplete"
        );
    }

    #[test]
    fn cell_arithmetic_saturates_on_extreme_attacker_count() {
        // Regression: `IbltCell::{subtract, apply}` are reached with
        // attacker-controlled `count` values via the reconcile path. Wrapping
        // arithmetic panics in debug (`0 - i32::MIN`, `i32::MAX + 1`) and
        // silently corrupts in release; saturating arithmetic keeps both total
        // and the result out of the ±1 pure range.
        let local = IbltCell::default();
        let hostile = IbltCell {
            count: i32::MIN,
            key_sum: [7_u8; 32],
            hash_check: 9,
        };
        let diff = local.subtract(&hostile);
        assert_eq!(
            diff.count,
            i32::MAX,
            "0 - i32::MIN must saturate to i32::MAX"
        );
        assert!(diff.pure_key().is_none());

        let mut cell = IbltCell {
            count: i32::MAX,
            key_sum: [0_u8; 32],
            hash_check: 0,
        };
        cell.apply(object_id("apply-extreme"), 1);
        assert_eq!(cell.count, i32::MAX, "i32::MAX + 1 must saturate");
    }

    #[test]
    fn cell_count_equal_to_hash_count_is_accepted() {
        // The smallest valid IBLT has exactly IBLT_HASH_COUNT cells; with
        // distinct hash positions, insert/decode still works.
        let mut iblt = Iblt::with_cell_count(IBLT_HASH_COUNT).expect("IBLT_HASH_COUNT is valid");
        let obj = object_id("min-cell-iblt");
        iblt.insert(obj);
        let decoded = iblt.decode();
        assert!(decoded.is_complete());
        assert_eq!(decoded.only_left, BTreeSet::from([obj]));
    }
}
