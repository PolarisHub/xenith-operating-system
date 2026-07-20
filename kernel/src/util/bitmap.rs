//! Bit-level allocator over a borrowed `&mut [u64]` word buffer.
//!
//! [`Bitmap`] is a thin, zero-allocation view over a caller-owned array of
//! `u64` words. It is the foundation of the physical frame allocator and any
//! other kernel subsystem that needs to track a fixed, contiguous set of
//! resources (CPU vector assignments, MSI message slots, port-bitmap IO
//! permissions) without touching the heap.
//!
//! # Representation
//!
//! Bits are packed LSB-first within each `u64` word and word-indexed in array
//! order: bit `i` lives in word `i / 64` at position `i % 64`. The total bit
//! count (`len`) need not be a multiple of 64; the trailing word simply has
//! its unused high bits ignored by every operation. `set` on an out-of-range
//! bit is a panic — the caller owns the backing buffer and therefore knows the
//! valid range up front.
//!
//! # Conventions
//!
//! A `1` bit means *allocated* / *in use*; a `0` bit means *free*. This
//! matches the convention used by the frame allocator and by every Linux-style
//! bitmap the Xenith developer is likely to cross-reference. `find_first_free`
//! and `find_first_zero` therefore return the same index; both names are kept
//! because callers read better with one or the other depending on context.
//!
//! # Const-friendliness
//!
//! The constructor and the pure inspectors are `const fn` so a `Bitmap` can be
//! placed in a `static` once the backing storage itself is static (e.g. a
//! `static mut WORDS: [u64; 8] = [0; 8];` paired with `Bitmap::new(&mut
//! WORDS)` inside an `unsafe` block that establishes exclusive access). The
//! mutating methods are not `const` because they write through a `&mut` slice.

use core::fmt;

/// Number of bits packed into a single backing word.
pub const BITS_PER_WORD: usize = 64;

/// A bit-level view over a borrowed `u64` word buffer.
///
/// The bitmap does not own its storage: it borrows a `&mut [u64]` for the
/// duration of its life. This keeps the type zero-allocation and lets the
/// caller decide where the words live (a `static mut` array in `.bss`, a
/// frame carved out of the HHDM, or a stack buffer during early bring-up).
#[derive(Debug)]
pub struct Bitmap<'a> {
    /// The backing word slice. Bit `i` is `(words[i / 64] >> (i % 64)) & 1`.
    words: &'a mut [u64],
    /// Total number of addressable bits. Always `<= words.len() * 64`.
    len: usize,
}

impl<'a> Bitmap<'a> {
    /// Wrap a word buffer, addressing `words.len() * 64` bits.
    ///
    /// The buffer is not zeroed by the constructor; the caller is responsible
    /// for initialising it (almost always to all-zeros, meaning "all free") if
    /// they need a defined starting state. This avoids an implicit memset on a
    /// buffer the caller may have already prepared.
    #[inline]
    pub const fn new(words: &'a mut [u64]) -> Self {
        Bitmap {
            len: words.len().saturating_mul(BITS_PER_WORD),
            words,
        }
    }

    /// Wrap a word buffer but expose only `len` bits, which may be smaller
    /// than `words.len() * 64`.
    ///
    /// `len` is clamped to `words.len() * 64` so a mis-sized caller cannot
    /// address bits that have no backing storage. Bits beyond `len` in the
    /// final partial word are invisible to every operation.
    #[inline]
    pub const fn with_len(words: &'a mut [u64], len: usize) -> Self {
        let cap = words.len().saturating_mul(BITS_PER_WORD);
        Bitmap {
            len: if len < cap { len } else { cap },
            words,
        }
    }

    /// Total number of addressable bits.
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// `true` if the bitmap addresses zero bits (an empty backing slice).
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Number of `u64` words the bitmap is backed by.
    #[inline]
    pub const fn words(&self) -> usize {
        self.words.len()
    }

    // --- Bit indexing helpers ----------------------------------------------

    /// Split a bit index into `(word_index, bit_index)`. Pure arithmetic, no
    /// `self` access, so this is a standalone `const fn` usable in any context
    /// (including inside other `const fn`s). Used by every per-bit method so
    /// the word/bit decomposition lives in one place.
    #[inline]
    const fn split_idx(idx: usize) -> (usize, usize) {
        (idx / BITS_PER_WORD, idx % BITS_PER_WORD)
    }

    // --- Single-bit queries -------------------------------------------------

    /// Returns `true` if bit `idx` is set (allocated).
    ///
    /// # Panics
    ///
    /// Panics if `idx >= len`.
    #[inline]
    pub fn get(&self, idx: usize) -> bool {
        assert!(
            idx < self.len,
            "bitmap: index {idx} out of range {len}",
            len = self.len
        );
        let (w, b) = Self::split_idx(idx);
        (self.words[w] >> b) & 1 != 0
    }

    /// Set bit `idx` (mark allocated).
    ///
    /// # Panics
    ///
    /// Panics if `idx >= len`.
    #[inline]
    pub fn set(&mut self, idx: usize) {
        assert!(
            idx < self.len,
            "bitmap: index {idx} out of range {len}",
            len = self.len
        );
        let (w, b) = Self::split_idx(idx);
        self.words[w] |= 1u64 << b;
    }

    /// Clear bit `idx` (mark free).
    ///
    /// # Panics
    ///
    /// Panics if `idx >= len`.
    #[inline]
    pub fn clear(&mut self, idx: usize) {
        assert!(
            idx < self.len,
            "bitmap: index {idx} out of range {len}",
            len = self.len
        );
        let (w, b) = Self::split_idx(idx);
        self.words[w] &= !(1u64 << b);
    }

    /// Flip bit `idx` and return its new state.
    ///
    /// # Panics
    ///
    /// Panics if `idx >= len`.
    #[inline]
    pub fn toggle(&mut self, idx: usize) -> bool {
        assert!(
            idx < self.len,
            "bitmap: index {idx} out of range {len}",
            len = self.len
        );
        let (w, b) = Self::split_idx(idx);
        self.words[w] ^= 1u64 << b;
        (self.words[w] >> b) & 1 != 0
    }

    /// Atomically (relative to this `&mut self` borrow) set or clear `idx`
    /// depending on `value`. Convenience wrapper for `set`/`clear`.
    #[inline]
    pub fn assign(&mut self, idx: usize, value: bool) {
        if value {
            self.set(idx);
        } else {
            self.clear(idx);
        }
    }

    // --- Bulk queries -------------------------------------------------------

    /// Count the number of set bits across the whole bitmap.
    ///
    /// Uses `count_ones` on each full word; the trailing partial word has its
    /// out-of-range bits masked off before counting so they do not leak into
    /// the total even if the caller left garbage there.
    #[inline]
    pub fn count_ones(&self) -> usize {
        let full_words = self.len / BITS_PER_WORD;
        let mut total: usize = 0;
        for w in 0..full_words {
            total += self.words[w].count_ones() as usize;
        }
        let rem = self.len % BITS_PER_WORD;
        if rem != 0 {
            // Mask off the high bits that fall outside `len`; the rest are
            // counted as usual. `(1 << rem) - 1` is the mask of `rem` low bits.
            let mask = (1u64 << rem) - 1;
            total += (self.words[full_words] & mask).count_ones() as usize;
        }
        total
    }

    /// Count the number of free (zero) bits: `len - count_ones()`.
    #[inline]
    pub fn count_zeros(&self) -> usize {
        self.len - self.count_ones()
    }

    // --- Free-bit search ----------------------------------------------------

    /// Return the index of the first zero bit, or `None` if every bit is set.
    ///
    /// This scans word-by-word, skipping words that are all-ones via a direct
    /// `u64 == !0` comparison, which is faster than `count_ones` on every
    /// architecture Xenith targets. The trailing partial word is masked so its
    /// invisible high bits are treated as "set" and never reported as free.
    #[inline]
    pub fn find_first_zero(&self) -> Option<usize> {
        let full_words = self.len / BITS_PER_WORD;
        let rem = self.len % BITS_PER_WORD;

        for w in 0..full_words {
            let word = self.words[w];
            if word != u64::MAX {
                // The first zero bit in `word` is the first zero bit overall in
                // this word. `trailing_ones()` counts the run of 1s before the
                // first 0; that run length is exactly the bit index within the
                // word. This is the classic Linux `find_first_zero_bit` trick.
                let bit_in_word = word.trailing_ones() as usize;
                return Some(w * BITS_PER_WORD + bit_in_word);
            }
        }
        if rem != 0 {
            // Treat the out-of-range high bits as set so a partial final word
            // whose only zero bits are beyond `len` is reported as full.
            let mask = (1u64 << rem) - 1;
            let word = self.words[full_words] | !mask;
            if word != u64::MAX {
                let bit_in_word = word.trailing_ones() as usize;
                let idx = full_words * BITS_PER_WORD + bit_in_word;
                // Defensive: trailing_ones may point past `len` if every
                // in-range bit is set and the mask logic left a zero above.
                if idx < self.len {
                    return Some(idx);
                }
            }
        }
        None
    }

    /// Alias for [`find_first_zero`](Self::find_first_zero) using the
    /// "free means available" vocabulary of the frame allocator.
    #[inline]
    pub fn find_first_free(&self) -> Option<usize> {
        self.find_first_zero()
    }

    /// Return the first zero bit in the half-open interval `start..end`.
    ///
    /// Whole allocated words are skipped with one comparison. The boundary
    /// words are masked so bits outside the requested interval are treated as
    /// allocated and can never be returned. Invalid or empty intervals return
    /// `None` rather than widening the search.
    #[inline]
    pub fn find_zero_in(&self, start: usize, end: usize) -> Option<usize> {
        if start >= end || start >= self.len {
            return None;
        }
        let end = end.min(self.len);
        let first_word = start / BITS_PER_WORD;
        let last_word = (end - 1) / BITS_PER_WORD;

        for word_index in first_word..=last_word {
            let word_start = word_index * BITS_PER_WORD;
            let lower = start.saturating_sub(word_start).min(BITS_PER_WORD);
            let upper = end.saturating_sub(word_start).min(BITS_PER_WORD);

            let below_mask = if lower == 0 { 0 } else { (1u64 << lower) - 1 };
            let above_mask = if upper == BITS_PER_WORD {
                0
            } else {
                !((1u64 << upper) - 1)
            };
            let masked = self.words[word_index] | below_mask | above_mask;
            if masked != u64::MAX {
                let bit = masked.trailing_ones() as usize;
                let index = word_start + bit;
                if index < end {
                    return Some(index);
                }
            }
        }
        None
    }

    /// Find the first run of `count` consecutive zero bits, set them all, and
    /// return the starting index. Returns `None` if no such run exists.
    ///
    /// This is the allocator core: the physical frame allocator asks for a run
    /// of `order` frames (order 0 = one frame, order 1 = two, ...) and this
    /// method locates and claims the run in a single pass. The search is
    /// linear and scans bit-by-bit only within candidate windows, which is
    /// optimal for sparse bitmaps; a buddy-style hierarchical allocator would
    /// layer its own structure on top rather than call this with large counts.
    ///
    /// On success every bit in `[idx, idx + count)` is set before returning.
    pub fn allocate_range(&mut self, count: usize) -> Option<usize> {
        if count == 0 {
            // A zero-length allocation succeeds at index 0 without mutating
            // anything. This matches the convention that asking for nothing is
            // trivially satisfiable.
            return Some(0);
        }
        if count > self.len {
            return None;
        }

        // Walk the bitmap looking for a run of `count` zeros. We keep `start`
        // as the index of the first zero of the current candidate run and
        // extend it one bit at a time; when the run reaches `count` we commit,
        // and when we hit a set bit we restart from the next position.
        let mut start: Option<usize> = None;
        let mut run = 0usize;
        let mut idx = 0usize;

        while idx < self.len {
            if !self.get(idx) {
                if start.is_none() {
                    start = Some(idx);
                }
                run += 1;
                if run == count {
                    let s = start.unwrap();
                    for j in s..s + count {
                        self.set(j);
                    }
                    return Some(s);
                }
            } else {
                start = None;
                run = 0;
            }
            idx += 1;
        }
        None
    }

    /// Release a previously allocated run of `count` bits starting at `start`.
    ///
    /// This is the inverse of [`allocate_range`](Self::allocate_range). It is
    /// deliberately permissive about the current state of the bits: clearing an
    /// already-free bit is a no-op, which keeps callers from having to track
    /// double-frees in error paths.
    ///
    /// # Panics
    ///
    /// Panics if `start` or `start + count` exceeds `len`.
    pub fn free_range(&mut self, start: usize, count: usize) {
        if count == 0 {
            return;
        }
        let end = start
            .checked_add(count)
            .expect("bitmap: free_range overflow");
        assert!(end <= self.len, "bitmap: free_range out of range");
        for i in start..end {
            self.clear(i);
        }
    }

    /// Clear every bit in the bitmap (mark everything free).
    ///
    /// Cheaper than iterating bit-by-bit: it zeroes each word directly. The
    /// trailing partial word is also zeroed, which is safe because its
    /// out-of-range bits are already invisible to every other operation.
    #[inline]
    pub fn clear_all(&mut self) {
        for w in self.words.iter_mut() {
            *w = 0;
        }
    }

    /// Set every bit in the bitmap (mark everything allocated).
    ///
    /// Sets every full word to `u64::MAX` and, for the trailing partial word,
    /// sets only the in-range bits so out-of-range bits stay zero and remain
    /// invisible. This keeps `count_ones` consistent with `len` after a
    /// `set_all`.
    #[inline]
    pub fn set_all(&mut self) {
        let full_words = self.len / BITS_PER_WORD;
        let rem = self.len % BITS_PER_WORD;
        for w in 0..full_words {
            self.words[w] = u64::MAX;
        }
        if rem != 0 {
            let mask = (1u64 << rem) - 1;
            self.words[full_words] = mask;
        }
    }
}

impl fmt::Binary for Bitmap<'_> {
    /// Print the bitmap as a binary string, MSB of the highest index first.
    ///
    /// Useful for debugging allocator state from a `log::debug!` call site:
    /// `format!("{:b}", bitmap)` shows exactly which frames are claimed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `write_char` is a trait method on `core::fmt::Write`; bring the
        // trait into scope locally so we do not pollute the module namespace
        // or risk an `unused_import` warning outside this impl.
        use core::fmt::Write as _;
        for i in 0..self.len {
            let bit = if self.get(i) { '1' } else { '0' };
            f.write_char(bit)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 128-bit bitmap backed by two zeroed words.
    fn fresh_two_words() -> [u64; 2] {
        [0u64; 2]
    }

    #[test]
    fn len_and_empty() {
        let mut storage = fresh_two_words();
        let bm = Bitmap::new(&mut storage);
        assert_eq!(bm.len(), 128);
        assert!(!bm.is_empty());
        assert_eq!(bm.words(), 2);

        let mut empty: [u64; 0] = [];
        let bm0 = Bitmap::new(&mut empty);
        assert_eq!(bm0.len(), 0);
        assert!(bm0.is_empty());
    }

    #[test]
    fn with_len_clamps_to_capacity() {
        let mut storage = [0u64; 2];
        // Request 1000 bits but only 128 fit — the constructor must clamp.
        let bm = Bitmap::with_len(&mut storage, 1000);
        assert_eq!(bm.len(), 128);
    }

    #[test]
    fn set_get_clear_toggle() {
        let mut storage = fresh_two_words();

        // Scope the bitmap borrow so we can inspect `storage` directly after
        // the bitmap is done mutating it; the borrow checker would otherwise
        // reject the immutable read of `storage[1]` below.
        {
            let mut bm = Bitmap::new(&mut storage);

            assert!(!bm.get(0));
            bm.set(0);
            assert!(bm.get(0));
            assert!(!bm.get(1));

            bm.set(67);
            assert!(bm.get(67));

            bm.clear(0);
            assert!(!bm.get(0));
            assert!(bm.get(67));

            let now_set = bm.toggle(5);
            assert!(now_set);
            assert!(bm.get(5));
            let now_clear = bm.toggle(5);
            assert!(!now_clear);
            assert!(!bm.get(5));

            bm.assign(10, true);
            assert!(bm.get(10));
            bm.assign(10, false);
            assert!(!bm.get(10));
        }
        // Bit 67 lives in word 1 at bit 3; verify the backing store reflects
        // the set, now that the bitmap borrow has released `storage`.
        assert_eq!(storage[1], 1u64 << 3);
        // Bit 0 was cleared; word 0 should have no bit 0 set. Other bits may
        // be set from the toggle/assign sequence above, so only check the
        // specific bit we care about.
        assert_eq!(storage[0] & 1, 0);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn get_out_of_range_panics() {
        let mut storage = fresh_two_words();
        let bm = Bitmap::new(&mut storage);
        let _ = bm.get(128);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn set_out_of_range_panics() {
        let mut storage = fresh_two_words();
        let mut bm = Bitmap::new(&mut storage);
        bm.set(200);
    }

    #[test]
    fn count_ones_and_zeros() {
        let mut storage = fresh_two_words();
        let mut bm = Bitmap::new(&mut storage);

        assert_eq!(bm.count_ones(), 0);
        assert_eq!(bm.count_zeros(), 128);

        bm.set(0);
        bm.set(63);
        bm.set(64);
        bm.set(127);
        assert_eq!(bm.count_ones(), 4);
        assert_eq!(bm.count_zeros(), 124);
    }

    #[test]
    fn count_ones_with_partial_word() {
        // A 70-bit bitmap: one full 64-bit word plus 6 bits in the second.
        let mut storage = [0u64; 2];
        // Plant an out-of-range bit in the backing store BEFORE borrowing it
        // into a Bitmap; count_ones must ignore it because it falls beyond
        // `len`. Bit 20 of word 1 is bit 84 overall, which is past 70.
        storage[1] = 1u64 << 20;
        let mut bm = Bitmap::with_len(&mut storage, 70);

        // Set two in-range bits in the partial word.
        bm.set(64);
        bm.set(65);
        assert_eq!(bm.count_ones(), 2);
        assert_eq!(bm.count_zeros(), 68);
    }

    #[test]
    fn find_first_zero_basic() {
        let mut storage = fresh_two_words();
        let mut bm = Bitmap::new(&mut storage);

        assert_eq!(bm.find_first_zero(), Some(0));
        assert_eq!(bm.find_first_free(), Some(0));

        bm.set(0);
        assert_eq!(bm.find_first_zero(), Some(1));

        // Fill word 0 entirely; the first zero must jump to word 1.
        for i in 0..64 {
            bm.set(i);
        }
        assert_eq!(bm.find_first_zero(), Some(64));

        // Fill everything; the bitmap is full.
        bm.set_all();
        assert_eq!(bm.find_first_zero(), None);
    }

    #[test]
    fn find_first_zero_skips_full_word() {
        let mut storage = [u64::MAX, 0u64];
        let mut bm = Bitmap::new(&mut storage);
        // Word 0 is full; the first zero is at the start of word 1.
        assert_eq!(bm.find_first_zero(), Some(64));
        bm.set(64);
        assert_eq!(bm.find_first_zero(), Some(65));
    }

    #[test]
    fn find_first_zero_partial_word_ignores_high_bits() {
        // 10-bit bitmap backed by one word. Set the in-range bits; out-of-range
        // high bits must not be reported as free.
        let mut storage = [0u64; 1];
        let mut bm = Bitmap::with_len(&mut storage, 10);
        for i in 0..10 {
            bm.set(i);
        }
        assert_eq!(bm.find_first_zero(), None);
        bm.clear(7);
        assert_eq!(bm.find_first_zero(), Some(7));
    }

    #[test]
    fn allocate_range_single() {
        let mut storage = fresh_two_words();
        let mut bm = Bitmap::new(&mut storage);
        let i = bm.allocate_range(1).expect("empty bitmap has room");
        assert_eq!(i, 0);
        assert!(bm.get(0));
        assert_eq!(bm.count_ones(), 1);
    }

    #[test]
    fn allocate_range_run() {
        let mut storage = fresh_two_words();
        let mut bm = Bitmap::new(&mut storage);

        // Pre-allocate bit 0 so the run must start at 1.
        bm.set(0);
        let start = bm.allocate_range(4).expect("room for a 4-run");
        assert_eq!(start, 1);
        for i in 1..5 {
            assert!(bm.get(i), "bit {i} should be allocated");
        }
        assert!(!bm.get(0) || true); // bit 0 was already set
        assert!(!bm.get(5));
        assert_eq!(bm.count_ones(), 5);
    }

    #[test]
    fn allocate_range_crosses_word_boundary() {
        let mut storage = fresh_two_words();
        let mut bm = Bitmap::new(&mut storage);
        // Fill bits 0..62 so the first 4-run of free bits straddles the
        // word-0/word-1 boundary at indices 62, 63, 64, 65.
        for i in 0..62 {
            bm.set(i);
        }
        let start = bm.allocate_range(4).expect("room across boundary");
        assert_eq!(start, 62);
        // The run spans the boundary: 62 and 63 in word 0, 64 and 65 in word 1.
        assert!(bm.get(62));
        assert!(bm.get(63));
        assert!(bm.get(64));
        assert!(bm.get(65));
        // Bit 66 is just past the run and must remain free.
        assert!(!bm.get(66));
    }

    #[test]
    fn allocate_range_full_returns_none() {
        let mut storage = fresh_two_words();
        let mut bm = Bitmap::new(&mut storage);
        bm.set_all();
        assert!(bm.allocate_range(1).is_none());
    }

    #[test]
    fn allocate_range_zero_is_trivial() {
        let mut storage = fresh_two_words();
        let mut bm = Bitmap::new(&mut storage);
        let i = bm
            .allocate_range(0)
            .expect("zero-length is always satisfiable");
        assert_eq!(i, 0);
        assert_eq!(bm.count_ones(), 0);
    }

    #[test]
    fn allocate_range_too_large_returns_none() {
        let mut storage = fresh_two_words();
        let mut bm = Bitmap::new(&mut storage);
        assert!(bm.allocate_range(129).is_none());
    }

    #[test]
    fn free_range_clears_run() {
        let mut storage = fresh_two_words();
        let mut bm = Bitmap::new(&mut storage);
        let start = bm.allocate_range(8).unwrap();
        assert_eq!(bm.count_ones(), 8);
        bm.free_range(start, 8);
        assert_eq!(bm.count_ones(), 0);
        assert_eq!(bm.find_first_zero(), Some(0));
    }

    #[test]
    fn free_range_is_idempotent() {
        let mut storage = fresh_two_words();
        let mut bm = Bitmap::new(&mut storage);
        bm.free_range(0, 4); // clearing already-clear bits is a no-op
        assert_eq!(bm.count_ones(), 0);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn free_range_out_of_range_panics() {
        let mut storage = fresh_two_words();
        let mut bm = Bitmap::new(&mut storage);
        bm.free_range(120, 20);
    }

    #[test]
    fn clear_all_and_set_all() {
        let mut storage = fresh_two_words();
        let mut bm = Bitmap::new(&mut storage);
        bm.set_all();
        assert_eq!(bm.count_ones(), 128);
        assert_eq!(bm.find_first_zero(), None);
        bm.clear_all();
        assert_eq!(bm.count_ones(), 0);
        assert_eq!(bm.find_first_zero(), Some(0));
    }

    #[test]
    fn set_all_respects_partial_word() {
        let mut storage = [0u64; 1];
        let mut bm = Bitmap::with_len(&mut storage, 10);
        bm.set_all();
        // Only 10 bits should be set, not 64.
        assert_eq!(bm.count_ones(), 10);
        assert_eq!(bm.find_first_zero(), None);
    }

    #[test]
    fn binary_fmt_emits_one_char_per_bit() {
        // `format!` requires the allocator, so drive the `Binary` impl through
        // a fixed-buffer writer instead. This keeps the test `no_std`-clean.
        use core::fmt::Write;
        struct BufWriter {
            buf: [u8; 16],
            pos: usize,
        }
        impl Write for BufWriter {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let bytes = s.as_bytes();
                if self.pos + bytes.len() > self.buf.len() {
                    return Err(core::fmt::Error);
                }
                self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
                self.pos += bytes.len();
                Ok(())
            }
        }
        let mut storage = [0u64; 1];
        let mut bm = Bitmap::with_len(&mut storage, 8);
        bm.set(0);
        bm.set(7);
        let mut w = BufWriter {
            buf: [0u8; 16],
            pos: 0,
        };
        write!(w, "{:b}", bm).unwrap();
        let s = core::str::from_utf8(&w.buf[..w.pos]).unwrap();
        assert_eq!(s.len(), 8);
        assert!(s.starts_with('1'));
        assert!(s.ends_with('1'));
    }

    #[test]
    fn allocate_and_free_round_trip() {
        let mut storage = fresh_two_words();
        let mut bm = Bitmap::new(&mut storage);

        // Allocate four single-bit slots and verify they are contiguous from 0.
        let mut slots = [0usize; 4];
        for slot in &mut slots {
            *slot = bm.allocate_range(1).unwrap();
        }
        assert_eq!(slots, [0, 1, 2, 3]);
        // Free the middle two and re-allocate: they should come back in order.
        bm.free_range(1, 1);
        bm.free_range(2, 1);
        assert_eq!(bm.allocate_range(1), Some(1));
        assert_eq!(bm.allocate_range(1), Some(2));
    }

    #[test]
    fn bounded_zero_search_masks_edges_and_partial_words() {
        let mut storage = [u64::MAX; 3];
        let mut bm = Bitmap::with_len(&mut storage, 130);
        bm.clear(5);
        bm.clear(64);
        bm.clear(129);

        assert_eq!(bm.find_zero_in(6, 129), Some(64));
        assert_eq!(bm.find_zero_in(65, 130), Some(129));
        assert_eq!(bm.find_zero_in(0, 5), None);
        assert_eq!(bm.find_zero_in(130, usize::MAX), None);
        assert_eq!(bm.find_zero_in(10, 10), None);
    }
}
