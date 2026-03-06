// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Bitmap operations.
//!
//! Fixed-size bitmaps for tracking resource allocation (CPUs,
//! IRQs, pages, etc.). Supports per-bit set/clear/test, bulk
//! logical operations, population count, and first-bit search.
//!
//! # Design
//!
//! ```text
//!   Bitmap (256 bits = 4 × u64 words)
//!   +--------+--------+--------+--------+
//!   | word[0]| word[1]| word[2]| word[3]|
//!   +--------+--------+--------+--------+
//!   bits 0-63  64-127  128-191  192-255
//! ```
//!
//! # Reference
//!
//! Linux `include/linux/bitmap.h`,
//! `lib/bitmap.c`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Number of bits per bitmap.
const BITMAP_BITS: usize = 256;

/// Number of u64 words.
const BITMAP_WORDS: usize = BITMAP_BITS / 64;

/// Bits per word.
const BITS_PER_WORD: usize = 64;

/// Maximum managed bitmaps.
const MAX_BITMAPS: usize = 128;

// ======================================================================
// Bitmap
// ======================================================================

/// Fixed-size bitmap (256 bits).
pub struct Bitmap {
    /// Backing words.
    words: [u64; BITMAP_WORDS],
}

impl Bitmap {
    /// Creates a new all-zeros bitmap.
    pub const fn new() -> Self {
        Self {
            words: [0u64; BITMAP_WORDS],
        }
    }

    /// Creates a new all-ones bitmap.
    pub const fn full() -> Self {
        Self {
            words: [u64::MAX; BITMAP_WORDS],
        }
    }

    /// Sets a bit.
    pub fn set_bit(&mut self, bit: usize) -> Result<()> {
        if bit >= BITMAP_BITS {
            return Err(Error::InvalidArgument);
        }
        let word = bit / BITS_PER_WORD;
        let offset = bit % BITS_PER_WORD;
        self.words[word] |= 1u64 << offset;
        Ok(())
    }

    /// Clears a bit.
    pub fn clear_bit(&mut self, bit: usize) -> Result<()> {
        if bit >= BITMAP_BITS {
            return Err(Error::InvalidArgument);
        }
        let word = bit / BITS_PER_WORD;
        let offset = bit % BITS_PER_WORD;
        self.words[word] &= !(1u64 << offset);
        Ok(())
    }

    /// Tests whether a bit is set.
    pub fn test_bit(&self, bit: usize) -> Result<bool> {
        if bit >= BITMAP_BITS {
            return Err(Error::InvalidArgument);
        }
        let word = bit / BITS_PER_WORD;
        let offset = bit % BITS_PER_WORD;
        Ok((self.words[word] >> offset) & 1 != 0)
    }

    /// Finds the first set bit.
    ///
    /// Returns `None` if no bits are set.
    pub fn find_first_bit(&self) -> Option<usize> {
        for (i, &w) in self.words.iter().enumerate() {
            if w != 0 {
                return Some(i * BITS_PER_WORD + w.trailing_zeros() as usize);
            }
        }
        None
    }

    /// Finds the first zero (clear) bit.
    ///
    /// Returns `None` if all bits are set.
    pub fn find_first_zero_bit(&self) -> Option<usize> {
        for (i, &w) in self.words.iter().enumerate() {
            if w != u64::MAX {
                let bit = i * BITS_PER_WORD + (!w).trailing_zeros() as usize;
                if bit < BITMAP_BITS {
                    return Some(bit);
                }
            }
        }
        None
    }

    /// Finds the next set bit at or after `start`.
    pub fn find_next_bit(&self, start: usize) -> Option<usize> {
        if start >= BITMAP_BITS {
            return None;
        }
        let word_idx = start / BITS_PER_WORD;
        let bit_off = start % BITS_PER_WORD;

        // Check remainder of the first word.
        let masked = self.words[word_idx] >> bit_off;
        if masked != 0 {
            return Some(start + masked.trailing_zeros() as usize);
        }

        // Check subsequent words.
        for i in (word_idx + 1)..BITMAP_WORDS {
            if self.words[i] != 0 {
                let bit = i * BITS_PER_WORD + self.words[i].trailing_zeros() as usize;
                if bit < BITMAP_BITS {
                    return Some(bit);
                }
            }
        }
        None
    }

    /// Bitwise AND with another bitmap (in place).
    pub fn bitmap_and(&mut self, other: &Bitmap) {
        for i in 0..BITMAP_WORDS {
            self.words[i] &= other.words[i];
        }
    }

    /// Bitwise OR with another bitmap (in place).
    pub fn bitmap_or(&mut self, other: &Bitmap) {
        for i in 0..BITMAP_WORDS {
            self.words[i] |= other.words[i];
        }
    }

    /// Bitwise XOR with another bitmap (in place).
    pub fn bitmap_xor(&mut self, other: &Bitmap) {
        for i in 0..BITMAP_WORDS {
            self.words[i] ^= other.words[i];
        }
    }

    /// Returns the population count (number of set bits).
    pub fn bitmap_weight(&self) -> u32 {
        let mut count = 0u32;
        for &w in &self.words {
            count += w.count_ones();
        }
        count
    }

    /// Returns whether all bits are set.
    pub fn bitmap_full(&self) -> bool {
        self.words.iter().all(|&w| w == u64::MAX)
    }

    /// Returns whether all bits are clear.
    pub fn bitmap_empty(&self) -> bool {
        self.words.iter().all(|&w| w == 0)
    }

    /// Clears all bits.
    pub fn clear_all(&mut self) {
        for w in &mut self.words {
            *w = 0;
        }
    }

    /// Sets all bits.
    pub fn set_all(&mut self) {
        for w in &mut self.words {
            *w = u64::MAX;
        }
    }

    /// Returns the total number of bits.
    pub fn nbits(&self) -> usize {
        BITMAP_BITS
    }

    /// Returns a reference to the backing words.
    pub fn words(&self) -> &[u64; BITMAP_WORDS] {
        &self.words
    }

    /// Compares two bitmaps for equality.
    pub fn bitmap_equal(&self, other: &Bitmap) -> bool {
        self.words == other.words
    }

    /// Inverts all bits (bitwise NOT).
    pub fn bitmap_complement(&mut self) {
        for w in &mut self.words {
            *w = !*w;
        }
    }
}

// ======================================================================
// BitmapTable — global registry
// ======================================================================

/// Global table of bitmaps.
pub struct BitmapTable {
    /// Entries.
    entries: [BitmapEntry; MAX_BITMAPS],
    /// Number of allocated bitmaps.
    count: usize,
}

/// Entry in the bitmap table.
struct BitmapEntry {
    /// The bitmap.
    bm: Bitmap,
    /// Whether allocated.
    allocated: bool,
    /// Name (debugging).
    name: [u8; 32],
    /// Name length.
    name_len: usize,
}

impl BitmapEntry {
    const fn new() -> Self {
        Self {
            bm: Bitmap::new(),
            allocated: false,
            name: [0u8; 32],
            name_len: 0,
        }
    }
}

impl BitmapTable {
    /// Creates a new empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { BitmapEntry::new() }; MAX_BITMAPS],
            count: 0,
        }
    }

    /// Allocates a new bitmap.
    pub fn alloc(&mut self, name: &[u8]) -> Result<usize> {
        if self.count >= MAX_BITMAPS {
            return Err(Error::OutOfMemory);
        }
        let idx = self
            .entries
            .iter()
            .position(|e| !e.allocated)
            .ok_or(Error::OutOfMemory)?;
        self.entries[idx].allocated = true;
        self.entries[idx].bm = Bitmap::new();
        let copy_len = name.len().min(32);
        self.entries[idx].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.entries[idx].name_len = copy_len;
        self.count += 1;
        Ok(idx)
    }

    /// Frees a bitmap by index.
    pub fn free(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_BITMAPS || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        self.entries[idx] = BitmapEntry::new();
        self.count -= 1;
        Ok(())
    }

    /// Returns a reference to the bitmap at `idx`.
    pub fn get(&self, idx: usize) -> Result<&Bitmap> {
        if idx >= MAX_BITMAPS || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&self.entries[idx].bm)
    }

    /// Returns a mutable reference to the bitmap at `idx`.
    pub fn get_mut(&mut self, idx: usize) -> Result<&mut Bitmap> {
        if idx >= MAX_BITMAPS || !self.entries[idx].allocated {
            return Err(Error::NotFound);
        }
        Ok(&mut self.entries[idx].bm)
    }

    /// Returns the number of allocated bitmaps.
    pub fn count(&self) -> usize {
        self.count
    }
}
