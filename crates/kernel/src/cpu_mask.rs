// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU bitmask operations.
//!
//! [`CpuMask`] is a fixed-size bitmask supporting up to 256 CPUs,
//! stored as `[u64; 4]`. It provides set/clear/test operations and
//! bitwise combinators for efficient CPU set management.
//!
//! Used by the scheduler, IRQ affinity, workqueue, and RCU
//! subsystems to express which CPUs participate in an operation.
//!
//! # Representation
//!
//! ```text
//! CpuMask([u64; 4])
//!   bits[0]: CPUs   0..63
//!   bits[1]: CPUs  64..127
//!   bits[2]: CPUs 128..191
//!   bits[3]: CPUs 192..255
//! ```
//!
//! # Reference
//!
//! Linux `include/linux/cpumask.h`, `lib/cpumask.c`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────

/// Maximum number of CPUs supported.
pub const MAX_CPUS: usize = 256;

/// Number of u64 words in the mask.
const WORDS: usize = 4;

/// Bits per word.
const BITS_PER_WORD: usize = 64;

/// Maximum number of managed CPU masks.
const MAX_MASKS: usize = 128;

// ── CpuMask ─────────────────────────────────────────────────

/// A bitmask of CPUs supporting up to [`MAX_CPUS`] processors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuMask {
    /// Underlying bit storage.
    bits: [u64; WORDS],
}

impl CpuMask {
    /// Create an empty CPU mask (no CPUs set).
    pub const fn empty() -> Self {
        Self { bits: [0; WORDS] }
    }

    /// Create a full CPU mask (all 256 CPUs set).
    pub const fn full() -> Self {
        Self {
            bits: [u64::MAX; WORDS],
        }
    }

    /// Create a mask with a single CPU set.
    pub const fn single(cpu: usize) -> Self {
        let mut mask = Self::empty();
        if cpu < MAX_CPUS {
            let word = cpu / BITS_PER_WORD;
            let bit = cpu % BITS_PER_WORD;
            mask.bits[word] = 1u64 << bit;
        }
        mask
    }

    /// Create a mask from a range `[start, end)`.
    pub fn from_range(start: usize, end: usize) -> Self {
        let mut mask = Self::empty();
        let end = end.min(MAX_CPUS);
        for cpu in start..end {
            mask.set(cpu);
        }
        mask
    }

    /// Set a CPU in the mask.
    pub fn set(&mut self, cpu: usize) {
        if cpu < MAX_CPUS {
            let word = cpu / BITS_PER_WORD;
            let bit = cpu % BITS_PER_WORD;
            self.bits[word] |= 1u64 << bit;
        }
    }

    /// Clear a CPU from the mask.
    pub fn clear(&mut self, cpu: usize) {
        if cpu < MAX_CPUS {
            let word = cpu / BITS_PER_WORD;
            let bit = cpu % BITS_PER_WORD;
            self.bits[word] &= !(1u64 << bit);
        }
    }

    /// Test whether a CPU is set.
    pub fn test(&self, cpu: usize) -> bool {
        if cpu >= MAX_CPUS {
            return false;
        }
        let word = cpu / BITS_PER_WORD;
        let bit = cpu % BITS_PER_WORD;
        (self.bits[word] & (1u64 << bit)) != 0
    }

    /// Return the index of the first set CPU, or `None`.
    pub fn first_set(&self) -> Option<usize> {
        for (i, &word) in self.bits.iter().enumerate() {
            if word != 0 {
                let bit = word.trailing_zeros() as usize;
                return Some(i * BITS_PER_WORD + bit);
            }
        }
        None
    }

    /// Return the next set CPU after `cpu`, or `None`.
    pub fn next_set(&self, cpu: usize) -> Option<usize> {
        let start = cpu + 1;
        if start >= MAX_CPUS {
            return None;
        }
        let word_idx = start / BITS_PER_WORD;
        let bit_idx = start % BITS_PER_WORD;

        // Check remaining bits in the current word.
        let masked = self.bits[word_idx] >> bit_idx;
        if masked != 0 {
            let pos = masked.trailing_zeros() as usize;
            return Some(word_idx * BITS_PER_WORD + bit_idx + pos);
        }

        // Check subsequent words.
        for i in (word_idx + 1)..WORDS {
            if self.bits[i] != 0 {
                let pos = self.bits[i].trailing_zeros() as usize;
                return Some(i * BITS_PER_WORD + pos);
            }
        }
        None
    }

    /// Return the last set CPU, or `None`.
    pub fn last_set(&self) -> Option<usize> {
        for i in (0..WORDS).rev() {
            if self.bits[i] != 0 {
                let bit = 63 - self.bits[i].leading_zeros() as usize;
                return Some(i * BITS_PER_WORD + bit);
            }
        }
        None
    }

    /// Count the number of set CPUs (population count).
    pub fn count(&self) -> usize {
        self.bits.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Whether the mask is empty (no CPUs set).
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|&w| w == 0)
    }

    /// Whether the mask is full (all CPUs set).
    pub fn is_full(&self) -> bool {
        self.bits.iter().all(|&w| w == u64::MAX)
    }

    /// Bitwise AND of two masks.
    pub fn and(&self, other: &CpuMask) -> CpuMask {
        let mut result = CpuMask::empty();
        for i in 0..WORDS {
            result.bits[i] = self.bits[i] & other.bits[i];
        }
        result
    }

    /// Bitwise OR of two masks.
    pub fn or(&self, other: &CpuMask) -> CpuMask {
        let mut result = CpuMask::empty();
        for i in 0..WORDS {
            result.bits[i] = self.bits[i] | other.bits[i];
        }
        result
    }

    /// Bitwise XOR of two masks.
    pub fn xor(&self, other: &CpuMask) -> CpuMask {
        let mut result = CpuMask::empty();
        for i in 0..WORDS {
            result.bits[i] = self.bits[i] ^ other.bits[i];
        }
        result
    }

    /// Bitwise NOT (complement) of the mask.
    pub fn not(&self) -> CpuMask {
        let mut result = CpuMask::empty();
        for i in 0..WORDS {
            result.bits[i] = !self.bits[i];
        }
        result
    }

    /// AND-NOT: `self & !other` (CPUs in self but not other).
    pub fn andnot(&self, other: &CpuMask) -> CpuMask {
        let mut result = CpuMask::empty();
        for i in 0..WORDS {
            result.bits[i] = self.bits[i] & !other.bits[i];
        }
        result
    }

    /// Whether two masks have any overlap.
    pub fn intersects(&self, other: &CpuMask) -> bool {
        for i in 0..WORDS {
            if self.bits[i] & other.bits[i] != 0 {
                return true;
            }
        }
        false
    }

    /// Whether `self` is a subset of `other`.
    pub fn is_subset_of(&self, other: &CpuMask) -> bool {
        for i in 0..WORDS {
            if self.bits[i] & !other.bits[i] != 0 {
                return false;
            }
        }
        true
    }

    /// Return the raw words.
    pub fn raw(&self) -> &[u64; WORDS] {
        &self.bits
    }

    /// Create from raw words.
    pub const fn from_raw(bits: [u64; WORDS]) -> Self {
        Self { bits }
    }

    /// Write set CPU IDs into `out`, returning the count written.
    pub fn to_cpu_list(&self, out: &mut [u32]) -> usize {
        let mut count = 0;
        let mut cpu = self.first_set();
        while let Some(c) = cpu {
            if count >= out.len() {
                break;
            }
            out[count] = c as u32;
            count += 1;
            cpu = self.next_set(c);
        }
        count
    }
}

impl Default for CpuMask {
    fn default() -> Self {
        Self::empty()
    }
}

// ── CpuMaskIterator ─────────────────────────────────────────

/// Iterator over set CPU indices in a [`CpuMask`].
pub struct CpuMaskIter {
    /// Snapshot of the mask.
    mask: CpuMask,
    /// Next CPU to check.
    next: Option<usize>,
}

impl CpuMaskIter {
    /// Create an iterator for the given mask.
    pub fn new(mask: &CpuMask) -> Self {
        let next = mask.first_set();
        Self { mask: *mask, next }
    }
}

impl Iterator for CpuMaskIter {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        let current = self.next?;
        self.next = self.mask.next_set(current);
        Some(current)
    }
}

// ── CpuMaskRegistry ─────────────────────────────────────────

/// Registry of named CPU masks.
pub struct CpuMaskRegistry {
    /// Masks.
    masks: [CpuMask; MAX_MASKS],
    /// Names.
    names: [[u8; MAX_NAME_LEN]; MAX_MASKS],
    /// Name lengths.
    name_lens: [usize; MAX_MASKS],
    /// Occupied slots.
    occupied: [bool; MAX_MASKS],
    /// IDs.
    ids: [u32; MAX_MASKS],
    /// Count.
    count: usize,
    /// Next ID.
    next_id: u32,
}

/// Maximum name length for a registered mask.
const MAX_NAME_LEN: usize = 32;

impl CpuMaskRegistry {
    /// Create a new, empty registry.
    pub const fn new() -> Self {
        Self {
            masks: [CpuMask::empty(); MAX_MASKS],
            names: [[0u8; MAX_NAME_LEN]; MAX_MASKS],
            name_lens: [0; MAX_MASKS],
            occupied: [false; MAX_MASKS],
            ids: [0; MAX_MASKS],
            count: 0,
            next_id: 1,
        }
    }

    /// Register a named CPU mask. Returns the mask ID.
    pub fn register(&mut self, name: &str, mask: CpuMask) -> Result<u32> {
        let slot = self
            .occupied
            .iter()
            .position(|&o| !o)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        self.masks[slot] = mask;
        let copy_len = name.len().min(MAX_NAME_LEN);
        self.names[slot][..copy_len].copy_from_slice(&name.as_bytes()[..copy_len]);
        self.name_lens[slot] = copy_len;
        self.ids[slot] = id;
        self.occupied[slot] = true;
        self.count += 1;
        Ok(id)
    }

    /// Unregister a mask by ID.
    pub fn unregister(&mut self, id: u32) -> Result<()> {
        let slot = self.find(id)?;
        self.occupied[slot] = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Get a mask by ID.
    pub fn get(&self, id: u32) -> Result<&CpuMask> {
        let slot = self.find(id)?;
        Ok(&self.masks[slot])
    }

    /// Update a mask by ID.
    pub fn update(&mut self, id: u32, mask: CpuMask) -> Result<()> {
        let slot = self.find(id)?;
        self.masks[slot] = mask;
        Ok(())
    }

    /// Find slot by ID.
    fn find(&self, id: u32) -> Result<usize> {
        for i in 0..MAX_MASKS {
            if self.occupied[i] && self.ids[i] == id {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Return the number of registered masks.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for CpuMaskRegistry {
    fn default() -> Self {
        Self::new()
    }
}
