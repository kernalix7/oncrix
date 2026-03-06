// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CPU affinity mask operations.
//!
//! Provides bitmap-based CPU affinity masks used throughout the
//! kernel for constraining task execution, IRQ routing, and
//! workqueue placement to specific CPUs. Supports set operations
//! (union, intersection, complement), iteration, weight
//! counting, and NUMA-aware mask generation.

use oncrix_lib::{Error, Result};

/// Maximum number of CPUs supported by the mask.
const MAX_CPUS: usize = 256;

/// Number of u64 words needed for MAX_CPUS bits.
const MASK_WORDS: usize = MAX_CPUS / 64;

/// Maximum number of managed affinity sets.
const MAX_AFFINITY_SETS: usize = 128;

/// CPU affinity bitmask.
#[derive(Clone, Copy)]
pub struct CpuAffinityMask {
    /// Bitmap words (each bit represents one CPU).
    bits: [u64; MASK_WORDS],
    /// Number of CPUs this mask covers.
    nr_cpus: u32,
}

impl CpuAffinityMask {
    /// Creates an empty affinity mask.
    pub const fn new() -> Self {
        Self {
            bits: [0u64; MASK_WORDS],
            nr_cpus: MAX_CPUS as u32,
        }
    }

    /// Creates a mask with all CPUs set (up to nr_cpus).
    pub fn all(nr_cpus: u32) -> Self {
        let mut mask = Self::new();
        mask.nr_cpus = nr_cpus;
        let full_words = nr_cpus as usize / 64;
        for word in mask.bits.iter_mut().take(full_words) {
            *word = u64::MAX;
        }
        let remaining = nr_cpus as usize % 64;
        if remaining > 0 && full_words < MASK_WORDS {
            mask.bits[full_words] = (1u64 << remaining) - 1;
        }
        mask
    }

    /// Sets a CPU in the mask.
    pub fn set_cpu(&mut self, cpu: u32) -> Result<()> {
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        let word = cpu as usize / 64;
        let bit = cpu as usize % 64;
        self.bits[word] |= 1u64 << bit;
        Ok(())
    }

    /// Clears a CPU from the mask.
    pub fn clear_cpu(&mut self, cpu: u32) -> Result<()> {
        if cpu >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        let word = cpu as usize / 64;
        let bit = cpu as usize % 64;
        self.bits[word] &= !(1u64 << bit);
        Ok(())
    }

    /// Tests if a CPU is set in the mask.
    pub fn test_cpu(&self, cpu: u32) -> bool {
        if cpu >= self.nr_cpus {
            return false;
        }
        let word = cpu as usize / 64;
        let bit = cpu as usize % 64;
        (self.bits[word] & (1u64 << bit)) != 0
    }

    /// Returns the number of CPUs set in the mask (weight).
    pub fn weight(&self) -> u32 {
        let mut count = 0u32;
        for word in &self.bits {
            count += word.count_ones();
        }
        count
    }

    /// Returns whether the mask is empty.
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|w| *w == 0)
    }

    /// Returns the first set CPU, or None.
    pub fn first_cpu(&self) -> Option<u32> {
        for (word_idx, word) in self.bits.iter().enumerate() {
            if *word != 0 {
                let bit = word.trailing_zeros();
                let cpu = word_idx as u32 * 64 + bit;
                if cpu < self.nr_cpus {
                    return Some(cpu);
                }
            }
        }
        None
    }

    /// Returns the next set CPU after `prev`, or None.
    pub fn next_cpu(&self, prev: u32) -> Option<u32> {
        let start = prev + 1;
        if start >= self.nr_cpus {
            return None;
        }
        let start_word = start as usize / 64;
        let start_bit = start as usize % 64;

        // Check remaining bits in the first word
        if start_word < MASK_WORDS {
            let masked = self.bits[start_word] >> start_bit;
            if masked != 0 {
                let bit = masked.trailing_zeros();
                let cpu = start_word as u32 * 64 + start_bit as u32 + bit;
                if cpu < self.nr_cpus {
                    return Some(cpu);
                }
            }
        }

        // Check subsequent words
        for word_idx in (start_word + 1)..MASK_WORDS {
            if self.bits[word_idx] != 0 {
                let bit = self.bits[word_idx].trailing_zeros();
                let cpu = word_idx as u32 * 64 + bit;
                if cpu < self.nr_cpus {
                    return Some(cpu);
                }
            }
        }
        None
    }

    /// Computes the intersection (AND) of two masks.
    pub fn intersect(&self, other: &Self) -> Self {
        let mut result = Self::new();
        result.nr_cpus = if self.nr_cpus < other.nr_cpus {
            self.nr_cpus
        } else {
            other.nr_cpus
        };
        for i in 0..MASK_WORDS {
            result.bits[i] = self.bits[i] & other.bits[i];
        }
        result
    }

    /// Computes the union (OR) of two masks.
    pub fn union_with(&self, other: &Self) -> Self {
        let mut result = Self::new();
        result.nr_cpus = if self.nr_cpus > other.nr_cpus {
            self.nr_cpus
        } else {
            other.nr_cpus
        };
        for i in 0..MASK_WORDS {
            result.bits[i] = self.bits[i] | other.bits[i];
        }
        result
    }

    /// Computes the complement (NOT) of the mask.
    pub fn complement(&self) -> Self {
        let mut result = Self::new();
        result.nr_cpus = self.nr_cpus;
        for i in 0..MASK_WORDS {
            result.bits[i] = !self.bits[i];
        }
        // Clear bits beyond nr_cpus
        let last_word = self.nr_cpus as usize / 64;
        let last_bits = self.nr_cpus as usize % 64;
        if last_bits > 0 && last_word < MASK_WORDS {
            result.bits[last_word] &= (1u64 << last_bits) - 1;
        }
        for i in (last_word + 1)..MASK_WORDS {
            result.bits[i] = 0;
        }
        result
    }

    /// Returns the number of CPUs this mask covers.
    pub const fn nr_cpus(&self) -> u32 {
        self.nr_cpus
    }

    /// Checks if two masks have any CPU in common.
    pub fn intersects(&self, other: &Self) -> bool {
        for i in 0..MASK_WORDS {
            if (self.bits[i] & other.bits[i]) != 0 {
                return true;
            }
        }
        false
    }
}

impl Default for CpuAffinityMask {
    fn default() -> Self {
        Self::new()
    }
}

/// Named affinity set for group management.
#[derive(Clone, Copy)]
pub struct AffinitySet {
    /// Set identifier.
    id: u32,
    /// CPU mask for this set.
    mask: CpuAffinityMask,
    /// Name tag (for debugging).
    tag: [u8; 32],
    /// Tag length.
    tag_len: usize,
    /// Whether this set is active.
    active: bool,
}

impl AffinitySet {
    /// Creates a new empty affinity set.
    pub const fn new() -> Self {
        Self {
            id: 0,
            mask: CpuAffinityMask::new(),
            tag: [0u8; 32],
            tag_len: 0,
            active: false,
        }
    }

    /// Returns the set identifier.
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Returns the CPU mask.
    pub const fn mask(&self) -> &CpuAffinityMask {
        &self.mask
    }

    /// Returns whether this set is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }
}

impl Default for AffinitySet {
    fn default() -> Self {
        Self::new()
    }
}

/// Affinity mask manager.
pub struct AffinityManager {
    /// Named affinity sets.
    sets: [AffinitySet; MAX_AFFINITY_SETS],
    /// Number of sets.
    set_count: usize,
    /// Next set ID.
    next_id: u32,
    /// System-wide online CPU mask.
    online_mask: CpuAffinityMask,
    /// System-wide possible CPU mask.
    possible_mask: CpuAffinityMask,
}

impl AffinityManager {
    /// Creates a new affinity manager.
    pub const fn new() -> Self {
        Self {
            sets: [const { AffinitySet::new() }; MAX_AFFINITY_SETS],
            set_count: 0,
            next_id: 1,
            online_mask: CpuAffinityMask::new(),
            possible_mask: CpuAffinityMask::new(),
        }
    }

    /// Sets the online CPU mask.
    pub fn set_online_mask(&mut self, mask: CpuAffinityMask) {
        self.online_mask = mask;
    }

    /// Sets the possible CPU mask.
    pub fn set_possible_mask(&mut self, mask: CpuAffinityMask) {
        self.possible_mask = mask;
    }

    /// Returns the online CPU mask.
    pub const fn online_mask(&self) -> &CpuAffinityMask {
        &self.online_mask
    }

    /// Creates a named affinity set.
    pub fn create_set(&mut self, mask: CpuAffinityMask) -> Result<u32> {
        if self.set_count >= MAX_AFFINITY_SETS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.sets[self.set_count] = AffinitySet {
            id,
            mask,
            tag: [0u8; 32],
            tag_len: 0,
            active: true,
        };
        self.set_count += 1;
        Ok(id)
    }

    /// Gets an affinity set by ID.
    pub fn get_set(&self, id: u32) -> Result<&AffinitySet> {
        self.sets[..self.set_count]
            .iter()
            .find(|s| s.id == id && s.active)
            .ok_or(Error::NotFound)
    }

    /// Validates that a mask only includes online CPUs.
    pub fn validate_mask(&self, mask: &CpuAffinityMask) -> bool {
        let valid = mask.intersect(&self.online_mask);
        valid.weight() == mask.weight()
    }

    /// Returns the number of affinity sets.
    pub const fn set_count(&self) -> usize {
        self.set_count
    }
}

impl Default for AffinityManager {
    fn default() -> Self {
        Self::new()
    }
}
