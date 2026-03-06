// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Maple tree — range-based data structure for address-space management.
//!
//! The maple tree stores non-overlapping ranges (`[start, end)`) associated
//! with arbitrary 64-bit values. It is optimised for VMA (virtual memory
//! area) management where ranges rarely overlap and sequential access is
//! common.
//!
//! This implementation uses a flat sorted array of `MtEntry` values for
//! simplicity; a production tree would use B-tree nodes. The API surface
//! mirrors Linux's maple tree: `insert`, `remove`, `find`, `find_first_gap`.

use oncrix_lib::{Error, Result};

/// Maximum number of entries in a maple tree instance.
pub const MT_MAX_ENTRIES: usize = 512;

/// A single range entry in the maple tree.
#[derive(Debug, Clone, Copy)]
pub struct MtEntry {
    /// Start of the range (inclusive).
    pub start: u64,
    /// End of the range (exclusive).
    pub end: u64,
    /// User value stored for this range.
    pub value: u64,
}

impl MtEntry {
    /// Creates an empty (unused) entry.
    pub const fn empty() -> Self {
        Self {
            start: 0,
            end: 0,
            value: 0,
        }
    }

    /// Returns `true` if the entry is unused (start == end == 0).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.start == 0 && self.end == 0
    }

    /// Returns `true` if `addr` falls within `[start, end)`.
    #[inline]
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    /// Returns `true` if `[s, e)` overlaps this entry.
    #[inline]
    pub fn overlaps(&self, s: u64, e: u64) -> bool {
        s < self.end && e > self.start
    }
}

/// Maple tree container.
pub struct MapleTree {
    entries: [MtEntry; MT_MAX_ENTRIES],
    count: usize,
}

impl MapleTree {
    /// Creates an empty maple tree.
    pub const fn new() -> Self {
        Self {
            entries: [const { MtEntry::empty() }; MT_MAX_ENTRIES],
            count: 0,
        }
    }

    /// Inserts a range `[start, end)` with the given `value`.
    ///
    /// Returns `Err(AlreadyExists)` if the range overlaps an existing entry.
    /// Returns `Err(OutOfMemory)` if the tree is full.
    pub fn insert(&mut self, start: u64, end: u64, value: u64) -> Result<()> {
        if start >= end {
            return Err(Error::InvalidArgument);
        }
        // Check for overlap.
        for i in 0..self.count {
            if self.entries[i].overlaps(start, end) {
                return Err(Error::AlreadyExists);
            }
        }
        if self.count >= MT_MAX_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = MtEntry { start, end, value };
        self.count += 1;
        // Keep sorted by start for efficient gap search.
        self.sort_entries();
        Ok(())
    }

    /// Removes the entry whose range contains `addr`.
    ///
    /// Returns `Err(NotFound)` if no entry matches.
    pub fn remove(&mut self, addr: u64) -> Result<MtEntry> {
        let idx = (0..self.count)
            .find(|&i| self.entries[i].contains(addr))
            .ok_or(Error::NotFound)?;
        let removed = self.entries[idx];
        // Shift remaining entries left.
        for i in idx..self.count - 1 {
            self.entries[i] = self.entries[i + 1];
        }
        self.entries[self.count - 1] = MtEntry::empty();
        self.count -= 1;
        Ok(removed)
    }

    /// Removes an entry matching the exact range `[start, end)`.
    pub fn remove_range(&mut self, start: u64, end: u64) -> Result<MtEntry> {
        let idx = (0..self.count)
            .find(|&i| self.entries[i].start == start && self.entries[i].end == end)
            .ok_or(Error::NotFound)?;
        let removed = self.entries[idx];
        for i in idx..self.count - 1 {
            self.entries[i] = self.entries[i + 1];
        }
        self.entries[self.count - 1] = MtEntry::empty();
        self.count -= 1;
        Ok(removed)
    }

    /// Finds the entry containing `addr`.
    pub fn find(&self, addr: u64) -> Option<&MtEntry> {
        self.entries[..self.count].iter().find(|e| e.contains(addr))
    }

    /// Finds the first free gap of at least `size` bytes starting from `min_addr`.
    ///
    /// Returns the start of the gap or `None` if no gap is large enough.
    pub fn find_first_gap(&self, min_addr: u64, size: u64, max_addr: u64) -> Option<u64> {
        let mut cursor = min_addr;
        for i in 0..self.count {
            let e = &self.entries[i];
            if e.start >= max_addr {
                break;
            }
            if e.start > cursor && e.start.wrapping_sub(cursor) >= size {
                if cursor + size <= max_addr {
                    return Some(cursor);
                }
            }
            if e.end > cursor {
                cursor = e.end;
            }
        }
        // Check trailing gap.
        if max_addr.wrapping_sub(cursor) >= size {
            Some(cursor)
        } else {
            None
        }
    }

    /// Iterates all entries in order of start address.
    pub fn iter(&self) -> impl Iterator<Item = &MtEntry> {
        self.entries[..self.count].iter()
    }

    /// Returns the number of entries in the tree.
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if the tree contains no entries.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Sorts entries by `start` (insertion sort — count is small in practice).
    fn sort_entries(&mut self) {
        for i in 1..self.count {
            let mut j = i;
            while j > 0 && self.entries[j - 1].start > self.entries[j].start {
                self.entries.swap(j - 1, j);
                j -= 1;
            }
        }
    }

    /// Checks that no two entries overlap (invariant verification).
    pub fn verify_invariants(&self) -> bool {
        for i in 0..self.count {
            if self.entries[i].start >= self.entries[i].end {
                return false;
            }
            if i + 1 < self.count && self.entries[i].end > self.entries[i + 1].start {
                return false;
            }
        }
        true
    }
}

impl Default for MapleTree {
    fn default() -> Self {
        Self::new()
    }
}
