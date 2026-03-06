// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ID radix allocator (IDR).
//!
//! The IDR provides automatic integer ID allocation with O(log n)
//! lookup. It is used throughout the kernel for file descriptors,
//! device minor numbers, IPC identifiers, etc.
//!
//! # Operations
//!
//! ```text
//! idr_alloc()       → allocate next free ID, store value
//! idr_alloc_range() → allocate ID within [start, end)
//! idr_find()        → look up value by ID
//! idr_remove()      → remove an ID
//! idr_for_each()    → iterate over all entries
//! ```
//!
//! # Cyclic Allocation
//!
//! In cyclic mode, IDs are allocated sequentially and wrap around,
//! avoiding reuse of recently freed IDs (useful for file descriptors
//! and other identifiers where immediate reuse is undesirable).
//!
//! # Reference
//!
//! Linux `lib/idr.c`, `include/linux/idr.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum number of IDs.
const IDR_MAX_IDS: usize = 16384;

/// Bitmap words for tracking free IDs.
const IDR_BITMAP_WORDS: usize = IDR_MAX_IDS / 64;

/// Default range end (exclusive).
const IDR_DEFAULT_END: u32 = IDR_MAX_IDS as u32;

/// Maximum number of managed IDR instances.
const MAX_IDRS: usize = 32;

// ======================================================================
// IDR entry
// ======================================================================

/// A stored entry in the IDR.
#[derive(Debug, Clone, Copy)]
pub struct IdrEntry {
    /// The stored value.
    value: u64,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl IdrEntry {
    /// Creates an empty entry.
    pub const fn new() -> Self {
        Self {
            value: 0,
            occupied: false,
        }
    }

    /// Returns the value.
    pub fn value(&self) -> u64 {
        self.value
    }

    /// Returns whether this entry is occupied.
    pub fn is_occupied(&self) -> bool {
        self.occupied
    }
}

// ======================================================================
// IDR
// ======================================================================

/// An ID radix allocator.
pub struct Idr {
    /// Stored entries indexed by ID.
    entries: [IdrEntry; IDR_MAX_IDS],
    /// Allocation bitmap (1 = occupied).
    bitmap: [u64; IDR_BITMAP_WORDS],
    /// Number of allocated IDs.
    count: usize,
    /// Next ID to try for sequential allocation.
    next_id: u32,
    /// Whether cyclic allocation is enabled.
    cyclic: bool,
    /// Cyclic cursor (wraps around).
    cyclic_cursor: u32,
    /// Generation counter for cyclic mode (increments on wrap).
    cyclic_generation: u32,
    /// Total allocations performed.
    total_allocs: u64,
    /// Total frees performed.
    total_frees: u64,
}

impl Idr {
    /// Creates a new empty IDR.
    pub const fn new() -> Self {
        Self {
            entries: [const { IdrEntry::new() }; IDR_MAX_IDS],
            bitmap: [0u64; IDR_BITMAP_WORDS],
            count: 0,
            next_id: 0,
            cyclic: false,
            cyclic_cursor: 0,
            cyclic_generation: 0,
            total_allocs: 0,
            total_frees: 0,
        }
    }

    /// Creates a new IDR with cyclic allocation.
    pub const fn new_cyclic() -> Self {
        let mut idr = Self::new();
        idr.cyclic = true;
        idr
    }

    /// Returns the number of allocated IDs.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns whether the IDR is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the total allocations.
    pub fn total_allocs(&self) -> u64 {
        self.total_allocs
    }

    /// Returns the total frees.
    pub fn total_frees(&self) -> u64 {
        self.total_frees
    }

    /// Returns whether cyclic mode is enabled.
    pub fn is_cyclic(&self) -> bool {
        self.cyclic
    }

    /// Allocates the next free ID and stores a value.
    pub fn idr_alloc(&mut self, value: u64) -> Result<u32> {
        self.idr_alloc_range(0, IDR_DEFAULT_END, value)
    }

    /// Allocates an ID within [start, end) and stores a value.
    pub fn idr_alloc_range(&mut self, start: u32, end: u32, value: u64) -> Result<u32> {
        if start as usize >= IDR_MAX_IDS || end as usize > IDR_MAX_IDS || start >= end {
            return Err(Error::InvalidArgument);
        }
        let id = if self.cyclic {
            self.alloc_cyclic(start, end)?
        } else {
            self.alloc_linear(start, end)?
        };
        self.entries[id as usize].value = value;
        self.entries[id as usize].occupied = true;
        self.set_bit(id as usize);
        self.count += 1;
        self.total_allocs = self.total_allocs.saturating_add(1);
        Ok(id)
    }

    /// Looks up a value by ID.
    pub fn idr_find(&self, id: u32) -> Option<u64> {
        if id as usize >= IDR_MAX_IDS {
            return None;
        }
        if self.entries[id as usize].occupied {
            Some(self.entries[id as usize].value)
        } else {
            None
        }
    }

    /// Removes an ID and returns its value.
    pub fn idr_remove(&mut self, id: u32) -> Result<u64> {
        if id as usize >= IDR_MAX_IDS {
            return Err(Error::InvalidArgument);
        }
        if !self.entries[id as usize].occupied {
            return Err(Error::NotFound);
        }
        let value = self.entries[id as usize].value;
        self.entries[id as usize].occupied = false;
        self.clear_bit(id as usize);
        self.count = self.count.saturating_sub(1);
        self.total_frees = self.total_frees.saturating_add(1);
        Ok(value)
    }

    /// Replaces the value at an existing ID.
    pub fn idr_replace(&mut self, id: u32, value: u64) -> Result<u64> {
        if id as usize >= IDR_MAX_IDS {
            return Err(Error::InvalidArgument);
        }
        if !self.entries[id as usize].occupied {
            return Err(Error::NotFound);
        }
        let old = self.entries[id as usize].value;
        self.entries[id as usize].value = value;
        Ok(old)
    }

    /// Iterates over all entries, calling `f` for each (id, value).
    /// Returns the number of entries visited.
    pub fn idr_for_each<F>(&self, mut f: F) -> usize
    where
        F: FnMut(u32, u64),
    {
        let mut visited = 0;
        for id in 0..IDR_MAX_IDS {
            if self.entries[id].occupied {
                f(id as u32, self.entries[id].value);
                visited += 1;
            }
        }
        visited
    }

    /// Returns the next allocated ID at or after `start`.
    pub fn idr_get_next(&self, start: u32) -> Option<u32> {
        for id in start as usize..IDR_MAX_IDS {
            if self.entries[id].occupied {
                return Some(id as u32);
            }
        }
        None
    }

    /// Returns whether an ID is allocated.
    pub fn is_allocated(&self, id: u32) -> bool {
        if id as usize >= IDR_MAX_IDS {
            return false;
        }
        self.entries[id as usize].occupied
    }

    // --- Internal helpers ---

    /// Allocates linearly from `start` to `end`.
    fn alloc_linear(&mut self, start: u32, end: u32) -> Result<u32> {
        let search_start = self.next_id.max(start) as usize;
        // First pass: from search_start to end.
        if let Some(id) = self.find_free_bit(search_start, end as usize) {
            self.next_id = id as u32 + 1;
            return Ok(id as u32);
        }
        // Second pass: from start to search_start.
        if search_start > start as usize {
            if let Some(id) = self.find_free_bit(start as usize, search_start) {
                self.next_id = id as u32 + 1;
                return Ok(id as u32);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Allocates in cyclic mode.
    fn alloc_cyclic(&mut self, start: u32, end: u32) -> Result<u32> {
        let cursor = self.cyclic_cursor.max(start) as usize;
        // First pass: from cursor to end.
        if let Some(id) = self.find_free_bit(cursor, end as usize) {
            self.cyclic_cursor = id as u32 + 1;
            return Ok(id as u32);
        }
        // Wrap around.
        self.cyclic_generation = self.cyclic_generation.wrapping_add(1);
        if let Some(id) = self.find_free_bit(start as usize, end as usize) {
            self.cyclic_cursor = id as u32 + 1;
            return Ok(id as u32);
        }
        Err(Error::OutOfMemory)
    }

    /// Finds the first free bit in [start, end).
    fn find_free_bit(&self, start: usize, end: usize) -> Option<usize> {
        let start_word = start / 64;
        let end_word = (end + 63) / 64;
        for w in start_word..end_word.min(IDR_BITMAP_WORDS) {
            if self.bitmap[w] == u64::MAX {
                continue;
            }
            let inverted = !self.bitmap[w];
            let first_bit = inverted.trailing_zeros() as usize;
            for b in first_bit..64 {
                let id = w * 64 + b;
                if id >= start && id < end {
                    if (self.bitmap[w] & (1u64 << b)) == 0 {
                        return Some(id);
                    }
                }
            }
        }
        None
    }

    /// Sets a bit in the allocation bitmap.
    fn set_bit(&mut self, id: usize) {
        let word = id / 64;
        let bit = id % 64;
        if word < IDR_BITMAP_WORDS {
            self.bitmap[word] |= 1u64 << bit;
        }
    }

    /// Clears a bit in the allocation bitmap.
    fn clear_bit(&mut self, id: usize) {
        let word = id / 64;
        let bit = id % 64;
        if word < IDR_BITMAP_WORDS {
            self.bitmap[word] &= !(1u64 << bit);
        }
    }
}

// ======================================================================
// IDR manager
// ======================================================================

/// Manages multiple IDR instances.
pub struct IdrManager {
    /// IDR instances.
    idrs: [Idr; MAX_IDRS],
    /// Which slots are occupied.
    occupied: [bool; MAX_IDRS],
    /// Instance IDs.
    ids: [u32; MAX_IDRS],
    /// Number of active instances.
    count: usize,
    /// Next instance ID.
    next_id: u32,
}

impl IdrManager {
    /// Creates a new IDR manager.
    pub const fn new() -> Self {
        Self {
            idrs: [const { Idr::new() }; MAX_IDRS],
            occupied: [false; MAX_IDRS],
            ids: [0; MAX_IDRS],
            count: 0,
            next_id: 1,
        }
    }

    /// Returns the number of active IDR instances.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Creates a new IDR instance.
    pub fn create(&mut self, cyclic: bool) -> Result<u32> {
        let slot = self
            .occupied
            .iter()
            .position(|&o| !o)
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.idrs[slot] = if cyclic {
            Idr::new_cyclic()
        } else {
            Idr::new()
        };
        self.ids[slot] = id;
        self.occupied[slot] = true;
        self.count += 1;
        Ok(id)
    }

    /// Destroys an IDR instance.
    pub fn destroy(&mut self, id: u32) -> Result<()> {
        let slot = self.find(id)?;
        self.occupied[slot] = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Returns a reference to an IDR instance.
    pub fn get(&self, id: u32) -> Result<&Idr> {
        let slot = self.find(id)?;
        Ok(&self.idrs[slot])
    }

    /// Returns a mutable reference to an IDR instance.
    pub fn get_mut(&mut self, id: u32) -> Result<&mut Idr> {
        let slot = self.find(id)?;
        Ok(&mut self.idrs[slot])
    }

    /// Finds a slot by instance ID.
    fn find(&self, id: u32) -> Result<usize> {
        for i in 0..MAX_IDRS {
            if self.occupied[i] && self.ids[i] == id {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }
}
