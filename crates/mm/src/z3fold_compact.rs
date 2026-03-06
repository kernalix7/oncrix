// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Z3fold compaction.
//!
//! Z3fold stores up to three compressed pages in a single physical
//! page. Over time, partial pages accumulate as objects are freed.
//! This module compacts z3fold pages by migrating objects from
//! partially-filled pages into fuller ones, freeing the source pages
//! back to the allocator.
//!
//! # Design
//!
//! ```text
//!  z3fold_compact()
//!     │
//!     ├─ scan partial pages (1 or 2 objects)
//!     ├─ find destination page with room
//!     ├─ copy object data from source → destination
//!     ├─ update handle pointers
//!     └─ free emptied source page
//! ```
//!
//! # Key Types
//!
//! - [`Z3foldSlot`] — slot position within a z3fold page
//! - [`Z3foldPage`] — a single z3fold page with up to 3 slots
//! - [`Z3foldCompactor`] — drives compaction
//! - [`Z3foldCompactStats`] — compaction statistics
//!
//! Reference: Linux `mm/z3fold.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum tracked z3fold pages.
const MAX_PAGES: usize = 2048;

/// Slots per z3fold page.
const SLOTS_PER_PAGE: usize = 3;

/// Page size.
const PAGE_SIZE: u64 = 4096;

/// Maximum object size (must fit 3 in a page).
const MAX_OBJECT_SIZE: u32 = 1360;

// -------------------------------------------------------------------
// Z3foldSlot
// -------------------------------------------------------------------

/// Slot position within a z3fold page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Z3foldSlot {
    /// First slot.
    First,
    /// Middle slot.
    Middle,
    /// Last slot.
    Last,
}

impl Z3foldSlot {
    /// Return a label string.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::First => "first",
            Self::Middle => "middle",
            Self::Last => "last",
        }
    }

    /// Return the index.
    pub const fn index(&self) -> usize {
        match self {
            Self::First => 0,
            Self::Middle => 1,
            Self::Last => 2,
        }
    }
}

// -------------------------------------------------------------------
// Z3foldPage
// -------------------------------------------------------------------

/// A single z3fold page with up to 3 compressed objects.
#[derive(Debug, Clone, Copy)]
pub struct Z3foldPage {
    /// Physical frame number.
    pfn: u64,
    /// Slot sizes (0 = empty).
    slot_sizes: [u32; SLOTS_PER_PAGE],
    /// Slot handles (opaque ID, 0 = empty).
    slot_handles: [u64; SLOTS_PER_PAGE],
    /// Number of occupied slots.
    occupied: u8,
}

impl Z3foldPage {
    /// Create a new empty z3fold page.
    pub const fn new(pfn: u64) -> Self {
        Self {
            pfn,
            slot_sizes: [0; SLOTS_PER_PAGE],
            slot_handles: [0; SLOTS_PER_PAGE],
            occupied: 0,
        }
    }

    /// Return the PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Return the number of occupied slots.
    pub const fn occupied(&self) -> u8 {
        self.occupied
    }

    /// Check whether the page is full.
    pub const fn is_full(&self) -> bool {
        self.occupied as usize >= SLOTS_PER_PAGE
    }

    /// Check whether the page is empty.
    pub const fn is_empty(&self) -> bool {
        self.occupied == 0
    }

    /// Check whether the page is partial (1 or 2 slots used).
    pub const fn is_partial(&self) -> bool {
        self.occupied > 0 && (self.occupied as usize) < SLOTS_PER_PAGE
    }

    /// Available space in bytes.
    pub fn available_bytes(&self) -> u32 {
        let used: u32 = self.slot_sizes[0] + self.slot_sizes[1] + self.slot_sizes[2];
        (PAGE_SIZE as u32).saturating_sub(used)
    }

    /// Find a free slot that can fit the given size.
    pub fn find_free_slot(&self, size: u32) -> Option<Z3foldSlot> {
        if size > MAX_OBJECT_SIZE {
            return None;
        }
        if self.slot_sizes[0] == 0 && self.available_bytes() >= size {
            return Some(Z3foldSlot::First);
        }
        if self.slot_sizes[1] == 0 && self.available_bytes() >= size {
            return Some(Z3foldSlot::Middle);
        }
        if self.slot_sizes[2] == 0 && self.available_bytes() >= size {
            return Some(Z3foldSlot::Last);
        }
        None
    }

    /// Insert an object into a slot.
    pub fn insert(&mut self, slot: Z3foldSlot, size: u32, handle: u64) -> Result<()> {
        let idx = slot.index();
        if self.slot_sizes[idx] != 0 {
            return Err(Error::AlreadyExists);
        }
        if size > MAX_OBJECT_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.slot_sizes[idx] = size;
        self.slot_handles[idx] = handle;
        self.occupied += 1;
        Ok(())
    }

    /// Remove an object from a slot.
    pub fn remove(&mut self, slot: Z3foldSlot) -> Result<(u32, u64)> {
        let idx = slot.index();
        if self.slot_sizes[idx] == 0 {
            return Err(Error::NotFound);
        }
        let size = self.slot_sizes[idx];
        let handle = self.slot_handles[idx];
        self.slot_sizes[idx] = 0;
        self.slot_handles[idx] = 0;
        self.occupied -= 1;
        Ok((size, handle))
    }

    /// Get slot size.
    pub fn slot_size(&self, slot: Z3foldSlot) -> u32 {
        self.slot_sizes[slot.index()]
    }
}

impl Default for Z3foldPage {
    fn default() -> Self {
        Self {
            pfn: 0,
            slot_sizes: [0; SLOTS_PER_PAGE],
            slot_handles: [0; SLOTS_PER_PAGE],
            occupied: 0,
        }
    }
}

// -------------------------------------------------------------------
// Z3foldCompactStats
// -------------------------------------------------------------------

/// Compaction statistics.
#[derive(Debug, Clone, Copy)]
pub struct Z3foldCompactStats {
    /// Compaction cycles run.
    pub cycles: u64,
    /// Objects migrated.
    pub objects_migrated: u64,
    /// Pages freed by compaction.
    pub pages_freed: u64,
    /// Bytes reclaimed.
    pub bytes_reclaimed: u64,
    /// Migration failures.
    pub migration_failures: u64,
}

impl Z3foldCompactStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            cycles: 0,
            objects_migrated: 0,
            pages_freed: 0,
            bytes_reclaimed: 0,
            migration_failures: 0,
        }
    }

    /// Average objects migrated per cycle.
    pub const fn avg_objects_per_cycle(&self) -> u64 {
        if self.cycles == 0 {
            return 0;
        }
        self.objects_migrated / self.cycles
    }
}

impl Default for Z3foldCompactStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Z3foldCompactor
// -------------------------------------------------------------------

/// Drives z3fold compaction.
pub struct Z3foldCompactor {
    /// Tracked pages.
    pages: [Z3foldPage; MAX_PAGES],
    /// Number of pages.
    count: usize,
    /// Statistics.
    stats: Z3foldCompactStats,
}

impl Z3foldCompactor {
    /// Create a new compactor.
    pub const fn new() -> Self {
        Self {
            pages: [const {
                Z3foldPage {
                    pfn: 0,
                    slot_sizes: [0; SLOTS_PER_PAGE],
                    slot_handles: [0; SLOTS_PER_PAGE],
                    occupied: 0,
                }
            }; MAX_PAGES],
            count: 0,
            stats: Z3foldCompactStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &Z3foldCompactStats {
        &self.stats
    }

    /// Return the number of pages.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Register a z3fold page.
    pub fn register(&mut self, pfn: u64) -> Result<()> {
        if self.count >= MAX_PAGES {
            return Err(Error::OutOfMemory);
        }
        self.pages[self.count] = Z3foldPage::new(pfn);
        self.count += 1;
        Ok(())
    }

    /// Count partial pages.
    pub fn partial_count(&self) -> usize {
        let mut n = 0;
        for idx in 0..self.count {
            if self.pages[idx].is_partial() {
                n += 1;
            }
        }
        n
    }

    /// Count empty pages.
    pub fn empty_count(&self) -> usize {
        let mut n = 0;
        for idx in 0..self.count {
            if self.pages[idx].is_empty() {
                n += 1;
            }
        }
        n
    }

    /// Run one compaction cycle.
    pub fn compact(&mut self) -> u64 {
        self.stats.cycles += 1;
        let mut freed: u64 = 0;

        // Simple strategy: move objects from partial pages to other
        // partial/non-full pages.
        let count = self.count;
        for src_idx in 0..count {
            if !self.pages[src_idx].is_partial() {
                continue;
            }
            for slot_i in 0..SLOTS_PER_PAGE {
                let size = self.pages[src_idx].slot_sizes[slot_i];
                if size == 0 {
                    continue;
                }
                // Find destination.
                let mut found_dst = false;
                for dst_idx in 0..count {
                    if dst_idx == src_idx {
                        continue;
                    }
                    if self.pages[dst_idx].is_full() {
                        continue;
                    }
                    if self.pages[dst_idx].find_free_slot(size).is_some() {
                        let handle = self.pages[src_idx].slot_handles[slot_i];
                        let dst_slot = self.pages[dst_idx].find_free_slot(size).unwrap();
                        if self.pages[dst_idx].insert(dst_slot, size, handle).is_ok() {
                            self.pages[src_idx].slot_sizes[slot_i] = 0;
                            self.pages[src_idx].slot_handles[slot_i] = 0;
                            self.pages[src_idx].occupied -= 1;
                            self.stats.objects_migrated += 1;
                            found_dst = true;
                            break;
                        }
                    }
                }
                if !found_dst {
                    self.stats.migration_failures += 1;
                }
            }
            if self.pages[src_idx].is_empty() {
                freed += 1;
            }
        }

        self.stats.pages_freed += freed;
        self.stats.bytes_reclaimed += freed * PAGE_SIZE;
        freed
    }
}

impl Default for Z3foldCompactor {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum pages.
pub const fn max_pages() -> usize {
    MAX_PAGES
}

/// Return the slots per page.
pub const fn slots_per_page() -> usize {
    SLOTS_PER_PAGE
}

/// Return the maximum object size.
pub const fn max_object_size() -> u32 {
    MAX_OBJECT_SIZE
}
