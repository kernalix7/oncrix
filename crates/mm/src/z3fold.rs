// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Z3fold compressed page allocator.
//!
//! Z3fold packs up to three compressed objects ("buddies") into a single
//! 4 KiB physical page. Each page is divided into three variable-size
//! regions — First, Middle, and Last — that grow inward from the page
//! boundaries and center respectively.
//!
//! This approach reduces memory overhead for compressed swap and
//! zsmalloc-like workloads by achieving up to 3:1 density when objects
//! are small enough.
//!
//! Key components:
//! - [`Z3foldBuddy`] — buddy region identifier (First, Middle, Last)
//! - [`Z3foldHandle`] — opaque handle referencing a stored object
//! - [`Z3foldPage`] — a single 4 KiB page holding up to 3 buddy regions
//! - [`Z3foldPool`] — pool of z3fold pages with alloc/free/compact
//! - [`Z3foldStats`] — pool usage and compression statistics
//!
//! Reference: `.kernelORG/` — `mm/z3fold.c`.

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Maximum number of pages managed by the z3fold pool.
const MAX_Z3FOLD_PAGES: usize = 512;

/// Number of buddy regions per z3fold page.
const BUDDY_COUNT: usize = 3;

/// Minimum allocation size in bytes.
const MIN_ALLOC_SIZE: usize = 64;

/// Maximum allocation size per buddy region.
///
/// Each buddy can occupy at most one-third of the page minus a small
/// header allowance.
const MAX_BUDDY_SIZE: usize = PAGE_SIZE / 3;

// ── Z3foldBuddy ─────────────────────────────────────────────────

/// Identifies which of the three buddy regions within a z3fold page
/// an allocation resides in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Z3foldBuddy {
    /// First region: grows forward from the start of the page.
    #[default]
    First,
    /// Middle region: occupies the center of the page.
    Middle,
    /// Last region: grows backward from the end of the page.
    Last,
}

// ── Z3foldHandle ────────────────────────────────────────────────

/// Opaque handle returned by [`Z3foldPool::alloc`].
///
/// Encodes the page index, buddy region, byte offset, and allocation
/// size so that the pool can locate and free the object later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Z3foldHandle {
    /// Index of the z3fold page within the pool.
    pub page_index: u16,
    /// Buddy region containing this allocation.
    pub buddy: Z3foldBuddy,
    /// Byte offset within the page where the object starts.
    pub offset: u16,
    /// Size of the allocated object in bytes.
    pub size: u16,
}

// ── Z3foldPage ──────────────────────────────────────────────────

/// A single 4 KiB page that stores up to three compressed objects.
///
/// The page is partitioned into First (offset 0), Middle (center),
/// and Last (grows backward from offset 4095) buddy regions.
#[derive(Clone, Copy)]
pub struct Z3foldPage {
    /// Raw page data.
    data: [u8; PAGE_SIZE],
    /// Size of each buddy region in bytes (indexed by buddy ordinal).
    buddy_sizes: [u16; BUDDY_COUNT],
    /// Total free space remaining in the page.
    free_space: u16,
    /// Whether this page slot is in use.
    active: bool,
}

impl Z3foldPage {
    /// Creates an empty (inactive) z3fold page.
    const fn empty() -> Self {
        Self {
            data: [0u8; PAGE_SIZE],
            buddy_sizes: [0; BUDDY_COUNT],
            free_space: PAGE_SIZE as u16,
            active: false,
        }
    }

    /// Returns the byte offset where the given buddy region starts.
    fn buddy_offset(&self, buddy: Z3foldBuddy) -> u16 {
        match buddy {
            Z3foldBuddy::First => 0,
            Z3foldBuddy::Middle => {
                // Middle starts right after First.
                self.buddy_sizes[0]
            }
            Z3foldBuddy::Last => {
                // Last grows backward from the end.
                (PAGE_SIZE as u16).saturating_sub(self.buddy_sizes[2])
            }
        }
    }

    /// Returns the buddy ordinal index.
    fn buddy_index(buddy: Z3foldBuddy) -> usize {
        match buddy {
            Z3foldBuddy::First => 0,
            Z3foldBuddy::Middle => 1,
            Z3foldBuddy::Last => 2,
        }
    }

    /// Attempts to allocate `size` bytes in the specified buddy region.
    ///
    /// Returns the byte offset on success.
    fn try_alloc(&mut self, buddy: Z3foldBuddy, size: u16) -> Option<u16> {
        let idx = Self::buddy_index(buddy);

        // Buddy must be empty to allocate into it.
        if self.buddy_sizes[idx] != 0 {
            return None;
        }

        // Check that the allocation fits within remaining free space.
        if size > self.free_space {
            return None;
        }

        // Verify no overlap with adjacent regions.
        let offset = self.buddy_offset(buddy);
        let end = offset + size;

        match buddy {
            Z3foldBuddy::First => {
                // Must not overlap Middle.
                let middle_start = self.buddy_sizes[0]; // currently 0
                let middle_end = middle_start + self.buddy_sizes[1];
                if self.buddy_sizes[1] > 0 && end > self.buddy_offset(Z3foldBuddy::Middle) {
                    return None;
                }
                // Must not overlap Last.
                let last_start = self.buddy_offset(Z3foldBuddy::Last);
                if self.buddy_sizes[2] > 0 && end > last_start {
                    return None;
                }
                let _ = (middle_end, last_start);
            }
            Z3foldBuddy::Middle => {
                // Must not overlap First.
                if end > self.buddy_offset(Z3foldBuddy::Last) && self.buddy_sizes[2] > 0 {
                    return None;
                }
            }
            Z3foldBuddy::Last => {
                // Offset is computed from end; check it doesn't overlap
                // Middle or First.
                let first_end = self.buddy_sizes[0];
                let middle_end = self.buddy_sizes[0] + self.buddy_sizes[1];
                let used_front = if middle_end > 0 {
                    middle_end
                } else {
                    first_end
                };
                if offset < used_front {
                    return None;
                }
            }
        }

        self.buddy_sizes[idx] = size;
        self.free_space = self.free_space.saturating_sub(size);

        Some(offset)
    }

    /// Frees the buddy region, reclaiming its space.
    fn free_buddy(&mut self, buddy: Z3foldBuddy) {
        let idx = Self::buddy_index(buddy);
        let size = self.buddy_sizes[idx];
        self.buddy_sizes[idx] = 0;
        self.free_space = self.free_space.saturating_add(size).min(PAGE_SIZE as u16);

        // Clear the data region.
        let offset = self.buddy_offset(buddy) as usize;
        let end = (offset + size as usize).min(PAGE_SIZE);
        let mut i = offset;
        while i < end {
            self.data[i] = 0;
            i += 1;
        }
    }

    /// Returns `true` if all three buddy regions are empty.
    fn is_empty(&self) -> bool {
        self.buddy_sizes[0] == 0 && self.buddy_sizes[1] == 0 && self.buddy_sizes[2] == 0
    }
}

// ── Z3foldStats ─────────────────────────────────────────────────

/// Usage and compression statistics for the z3fold pool.
#[derive(Debug, Clone, Copy, Default)]
pub struct Z3foldStats {
    /// Number of z3fold pages currently in use.
    pub pages_used: u64,
    /// Total number of objects stored across all pages.
    pub objects_stored: u64,
    /// Total bytes stored (sum of all buddy region sizes).
    pub total_size_stored: u64,
    /// Effective compression ratio as a percentage.
    ///
    /// Computed as `(total_size_stored / (pages_used * PAGE_SIZE)) * 100`.
    pub compression_ratio: u64,
}

// ── Z3foldPool ──────────────────────────────────────────────────

/// Pool of z3fold pages for compressed object storage.
///
/// Manages up to [`MAX_Z3FOLD_PAGES`] pages, each capable of
/// holding three buddy-region allocations. The allocator uses a
/// first-fit strategy, preferring pages with the most free space.
pub struct Z3foldPool {
    /// Array of z3fold pages.
    pages: [Z3foldPage; MAX_Z3FOLD_PAGES],
    /// Number of active pages.
    active_count: usize,
    /// Total number of stored objects across all pages.
    objects_stored: u64,
    /// Total bytes stored across all buddy regions.
    total_size_stored: u64,
    /// Lifetime count of allocations.
    total_allocs: u64,
    /// Lifetime count of frees.
    total_frees: u64,
}

impl Default for Z3foldPool {
    fn default() -> Self {
        Self::new()
    }
}

impl Z3foldPool {
    /// Creates a new empty z3fold pool.
    pub const fn new() -> Self {
        Self {
            pages: [Z3foldPage::empty(); MAX_Z3FOLD_PAGES],
            active_count: 0,
            objects_stored: 0,
            total_size_stored: 0,
            total_allocs: 0,
            total_frees: 0,
        }
    }

    /// Allocates space for an object of `size` bytes.
    ///
    /// Searches existing pages for a buddy region with enough free
    /// space using first-fit. If no existing page can accommodate the
    /// request, a new page is allocated from the pool.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — `size` is zero or exceeds
    ///   [`MAX_BUDDY_SIZE`].
    /// - [`Error::OutOfMemory`] — pool is full and no page has
    ///   sufficient free space.
    pub fn alloc(&mut self, size: u16) -> Result<Z3foldHandle> {
        let alloc_size = size as usize;
        if alloc_size == 0 || alloc_size > MAX_BUDDY_SIZE {
            return Err(Error::InvalidArgument);
        }
        let alloc_size = if alloc_size < MIN_ALLOC_SIZE {
            MIN_ALLOC_SIZE as u16
        } else {
            size
        };

        // Try to fit into an existing active page.
        let buddies = [Z3foldBuddy::First, Z3foldBuddy::Middle, Z3foldBuddy::Last];

        for i in 0..self.active_count {
            if !self.pages[i].active {
                continue;
            }
            if self.pages[i].free_space < alloc_size {
                continue;
            }
            for &buddy in &buddies {
                if let Some(offset) = self.pages[i].try_alloc(buddy, alloc_size) {
                    self.objects_stored += 1;
                    self.total_size_stored += alloc_size as u64;
                    self.total_allocs += 1;
                    return Ok(Z3foldHandle {
                        page_index: i as u16,
                        buddy,
                        offset,
                        size: alloc_size,
                    });
                }
            }
        }

        // Allocate a new page.
        if self.active_count >= MAX_Z3FOLD_PAGES {
            return Err(Error::OutOfMemory);
        }

        let page_idx = self.active_count;
        self.pages[page_idx].active = true;
        self.active_count += 1;

        let buddy = Z3foldBuddy::First;
        let offset = self.pages[page_idx]
            .try_alloc(buddy, alloc_size)
            .ok_or(Error::OutOfMemory)?;

        self.objects_stored += 1;
        self.total_size_stored += alloc_size as u64;
        self.total_allocs += 1;

        Ok(Z3foldHandle {
            page_index: page_idx as u16,
            buddy,
            offset,
            size: alloc_size,
        })
    }

    /// Frees a previously allocated object.
    ///
    /// Releases the buddy region identified by `handle`. If the page
    /// becomes completely empty, it is deactivated.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — handle refers to an invalid
    ///   page index or inactive page.
    pub fn free(&mut self, handle: Z3foldHandle) -> Result<()> {
        let idx = handle.page_index as usize;
        if idx >= self.active_count || !self.pages[idx].active {
            return Err(Error::InvalidArgument);
        }

        let buddy_idx = Z3foldPage::buddy_index(handle.buddy);
        if self.pages[idx].buddy_sizes[buddy_idx] == 0 {
            return Err(Error::InvalidArgument);
        }

        self.pages[idx].free_buddy(handle.buddy);
        self.objects_stored = self.objects_stored.saturating_sub(1);
        self.total_size_stored = self.total_size_stored.saturating_sub(handle.size as u64);
        self.total_frees += 1;

        // Deactivate page if all buddies are empty.
        if self.pages[idx].is_empty() {
            self.pages[idx].active = false;
        }

        Ok(())
    }

    /// Compacts the pool by merging adjacent free regions.
    ///
    /// Scans all active pages and deactivates any that are completely
    /// empty after prior frees. Returns the number of pages reclaimed.
    pub fn compact(&mut self) -> usize {
        let mut reclaimed = 0_usize;

        for i in 0..self.active_count {
            if self.pages[i].active && self.pages[i].is_empty() {
                self.pages[i].active = false;
                self.pages[i].free_space = PAGE_SIZE as u16;
                reclaimed += 1;
            }
        }

        // Compact the active page array by shifting active pages down.
        let mut write = 0_usize;
        for read in 0..self.active_count {
            if self.pages[read].active {
                if write != read {
                    self.pages[write] = self.pages[read];
                    self.pages[read] = Z3foldPage::empty();
                }
                write += 1;
            }
        }
        self.active_count = write;

        reclaimed
    }

    /// Returns current pool statistics.
    pub fn stats(&self) -> Z3foldStats {
        let pages_used = self
            .pages
            .iter()
            .take(self.active_count)
            .filter(|p| p.active)
            .count() as u64;

        let ratio = if pages_used > 0 {
            self.total_size_stored * 100 / (pages_used * PAGE_SIZE as u64)
        } else {
            0
        };

        Z3foldStats {
            pages_used,
            objects_stored: self.objects_stored,
            total_size_stored: self.total_size_stored,
            compression_ratio: ratio,
        }
    }

    /// Returns the number of active pages in the pool.
    pub fn len(&self) -> usize {
        self.active_count
    }

    /// Returns `true` if the pool contains no active pages.
    pub fn is_empty(&self) -> bool {
        self.active_count == 0
    }
}
