// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! zbud compressed page allocator (buddy pairs).
//!
//! zbud is a specialized allocator for storing compressed pages. Each
//! physical page ("zbud page") holds exactly one or two compressed
//! objects laid out as a buddy pair. Objects are limited to half a
//! page (2040 bytes) so that two always fit within a single 4 KiB frame.
//!
//! # Design
//!
//! ```text
//! ┌──────────────────────────────────┐
//! │ ZbudPage header (8 bytes)        │  ← slot offsets, sizes, flags
//! ├──────────────────────────────────┤
//! │ buddy[0]  (0..2040 bytes)        │  ← first compressed object
//! ├──────────────────────────────────┤
//! │ buddy[1]  (0..2040 bytes)        │  ← second compressed object
//! └──────────────────────────────────┘
//! ```
//!
//! An unzbudded page with only one object occupies the "unbuddied" list.
//! When a second object arrives, zbud tries to pair it with an existing
//! unbuddied page; if none fit, a new physical page is allocated.
//!
//! # Key Types
//!
//! - [`ZbudHandle`] — opaque handle returned by `alloc`
//! - [`ZbudPage`] — metadata for one physical page holding buddy objects
//! - [`ZbudPool`] — the allocator managing a collection of zbud pages
//! - [`ZbudStats`] — allocation statistics
//!
//! Reference: Linux `mm/zbud.c`, `include/linux/zbud.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Size of the zbud page header (reserved for metadata).
const ZBUD_HEADER_SIZE: usize = 8;

/// Maximum usable bytes per zbud page (split between two buddies).
const ZBUD_DATA_SIZE: usize = PAGE_SIZE - ZBUD_HEADER_SIZE;

/// Maximum size of a single compressed object.
const MAX_OBJECT_SIZE: usize = ZBUD_DATA_SIZE / 2;

/// Maximum number of zbud pages in one pool.
const MAX_ZBUD_PAGES: usize = 1024;

/// Maximum total handles the pool can track.
const MAX_HANDLES: usize = MAX_ZBUD_PAGES * 2;

/// Sentinel: invalid handle / page index.
const INVALID_IDX: u32 = u32::MAX;

/// Alignment for objects within a zbud page (8 bytes).
const OBJECT_ALIGN: usize = 8;

// -------------------------------------------------------------------
// ZbudHandle
// -------------------------------------------------------------------

/// Opaque handle identifying a compressed object in a zbud pool.
///
/// Encodes the page index and buddy slot (0 or 1) in a single `u64`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ZbudHandle(u64);

impl ZbudHandle {
    /// Create a handle from a page index and buddy slot.
    fn new(page_idx: u32, slot: u8) -> Self {
        ZbudHandle(((page_idx as u64) << 1) | (slot as u64 & 1))
    }

    /// Return the page index encoded in this handle.
    pub fn page_idx(self) -> u32 {
        (self.0 >> 1) as u32
    }

    /// Return the buddy slot (0 or 1) encoded in this handle.
    pub fn slot(self) -> u8 {
        (self.0 & 1) as u8
    }

    /// Return the raw handle value.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Return `true` if this handle is valid (not a sentinel).
    pub const fn is_valid(self) -> bool {
        self.0 != u64::MAX
    }

    /// Return a sentinel (invalid) handle.
    pub const fn invalid() -> Self {
        ZbudHandle(u64::MAX)
    }
}

// -------------------------------------------------------------------
// ZbudBuddy — per-slot metadata
// -------------------------------------------------------------------

/// Metadata for a single compressed object slot within a zbud page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ZbudBuddy {
    /// Size of the stored compressed object in bytes. Zero means empty.
    pub size: u16,
    /// Byte offset of this buddy's data relative to the start of the
    /// zbud page's data region.
    pub offset: u16,
}

impl ZbudBuddy {
    const fn empty() -> Self {
        ZbudBuddy { size: 0, offset: 0 }
    }

    const fn is_occupied(self) -> bool {
        self.size > 0
    }

    /// Return the aligned allocation size for an object of `size` bytes.
    fn aligned_size(size: usize) -> usize {
        (size + OBJECT_ALIGN - 1) & !(OBJECT_ALIGN - 1)
    }
}

// -------------------------------------------------------------------
// ZbudPage
// -------------------------------------------------------------------

/// Metadata and data storage for one zbud physical page.
///
/// Each zbud page stores up to two compressed objects. Buddy 0 grows
/// from the start of the data region; buddy 1 grows from the end.
pub struct ZbudPage {
    /// Per-slot metadata.
    buddy: [ZbudBuddy; 2],
    /// Raw data storage (DATA_SIZE bytes).
    data: [u8; ZBUD_DATA_SIZE],
    /// Whether this page is in the pool (true) or freed (false).
    active: bool,
}

impl ZbudPage {
    /// Create a new, empty zbud page.
    pub const fn new() -> Self {
        ZbudPage {
            buddy: [
                ZbudBuddy { size: 0, offset: 0 },
                ZbudBuddy { size: 0, offset: 0 },
            ],
            data: [0u8; ZBUD_DATA_SIZE],
            active: false,
        }
    }

    /// Return `true` if slot `s` (0 or 1) is occupied.
    pub fn is_occupied(&self, s: usize) -> bool {
        self.buddy[s].is_occupied()
    }

    /// Return `true` if both slots are occupied.
    pub fn is_full(&self) -> bool {
        self.buddy[0].is_occupied() && self.buddy[1].is_occupied()
    }

    /// Return `true` if neither slot is occupied.
    pub fn is_empty(&self) -> bool {
        !self.buddy[0].is_occupied() && !self.buddy[1].is_occupied()
    }

    /// Try to store a compressed object in an available slot.
    ///
    /// Buddy 0 occupies the low end of the data region; buddy 1 occupies
    /// the high end. Returns the slot index (0 or 1) on success.
    ///
    /// Returns `Err(OutOfMemory)` if both slots are occupied or the
    /// object is too large.
    pub fn alloc_slot(&mut self, data: &[u8]) -> Result<u8> {
        let size = data.len();
        if size == 0 || size > MAX_OBJECT_SIZE {
            return Err(Error::InvalidArgument);
        }
        let aligned = ZbudBuddy::aligned_size(size);

        // Try slot 0 (low end).
        if !self.buddy[0].is_occupied() {
            let offset = 0u16;
            let end = aligned;
            // Ensure no overlap with slot 1.
            if !self.buddy[1].is_occupied() || end <= self.buddy[1].offset as usize {
                self.buddy[0] = ZbudBuddy {
                    size: size as u16,
                    offset,
                };
                self.data[..size].copy_from_slice(data);
                return Ok(0);
            }
        }

        // Try slot 1 (high end).
        if !self.buddy[1].is_occupied() {
            let aligned_end = ZBUD_DATA_SIZE;
            let start = aligned_end.saturating_sub(aligned);
            // Ensure no overlap with slot 0.
            let slot0_end = if self.buddy[0].is_occupied() {
                ZbudBuddy::aligned_size(self.buddy[0].size as usize)
            } else {
                0
            };
            if start >= slot0_end {
                self.buddy[1] = ZbudBuddy {
                    size: size as u16,
                    offset: start as u16,
                };
                self.data[start..start + size].copy_from_slice(data);
                return Ok(1);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Read the compressed object stored in slot `s` into `out`.
    ///
    /// Returns `Err(InvalidArgument)` if the slot is empty or `out` is
    /// too small.
    pub fn read_slot(&self, s: usize, out: &mut [u8]) -> Result<usize> {
        let buddy = self.buddy[s];
        if !buddy.is_occupied() {
            return Err(Error::NotFound);
        }
        let size = buddy.size as usize;
        if out.len() < size {
            return Err(Error::InvalidArgument);
        }
        let offset = buddy.offset as usize;
        out[..size].copy_from_slice(&self.data[offset..offset + size]);
        Ok(size)
    }

    /// Free the compressed object in slot `s`.
    ///
    /// Returns `Err(NotFound)` if the slot is already empty.
    pub fn free_slot(&mut self, s: usize) -> Result<()> {
        if !self.buddy[s].is_occupied() {
            return Err(Error::NotFound);
        }
        let offset = self.buddy[s].offset as usize;
        let size = self.buddy[s].size as usize;
        // Zero out the object data.
        let end = (offset + size).min(ZBUD_DATA_SIZE);
        self.data[offset..end].fill(0);
        self.buddy[s] = ZbudBuddy::empty();
        Ok(())
    }

    /// Return the used bytes in this page.
    pub fn used_bytes(&self) -> usize {
        let s0 = if self.buddy[0].is_occupied() {
            self.buddy[0].size as usize
        } else {
            0
        };
        let s1 = if self.buddy[1].is_occupied() {
            self.buddy[1].size as usize
        } else {
            0
        };
        s0 + s1
    }
}

impl Default for ZbudPage {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// ZbudStats
// -------------------------------------------------------------------

/// Allocation statistics for a zbud pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ZbudStats {
    /// Total compressed objects currently stored.
    pub objects: u64,
    /// Total bytes of compressed data stored.
    pub compressed_bytes: u64,
    /// Total physical pages currently in the pool.
    pub pages_in_use: u64,
    /// Cumulative allocations since pool creation.
    pub total_allocs: u64,
    /// Cumulative frees since pool creation.
    pub total_frees: u64,
    /// Cumulative pages allocated from the backing allocator.
    pub pages_allocated: u64,
    /// Cumulative pages returned to the backing allocator.
    pub pages_freed: u64,
}

// -------------------------------------------------------------------
// ZbudPool
// -------------------------------------------------------------------

/// A zbud pool managing compressed page storage.
///
/// Internally maintains a fixed array of [`ZbudPage`] descriptors.
/// Objects are stored in buddy pairs within individual physical pages,
/// maximising storage density while keeping allocation O(1) amortized.
pub struct ZbudPool {
    /// Array of zbud page descriptors.
    pages: [ZbudPage; MAX_ZBUD_PAGES],
    /// Number of active zbud pages.
    page_count: usize,
    /// Statistics.
    stats: ZbudStats,
}

impl ZbudPool {
    /// Create a new, empty zbud pool.
    pub fn new() -> Self {
        ZbudPool {
            pages: core::array::from_fn(|_| ZbudPage::new()),
            page_count: 0,
            stats: ZbudStats::default(),
        }
    }

    /// Store a compressed object in the pool.
    ///
    /// First tries to buddy the object with an existing half-full page.
    /// If none are available, a new page is allocated.
    ///
    /// Returns an opaque [`ZbudHandle`] on success.
    pub fn alloc(&mut self, data: &[u8]) -> Result<ZbudHandle> {
        if data.len() > MAX_OBJECT_SIZE {
            return Err(Error::InvalidArgument);
        }

        // Try existing pages with a free slot.
        for i in 0..self.page_count {
            if !self.pages[i].is_full() && self.pages[i].active {
                if let Ok(slot) = self.pages[i].alloc_slot(data) {
                    self.stats.objects += 1;
                    self.stats.compressed_bytes += data.len() as u64;
                    self.stats.total_allocs += 1;
                    return Ok(ZbudHandle::new(i as u32, slot));
                }
            }
        }

        // Allocate a new zbud page.
        if self.page_count >= MAX_ZBUD_PAGES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.page_count;
        self.pages[idx].active = true;
        let slot = self.pages[idx].alloc_slot(data)?;
        self.page_count += 1;
        self.stats.objects += 1;
        self.stats.compressed_bytes += data.len() as u64;
        self.stats.total_allocs += 1;
        self.stats.pages_in_use += 1;
        self.stats.pages_allocated += 1;
        Ok(ZbudHandle::new(idx as u32, slot))
    }

    /// Read the compressed object identified by `handle` into `out`.
    ///
    /// Returns the number of bytes written on success.
    pub fn get(&self, handle: ZbudHandle, out: &mut [u8]) -> Result<usize> {
        if !handle.is_valid() {
            return Err(Error::InvalidArgument);
        }
        let idx = handle.page_idx() as usize;
        let slot = handle.slot() as usize;
        if idx >= self.page_count || !self.pages[idx].active {
            return Err(Error::NotFound);
        }
        self.pages[idx].read_slot(slot, out)
    }

    /// Free the compressed object identified by `handle`.
    pub fn free(&mut self, handle: ZbudHandle) -> Result<()> {
        if !handle.is_valid() {
            return Err(Error::InvalidArgument);
        }
        let idx = handle.page_idx() as usize;
        let slot = handle.slot() as usize;
        if idx >= self.page_count || !self.pages[idx].active {
            return Err(Error::NotFound);
        }
        let size_before = self.pages[idx].buddy[slot].size as u64;
        self.pages[idx].free_slot(slot)?;
        self.stats.objects = self.stats.objects.saturating_sub(1);
        self.stats.compressed_bytes = self.stats.compressed_bytes.saturating_sub(size_before);
        self.stats.total_frees += 1;

        // If the page is now empty, deactivate it.
        if self.pages[idx].is_empty() {
            self.pages[idx].active = false;
            self.stats.pages_in_use = self.stats.pages_in_use.saturating_sub(1);
            self.stats.pages_freed += 1;
        }
        Ok(())
    }

    /// Return a copy of the current pool statistics.
    pub fn stats(&self) -> ZbudStats {
        self.stats
    }

    /// Return the number of active zbud pages.
    pub fn page_count(&self) -> usize {
        self.page_count
    }

    /// Return the maximum object size this pool accepts.
    pub const fn max_object_size() -> usize {
        MAX_OBJECT_SIZE
    }

    /// Compute the approximate storage efficiency as a percentage.
    ///
    /// Returns `None` if no pages are in use.
    pub fn efficiency_percent(&self) -> Option<u32> {
        if self.stats.pages_in_use == 0 {
            return None;
        }
        let total_capacity = self.stats.pages_in_use * ZBUD_DATA_SIZE as u64;
        let used = self.stats.compressed_bytes;
        let pct = (used * 100 / total_capacity) as u32;
        Some(pct)
    }
}

impl Default for ZbudPool {
    fn default() -> Self {
        Self::new()
    }
}
