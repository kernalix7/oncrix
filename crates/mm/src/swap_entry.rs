// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Swap entry management.
//!
//! Implements swap entry encoding/decoding and swap device bookkeeping.
//! A [`SwapEntry`] packs a swap device type and page offset into a
//! single u64 for storage in page table entries. Each swap device is
//! described by [`SwapInfo`] which tracks capacity, usage, and priority.
//!
//! - [`SwapEntry`] — encoded swap location
//! - [`SwapInfo`] — per-device swap state
//! - [`SwapAllocator`] — swap slot allocator
//! - [`SwapStats`] — global swap statistics
//!
//! Reference: `.kernelORG/` — `include/linux/swapops.h`, `mm/swapfile.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of swap devices.
const MAX_SWAP_DEVICES: usize = 8;

/// Bits reserved for swap type.
const SWAP_TYPE_BITS: u32 = 8;

/// Mask for swap type.
const SWAP_TYPE_MASK: u64 = (1u64 << SWAP_TYPE_BITS) - 1;

/// Bits reserved for swap offset.
const SWAP_OFFSET_BITS: u32 = 56;

/// Maximum swap offset.
const MAX_SWAP_OFFSET: u64 = (1u64 << SWAP_OFFSET_BITS) - 1;

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum pages per swap device.
const MAX_PAGES_PER_DEVICE: u64 = 1 << 20; // 1M pages = 4 GiB

/// Bitmap size for swap slot tracking (pages / 64).
const BITMAP_SIZE: usize = (MAX_PAGES_PER_DEVICE as usize) / 64;

/// Invalid swap type sentinel.
const SWAP_TYPE_NONE: u8 = 0xFF;

// -------------------------------------------------------------------
// SwapEntry
// -------------------------------------------------------------------

/// An encoded swap entry: (type, offset) packed into u64.
///
/// Layout: `[63:8] offset | [7:0] type`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SwapEntry(u64);

impl SwapEntry {
    /// Creates a swap entry from type and offset.
    pub fn new(swap_type: u8, offset: u64) -> Result<Self> {
        if offset > MAX_SWAP_OFFSET {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(((offset) << SWAP_TYPE_BITS) | (swap_type as u64)))
    }

    /// Creates a swap entry from a raw u64.
    pub fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw packed value.
    pub fn to_raw(self) -> u64 {
        self.0
    }

    /// Extracts the swap device type.
    pub fn swp_type(self) -> u8 {
        (self.0 & SWAP_TYPE_MASK) as u8
    }

    /// Extracts the swap offset (in pages).
    pub fn swp_offset(self) -> u64 {
        self.0 >> SWAP_TYPE_BITS
    }

    /// Returns true if this is a null/invalid entry.
    pub fn is_null(self) -> bool {
        self.0 == 0
    }

    /// Returns a null swap entry.
    pub fn null() -> Self {
        Self(0)
    }

    /// Returns the byte offset within the swap device.
    pub fn byte_offset(self) -> u64 {
        self.swp_offset() * PAGE_SIZE
    }
}

/// Constructs a swap entry (convenience function matching Linux API).
pub fn swp_entry(swap_type: u8, offset: u64) -> Result<SwapEntry> {
    SwapEntry::new(swap_type, offset)
}

/// Extracts swap type from an entry.
pub fn swp_type(entry: SwapEntry) -> u8 {
    entry.swp_type()
}

/// Extracts swap offset from an entry.
pub fn swp_offset(entry: SwapEntry) -> u64 {
    entry.swp_offset()
}

// -------------------------------------------------------------------
// SwapPriority
// -------------------------------------------------------------------

/// Swap device priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct SwapPriority(i16);

impl SwapPriority {
    /// Creates a new priority value.
    pub fn new(val: i16) -> Self {
        Self(val)
    }

    /// Returns the raw priority value.
    pub fn value(self) -> i16 {
        self.0
    }

    /// Default (automatic) priority.
    pub fn auto_priority() -> Self {
        Self(-1)
    }
}

// -------------------------------------------------------------------
// SwapInfo
// -------------------------------------------------------------------

/// Per-device swap information.
#[derive(Debug, Clone)]
pub struct SwapInfo {
    /// Swap device type index.
    pub swap_type: u8,
    /// Total pages in this swap area.
    pub pages: u64,
    /// Number of pages currently in use.
    pub inuse_pages: u64,
    /// Priority (higher = preferred).
    pub priority: SwapPriority,
    /// Whether the device is active.
    pub active: bool,
    /// Allocation bitmap (1 = used).
    bitmap: [u64; BITMAP_SIZE],
    /// Next offset to try for allocation.
    next_offset: u64,
    /// Number of allocation failures.
    pub alloc_failures: u64,
}

impl SwapInfo {
    /// Creates a new swap info for a device.
    pub fn new(swap_type: u8, pages: u64, priority: SwapPriority) -> Self {
        Self {
            swap_type,
            pages: pages.min(MAX_PAGES_PER_DEVICE),
            inuse_pages: 0,
            priority,
            active: true,
            bitmap: [0u64; BITMAP_SIZE],
            next_offset: 0,
            alloc_failures: 0,
        }
    }

    /// Returns the number of free pages.
    pub fn free_pages(&self) -> u64 {
        self.pages.saturating_sub(self.inuse_pages)
    }

    /// Returns usage as a percentage (0-100).
    pub fn usage_pct(&self) -> u64 {
        if self.pages == 0 {
            return 0;
        }
        self.inuse_pages * 100 / self.pages
    }

    /// Checks if a specific offset is free.
    fn is_offset_free(&self, offset: u64) -> bool {
        if offset >= self.pages {
            return false;
        }
        let word = (offset / 64) as usize;
        let bit = offset % 64;
        if word >= BITMAP_SIZE {
            return false;
        }
        self.bitmap[word] & (1u64 << bit) == 0
    }

    /// Marks an offset as used.
    fn mark_used(&mut self, offset: u64) {
        let word = (offset / 64) as usize;
        let bit = offset % 64;
        if word < BITMAP_SIZE {
            self.bitmap[word] |= 1u64 << bit;
            self.inuse_pages += 1;
        }
    }

    /// Marks an offset as free.
    fn mark_free(&mut self, offset: u64) {
        let word = (offset / 64) as usize;
        let bit = offset % 64;
        if word < BITMAP_SIZE {
            self.bitmap[word] &= !(1u64 << bit);
            self.inuse_pages = self.inuse_pages.saturating_sub(1);
        }
    }

    /// Allocates a swap slot, returning the offset.
    fn alloc_slot(&mut self) -> Option<u64> {
        if self.inuse_pages >= self.pages {
            self.alloc_failures += 1;
            return None;
        }

        // Scan from next_offset.
        let start = self.next_offset;
        let mut offset = start;
        loop {
            if self.is_offset_free(offset) {
                self.mark_used(offset);
                self.next_offset = (offset + 1) % self.pages;
                return Some(offset);
            }
            offset = (offset + 1) % self.pages;
            if offset == start {
                break; // Full scan, no free slot.
            }
        }

        self.alloc_failures += 1;
        None
    }
}

impl Default for SwapInfo {
    fn default() -> Self {
        Self {
            swap_type: SWAP_TYPE_NONE,
            pages: 0,
            inuse_pages: 0,
            priority: SwapPriority::auto_priority(),
            active: false,
            bitmap: [0u64; BITMAP_SIZE],
            next_offset: 0,
            alloc_failures: 0,
        }
    }
}

// -------------------------------------------------------------------
// SwapStats
// -------------------------------------------------------------------

/// Global swap statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct SwapStats {
    /// Total swap pages across all devices.
    pub total_pages: u64,
    /// Total used swap pages.
    pub used_pages: u64,
    /// Total swap allocations.
    pub total_allocs: u64,
    /// Total swap frees.
    pub total_frees: u64,
    /// Allocation failures.
    pub alloc_failures: u64,
    /// Number of active swap devices.
    pub nr_active_devices: u32,
}

impl SwapStats {
    /// Returns total free swap pages.
    pub fn free_pages(&self) -> u64 {
        self.total_pages.saturating_sub(self.used_pages)
    }

    /// Returns usage percentage (0-100).
    pub fn usage_pct(&self) -> u64 {
        if self.total_pages == 0 {
            return 0;
        }
        self.used_pages * 100 / self.total_pages
    }
}

// -------------------------------------------------------------------
// SwapAllocator
// -------------------------------------------------------------------

/// Swap slot allocator.
///
/// Manages multiple swap devices and allocates/frees swap entries.
/// Devices are tried in priority order.
pub struct SwapAllocator {
    /// Per-device swap info.
    devices: [SwapInfo; MAX_SWAP_DEVICES],
    /// Number of registered devices.
    nr_devices: usize,
    /// Global statistics.
    stats: SwapStats,
}

impl SwapAllocator {
    /// Creates a new swap allocator.
    pub fn new() -> Self {
        Self {
            devices: [
                SwapInfo::default(),
                SwapInfo::default(),
                SwapInfo::default(),
                SwapInfo::default(),
                SwapInfo::default(),
                SwapInfo::default(),
                SwapInfo::default(),
                SwapInfo::default(),
            ],
            nr_devices: 0,
            stats: SwapStats::default(),
        }
    }

    /// Registers a swap device.
    pub fn add_device(&mut self, pages: u64, priority: SwapPriority) -> Result<u8> {
        if self.nr_devices >= MAX_SWAP_DEVICES {
            return Err(Error::OutOfMemory);
        }
        let swap_type = self.nr_devices as u8;
        self.devices[self.nr_devices] = SwapInfo::new(swap_type, pages, priority);
        self.nr_devices += 1;
        self.stats.total_pages += pages.min(MAX_PAGES_PER_DEVICE);
        self.stats.nr_active_devices += 1;
        Ok(swap_type)
    }

    /// Allocates a swap page, returning a swap entry.
    ///
    /// Tries devices in priority order (highest first).
    pub fn get_swap_page(&mut self) -> Result<SwapEntry> {
        // Sort device indices by priority (highest first).
        let mut indices: [usize; MAX_SWAP_DEVICES] = [0, 1, 2, 3, 4, 5, 6, 7];
        // Simple insertion sort by priority (descending).
        for i in 1..self.nr_devices {
            let mut j = i;
            while j > 0 && self.devices[indices[j]].priority > self.devices[indices[j - 1]].priority
            {
                indices.swap(j, j - 1);
                j -= 1;
            }
        }

        for &idx in &indices[..self.nr_devices] {
            if !self.devices[idx].active {
                continue;
            }
            if let Some(offset) = self.devices[idx].alloc_slot() {
                self.stats.used_pages += 1;
                self.stats.total_allocs += 1;
                return SwapEntry::new(self.devices[idx].swap_type, offset);
            }
        }

        self.stats.alloc_failures += 1;
        Err(Error::OutOfMemory)
    }

    /// Frees a swap entry.
    pub fn swap_entry_free(&mut self, entry: SwapEntry) -> Result<()> {
        let swap_type = entry.swp_type() as usize;
        let offset = entry.swp_offset();

        if swap_type >= self.nr_devices {
            return Err(Error::InvalidArgument);
        }

        self.devices[swap_type].mark_free(offset);
        self.stats.used_pages = self.stats.used_pages.saturating_sub(1);
        self.stats.total_frees += 1;
        Ok(())
    }

    /// Returns the swap info for a device.
    pub fn device_info(&self, swap_type: u8) -> Option<&SwapInfo> {
        let idx = swap_type as usize;
        if idx >= self.nr_devices {
            return None;
        }
        Some(&self.devices[idx])
    }

    /// Returns global swap statistics.
    pub fn stats(&self) -> &SwapStats {
        &self.stats
    }

    /// Returns the number of registered devices.
    pub fn nr_devices(&self) -> usize {
        self.nr_devices
    }
}

impl Default for SwapAllocator {
    fn default() -> Self {
        Self::new()
    }
}
