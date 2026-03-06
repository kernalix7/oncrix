// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! vmalloc address space management.
//!
//! The vmalloc address range is a region of kernel virtual address space
//! used for virtually-contiguous but physically-discontiguous allocations.
//! This module manages the free/used ranges within that space using a
//! simple free-list allocator.
//!
//! # Design
//!
//! ```text
//!  vmalloc virtual space [VMALLOC_START .. VMALLOC_END]
//!   ├─ FreeRegion [0..64 pages]
//!   ├─ UsedRegion [64..128 pages]  ← vmalloc allocation
//!   ├─ FreeRegion [128..256 pages]
//!   └─ ...
//! ```
//!
//! # Key Types
//!
//! - [`VmallocRegion`] — a region in vmalloc space (free or used)
//! - [`VmallocAddrSpace`] — the vmalloc address space allocator
//! - [`VmallocInfo`] — information about a vmalloc allocation
//!
//! Reference: Linux `mm/vmalloc.c`, `include/linux/vmalloc.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Start of vmalloc virtual address space.
const VMALLOC_START: u64 = 0xFFFF_C800_0000_0000;

/// End of vmalloc virtual address space.
const VMALLOC_END: u64 = 0xFFFF_C8FF_FFFF_FFFF;

/// Page size.
const PAGE_SIZE: u64 = 4096;

/// Maximum tracked regions.
const MAX_REGIONS: usize = 1024;

/// Guard page count between allocations.
const GUARD_PAGES: u64 = 1;

// -------------------------------------------------------------------
// VmallocRegion
// -------------------------------------------------------------------

/// State of a vmalloc region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegionState {
    /// Available for allocation.
    Free,
    /// Currently allocated.
    Used,
}

impl Default for RegionState {
    fn default() -> Self {
        Self::Free
    }
}

/// A region within the vmalloc address space.
#[derive(Debug, Clone, Copy)]
pub struct VmallocRegion {
    /// Virtual start address.
    start: u64,
    /// Size in bytes.
    size: u64,
    /// Region state.
    state: RegionState,
    /// Caller identifier (for debugging).
    caller_id: u32,
}

impl VmallocRegion {
    /// Create a new free region.
    pub const fn new_free(start: u64, size: u64) -> Self {
        Self {
            start,
            size,
            state: RegionState::Free,
            caller_id: 0,
        }
    }

    /// Create a new used region.
    pub const fn new_used(start: u64, size: u64, caller_id: u32) -> Self {
        Self {
            start,
            size,
            state: RegionState::Used,
            caller_id,
        }
    }

    /// Return the start address.
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// Return the end address (exclusive).
    pub const fn end(&self) -> u64 {
        self.start + self.size
    }

    /// Return the size.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Return the number of pages.
    pub const fn page_count(&self) -> u64 {
        self.size / PAGE_SIZE
    }

    /// Return the state.
    pub const fn state(&self) -> RegionState {
        self.state
    }

    /// Return the caller ID.
    pub const fn caller_id(&self) -> u32 {
        self.caller_id
    }

    /// Check whether this region is free.
    pub const fn is_free(&self) -> bool {
        matches!(self.state, RegionState::Free)
    }
}

impl Default for VmallocRegion {
    fn default() -> Self {
        Self::new_free(0, 0)
    }
}

// -------------------------------------------------------------------
// VmallocInfo
// -------------------------------------------------------------------

/// Information about a vmalloc allocation.
#[derive(Debug, Clone, Copy)]
pub struct VmallocInfo {
    /// Virtual base address.
    pub virt_addr: u64,
    /// Allocation size.
    pub size: u64,
    /// Number of physical pages backing this allocation.
    pub phys_pages: u64,
    /// Caller ID.
    pub caller_id: u32,
}

// -------------------------------------------------------------------
// VmallocAddrSpace
// -------------------------------------------------------------------

/// The vmalloc address space allocator.
pub struct VmallocAddrSpace {
    /// Region descriptors.
    regions: [VmallocRegion; MAX_REGIONS],
    /// Number of valid regions.
    count: usize,
    /// Total bytes allocated.
    total_allocated: u64,
    /// Peak bytes allocated.
    peak_allocated: u64,
}

impl VmallocAddrSpace {
    /// Create a new vmalloc address space with one free region.
    pub const fn new() -> Self {
        let mut regions = [const { VmallocRegion::new_free(0, 0) }; MAX_REGIONS];
        regions[0] = VmallocRegion::new_free(VMALLOC_START, VMALLOC_END - VMALLOC_START);
        Self {
            regions,
            count: 1,
            total_allocated: 0,
            peak_allocated: 0,
        }
    }

    /// Return the number of regions tracked.
    pub const fn region_count(&self) -> usize {
        self.count
    }

    /// Return total bytes currently allocated.
    pub const fn total_allocated(&self) -> u64 {
        self.total_allocated
    }

    /// Return peak allocation.
    pub const fn peak_allocated(&self) -> u64 {
        self.peak_allocated
    }

    /// Align size up to a page boundary plus guard pages.
    fn alloc_size(requested: u64) -> u64 {
        let pages = (requested + PAGE_SIZE - 1) / PAGE_SIZE + GUARD_PAGES;
        pages * PAGE_SIZE
    }

    /// Allocate a region of vmalloc space (first-fit).
    pub fn alloc(&mut self, size: u64, caller_id: u32) -> Result<u64> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        let needed = Self::alloc_size(size);

        // Find first free region that fits.
        let mut found_idx = None;
        for idx in 0..self.count {
            if self.regions[idx].is_free() && self.regions[idx].size() >= needed {
                found_idx = Some(idx);
                break;
            }
        }

        let idx = found_idx.ok_or(Error::OutOfMemory)?;
        let region_start = self.regions[idx].start();
        let region_size = self.regions[idx].size();

        // Split: used + remaining free.
        self.regions[idx] = VmallocRegion::new_used(region_start, needed, caller_id);

        let leftover = region_size - needed;
        if leftover > 0 && self.count < MAX_REGIONS {
            // Insert remaining free region after the used one.
            // Shift entries up.
            let insert_at = idx + 1;
            let mut pos = self.count;
            while pos > insert_at {
                self.regions[pos] = self.regions[pos - 1];
                pos -= 1;
            }
            self.regions[insert_at] = VmallocRegion::new_free(region_start + needed, leftover);
            self.count += 1;
        }

        self.total_allocated += needed;
        if self.total_allocated > self.peak_allocated {
            self.peak_allocated = self.total_allocated;
        }

        Ok(region_start)
    }

    /// Free a previously allocated region.
    pub fn free(&mut self, virt_addr: u64) -> Result<u64> {
        for idx in 0..self.count {
            if self.regions[idx].start() == virt_addr && !self.regions[idx].is_free() {
                let size = self.regions[idx].size();
                self.regions[idx] = VmallocRegion::new_free(virt_addr, size);
                self.total_allocated = self.total_allocated.saturating_sub(size);
                self.coalesce(idx);
                return Ok(size);
            }
        }
        Err(Error::NotFound)
    }

    /// Coalesce adjacent free regions around `idx`.
    fn coalesce(&mut self, idx: usize) {
        // Merge with next.
        if idx + 1 < self.count && self.regions[idx].is_free() && self.regions[idx + 1].is_free() {
            let merged_size = self.regions[idx].size() + self.regions[idx + 1].size();
            self.regions[idx] = VmallocRegion::new_free(self.regions[idx].start(), merged_size);
            // Remove idx+1.
            let mut pos = idx + 1;
            while pos + 1 < self.count {
                self.regions[pos] = self.regions[pos + 1];
                pos += 1;
            }
            self.count -= 1;
        }
        // Merge with previous.
        if idx > 0 && self.regions[idx - 1].is_free() && self.regions[idx].is_free() {
            let merged_size = self.regions[idx - 1].size() + self.regions[idx].size();
            self.regions[idx - 1] =
                VmallocRegion::new_free(self.regions[idx - 1].start(), merged_size);
            let mut pos = idx;
            while pos + 1 < self.count {
                self.regions[pos] = self.regions[pos + 1];
                pos += 1;
            }
            self.count -= 1;
        }
    }

    /// Look up information about an allocation.
    pub fn lookup(&self, virt_addr: u64) -> Option<VmallocInfo> {
        for idx in 0..self.count {
            let r = &self.regions[idx];
            if !r.is_free() && virt_addr >= r.start() && virt_addr < r.end() {
                return Some(VmallocInfo {
                    virt_addr: r.start(),
                    size: r.size(),
                    phys_pages: r.page_count(),
                    caller_id: r.caller_id(),
                });
            }
        }
        None
    }
}

impl Default for VmallocAddrSpace {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Allocate vmalloc space and return the virtual address.
pub fn vmalloc_alloc(space: &mut VmallocAddrSpace, size: u64) -> Result<u64> {
    space.alloc(size, 0)
}

/// Free vmalloc space.
pub fn vmalloc_free(space: &mut VmallocAddrSpace, virt_addr: u64) -> Result<u64> {
    space.free(virt_addr)
}

/// Return a summary of vmalloc space usage.
pub fn vmalloc_summary(space: &VmallocAddrSpace) -> &'static str {
    let usage_pct = if VMALLOC_END > VMALLOC_START {
        space.total_allocated() * 100 / (VMALLOC_END - VMALLOC_START)
    } else {
        0
    };
    if usage_pct > 90 {
        "vmalloc space: critical (>90%)"
    } else if usage_pct > 50 {
        "vmalloc space: moderate"
    } else {
        "vmalloc space: healthy"
    }
}
