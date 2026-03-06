// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Vmalloc statistics and diagnostics.
//!
//! The vmalloc subsystem allocates virtually contiguous but physically
//! non-contiguous kernel memory. This module tracks usage statistics,
//! fragmentation, and provides diagnostic information similar to
//! `/proc/vmallocinfo` in Linux.
//!
//! # Design
//!
//! ```text
//!  vmalloc() ──→ VmallocStatTracker::record_alloc(addr, size, caller)
//!  vfree()   ──→ VmallocStatTracker::record_free(addr)
//!
//!  /proc/vmallocinfo ──→ VmallocStatTracker::dump()
//! ```
//!
//! # Key Types
//!
//! - [`VmallocRegion`] — describes a single vmalloc allocation
//! - [`VmallocStatTracker`] — tracks all vmalloc allocations
//! - [`VmallocSummary`] — aggregate statistics
//! - [`VmallocFragInfo`] — fragmentation information
//!
//! Reference: Linux `mm/vmalloc.c`, `/proc/vmallocinfo`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum tracked vmalloc regions.
const MAX_REGIONS: usize = 2048;

/// Page size.
const PAGE_SIZE: u64 = 4096;

/// Vmalloc address space start (typical x86_64).
const VMALLOC_START: u64 = 0xFFFF_C900_0000_0000;

/// Vmalloc address space end.
const VMALLOC_END: u64 = 0xFFFF_E8FF_FFFF_FFFF;

// -------------------------------------------------------------------
// VmallocRegionType
// -------------------------------------------------------------------

/// Type of vmalloc allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmallocRegionType {
    /// Standard vmalloc allocation.
    Vmalloc,
    /// ioremap mapping.
    Ioremap,
    /// Module mapping.
    Module,
    /// vmap of existing pages.
    Vmap,
    /// User-space mapping via vmap.
    UserMap,
}

impl VmallocRegionType {
    /// Return a label for the region type.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Vmalloc => "vmalloc",
            Self::Ioremap => "ioremap",
            Self::Module => "module",
            Self::Vmap => "vmap",
            Self::UserMap => "user_map",
        }
    }
}

// -------------------------------------------------------------------
// VmallocRegion
// -------------------------------------------------------------------

/// Describes a single vmalloc allocation.
#[derive(Debug, Clone, Copy)]
pub struct VmallocRegion {
    /// Virtual address of the allocation.
    addr: u64,
    /// Size in bytes.
    size: u64,
    /// Number of physical pages backing this region.
    nr_pages: u32,
    /// Type of allocation.
    region_type: VmallocRegionType,
    /// Whether the region is currently allocated.
    active: bool,
    /// Caller identifier (e.g. function address).
    caller_id: u64,
}

impl VmallocRegion {
    /// Create a new region descriptor.
    pub const fn new(addr: u64, size: u64, region_type: VmallocRegionType, caller_id: u64) -> Self {
        let nr_pages = ((size + PAGE_SIZE - 1) / PAGE_SIZE) as u32;
        Self {
            addr,
            size,
            nr_pages,
            region_type,
            active: true,
            caller_id,
        }
    }

    /// Return the virtual address.
    pub const fn addr(&self) -> u64 {
        self.addr
    }

    /// Return the size in bytes.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Return the number of physical pages.
    pub const fn nr_pages(&self) -> u32 {
        self.nr_pages
    }

    /// Return the region type.
    pub const fn region_type(&self) -> VmallocRegionType {
        self.region_type
    }

    /// Check whether the region is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Return the caller identifier.
    pub const fn caller_id(&self) -> u64 {
        self.caller_id
    }

    /// Mark the region as freed.
    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl Default for VmallocRegion {
    fn default() -> Self {
        Self {
            addr: 0,
            size: 0,
            nr_pages: 0,
            region_type: VmallocRegionType::Vmalloc,
            active: false,
            caller_id: 0,
        }
    }
}

// -------------------------------------------------------------------
// VmallocSummary
// -------------------------------------------------------------------

/// Aggregate vmalloc statistics.
#[derive(Debug, Clone, Copy)]
pub struct VmallocSummary {
    /// Total active allocations.
    pub active_count: u64,
    /// Total bytes in active allocations.
    pub active_bytes: u64,
    /// Total physical pages backing active allocations.
    pub active_pages: u64,
    /// Total allocations ever made.
    pub total_allocs: u64,
    /// Total frees ever made.
    pub total_frees: u64,
    /// Allocation failures.
    pub alloc_failures: u64,
}

impl VmallocSummary {
    /// Create zero summary.
    pub const fn new() -> Self {
        Self {
            active_count: 0,
            active_bytes: 0,
            active_pages: 0,
            total_allocs: 0,
            total_frees: 0,
            alloc_failures: 0,
        }
    }

    /// Average allocation size in bytes (0 if none).
    pub const fn avg_alloc_size(&self) -> u64 {
        if self.active_count == 0 {
            return 0;
        }
        self.active_bytes / self.active_count
    }
}

impl Default for VmallocSummary {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// VmallocFragInfo
// -------------------------------------------------------------------

/// Fragmentation information for the vmalloc address space.
#[derive(Debug, Clone, Copy)]
pub struct VmallocFragInfo {
    /// Total address space available (bytes).
    pub total_space: u64,
    /// Currently used space (bytes).
    pub used_space: u64,
    /// Largest contiguous free block (bytes).
    pub largest_free: u64,
    /// Number of free gaps.
    pub free_gaps: u32,
}

impl VmallocFragInfo {
    /// Create empty fragmentation info.
    pub const fn new() -> Self {
        Self {
            total_space: VMALLOC_END - VMALLOC_START,
            used_space: 0,
            largest_free: VMALLOC_END - VMALLOC_START,
            free_gaps: 1,
        }
    }

    /// Fragmentation percentage (0 = no fragmentation).
    pub const fn fragmentation_pct(&self) -> u64 {
        if self.total_space == 0 {
            return 0;
        }
        let free = self.total_space - self.used_space;
        if free == 0 {
            return 100;
        }
        // If largest_free == total_free then 0% fragmentation.
        (free - self.largest_free) * 100 / free
    }
}

impl Default for VmallocFragInfo {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// VmallocStatTracker
// -------------------------------------------------------------------

/// Tracks all vmalloc allocations for statistics and diagnostics.
pub struct VmallocStatTracker {
    /// Tracked regions.
    regions: [VmallocRegion; MAX_REGIONS],
    /// Number of valid entries.
    count: usize,
    /// Summary statistics.
    summary: VmallocSummary,
}

impl VmallocStatTracker {
    /// Create a new tracker.
    pub const fn new() -> Self {
        Self {
            regions: [const {
                VmallocRegion {
                    addr: 0,
                    size: 0,
                    nr_pages: 0,
                    region_type: VmallocRegionType::Vmalloc,
                    active: false,
                    caller_id: 0,
                }
            }; MAX_REGIONS],
            count: 0,
            summary: VmallocSummary::new(),
        }
    }

    /// Return the number of tracked regions.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return the summary.
    pub const fn summary(&self) -> &VmallocSummary {
        &self.summary
    }

    /// Record a new vmalloc allocation.
    pub fn record_alloc(
        &mut self,
        addr: u64,
        size: u64,
        region_type: VmallocRegionType,
        caller_id: u64,
    ) -> Result<()> {
        if self.count >= MAX_REGIONS {
            self.summary.alloc_failures += 1;
            return Err(Error::OutOfMemory);
        }
        let region = VmallocRegion::new(addr, size, region_type, caller_id);
        self.regions[self.count] = region;
        self.count += 1;
        self.summary.active_count += 1;
        self.summary.active_bytes += size;
        self.summary.active_pages += region.nr_pages() as u64;
        self.summary.total_allocs += 1;
        Ok(())
    }

    /// Record a vmalloc free.
    pub fn record_free(&mut self, addr: u64) -> Result<()> {
        for idx in 0..self.count {
            if self.regions[idx].is_active() && self.regions[idx].addr() == addr {
                let size = self.regions[idx].size();
                let pages = self.regions[idx].nr_pages() as u64;
                self.regions[idx].deactivate();
                self.summary.active_count = self.summary.active_count.saturating_sub(1);
                self.summary.active_bytes = self.summary.active_bytes.saturating_sub(size);
                self.summary.active_pages = self.summary.active_pages.saturating_sub(pages);
                self.summary.total_frees += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Find a region by address.
    pub fn find(&self, addr: u64) -> Option<&VmallocRegion> {
        for idx in 0..self.count {
            if self.regions[idx].is_active() && self.regions[idx].addr() == addr {
                return Some(&self.regions[idx]);
            }
        }
        None
    }
}

impl Default for VmallocStatTracker {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Compute fragmentation info from a tracker.
pub fn compute_fragmentation(tracker: &VmallocStatTracker) -> VmallocFragInfo {
    let mut info = VmallocFragInfo::new();
    info.used_space = tracker.summary().active_bytes;
    info.largest_free = info.total_space.saturating_sub(info.used_space);
    info.free_gaps = if tracker.summary().active_count > 0 {
        (tracker.summary().active_count + 1) as u32
    } else {
        1
    };
    info
}

/// Check whether an address falls in the vmalloc range.
pub const fn is_vmalloc_addr(addr: u64) -> bool {
    addr >= VMALLOC_START && addr < VMALLOC_END
}

/// Return the total vmalloc address space size.
pub const fn vmalloc_space_size() -> u64 {
    VMALLOC_END - VMALLOC_START
}
