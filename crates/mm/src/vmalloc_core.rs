// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Core vmalloc area management.
//!
//! Manages the kernel virtual address space used for vmalloc
//! allocations. Tracks allocated and free areas, handles area
//! splitting and merging, and provides the core alloc/free path.
//!
//! - [`VmallocArea`] — a vmalloc area descriptor
//! - [`VmallocAreaFlags`] — area type flags
//! - [`VmallocStats`] — allocation statistics
//! - [`VmallocCore`] — the vmalloc area manager
//!
//! Reference: Linux `mm/vmalloc.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum tracked vmalloc areas.
const MAX_AREAS: usize = 256;

/// Default vmalloc space start address.
const VMALLOC_START: u64 = 0xFFFF_C900_0000_0000;

/// Default vmalloc space end address.
const VMALLOC_END: u64 = 0xFFFF_E8FF_FFFF_FFFF;

/// Guard page between allocations.
const GUARD_SIZE: u64 = PAGE_SIZE;

// -------------------------------------------------------------------
// VmallocAreaFlags
// -------------------------------------------------------------------

/// Flags describing a vmalloc area.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VmallocAreaFlags {
    /// Raw flag bits.
    bits: u32,
}

impl VmallocAreaFlags {
    /// Standard vmalloc allocation.
    pub const VM_ALLOC: u32 = 1 << 0;
    /// Mapped I/O region.
    pub const VM_IOREMAP: u32 = 1 << 1;
    /// User-space mapping.
    pub const VM_USERMAP: u32 = 1 << 2;
    /// DMA coherent region.
    pub const VM_DMA_COHERENT: u32 = 1 << 3;

    /// Creates empty flags.
    pub fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Creates from raw bits.
    pub fn from_bits(bits: u32) -> Self {
        Self { bits }
    }

    /// Tests a flag.
    pub fn contains(self, flag: u32) -> bool {
        self.bits & flag == flag
    }

    /// Sets a flag.
    pub fn set(self, flag: u32) -> Self {
        Self {
            bits: self.bits | flag,
        }
    }
}

// -------------------------------------------------------------------
// VmallocArea
// -------------------------------------------------------------------

/// A vmalloc area descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmallocArea {
    /// Virtual start address.
    pub addr: u64,
    /// Size in bytes (excluding guard page).
    pub size: u64,
    /// Area flags.
    pub flags: VmallocAreaFlags,
    /// Number of pages backing this area.
    pub nr_pages: u64,
    /// Caller address (for debugging).
    pub caller: u64,
    /// Whether this area is active.
    pub active: bool,
}

impl VmallocArea {
    /// Creates a new vmalloc area.
    pub fn new(addr: u64, size: u64, flags: VmallocAreaFlags) -> Self {
        Self {
            addr,
            size,
            flags,
            nr_pages: (size + PAGE_SIZE - 1) / PAGE_SIZE,
            caller: 0,
            active: true,
        }
    }

    /// Returns the end address (exclusive, including guard).
    pub fn end(&self) -> u64 {
        self.addr
            .saturating_add(self.size)
            .saturating_add(GUARD_SIZE)
    }

    /// Returns `true` if this area overlaps the given range.
    pub fn overlaps(&self, addr: u64, size: u64) -> bool {
        self.active && self.addr < addr.saturating_add(size) && addr < self.end()
    }
}

// -------------------------------------------------------------------
// VmallocStats
// -------------------------------------------------------------------

/// Vmalloc allocation statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmallocStats {
    /// Total allocations.
    pub allocs: u64,
    /// Total frees.
    pub frees: u64,
    /// Total bytes allocated.
    pub bytes_allocated: u64,
    /// Total bytes freed.
    pub bytes_freed: u64,
    /// Allocation failures.
    pub alloc_failures: u64,
    /// Current active areas.
    pub active_areas: u64,
}

impl VmallocStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// VmallocCore
// -------------------------------------------------------------------

/// The vmalloc area manager.
pub struct VmallocCore {
    /// Tracked areas.
    areas: [VmallocArea; MAX_AREAS],
    /// Number of areas.
    count: usize,
    /// Next allocation address.
    next_addr: u64,
    /// Statistics.
    stats: VmallocStats,
}

impl Default for VmallocCore {
    fn default() -> Self {
        Self {
            areas: [VmallocArea::default(); MAX_AREAS],
            count: 0,
            next_addr: VMALLOC_START,
            stats: VmallocStats::default(),
        }
    }
}

impl VmallocCore {
    /// Creates a new vmalloc core manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocates a vmalloc area of the given size.
    pub fn alloc(&mut self, size: u64, flags: VmallocAreaFlags) -> Result<u64> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let total_size = aligned_size + GUARD_SIZE;

        if self.count >= MAX_AREAS {
            self.stats.alloc_failures += 1;
            return Err(Error::OutOfMemory);
        }

        if self.next_addr.saturating_add(total_size) > VMALLOC_END {
            self.stats.alloc_failures += 1;
            return Err(Error::OutOfMemory);
        }

        let addr = self.next_addr;
        self.next_addr = self.next_addr.saturating_add(total_size);

        let idx = self.count;
        self.areas[idx] = VmallocArea::new(addr, aligned_size, flags);
        self.count += 1;

        self.stats.allocs += 1;
        self.stats.bytes_allocated += aligned_size;
        self.stats.active_areas += 1;
        Ok(addr)
    }

    /// Frees a vmalloc area by address.
    pub fn free(&mut self, addr: u64) -> Result<()> {
        for i in 0..self.count {
            if self.areas[i].active && self.areas[i].addr == addr {
                self.areas[i].active = false;
                self.stats.frees += 1;
                self.stats.bytes_freed += self.areas[i].size;
                if self.stats.active_areas > 0 {
                    self.stats.active_areas -= 1;
                }
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Looks up a vmalloc area by address.
    pub fn find(&self, addr: u64) -> Option<&VmallocArea> {
        for i in 0..self.count {
            if self.areas[i].active && self.areas[i].addr == addr {
                return Some(&self.areas[i]);
            }
        }
        None
    }

    /// Returns the total number of areas.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns statistics.
    pub fn stats(&self) -> &VmallocStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
