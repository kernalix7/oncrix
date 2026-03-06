// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel vmalloc allocator for virtually contiguous memory.
//!
//! Allocates virtually contiguous but physically non-contiguous
//! memory regions in the kernel's vmalloc address range. Each
//! allocation maps individual physical pages into a contiguous
//! virtual range, making it suitable for large allocations where
//! physically contiguous memory is not required.
//!
//! - [`VmallocArea`] — descriptor for a vmalloc region
//! - [`VmallocAllocator`] — main allocator managing the vmalloc space
//! - [`VmallocStats`] — allocation statistics and memory usage
//!
//! Reference: `.kernelORG/` — `mm/vmalloc.c`, `include/linux/vmalloc.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Start of the vmalloc virtual address range.
const VMALLOC_START: u64 = 0xFFFF_C900_0000_0000;

/// End of the vmalloc virtual address range.
const VMALLOC_END: u64 = 0xFFFF_E8FF_FFFF_FFFF;

/// Guard page size (inserted between vmalloc areas).
const GUARD_SIZE: u64 = PAGE_SIZE;

/// Maximum number of vmalloc areas.
const MAX_AREAS: usize = 256;

/// Maximum number of pages per vmalloc area.
const MAX_PAGES_PER_AREA: usize = 64;

/// Maximum total pages tracked by the allocator.
const MAX_TOTAL_PAGES: usize = 1024;

// -------------------------------------------------------------------
// VmallocFlags
// -------------------------------------------------------------------

/// Flags describing a vmalloc area type.
pub struct VmallocFlags;

impl VmallocFlags {
    /// Area allocated via vmalloc().
    pub const VM_ALLOC: u32 = 1 << 0;
    /// Area created by mapping existing pages.
    pub const VM_MAP: u32 = 1 << 1;
    /// Area created via ioremap().
    pub const VM_IOREMAP: u32 = 1 << 2;
    /// Area is user-mappable.
    pub const VM_USERMAP: u32 = 1 << 3;
    /// Area uses huge pages.
    pub const VM_HUGE: u32 = 1 << 4;
    /// Area is no-cache (uncacheable mapping).
    pub const VM_NO_CACHE: u32 = 1 << 5;
}

// -------------------------------------------------------------------
// PageEntry
// -------------------------------------------------------------------

/// Tracks a physical page backing a vmalloc area.
#[derive(Debug, Clone, Copy, Default)]
pub struct PageEntry {
    /// Physical frame number (PFN).
    pub pfn: u64,
    /// Virtual address this page is mapped at.
    pub virt_addr: u64,
    /// Whether this entry is in use.
    pub active: bool,
}

impl PageEntry {
    /// Create an empty page entry.
    pub const fn empty() -> Self {
        Self {
            pfn: 0,
            virt_addr: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// VmallocArea
// -------------------------------------------------------------------

/// Descriptor for a single vmalloc region.
#[derive(Debug, Clone, Copy)]
pub struct VmallocArea {
    /// Virtual start address.
    pub va_start: u64,
    /// Size of the area in bytes (not including guard pages).
    pub size: u64,
    /// Flags describing the area type.
    pub flags: u32,
    /// Number of physical pages backing this area.
    pub nr_pages: u32,
    /// Index of the first page entry in the global page table.
    pub page_start_idx: u32,
    /// Caller return address (for debugging).
    pub caller: u64,
    /// Whether this area is active.
    pub active: bool,
}

impl VmallocArea {
    /// Create an empty area.
    pub const fn empty() -> Self {
        Self {
            va_start: 0,
            size: 0,
            flags: 0,
            nr_pages: 0,
            page_start_idx: 0,
            caller: 0,
            active: false,
        }
    }

    /// Get the virtual end address (exclusive).
    pub fn va_end(&self) -> u64 {
        self.va_start + self.size
    }

    /// Get the number of pages.
    pub fn page_count(&self) -> u32 {
        self.nr_pages
    }

    /// Check if this area was allocated via vmalloc.
    pub fn is_vmalloc(&self) -> bool {
        self.flags & VmallocFlags::VM_ALLOC != 0
    }

    /// Check if this area is an ioremap region.
    pub fn is_ioremap(&self) -> bool {
        self.flags & VmallocFlags::VM_IOREMAP != 0
    }
}

// -------------------------------------------------------------------
// VmallocStats
// -------------------------------------------------------------------

/// Statistics for the vmalloc allocator.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmallocStats {
    /// Total number of vmalloc allocations.
    pub total_allocs: u64,
    /// Total number of vfree operations.
    pub total_frees: u64,
    /// Current number of active areas.
    pub active_areas: u64,
    /// Total virtual memory currently allocated (bytes).
    pub total_size: u64,
    /// Total physical pages currently backing vmalloc areas.
    pub total_pages: u64,
    /// Number of allocation failures.
    pub alloc_failures: u64,
    /// Peak number of concurrent allocations.
    pub peak_areas: u64,
    /// Peak total size.
    pub peak_size: u64,
}

// -------------------------------------------------------------------
// VmallocAllocator
// -------------------------------------------------------------------

/// Kernel vmalloc allocator.
///
/// Manages the vmalloc virtual address space, allocating contiguous
/// virtual ranges and mapping them to individual physical pages.
pub struct VmallocAllocator {
    /// Tracked vmalloc areas.
    areas: [VmallocArea; MAX_AREAS],
    /// Physical page entries backing all vmalloc areas.
    pages: [PageEntry; MAX_TOTAL_PAGES],
    /// Number of registered areas.
    area_count: usize,
    /// Number of page entries in use.
    page_count: usize,
    /// Next available virtual address for allocation.
    next_va: u64,
    /// Statistics.
    stats: VmallocStats,
    /// Next simulated PFN for physical page allocation.
    next_pfn: u64,
}

impl VmallocAllocator {
    /// Create a new vmalloc allocator.
    pub fn new() -> Self {
        Self {
            areas: [VmallocArea::empty(); MAX_AREAS],
            pages: [PageEntry::empty(); MAX_TOTAL_PAGES],
            area_count: 0,
            page_count: 0,
            next_va: VMALLOC_START,
            stats: VmallocStats::default(),
            next_pfn: 0x10_0000,
        }
    }

    /// Allocate a virtually contiguous region of the given size.
    ///
    /// The size is rounded up to the next page boundary. Individual
    /// physical pages are allocated and mapped into the virtual range.
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if the area table, page table, or
    /// virtual address space is exhausted. Returns `InvalidArgument`
    /// if size is zero.
    pub fn vmalloc(&mut self, size: u64, flags: u32) -> Result<u64> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }

        let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let nr_pages = (aligned_size / PAGE_SIZE) as usize;

        if self.area_count >= MAX_AREAS {
            self.stats.alloc_failures += 1;
            return Err(Error::OutOfMemory);
        }

        if nr_pages > MAX_PAGES_PER_AREA {
            self.stats.alloc_failures += 1;
            return Err(Error::OutOfMemory);
        }

        if self.page_count + nr_pages > MAX_TOTAL_PAGES {
            self.stats.alloc_failures += 1;
            return Err(Error::OutOfMemory);
        }

        // Check virtual address space.
        let va_needed = aligned_size + GUARD_SIZE;
        if self.next_va + va_needed > VMALLOC_END {
            self.stats.alloc_failures += 1;
            return Err(Error::OutOfMemory);
        }

        let va_start = self.next_va;
        let page_start_idx = self.page_count;

        // Allocate physical pages and map them.
        for i in 0..nr_pages {
            let pfn = self.next_pfn;
            self.next_pfn += 1;

            self.pages[self.page_count] = PageEntry {
                pfn,
                virt_addr: va_start + (i as u64) * PAGE_SIZE,
                active: true,
            };
            self.page_count += 1;
        }

        // Record the area.
        let area_idx = self.area_count;
        self.areas[area_idx] = VmallocArea {
            va_start,
            size: aligned_size,
            flags: flags | VmallocFlags::VM_ALLOC,
            nr_pages: nr_pages as u32,
            page_start_idx: page_start_idx as u32,
            caller: 0,
            active: true,
        };
        self.area_count += 1;

        // Advance the virtual address pointer past the area + guard.
        self.next_va = va_start + aligned_size + GUARD_SIZE;

        // Update statistics.
        self.stats.total_allocs += 1;
        self.stats.active_areas += 1;
        self.stats.total_size += aligned_size;
        self.stats.total_pages += nr_pages as u64;
        if self.stats.active_areas > self.stats.peak_areas {
            self.stats.peak_areas = self.stats.active_areas;
        }
        if self.stats.total_size > self.stats.peak_size {
            self.stats.peak_size = self.stats.total_size;
        }

        Ok(va_start)
    }

    /// Free a vmalloc region.
    ///
    /// Unmaps all pages and releases the physical frames. The virtual
    /// address range is not reclaimed (lazy reclaim).
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if no area starts at the given address.
    pub fn vfree(&mut self, va: u64) -> Result<()> {
        let area_idx = self.find_area(va).ok_or(Error::NotFound)?;
        let area = &self.areas[area_idx];
        let start = area.page_start_idx as usize;
        let count = area.nr_pages as usize;
        let size = area.size;

        // Release physical pages.
        for i in start..start + count {
            if i < self.page_count {
                self.pages[i].active = false;
            }
        }

        // Mark area as inactive.
        self.areas[area_idx].active = false;

        // Update statistics.
        self.stats.total_frees += 1;
        self.stats.active_areas = self.stats.active_areas.saturating_sub(1);
        self.stats.total_size = self.stats.total_size.saturating_sub(size);
        self.stats.total_pages = self.stats.total_pages.saturating_sub(count as u64);

        Ok(())
    }

    /// Look up the physical PFN for a vmalloc virtual address.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the address is not in a vmalloc area.
    pub fn vmalloc_to_pfn(&self, va: u64) -> Result<u64> {
        for i in 0..self.page_count {
            let page = &self.pages[i];
            if page.active && page.virt_addr == (va & !(PAGE_SIZE - 1)) {
                return Ok(page.pfn);
            }
        }
        Err(Error::NotFound)
    }

    /// Find the vmalloc area containing the given virtual address.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if no area contains the address.
    pub fn find_vmalloc_area(&self, va: u64) -> Result<&VmallocArea> {
        for i in 0..self.area_count {
            let area = &self.areas[i];
            if area.active && va >= area.va_start && va < area.va_end() {
                return Ok(area);
            }
        }
        Err(Error::NotFound)
    }

    /// Map existing physical pages into a vmalloc area.
    ///
    /// Unlike `vmalloc`, this does not allocate physical pages — it
    /// maps caller-provided PFNs into a contiguous virtual range.
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if the area or page tables are full.
    pub fn vmap(&mut self, pfns: &[u64], flags: u32) -> Result<u64> {
        if pfns.is_empty() {
            return Err(Error::InvalidArgument);
        }

        let nr_pages = pfns.len();
        let aligned_size = (nr_pages as u64) * PAGE_SIZE;

        if self.area_count >= MAX_AREAS {
            return Err(Error::OutOfMemory);
        }
        if self.page_count + nr_pages > MAX_TOTAL_PAGES {
            return Err(Error::OutOfMemory);
        }
        if self.next_va + aligned_size + GUARD_SIZE > VMALLOC_END {
            return Err(Error::OutOfMemory);
        }

        let va_start = self.next_va;
        let page_start_idx = self.page_count;

        for (i, &pfn) in pfns.iter().enumerate() {
            self.pages[self.page_count] = PageEntry {
                pfn,
                virt_addr: va_start + (i as u64) * PAGE_SIZE,
                active: true,
            };
            self.page_count += 1;
        }

        self.areas[self.area_count] = VmallocArea {
            va_start,
            size: aligned_size,
            flags: flags | VmallocFlags::VM_MAP,
            nr_pages: nr_pages as u32,
            page_start_idx: page_start_idx as u32,
            caller: 0,
            active: true,
        };
        self.area_count += 1;
        self.next_va = va_start + aligned_size + GUARD_SIZE;

        self.stats.total_allocs += 1;
        self.stats.active_areas += 1;
        self.stats.total_size += aligned_size;
        self.stats.total_pages += nr_pages as u64;

        Ok(va_start)
    }

    /// Create an ioremap mapping for a physical MMIO range.
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if the area table is full.
    pub fn ioremap(&mut self, phys_addr: u64, size: u64) -> Result<u64> {
        let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let nr_pages = (aligned_size / PAGE_SIZE) as usize;

        if self.area_count >= MAX_AREAS {
            return Err(Error::OutOfMemory);
        }
        if self.page_count + nr_pages > MAX_TOTAL_PAGES {
            return Err(Error::OutOfMemory);
        }
        if self.next_va + aligned_size + GUARD_SIZE > VMALLOC_END {
            return Err(Error::OutOfMemory);
        }

        let va_start = self.next_va;
        let page_start_idx = self.page_count;
        let base_pfn = phys_addr / PAGE_SIZE;

        for i in 0..nr_pages {
            self.pages[self.page_count] = PageEntry {
                pfn: base_pfn + i as u64,
                virt_addr: va_start + (i as u64) * PAGE_SIZE,
                active: true,
            };
            self.page_count += 1;
        }

        self.areas[self.area_count] = VmallocArea {
            va_start,
            size: aligned_size,
            flags: VmallocFlags::VM_IOREMAP | VmallocFlags::VM_NO_CACHE,
            nr_pages: nr_pages as u32,
            page_start_idx: page_start_idx as u32,
            caller: 0,
            active: true,
        };
        self.area_count += 1;
        self.next_va = va_start + aligned_size + GUARD_SIZE;

        self.stats.total_allocs += 1;
        self.stats.active_areas += 1;
        self.stats.total_size += aligned_size;

        Ok(va_start)
    }

    /// Unmap an ioremap region. Equivalent to `vfree` for ioremap areas.
    pub fn iounmap(&mut self, va: u64) -> Result<()> {
        self.vfree(va)
    }

    /// Find the area index by virtual address.
    fn find_area(&self, va: u64) -> Option<usize> {
        for i in 0..self.area_count {
            if self.areas[i].active && self.areas[i].va_start == va {
                return Some(i);
            }
        }
        None
    }

    /// Get the number of active areas.
    pub fn active_area_count(&self) -> usize {
        self.stats.active_areas as usize
    }

    /// Get allocator statistics.
    pub fn statistics(&self) -> &VmallocStats {
        &self.stats
    }

    /// Get the current virtual address watermark.
    pub fn current_va(&self) -> u64 {
        self.next_va
    }

    /// Get the remaining virtual address space in bytes.
    pub fn remaining_va_space(&self) -> u64 {
        VMALLOC_END.saturating_sub(self.next_va)
    }
}
