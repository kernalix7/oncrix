// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Non-contiguous virtual kernel memory allocation (vmalloc).
//!
//! Provides allocation of virtually contiguous but physically
//! non-contiguous memory regions in the kernel address space.
//! This is the kernel equivalent of `vmalloc()` / `vfree()` in
//! Linux, plus `ioremap()` / `iounmap()` for MMIO mappings.
//!
//! - [`VmallocAllocator`] — central allocator managing vmalloc
//!   areas
//! - [`VmallocArea`] — descriptor for a single vmalloc region
//! - [`VmallocFlags`] — allocation flags
//! - [`VmallocStats`] — summary statistics

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Start of the vmalloc virtual address range.
const _VMALLOC_START: u64 = 0xFFFF_C900_0000_0000;

/// End of the vmalloc virtual address range (inclusive).
const _VMALLOC_END: u64 = 0xFFFF_E8FF_FFFF_FFFF;

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of tracked vmalloc areas.
const MAX_VMALLOC_AREAS: usize = 256;

/// Guard page size inserted after each vmalloc area.
const GUARD_PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// VmallocFlags
// -------------------------------------------------------------------

/// Flags that describe the type of a vmalloc area.
pub struct VmallocFlags;

impl VmallocFlags {
    /// Area allocated via `vmalloc()`.
    pub const VM_ALLOC: u32 = 1;
    /// Area created by mapping existing pages.
    pub const VM_MAP: u32 = 2;
    /// Area created via `ioremap()`.
    pub const VM_IOREMAP: u32 = 4;
    /// Area mappable into user space.
    pub const VM_USERMAP: u32 = 8;
}

// -------------------------------------------------------------------
// VmallocArea
// -------------------------------------------------------------------

/// Descriptor for a single vmalloc region.
#[derive(Clone, Copy)]
pub struct VmallocArea {
    /// Virtual base address of this area.
    pub base: u64,
    /// Total size in bytes (including guard page).
    pub size: u64,
    /// Number of pages backing this area.
    pub nr_pages: usize,
    /// Physical page addresses (max 64 pages = 256 KiB).
    pub phys_pages: [u64; 64],
    /// Allocation flags ([`VmallocFlags`]).
    pub flags: u32,
    /// Address of the caller that requested this area.
    pub caller_addr: u64,
    /// Whether this area is currently in use.
    pub active: bool,
    /// Unique identifier for this area.
    pub id: u32,
}

impl VmallocArea {
    /// Creates an empty, inactive vmalloc area.
    const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            nr_pages: 0,
            phys_pages: [0; 64],
            flags: 0,
            caller_addr: 0,
            active: false,
            id: 0,
        }
    }
}

// -------------------------------------------------------------------
// VmallocStats
// -------------------------------------------------------------------

/// Summary statistics for the vmalloc allocator.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmallocStats {
    /// Number of active vmalloc areas.
    pub total_areas: usize,
    /// Total number of pages across all active areas.
    pub total_pages: usize,
    /// Total bytes across all active areas.
    pub total_bytes: u64,
    /// Largest contiguous free region in the vmalloc space.
    pub largest_free: u64,
}

// -------------------------------------------------------------------
// VmallocAllocator
// -------------------------------------------------------------------

/// Central allocator for non-contiguous virtual kernel memory.
///
/// Manages up to [`MAX_VMALLOC_AREAS`] regions in the kernel's
/// vmalloc address range.
pub struct VmallocAllocator {
    /// Array of all vmalloc areas (active and free slots).
    areas: [VmallocArea; MAX_VMALLOC_AREAS],
    /// Next unique area identifier to assign.
    next_id: u32,
    /// Number of currently active areas.
    count: usize,
    /// Next free virtual address to hand out.
    next_addr: u64,
    /// Total number of physical pages across all areas.
    total_pages: usize,
}

impl Default for VmallocAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl VmallocAllocator {
    /// Creates a new, empty vmalloc allocator.
    pub const fn new() -> Self {
        const EMPTY: VmallocArea = VmallocArea::empty();
        Self {
            areas: [EMPTY; MAX_VMALLOC_AREAS],
            next_id: 1,
            count: 0,
            next_addr: _VMALLOC_START,
            total_pages: 0,
        }
    }

    /// Allocates virtually contiguous (physically
    /// non-contiguous) kernel memory.
    ///
    /// Returns the virtual base address of the allocated
    /// region. The actual size is rounded up to the nearest
    /// page boundary, plus a guard page is appended.
    pub fn vmalloc(&mut self, size: u64) -> Result<u64> {
        self.alloc_area(size, VmallocFlags::VM_ALLOC)
    }

    /// Allocates zero-initialized virtually contiguous kernel
    /// memory.
    ///
    /// Behaves like [`vmalloc`](Self::vmalloc) but marks pages
    /// as zeroed (physical page addresses set to zero).
    pub fn vzalloc(&mut self, size: u64) -> Result<u64> {
        let addr = self.alloc_area(size, VmallocFlags::VM_ALLOC)?;
        // Mark area pages as zero-initialised by finding the
        // area and clearing its physical page entries.
        if let Some(area) = self.areas.iter_mut().find(|a| a.active && a.base == addr) {
            for p in area.phys_pages.iter_mut().take(area.nr_pages) {
                *p = 0;
            }
        }
        Ok(addr)
    }

    /// Frees a vmalloc area identified by its virtual base
    /// address.
    pub fn vfree(&mut self, addr: u64) -> Result<()> {
        let area = self
            .areas
            .iter_mut()
            .find(|a| a.active && a.base == addr)
            .ok_or(Error::NotFound)?;

        area.active = false;
        let nr = area.nr_pages;
        area.nr_pages = 0;
        area.size = 0;
        area.base = 0;
        area.flags = 0;

        self.count = self.count.saturating_sub(1);
        self.total_pages = self.total_pages.saturating_sub(nr);
        Ok(())
    }

    /// Maps a physical MMIO region into the vmalloc address
    /// space.
    ///
    /// Returns the virtual address at which the physical region
    /// is mapped.
    pub fn ioremap(&mut self, phys: u64, size: u64) -> Result<u64> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        let nr_pages = pages_for(size);
        if nr_pages > 64 {
            return Err(Error::InvalidArgument);
        }

        let total_size = (nr_pages as u64) * PAGE_SIZE + GUARD_PAGE_SIZE;

        if self
            .next_addr
            .checked_add(total_size)
            .is_none_or(|end| end > _VMALLOC_END)
        {
            return Err(Error::OutOfMemory);
        }

        let idx = self
            .areas
            .iter()
            .position(|a| !a.active)
            .ok_or(Error::OutOfMemory)?;

        let base = self.next_addr;
        let area = &mut self.areas[idx];
        area.base = base;
        area.size = total_size;
        area.nr_pages = nr_pages;
        area.flags = VmallocFlags::VM_IOREMAP;
        area.caller_addr = 0;
        area.active = true;
        area.id = self.next_id;

        // Store contiguous physical addresses.
        for i in 0..nr_pages {
            area.phys_pages[i] = phys + (i as u64) * PAGE_SIZE;
        }

        self.next_id = self.next_id.wrapping_add(1);
        self.count += 1;
        self.total_pages += nr_pages;
        self.next_addr += total_size;
        Ok(base)
    }

    /// Unmaps a previously `ioremap`'d region.
    pub fn iounmap(&mut self, addr: u64) -> Result<()> {
        let area = self
            .areas
            .iter_mut()
            .find(|a| a.active && a.base == addr && (a.flags & VmallocFlags::VM_IOREMAP) != 0)
            .ok_or(Error::NotFound)?;

        area.active = false;
        let nr = area.nr_pages;
        area.nr_pages = 0;
        area.size = 0;
        area.base = 0;
        area.flags = 0;

        self.count = self.count.saturating_sub(1);
        self.total_pages = self.total_pages.saturating_sub(nr);
        Ok(())
    }

    /// Finds the vmalloc area that contains the given virtual
    /// address.
    pub fn find_area(&self, addr: u64) -> Option<&VmallocArea> {
        self.areas
            .iter()
            .find(|a| a.active && addr >= a.base && addr < a.base + a.size)
    }

    /// Translates a vmalloc virtual address to its backing
    /// physical address.
    pub fn virt_to_phys(&self, addr: u64) -> Result<u64> {
        let area = self.find_area(addr).ok_or(Error::NotFound)?;

        let offset = addr - area.base;
        let page_idx = (offset / PAGE_SIZE) as usize;

        if page_idx >= area.nr_pages {
            return Err(Error::InvalidArgument);
        }

        let page_offset = offset % PAGE_SIZE;
        Ok(area.phys_pages[page_idx] + page_offset)
    }

    /// Returns summary statistics for the vmalloc allocator.
    pub fn stats(&self) -> VmallocStats {
        let total_bytes = self.total_pages as u64 * PAGE_SIZE;

        // Compute largest free gap.
        let mut sorted_bases: [u64; MAX_VMALLOC_AREAS] = [0; MAX_VMALLOC_AREAS];
        let mut sorted_ends: [u64; MAX_VMALLOC_AREAS] = [0; MAX_VMALLOC_AREAS];
        let mut n = 0usize;
        for a in &self.areas {
            if a.active {
                sorted_bases[n] = a.base;
                sorted_ends[n] = a.base + a.size;
                n += 1;
            }
        }

        // Simple O(n^2) sort — n <= 256, acceptable.
        for i in 0..n {
            for j in (i + 1)..n {
                if sorted_bases[j] < sorted_bases[i] {
                    sorted_bases.swap(i, j);
                    sorted_ends.swap(i, j);
                }
            }
        }

        let mut largest_free: u64 = 0;
        if n == 0 {
            largest_free = _VMALLOC_END - _VMALLOC_START + 1;
        } else {
            // Gap before first area.
            let gap = sorted_bases[0].saturating_sub(_VMALLOC_START);
            if gap > largest_free {
                largest_free = gap;
            }
            // Gaps between areas.
            for i in 1..n {
                let gap = sorted_bases[i].saturating_sub(sorted_ends[i - 1]);
                if gap > largest_free {
                    largest_free = gap;
                }
            }
            // Gap after last area.
            let gap = (_VMALLOC_END + 1).saturating_sub(sorted_ends[n - 1]);
            if gap > largest_free {
                largest_free = gap;
            }
        }

        VmallocStats {
            total_areas: self.count,
            total_pages: self.total_pages,
            total_bytes,
            largest_free,
        }
    }

    /// Returns the number of active vmalloc areas.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if there are no active vmalloc areas.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Core allocation routine shared by `vmalloc` and `vzalloc`.
    fn alloc_area(&mut self, size: u64, flags: u32) -> Result<u64> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }

        let nr_pages = pages_for(size);
        if nr_pages > 64 {
            return Err(Error::InvalidArgument);
        }

        let total_size = (nr_pages as u64) * PAGE_SIZE + GUARD_PAGE_SIZE;

        if self
            .next_addr
            .checked_add(total_size)
            .is_none_or(|end| end > _VMALLOC_END)
        {
            return Err(Error::OutOfMemory);
        }

        let idx = self
            .areas
            .iter()
            .position(|a| !a.active)
            .ok_or(Error::OutOfMemory)?;

        let base = self.next_addr;
        let area = &mut self.areas[idx];
        area.base = base;
        area.size = total_size;
        area.nr_pages = nr_pages;
        area.flags = flags;
        area.caller_addr = 0;
        area.active = true;
        area.id = self.next_id;

        // Assign placeholder physical page addresses.
        for i in 0..nr_pages {
            area.phys_pages[i] =
                0x1000_0000 + (self.next_id as u64) * 0x1000 + (i as u64) * PAGE_SIZE;
        }

        self.next_id = self.next_id.wrapping_add(1);
        self.count += 1;
        self.total_pages += nr_pages;
        self.next_addr += total_size;
        Ok(base)
    }
}

// -------------------------------------------------------------------
// Free functions
// -------------------------------------------------------------------

/// Returns the number of pages needed to cover `size` bytes.
fn pages_for(size: u64) -> usize {
    size.div_ceil(PAGE_SIZE) as usize
}
