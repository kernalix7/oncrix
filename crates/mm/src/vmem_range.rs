// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Virtual memory range management.
//!
//! Provides range-based virtual memory allocation for the kernel
//! address space. The allocator manages a contiguous virtual address
//! region and hands out sub-ranges with configurable alignment and
//! optional guard pages.
//!
//! Unlike user-space VMA management (which tracks per-process mappings),
//! this module manages the kernel's own virtual address space for
//! subsystems like vmalloc, ioremap, and module loading.
//!
//! Features:
//!
//! - **Best-fit allocation** — minimizes fragmentation
//! - **Guard pages** — optional 4 KiB guard before/after each range
//! - **Alignment support** — power-of-two alignment up to 2 MiB
//! - **Named ranges** — up to 32 bytes of identifier for debugging
//!
//! - [`VmemRange`] — a single allocated range
//! - [`VmemAllocator`] — the range allocator with 512 entries
//! - [`VmemStats`] — fragmentation and usage statistics
//!
//! Reference: Linux `mm/vmalloc.c` — `__get_vm_area_node()`,
//! `alloc_vmap_area()`, `free_vmap_area()`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of managed ranges.
const MAX_RANGES: usize = 512;

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Default start of the kernel virtual memory region.
pub const VMEM_START: u64 = 0xFFFF_C900_0000_0000;

/// Default end of the kernel virtual memory region (exclusive).
pub const VMEM_END: u64 = 0xFFFF_E900_0000_0000;

/// Maximum name length for a range (bytes).
const RANGE_NAME_LEN: usize = 32;

/// Range flag: guard page inserted before the range.
pub const VMEM_FLAG_GUARD_BEFORE: u32 = 1 << 0;

/// Range flag: guard page inserted after the range.
pub const VMEM_FLAG_GUARD_AFTER: u32 = 1 << 1;

/// Range flag: range is used by vmalloc.
pub const VMEM_FLAG_VMALLOC: u32 = 1 << 2;

/// Range flag: range is used by ioremap.
pub const VMEM_FLAG_IOREMAP: u32 = 1 << 3;

/// Range flag: range is used for module loading.
pub const VMEM_FLAG_MODULE: u32 = 1 << 4;

/// Combination of both guard page flags.
pub const VMEM_FLAG_GUARD_BOTH: u32 = VMEM_FLAG_GUARD_BEFORE | VMEM_FLAG_GUARD_AFTER;

// -------------------------------------------------------------------
// VmemRange
// -------------------------------------------------------------------

/// A single virtual memory range descriptor.
#[derive(Debug, Clone, Copy)]
pub struct VmemRange {
    /// Start virtual address (page-aligned).
    pub start: u64,
    /// Size of the usable region in bytes (page-aligned).
    pub size: u64,
    /// Flags (guard pages, purpose, etc.).
    pub flags: u32,
    /// Whether this range is currently allocated.
    pub in_use: bool,
    /// Human-readable name for debugging.
    pub name: [u8; RANGE_NAME_LEN],
    /// Length of the valid portion of `name`.
    pub name_len: usize,
    /// The actual reserved size including guard pages.
    pub reserved_size: u64,
    /// Unique range identifier.
    pub range_id: u32,
}

impl VmemRange {
    /// Creates an empty, unused range.
    const fn empty() -> Self {
        Self {
            start: 0,
            size: 0,
            flags: 0,
            in_use: false,
            name: [0u8; RANGE_NAME_LEN],
            name_len: 0,
            reserved_size: 0,
            range_id: 0,
        }
    }

    /// Returns the end address of the usable region (exclusive).
    pub fn end(&self) -> u64 {
        self.start + self.size
    }

    /// Returns the total reserved region including guard pages.
    pub fn reserved_end(&self) -> u64 {
        self.start.wrapping_sub(self.guard_before_size()) + self.reserved_size
    }

    /// Returns the size of the guard page before this range.
    pub fn guard_before_size(&self) -> u64 {
        if self.flags & VMEM_FLAG_GUARD_BEFORE != 0 {
            PAGE_SIZE
        } else {
            0
        }
    }

    /// Returns the size of the guard page after this range.
    pub fn guard_after_size(&self) -> u64 {
        if self.flags & VMEM_FLAG_GUARD_AFTER != 0 {
            PAGE_SIZE
        } else {
            0
        }
    }

    /// Returns the name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns `true` if this range overlaps with `[start, start+size)`.
    pub fn overlaps(&self, start: u64, size: u64) -> bool {
        if !self.in_use {
            return false;
        }
        let guard_start = self.start.wrapping_sub(self.guard_before_size());
        let guard_end = self.end() + self.guard_after_size();
        let other_end = start + size;
        guard_start < other_end && start < guard_end
    }
}

// -------------------------------------------------------------------
// VmemStats
// -------------------------------------------------------------------

/// Statistics for the virtual memory range allocator.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmemStats {
    /// Total bytes allocated (usable, excluding guards).
    pub total_allocated: u64,
    /// Total bytes freed.
    pub total_freed: u64,
    /// Currently allocated bytes.
    pub current_used: u64,
    /// Size of the largest contiguous free gap.
    pub largest_free_gap: u64,
    /// Fragmentation ratio (0-100, higher = more fragmented).
    pub fragmentation_ratio: u32,
    /// Number of active allocations.
    pub active_count: usize,
    /// Total allocation operations.
    pub alloc_ops: u64,
    /// Total free operations.
    pub free_ops: u64,
}

// -------------------------------------------------------------------
// FreeGap
// -------------------------------------------------------------------

/// A contiguous free gap in the virtual address space.
#[derive(Debug, Clone, Copy)]
struct FreeGap {
    /// Start address of the gap.
    start: u64,
    /// Size of the gap in bytes.
    size: u64,
}

// -------------------------------------------------------------------
// VmemAllocator
// -------------------------------------------------------------------

/// Virtual memory range allocator.
///
/// Manages a region of kernel virtual address space, handing out
/// sub-ranges with best-fit allocation and optional guard pages.
pub struct VmemAllocator {
    /// Array of managed ranges (sorted by start address).
    ranges: [VmemRange; MAX_RANGES],
    /// Number of active (in-use) ranges.
    count: usize,
    /// Start of the managed virtual address region.
    region_start: u64,
    /// End of the managed virtual address region (exclusive).
    region_end: u64,
    /// Next range identifier.
    next_id: u32,
    /// Total bytes currently allocated.
    current_used: u64,
    /// Total allocation operations performed.
    alloc_ops: u64,
    /// Total free operations performed.
    free_ops: u64,
    /// Total bytes ever allocated.
    total_allocated: u64,
    /// Total bytes ever freed.
    total_freed: u64,
}

impl Default for VmemAllocator {
    fn default() -> Self {
        Self::new(VMEM_START, VMEM_END)
    }
}

impl VmemAllocator {
    /// Creates a new allocator for the given virtual address region.
    pub const fn new(start: u64, end: u64) -> Self {
        Self {
            ranges: [VmemRange::empty(); MAX_RANGES],
            count: 0,
            region_start: start,
            region_end: end,
            next_id: 1,
            current_used: 0,
            alloc_ops: 0,
            free_ops: 0,
            total_allocated: 0,
            total_freed: 0,
        }
    }

    /// Allocates a virtual address range of `size` bytes with the
    /// given alignment.
    ///
    /// Uses best-fit allocation: scans all free gaps and selects the
    /// smallest one that satisfies the request.
    ///
    /// # Arguments
    ///
    /// - `size` — requested size in bytes (will be page-aligned)
    /// - `align` — alignment requirement (must be power of two, >= PAGE_SIZE)
    /// - `flags` — range flags (guard pages, purpose)
    /// - `name` — optional name for debugging (up to 32 bytes)
    ///
    /// # Returns
    ///
    /// The start address of the usable region (after any guard page).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if size is 0 or alignment
    /// is not a power of two.
    /// Returns [`Error::OutOfMemory`] if no suitable gap exists.
    pub fn alloc_range(&mut self, size: u64, align: u64, flags: u32, name: &[u8]) -> Result<u64> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        if align == 0 || (align & (align - 1)) != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_RANGES {
            return Err(Error::OutOfMemory);
        }

        // Round size up to page boundary.
        let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        // Calculate total reservation including guard pages.
        let guard_before = if flags & VMEM_FLAG_GUARD_BEFORE != 0 {
            PAGE_SIZE
        } else {
            0
        };
        let guard_after = if flags & VMEM_FLAG_GUARD_AFTER != 0 {
            PAGE_SIZE
        } else {
            0
        };
        let total_needed = guard_before + aligned_size + guard_after;

        // Find the best-fit gap.
        let gap = self.find_best_fit_gap(total_needed, align, guard_before)?;

        // The usable region starts after the guard-before page.
        let usable_start = gap.start + guard_before;

        // Align the usable start.
        let aligned_start = align_up(usable_start, align);

        // Recalculate the actual reservation start.
        let reservation_start = aligned_start - guard_before;

        // Build the range name.
        let mut range_name = [0u8; RANGE_NAME_LEN];
        let copy_len = if name.len() < RANGE_NAME_LEN {
            name.len()
        } else {
            RANGE_NAME_LEN
        };
        let mut i = 0;
        while i < copy_len {
            range_name[i] = name[i];
            i += 1;
        }

        let id = self.next_id;
        self.next_id += 1;

        let range = VmemRange {
            start: aligned_start,
            size: aligned_size,
            flags,
            in_use: true,
            name: range_name,
            name_len: copy_len,
            reserved_size: guard_before + aligned_size + guard_after,
            range_id: id,
        };

        // Insert in sorted order.
        let pos = self.find_insert_pos(reservation_start);
        let mut j = self.count;
        while j > pos {
            self.ranges[j] = self.ranges[j - 1];
            j -= 1;
        }
        self.ranges[pos] = range;
        self.count += 1;

        self.current_used += aligned_size;
        self.total_allocated += aligned_size;
        self.alloc_ops += 1;

        Ok(aligned_start)
    }

    /// Frees a previously allocated range by its start address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no range starts at the given address.
    pub fn free_range(&mut self, start: u64) -> Result<()> {
        let idx = self.find_range_by_start(start)?;
        let size = self.ranges[idx].size;

        // Remove by shifting entries left.
        let mut i = idx;
        while i + 1 < self.count {
            self.ranges[i] = self.ranges[i + 1];
            i += 1;
        }
        self.ranges[self.count - 1] = VmemRange::empty();
        self.count -= 1;

        self.current_used -= size;
        self.total_freed += size;
        self.free_ops += 1;

        Ok(())
    }

    /// Frees a range by its identifier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no range with the given ID exists.
    pub fn free_range_by_id(&mut self, range_id: u32) -> Result<()> {
        let idx = self.find_range_by_id(range_id)?;
        let start = self.ranges[idx].start;
        self.free_range(start)
    }

    /// Finds the largest contiguous free gap.
    ///
    /// Returns the start address and size of the gap, or `None` if
    /// there is no free space.
    pub fn find_largest_free_gap(&self) -> Option<(u64, u64)> {
        let mut best_start = 0_u64;
        let mut best_size = 0_u64;
        let mut scan_start = self.region_start;

        for i in 0..self.count {
            if !self.ranges[i].in_use {
                continue;
            }
            let range_reservation_start = self.ranges[i].start - self.ranges[i].guard_before_size();

            if range_reservation_start > scan_start {
                let gap = range_reservation_start - scan_start;
                if gap > best_size {
                    best_size = gap;
                    best_start = scan_start;
                }
            }
            let range_end = self.ranges[i].end() + self.ranges[i].guard_after_size();
            if range_end > scan_start {
                scan_start = range_end;
            }
        }

        // Check the gap after the last range.
        if self.region_end > scan_start {
            let gap = self.region_end - scan_start;
            if gap > best_size {
                best_size = gap;
                best_start = scan_start;
            }
        }

        if best_size > 0 {
            Some((best_start, best_size))
        } else {
            None
        }
    }

    /// Finds a free gap that can accommodate `size` bytes with `align`
    /// alignment.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no suitable gap exists.
    pub fn find_free_gap(&self, size: u64, align: u64) -> Result<u64> {
        let gap = self.find_best_fit_gap(size, align, 0)?;
        Ok(align_up(gap.start, align))
    }

    /// Returns the range at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is out of range.
    pub fn get(&self, idx: usize) -> Result<&VmemRange> {
        if idx >= self.count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.ranges[idx])
    }

    /// Returns the range containing the given address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no range contains the address.
    pub fn find_range(&self, addr: u64) -> Result<&VmemRange> {
        for i in 0..self.count {
            if self.ranges[i].in_use && addr >= self.ranges[i].start && addr < self.ranges[i].end()
            {
                return Ok(&self.ranges[i]);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of active ranges.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no ranges are allocated.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the total region size managed by this allocator.
    pub fn region_size(&self) -> u64 {
        self.region_end - self.region_start
    }

    /// Returns the start of the managed region.
    pub fn region_start(&self) -> u64 {
        self.region_start
    }

    /// Returns the end of the managed region.
    pub fn region_end(&self) -> u64 {
        self.region_end
    }

    /// Returns usage and fragmentation statistics.
    pub fn stats(&self) -> VmemStats {
        let largest_gap = self
            .find_largest_free_gap()
            .map(|(_, size)| size)
            .unwrap_or(0);

        let total_free = self.region_size().saturating_sub(self.current_used);
        let fragmentation = if total_free > 0 && largest_gap < total_free {
            // Fragmentation = 1 - (largest_gap / total_free)
            // Scaled to 0-100.
            let ratio = (largest_gap * 100) / total_free;
            100_u32.saturating_sub(ratio as u32)
        } else {
            0
        };

        VmemStats {
            total_allocated: self.total_allocated,
            total_freed: self.total_freed,
            current_used: self.current_used,
            largest_free_gap: largest_gap,
            fragmentation_ratio: fragmentation,
            active_count: self.count,
            alloc_ops: self.alloc_ops,
            free_ops: self.free_ops,
        }
    }

    /// Finds the best-fit free gap for the given total size and alignment.
    fn find_best_fit_gap(
        &self,
        total_needed: u64,
        align: u64,
        guard_before: u64,
    ) -> Result<FreeGap> {
        let mut best: Option<FreeGap> = None;
        let mut scan_start = self.region_start;

        for i in 0..self.count {
            if !self.ranges[i].in_use {
                continue;
            }
            let range_reservation_start = self.ranges[i].start - self.ranges[i].guard_before_size();

            if range_reservation_start > scan_start {
                let gap_size = range_reservation_start - scan_start;
                if let Some(candidate) =
                    self.check_gap_fit(scan_start, gap_size, total_needed, align, guard_before)
                {
                    best = Some(match best {
                        Some(current) if current.size <= candidate.size => current,
                        _ => candidate,
                    });
                }
            }
            let range_end = self.ranges[i].end() + self.ranges[i].guard_after_size();
            if range_end > scan_start {
                scan_start = range_end;
            }
        }

        // Check gap after last range.
        if self.region_end > scan_start {
            let gap_size = self.region_end - scan_start;
            if let Some(candidate) =
                self.check_gap_fit(scan_start, gap_size, total_needed, align, guard_before)
            {
                best = Some(match best {
                    Some(current) if current.size <= candidate.size => current,
                    _ => candidate,
                });
            }
        }

        best.ok_or(Error::OutOfMemory)
    }

    /// Checks whether a gap can accommodate the request after alignment.
    fn check_gap_fit(
        &self,
        gap_start: u64,
        gap_size: u64,
        total_needed: u64,
        align: u64,
        guard_before: u64,
    ) -> Option<FreeGap> {
        // The usable region starts after guard-before.
        let usable_start = gap_start + guard_before;
        let aligned_start = align_up(usable_start, align);

        // How much space is consumed from the gap start to aligned start
        // plus the total needed.
        let consumed = (aligned_start - gap_start) + (total_needed - guard_before);

        if consumed <= gap_size {
            Some(FreeGap {
                start: gap_start,
                size: gap_size,
            })
        } else {
            None
        }
    }

    /// Finds the insertion position to maintain sorted order by start.
    fn find_insert_pos(&self, start: u64) -> usize {
        for i in 0..self.count {
            if self.ranges[i].start > start {
                return i;
            }
        }
        self.count
    }

    /// Finds a range by its usable start address.
    fn find_range_by_start(&self, start: u64) -> Result<usize> {
        for i in 0..self.count {
            if self.ranges[i].in_use && self.ranges[i].start == start {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Finds a range by its identifier.
    fn find_range_by_id(&self, range_id: u32) -> Result<usize> {
        for i in 0..self.count {
            if self.ranges[i].in_use && self.ranges[i].range_id == range_id {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }
}

// -------------------------------------------------------------------
// Helper functions
// -------------------------------------------------------------------

/// Aligns `addr` up to the next multiple of `align`.
///
/// `align` must be a power of two.
fn align_up(addr: u64, align: u64) -> u64 {
    (addr + align - 1) & !(align - 1)
}
