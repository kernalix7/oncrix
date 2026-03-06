// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Huge page (2 MiB / 1 GiB) support for the ONCRIX memory manager.
//!
//! Huge pages reduce TLB pressure and page table overhead for large
//! memory-intensive workloads. This module provides:
//!
//! - [`HugePageSize`] — 2 MiB and 1 GiB page size variants
//! - [`HugePagePool`] — bitmap-based allocator for huge pages
//! - [`HugePageMapping`] — tracks huge page virtual mappings
//! - [`HugePageStats`] — usage statistics
//!
//! # x86_64 Implementation
//!
//! - **2 MiB pages**: Use the PS (Page Size) bit in a PDE (level 2)
//! - **1 GiB pages**: Use the PS bit in a PDPTE (level 3),
//!   requires CPU support (CPUID.80000001H:EDX bit 26)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// 4 KiB standard page size.
const _PAGE_SIZE_4K: usize = 4096;

/// 2 MiB huge page size.
pub const HUGE_PAGE_2M: usize = 2 * 1024 * 1024;

/// 1 GiB huge page size.
pub const HUGE_PAGE_1G: usize = 1024 * 1024 * 1024;

/// Maximum number of 2 MiB huge pages in the pool (2048 = 4 GiB).
const MAX_HUGE_2M: usize = 2048;

/// Maximum number of 1 GiB huge pages in the pool (16 = 16 GiB).
const MAX_HUGE_1G: usize = 16;

/// Maximum tracked huge page mappings.
const MAX_MAPPINGS: usize = 256;

// ---------------------------------------------------------------------------
// Huge Page Size
// ---------------------------------------------------------------------------

/// Huge page size variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HugePageSize {
    /// 2 MiB huge page (x86_64 PDE with PS bit).
    Size2M,
    /// 1 GiB huge page (x86_64 PDPTE with PS bit).
    Size1G,
}

impl HugePageSize {
    /// Returns the page size in bytes.
    pub const fn bytes(self) -> usize {
        match self {
            Self::Size2M => HUGE_PAGE_2M,
            Self::Size1G => HUGE_PAGE_1G,
        }
    }

    /// Returns the number of 4 KiB pages in one huge page.
    pub const fn small_pages(self) -> usize {
        match self {
            Self::Size2M => 512,
            Self::Size1G => 262_144,
        }
    }

    /// Returns the alignment mask.
    pub const fn align_mask(self) -> usize {
        self.bytes() - 1
    }

    /// Check if an address is aligned to this huge page size.
    pub const fn is_aligned(self, addr: u64) -> bool {
        (addr as usize) & self.align_mask() == 0
    }
}

// ---------------------------------------------------------------------------
// Huge Page Bitmap Allocator
// ---------------------------------------------------------------------------

/// Bitmap word count for 2 MiB pages (2048 / 64 = 32 words).
const BITMAP_2M_WORDS: usize = MAX_HUGE_2M / 64;

/// Bitmap word count for 1 GiB pages (16 / 64 = 1 word, rounded up).
const BITMAP_1G_WORDS: usize = 1;

/// Bitmap-based allocator for huge pages of a specific size.
///
/// Each bit in the bitmap represents one huge page frame.
/// A set bit (1) means the frame is free; clear (0) means allocated.
pub struct HugePagePool {
    /// Bitmap for 2 MiB pages (1 = free, 0 = allocated).
    bitmap_2m: [u64; BITMAP_2M_WORDS],
    /// Bitmap for 1 GiB pages.
    bitmap_1g: [u64; BITMAP_1G_WORDS],
    /// Base physical address of the 2 MiB pool.
    base_2m: u64,
    /// Base physical address of the 1 GiB pool.
    base_1g: u64,
    /// Total 2 MiB pages available.
    total_2m: usize,
    /// Total 1 GiB pages available.
    total_1g: usize,
    /// Allocated 2 MiB page count.
    allocated_2m: usize,
    /// Allocated 1 GiB page count.
    allocated_1g: usize,
}

impl HugePagePool {
    /// Create a new empty pool (no pages available until configured).
    pub const fn new() -> Self {
        Self {
            bitmap_2m: [0; BITMAP_2M_WORDS],
            bitmap_1g: [0; BITMAP_1G_WORDS],
            base_2m: 0,
            base_1g: 0,
            total_2m: 0,
            total_1g: 0,
            allocated_2m: 0,
            allocated_1g: 0,
        }
    }

    /// Configure the 2 MiB huge page pool.
    ///
    /// `base` must be 2 MiB-aligned. `count` is the number of
    /// contiguous 2 MiB frames available.
    pub fn init_2m(&mut self, base: u64, count: usize) {
        self.base_2m = base;
        self.total_2m = count.min(MAX_HUGE_2M);
        // Mark all pages as free
        for i in 0..self.total_2m {
            let word = i / 64;
            let bit = i % 64;
            self.bitmap_2m[word] |= 1u64 << bit;
        }
    }

    /// Configure the 1 GiB huge page pool.
    ///
    /// `base` must be 1 GiB-aligned. `count` is the number of
    /// contiguous 1 GiB frames available.
    pub fn init_1g(&mut self, base: u64, count: usize) {
        self.base_1g = base;
        self.total_1g = count.min(MAX_HUGE_1G);
        for i in 0..self.total_1g {
            let word = i / 64;
            let bit = i % 64;
            self.bitmap_1g[word] |= 1u64 << bit;
        }
    }

    /// Allocate a huge page of the specified size.
    ///
    /// Returns the physical address of the allocated page.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no free huge pages remain.
    pub fn alloc(&mut self, size: HugePageSize) -> Result<u64> {
        match size {
            HugePageSize::Size2M => self.alloc_2m(),
            HugePageSize::Size1G => self.alloc_1g(),
        }
    }

    /// Free a previously allocated huge page.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the address is not valid
    /// or the page is already free.
    pub fn free(&mut self, addr: u64, size: HugePageSize) -> Result<()> {
        match size {
            HugePageSize::Size2M => self.free_2m(addr),
            HugePageSize::Size1G => self.free_1g(addr),
        }
    }

    /// Allocate a 2 MiB page.
    fn alloc_2m(&mut self) -> Result<u64> {
        for (word_idx, word) in self.bitmap_2m.iter_mut().enumerate() {
            if *word != 0 {
                let bit = word.trailing_zeros() as usize;
                let idx = word_idx * 64 + bit;
                if idx >= self.total_2m {
                    break;
                }
                *word &= !(1u64 << bit);
                self.allocated_2m += 1;
                return Ok(self.base_2m + (idx as u64) * HUGE_PAGE_2M as u64);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Allocate a 1 GiB page.
    fn alloc_1g(&mut self) -> Result<u64> {
        for (word_idx, word) in self.bitmap_1g.iter_mut().enumerate() {
            if *word != 0 {
                let bit = word.trailing_zeros() as usize;
                let idx = word_idx * 64 + bit;
                if idx >= self.total_1g {
                    break;
                }
                *word &= !(1u64 << bit);
                self.allocated_1g += 1;
                return Ok(self.base_1g + (idx as u64) * HUGE_PAGE_1G as u64);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free a 2 MiB page.
    fn free_2m(&mut self, addr: u64) -> Result<()> {
        if addr < self.base_2m {
            return Err(Error::InvalidArgument);
        }
        let offset = (addr - self.base_2m) as usize;
        if offset % HUGE_PAGE_2M != 0 {
            return Err(Error::InvalidArgument);
        }
        let idx = offset / HUGE_PAGE_2M;
        if idx >= self.total_2m {
            return Err(Error::InvalidArgument);
        }
        let word = idx / 64;
        let bit = idx % 64;
        if self.bitmap_2m[word] & (1u64 << bit) != 0 {
            return Err(Error::InvalidArgument); // double free
        }
        self.bitmap_2m[word] |= 1u64 << bit;
        self.allocated_2m = self.allocated_2m.saturating_sub(1);
        Ok(())
    }

    /// Free a 1 GiB page.
    fn free_1g(&mut self, addr: u64) -> Result<()> {
        if addr < self.base_1g {
            return Err(Error::InvalidArgument);
        }
        let offset = (addr - self.base_1g) as usize;
        if offset % HUGE_PAGE_1G != 0 {
            return Err(Error::InvalidArgument);
        }
        let idx = offset / HUGE_PAGE_1G;
        if idx >= self.total_1g {
            return Err(Error::InvalidArgument);
        }
        let word = idx / 64;
        let bit = idx % 64;
        if self.bitmap_1g[word] & (1u64 << bit) != 0 {
            return Err(Error::InvalidArgument); // double free
        }
        self.bitmap_1g[word] |= 1u64 << bit;
        self.allocated_1g = self.allocated_1g.saturating_sub(1);
        Ok(())
    }

    /// Returns the number of free 2 MiB pages.
    pub fn free_2m_count(&self) -> usize {
        self.total_2m - self.allocated_2m
    }

    /// Returns the number of free 1 GiB pages.
    pub fn free_1g_count(&self) -> usize {
        self.total_1g - self.allocated_1g
    }

    /// Returns the total configured 2 MiB page count.
    pub fn total_2m_count(&self) -> usize {
        self.total_2m
    }

    /// Returns the total configured 1 GiB page count.
    pub fn total_1g_count(&self) -> usize {
        self.total_1g
    }
}

impl Default for HugePagePool {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Huge Page Mapping
// ---------------------------------------------------------------------------

/// Tracks a virtual mapping backed by a huge page.
#[derive(Debug, Clone, Copy)]
pub struct HugePageMapping {
    /// Virtual address (huge-page aligned).
    pub vaddr: u64,
    /// Physical address of the backing huge page.
    pub paddr: u64,
    /// Page size.
    pub size: HugePageSize,
    /// PID owning this mapping.
    pub pid: u32,
    /// Whether this slot is active.
    pub active: bool,
}

impl Default for HugePageMapping {
    fn default() -> Self {
        Self {
            vaddr: 0,
            paddr: 0,
            size: HugePageSize::Size2M,
            pid: 0,
            active: false,
        }
    }
}

/// Tracks all huge page mappings.
pub struct HugePageMappingTable {
    /// Mapping entries.
    entries: [HugePageMapping; MAX_MAPPINGS],
    /// Active mapping count.
    count: usize,
}

impl HugePageMappingTable {
    /// Create an empty mapping table.
    pub const fn new() -> Self {
        const EMPTY: HugePageMapping = HugePageMapping {
            vaddr: 0,
            paddr: 0,
            size: HugePageSize::Size2M,
            pid: 0,
            active: false,
        };
        Self {
            entries: [EMPTY; MAX_MAPPINGS],
            count: 0,
        }
    }

    /// Add a huge page mapping.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn add(&mut self, vaddr: u64, paddr: u64, size: HugePageSize, pid: u32) -> Result<usize> {
        let idx = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;
        self.entries[idx] = HugePageMapping {
            vaddr,
            paddr,
            size,
            pid,
            active: true,
        };
        self.count += 1;
        Ok(idx)
    }

    /// Remove a mapping by virtual address and PID.
    pub fn remove(&mut self, vaddr: u64, pid: u32) -> Option<HugePageMapping> {
        for entry in &mut self.entries {
            if entry.active && entry.vaddr == vaddr && entry.pid == pid {
                entry.active = false;
                self.count = self.count.saturating_sub(1);
                return Some(*entry);
            }
        }
        None
    }

    /// Look up a mapping by virtual address and PID.
    pub fn lookup(&self, vaddr: u64, pid: u32) -> Option<&HugePageMapping> {
        self.entries
            .iter()
            .find(|e| e.active && e.pid == pid && e.vaddr == vaddr)
    }

    /// Remove all mappings for a given PID. Returns removed count.
    pub fn remove_all_for_pid(&mut self, pid: u32) -> usize {
        let mut removed = 0;
        for entry in &mut self.entries {
            if entry.active && entry.pid == pid {
                entry.active = false;
                removed += 1;
            }
        }
        self.count = self.count.saturating_sub(removed);
        removed
    }

    /// Returns the number of active mappings.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if there are no active mappings.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for HugePageMappingTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Huge Page Statistics
// ---------------------------------------------------------------------------

/// Huge page usage statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct HugePageStats {
    /// Total 2 MiB pages configured.
    pub total_2m: usize,
    /// Free 2 MiB pages.
    pub free_2m: usize,
    /// Total 1 GiB pages configured.
    pub total_1g: usize,
    /// Free 1 GiB pages.
    pub free_1g: usize,
    /// Active mappings.
    pub active_mappings: usize,
}

impl HugePageStats {
    /// Collect stats from a pool and mapping table.
    pub fn collect(pool: &HugePagePool, mappings: &HugePageMappingTable) -> Self {
        Self {
            total_2m: pool.total_2m_count(),
            free_2m: pool.free_2m_count(),
            total_1g: pool.total_1g_count(),
            free_1g: pool.free_1g_count(),
            active_mappings: mappings.len(),
        }
    }

    /// Total huge page memory in bytes.
    pub fn total_bytes(&self) -> u64 {
        (self.total_2m as u64 * HUGE_PAGE_2M as u64) + (self.total_1g as u64 * HUGE_PAGE_1G as u64)
    }

    /// Free huge page memory in bytes.
    pub fn free_bytes(&self) -> u64 {
        (self.free_2m as u64 * HUGE_PAGE_2M as u64) + (self.free_1g as u64 * HUGE_PAGE_1G as u64)
    }
}

// ---------------------------------------------------------------------------
// Page Table Flags for Huge Pages (x86_64)
// ---------------------------------------------------------------------------

/// PTE flag: Present.
pub const PTE_PRESENT: u64 = 1 << 0;

/// PTE flag: Writable.
pub const PTE_WRITABLE: u64 = 1 << 1;

/// PTE flag: User accessible.
pub const PTE_USER: u64 = 1 << 2;

/// PTE flag: Page Size (PS) — marks a PDE as a 2 MiB or PDPTE as
/// a 1 GiB huge page.
pub const PTE_HUGE: u64 = 1 << 7;

/// PTE flag: Global (not flushed on CR3 switch).
pub const PTE_GLOBAL: u64 = 1 << 8;

/// PTE flag: No Execute (NX).
pub const PTE_NO_EXEC: u64 = 1 << 63;

/// Build page table entry flags for a huge page mapping.
pub fn huge_page_flags(writable: bool, user: bool, exec: bool) -> u64 {
    let mut flags = PTE_PRESENT | PTE_HUGE;
    if writable {
        flags |= PTE_WRITABLE;
    }
    if user {
        flags |= PTE_USER;
    }
    if !exec {
        flags |= PTE_NO_EXEC;
    }
    flags
}
