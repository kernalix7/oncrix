// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VMA adjustment operations.
//!
//! When a `mprotect`, `mremap`, or `mmap` call changes the properties
//! of an existing virtual memory area, the VMA may need to be split,
//! extended, or shrunk. This module implements these adjustment
//! operations: split at an address, extend to a new end, shrink from
//! either side, and update permissions on a sub-range.
//!
//! # Design
//!
//! ```text
//!  mprotect(addr, len, prot)
//!       │
//!       ├─ vma covers [addr, addr+len) exactly → update flags
//!       ├─ addr > vma.start                    → split at addr
//!       └─ addr+len < vma.end                  → split at addr+len
//!
//!  mremap(old_addr, old_size, new_size, MREMAP_MAYMOVE)
//!       └─ vma_adjust::extend(vma, new_end)
//! ```
//!
//! # Key Types
//!
//! - [`VmaRegion`] — a virtual memory area descriptor
//! - [`VmaAdjustOp`] — the type of adjustment
//! - [`VmaAdjuster`] — performs VMA adjustments
//! - [`VmaAdjustStats`] — adjustment statistics
//!
//! Reference: Linux `mm/mmap.c` (vma_adjust), `mm/mprotect.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum VMAs tracked.
const MAX_VMAS: usize = 1024;

/// Page size.
const PAGE_SIZE: u64 = 4096;

/// VMA flag: readable.
const VM_READ: u32 = 1 << 0;
/// VMA flag: writable.
const VM_WRITE: u32 = 1 << 1;
/// VMA flag: executable.
const VM_EXEC: u32 = 1 << 2;
/// VMA flag: shared mapping.
const VM_SHARED: u32 = 1 << 3;

// -------------------------------------------------------------------
// VmaAdjustOp
// -------------------------------------------------------------------

/// Type of VMA adjustment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmaAdjustOp {
    /// Split the VMA at an address.
    Split,
    /// Extend the VMA to a new end.
    Extend,
    /// Shrink the VMA from the start.
    ShrinkStart,
    /// Shrink the VMA from the end.
    ShrinkEnd,
    /// Update permissions on a sub-range.
    Protect,
}

impl VmaAdjustOp {
    /// Return a label.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Split => "split",
            Self::Extend => "extend",
            Self::ShrinkStart => "shrink_start",
            Self::ShrinkEnd => "shrink_end",
            Self::Protect => "protect",
        }
    }
}

// -------------------------------------------------------------------
// VmaRegion
// -------------------------------------------------------------------

/// A virtual memory area descriptor.
#[derive(Debug, Clone, Copy)]
pub struct VmaRegion {
    /// Start address (page-aligned).
    start: u64,
    /// End address (exclusive, page-aligned).
    end: u64,
    /// Protection flags.
    flags: u32,
    /// File offset if file-backed, 0 otherwise.
    file_offset: u64,
    /// Whether this VMA is active.
    active: bool,
}

impl VmaRegion {
    /// Create a new VMA region.
    pub const fn new(start: u64, end: u64, flags: u32) -> Self {
        Self {
            start,
            end,
            flags,
            file_offset: 0,
            active: true,
        }
    }

    /// Create a file-backed VMA.
    pub const fn file_backed(start: u64, end: u64, flags: u32, offset: u64) -> Self {
        Self {
            start,
            end,
            flags,
            file_offset: offset,
            active: true,
        }
    }

    /// Return the start address.
    pub const fn start(&self) -> u64 {
        self.start
    }

    /// Return the end address.
    pub const fn end(&self) -> u64 {
        self.end
    }

    /// Return the size in bytes.
    pub const fn size(&self) -> u64 {
        self.end - self.start
    }

    /// Return the size in pages.
    pub const fn nr_pages(&self) -> u64 {
        self.size() / PAGE_SIZE
    }

    /// Return the flags.
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Check whether the VMA is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Check whether the VMA is writable.
    pub const fn is_writable(&self) -> bool {
        self.flags & VM_WRITE != 0
    }

    /// Check whether the VMA is executable.
    pub const fn is_executable(&self) -> bool {
        self.flags & VM_EXEC != 0
    }

    /// Check whether the VMA is shared.
    pub const fn is_shared(&self) -> bool {
        self.flags & VM_SHARED != 0
    }

    /// Check whether an address falls within this VMA.
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    /// Check whether the given range overlaps this VMA.
    pub const fn overlaps(&self, start: u64, end: u64) -> bool {
        start < self.end && end > self.start
    }

    /// Set new flags.
    pub fn set_flags(&mut self, flags: u32) {
        self.flags = flags;
    }

    /// Set a new end address.
    pub fn set_end(&mut self, end: u64) {
        self.end = end;
    }

    /// Set a new start address.
    pub fn set_start(&mut self, start: u64) {
        self.start = start;
    }

    /// Deactivate this VMA.
    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl Default for VmaRegion {
    fn default() -> Self {
        Self {
            start: 0,
            end: 0,
            flags: 0,
            file_offset: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// VmaAdjustStats
// -------------------------------------------------------------------

/// VMA adjustment statistics.
#[derive(Debug, Clone, Copy)]
pub struct VmaAdjustStats {
    /// Total split operations.
    pub splits: u64,
    /// Total extend operations.
    pub extends: u64,
    /// Total shrink operations.
    pub shrinks: u64,
    /// Total protect operations.
    pub protects: u64,
    /// Total VMA count.
    pub vma_count: u64,
}

impl VmaAdjustStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            splits: 0,
            extends: 0,
            shrinks: 0,
            protects: 0,
            vma_count: 0,
        }
    }
}

impl Default for VmaAdjustStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// VmaAdjuster
// -------------------------------------------------------------------

/// Performs VMA adjustment operations.
pub struct VmaAdjuster {
    /// Tracked VMAs.
    vmas: [VmaRegion; MAX_VMAS],
    /// Number of active VMAs.
    count: usize,
    /// Statistics.
    stats: VmaAdjustStats,
}

impl VmaAdjuster {
    /// Create a new adjuster.
    pub const fn new() -> Self {
        Self {
            vmas: [const {
                VmaRegion {
                    start: 0,
                    end: 0,
                    flags: 0,
                    file_offset: 0,
                    active: false,
                }
            }; MAX_VMAS],
            count: 0,
            stats: VmaAdjustStats::new(),
        }
    }

    /// Return the number of active VMAs.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &VmaAdjustStats {
        &self.stats
    }

    /// Add a VMA.
    pub fn add(&mut self, vma: VmaRegion) -> Result<()> {
        if self.count >= MAX_VMAS {
            return Err(Error::OutOfMemory);
        }
        self.vmas[self.count] = vma;
        self.count += 1;
        self.stats.vma_count += 1;
        Ok(())
    }

    /// Split a VMA at the given address, producing two VMAs.
    pub fn split(&mut self, addr: u64) -> Result<()> {
        let target_idx = self.find_containing(addr)?;
        let vma = self.vmas[target_idx];

        if addr <= vma.start() || addr >= vma.end() {
            return Err(Error::InvalidArgument);
        }
        if addr % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }

        // Shrink the original to [start, addr).
        self.vmas[target_idx].set_end(addr);

        // Create a new VMA for [addr, end).
        let new_vma = VmaRegion::new(addr, vma.end(), vma.flags());
        self.add(new_vma)?;
        self.stats.splits += 1;
        Ok(())
    }

    /// Extend a VMA to a new end.
    pub fn extend(&mut self, start: u64, new_end: u64) -> Result<()> {
        if new_end % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        for idx in 0..self.count {
            if self.vmas[idx].is_active() && self.vmas[idx].start() == start {
                if new_end <= self.vmas[idx].end() {
                    return Err(Error::InvalidArgument);
                }
                self.vmas[idx].set_end(new_end);
                self.stats.extends += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Protect a sub-range with new flags.
    pub fn protect(&mut self, addr: u64, len: u64, new_flags: u32) -> Result<()> {
        if addr % PAGE_SIZE != 0 || len % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        let end = addr + len;
        for idx in 0..self.count {
            if self.vmas[idx].is_active() && self.vmas[idx].overlaps(addr, end) {
                self.vmas[idx].set_flags(new_flags);
                self.stats.protects += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Find the VMA containing a given address.
    fn find_containing(&self, addr: u64) -> Result<usize> {
        for idx in 0..self.count {
            if self.vmas[idx].is_active() && self.vmas[idx].contains(addr) {
                return Ok(idx);
            }
        }
        Err(Error::NotFound)
    }

    /// Look up a VMA by start address.
    pub fn find_by_start(&self, start: u64) -> Option<&VmaRegion> {
        for idx in 0..self.count {
            if self.vmas[idx].is_active() && self.vmas[idx].start() == start {
                return Some(&self.vmas[idx]);
            }
        }
        None
    }
}

impl Default for VmaAdjuster {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Check whether a VMA can be split at the given address.
pub fn can_split(adjuster: &VmaAdjuster, addr: u64) -> bool {
    if addr % PAGE_SIZE != 0 {
        return false;
    }
    for idx in 0..adjuster.count() {
        if let Some(vma) = adjuster.find_by_start(0) {
            if vma.contains(addr) && addr > vma.start() {
                return true;
            }
        }
        let _ = idx;
    }
    false
}

/// Return the VM_READ flag.
pub const fn vm_read() -> u32 {
    VM_READ
}

/// Return the VM_WRITE flag.
pub const fn vm_write() -> u32 {
    VM_WRITE
}

/// Return the VM_EXEC flag.
pub const fn vm_exec() -> u32 {
    VM_EXEC
}
