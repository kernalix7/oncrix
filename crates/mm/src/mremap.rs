// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory region remapping (`mremap`).
//!
//! Implements the `mremap(2)` system call semantics for resizing and
//! moving virtual memory regions. Supports:
//!
//! - **In-place expansion**: grow a mapping at its current address
//!   if adjacent virtual space is available.
//! - **In-place shrinkage**: truncate a mapping, unmapping trailing
//!   pages.
//! - **Move to new address**: relocate a mapping to a different
//!   virtual address (with `MREMAP_MAYMOVE`).
//! - **Fixed move**: relocate to a specific address (with
//!   `MREMAP_FIXED`).
//! - **VMA splitting/merging**: split a VMA when partially
//!   remapping, merge when adjacent compatible VMAs result.
//!
//! # Architecture
//!
//! - [`MremapFlags`] — flag set controlling mremap behavior
//! - [`VmaDescriptor`] — virtual memory area descriptor
//! - [`MremapRequest`] — parameters for a single mremap operation
//! - [`MremapResult`] — outcome of a mremap operation
//! - [`MremapStats`] — aggregate statistics
//! - [`MremapManager`] — engine that processes mremap requests
//!   against a VMA list
//!
//! Reference: Linux `mm/mremap.c`, `include/linux/mm.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of VMAs tracked.
const MAX_VMAS: usize = 256;

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Page alignment mask.
const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

// -------------------------------------------------------------------
// MremapFlags
// -------------------------------------------------------------------

/// Flags controlling `mremap` behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MremapFlags(u32);

impl MremapFlags {
    /// No special flags — try in-place only.
    pub const NONE: Self = Self(0);
    /// Allow the kernel to move the mapping to a new address.
    pub const MAYMOVE: Self = Self(1 << 0);
    /// Move the mapping to the exact address specified in
    /// `new_address` (implies MAYMOVE).
    pub const FIXED: Self = Self(1 << 1);
    /// Do not unmap the old mapping when moving (creates a
    /// shared alias). Linux 5.7+.
    pub const DONTUNMAP: Self = Self(1 << 2);

    /// Returns `true` if the flag is set.
    pub const fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 == flag.0
    }

    /// Returns the raw flag bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Creates flags from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Combines two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

// -------------------------------------------------------------------
// VmaProtection
// -------------------------------------------------------------------

/// Protection bits for a VMA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VmaProtection(u8);

impl VmaProtection {
    /// Read permission.
    pub const READ: Self = Self(1 << 0);
    /// Write permission.
    pub const WRITE: Self = Self(1 << 1);
    /// Execute permission.
    pub const EXEC: Self = Self(1 << 2);

    /// Returns `true` if the given bit is set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns the raw bits.
    pub const fn bits(self) -> u8 {
        self.0
    }
}

// -------------------------------------------------------------------
// VmaDescriptor
// -------------------------------------------------------------------

/// Virtual memory area descriptor.
///
/// Represents a contiguous virtual address range with uniform
/// protection and mapping properties.
#[derive(Debug, Clone, Copy)]
pub struct VmaDescriptor {
    /// Start virtual address (page-aligned).
    pub start: u64,
    /// Size in bytes (page-aligned).
    pub size: u64,
    /// Protection flags.
    pub prot: VmaProtection,
    /// Whether this VMA is locked in memory (mlock).
    pub locked: bool,
    /// Whether this VMA is a shared mapping.
    pub shared: bool,
    /// Whether this VMA is an anonymous mapping.
    pub anonymous: bool,
    /// Process ID that owns this VMA.
    pub owner_pid: u64,
    /// Whether this VMA slot is active.
    pub active: bool,
}

impl VmaDescriptor {
    /// Creates an empty, inactive VMA.
    const fn empty() -> Self {
        Self {
            start: 0,
            size: 0,
            prot: VmaProtection(0),
            locked: false,
            shared: false,
            anonymous: false,
            owner_pid: 0,
            active: false,
        }
    }

    /// Returns the end address (exclusive).
    pub const fn end(&self) -> u64 {
        self.start.saturating_add(self.size)
    }

    /// Returns `true` if this VMA overlaps `[addr, addr+size)`.
    pub const fn overlaps(&self, addr: u64, size: u64) -> bool {
        let end = addr.saturating_add(size);
        self.start < end && addr < self.end()
    }

    /// Returns `true` if this VMA is compatible with `other` for
    /// merging (same protection, shared, anon, owner).
    pub const fn merge_compatible(&self, other: &Self) -> bool {
        self.prot.0 == other.prot.0
            && self.shared == other.shared
            && self.anonymous == other.anonymous
            && self.owner_pid == other.owner_pid
            && self.locked == other.locked
    }
}

// -------------------------------------------------------------------
// MremapResult
// -------------------------------------------------------------------

/// Outcome of a mremap operation.
#[derive(Debug, Clone, Copy)]
pub struct MremapResult {
    /// New start address of the mapping.
    pub new_addr: u64,
    /// New size of the mapping.
    pub new_size: u64,
    /// Whether the mapping was moved.
    pub moved: bool,
    /// Number of page table entries updated.
    pub ptes_updated: u64,
}

// -------------------------------------------------------------------
// MremapStats
// -------------------------------------------------------------------

/// Aggregate mremap statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MremapStats {
    /// Total mremap calls.
    pub total_calls: u64,
    /// Successful in-place expansions.
    pub expand_inplace: u64,
    /// Successful in-place shrinkages.
    pub shrink_inplace: u64,
    /// Successful moves.
    pub moves: u64,
    /// Failed mremap calls.
    pub failures: u64,
    /// VMA splits performed.
    pub vma_splits: u64,
    /// VMA merges performed.
    pub vma_merges: u64,
}

// -------------------------------------------------------------------
// MremapManager
// -------------------------------------------------------------------

/// Engine that processes mremap requests against a VMA list.
///
/// Manages a flat array of VMAs and supports expand, shrink, move,
/// split, and merge operations.
pub struct MremapManager {
    /// VMA descriptors.
    vmas: [VmaDescriptor; MAX_VMAS],
    /// Number of active VMAs.
    vma_count: usize,
    /// Statistics.
    stats: MremapStats,
}

impl Default for MremapManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MremapManager {
    /// Creates a new manager with no VMAs.
    pub const fn new() -> Self {
        Self {
            vmas: [VmaDescriptor::empty(); MAX_VMAS],
            vma_count: 0,
            stats: MremapStats {
                total_calls: 0,
                expand_inplace: 0,
                shrink_inplace: 0,
                moves: 0,
                failures: 0,
                vma_splits: 0,
                vma_merges: 0,
            },
        }
    }

    // ---------------------------------------------------------------
    // VMA management
    // ---------------------------------------------------------------

    /// Adds a VMA to the manager.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all VMA slots are full.
    /// Returns [`Error::InvalidArgument`] if `size` is zero or
    /// addresses are not page-aligned.
    pub fn add_vma(
        &mut self,
        start: u64,
        size: u64,
        prot: VmaProtection,
        owner_pid: u64,
        anonymous: bool,
    ) -> Result<()> {
        if size == 0 || start & (PAGE_SIZE - 1) != 0 || size & (PAGE_SIZE - 1) != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.vma_count >= MAX_VMAS {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .vmas
            .iter_mut()
            .find(|v| !v.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = VmaDescriptor {
            start,
            size,
            prot,
            locked: false,
            shared: false,
            anonymous,
            owner_pid,
            active: true,
        };

        self.vma_count += 1;
        Ok(())
    }

    /// Removes a VMA by start address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no VMA starts at the given
    /// address.
    pub fn remove_vma(&mut self, start: u64) -> Result<()> {
        let idx = self.find_vma_index(start).ok_or(Error::NotFound)?;
        self.vmas[idx].active = false;
        self.vma_count = self.vma_count.saturating_sub(1);
        Ok(())
    }

    /// Returns the number of active VMAs.
    pub const fn vma_count(&self) -> usize {
        self.vma_count
    }

    /// Returns a reference to a VMA by start address.
    pub fn find_vma(&self, start: u64) -> Option<&VmaDescriptor> {
        self.vmas.iter().find(|v| v.active && v.start == start)
    }

    // ---------------------------------------------------------------
    // mremap core
    // ---------------------------------------------------------------

    /// Performs a mremap operation.
    ///
    /// `old_addr` and `old_size` identify the existing mapping.
    /// `new_size` is the desired new size.
    /// `flags` controls whether moving is allowed.
    /// `new_addr_hint` is used only with `MREMAP_FIXED`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no VMA covers `old_addr`.
    /// Returns [`Error::InvalidArgument`] for invalid parameters.
    /// Returns [`Error::OutOfMemory`] if expansion or move fails.
    pub fn mremap(
        &mut self,
        old_addr: u64,
        old_size: u64,
        new_size: u64,
        flags: MremapFlags,
        new_addr_hint: u64,
    ) -> Result<MremapResult> {
        self.stats.total_calls += 1;

        // Validate alignment.
        if old_addr & (PAGE_SIZE - 1) != 0 {
            self.stats.failures += 1;
            return Err(Error::InvalidArgument);
        }

        let old_size = page_align_up(old_size);
        let new_size = page_align_up(new_size);

        if new_size == 0 {
            self.stats.failures += 1;
            return Err(Error::InvalidArgument);
        }

        // FIXED implies MAYMOVE.
        if flags.contains(MremapFlags::FIXED) && new_addr_hint & (PAGE_SIZE - 1) != 0 {
            self.stats.failures += 1;
            return Err(Error::InvalidArgument);
        }

        // Find the VMA.
        let vma_idx = self.find_vma_index(old_addr).ok_or_else(|| {
            self.stats.failures += 1;
            Error::NotFound
        })?;

        // Shrink case.
        if new_size < old_size {
            return self.shrink(vma_idx, old_addr, old_size, new_size);
        }

        // Same size — no-op.
        if new_size == old_size {
            let vma = &self.vmas[vma_idx];
            return Ok(MremapResult {
                new_addr: vma.start,
                new_size,
                moved: false,
                ptes_updated: 0,
            });
        }

        // Expand case.
        // Try in-place first.
        if self.can_expand_inplace(vma_idx, new_size) {
            return self.expand_inplace(vma_idx, new_size);
        }

        // Try moving if allowed.
        if flags.contains(MremapFlags::MAYMOVE) || flags.contains(MremapFlags::FIXED) {
            let target = if flags.contains(MremapFlags::FIXED) {
                new_addr_hint
            } else {
                self.find_free_region(new_size)?
            };

            return self.move_vma(
                vma_idx,
                target,
                new_size,
                flags.contains(MremapFlags::DONTUNMAP),
            );
        }

        self.stats.failures += 1;
        Err(Error::OutOfMemory)
    }

    // ---------------------------------------------------------------
    // Shrink
    // ---------------------------------------------------------------

    /// Shrinks a VMA in place.
    fn shrink(
        &mut self,
        vma_idx: usize,
        _old_addr: u64,
        old_size: u64,
        new_size: u64,
    ) -> Result<MremapResult> {
        // If shrinking to less than the VMA, split.
        let vma = &self.vmas[vma_idx];
        let vma_start = vma.start;

        if new_size < old_size {
            // Unmap trailing pages.
            let pages_freed = (old_size - new_size) / PAGE_SIZE;
            self.vmas[vma_idx].size = new_size;

            self.stats.shrink_inplace += 1;
            return Ok(MremapResult {
                new_addr: vma_start,
                new_size,
                moved: false,
                ptes_updated: pages_freed,
            });
        }

        Ok(MremapResult {
            new_addr: vma_start,
            new_size,
            moved: false,
            ptes_updated: 0,
        })
    }

    // ---------------------------------------------------------------
    // Expand in-place
    // ---------------------------------------------------------------

    /// Checks whether a VMA can be expanded in place.
    fn can_expand_inplace(&self, vma_idx: usize, new_size: u64) -> bool {
        let vma = &self.vmas[vma_idx];
        let new_end = vma.start.saturating_add(new_size);
        let growth = new_size.saturating_sub(vma.size);

        // Check no other VMA overlaps the growth region.
        let growth_start = vma.end();
        for (i, other) in self.vmas.iter().enumerate() {
            if i == vma_idx || !other.active {
                continue;
            }
            if other.overlaps(growth_start, growth) {
                return false;
            }
        }

        // Sanity: new_end must not wrap.
        new_end > vma.start
    }

    /// Expands a VMA in place.
    fn expand_inplace(&mut self, vma_idx: usize, new_size: u64) -> Result<MremapResult> {
        let old_size = self.vmas[vma_idx].size;
        let pages_added = (new_size - old_size) / PAGE_SIZE;

        self.vmas[vma_idx].size = new_size;
        self.stats.expand_inplace += 1;

        Ok(MremapResult {
            new_addr: self.vmas[vma_idx].start,
            new_size,
            moved: false,
            ptes_updated: pages_added,
        })
    }

    // ---------------------------------------------------------------
    // Move
    // ---------------------------------------------------------------

    /// Moves a VMA to a new address.
    fn move_vma(
        &mut self,
        vma_idx: usize,
        new_addr: u64,
        new_size: u64,
        dont_unmap: bool,
    ) -> Result<MremapResult> {
        // Verify the target region is free.
        for (i, other) in self.vmas.iter().enumerate() {
            if i == vma_idx || !other.active {
                continue;
            }
            if other.overlaps(new_addr, new_size) {
                self.stats.failures += 1;
                return Err(Error::OutOfMemory);
            }
        }

        let old_size = self.vmas[vma_idx].size;
        let pages_moved = old_size / PAGE_SIZE;

        if dont_unmap {
            // Create a new VMA at the target, keep the old one.
            let vma = self.vmas[vma_idx];
            self.add_vma(new_addr, new_size, vma.prot, vma.owner_pid, vma.anonymous)?;
        } else {
            // Update the VMA in-place.
            self.vmas[vma_idx].start = new_addr;
            self.vmas[vma_idx].size = new_size;
        }

        self.stats.moves += 1;
        Ok(MremapResult {
            new_addr,
            new_size,
            moved: true,
            ptes_updated: pages_moved,
        })
    }

    // ---------------------------------------------------------------
    // VMA split
    // ---------------------------------------------------------------

    /// Splits a VMA at the given address.
    ///
    /// The original VMA is shrunk to `[start, addr)` and a new
    /// VMA is created for `[addr, end)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no VMA contains `addr`.
    /// Returns [`Error::InvalidArgument`] if `addr` is at the
    /// start or end of the VMA (no split needed).
    /// Returns [`Error::OutOfMemory`] if no VMA slot is available.
    pub fn split_vma(&mut self, addr: u64) -> Result<()> {
        let addr = page_align_up(addr);

        let idx = self
            .vmas
            .iter()
            .position(|v| v.active && addr > v.start && addr < v.end())
            .ok_or(Error::NotFound)?;

        let vma = self.vmas[idx];
        let left_size = addr - vma.start;
        let right_size = vma.end() - addr;

        // Shrink original to the left part.
        self.vmas[idx].size = left_size;

        // Create the right part.
        self.add_vma(addr, right_size, vma.prot, vma.owner_pid, vma.anonymous)?;

        self.stats.vma_splits += 1;
        Ok(())
    }

    /// Attempts to merge adjacent compatible VMAs.
    ///
    /// Returns the number of merges performed.
    pub fn merge_adjacent(&mut self) -> usize {
        let mut merges = 0_usize;
        let mut changed = true;

        while changed {
            changed = false;
            for i in 0..MAX_VMAS {
                if !self.vmas[i].active {
                    continue;
                }
                let end_i = self.vmas[i].end();

                for j in (i + 1)..MAX_VMAS {
                    if !self.vmas[j].active {
                        continue;
                    }

                    // Check if j starts where i ends.
                    if self.vmas[j].start == end_i && self.vmas[i].merge_compatible(&self.vmas[j]) {
                        self.vmas[i].size = self.vmas[i].size.saturating_add(self.vmas[j].size);
                        self.vmas[j].active = false;
                        self.vma_count = self.vma_count.saturating_sub(1);
                        merges += 1;
                        self.stats.vma_merges += 1;
                        changed = true;
                        break;
                    }
                }
                if changed {
                    break;
                }
            }
        }

        merges
    }

    // ---------------------------------------------------------------
    // Free region search
    // ---------------------------------------------------------------

    /// Finds a free virtual address region of the given size.
    fn find_free_region(&self, size: u64) -> Result<u64> {
        // Simple first-fit above all existing VMAs.
        let mut candidate: u64 = PAGE_SIZE; // Start above NULL.

        // Collect active VMA ranges and sort by start.
        let mut ranges: [(u64, u64); MAX_VMAS] = [(0, 0); MAX_VMAS];
        let mut count = 0_usize;

        for vma in &self.vmas {
            if vma.active {
                ranges[count] = (vma.start, vma.end());
                count += 1;
            }
        }

        // Sort by start (insertion sort).
        for i in 1..count {
            let mut j = i;
            while j > 0 && ranges[j].0 < ranges[j - 1].0 {
                ranges.swap(j, j - 1);
                j -= 1;
            }
        }

        for i in 0..count {
            if candidate + size <= ranges[i].0 {
                return Ok(candidate);
            }
            if ranges[i].1 > candidate {
                candidate = ranges[i].1;
            }
        }

        // Try after the last VMA.
        if candidate.checked_add(size).is_some() {
            return Ok(candidate);
        }

        Err(Error::OutOfMemory)
    }

    // ---------------------------------------------------------------
    // Accessors
    // ---------------------------------------------------------------

    /// Returns aggregate statistics.
    pub const fn stats(&self) -> &MremapStats {
        &self.stats
    }

    /// Returns `true` if no VMAs are tracked.
    pub const fn is_empty(&self) -> bool {
        self.vma_count == 0
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Finds the index of a VMA by start address.
    fn find_vma_index(&self, start: u64) -> Option<usize> {
        self.vmas.iter().position(|v| v.active && v.start == start)
    }
}

/// Rounds `size` up to the next page boundary.
const fn page_align_up(size: u64) -> u64 {
    (size + PAGE_SIZE - 1) & PAGE_MASK
}
