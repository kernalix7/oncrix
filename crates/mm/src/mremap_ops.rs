// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! mremap operations for the ONCRIX memory management subsystem.
//!
//! Implements the `mremap(2)` system call, which allows a process to
//! resize and/or move an existing memory mapping. Supports in-place
//! expansion, shrinking, and relocation of mappings.
//!
//! - [`MremapFlags`] — flags controlling remap behavior
//! - [`MremapOps`] — main mremap handler with mapping table
//! - [`MremapResult`] — outcome of a remap operation
//! - [`MremapStats`] — operation statistics
//!
//! Reference: `.kernelORG/` — `mm/mremap.c`, POSIX `mremap(2)`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of mappings tracked.
const MAX_MAPPINGS: usize = 256;

/// Maximum mapping size (1 GiB).
const MAX_MAPPING_SIZE: u64 = 1024 * 1024 * 1024;

// -------------------------------------------------------------------
// MremapFlags
// -------------------------------------------------------------------

/// Flags for the mremap operation.
pub struct MremapFlags;

impl MremapFlags {
    /// Allow the kernel to relocate the mapping if in-place expansion
    /// is not possible.
    pub const MAYMOVE: u32 = 1 << 0;
    /// Place the mapping at the exact address specified (requires MAYMOVE).
    pub const FIXED: u32 = 1 << 1;
    /// Don't unmap the original mapping when moving (create a copy).
    pub const DONTUNMAP: u32 = 1 << 2;
}

// -------------------------------------------------------------------
// MappingState
// -------------------------------------------------------------------

/// State of a memory mapping for mremap tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MappingState {
    /// Mapping is free (slot unused).
    #[default]
    Free,
    /// Mapping is active.
    Active,
    /// Mapping has been moved (original location).
    Moved,
}

// -------------------------------------------------------------------
// Mapping
// -------------------------------------------------------------------

/// A memory mapping entry.
#[derive(Debug, Clone, Copy)]
pub struct Mapping {
    /// Start address (page-aligned).
    pub start: u64,
    /// Size in bytes (page-aligned).
    pub size: u64,
    /// Protection flags (read/write/exec).
    pub prot: u32,
    /// Mapping flags (shared/private/etc.).
    pub map_flags: u32,
    /// Number of resident pages.
    pub resident_pages: u64,
    /// State of this mapping.
    pub state: MappingState,
    /// Whether this mapping is file-backed.
    pub file_backed: bool,
    /// File offset (for file-backed mappings).
    pub file_offset: u64,
}

impl Mapping {
    /// Create an empty (free) mapping.
    pub const fn empty() -> Self {
        Self {
            start: 0,
            size: 0,
            prot: 0,
            map_flags: 0,
            resident_pages: 0,
            state: MappingState::Free,
            file_backed: false,
            file_offset: 0,
        }
    }

    /// Check if the mapping is active.
    pub fn is_active(&self) -> bool {
        matches!(self.state, MappingState::Active)
    }

    /// End address (exclusive).
    pub fn end(&self) -> u64 {
        self.start + self.size
    }

    /// Number of pages in the mapping.
    pub fn page_count(&self) -> u64 {
        self.size / PAGE_SIZE
    }

    /// Check if the mapping contains the given address.
    pub fn contains(&self, addr: u64) -> bool {
        self.is_active() && addr >= self.start && addr < self.end()
    }

    /// Check if this mapping can expand in-place by `extra` bytes
    /// without colliding with `other` mappings.
    pub fn can_expand(&self, extra: u64, others: &[Mapping]) -> bool {
        let new_end = self.end() + extra;
        for other in others {
            if !other.is_active() {
                continue;
            }
            if other.start == self.start {
                continue;
            }
            if new_end > other.start && self.start < other.end() {
                return false;
            }
        }
        true
    }
}

// -------------------------------------------------------------------
// MremapResult
// -------------------------------------------------------------------

/// Outcome of a mremap operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MremapResult {
    /// Mapping was expanded or shrunk in place.
    InPlace(u64),
    /// Mapping was moved to a new address.
    Moved(u64),
    /// Mapping was shrunk (no move needed).
    Shrunk(u64),
}

impl MremapResult {
    /// Get the resulting address.
    pub fn address(&self) -> u64 {
        match self {
            MremapResult::InPlace(a) | MremapResult::Moved(a) | MremapResult::Shrunk(a) => *a,
        }
    }
}

// -------------------------------------------------------------------
// MremapStats
// -------------------------------------------------------------------

/// Statistics for mremap operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct MremapStats {
    /// Total mremap calls.
    pub total_calls: u64,
    /// Number of in-place expansions.
    pub in_place_grows: u64,
    /// Number of in-place shrinks.
    pub in_place_shrinks: u64,
    /// Number of moves.
    pub moves: u64,
    /// Number of failures.
    pub failures: u64,
    /// Total bytes remapped.
    pub bytes_remapped: u64,
    /// Number of TLB flushes triggered.
    pub tlb_flushes: u64,
}

// -------------------------------------------------------------------
// MremapOps
// -------------------------------------------------------------------

/// Main mremap handler.
///
/// Manages memory mappings and processes mremap requests to resize
/// or relocate them.
pub struct MremapOps {
    /// Mapping table.
    mappings: [Mapping; MAX_MAPPINGS],
    /// Number of mapping slots in use (may include freed slots).
    mapping_count: usize,
    /// Next available virtual address for new mappings.
    next_va: u64,
    /// Statistics.
    stats: MremapStats,
}

impl MremapOps {
    /// Create a new mremap handler.
    pub fn new() -> Self {
        Self {
            mappings: [Mapping::empty(); MAX_MAPPINGS],
            mapping_count: 0,
            next_va: 0x7F00_0000_0000,
            stats: MremapStats::default(),
        }
    }

    /// Register a mapping.
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if the mapping table is full, or
    /// `InvalidArgument` if the range is invalid.
    pub fn register_mapping(
        &mut self,
        start: u64,
        size: u64,
        prot: u32,
        map_flags: u32,
    ) -> Result<usize> {
        if size == 0 || start % PAGE_SIZE != 0 || size % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.mapping_count >= MAX_MAPPINGS {
            return Err(Error::OutOfMemory);
        }

        let idx = self.mapping_count;
        self.mappings[idx] = Mapping {
            start,
            size,
            prot,
            map_flags,
            resident_pages: size / PAGE_SIZE,
            state: MappingState::Active,
            file_backed: false,
            file_offset: 0,
        };
        self.mapping_count += 1;

        if start + size > self.next_va {
            self.next_va = start + size + PAGE_SIZE;
        }

        Ok(idx)
    }

    /// Perform an mremap operation.
    ///
    /// Resizes or moves the mapping at `old_addr` from `old_size` to
    /// `new_size`. If `flags` includes `MAYMOVE`, the mapping may be
    /// relocated. If `flags` includes `FIXED`, `new_addr` specifies
    /// the target address.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` for invalid parameters,
    /// `NotFound` if no mapping exists at `old_addr`, or
    /// `OutOfMemory` if the mapping cannot be expanded.
    pub fn do_mremap(
        &mut self,
        old_addr: u64,
        old_size: u64,
        new_size: u64,
        flags: u32,
        new_addr: u64,
    ) -> Result<MremapResult> {
        // Validate parameters.
        if old_addr % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if new_size == 0 || new_size > MAX_MAPPING_SIZE {
            return Err(Error::InvalidArgument);
        }

        let aligned_old = (old_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let aligned_new = (new_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        self.stats.total_calls += 1;

        // Find the mapping.
        let map_idx = self.find_mapping(old_addr).ok_or(Error::NotFound)?;

        // Verify old_size matches (or is within) the mapping.
        if aligned_old > self.mappings[map_idx].size {
            self.stats.failures += 1;
            return Err(Error::InvalidArgument);
        }

        // Case 1: Shrinking.
        if aligned_new < aligned_old {
            return self.do_shrink(map_idx, aligned_new);
        }

        // Case 2: Same size.
        if aligned_new == aligned_old {
            return Ok(MremapResult::InPlace(old_addr));
        }

        // Case 3: Growing.
        let extra = aligned_new - self.mappings[map_idx].size;

        // Try in-place expansion first.
        if self.can_expand_in_place(map_idx, extra) {
            return self.do_expand_in_place(map_idx, aligned_new);
        }

        // Cannot expand in place — check MAYMOVE.
        if flags & MremapFlags::MAYMOVE == 0 {
            self.stats.failures += 1;
            return Err(Error::OutOfMemory);
        }

        // If FIXED, use the specified address; otherwise, find a free slot.
        let target = if flags & MremapFlags::FIXED != 0 {
            if new_addr % PAGE_SIZE != 0 {
                self.stats.failures += 1;
                return Err(Error::InvalidArgument);
            }
            new_addr
        } else {
            self.find_free_range(aligned_new)?
        };

        let dont_unmap = flags & MremapFlags::DONTUNMAP != 0;
        self.do_move(map_idx, target, aligned_new, dont_unmap)
    }

    /// Try in-place expansion of a mapping.
    fn can_expand_in_place(&self, map_idx: usize, extra: u64) -> bool {
        let mapping = &self.mappings[map_idx];
        let new_end = mapping.end() + extra;

        for i in 0..self.mapping_count {
            if i == map_idx {
                continue;
            }
            let other = &self.mappings[i];
            if !other.is_active() {
                continue;
            }
            if new_end > other.start && mapping.end() <= other.start {
                return false;
            }
        }
        true
    }

    /// Shrink a mapping in place.
    fn do_shrink(&mut self, map_idx: usize, new_size: u64) -> Result<MremapResult> {
        let mapping = &mut self.mappings[map_idx];
        let old_size = mapping.size;
        mapping.size = new_size;
        mapping.resident_pages = new_size / PAGE_SIZE;

        self.stats.in_place_shrinks += 1;
        self.stats.bytes_remapped += old_size.saturating_sub(new_size);
        self.stats.tlb_flushes += 1;

        Ok(MremapResult::Shrunk(mapping.start))
    }

    /// Expand a mapping in place.
    fn do_expand_in_place(&mut self, map_idx: usize, new_size: u64) -> Result<MremapResult> {
        let mapping = &mut self.mappings[map_idx];
        let addr = mapping.start;
        mapping.size = new_size;
        mapping.resident_pages = new_size / PAGE_SIZE;

        self.stats.in_place_grows += 1;
        self.stats.bytes_remapped += new_size;

        Ok(MremapResult::InPlace(addr))
    }

    /// Move a mapping to a new address.
    fn do_move(
        &mut self,
        map_idx: usize,
        new_addr: u64,
        new_size: u64,
        dont_unmap: bool,
    ) -> Result<MremapResult> {
        let old_mapping = self.mappings[map_idx];

        // Create the new mapping at the target address.
        if self.mapping_count >= MAX_MAPPINGS {
            self.stats.failures += 1;
            return Err(Error::OutOfMemory);
        }

        let new_idx = self.mapping_count;
        self.mappings[new_idx] = Mapping {
            start: new_addr,
            size: new_size,
            prot: old_mapping.prot,
            map_flags: old_mapping.map_flags,
            resident_pages: new_size / PAGE_SIZE,
            state: MappingState::Active,
            file_backed: old_mapping.file_backed,
            file_offset: old_mapping.file_offset,
        };
        self.mapping_count += 1;

        // Mark the old mapping.
        if dont_unmap {
            // Keep the old mapping but mark it as moved.
            self.mappings[map_idx].state = MappingState::Moved;
        } else {
            // Free the old mapping.
            self.mappings[map_idx].state = MappingState::Free;
        }

        if new_addr + new_size > self.next_va {
            self.next_va = new_addr + new_size + PAGE_SIZE;
        }

        self.stats.moves += 1;
        self.stats.bytes_remapped += new_size;
        self.stats.tlb_flushes += 1;

        Ok(MremapResult::Moved(new_addr))
    }

    /// Find a free virtual address range of the given size.
    fn find_free_range(&self, size: u64) -> Result<u64> {
        let mut candidate = self.next_va;

        // Simple bump allocation for finding free ranges.
        let aligned = (candidate + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        if aligned + size < aligned {
            return Err(Error::OutOfMemory);
        }

        // Verify no overlaps.
        for i in 0..self.mapping_count {
            let m = &self.mappings[i];
            if !m.is_active() {
                continue;
            }
            if aligned < m.end() && aligned + size > m.start {
                candidate = m.end() + PAGE_SIZE;
            }
        }

        Ok((candidate + PAGE_SIZE - 1) & !(PAGE_SIZE - 1))
    }

    /// Find a mapping by its start address.
    fn find_mapping(&self, addr: u64) -> Option<usize> {
        for i in 0..self.mapping_count {
            if self.mappings[i].is_active() && self.mappings[i].start == addr {
                return Some(i);
            }
        }
        None
    }

    /// Get statistics.
    pub fn statistics(&self) -> &MremapStats {
        &self.stats
    }

    /// Get the number of active mappings.
    pub fn active_count(&self) -> usize {
        self.mappings
            .iter()
            .take(self.mapping_count)
            .filter(|m| m.is_active())
            .count()
    }

    /// Get a mapping by index.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the index is out of bounds.
    pub fn get_mapping(&self, idx: usize) -> Result<&Mapping> {
        if idx >= self.mapping_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.mappings[idx])
    }
}
