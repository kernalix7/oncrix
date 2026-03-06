// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VMA (Virtual Memory Area) merge operations.
//!
//! Adjacent VMAs with compatible attributes (same protection, flags,
//! and backing file) can be merged into a single VMA to reduce the
//! total number of VMA entries in a process's address space. Fewer
//! VMAs improve lookup performance and reduce metadata overhead.
//!
//! This module implements:
//!
//! - [`VmaCanMerge`] — classification of merge eligibility
//! - [`VmaCompatFlags`] — compatibility attributes for merge testing
//! - [`VmaEntry`] — a single VMA descriptor
//! - [`VmaMerger`] — the merge engine with 512 VMA capacity
//! - [`VmaMergeSubsystem`] — top-level subsystem with merge scanning
//! - [`VmaMergeStats`] — aggregate merge statistics
//!
//! Reference: Linux `mm/mmap.c` — `vma_merge()`, `can_vma_merge_before()`,
//! `can_vma_merge_after()`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of VMA entries managed by a single merger.
const MAX_VMAS: usize = 512;

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// VMA flag: region is anonymous (no file backing).
pub const VMA_FLAG_ANONYMOUS: u32 = 1 << 0;

/// VMA flag: region is shared (visible to other processes).
pub const VMA_FLAG_SHARED: u32 = 1 << 1;

/// VMA flag: region is growable (e.g., stack).
pub const VMA_FLAG_GROWSDOWN: u32 = 1 << 2;

/// VMA flag: region is locked in memory (mlock).
pub const VMA_FLAG_LOCKED: u32 = 1 << 3;

/// VMA flag: region uses huge pages.
pub const VMA_FLAG_HUGEPAGE: u32 = 1 << 4;

/// VMA flag: region has been merged (internal marker).
const VMA_FLAG_MERGED: u32 = 1 << 16;

/// Protection: readable.
const PROT_READ: u8 = 1 << 0;

/// Protection: writable.
const PROT_WRITE: u8 = 1 << 1;

/// Protection: executable.
const PROT_EXEC: u8 = 1 << 2;

// -------------------------------------------------------------------
// VmaCanMerge
// -------------------------------------------------------------------

/// Classification of how two adjacent VMAs can be merged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VmaCanMerge {
    /// The VMAs cannot be merged.
    #[default]
    None,
    /// The left VMA can absorb the right VMA (extend right boundary).
    Left,
    /// The right VMA can absorb the left VMA (extend left boundary).
    Right,
    /// Both directions are valid; merge into a single VMA.
    Both,
}

// -------------------------------------------------------------------
// VmaCompatFlags
// -------------------------------------------------------------------

/// Compatibility attributes used to determine if two VMAs can merge.
///
/// Two VMAs are merge-compatible only if all fields match exactly,
/// and for file-backed VMAs, the page offset must be contiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmaCompatFlags {
    /// Protection bits (PROT_READ | PROT_WRITE | PROT_EXEC).
    pub prot: u8,
    /// VMA flags (anonymous, shared, growsdown, etc.).
    pub flags: u32,
    /// Optional file identifier for file-backed VMAs.
    pub file_id: Option<u32>,
    /// Page offset into the backing file (in pages, not bytes).
    pub pgoff: u64,
}

impl VmaCompatFlags {
    /// Creates compatibility flags for an anonymous VMA.
    pub const fn anonymous(prot: u8, flags: u32) -> Self {
        Self {
            prot,
            flags,
            file_id: None,
            pgoff: 0,
        }
    }

    /// Creates compatibility flags for a file-backed VMA.
    pub const fn file_backed(prot: u8, flags: u32, file_id: u32, pgoff: u64) -> Self {
        Self {
            prot,
            flags,
            file_id: Some(file_id),
            pgoff,
        }
    }

    /// Checks if two VMA compat flag sets are merge-compatible.
    ///
    /// For anonymous VMAs, prot and flags must match.
    /// For file-backed VMAs, the file_id must also match.
    pub fn is_compatible(&self, other: &Self) -> bool {
        if self.prot != other.prot {
            return false;
        }
        // Mask out the internal merged flag for comparison.
        let mask = !VMA_FLAG_MERGED;
        if (self.flags & mask) != (other.flags & mask) {
            return false;
        }
        self.file_id == other.file_id
    }
}

impl Default for VmaCompatFlags {
    fn default() -> Self {
        Self {
            prot: 0,
            flags: 0,
            file_id: None,
            pgoff: 0,
        }
    }
}

// -------------------------------------------------------------------
// VmaEntry
// -------------------------------------------------------------------

/// A single VMA (Virtual Memory Area) descriptor.
///
/// Represents a contiguous region of virtual address space with
/// uniform protection and backing.
#[derive(Debug, Clone, Copy)]
pub struct VmaEntry {
    /// Start virtual address (page-aligned).
    pub start: u64,
    /// End virtual address (exclusive, page-aligned).
    pub end: u64,
    /// Compatibility attributes for merge testing.
    pub compat: VmaCompatFlags,
    /// Whether this entry is actively in use.
    pub in_use: bool,
    /// Reference count (number of mappings sharing this VMA).
    pub ref_count: u32,
    /// Unique VMA identifier.
    pub vma_id: u32,
}

impl VmaEntry {
    /// Creates an empty, unused VMA entry.
    const fn empty() -> Self {
        Self {
            start: 0,
            end: 0,
            compat: VmaCompatFlags {
                prot: 0,
                flags: 0,
                file_id: None,
                pgoff: 0,
            },
            in_use: false,
            ref_count: 0,
            vma_id: 0,
        }
    }

    /// Returns the size of this VMA in bytes.
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Returns the number of pages this VMA spans.
    pub fn nr_pages(&self) -> u64 {
        self.size() / PAGE_SIZE
    }

    /// Checks whether the given address falls within this VMA.
    pub fn contains(&self, addr: u64) -> bool {
        self.in_use && addr >= self.start && addr < self.end
    }

    /// Checks whether this VMA is adjacent to (immediately before) `other`.
    pub fn is_adjacent_before(&self, other: &Self) -> bool {
        self.in_use && other.in_use && self.end == other.start
    }

    /// Checks whether page offsets are contiguous for file-backed merges.
    ///
    /// If VMA A ends at page offset P, VMA B must start at page offset P
    /// for the file mapping to remain contiguous.
    pub fn pgoff_contiguous(&self, other: &Self) -> bool {
        if self.compat.file_id.is_none() && other.compat.file_id.is_none() {
            // Anonymous VMAs always have contiguous "offsets".
            return true;
        }
        let a_end_pgoff = self.compat.pgoff + self.nr_pages();
        a_end_pgoff == other.compat.pgoff
    }
}

// -------------------------------------------------------------------
// VmaMerger
// -------------------------------------------------------------------

/// The VMA merge engine.
///
/// Manages a fixed-size array of VMA entries and provides operations
/// to merge adjacent compatible VMAs and split VMAs at arbitrary
/// addresses.
pub struct VmaMerger {
    /// Array of VMA entries.
    entries: [VmaEntry; MAX_VMAS],
    /// Number of active (in-use) entries.
    count: usize,
    /// Next VMA identifier to assign.
    next_id: u32,
    /// Total merges attempted.
    merges_attempted: u64,
    /// Total merges that succeeded.
    merges_succeeded: u64,
    /// Total splits performed.
    splits: u64,
}

impl Default for VmaMerger {
    fn default() -> Self {
        Self::new()
    }
}

impl VmaMerger {
    /// Creates a new empty VMA merger.
    pub const fn new() -> Self {
        Self {
            entries: [VmaEntry::empty(); MAX_VMAS],
            count: 0,
            next_id: 1,
            merges_attempted: 0,
            merges_succeeded: 0,
            splits: 0,
        }
    }

    /// Adds a new VMA entry to the merger.
    ///
    /// The entry is inserted in sorted order by start address. Merging
    /// with adjacent entries is NOT performed automatically; call
    /// [`try_merge_at`] afterwards if desired.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the entry array is full.
    /// Returns [`Error::InvalidArgument`] if `start >= end` or addresses
    /// are not page-aligned.
    pub fn add_vma(&mut self, start: u64, end: u64, compat: VmaCompatFlags) -> Result<u32> {
        if start >= end {
            return Err(Error::InvalidArgument);
        }
        if start % PAGE_SIZE != 0 || end % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_VMAS {
            return Err(Error::OutOfMemory);
        }

        // Check for overlap with existing VMAs.
        for i in 0..self.count {
            let e = &self.entries[i];
            if e.in_use && start < e.end && end > e.start {
                return Err(Error::InvalidArgument);
            }
        }

        let id = self.next_id;
        self.next_id += 1;

        // Find insertion position (sorted by start address).
        let pos = self.find_insert_pos(start);

        // Shift entries right to make room.
        if pos < self.count {
            let mut i = self.count;
            while i > pos {
                self.entries[i] = self.entries[i - 1];
                i -= 1;
            }
        }

        self.entries[pos] = VmaEntry {
            start,
            end,
            compat,
            in_use: true,
            ref_count: 1,
            vma_id: id,
        };
        self.count += 1;

        Ok(id)
    }

    /// Removes a VMA entry by its identifier.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no VMA with the given ID exists.
    pub fn remove_vma(&mut self, vma_id: u32) -> Result<()> {
        let idx = self.find_by_id(vma_id)?;
        self.remove_at(idx);
        Ok(())
    }

    /// Determines whether two VMAs (by index) can be merged.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if either index is out of range.
    pub fn can_vma_merge(&self, idx_a: usize, idx_b: usize) -> Result<VmaCanMerge> {
        if idx_a >= self.count || idx_b >= self.count {
            return Err(Error::InvalidArgument);
        }

        let a = &self.entries[idx_a];
        let b = &self.entries[idx_b];

        if !a.in_use || !b.in_use {
            return Ok(VmaCanMerge::None);
        }

        if !a.compat.is_compatible(&b.compat) {
            return Ok(VmaCanMerge::None);
        }

        let left_ok = a.is_adjacent_before(b) && a.pgoff_contiguous(b);
        let right_ok = b.is_adjacent_before(a) && b.pgoff_contiguous(a);

        match (left_ok, right_ok) {
            (true, true) => Ok(VmaCanMerge::Both),
            (true, false) => Ok(VmaCanMerge::Left),
            (false, true) => Ok(VmaCanMerge::Right),
            (false, false) => Ok(VmaCanMerge::None),
        }
    }

    /// Attempts to merge the VMA at `idx` with its left neighbor.
    ///
    /// On success the left neighbor is extended and the VMA at `idx`
    /// is removed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `idx` is 0 or out of range.
    /// Returns [`Error::NotFound`] if merge is not possible.
    pub fn try_merge_left(&mut self, idx: usize) -> Result<()> {
        if idx == 0 || idx >= self.count {
            return Err(Error::InvalidArgument);
        }
        self.merges_attempted += 1;

        let merge = self.can_vma_merge(idx - 1, idx)?;
        if merge == VmaCanMerge::None {
            return Err(Error::NotFound);
        }

        // Extend left neighbor to cover the current VMA.
        let end = self.entries[idx].end;
        self.entries[idx - 1].end = end;
        self.entries[idx - 1].compat.flags |= VMA_FLAG_MERGED;
        self.remove_at(idx);
        self.merges_succeeded += 1;
        Ok(())
    }

    /// Attempts to merge the VMA at `idx` with its right neighbor.
    ///
    /// On success the current VMA is extended and the right neighbor
    /// is removed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `idx` is the last entry or
    /// out of range.
    /// Returns [`Error::NotFound`] if merge is not possible.
    pub fn try_merge_right(&mut self, idx: usize) -> Result<()> {
        if idx + 1 >= self.count {
            return Err(Error::InvalidArgument);
        }
        self.merges_attempted += 1;

        let merge = self.can_vma_merge(idx, idx + 1)?;
        if merge == VmaCanMerge::None {
            return Err(Error::NotFound);
        }

        // Extend current VMA to cover the right neighbor.
        let end = self.entries[idx + 1].end;
        self.entries[idx].end = end;
        self.entries[idx].compat.flags |= VMA_FLAG_MERGED;
        self.remove_at(idx + 1);
        self.merges_succeeded += 1;
        Ok(())
    }

    /// Attempts to merge the VMA at `idx` with both neighbors.
    ///
    /// This is the most aggressive merge: if the VMA can merge with
    /// both its left and right neighbors, all three are collapsed
    /// into one.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the VMA has no neighbors.
    /// Returns [`Error::NotFound`] if no merge is possible.
    pub fn try_merge_both(&mut self, idx: usize) -> Result<()> {
        if idx == 0 || idx + 1 >= self.count {
            return Err(Error::InvalidArgument);
        }
        self.merges_attempted += 1;

        let left_ok = self.can_vma_merge(idx - 1, idx)?;
        let right_ok = self.can_vma_merge(idx, idx + 1)?;

        match (left_ok != VmaCanMerge::None, right_ok != VmaCanMerge::None) {
            (true, true) => {
                // Merge all three: extend left to cover right's end.
                let end = self.entries[idx + 1].end;
                self.entries[idx - 1].end = end;
                self.entries[idx - 1].compat.flags |= VMA_FLAG_MERGED;
                // Remove right first (higher index), then middle.
                self.remove_at(idx + 1);
                self.remove_at(idx);
                self.merges_succeeded += 1;
                Ok(())
            }
            (true, false) => {
                let end = self.entries[idx].end;
                self.entries[idx - 1].end = end;
                self.entries[idx - 1].compat.flags |= VMA_FLAG_MERGED;
                self.remove_at(idx);
                self.merges_succeeded += 1;
                Ok(())
            }
            (false, true) => {
                let end = self.entries[idx + 1].end;
                self.entries[idx].end = end;
                self.entries[idx].compat.flags |= VMA_FLAG_MERGED;
                self.remove_at(idx + 1);
                self.merges_succeeded += 1;
                Ok(())
            }
            (false, false) => Err(Error::NotFound),
        }
    }

    /// Merges VMAs in the range `[start_idx, end_idx]` into a single VMA.
    ///
    /// All VMAs in the range must be compatible with each other and
    /// contiguous. The resulting VMA spans from the start of the first
    /// to the end of the last.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if indices are out of range
    /// or VMAs are not compatible/contiguous.
    pub fn merge_vmas(&mut self, start_idx: usize, end_idx: usize) -> Result<()> {
        if start_idx >= self.count || end_idx >= self.count || start_idx > end_idx {
            return Err(Error::InvalidArgument);
        }
        if start_idx == end_idx {
            return Ok(());
        }

        // Verify all are compatible and contiguous.
        for i in start_idx..end_idx {
            if !self.entries[i].in_use || !self.entries[i + 1].in_use {
                return Err(Error::InvalidArgument);
            }
            if !self.entries[i]
                .compat
                .is_compatible(&self.entries[i + 1].compat)
            {
                return Err(Error::InvalidArgument);
            }
            if self.entries[i].end != self.entries[i + 1].start {
                return Err(Error::InvalidArgument);
            }
        }

        self.merges_attempted += 1;

        // Extend the first entry to cover the entire range.
        let new_end = self.entries[end_idx].end;
        self.entries[start_idx].end = new_end;
        self.entries[start_idx].compat.flags |= VMA_FLAG_MERGED;

        // Remove entries from end_idx down to start_idx+1.
        let mut i = end_idx;
        while i > start_idx {
            self.remove_at(i);
            i -= 1;
        }

        self.merges_succeeded += 1;
        Ok(())
    }

    /// Splits a VMA at the given address into two VMAs.
    ///
    /// The original VMA `[start, end)` becomes `[start, addr)` and a
    /// new VMA `[addr, end)` is created with the same attributes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `addr` is not page-aligned
    /// or does not fall within the VMA.
    /// Returns [`Error::OutOfMemory`] if there is no room for the new entry.
    pub fn split_vma(&mut self, idx: usize, addr: u64) -> Result<u32> {
        if idx >= self.count || !self.entries[idx].in_use {
            return Err(Error::InvalidArgument);
        }
        if addr % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        let entry = self.entries[idx];
        if addr <= entry.start || addr >= entry.end {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_VMAS {
            return Err(Error::OutOfMemory);
        }

        // Compute the new pgoff for the right half.
        let pages_in_left = (addr - entry.start) / PAGE_SIZE;
        let right_pgoff = entry.compat.pgoff + pages_in_left;

        // Shrink the original entry.
        self.entries[idx].end = addr;

        // Create the right half.
        let new_id = self.next_id;
        self.next_id += 1;

        let right = VmaEntry {
            start: addr,
            end: entry.end,
            compat: VmaCompatFlags {
                prot: entry.compat.prot,
                flags: entry.compat.flags,
                file_id: entry.compat.file_id,
                pgoff: right_pgoff,
            },
            in_use: true,
            ref_count: entry.ref_count,
            vma_id: new_id,
        };

        // Insert right after current entry.
        let insert_pos = idx + 1;
        let mut i = self.count;
        while i > insert_pos {
            self.entries[i] = self.entries[i - 1];
            i -= 1;
        }
        self.entries[insert_pos] = right;
        self.count += 1;
        self.splits += 1;

        Ok(new_id)
    }

    /// Finds a VMA that contains the given address.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no VMA contains the address.
    pub fn find_vma(&self, addr: u64) -> Result<usize> {
        for i in 0..self.count {
            if self.entries[i].contains(addr) {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the VMA entry at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the index is out of range.
    pub fn get(&self, idx: usize) -> Result<&VmaEntry> {
        if idx >= self.count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.entries[idx])
    }

    /// Returns the number of active VMA entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if there are no active VMA entries.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the total VMAs reduced (merges_succeeded counts).
    pub fn total_vmas_reduced(&self) -> u64 {
        self.merges_succeeded
    }

    /// Finds the insertion position for a new VMA with the given start.
    fn find_insert_pos(&self, start: u64) -> usize {
        for i in 0..self.count {
            if self.entries[i].start > start {
                return i;
            }
        }
        self.count
    }

    /// Finds a VMA by its unique identifier.
    fn find_by_id(&self, vma_id: u32) -> Result<usize> {
        for i in 0..self.count {
            if self.entries[i].in_use && self.entries[i].vma_id == vma_id {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Removes the entry at `idx` by shifting subsequent entries left.
    fn remove_at(&mut self, idx: usize) {
        if idx >= self.count {
            return;
        }
        let mut i = idx;
        while i + 1 < self.count {
            self.entries[i] = self.entries[i + 1];
            i += 1;
        }
        self.entries[self.count - 1] = VmaEntry::empty();
        self.count -= 1;
    }
}

// -------------------------------------------------------------------
// VmaMergeStats
// -------------------------------------------------------------------

/// Aggregate statistics for VMA merge operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmaMergeStats {
    /// Total merge attempts.
    pub merges_attempted: u64,
    /// Total successful merges.
    pub merges_succeeded: u64,
    /// Total VMA splits performed.
    pub splits: u64,
    /// Total VMAs reduced by merging.
    pub total_vmas_reduced: u64,
    /// Current active VMA count.
    pub current_vma_count: usize,
}

// -------------------------------------------------------------------
// VmaMergeSubsystem
// -------------------------------------------------------------------

/// Top-level VMA merge subsystem.
///
/// Wraps a [`VmaMerger`] and provides a scan-based merge pass that
/// iterates over all VMAs looking for merge opportunities.
pub struct VmaMergeSubsystem {
    /// The underlying VMA merger engine.
    merger: VmaMerger,
    /// Number of full merge scans performed.
    scan_count: u64,
    /// Total VMAs eliminated across all scans.
    total_reduced: u64,
}

impl Default for VmaMergeSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl VmaMergeSubsystem {
    /// Creates a new VMA merge subsystem.
    pub const fn new() -> Self {
        Self {
            merger: VmaMerger::new(),
            scan_count: 0,
            total_reduced: 0,
        }
    }

    /// Returns a reference to the underlying merger.
    pub fn merger(&self) -> &VmaMerger {
        &self.merger
    }

    /// Returns a mutable reference to the underlying merger.
    pub fn merger_mut(&mut self) -> &mut VmaMerger {
        &mut self.merger
    }

    /// Performs a full scan of all VMAs, merging adjacent compatible
    /// entries.
    ///
    /// Iterates from the beginning of the VMA list and attempts to
    /// merge each entry with its right neighbor. Continues scanning
    /// until no more merges are found in a complete pass.
    ///
    /// Returns the number of merges performed in this scan.
    pub fn do_merge_scan(&mut self) -> u64 {
        self.scan_count += 1;
        let mut total_merged = 0_u64;

        loop {
            let mut merged_this_pass = 0_u64;
            let mut idx = 0_usize;

            while idx + 1 < self.merger.count {
                let can_merge = self.merger.can_vma_merge(idx, idx + 1);
                if let Ok(result) = can_merge {
                    if result != VmaCanMerge::None {
                        if self.merger.try_merge_right(idx).is_ok() {
                            merged_this_pass += 1;
                            // Don't advance idx; the merged entry may
                            // merge with the next one too.
                            continue;
                        }
                    }
                }
                idx += 1;
            }

            total_merged += merged_this_pass;
            if merged_this_pass == 0 {
                break;
            }
        }

        self.total_reduced += total_merged;
        total_merged
    }

    /// Returns aggregate merge statistics.
    pub fn stats(&self) -> VmaMergeStats {
        VmaMergeStats {
            merges_attempted: self.merger.merges_attempted,
            merges_succeeded: self.merger.merges_succeeded,
            splits: self.merger.splits,
            total_vmas_reduced: self.total_reduced,
            current_vma_count: self.merger.count,
        }
    }

    /// Returns the number of full merge scans performed.
    pub fn scan_count(&self) -> u64 {
        self.scan_count
    }

    /// Adds a VMA and immediately attempts to merge it with neighbors.
    ///
    /// This is the recommended way to insert VMAs when automatic
    /// merging is desired.
    ///
    /// # Errors
    ///
    /// Returns errors from [`VmaMerger::add_vma`].
    pub fn add_and_merge(&mut self, start: u64, end: u64, compat: VmaCompatFlags) -> Result<()> {
        self.merger.add_vma(start, end, compat)?;
        self.do_merge_scan();
        Ok(())
    }

    /// Splits a VMA at the given address.
    ///
    /// Delegates to [`VmaMerger::split_vma`].
    ///
    /// # Errors
    ///
    /// Returns errors from [`VmaMerger::split_vma`].
    pub fn split_at(&mut self, addr: u64) -> Result<u32> {
        let idx = self.merger.find_vma(addr)?;
        self.merger.split_vma(idx, addr)
    }
}

// -------------------------------------------------------------------
// Helper functions
// -------------------------------------------------------------------

/// Checks if two VMAs (given as entries) can be merged.
///
/// This is a standalone function that does not require a merger instance.
/// It checks compatibility, adjacency, and page offset contiguity.
pub fn can_vma_merge(vma_a: &VmaEntry, vma_b: &VmaEntry) -> VmaCanMerge {
    if !vma_a.in_use || !vma_b.in_use {
        return VmaCanMerge::None;
    }
    if !vma_a.compat.is_compatible(&vma_b.compat) {
        return VmaCanMerge::None;
    }

    let left_ok = vma_a.is_adjacent_before(vma_b) && vma_a.pgoff_contiguous(vma_b);
    let right_ok = vma_b.is_adjacent_before(vma_a) && vma_b.pgoff_contiguous(vma_a);

    match (left_ok, right_ok) {
        (true, true) => VmaCanMerge::Both,
        (true, false) => VmaCanMerge::Left,
        (false, true) => VmaCanMerge::Right,
        (false, false) => VmaCanMerge::None,
    }
}

/// Creates a default anonymous VMA compatibility set with read-write
/// protection.
pub fn default_anon_compat() -> VmaCompatFlags {
    VmaCompatFlags::anonymous(PROT_READ | PROT_WRITE, VMA_FLAG_ANONYMOUS)
}

/// Creates a default executable VMA compatibility set (e.g., for .text).
pub fn default_exec_compat() -> VmaCompatFlags {
    VmaCompatFlags::anonymous(PROT_READ | PROT_EXEC, 0)
}
