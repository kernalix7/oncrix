// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! mremap grow/shrink implementation.
//!
//! The `mremap()` system call allows a process to resize or relocate
//! an existing memory mapping. This module implements:
//!
//! - **Grow in place**: extending a mapping's end address if the
//!   adjacent virtual address space is free.
//! - **Shrink in place**: reducing a mapping's size (truncating
//!   pages from the end).
//! - **Relocate (MREMAP_MAYMOVE)**: when in-place growth is not
//!   possible, allocate a new region, copy the data, and unmap
//!   the old region.
//! - **Fixed relocation (MREMAP_FIXED)**: move the mapping to an
//!   exact address.
//!
//! # Key types
//!
//! - [`MremapFlags`] — MREMAP_MAYMOVE, MREMAP_FIXED, etc.
//! - [`MremapRequest`] — parameters for an mremap operation
//! - [`MremapResult`] — outcome of an mremap operation
//! - [`MremapEntry`] — one tracked remapping in the history
//! - [`MremapTable`] — per-mm remapping tracker
//! - [`MremapSubsystem`] — top-level subsystem
//! - [`MremapStats`] — aggregate statistics
//!
//! Reference: Linux `mm/mremap.c` — `mremap_to()`,
//! `vma_to_resize()`, `move_vma()`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of address spaces tracked.
const MAX_MM: usize = 128;

/// Maximum number of VMAs per address space (for search).
const MAX_VMAS: usize = 512;

/// Maximum number of mremap history entries per mm.
const MAX_HISTORY: usize = 64;

/// Default mmap minimum address.
const MMAP_MIN_ADDR: u64 = 0x1_0000;

/// User-space address limit (canonical x86_64).
const USER_ADDR_LIMIT: u64 = 0x0000_7FFF_FFFF_F000;

// -------------------------------------------------------------------
// MremapFlags
// -------------------------------------------------------------------

/// Flags controlling mremap behaviour.
#[derive(Debug, Clone, Copy, Default)]
pub struct MremapFlags {
    /// Allow the kernel to move the mapping if in-place growth
    /// fails.
    pub may_move: bool,
    /// Move the mapping to a specific address (requires
    /// `may_move`).
    pub fixed: bool,
    /// Do not unmap the old mapping (creates an alias).
    /// Linux 5.7+ MREMAP_DONTUNMAP.
    pub dontunmap: bool,
}

impl MremapFlags {
    /// Default: may move.
    pub const MAYMOVE: Self = Self {
        may_move: true,
        fixed: false,
        dontunmap: false,
    };

    /// Fixed relocation.
    pub const fn fixed(new_addr: u64) -> Self {
        let _ = new_addr; // address is in the request, not here
        Self {
            may_move: true,
            fixed: true,
            dontunmap: false,
        }
    }

    /// Encode as a u32 bitmask.
    pub fn as_bits(&self) -> u32 {
        let mut bits = 0u32;
        if self.may_move {
            bits |= 1 << 0;
        }
        if self.fixed {
            bits |= 1 << 1;
        }
        if self.dontunmap {
            bits |= 1 << 2;
        }
        bits
    }

    /// Decode from a u32 bitmask.
    pub fn from_bits(bits: u32) -> Self {
        Self {
            may_move: bits & (1 << 0) != 0,
            fixed: bits & (1 << 1) != 0,
            dontunmap: bits & (1 << 2) != 0,
        }
    }
}

// -------------------------------------------------------------------
// VmaSnapshot
// -------------------------------------------------------------------

/// Lightweight snapshot of a VMA for mremap validation.
#[derive(Debug, Clone, Copy)]
pub struct VmaSnapshot {
    /// Start virtual address.
    pub start: u64,
    /// End virtual address (exclusive).
    pub end: u64,
    /// Protection bits (r/w/x as bitmask).
    pub prot: u8,
    /// Mapping flags bitmask.
    pub flags: u32,
    /// Backing inode (0 = anonymous).
    pub inode: u64,
    /// File offset.
    pub offset: u64,
    /// Whether the VMA is active.
    pub active: bool,
}

impl VmaSnapshot {
    /// Create an empty snapshot.
    const fn empty() -> Self {
        Self {
            start: 0,
            end: 0,
            prot: 0,
            flags: 0,
            inode: 0,
            offset: 0,
            active: false,
        }
    }

    /// Size in bytes.
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Size in pages.
    pub fn page_count(&self) -> u64 {
        self.size() / PAGE_SIZE
    }

    /// Whether `addr` is within this VMA.
    pub fn contains(&self, addr: u64) -> bool {
        self.active && addr >= self.start && addr < self.end
    }

    /// Whether the VMA overlaps `[start, end)`.
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.active && self.start < end && self.end > start
    }
}

impl Default for VmaSnapshot {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// MremapRequest
// -------------------------------------------------------------------

/// Parameters for an mremap operation.
#[derive(Debug, Clone, Copy)]
pub struct MremapRequest {
    /// Current start address of the mapping.
    pub old_addr: u64,
    /// Current size of the mapping.
    pub old_size: u64,
    /// Requested new size.
    pub new_size: u64,
    /// Flags.
    pub flags: MremapFlags,
    /// New address (valid only if `flags.fixed` is set).
    pub new_addr: u64,
    /// Address space identifier.
    pub mm_id: u64,
}

impl MremapRequest {
    /// Whether this is a shrink operation.
    pub fn is_shrink(&self) -> bool {
        self.new_size < self.old_size
    }

    /// Whether this is a grow operation.
    pub fn is_grow(&self) -> bool {
        self.new_size > self.old_size
    }

    /// Whether this is a no-size-change (relocate only).
    pub fn is_relocate_only(&self) -> bool {
        self.new_size == self.old_size && self.flags.fixed
    }

    /// Validate the request parameters.
    pub fn validate(&self) -> Result<()> {
        if self.old_addr % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.old_size == 0 || self.old_size % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.new_size == 0 || self.new_size % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.flags.fixed && !self.flags.may_move {
            return Err(Error::InvalidArgument);
        }
        if self.flags.fixed && self.new_addr % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.flags.dontunmap && !self.flags.may_move {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for MremapRequest {
    fn default() -> Self {
        Self {
            old_addr: 0,
            old_size: 0,
            new_size: 0,
            flags: MremapFlags::default(),
            new_addr: 0,
            mm_id: 0,
        }
    }
}

// -------------------------------------------------------------------
// MremapOutcome
// -------------------------------------------------------------------

/// Classification of how the mremap was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MremapOutcome {
    /// Mapping was grown in place.
    #[default]
    GrownInPlace,
    /// Mapping was shrunk in place.
    ShrunkInPlace,
    /// Mapping was relocated to a new address.
    Relocated,
    /// Mapping was relocated to a fixed address.
    FixedRelocated,
    /// No change was needed.
    Unchanged,
}

// -------------------------------------------------------------------
// MremapResult
// -------------------------------------------------------------------

/// Outcome of an mremap operation.
#[derive(Debug, Clone, Copy)]
pub struct MremapResult {
    /// New start address of the mapping.
    pub new_addr: u64,
    /// New size of the mapping.
    pub new_size: u64,
    /// How the remap was resolved.
    pub outcome: MremapOutcome,
    /// Number of pages that need to be copied (for relocations).
    pub pages_to_copy: u64,
    /// Whether the operation succeeded.
    pub success: bool,
}

impl MremapResult {
    /// Create a failure result.
    const fn failure() -> Self {
        Self {
            new_addr: 0,
            new_size: 0,
            outcome: MremapOutcome::Unchanged,
            pages_to_copy: 0,
            success: false,
        }
    }
}

impl Default for MremapResult {
    fn default() -> Self {
        Self::failure()
    }
}

// -------------------------------------------------------------------
// MremapEntry
// -------------------------------------------------------------------

/// One entry in the mremap history for an address space.
#[derive(Debug, Clone, Copy)]
pub struct MremapEntry {
    /// Original start address.
    pub old_addr: u64,
    /// Original size.
    pub old_size: u64,
    /// New start address.
    pub new_addr: u64,
    /// New size.
    pub new_size: u64,
    /// How the remap was resolved.
    pub outcome: MremapOutcome,
    /// Operation sequence number.
    pub seq: u64,
    /// Whether this entry is valid.
    pub valid: bool,
}

impl MremapEntry {
    /// Create an empty entry.
    const fn empty() -> Self {
        Self {
            old_addr: 0,
            old_size: 0,
            new_addr: 0,
            new_size: 0,
            outcome: MremapOutcome::Unchanged,
            seq: 0,
            valid: false,
        }
    }
}

impl Default for MremapEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// MremapTable
// -------------------------------------------------------------------

/// Per-mm mremap state and history.
pub struct MremapTable {
    /// VMA snapshots for this address space.
    vmas: [VmaSnapshot; MAX_VMAS],
    /// Number of active VMAs.
    vma_count: usize,
    /// Mremap history ring buffer.
    history: [MremapEntry; MAX_HISTORY],
    /// Next history write index.
    history_head: usize,
    /// Total operations.
    total_ops: u64,
    /// Address space identifier.
    mm_id: u64,
    /// Whether this table is active.
    active: bool,
    /// Number of in-place grows.
    grows_in_place: u64,
    /// Number of in-place shrinks.
    shrinks_in_place: u64,
    /// Number of relocations.
    relocations: u64,
}

impl MremapTable {
    /// Create an empty table.
    const fn empty() -> Self {
        Self {
            vmas: [const { VmaSnapshot::empty() }; MAX_VMAS],
            vma_count: 0,
            history: [const { MremapEntry::empty() }; MAX_HISTORY],
            history_head: 0,
            total_ops: 0,
            mm_id: 0,
            active: false,
            grows_in_place: 0,
            shrinks_in_place: 0,
            relocations: 0,
        }
    }

    /// Register a VMA.
    pub fn add_vma(&mut self, vma: VmaSnapshot) -> Result<usize> {
        if self.vma_count >= MAX_VMAS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.vma_count;
        self.vmas[idx] = vma;
        self.vma_count += 1;
        Ok(idx)
    }

    /// Remove a VMA by start address.
    pub fn remove_vma(&mut self, start: u64) -> Result<()> {
        let pos = self
            .vmas
            .iter()
            .take(self.vma_count)
            .position(|v| v.active && v.start == start)
            .ok_or(Error::NotFound)?;
        self.vma_count -= 1;
        if pos < self.vma_count {
            self.vmas[pos] = self.vmas[self.vma_count];
        }
        self.vmas[self.vma_count] = VmaSnapshot::empty();
        Ok(())
    }

    /// Find a VMA containing `addr`.
    fn find_vma(&self, addr: u64) -> Option<usize> {
        self.vmas
            .iter()
            .take(self.vma_count)
            .position(|v| v.contains(addr))
    }

    /// Check whether `[start, end)` is free of VMAs.
    fn is_range_free(&self, start: u64, end: u64) -> bool {
        !self
            .vmas
            .iter()
            .take(self.vma_count)
            .any(|v| v.overlaps(start, end))
    }

    /// Find a free gap of `size` bytes.
    fn find_gap(&self, size: u64) -> Result<u64> {
        let mut prev_end = MMAP_MIN_ADDR;
        // Sort-free scan: iterate VMAs.
        for v in self.vmas.iter().take(self.vma_count) {
            if !v.active {
                continue;
            }
            if v.start > prev_end {
                let gap_size = v.start - prev_end;
                if gap_size >= size {
                    return Ok(prev_end);
                }
            }
            if v.end > prev_end {
                prev_end = v.end;
            }
        }
        // Check the gap after all VMAs.
        if USER_ADDR_LIMIT > prev_end && USER_ADDR_LIMIT - prev_end >= size {
            return Ok(prev_end);
        }
        Err(Error::OutOfMemory)
    }

    /// Execute an mremap request.
    pub fn mremap(&mut self, req: &MremapRequest) -> Result<MremapResult> {
        req.validate()?;

        let vma_idx = self.find_vma(req.old_addr).ok_or(Error::NotFound)?;
        let vma = &self.vmas[vma_idx];

        // Verify old_addr + old_size falls within the VMA.
        let old_end = req.old_addr + req.old_size;
        if old_end > vma.end {
            return Err(Error::InvalidArgument);
        }

        // Case 1: Shrink in place.
        if req.is_shrink() {
            return self.do_shrink(vma_idx, req);
        }

        // Case 2: Same size (relocate-only with FIXED).
        if req.is_relocate_only() {
            return self.do_fixed_relocate(vma_idx, req);
        }

        // Case 3: Grow.
        // Try in-place first.
        let new_end = req.old_addr + req.new_size;
        let growth = req.new_size - req.old_size;
        if new_end <= USER_ADDR_LIMIT && self.is_range_free(old_end, new_end) {
            return self.do_grow_in_place(vma_idx, req, new_end);
        }

        // Cannot grow in place.
        if req.flags.fixed {
            return self.do_fixed_relocate(vma_idx, req);
        }

        if req.flags.may_move {
            return self.do_relocate(vma_idx, req);
        }

        // Cannot grow and cannot move — fail.
        let _ = growth;
        Err(Error::OutOfMemory)
    }

    /// Shrink in place.
    fn do_shrink(&mut self, vma_idx: usize, req: &MremapRequest) -> Result<MremapResult> {
        let new_end = req.old_addr + req.new_size;
        self.vmas[vma_idx].end = new_end;
        self.shrinks_in_place = self.shrinks_in_place.saturating_add(1);
        let result = MremapResult {
            new_addr: req.old_addr,
            new_size: req.new_size,
            outcome: MremapOutcome::ShrunkInPlace,
            pages_to_copy: 0,
            success: true,
        };
        self.record(req, &result);
        Ok(result)
    }

    /// Grow in place.
    fn do_grow_in_place(
        &mut self,
        vma_idx: usize,
        req: &MremapRequest,
        new_end: u64,
    ) -> Result<MremapResult> {
        self.vmas[vma_idx].end = new_end;
        self.grows_in_place = self.grows_in_place.saturating_add(1);
        let result = MremapResult {
            new_addr: req.old_addr,
            new_size: req.new_size,
            outcome: MremapOutcome::GrownInPlace,
            pages_to_copy: 0,
            success: true,
        };
        self.record(req, &result);
        Ok(result)
    }

    /// Relocate to a new address (MAYMOVE).
    fn do_relocate(&mut self, vma_idx: usize, req: &MremapRequest) -> Result<MremapResult> {
        let new_addr = self.find_gap(req.new_size)?;
        let pages = req.old_size.min(req.new_size) / PAGE_SIZE;

        // Create new VMA at new_addr.
        let mut new_vma = self.vmas[vma_idx];
        new_vma.start = new_addr;
        new_vma.end = new_addr + req.new_size;
        // Adjust offset for file-backed.
        // (offset stays relative to the mapping start)

        if !req.flags.dontunmap {
            // Remove old VMA.
            self.vmas[vma_idx].active = false;
        }
        self.add_vma(new_vma)?;
        self.relocations = self.relocations.saturating_add(1);

        let result = MremapResult {
            new_addr,
            new_size: req.new_size,
            outcome: MremapOutcome::Relocated,
            pages_to_copy: pages,
            success: true,
        };
        self.record(req, &result);
        Ok(result)
    }

    /// Fixed relocation (MREMAP_FIXED).
    fn do_fixed_relocate(&mut self, vma_idx: usize, req: &MremapRequest) -> Result<MremapResult> {
        let new_addr = req.new_addr;
        let new_end = new_addr + req.new_size;

        if new_addr < MMAP_MIN_ADDR || new_end > USER_ADDR_LIMIT {
            return Err(Error::InvalidArgument);
        }

        // Check the destination is free (excluding the old
        // mapping itself, which we will unmap).
        for (i, v) in self.vmas.iter().enumerate().take(self.vma_count) {
            if i == vma_idx {
                continue;
            }
            if v.active && v.overlaps(new_addr, new_end) {
                return Err(Error::InvalidArgument);
            }
        }

        let pages = req.old_size.min(req.new_size) / PAGE_SIZE;

        let mut new_vma = self.vmas[vma_idx];
        new_vma.start = new_addr;
        new_vma.end = new_end;

        if !req.flags.dontunmap {
            self.vmas[vma_idx].active = false;
        }
        self.add_vma(new_vma)?;
        self.relocations = self.relocations.saturating_add(1);

        let result = MremapResult {
            new_addr,
            new_size: req.new_size,
            outcome: MremapOutcome::FixedRelocated,
            pages_to_copy: pages,
            success: true,
        };
        self.record(req, &result);
        Ok(result)
    }

    /// Record an mremap in the history.
    fn record(&mut self, req: &MremapRequest, result: &MremapResult) {
        self.total_ops = self.total_ops.saturating_add(1);
        self.history[self.history_head] = MremapEntry {
            old_addr: req.old_addr,
            old_size: req.old_size,
            new_addr: result.new_addr,
            new_size: result.new_size,
            outcome: result.outcome,
            seq: self.total_ops,
            valid: true,
        };
        self.history_head = (self.history_head + 1) % MAX_HISTORY;
    }

    /// Number of active VMAs.
    pub fn vma_count(&self) -> usize {
        self.vma_count
    }

    /// Total mremap operations.
    pub fn total_ops(&self) -> u64 {
        self.total_ops
    }

    /// Most recent mremap history entry.
    pub fn last_entry(&self) -> Option<MremapEntry> {
        if self.total_ops == 0 {
            return None;
        }
        let idx = if self.history_head == 0 {
            MAX_HISTORY - 1
        } else {
            self.history_head - 1
        };
        if self.history[idx].valid {
            Some(self.history[idx])
        } else {
            None
        }
    }
}

impl Default for MremapTable {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// MremapSubsystem
// -------------------------------------------------------------------

/// Top-level mremap subsystem.
pub struct MremapSubsystem {
    /// Per-mm tables.
    tables: [MremapTable; MAX_MM],
    /// Number of active tables.
    active_mm: usize,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl MremapSubsystem {
    /// Create an uninitialised subsystem.
    pub const fn new() -> Self {
        Self {
            tables: [const { MremapTable::empty() }; MAX_MM],
            active_mm: 0,
            initialised: false,
        }
    }

    /// Initialise the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    /// Register an address space.
    pub fn register_mm(&mut self, mm_id: u64) -> Result<usize> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        for t in self.tables.iter().take(self.active_mm) {
            if t.active && t.mm_id == mm_id {
                return Err(Error::AlreadyExists);
            }
        }
        if self.active_mm >= MAX_MM {
            return Err(Error::OutOfMemory);
        }
        let idx = self.active_mm;
        self.tables[idx].mm_id = mm_id;
        self.tables[idx].active = true;
        self.active_mm += 1;
        Ok(idx)
    }

    /// Unregister an address space.
    pub fn unregister_mm(&mut self, mm_id: u64) -> Result<()> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        let pos = self
            .tables
            .iter()
            .take(self.active_mm)
            .position(|t| t.active && t.mm_id == mm_id)
            .ok_or(Error::NotFound)?;
        self.active_mm -= 1;
        if pos < self.active_mm {
            self.tables.swap(pos, self.active_mm);
        }
        self.tables[self.active_mm] = MremapTable::empty();
        Ok(())
    }

    /// Find the table for an mm.
    fn find_table(&mut self, mm_id: u64) -> Result<usize> {
        self.tables
            .iter()
            .take(self.active_mm)
            .position(|t| t.active && t.mm_id == mm_id)
            .ok_or(Error::NotFound)
    }

    /// Register a VMA for an address space.
    pub fn add_vma(&mut self, mm_id: u64, vma: VmaSnapshot) -> Result<usize> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        let idx = self.find_table(mm_id)?;
        self.tables[idx].add_vma(vma)
    }

    /// Execute an mremap.
    pub fn mremap(&mut self, req: &MremapRequest) -> Result<MremapResult> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        let idx = self.find_table(req.mm_id)?;
        self.tables[idx].mremap(req)
    }

    /// Collect aggregate statistics.
    pub fn stats(&self) -> MremapStats {
        let mut s = MremapStats {
            active_mm: self.active_mm as u64,
            ..MremapStats::default()
        };
        for t in self.tables.iter().take(self.active_mm) {
            if !t.active {
                continue;
            }
            s.total_ops = s.total_ops.saturating_add(t.total_ops);
            s.grows_in_place = s.grows_in_place.saturating_add(t.grows_in_place);
            s.shrinks_in_place = s.shrinks_in_place.saturating_add(t.shrinks_in_place);
            s.relocations = s.relocations.saturating_add(t.relocations);
            s.total_vmas = s.total_vmas.saturating_add(t.vma_count as u64);
        }
        s
    }

    /// Whether the subsystem is initialised.
    pub fn is_initialised(&self) -> bool {
        self.initialised
    }
}

impl Default for MremapSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MremapStats
// -------------------------------------------------------------------

/// Aggregate statistics for the mremap subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct MremapStats {
    /// Number of active address spaces.
    pub active_mm: u64,
    /// Total mremap operations.
    pub total_ops: u64,
    /// Number of in-place grows.
    pub grows_in_place: u64,
    /// Number of in-place shrinks.
    pub shrinks_in_place: u64,
    /// Number of relocations.
    pub relocations: u64,
    /// Total VMAs across all address spaces.
    pub total_vmas: u64,
}

// -------------------------------------------------------------------
// Helper functions
// -------------------------------------------------------------------

/// Validate that an address range is page-aligned and within
/// user-space limits.
pub fn validate_range(addr: u64, size: u64) -> Result<()> {
    if addr % PAGE_SIZE != 0 {
        return Err(Error::InvalidArgument);
    }
    if size == 0 || size % PAGE_SIZE != 0 {
        return Err(Error::InvalidArgument);
    }
    if addr < MMAP_MIN_ADDR {
        return Err(Error::InvalidArgument);
    }
    let end = addr.checked_add(size).ok_or(Error::InvalidArgument)?;
    if end > USER_ADDR_LIMIT {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Compute the number of pages that must be copied when relocating
/// a mapping from `old_size` to `new_size`.
pub fn pages_to_copy(old_size: u64, new_size: u64) -> u64 {
    old_size.min(new_size) / PAGE_SIZE
}

/// Align a value up to the nearest page boundary.
pub fn page_align_up(val: u64) -> u64 {
    (val + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// Align a value down to the nearest page boundary.
pub fn page_align_down(val: u64) -> u64 {
    val & !(PAGE_SIZE - 1)
}
