// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! mmap region allocation and splitting.
//!
//! When a process calls `mmap()`, the kernel must find a suitable
//! gap in the process's address space, create a new VMA, and
//! optionally split or adjust existing VMAs if the new mapping
//! overlaps with an existing one.
//!
//! This module implements:
//!
//! - **Gap finding**: locating a free region in the address space
//!   that satisfies alignment and size constraints.
//! - **Region allocation**: creating the VMA descriptor and
//!   inserting it into the VMA table.
//! - **VMA splitting**: breaking a VMA into two or three parts
//!   when a partial overlap or `munmap()` occurs.
//! - **Region expansion**: extending an existing VMA (e.g.,
//!   `brk()` expanding the heap).
//!
//! # Key types
//!
//! - [`MmapProt`] — memory protection bits
//! - [`MmapFlags`] — MAP_SHARED, MAP_ANONYMOUS, etc.
//! - [`MmapRegion`] — a virtual memory region descriptor
//! - [`MmapGap`] — a free gap in the address space
//! - [`MmapRegionTable`] — per-mm region table
//! - [`MmapRegionSubsystem`] — top-level subsystem
//! - [`MmapRegionStats`] — aggregate statistics
//!
//! Reference: Linux `mm/mmap.c` — `do_mmap()`, `mmap_region()`,
//! `__split_vma()`, `find_vma_intersection()`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of regions per address space.
const MAX_REGIONS: usize = 512;

/// Maximum number of address spaces tracked.
const MAX_MM: usize = 128;

/// Default mmap minimum address (64 KiB to avoid null-deref zone).
const MMAP_MIN_ADDR: u64 = 0x1_0000;

/// User-space virtual address limit (canonical x86_64 lower half).
const USER_ADDR_LIMIT: u64 = 0x0000_7FFF_FFFF_F000;

/// Default alignment for mmap allocations.
const DEFAULT_ALIGN: u64 = PAGE_SIZE;

// -------------------------------------------------------------------
// MmapProt
// -------------------------------------------------------------------

/// Memory protection flags for a mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MmapProt {
    /// Pages may be read.
    pub read: bool,
    /// Pages may be written.
    pub write: bool,
    /// Pages may be executed.
    pub exec: bool,
}

impl MmapProt {
    /// No access.
    pub const NONE: Self = Self {
        read: false,
        write: false,
        exec: false,
    };

    /// Read-only.
    pub const READ: Self = Self {
        read: true,
        write: false,
        exec: false,
    };

    /// Read-write.
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
        exec: false,
    };

    /// Read-execute (code).
    pub const READ_EXEC: Self = Self {
        read: true,
        write: false,
        exec: true,
    };

    /// Full access.
    pub const ALL: Self = Self {
        read: true,
        write: true,
        exec: true,
    };

    /// Encode as a u8 bitmask.
    pub fn as_bits(&self) -> u8 {
        let mut bits = 0u8;
        if self.read {
            bits |= 1;
        }
        if self.write {
            bits |= 2;
        }
        if self.exec {
            bits |= 4;
        }
        bits
    }

    /// Decode from a u8 bitmask.
    pub fn from_bits(bits: u8) -> Self {
        Self {
            read: bits & 1 != 0,
            write: bits & 2 != 0,
            exec: bits & 4 != 0,
        }
    }
}

// -------------------------------------------------------------------
// MmapFlags
// -------------------------------------------------------------------

/// Flags controlling mapping behaviour.
#[derive(Debug, Clone, Copy, Default)]
pub struct MmapFlags {
    /// Mapping is shared (writes visible to other processes).
    pub shared: bool,
    /// Mapping is private (CoW on write).
    pub private: bool,
    /// Mapping is anonymous (not backed by a file).
    pub anonymous: bool,
    /// Map at exactly the requested address.
    pub fixed: bool,
    /// Do not reserve swap space for this mapping.
    pub noreserve: bool,
    /// Populate (prefault) page tables.
    pub populate: bool,
    /// Use huge pages if available.
    pub hugetlb: bool,
    /// Lock pages in memory after mapping.
    pub locked: bool,
    /// Mapping grows downward (stack).
    pub growsdown: bool,
    /// Stack mapping (implies growsdown).
    pub stack: bool,
}

impl MmapFlags {
    /// Shared anonymous mapping.
    pub const SHARED_ANON: Self = Self {
        shared: true,
        private: false,
        anonymous: true,
        fixed: false,
        noreserve: false,
        populate: false,
        hugetlb: false,
        locked: false,
        growsdown: false,
        stack: false,
    };

    /// Private anonymous mapping (typical malloc backend).
    pub const PRIVATE_ANON: Self = Self {
        shared: false,
        private: true,
        anonymous: true,
        fixed: false,
        noreserve: false,
        populate: false,
        hugetlb: false,
        locked: false,
        growsdown: false,
        stack: false,
    };

    /// Encode as a u32 bitmask.
    pub fn as_bits(&self) -> u32 {
        let mut bits = 0u32;
        if self.shared {
            bits |= 1 << 0;
        }
        if self.private {
            bits |= 1 << 1;
        }
        if self.anonymous {
            bits |= 1 << 2;
        }
        if self.fixed {
            bits |= 1 << 3;
        }
        if self.noreserve {
            bits |= 1 << 4;
        }
        if self.populate {
            bits |= 1 << 5;
        }
        if self.hugetlb {
            bits |= 1 << 6;
        }
        if self.locked {
            bits |= 1 << 7;
        }
        if self.growsdown {
            bits |= 1 << 8;
        }
        if self.stack {
            bits |= 1 << 9;
        }
        bits
    }
}

// -------------------------------------------------------------------
// MmapRegion
// -------------------------------------------------------------------

/// A virtual memory region (VMA) descriptor.
#[derive(Debug, Clone, Copy)]
pub struct MmapRegion {
    /// Start virtual address (page-aligned).
    pub start: u64,
    /// End virtual address (exclusive, page-aligned).
    pub end: u64,
    /// Memory protection.
    pub prot: MmapProt,
    /// Mapping flags.
    pub flags: MmapFlags,
    /// Backing file inode (0 = anonymous).
    pub inode: u64,
    /// Offset into the backing file (in bytes).
    pub offset: u64,
    /// Address space (mm) identifier.
    pub mm_id: u64,
    /// Whether this region is active.
    pub active: bool,
    /// Number of faults in this region.
    pub fault_count: u64,
    /// Number of pages currently resident.
    pub resident_pages: u64,
}

impl MmapRegion {
    /// Create an empty (inactive) region.
    const fn empty() -> Self {
        Self {
            start: 0,
            end: 0,
            prot: MmapProt::NONE,
            flags: MmapFlags {
                shared: false,
                private: false,
                anonymous: false,
                fixed: false,
                noreserve: false,
                populate: false,
                hugetlb: false,
                locked: false,
                growsdown: false,
                stack: false,
            },
            inode: 0,
            offset: 0,
            mm_id: 0,
            active: false,
            fault_count: 0,
            resident_pages: 0,
        }
    }

    /// Size of the region in bytes.
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Size in pages.
    pub fn page_count(&self) -> u64 {
        self.size() / PAGE_SIZE
    }

    /// Whether an address falls within this region.
    pub fn contains(&self, addr: u64) -> bool {
        self.active && addr >= self.start && addr < self.end
    }

    /// Whether this region overlaps with `[start, end)`.
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.active && self.start < end && self.end > start
    }

    /// Whether this region is anonymous.
    pub fn is_anonymous(&self) -> bool {
        self.flags.anonymous
    }

    /// Whether this region is shared.
    pub fn is_shared(&self) -> bool {
        self.flags.shared
    }

    /// Whether this region is writable.
    pub fn is_writable(&self) -> bool {
        self.prot.write
    }

    /// Whether this region is adjacent to and compatible with
    /// another region (for potential merging).
    pub fn can_merge_with(&self, other: &Self) -> bool {
        if !self.active || !other.active {
            return false;
        }
        // Must be in the same mm.
        if self.mm_id != other.mm_id {
            return false;
        }
        // Must be adjacent.
        if self.end != other.start {
            return false;
        }
        // Must have same protection and flags.
        if self.prot.as_bits() != other.prot.as_bits() {
            return false;
        }
        if self.flags.as_bits() != other.flags.as_bits() {
            return false;
        }
        // If file-backed, must be the same file with contiguous
        // offsets.
        if self.inode != 0 || other.inode != 0 {
            if self.inode != other.inode {
                return false;
            }
            let expected_off = self.offset + self.size();
            if other.offset != expected_off {
                return false;
            }
        }
        true
    }
}

impl Default for MmapRegion {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// MmapGap
// -------------------------------------------------------------------

/// A free gap in the address space.
#[derive(Debug, Clone, Copy, Default)]
pub struct MmapGap {
    /// Start of the gap.
    pub start: u64,
    /// End of the gap (exclusive).
    pub end: u64,
    /// Whether this gap is valid.
    pub valid: bool,
}

impl MmapGap {
    /// Size of the gap in bytes.
    pub fn size(&self) -> u64 {
        if self.valid {
            self.end.saturating_sub(self.start)
        } else {
            0
        }
    }

    /// Whether the gap can satisfy an allocation of `size` bytes
    /// with `align` alignment.
    pub fn can_fit(&self, size: u64, align: u64) -> bool {
        if !self.valid || size == 0 {
            return false;
        }
        let aligned_start = align_up(self.start, align);
        if aligned_start >= self.end {
            return false;
        }
        self.end - aligned_start >= size
    }

    /// Compute the aligned start address for an allocation.
    pub fn aligned_start(&self, align: u64) -> u64 {
        align_up(self.start, align)
    }
}

// -------------------------------------------------------------------
// SplitResult
// -------------------------------------------------------------------

/// Result of splitting a VMA.
#[derive(Debug, Clone, Copy)]
pub struct SplitResult {
    /// The original region index (now the lower half).
    pub lower_idx: usize,
    /// The upper half (newly created region), if any.
    pub upper_idx: Option<usize>,
    /// New end of the lower half.
    pub lower_end: u64,
    /// New start of the upper half.
    pub upper_start: u64,
}

// -------------------------------------------------------------------
// MmapRegionTable
// -------------------------------------------------------------------

/// Per-mm region table.
///
/// Stores all VMAs for a single address space. Regions are kept
/// sorted by start address.
pub struct MmapRegionTable {
    /// Region entries.
    regions: [MmapRegion; MAX_REGIONS],
    /// Number of active regions.
    count: usize,
    /// Address space identifier.
    mm_id: u64,
    /// Whether this table is in use.
    active: bool,
    /// Total bytes mapped.
    total_mapped: u64,
    /// Total mmap calls.
    mmap_count: u64,
    /// Total munmap calls.
    munmap_count: u64,
    /// Total split operations.
    split_count: u64,
}

impl MmapRegionTable {
    /// Create an empty table.
    const fn empty() -> Self {
        Self {
            regions: [const { MmapRegion::empty() }; MAX_REGIONS],
            count: 0,
            mm_id: 0,
            active: false,
            total_mapped: 0,
            mmap_count: 0,
            munmap_count: 0,
            split_count: 0,
        }
    }

    /// Find the region containing `addr`.
    pub fn find(&self, addr: u64) -> Option<usize> {
        self.regions
            .iter()
            .take(self.count)
            .position(|r| r.contains(addr))
    }

    /// Find the first region that overlaps `[start, end)`.
    pub fn find_overlap(&self, start: u64, end: u64) -> Option<usize> {
        self.regions
            .iter()
            .take(self.count)
            .position(|r| r.overlaps(start, end))
    }

    /// Find the largest gap in the address space.
    pub fn find_gap(&self, size: u64, align: u64) -> Result<MmapGap> {
        // Collect gap boundaries.
        let mut prev_end = MMAP_MIN_ADDR;
        let mut best_gap = MmapGap::default();

        // Regions are sorted by start address; find gaps between
        // them.
        for r in self.regions.iter().take(self.count) {
            if !r.active {
                continue;
            }
            if r.start > prev_end {
                let gap = MmapGap {
                    start: prev_end,
                    end: r.start,
                    valid: true,
                };
                if gap.can_fit(size, align) && gap.size() >= best_gap.size() {
                    best_gap = gap;
                }
            }
            if r.end > prev_end {
                prev_end = r.end;
            }
        }
        // Check gap after the last region.
        if USER_ADDR_LIMIT > prev_end {
            let gap = MmapGap {
                start: prev_end,
                end: USER_ADDR_LIMIT,
                valid: true,
            };
            if gap.can_fit(size, align) && gap.size() >= best_gap.size() {
                best_gap = gap;
            }
        }

        if !best_gap.valid || !best_gap.can_fit(size, align) {
            return Err(Error::OutOfMemory);
        }
        Ok(best_gap)
    }

    /// Insert a new region, keeping sorted order by start address.
    fn insert_sorted(&mut self, region: MmapRegion) -> Result<usize> {
        if self.count >= MAX_REGIONS {
            return Err(Error::OutOfMemory);
        }
        // Find insertion point.
        let mut pos = self.count;
        for i in 0..self.count {
            if self.regions[i].active && self.regions[i].start > region.start {
                pos = i;
                break;
            }
        }
        // Shift right.
        let mut j = self.count;
        while j > pos {
            self.regions[j] = self.regions[j - 1];
            j -= 1;
        }
        self.regions[pos] = region;
        self.count += 1;
        Ok(pos)
    }

    /// Allocate a new mapping. Returns the start address.
    pub fn mmap(
        &mut self,
        addr_hint: Option<u64>,
        size: u64,
        prot: MmapProt,
        flags: MmapFlags,
        inode: u64,
        offset: u64,
    ) -> Result<u64> {
        if size == 0 || size % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }

        let start = if let Some(hint) = addr_hint {
            if flags.fixed {
                // MAP_FIXED: use the exact address (unmap existing).
                let aligned = align_down(hint, PAGE_SIZE);
                // Remove any overlapping regions.
                self.unmap_range(aligned, aligned + size)?;
                aligned
            } else {
                // Try the hint; fall back to gap search.
                let aligned = align_up(hint, DEFAULT_ALIGN);
                if aligned + size <= USER_ADDR_LIMIT
                    && self.find_overlap(aligned, aligned + size).is_none()
                {
                    aligned
                } else {
                    let gap = self.find_gap(size, DEFAULT_ALIGN)?;
                    gap.aligned_start(DEFAULT_ALIGN)
                }
            }
        } else {
            let gap = self.find_gap(size, DEFAULT_ALIGN)?;
            gap.aligned_start(DEFAULT_ALIGN)
        };

        let region = MmapRegion {
            start,
            end: start + size,
            prot,
            flags,
            inode,
            offset,
            mm_id: self.mm_id,
            active: true,
            fault_count: 0,
            resident_pages: 0,
        };
        self.insert_sorted(region)?;
        self.total_mapped = self.total_mapped.saturating_add(size);
        self.mmap_count = self.mmap_count.saturating_add(1);
        Ok(start)
    }

    /// Unmap a range `[start, start+size)`.
    ///
    /// Splits any partially-overlapping regions and removes
    /// fully-contained regions.
    pub fn munmap(&mut self, start: u64, size: u64) -> Result<u64> {
        if size == 0 || start % PAGE_SIZE != 0 || size % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        let freed = self.unmap_range(start, start + size)?;
        self.munmap_count = self.munmap_count.saturating_add(1);
        Ok(freed)
    }

    /// Internal: unmap `[start, end)`, splitting as needed.
    fn unmap_range(&mut self, start: u64, end: u64) -> Result<u64> {
        let mut freed = 0u64;
        let mut i = 0;
        while i < self.count {
            let r = &self.regions[i];
            if !r.active || r.start >= end || r.end <= start {
                i += 1;
                continue;
            }

            if r.start >= start && r.end <= end {
                // Fully contained — remove.
                freed += r.size();
                self.total_mapped = self.total_mapped.saturating_sub(r.size());
                self.remove_at(i);
                // Don't increment i — the next region shifted down.
                continue;
            }

            if r.start < start && r.end > end {
                // Region straddles the unmap range — split into two.
                let orig_end = r.end;
                self.regions[i].end = start;
                // Create the upper part.
                let mut upper = self.regions[i];
                upper.start = end;
                upper.end = orig_end;
                upper.offset += end - self.regions[i].start;
                self.insert_sorted(upper)?;
                freed += end - start;
                self.total_mapped = self.total_mapped.saturating_sub(end - start);
                self.split_count = self.split_count.saturating_add(1);
                i += 2; // Skip both halves.
                continue;
            }

            if r.start < start {
                // Overlap at the tail — shrink.
                let old_end = r.end;
                self.regions[i].end = start;
                freed += old_end - start;
                self.total_mapped = self.total_mapped.saturating_sub(old_end - start);
            } else {
                // Overlap at the head — shrink.
                let old_start = r.start;
                let old_offset = r.offset;
                self.regions[i].start = end;
                self.regions[i].offset = old_offset + (end - old_start);
                freed += end - old_start;
                self.total_mapped = self.total_mapped.saturating_sub(end - old_start);
            }
            i += 1;
        }
        Ok(freed)
    }

    /// Remove a region at index `i` and compact.
    fn remove_at(&mut self, i: usize) {
        if i >= self.count {
            return;
        }
        let mut j = i;
        while j + 1 < self.count {
            self.regions[j] = self.regions[j + 1];
            j += 1;
        }
        self.regions[self.count - 1] = MmapRegion::empty();
        self.count -= 1;
    }

    /// Split a VMA at address `addr`. Returns a `SplitResult`.
    pub fn split_vma(&mut self, addr: u64) -> Result<SplitResult> {
        if addr % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        let idx = self.find(addr).ok_or(Error::NotFound)?;

        let r = &self.regions[idx];
        if addr == r.start || addr == r.end {
            return Err(Error::InvalidArgument);
        }

        let orig_end = r.end;
        let orig_offset = r.offset;
        let orig_start = r.start;
        self.regions[idx].end = addr;

        let mut upper = self.regions[idx];
        upper.start = addr;
        upper.end = orig_end;
        upper.offset = orig_offset + (addr - orig_start);
        let upper_idx = self.insert_sorted(upper)?;
        self.split_count = self.split_count.saturating_add(1);

        Ok(SplitResult {
            lower_idx: idx,
            upper_idx: Some(upper_idx),
            lower_end: addr,
            upper_start: addr,
        })
    }

    /// Number of active regions.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Total bytes mapped.
    pub fn total_mapped(&self) -> u64 {
        self.total_mapped
    }
}

impl Default for MmapRegionTable {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// MmapRegionSubsystem
// -------------------------------------------------------------------

/// Top-level mmap region subsystem.
///
/// Manages multiple per-mm region tables.
pub struct MmapRegionSubsystem {
    /// Per-mm tables.
    tables: [MmapRegionTable; MAX_MM],
    /// Number of active tables.
    active_mm: usize,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl MmapRegionSubsystem {
    /// Create an uninitialised subsystem.
    pub const fn new() -> Self {
        Self {
            tables: [const { MmapRegionTable::empty() }; MAX_MM],
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
        self.tables[self.active_mm] = MmapRegionTable::empty();
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

    /// Perform an mmap in the given address space.
    pub fn mmap(
        &mut self,
        mm_id: u64,
        addr_hint: Option<u64>,
        size: u64,
        prot: MmapProt,
        flags: MmapFlags,
        inode: u64,
        offset: u64,
    ) -> Result<u64> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        let idx = self.find_table(mm_id)?;
        self.tables[idx].mmap(addr_hint, size, prot, flags, inode, offset)
    }

    /// Perform a munmap.
    pub fn munmap(&mut self, mm_id: u64, start: u64, size: u64) -> Result<u64> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        let idx = self.find_table(mm_id)?;
        self.tables[idx].munmap(start, size)
    }

    /// Split a VMA at the given address.
    pub fn split_vma(&mut self, mm_id: u64, addr: u64) -> Result<SplitResult> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        let idx = self.find_table(mm_id)?;
        self.tables[idx].split_vma(addr)
    }

    /// Find the VMA containing an address.
    pub fn find_vma(&self, mm_id: u64, addr: u64) -> Result<Option<MmapRegion>> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        let idx = self
            .tables
            .iter()
            .take(self.active_mm)
            .position(|t| t.active && t.mm_id == mm_id)
            .ok_or(Error::NotFound)?;
        let table = &self.tables[idx];
        if let Some(ri) = table.find(addr) {
            Ok(Some(table.regions[ri]))
        } else {
            Ok(None)
        }
    }

    /// Collect aggregate statistics.
    pub fn stats(&self) -> MmapRegionStats {
        let mut s = MmapRegionStats {
            active_mm: self.active_mm as u64,
            ..MmapRegionStats::default()
        };
        for t in self.tables.iter().take(self.active_mm) {
            if !t.active {
                continue;
            }
            s.total_regions = s.total_regions.saturating_add(t.count as u64);
            s.total_mapped = s.total_mapped.saturating_add(t.total_mapped);
            s.total_mmaps = s.total_mmaps.saturating_add(t.mmap_count);
            s.total_munmaps = s.total_munmaps.saturating_add(t.munmap_count);
            s.total_splits = s.total_splits.saturating_add(t.split_count);
        }
        s
    }

    /// Whether the subsystem is initialised.
    pub fn is_initialised(&self) -> bool {
        self.initialised
    }
}

impl Default for MmapRegionSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MmapRegionStats
// -------------------------------------------------------------------

/// Aggregate statistics for the mmap region subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct MmapRegionStats {
    /// Number of active address spaces.
    pub active_mm: u64,
    /// Total VMA regions across all address spaces.
    pub total_regions: u64,
    /// Total bytes mapped.
    pub total_mapped: u64,
    /// Total mmap calls.
    pub total_mmaps: u64,
    /// Total munmap calls.
    pub total_munmaps: u64,
    /// Total split operations.
    pub total_splits: u64,
}

// -------------------------------------------------------------------
// Alignment helpers
// -------------------------------------------------------------------

/// Align `val` down to the nearest multiple of `align`.
fn align_down(val: u64, align: u64) -> u64 {
    val & !(align - 1)
}

/// Align `val` up to the nearest multiple of `align`.
fn align_up(val: u64, align: u64) -> u64 {
    (val + align - 1) & !(align - 1)
}
