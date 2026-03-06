// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VMA (Virtual Memory Area) iteration and lookup.
//!
//! Provides a fixed-capacity container of VMAs and an iterator for
//! walking, searching, and manipulating them. Modeled after the Linux
//! kernel's `struct vm_area_struct` and the maple-tree VMA walk API.
//!
//! - [`VmaFlags`] — permission and type flags for a VMA
//! - [`VmaArea`] — a single virtual memory area descriptor
//! - [`VmaList`] — sorted container of VMAs
//! - [`VmaIterator`] — cursor-based forward/backward iterator
//! - [`VmaMergeResult`] — outcome of a merge-check
//!
//! Reference: `.kernelORG/` — `mm/mmap.c`, `include/linux/mm_types.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of VMAs in a single address space.
const MAX_VMAS: usize = 256;

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// VmaFlags
// -------------------------------------------------------------------

/// Permission and type flags for a Virtual Memory Area.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VmaFlags {
    /// Raw flag bits.
    bits: u32,
}

impl VmaFlags {
    /// Readable.
    pub const READ: u32 = 1 << 0;
    /// Writable.
    pub const WRITE: u32 = 1 << 1;
    /// Executable.
    pub const EXEC: u32 = 1 << 2;
    /// Shared mapping.
    pub const SHARED: u32 = 1 << 3;
    /// Private (copy-on-write) mapping.
    pub const PRIVATE: u32 = 1 << 4;
    /// Anonymous (no file backing).
    pub const ANONYMOUS: u32 = 1 << 5;
    /// Stack region.
    pub const STACK: u32 = 1 << 6;
    /// Heap region.
    pub const HEAP: u32 = 1 << 7;
    /// Huge-page backed.
    pub const HUGEPAGE: u32 = 1 << 8;
    /// Region is locked (mlock).
    pub const LOCKED: u32 = 1 << 9;
    /// Region uses huge TLB pages.
    pub const HUGETLB: u32 = 1 << 10;
    /// Don't expand on fault.
    pub const DONTEXPAND: u32 = 1 << 11;
    /// Grow downward (stack).
    pub const GROWSDOWN: u32 = 1 << 12;

    /// Creates an empty flag set.
    pub fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Creates from raw bits.
    pub fn from_bits(bits: u32) -> Self {
        Self { bits }
    }

    /// Returns the raw bits.
    pub fn bits(self) -> u32 {
        self.bits
    }

    /// Tests if a flag is set.
    pub fn contains(self, flag: u32) -> bool {
        self.bits & flag == flag
    }

    /// Sets a flag.
    pub fn set(self, flag: u32) -> Self {
        Self {
            bits: self.bits | flag,
        }
    }

    /// Clears a flag.
    pub fn clear(self, flag: u32) -> Self {
        Self {
            bits: self.bits & !flag,
        }
    }

    /// Returns default flags for anonymous private mapping
    /// (READ | WRITE | PRIVATE | ANONYMOUS).
    pub fn anon_default() -> Self {
        Self {
            bits: Self::READ | Self::WRITE | Self::PRIVATE | Self::ANONYMOUS,
        }
    }
}

// -------------------------------------------------------------------
// VmaArea
// -------------------------------------------------------------------

/// A single Virtual Memory Area descriptor.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmaArea {
    /// Start virtual address (inclusive, page-aligned).
    pub start: u64,
    /// End virtual address (exclusive, page-aligned).
    pub end: u64,
    /// VMA permission and type flags.
    pub flags: VmaFlags,
    /// File offset in pages (for file-backed mappings).
    pub pgoff: u64,
    /// Identifier for the backing file (0 for anonymous).
    pub file_id: u64,
    /// Whether the VMA is in use.
    pub active: bool,
}

impl VmaArea {
    /// Creates a new VMA.
    pub fn new(start: u64, end: u64, flags: VmaFlags) -> Result<Self> {
        if start >= end || start % PAGE_SIZE != 0 || end % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            start,
            end,
            flags,
            pgoff: 0,
            file_id: 0,
            active: true,
        })
    }

    /// Returns the size in bytes.
    pub fn size(&self) -> u64 {
        self.end - self.start
    }

    /// Returns the number of pages covered.
    pub fn page_count(&self) -> u64 {
        self.size() / PAGE_SIZE
    }

    /// Returns `true` if the address falls within this VMA.
    pub fn contains(&self, addr: u64) -> bool {
        self.active && addr >= self.start && addr < self.end
    }

    /// Returns `true` if this VMA overlaps with the given range.
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        self.active && self.start < end && start < self.end
    }

    /// Returns `true` if this VMA is adjacent to another and
    /// they could potentially be merged (same flags, contiguous).
    pub fn can_merge_with(&self, other: &VmaArea) -> bool {
        if !self.active || !other.active {
            return false;
        }
        self.end == other.start && self.flags == other.flags && self.file_id == other.file_id
    }
}

// -------------------------------------------------------------------
// VmaMergeResult
// -------------------------------------------------------------------

/// Outcome of a VMA merge check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VmaMergeResult {
    /// No merge is possible.
    #[default]
    None,
    /// Merge with the predecessor VMA.
    MergePrev,
    /// Merge with the successor VMA.
    MergeNext,
    /// Merge with both predecessor and successor.
    MergeBoth,
}

// -------------------------------------------------------------------
// VmaList
// -------------------------------------------------------------------

/// Sorted container of VMAs for a single address space.
pub struct VmaList {
    /// VMA storage (sorted by start address).
    vmas: [VmaArea; MAX_VMAS],
    /// Number of active VMAs.
    count: usize,
    /// Total mapped bytes.
    total_mapped: u64,
}

impl Default for VmaList {
    fn default() -> Self {
        Self {
            vmas: [VmaArea::default(); MAX_VMAS],
            count: 0,
            total_mapped: 0,
        }
    }
}

impl VmaList {
    /// Creates a new empty VMA list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of active VMAs.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no VMAs are present.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns total mapped bytes.
    pub fn total_mapped(&self) -> u64 {
        self.total_mapped
    }

    /// Inserts a new VMA, keeping the list sorted by start address.
    pub fn insert(&mut self, vma: VmaArea) -> Result<usize> {
        if self.count >= MAX_VMAS {
            return Err(Error::OutOfMemory);
        }
        // Check for overlaps.
        for i in 0..self.count {
            if self.vmas[i].active && self.vmas[i].overlaps(vma.start, vma.end) {
                return Err(Error::AlreadyExists);
            }
        }
        // Find insertion point (sorted by start).
        let mut pos = self.count;
        for i in 0..self.count {
            if vma.start < self.vmas[i].start {
                pos = i;
                break;
            }
        }
        // Shift elements right.
        let mut j = self.count;
        while j > pos {
            self.vmas[j] = self.vmas[j - 1];
            j -= 1;
        }
        self.vmas[pos] = vma;
        self.count += 1;
        self.total_mapped += vma.size();
        Ok(pos)
    }

    /// Removes the VMA at the given index.
    pub fn remove(&mut self, index: usize) -> Result<VmaArea> {
        if index >= self.count {
            return Err(Error::NotFound);
        }
        let vma = self.vmas[index];
        self.total_mapped = self.total_mapped.saturating_sub(vma.size());
        // Shift elements left.
        for i in index..self.count - 1 {
            self.vmas[i] = self.vmas[i + 1];
        }
        self.vmas[self.count - 1] = VmaArea::default();
        self.count -= 1;
        Ok(vma)
    }

    /// Finds the first VMA containing the given address.
    pub fn find(&self, addr: u64) -> Option<(usize, &VmaArea)> {
        for i in 0..self.count {
            if self.vmas[i].contains(addr) {
                return Some((i, &self.vmas[i]));
            }
            // Sorted by start: if start > addr, no match.
            if self.vmas[i].start > addr {
                break;
            }
        }
        None
    }

    /// Finds the first VMA whose end > addr (same as Linux's
    /// `find_vma`).
    pub fn find_vma(&self, addr: u64) -> Option<(usize, &VmaArea)> {
        for i in 0..self.count {
            if self.vmas[i].active && self.vmas[i].end > addr {
                return Some((i, &self.vmas[i]));
            }
        }
        None
    }

    /// Finds any VMA that intersects [start, end).
    pub fn find_intersection(&self, start: u64, end: u64) -> Option<(usize, &VmaArea)> {
        for i in 0..self.count {
            if self.vmas[i].overlaps(start, end) {
                return Some((i, &self.vmas[i]));
            }
            if self.vmas[i].start >= end {
                break;
            }
        }
        None
    }

    /// Gets the VMA at the given index.
    pub fn get(&self, index: usize) -> Option<&VmaArea> {
        if index < self.count {
            Some(&self.vmas[index])
        } else {
            None
        }
    }

    /// Gets the next VMA after the given index.
    pub fn next(&self, index: usize) -> Option<(usize, &VmaArea)> {
        let next = index + 1;
        if next < self.count {
            Some((next, &self.vmas[next]))
        } else {
            None
        }
    }

    /// Gets the previous VMA before the given index.
    pub fn prev(&self, index: usize) -> Option<(usize, &VmaArea)> {
        if index > 0 && index <= self.count {
            Some((index - 1, &self.vmas[index - 1]))
        } else {
            None
        }
    }

    /// Checks if a new VMA at the given range could be merged with
    /// neighbours.
    pub fn merge_check(&self, start: u64, end: u64, flags: VmaFlags) -> VmaMergeResult {
        let candidate = VmaArea {
            start,
            end,
            flags,
            pgoff: 0,
            file_id: 0,
            active: true,
        };

        let mut merge_prev = false;
        let mut merge_next = false;

        for i in 0..self.count {
            if self.vmas[i].can_merge_with(&candidate) {
                merge_prev = true;
            }
            if candidate.can_merge_with(&self.vmas[i]) {
                merge_next = true;
            }
        }

        match (merge_prev, merge_next) {
            (true, true) => VmaMergeResult::MergeBoth,
            (true, false) => VmaMergeResult::MergePrev,
            (false, true) => VmaMergeResult::MergeNext,
            (false, false) => VmaMergeResult::None,
        }
    }

    /// Creates an iterator starting at the beginning.
    pub fn iter(&self) -> VmaIterator<'_> {
        VmaIterator {
            list: self,
            current: 0,
        }
    }

    /// Creates an iterator starting at the given index.
    pub fn iter_from(&self, index: usize) -> VmaIterator<'_> {
        VmaIterator {
            list: self,
            current: index,
        }
    }
}

// -------------------------------------------------------------------
// VmaIterator
// -------------------------------------------------------------------

/// Cursor-based forward iterator over VMAs.
pub struct VmaIterator<'a> {
    /// Reference to the VMA list.
    list: &'a VmaList,
    /// Current cursor position.
    current: usize,
}

impl<'a> VmaIterator<'a> {
    /// Returns the current VMA, or `None` if past the end.
    pub fn current(&self) -> Option<&'a VmaArea> {
        self.list.get(self.current)
    }

    /// Returns the current index.
    pub fn index(&self) -> usize {
        self.current
    }

    /// Advances to the next VMA.
    pub fn advance(&mut self) -> Option<&'a VmaArea> {
        if self.current < self.list.len() {
            self.current += 1;
        }
        self.list.get(self.current)
    }

    /// Moves back to the previous VMA.
    pub fn retreat(&mut self) -> Option<&'a VmaArea> {
        if self.current > 0 {
            self.current -= 1;
        }
        self.list.get(self.current)
    }

    /// Seeks to the first VMA containing `addr`.
    pub fn seek(&mut self, addr: u64) -> Option<&'a VmaArea> {
        if let Some((idx, _)) = self.list.find(addr) {
            self.current = idx;
            self.list.get(idx)
        } else {
            None
        }
    }

    /// Returns `true` if the iterator has more elements.
    pub fn has_next(&self) -> bool {
        self.current + 1 < self.list.len()
    }

    /// Calls `f` for each remaining VMA.
    pub fn for_each<F>(&mut self, mut f: F)
    where
        F: FnMut(&VmaArea),
    {
        while let Some(vma) = self.list.get(self.current) {
            f(vma);
            self.current += 1;
        }
    }

    /// Counts remaining VMAs from the current position.
    pub fn remaining(&self) -> usize {
        if self.current >= self.list.len() {
            0
        } else {
            self.list.len() - self.current
        }
    }
}
