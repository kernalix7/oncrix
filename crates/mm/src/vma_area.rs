// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VMA (Virtual Memory Area) descriptor and operations.
//!
//! Each process address space is described by a set of VMAs, where each
//! VMA represents a contiguous region of virtual memory with uniform
//! protection flags and backing. This module provides the core VMA
//! descriptor, operations for splitting and merging, and permission
//! validation.
//!
//! # Design
//!
//! ```text
//!  Process address space
//!   ├─ VmaDescriptor [0x1000..0x5000] r-x  (code)
//!   ├─ VmaDescriptor [0x5000..0x8000] rw-  (data)
//!   ├─ VmaDescriptor [0x8000..0xB000] rw-  (heap)
//!   └─ VmaDescriptor [0x7FFF0000..0x80000000] rw- (stack)
//! ```
//!
//! # Key Types
//!
//! - [`VmaFlags`] — protection and type flags
//! - [`VmaDescriptor`] — core VMA structure
//! - [`VmaSplitResult`] — result of splitting a VMA
//!
//! Reference: Linux `include/linux/mm_types.h` (`struct vm_area_struct`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of VMAs per address space.
const MAX_VMAS: usize = 4096;

/// Minimum VMA size (one page).
const MIN_VMA_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// VmaFlags
// -------------------------------------------------------------------

/// Protection and behaviour flags for a VMA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmaFlags(u32);

impl VmaFlags {
    /// Readable.
    pub const READ: Self = Self(1 << 0);
    /// Writable.
    pub const WRITE: Self = Self(1 << 1);
    /// Executable.
    pub const EXEC: Self = Self(1 << 2);
    /// Shared mapping (vs private/COW).
    pub const SHARED: Self = Self(1 << 3);
    /// Grows downward (stack).
    pub const GROWSDOWN: Self = Self(1 << 4);
    /// Locked in memory (mlock).
    pub const LOCKED: Self = Self(1 << 5);
    /// Huge-page backed.
    pub const HUGETLB: Self = Self(1 << 6);
    /// Anonymous (no file backing).
    pub const ANONYMOUS: Self = Self(1 << 7);

    /// Empty flags.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Create from raw bits.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Return raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Check whether a flag is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Set a flag.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Clear a flag.
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Default read-write anonymous.
    pub const fn rw_anon() -> Self {
        Self(Self::READ.0 | Self::WRITE.0 | Self::ANONYMOUS.0)
    }

    /// Default read-execute (code).
    pub const fn rx() -> Self {
        Self(Self::READ.0 | Self::EXEC.0)
    }
}

impl Default for VmaFlags {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// VmaDescriptor
// -------------------------------------------------------------------

/// Backing type for a VMA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmaBacking {
    /// Anonymous memory (swap-backed).
    Anonymous,
    /// File-backed mapping (inode reference).
    File { inode: u64 },
    /// Shared memory segment.
    SharedMem { key: u32 },
    /// Device mapping (MMIO).
    Device { base_phys: u64 },
}

impl Default for VmaBacking {
    fn default() -> Self {
        Self::Anonymous
    }
}

/// A virtual memory area descriptor.
#[derive(Debug, Clone, Copy)]
pub struct VmaDescriptor {
    /// Start address (page-aligned, inclusive).
    start: u64,
    /// End address (page-aligned, exclusive).
    end: u64,
    /// Protection and behaviour flags.
    flags: VmaFlags,
    /// Backing type.
    backing: VmaBacking,
    /// File offset (for file-backed mappings).
    offset: u64,
    /// Owner process ID.
    pid: u32,
}

impl VmaDescriptor {
    /// Create a new VMA descriptor.
    pub const fn new(start: u64, end: u64, flags: VmaFlags, backing: VmaBacking) -> Self {
        Self {
            start,
            end,
            flags,
            backing,
            offset: 0,
            pid: 0,
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

    /// Return the number of pages.
    pub const fn page_count(&self) -> u64 {
        (self.end - self.start) / 4096
    }

    /// Return the flags.
    pub const fn flags(&self) -> VmaFlags {
        self.flags
    }

    /// Return the backing type.
    pub const fn backing(&self) -> VmaBacking {
        self.backing
    }

    /// Return the file offset.
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Set the file offset.
    pub fn set_offset(&mut self, offset: u64) {
        self.offset = offset;
    }

    /// Set the owner PID.
    pub fn set_pid(&mut self, pid: u32) {
        self.pid = pid;
    }

    /// Return the owner PID.
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Check whether an address falls within this VMA.
    pub const fn contains_addr(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    /// Check whether this VMA overlaps with a range.
    pub const fn overlaps(&self, start: u64, end: u64) -> bool {
        self.start < end && start < self.end
    }

    /// Update protection flags.
    pub fn set_flags(&mut self, flags: VmaFlags) {
        self.flags = flags;
    }

    /// Check whether this VMA can be merged with `other`.
    pub fn can_merge_with(&self, other: &Self) -> bool {
        self.end == other.start
            && self.flags == other.flags
            && self.pid == other.pid
            && self.backing_matches(other)
    }

    /// Check whether backing types are compatible for merging.
    fn backing_matches(&self, other: &Self) -> bool {
        match (self.backing, other.backing) {
            (VmaBacking::Anonymous, VmaBacking::Anonymous) => true,
            (VmaBacking::File { inode: a }, VmaBacking::File { inode: b }) => a == b,
            (VmaBacking::SharedMem { key: a }, VmaBacking::SharedMem { key: b }) => a == b,
            _ => false,
        }
    }

    /// Validate that this descriptor is well-formed.
    pub fn validate(&self) -> Result<()> {
        if self.start >= self.end {
            return Err(Error::InvalidArgument);
        }
        if self.start % 4096 != 0 || self.end % 4096 != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.size() < MIN_VMA_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for VmaDescriptor {
    fn default() -> Self {
        Self::new(0, 4096, VmaFlags::empty(), VmaBacking::Anonymous)
    }
}

// -------------------------------------------------------------------
// VmaSplitResult
// -------------------------------------------------------------------

/// Result of splitting a VMA at a given address.
#[derive(Debug, Clone, Copy)]
pub struct VmaSplitResult {
    /// The lower half.
    pub lower: VmaDescriptor,
    /// The upper half.
    pub upper: VmaDescriptor,
}

// -------------------------------------------------------------------
// VmaTable
// -------------------------------------------------------------------

/// Collection of VMAs for an address space.
pub struct VmaTable {
    /// VMA descriptors sorted by start address.
    entries: [VmaDescriptor; MAX_VMAS],
    /// Number of valid entries.
    count: usize,
}

impl VmaTable {
    /// Create an empty VMA table.
    pub const fn new() -> Self {
        Self {
            entries: [const { VmaDescriptor::new(0, 4096, VmaFlags::empty(), VmaBacking::Anonymous) };
                MAX_VMAS],
            count: 0,
        }
    }

    /// Return the number of VMAs.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Check whether the table is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Insert a new VMA, keeping sorted order.
    pub fn insert(&mut self, vma: VmaDescriptor) -> Result<()> {
        vma.validate()?;
        if self.count >= MAX_VMAS {
            return Err(Error::OutOfMemory);
        }
        // Check overlap with existing entries.
        for idx in 0..self.count {
            if self.entries[idx].overlaps(vma.start(), vma.end()) {
                return Err(Error::AlreadyExists);
            }
        }
        // Insert sorted by start address.
        let mut pos = self.count;
        while pos > 0 && self.entries[pos - 1].start() > vma.start() {
            self.entries[pos] = self.entries[pos - 1];
            pos -= 1;
        }
        self.entries[pos] = vma;
        self.count += 1;
        Ok(())
    }

    /// Find the VMA containing `addr`.
    pub fn find(&self, addr: u64) -> Option<&VmaDescriptor> {
        for idx in 0..self.count {
            if self.entries[idx].contains_addr(addr) {
                return Some(&self.entries[idx]);
            }
        }
        None
    }
}

impl Default for VmaTable {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Split a VMA at the given address.
pub fn split_vma(vma: &VmaDescriptor, at: u64) -> Result<VmaSplitResult> {
    if at <= vma.start() || at >= vma.end() || at % 4096 != 0 {
        return Err(Error::InvalidArgument);
    }
    let lower = VmaDescriptor::new(vma.start(), at, vma.flags(), vma.backing());
    let upper = VmaDescriptor::new(at, vma.end(), vma.flags(), vma.backing());
    Ok(VmaSplitResult { lower, upper })
}

/// Merge two adjacent VMAs into one.
pub fn merge_vmas(lower: &VmaDescriptor, upper: &VmaDescriptor) -> Result<VmaDescriptor> {
    if !lower.can_merge_with(upper) {
        return Err(Error::InvalidArgument);
    }
    Ok(VmaDescriptor::new(
        lower.start(),
        upper.end(),
        lower.flags(),
        lower.backing(),
    ))
}

/// Create a standard anonymous RW VMA.
pub fn create_anon_vma(start: u64, size: u64, pid: u32) -> Result<VmaDescriptor> {
    let end = start.checked_add(size).ok_or(Error::InvalidArgument)?;
    let mut vma = VmaDescriptor::new(start, end, VmaFlags::rw_anon(), VmaBacking::Anonymous);
    vma.set_pid(pid);
    vma.validate()?;
    Ok(vma)
}
