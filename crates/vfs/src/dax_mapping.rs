// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Direct Access (DAX) file mapping for the ONCRIX VFS.
//!
//! DAX allows user-space processes and the kernel to access persistent memory
//! (PMEM / NVDIMM) without going through the page cache. This module provides
//! the VFS-layer structures for DAX inode extensions, pfn range management,
//! and the hooks needed by DAX-capable filesystem implementations.

use oncrix_lib::{Error, Result};

/// Page shift for a standard 4 KiB page.
pub const DAX_PAGE_SHIFT: u32 = 12;

/// Page shift for a 2 MiB huge page used in DAX huge mappings.
pub const DAX_HUGE_PAGE_SHIFT: u32 = 21;

/// Maximum number of pfn ranges tracked per DAX inode.
pub const DAX_MAX_PFN_RANGES: usize = 32;

/// Flags describing a DAX pfn range.
#[derive(Debug, Clone, Copy, Default)]
pub struct DaxPfnFlags {
    /// This range covers huge (2 MiB) pages.
    pub huge: bool,
    /// The backing PMEM region is write-protected.
    pub read_only: bool,
    /// The range has been zeroed (sparse file region).
    pub zeroed: bool,
}

/// A contiguous range of page frame numbers backing a DAX file extent.
#[derive(Debug, Clone, Copy)]
pub struct DaxPfnRange {
    /// Starting page frame number of the physical PMEM region.
    pub start_pfn: u64,
    /// Number of pages in this range.
    pub page_count: u64,
    /// File logical offset (in bytes) that this range begins at.
    pub file_offset: u64,
    /// Range flags.
    pub flags: DaxPfnFlags,
    /// Whether this range entry is active.
    pub active: bool,
}

impl DaxPfnRange {
    /// Construct a new pfn range descriptor.
    pub const fn new(start_pfn: u64, page_count: u64, file_offset: u64) -> Self {
        Self {
            start_pfn,
            page_count,
            file_offset,
            flags: DaxPfnFlags {
                huge: false,
                read_only: false,
                zeroed: false,
            },
            active: true,
        }
    }

    /// Return the physical byte address of the first byte in this range.
    pub fn phys_addr(&self) -> u64 {
        self.start_pfn << DAX_PAGE_SHIFT
    }

    /// Return the total size of this range in bytes.
    pub fn byte_size(&self) -> u64 {
        self.page_count << DAX_PAGE_SHIFT
    }

    /// Return the pfn that corresponds to a given file-relative byte offset.
    ///
    /// Returns `InvalidArgument` if the offset falls outside this range.
    pub fn pfn_at_offset(&self, file_offset: u64) -> Result<u64> {
        if file_offset < self.file_offset {
            return Err(Error::InvalidArgument);
        }
        let rel = file_offset - self.file_offset;
        let page_idx = rel >> DAX_PAGE_SHIFT;
        if page_idx >= self.page_count {
            return Err(Error::InvalidArgument);
        }
        Ok(self.start_pfn + page_idx)
    }
}

impl Default for DaxPfnRange {
    fn default() -> Self {
        Self {
            start_pfn: 0,
            page_count: 0,
            file_offset: 0,
            flags: DaxPfnFlags {
                huge: false,
                read_only: false,
                zeroed: false,
            },
            active: false,
        }
    }
}

/// DAX inode extension — attached to inodes on DAX-capable filesystems.
pub struct DaxInodeExt {
    /// All pfn ranges mapped for this file.
    ranges: [DaxPfnRange; DAX_MAX_PFN_RANGES],
    /// Number of active ranges.
    count: usize,
    /// Whether DAX is enabled for this inode.
    pub dax_enabled: bool,
}

impl DaxInodeExt {
    /// Create an empty DAX inode extension.
    pub const fn new() -> Self {
        Self {
            ranges: [const { DaxPfnRange::default_const() }; DAX_MAX_PFN_RANGES],
            count: 0,
            dax_enabled: false,
        }
    }

    /// Insert a pfn range, returning its index or `OutOfMemory`.
    pub fn insert_range(&mut self, range: DaxPfnRange) -> Result<usize> {
        if self.count >= DAX_MAX_PFN_RANGES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.ranges[idx] = range;
        self.count += 1;
        Ok(idx)
    }

    /// Look up the pfn for a given file offset, searching all ranges.
    pub fn lookup_pfn(&self, file_offset: u64) -> Result<u64> {
        for i in 0..self.count {
            let r = &self.ranges[i];
            if !r.active {
                continue;
            }
            if let Ok(pfn) = r.pfn_at_offset(file_offset) {
                return Ok(pfn);
            }
        }
        Err(Error::NotFound)
    }

    /// Remove a range by index.
    pub fn remove_range(&mut self, idx: usize) -> Result<()> {
        if idx >= self.count {
            return Err(Error::InvalidArgument);
        }
        self.ranges[idx].active = false;
        Ok(())
    }

    /// Return the total file size covered by all active DAX ranges.
    pub fn total_dax_bytes(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.count {
            if self.ranges[i].active {
                total += self.ranges[i].byte_size();
            }
        }
        total
    }
}

impl Default for DaxInodeExt {
    fn default() -> Self {
        Self::new()
    }
}

impl DaxPfnRange {
    /// A const version of Default for use in array initializers.
    pub const fn default_const() -> Self {
        Self {
            start_pfn: 0,
            page_count: 0,
            file_offset: 0,
            flags: DaxPfnFlags {
                huge: false,
                read_only: false,
                zeroed: false,
            },
            active: false,
        }
    }
}

/// DAX operation mode for a filesystem mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DaxMode {
    /// DAX is not enabled.
    #[default]
    Disabled,
    /// DAX is always on for all files.
    Always,
    /// DAX is on only for inodes with the DAX inode flag set.
    Inode,
    /// Never use DAX (even if the device supports it).
    Never,
}

impl DaxMode {
    /// Parse a DAX mode from the ASCII string used in mount options.
    pub fn from_mount_opt(s: &[u8]) -> Result<Self> {
        match s {
            b"always" => Ok(Self::Always),
            b"inode" => Ok(Self::Inode),
            b"never" => Ok(Self::Never),
            _ => Err(Error::InvalidArgument),
        }
    }
}

/// Compute the physical address of a pfn.
pub fn pfn_to_phys(pfn: u64) -> u64 {
    pfn << DAX_PAGE_SHIFT
}

/// Compute the pfn that contains a physical address.
pub fn phys_to_pfn(phys: u64) -> u64 {
    phys >> DAX_PAGE_SHIFT
}

/// Validate that a DAX mapping range is naturally aligned for huge pages.
pub fn validate_huge_alignment(phys: u64) -> Result<()> {
    const HUGE_ALIGN: u64 = 1 << DAX_HUGE_PAGE_SHIFT;
    if phys & (HUGE_ALIGN - 1) != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}
