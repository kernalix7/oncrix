// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Multi-page I/O (mpage) support for the ONCRIX VFS.
//!
//! Provides helper routines for building multi-page read and write BIO
//! requests. The mpage layer clusters contiguous page-cache pages into a
//! single block-layer I/O request, reducing per-page overhead for sequential
//! access patterns.

use oncrix_lib::{Error, Result};

/// Size of a page in bytes.
pub const PAGE_SIZE: usize = 4096;

/// Maximum number of pages that can be batched in one mpage operation.
pub const MPAGE_MAX_PAGES: usize = 256;

/// Maximum number of segments in a single mpage BIO.
pub const MPAGE_MAX_SEGS: usize = 128;

/// Direction of an mpage I/O operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpageDir {
    /// Read pages from storage into page cache.
    Read,
    /// Write pages from page cache to storage.
    Write,
}

/// A physical segment descriptor within an mpage BIO.
#[derive(Debug, Clone, Copy, Default)]
pub struct MpageSeg {
    /// Physical address of the page buffer.
    pub phys_addr: u64,
    /// Byte offset within the page.
    pub offset: u32,
    /// Length of the segment in bytes.
    pub length: u32,
}

impl MpageSeg {
    /// Construct a full-page segment.
    pub const fn full_page(phys_addr: u64) -> Self {
        Self {
            phys_addr,
            offset: 0,
            length: PAGE_SIZE as u32,
        }
    }

    /// Construct a partial-page segment.
    pub const fn partial(phys_addr: u64, offset: u32, length: u32) -> Self {
        Self {
            phys_addr,
            offset,
            length,
        }
    }
}

/// A multi-page BIO (block I/O) descriptor assembled by the mpage layer.
pub struct MpageBio {
    /// Starting logical block number on the device.
    pub start_block: u64,
    /// Block size used by the filesystem (in bytes).
    pub block_size: u32,
    /// Physical segment list.
    segs: [MpageSeg; MPAGE_MAX_SEGS],
    /// Number of valid segments.
    seg_count: usize,
    /// Total bytes covered by this BIO.
    pub total_bytes: u64,
    /// I/O direction.
    pub dir: MpageDir,
}

impl MpageBio {
    /// Create an empty BIO for the given starting block.
    pub fn new(start_block: u64, block_size: u32, dir: MpageDir) -> Self {
        Self {
            start_block,
            block_size,
            segs: [MpageSeg::default(); MPAGE_MAX_SEGS],
            seg_count: 0,
            total_bytes: 0,
            dir,
        }
    }

    /// Append a segment. Returns `OutOfMemory` if the segment list is full.
    pub fn add_seg(&mut self, seg: MpageSeg) -> Result<()> {
        if self.seg_count >= MPAGE_MAX_SEGS {
            return Err(Error::OutOfMemory);
        }
        self.total_bytes += seg.length as u64;
        self.segs[self.seg_count] = seg;
        self.seg_count += 1;
        Ok(())
    }

    /// Return a slice of the segment list.
    pub fn segs(&self) -> &[MpageSeg] {
        &self.segs[..self.seg_count]
    }

    /// Return the number of segments.
    pub fn seg_count(&self) -> usize {
        self.seg_count
    }

    /// Return `true` if this BIO has no segments.
    pub fn is_empty(&self) -> bool {
        self.seg_count == 0
    }
}

/// Tracks a batch of pages undergoing an mpage I/O operation.
pub struct MpageBatch {
    /// Physical addresses of the pages in the batch.
    page_addrs: [u64; MPAGE_MAX_PAGES],
    /// Page indices (file-relative page numbers).
    page_indices: [u64; MPAGE_MAX_PAGES],
    /// Number of pages in the batch.
    count: usize,
    /// First block number (logical) for the batch.
    pub first_block: u64,
    /// I/O direction.
    pub dir: MpageDir,
}

impl MpageBatch {
    /// Create an empty batch.
    pub fn new(dir: MpageDir) -> Self {
        Self {
            page_addrs: [0u64; MPAGE_MAX_PAGES],
            page_indices: [0u64; MPAGE_MAX_PAGES],
            count: 0,
            first_block: 0,
            dir,
        }
    }

    /// Add a page to the batch. Returns `OutOfMemory` if full.
    pub fn add_page(&mut self, phys_addr: u64, page_index: u64) -> Result<()> {
        if self.count >= MPAGE_MAX_PAGES {
            return Err(Error::OutOfMemory);
        }
        self.page_addrs[self.count] = phys_addr;
        self.page_indices[self.count] = page_index;
        self.count += 1;
        Ok(())
    }

    /// Return the number of pages in the batch.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return the physical address of page at batch index `i`.
    pub fn page_addr(&self, i: usize) -> Result<u64> {
        if i >= self.count {
            return Err(Error::InvalidArgument);
        }
        Ok(self.page_addrs[i])
    }

    /// Return the file-relative page index at batch index `i`.
    pub fn page_index(&self, i: usize) -> Result<u64> {
        if i >= self.count {
            return Err(Error::InvalidArgument);
        }
        Ok(self.page_indices[i])
    }
}

/// Convert a file byte offset to its containing page index.
pub fn offset_to_page_index(offset: u64) -> u64 {
    offset / PAGE_SIZE as u64
}

/// Convert a file byte offset to its offset within its page.
pub fn offset_within_page(offset: u64) -> usize {
    (offset % PAGE_SIZE as u64) as usize
}

/// Compute the logical block number from a file page index.
///
/// `blocks_per_page` is `PAGE_SIZE / block_size`.
pub fn page_to_block(page_index: u64, blocks_per_page: u64) -> u64 {
    page_index * blocks_per_page
}

/// Check whether two consecutive pages are contiguous on disk.
///
/// Returns `true` if `block2 == block1 + blocks_per_page`.
pub fn blocks_are_contiguous(block1: u64, block2: u64, blocks_per_page: u64) -> bool {
    block2 == block1 + blocks_per_page
}
