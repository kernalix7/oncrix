// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! File read/write iteration — `read_iter`/`write_iter` vectored I/O.
//!
//! Implements the `iov_iter`-based scatter-gather file access pattern used
//! by modern Linux kernels.  Instead of reading/writing a single contiguous
//! buffer, operations work with a chain of [`IoSegment`]s that describe
//! non-contiguous memory regions.
//!
//! # Architecture
//!
//! ```text
//! +-------------------------------------------------------------+
//! |  User-space read(fd, buf, count) / readv(fd, iov, iovcnt)   |
//! |       |                                                      |
//! |       v                                                      |
//! |  VFS dispatch layer                                          |
//! |       |                                                      |
//! |       v                                                      |
//! |  +----------------------------------------------+            |
//! |  | IoVecIter                                    |            |
//! |  | +----------+ +----------+ +----------+       |            |
//! |  | | Segment0 | | Segment1 | | Segment2 |       |            |
//! |  | | base,len | | base,len | | base,len |       |            |
//! |  | +----------+ +----------+ +----------+       |            |
//! |  |   current_seg ^   offset within segment      |            |
//! |  +----------------------------------------------+            |
//! |       |                                                      |
//! |       v                                                      |
//! |  read_iter() / write_iter() on file_operations               |
//! |       |                                                      |
//! |       v                                                      |
//! |  Page cache or direct I/O backend                            |
//! +-------------------------------------------------------------+
//! ```
//!
//! # Key types
//!
//! - [`IoSegment`] — a single (base, length) memory region.
//! - [`IoVecIter`] — iterator over a fixed-size array of segments.
//! - [`FileRange`] — describes a byte range within a file.
//! - [`RwIterOps`] — trait that filesystems implement for vectored I/O.
//! - [`SpliceDirection`] — direction for splice read/write operations.
//!
//! # Reference
//!
//! Linux `include/linux/uio.h`, `lib/iov_iter.c`, `fs/read_write.c`.

extern crate alloc;

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of I/O segments in a single vectored operation.
const MAX_SEGMENTS: usize = 16;

/// Maximum bytes per single I/O segment.
const MAX_SEGMENT_SIZE: usize = 1024 * 1024; // 1 MiB

/// Maximum total bytes across all segments in one operation.
const MAX_TOTAL_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

/// Page size constant.
const PAGE_SIZE: usize = 4096;

/// Maximum pages that can be referenced in a page-to-iter copy.
const MAX_PAGES: usize = 256;

/// Sentinel for "no page".
const NO_PAGE: u64 = u64::MAX;

// ── IoSegment ────────────────────────────────────────────────────────────────

/// A single I/O memory segment in a scatter-gather list.
///
/// Represents a contiguous region of memory (user-space or kernel-space)
/// that participates in a vectored read or write operation.
#[derive(Debug, Clone, Copy)]
pub struct IoSegment {
    /// Base address (as opaque `usize`; caller validates).
    pub base: usize,
    /// Length in bytes.
    pub length: usize,
}

impl IoSegment {
    /// Create a new I/O segment.
    pub const fn new(base: usize, length: usize) -> Self {
        Self { base, length }
    }

    /// Create an empty (zero-length) segment.
    pub const fn empty() -> Self {
        Self { base: 0, length: 0 }
    }

    /// Whether this segment is empty.
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// End address (base + length).
    pub const fn end(&self) -> usize {
        self.base + self.length
    }
}

// ── IoIterType ───────────────────────────────────────────────────────────────

/// Type of I/O iterator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoIterType {
    /// User-space iovec segments.
    IoVec,
    /// Kernel-space kvec segments.
    KVec,
    /// Bio-vec (block I/O pages).
    BioVec,
    /// Pipe-based iterator.
    Pipe,
    /// Extended attribute buffer.
    Xattr,
}

// ── IoVecIter ────────────────────────────────────────────────────────────────

/// Iterator over a fixed-size array of I/O segments.
///
/// Tracks the current position across multiple segments, providing
/// a unified cursor for scatter-gather I/O operations.
pub struct IoVecIter {
    /// Segment array.
    segments: [IoSegment; MAX_SEGMENTS],
    /// Number of valid segments.
    segment_count: usize,
    /// Index of the current segment being processed.
    current_seg: usize,
    /// Byte offset within the current segment.
    seg_offset: usize,
    /// Total bytes remaining to iterate.
    remaining: usize,
    /// Total bytes that have been consumed.
    consumed: usize,
    /// Type of this iterator.
    iter_type: IoIterType,
    /// Whether this iterator is for writing (to user) or reading (from user).
    is_write: bool,
}

impl IoVecIter {
    /// Create a new iterator from a slice of segments.
    ///
    /// Validates that the total size does not exceed limits.
    pub fn new(segments: &[IoSegment], iter_type: IoIterType, is_write: bool) -> Result<Self> {
        if segments.is_empty() || segments.len() > MAX_SEGMENTS {
            return Err(Error::InvalidArgument);
        }

        let mut segs = [IoSegment::empty(); MAX_SEGMENTS];
        let mut total: usize = 0;

        for (i, seg) in segments.iter().enumerate() {
            if seg.length > MAX_SEGMENT_SIZE {
                return Err(Error::InvalidArgument);
            }
            total = total
                .checked_add(seg.length)
                .ok_or(Error::InvalidArgument)?;
            segs[i] = *seg;
        }

        if total > MAX_TOTAL_BYTES {
            return Err(Error::InvalidArgument);
        }

        Ok(Self {
            segments: segs,
            segment_count: segments.len(),
            current_seg: 0,
            seg_offset: 0,
            remaining: total,
            consumed: 0,
            iter_type,
            is_write,
        })
    }

    /// Create an empty iterator (no segments, zero bytes).
    pub const fn empty() -> Self {
        Self {
            segments: [const { IoSegment::empty() }; MAX_SEGMENTS],
            segment_count: 0,
            current_seg: 0,
            seg_offset: 0,
            remaining: 0,
            consumed: 0,
            iter_type: IoIterType::IoVec,
            is_write: false,
        }
    }

    /// Total remaining bytes.
    pub fn remaining(&self) -> usize {
        self.remaining
    }

    /// Total consumed bytes.
    pub fn consumed(&self) -> usize {
        self.consumed
    }

    /// Whether the iterator has been fully consumed.
    pub fn is_exhausted(&self) -> bool {
        self.remaining == 0
    }

    /// Iterator type.
    pub fn iter_type(&self) -> IoIterType {
        self.iter_type
    }

    /// Number of segments.
    pub fn segment_count(&self) -> usize {
        self.segment_count
    }

    /// Advance the iterator by `n` bytes.
    ///
    /// Moves the cursor forward across segment boundaries.
    pub fn advance(&mut self, n: usize) -> Result<()> {
        let to_advance = n.min(self.remaining);
        let mut left = to_advance;

        while left > 0 && self.current_seg < self.segment_count {
            let seg = &self.segments[self.current_seg];
            let avail = seg.length - self.seg_offset;

            if left >= avail {
                left -= avail;
                self.current_seg += 1;
                self.seg_offset = 0;
            } else {
                self.seg_offset += left;
                left = 0;
            }
        }

        let actually_advanced = to_advance - left;
        self.remaining -= actually_advanced;
        self.consumed += actually_advanced;
        Ok(())
    }

    /// Revert (un-advance) by `n` bytes.
    ///
    /// Moves the cursor backward. Used when a partial I/O must be
    /// rolled back.
    pub fn revert(&mut self, n: usize) -> Result<()> {
        let to_revert = n.min(self.consumed);
        let mut left = to_revert;

        while left > 0 {
            if self.seg_offset >= left {
                self.seg_offset -= left;
                left = 0;
            } else {
                left -= self.seg_offset;
                if self.current_seg == 0 {
                    break;
                }
                self.current_seg -= 1;
                self.seg_offset = self.segments[self.current_seg].length;
            }
        }

        let actually_reverted = to_revert - left;
        self.remaining += actually_reverted;
        self.consumed -= actually_reverted;
        Ok(())
    }

    /// Return the current segment and offset within it.
    pub fn current_position(&self) -> Option<(IoSegment, usize)> {
        if self.current_seg < self.segment_count {
            Some((self.segments[self.current_seg], self.seg_offset))
        } else {
            None
        }
    }

    /// Return the effective base address at the current position.
    pub fn current_base(&self) -> Option<usize> {
        if self.current_seg < self.segment_count {
            Some(self.segments[self.current_seg].base + self.seg_offset)
        } else {
            None
        }
    }

    /// Return the number of contiguous bytes available from the current
    /// position within the current segment.
    pub fn current_available(&self) -> usize {
        if self.current_seg < self.segment_count {
            self.segments[self.current_seg].length - self.seg_offset
        } else {
            0
        }
    }

    /// Truncate the iterator to at most `n` remaining bytes.
    pub fn truncate(&mut self, n: usize) {
        if n < self.remaining {
            self.remaining = n;
        }
    }

    /// Reset the iterator to the beginning.
    pub fn reset(&mut self) {
        let total: usize = self.segments[..self.segment_count]
            .iter()
            .map(|s| s.length)
            .sum();
        self.current_seg = 0;
        self.seg_offset = 0;
        self.remaining = total;
        self.consumed = 0;
    }
}

// ── FileRange ────────────────────────────────────────────────────────────────

/// A byte range within a file.
///
/// Used to describe the portion of a file that a read or write
/// operation targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileRange {
    /// Starting byte offset within the file.
    pub offset: u64,
    /// Number of bytes in the range.
    pub length: u64,
}

impl FileRange {
    /// Create a new file range.
    pub const fn new(offset: u64, length: u64) -> Self {
        Self { offset, length }
    }

    /// End offset (exclusive).
    pub const fn end(&self) -> u64 {
        self.offset + self.length
    }

    /// Whether this range is empty.
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Whether two ranges overlap.
    pub fn overlaps(&self, other: &FileRange) -> bool {
        self.offset < other.end() && other.offset < self.end()
    }

    /// Compute the intersection of two ranges, if any.
    pub fn intersect(&self, other: &FileRange) -> Option<FileRange> {
        if !self.overlaps(other) {
            return None;
        }
        let start = self.offset.max(other.offset);
        let end = self.end().min(other.end());
        Some(FileRange::new(start, end - start))
    }

    /// Whether this range contains a given byte offset.
    pub fn contains_offset(&self, off: u64) -> bool {
        off >= self.offset && off < self.end()
    }

    /// Number of pages (4 KiB) this range spans.
    pub fn page_count(&self) -> u64 {
        if self.length == 0 {
            return 0;
        }
        let start_page = self.offset / PAGE_SIZE as u64;
        let end_page = (self.end() + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64;
        end_page - start_page
    }
}

// ── SpliceDirection ──────────────────────────────────────────────────────────

/// Direction of a splice operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpliceDirection {
    /// Splice data from a file into a pipe (splice read).
    FileToPipe,
    /// Splice data from a pipe into a file (splice write).
    PipeToFile,
}

// ── PageRef ──────────────────────────────────────────────────────────────────

/// A reference to a page in the page cache.
///
/// Used by `copy_page_to_iter` and `copy_page_from_iter` to move data
/// between page-cache pages and an I/O iterator.
#[derive(Debug, Clone, Copy)]
pub struct PageRef {
    /// Page frame number (or opaque page ID).
    pub pfn: u64,
    /// Offset within the page.
    pub offset: u32,
    /// Number of valid bytes from offset.
    pub length: u32,
}

impl PageRef {
    /// Create a new page reference.
    pub const fn new(pfn: u64, offset: u32, length: u32) -> Self {
        Self {
            pfn,
            offset,
            length,
        }
    }

    /// Create an invalid/empty page reference.
    pub const fn invalid() -> Self {
        Self {
            pfn: NO_PAGE,
            offset: 0,
            length: 0,
        }
    }

    /// Whether this page reference is valid.
    pub fn is_valid(&self) -> bool {
        self.pfn != NO_PAGE && self.length > 0
    }
}

// ── RwIterResult ─────────────────────────────────────────────────────────────

/// Result of a vectored read or write operation.
#[derive(Debug, Clone, Copy)]
pub struct RwIterResult {
    /// Number of bytes successfully transferred.
    pub bytes_transferred: usize,
    /// File offset after the operation.
    pub new_offset: u64,
    /// Whether the end-of-file was reached (reads only).
    pub eof: bool,
    /// Whether a short transfer occurred (fewer bytes than requested).
    pub short_transfer: bool,
}

impl RwIterResult {
    /// Create a result for a completed transfer.
    pub const fn completed(bytes: usize, new_offset: u64) -> Self {
        Self {
            bytes_transferred: bytes,
            new_offset,
            eof: false,
            short_transfer: false,
        }
    }

    /// Create a result for an EOF condition.
    pub const fn eof(bytes: usize, new_offset: u64) -> Self {
        Self {
            bytes_transferred: bytes,
            new_offset,
            eof: true,
            short_transfer: bytes > 0,
        }
    }
}

// ── SpliceState ──────────────────────────────────────────────────────────────

/// Internal state for tracking an in-progress splice operation.
#[derive(Debug, Clone, Copy)]
pub struct SpliceState {
    /// Direction of the splice.
    pub direction: SpliceDirection,
    /// Source file descriptor (or pipe ID).
    pub src_fd: u32,
    /// Destination file descriptor (or pipe ID).
    pub dst_fd: u32,
    /// Current file offset.
    pub file_offset: u64,
    /// Bytes remaining to splice.
    pub remaining: usize,
    /// Bytes already spliced.
    pub completed: usize,
    /// Whether the operation should not block.
    pub nonblock: bool,
    /// Whether more data follows (SPLICE_F_MORE hint).
    pub more: bool,
}

impl SpliceState {
    /// Create a new splice state.
    pub const fn new(
        direction: SpliceDirection,
        src_fd: u32,
        dst_fd: u32,
        file_offset: u64,
        count: usize,
        nonblock: bool,
    ) -> Self {
        Self {
            direction,
            src_fd,
            dst_fd,
            file_offset,
            remaining: count,
            completed: 0,
            nonblock,
            more: false,
        }
    }

    /// Whether the splice operation is finished.
    pub fn is_complete(&self) -> bool {
        self.remaining == 0
    }

    /// Record progress of `n` bytes.
    pub fn advance(&mut self, n: usize) {
        let actual = n.min(self.remaining);
        self.remaining -= actual;
        self.completed += actual;
        self.file_offset += actual as u64;
    }
}

// ── RwIterOps trait ──────────────────────────────────────────────────────────

/// Trait for filesystem-level vectored read/write operations.
///
/// Filesystems that support scatter-gather I/O implement this trait
/// on their file object type.
pub trait RwIterOps {
    /// Perform a vectored read, filling segments from the file.
    ///
    /// Reads up to `iter.remaining()` bytes starting at `offset`.
    /// Advances the iterator and returns the transfer result.
    fn read_iter(&self, iter: &mut IoVecIter, offset: u64) -> Result<RwIterResult>;

    /// Perform a vectored write, draining segments to the file.
    ///
    /// Writes up to `iter.remaining()` bytes starting at `offset`.
    /// Advances the iterator and returns the transfer result.
    fn write_iter(&self, iter: &mut IoVecIter, offset: u64) -> Result<RwIterResult>;

    /// Splice data from this file into a pipe.
    fn splice_read(&self, state: &mut SpliceState) -> Result<usize> {
        let _ = state;
        Err(Error::NotImplemented)
    }

    /// Splice data from a pipe into this file.
    fn splice_write(&self, state: &mut SpliceState) -> Result<usize> {
        let _ = state;
        Err(Error::NotImplemented)
    }
}

// ── PageIterOps ──────────────────────────────────────────────────────────────

/// Operations for copying data between page-cache pages and I/O iterators.
pub struct PageIterOps;

impl PageIterOps {
    /// Copy data from a page-cache page to an I/O iterator.
    ///
    /// Simulates copying `page.length` bytes from the given page into
    /// the current position of `iter`, then advances the iterator.
    pub fn copy_page_to_iter(page: &PageRef, iter: &mut IoVecIter) -> Result<usize> {
        if !page.is_valid() {
            return Err(Error::InvalidArgument);
        }
        if iter.is_exhausted() {
            return Ok(0);
        }

        let to_copy = (page.length as usize).min(iter.remaining());
        iter.advance(to_copy)?;
        Ok(to_copy)
    }

    /// Copy data from an I/O iterator to a page-cache page.
    ///
    /// Simulates copying up to `page.length` bytes from the iterator
    /// into the given page.
    pub fn copy_page_from_iter(page: &PageRef, iter: &mut IoVecIter) -> Result<usize> {
        if !page.is_valid() {
            return Err(Error::InvalidArgument);
        }
        if iter.is_exhausted() {
            return Ok(0);
        }

        let to_copy = (page.length as usize).min(iter.remaining());
        iter.advance(to_copy)?;
        Ok(to_copy)
    }

    /// Zero-fill the remainder of a page-cache page.
    ///
    /// Used when a read reaches EOF mid-page.
    pub fn zero_fill_page(_page: &PageRef, _from_offset: u32) -> Result<()> {
        // In a real implementation, this would memset the page
        // from `from_offset` to the end. In our model it is a no-op.
        Ok(())
    }

    /// Copy pages from a page array to an I/O iterator.
    ///
    /// Iterates through `pages`, copying each one into `iter` until
    /// the iterator is exhausted or all pages are processed.
    pub fn copy_pages_to_iter(pages: &[PageRef], iter: &mut IoVecIter) -> Result<usize> {
        let mut total = 0usize;
        for page in pages {
            if iter.is_exhausted() {
                break;
            }
            if !page.is_valid() {
                continue;
            }
            let n = Self::copy_page_to_iter(page, iter)?;
            total += n;
        }
        Ok(total)
    }
}

// ── IoVecIterBuilder ─────────────────────────────────────────────────────────

/// Builder for constructing an [`IoVecIter`] incrementally.
pub struct IoVecIterBuilder {
    /// Segments being built.
    segments: [IoSegment; MAX_SEGMENTS],
    /// Current segment count.
    count: usize,
    /// Iterator type.
    iter_type: IoIterType,
    /// Write direction.
    is_write: bool,
}

impl IoVecIterBuilder {
    /// Create a new builder.
    pub const fn new(iter_type: IoIterType, is_write: bool) -> Self {
        Self {
            segments: [const { IoSegment::empty() }; MAX_SEGMENTS],
            count: 0,
            iter_type,
            is_write,
        }
    }

    /// Add a segment to the builder.
    pub fn add_segment(&mut self, base: usize, length: usize) -> Result<&mut Self> {
        if self.count >= MAX_SEGMENTS {
            return Err(Error::OutOfMemory);
        }
        if length == 0 {
            return Err(Error::InvalidArgument);
        }
        if length > MAX_SEGMENT_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.segments[self.count] = IoSegment::new(base, length);
        self.count += 1;
        Ok(self)
    }

    /// Build the final [`IoVecIter`].
    pub fn build(&self) -> Result<IoVecIter> {
        if self.count == 0 {
            return Err(Error::InvalidArgument);
        }
        IoVecIter::new(&self.segments[..self.count], self.iter_type, self.is_write)
    }

    /// Current number of segments.
    pub fn segment_count(&self) -> usize {
        self.count
    }
}

// ── Generic read_iter / write_iter helpers ───────────────────────────────────

/// Perform a generic read through an I/O iterator by invoking a page-based
/// read callback for each page-aligned chunk.
///
/// The `read_page` closure receives (file_offset, page_index) and should
/// return a [`PageRef`] describing the data that was read.
pub fn generic_read_iter<F>(
    iter: &mut IoVecIter,
    file_offset: u64,
    file_size: u64,
    mut read_page: F,
) -> Result<RwIterResult>
where
    F: FnMut(u64, usize) -> Result<PageRef>,
{
    if file_offset >= file_size {
        return Ok(RwIterResult::eof(0, file_offset));
    }

    let available = (file_size - file_offset) as usize;
    let to_read = iter.remaining().min(available);
    let mut transferred = 0usize;
    let mut off = file_offset;
    let mut page_idx = 0usize;

    while transferred < to_read && !iter.is_exhausted() {
        let page = read_page(off, page_idx)?;
        let n = PageIterOps::copy_page_to_iter(&page, iter)?;
        if n == 0 {
            break;
        }
        transferred += n;
        off += n as u64;
        page_idx += 1;
    }

    let eof = off >= file_size;
    Ok(RwIterResult {
        bytes_transferred: transferred,
        new_offset: off,
        eof,
        short_transfer: transferred < iter.remaining() + transferred,
    })
}

/// Perform a generic write through an I/O iterator by invoking a page-based
/// write callback for each page-aligned chunk.
///
/// The `write_page` closure receives (file_offset, page_index, byte_count)
/// and should return the number of bytes actually written.
pub fn generic_write_iter<F>(
    iter: &mut IoVecIter,
    file_offset: u64,
    max_size: u64,
    mut write_page: F,
) -> Result<RwIterResult>
where
    F: FnMut(u64, usize, usize) -> Result<usize>,
{
    if file_offset >= max_size {
        return Err(Error::InvalidArgument);
    }

    let capacity = (max_size - file_offset) as usize;
    let to_write = iter.remaining().min(capacity);
    let mut transferred = 0usize;
    let mut off = file_offset;
    let mut page_idx = 0usize;

    while transferred < to_write && !iter.is_exhausted() {
        let chunk = iter.current_available().min(to_write - transferred);
        if chunk == 0 {
            break;
        }
        let n = write_page(off, page_idx, chunk)?;
        if n == 0 {
            break;
        }
        iter.advance(n)?;
        transferred += n;
        off += n as u64;
        page_idx += 1;
    }

    Ok(RwIterResult {
        bytes_transferred: transferred,
        new_offset: off,
        eof: false,
        short_transfer: transferred < to_write,
    })
}
