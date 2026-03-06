// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Direct I/O bypass layer for the VFS page cache.
//!
//! When a file is opened with `O_DIRECT`, read and write operations bypass
//! the page cache and transfer data directly between user buffers and the
//! block device. This reduces memory pressure and CPU overhead for workloads
//! that manage their own caching (e.g., databases).
//!
//! # Architecture
//!
//! ```text
//! VFS read/write with O_DIRECT
//!   → DirectIo::check_alignment()
//!     → if aligned: submit BioRequest directly
//!       → BlockDevice::submit_bio()
//!         → DMA transfer (page pinned)
//!           → complete → return to caller
//!     → if misaligned: fall back to buffered I/O
//!       → page cache read/write path
//! ```
//!
//! # Structures
//!
//! - [`DirectIoFlags`] — O_DIRECT and related open flags
//! - [`AlignmentReq`] — sector alignment requirements for a block device
//! - [`IoVec`] — scatter-gather I/O vector element
//! - [`IoVecTable`] — collection of I/O vectors for scatter-gather
//! - [`BioOp`] — block I/O operation type (Read/Write/Flush/Discard)
//! - [`BioRequest`] — block I/O request descriptor
//! - [`BioQueue`] — submission queue for BIO requests
//! - [`PinnedPage`] — page pinned for DMA transfer
//! - [`PinTable`] — table of pinned pages
//! - [`DirectIo`] — main direct I/O engine

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Default sector size in bytes (512 bytes, standard for most block devices).
const DEFAULT_SECTOR_SIZE: u32 = 512;

/// Page size in bytes (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Maximum number of I/O vectors in a single scatter-gather request.
const MAX_IO_VECS: usize = 64;

/// Maximum number of pending BIO requests in the submission queue.
const MAX_BIO_QUEUE: usize = 32;

/// Maximum number of simultaneously pinned pages for DMA.
const MAX_PINNED_PAGES: usize = 128;

/// Maximum size of a single direct I/O transfer (1 MiB).
const MAX_DIRECT_IO_SIZE: usize = 1024 * 1024;

/// O_DIRECT flag value (matches Linux kernel convention).
pub const O_DIRECT: u32 = 0o40000;

/// O_SYNC flag value (request synchronous I/O completion).
pub const O_SYNC: u32 = 0o4010000;

/// O_DSYNC flag value (synchronize data only, not metadata).
pub const O_DSYNC: u32 = 0o10000;

// ── DirectIoFlags ───────────────────────────────────────────────

/// Open flags relevant to direct I/O decisions.
///
/// Tracks whether O_DIRECT, O_SYNC, and O_DSYNC are set on a file
/// descriptor, controlling the I/O path selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectIoFlags {
    /// Raw flags value.
    flags: u32,
}

impl DirectIoFlags {
    /// Create flags from a raw open flags value.
    pub const fn from_raw(flags: u32) -> Self {
        Self { flags }
    }

    /// Check if O_DIRECT is set.
    pub fn is_direct(self) -> bool {
        self.flags & O_DIRECT != 0
    }

    /// Check if O_SYNC is set.
    pub fn is_sync(self) -> bool {
        self.flags & O_SYNC == O_SYNC
    }

    /// Check if O_DSYNC is set.
    pub fn is_dsync(self) -> bool {
        self.flags & O_DSYNC != 0
    }

    /// Check if any synchronous flag is set.
    pub fn needs_sync(self) -> bool {
        self.is_sync() || self.is_dsync()
    }

    /// Get the raw flags value.
    pub fn raw(self) -> u32 {
        self.flags
    }
}

// ── AlignmentReq ────────────────────────────────────────────────

/// Alignment requirements for direct I/O on a block device.
///
/// For direct I/O to succeed, the file offset, buffer address, and
/// transfer size must all be aligned to the device's sector boundary.
#[derive(Debug, Clone, Copy)]
pub struct AlignmentReq {
    /// Sector size in bytes (must be a power of 2).
    pub sector_size: u32,
    /// Minimum transfer alignment (may differ from sector_size on some devices).
    pub transfer_align: u32,
    /// Whether the device supports DMA.
    pub dma_capable: bool,
}

impl AlignmentReq {
    /// Create alignment requirements with the given sector size.
    pub const fn new(sector_size: u32) -> Self {
        Self {
            sector_size,
            transfer_align: sector_size,
            dma_capable: true,
        }
    }

    /// Create default alignment requirements (512-byte sectors).
    pub const fn default_512() -> Self {
        Self::new(DEFAULT_SECTOR_SIZE)
    }

    /// Check if a value is aligned to the sector boundary.
    pub fn is_sector_aligned(self, value: u64) -> bool {
        if self.sector_size == 0 {
            return false;
        }
        value % self.sector_size as u64 == 0
    }

    /// Check if a transfer size is aligned.
    pub fn is_size_aligned(self, size: usize) -> bool {
        if self.transfer_align == 0 {
            return false;
        }
        size % self.transfer_align as usize == 0
    }

    /// Check if an address is aligned for DMA.
    pub fn is_addr_aligned(self, addr: usize) -> bool {
        if self.transfer_align == 0 {
            return false;
        }
        addr % self.transfer_align as usize == 0
    }

    /// Validate all alignment requirements for a direct I/O request.
    ///
    /// Checks that the file offset, buffer address, and transfer size
    /// are all properly aligned.
    pub fn validate(self, file_offset: u64, buf_addr: usize, size: usize) -> Result<()> {
        if !self.is_sector_aligned(file_offset) {
            return Err(Error::InvalidArgument);
        }
        if !self.is_addr_aligned(buf_addr) {
            return Err(Error::InvalidArgument);
        }
        if !self.is_size_aligned(size) {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Round a size up to the next sector boundary.
    pub fn align_up(self, size: usize) -> usize {
        if self.sector_size == 0 {
            return size;
        }
        let mask = self.sector_size as usize - 1;
        (size + mask) & !mask
    }
}

// ── IoVec ───────────────────────────────────────────────────────

/// A single I/O vector for scatter-gather operations.
///
/// Describes a contiguous region of memory participating in a
/// vectored I/O transfer. The address is a virtual address that
/// must be pinned before DMA.
#[derive(Debug, Clone, Copy)]
pub struct IoVec {
    /// Virtual address of the buffer.
    pub base: usize,
    /// Length of the buffer in bytes.
    pub len: usize,
}

impl IoVec {
    /// Create a new I/O vector.
    pub const fn new(base: usize, len: usize) -> Self {
        Self { base, len }
    }

    /// Create an empty (zero-length) I/O vector.
    pub const fn empty() -> Self {
        Self { base: 0, len: 0 }
    }

    /// Check if this vector is empty.
    pub fn is_empty(self) -> bool {
        self.len == 0
    }
}

// ── IoVecTable ──────────────────────────────────────────────────

/// Collection of I/O vectors for scatter-gather DMA.
///
/// Allows a single I/O operation to touch multiple non-contiguous
/// memory regions, reducing syscall overhead for databases and
/// network file servers that maintain their own buffer pools.
pub struct IoVecTable {
    /// I/O vector entries.
    vecs: [IoVec; MAX_IO_VECS],
    /// Number of valid entries.
    count: usize,
    /// Total bytes across all vectors.
    total_bytes: usize,
}

impl IoVecTable {
    /// Create a new, empty I/O vector table.
    pub const fn new() -> Self {
        Self {
            vecs: [IoVec::empty(); MAX_IO_VECS],
            count: 0,
            total_bytes: 0,
        }
    }

    /// Add an I/O vector to the table.
    pub fn push(&mut self, iov: IoVec) -> Result<()> {
        if self.count >= MAX_IO_VECS {
            return Err(Error::OutOfMemory);
        }
        if iov.is_empty() {
            return Ok(());
        }
        self.vecs[self.count] = iov;
        self.total_bytes += iov.len;
        self.count += 1;
        Ok(())
    }

    /// Get the number of vectors.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Get total bytes across all vectors.
    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Get a vector by index.
    pub fn get(&self, index: usize) -> Result<&IoVec> {
        if index >= self.count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.vecs[index])
    }

    /// Validate that all vectors meet alignment requirements.
    pub fn validate_alignment(&self, align: &AlignmentReq) -> Result<()> {
        let mut i = 0;
        while i < self.count {
            if !align.is_addr_aligned(self.vecs[i].base) {
                return Err(Error::InvalidArgument);
            }
            if !align.is_size_aligned(self.vecs[i].len) {
                return Err(Error::InvalidArgument);
            }
            i += 1;
        }
        Ok(())
    }

    /// Reset the table, removing all vectors.
    pub fn clear(&mut self) {
        self.count = 0;
        self.total_bytes = 0;
    }
}

// ── BioOp ───────────────────────────────────────────────────────

/// Block I/O operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BioOp {
    /// Read from block device.
    Read,
    /// Write to block device.
    Write,
    /// Flush device write cache.
    Flush,
    /// Discard (TRIM) block range.
    Discard,
}

// ── BioStatus ───────────────────────────────────────────────────

/// Status of a block I/O request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BioStatus {
    /// Request is pending submission.
    Pending,
    /// Request has been submitted to the device.
    Submitted,
    /// Request completed successfully.
    Complete,
    /// Request failed with an error.
    Error,
}

// ── BioRequest ──────────────────────────────────────────────────

/// Block I/O request descriptor.
///
/// Represents a single request to transfer data between memory and
/// a block device. Used by the direct I/O path to bypass the page cache.
#[derive(Debug, Clone)]
pub struct BioRequest {
    /// Operation type (read, write, flush, discard).
    pub op: BioOp,
    /// Block device identifier.
    pub device_id: u32,
    /// Starting sector on the block device.
    pub sector: u64,
    /// Number of sectors to transfer.
    pub sector_count: u32,
    /// Virtual address of the data buffer (must be pinned for DMA).
    pub buf_addr: usize,
    /// Size of the data buffer in bytes.
    pub buf_size: usize,
    /// Current status of this request.
    pub status: BioStatus,
    /// Bytes actually transferred (set on completion).
    pub bytes_done: usize,
    /// Unique request identifier for tracking.
    pub request_id: u64,
}

impl BioRequest {
    /// Create a new BIO request.
    pub const fn new(
        op: BioOp,
        device_id: u32,
        sector: u64,
        sector_count: u32,
        buf_addr: usize,
        buf_size: usize,
        request_id: u64,
    ) -> Self {
        Self {
            op,
            device_id,
            sector,
            sector_count,
            buf_addr,
            buf_size,
            status: BioStatus::Pending,
            bytes_done: 0,
            request_id,
        }
    }

    /// Create an empty (invalid) BIO request.
    const fn empty() -> Self {
        Self {
            op: BioOp::Read,
            device_id: 0,
            sector: 0,
            sector_count: 0,
            buf_addr: 0,
            buf_size: 0,
            status: BioStatus::Pending,
            bytes_done: 0,
            request_id: 0,
        }
    }

    /// Mark this request as submitted.
    pub fn submit(&mut self) {
        self.status = BioStatus::Submitted;
    }

    /// Mark this request as completed.
    pub fn complete(&mut self, bytes: usize) {
        self.status = BioStatus::Complete;
        self.bytes_done = bytes;
    }

    /// Mark this request as failed.
    pub fn fail(&mut self) {
        self.status = BioStatus::Error;
    }

    /// Check if this request has finished (completed or errored).
    pub fn is_done(&self) -> bool {
        matches!(self.status, BioStatus::Complete | BioStatus::Error)
    }
}

// ── BioQueue ────────────────────────────────────────────────────

/// Submission queue for block I/O requests.
///
/// Holds pending BIO requests before they are dispatched to the block
/// device driver. Implements a simple ring buffer with FIFO ordering.
pub struct BioQueue {
    /// Request slots.
    requests: [BioRequest; MAX_BIO_QUEUE],
    /// Number of valid requests in the queue.
    count: usize,
    /// Next request ID to assign.
    next_id: u64,
}

impl BioQueue {
    /// Create a new, empty BIO queue.
    pub const fn new() -> Self {
        Self {
            requests: [const { BioRequest::empty() }; MAX_BIO_QUEUE],
            count: 0,
            next_id: 1,
        }
    }

    /// Enqueue a new BIO request.
    ///
    /// Returns the assigned request ID.
    pub fn enqueue(
        &mut self,
        op: BioOp,
        device_id: u32,
        sector: u64,
        sector_count: u32,
        buf_addr: usize,
        buf_size: usize,
    ) -> Result<u64> {
        if self.count >= MAX_BIO_QUEUE {
            return Err(Error::WouldBlock);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.requests[self.count] =
            BioRequest::new(op, device_id, sector, sector_count, buf_addr, buf_size, id);
        self.count += 1;
        Ok(id)
    }

    /// Dequeue the next pending request.
    ///
    /// Returns `None` if the queue is empty.
    pub fn dequeue(&mut self) -> Option<BioRequest> {
        if self.count == 0 {
            return None;
        }
        let req = self.requests[0].clone();
        // Shift remaining entries.
        let mut i = 1;
        while i < self.count {
            self.requests[i - 1] = self.requests[i].clone();
            i += 1;
        }
        self.count -= 1;
        Some(req)
    }

    /// Get the number of pending requests.
    pub fn pending(&self) -> usize {
        self.count
    }

    /// Check if the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check if the queue is full.
    pub fn is_full(&self) -> bool {
        self.count >= MAX_BIO_QUEUE
    }

    /// Find a request by ID and mark it as completed.
    ///
    /// Returns `NotFound` if the request is not in the queue.
    pub fn complete_request(&mut self, request_id: u64, bytes: usize) -> Result<()> {
        let mut i = 0;
        while i < self.count {
            if self.requests[i].request_id == request_id {
                self.requests[i].complete(bytes);
                return Ok(());
            }
            i += 1;
        }
        Err(Error::NotFound)
    }

    /// Drain all completed requests from the queue.
    ///
    /// Returns the number of requests drained.
    pub fn drain_completed(&mut self) -> usize {
        let mut write = 0;
        let mut drained = 0;
        let mut read = 0;
        while read < self.count {
            if self.requests[read].is_done() {
                drained += 1;
            } else {
                if write != read {
                    self.requests[write] = self.requests[read].clone();
                }
                write += 1;
            }
            read += 1;
        }
        self.count = write;
        drained
    }
}

// ── PinnedPage ──────────────────────────────────────────────────

/// A page pinned in physical memory for DMA transfer.
///
/// When performing direct I/O, the user buffer pages must be pinned
/// to prevent the page fault handler from moving them during DMA.
#[derive(Debug, Clone, Copy)]
pub struct PinnedPage {
    /// Virtual address of the pinned page.
    pub virt_addr: usize,
    /// Physical address for DMA programming.
    pub phys_addr: u64,
    /// Whether this slot is in use.
    pub in_use: bool,
    /// Reference count (multiple BIO requests may share a pinned page).
    pub ref_count: u32,
}

impl PinnedPage {
    /// Create an empty (unused) pinned page slot.
    const fn empty() -> Self {
        Self {
            virt_addr: 0,
            phys_addr: 0,
            in_use: false,
            ref_count: 0,
        }
    }
}

// ── PinTable ────────────────────────────────────────────────────

/// Table of pinned pages for DMA transfers.
///
/// Tracks pages that have been pinned for direct I/O. Pages are
/// pinned before DMA begins and unpinned after all transfers complete.
pub struct PinTable {
    /// Pinned page slots.
    pages: [PinnedPage; MAX_PINNED_PAGES],
    /// Number of pinned pages.
    count: usize,
}

impl PinTable {
    /// Create a new, empty pin table.
    pub const fn new() -> Self {
        Self {
            pages: [PinnedPage::empty(); MAX_PINNED_PAGES],
            count: 0,
        }
    }

    /// Pin a page at the given virtual address.
    ///
    /// `phys_addr` is the physical address obtained from the page table.
    /// Returns the slot index.
    pub fn pin(&mut self, virt_addr: usize, phys_addr: u64) -> Result<usize> {
        // Check if already pinned.
        let mut i = 0;
        while i < MAX_PINNED_PAGES {
            if self.pages[i].in_use && self.pages[i].virt_addr == virt_addr {
                self.pages[i].ref_count += 1;
                return Ok(i);
            }
            i += 1;
        }
        // Find a free slot.
        i = 0;
        while i < MAX_PINNED_PAGES {
            if !self.pages[i].in_use {
                self.pages[i] = PinnedPage {
                    virt_addr,
                    phys_addr,
                    in_use: true,
                    ref_count: 1,
                };
                self.count += 1;
                return Ok(i);
            }
            i += 1;
        }
        Err(Error::OutOfMemory)
    }

    /// Unpin a page by slot index.
    ///
    /// Decrements the reference count. The page is freed when the
    /// count reaches zero.
    pub fn unpin(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_PINNED_PAGES || !self.pages[slot].in_use {
            return Err(Error::NotFound);
        }
        self.pages[slot].ref_count = self.pages[slot].ref_count.saturating_sub(1);
        if self.pages[slot].ref_count == 0 {
            self.pages[slot].in_use = false;
            self.pages[slot].virt_addr = 0;
            self.pages[slot].phys_addr = 0;
            self.count = self.count.saturating_sub(1);
        }
        Ok(())
    }

    /// Unpin a page by virtual address.
    pub fn unpin_by_addr(&mut self, virt_addr: usize) -> Result<()> {
        let mut i = 0;
        while i < MAX_PINNED_PAGES {
            if self.pages[i].in_use && self.pages[i].virt_addr == virt_addr {
                return self.unpin(i);
            }
            i += 1;
        }
        Err(Error::NotFound)
    }

    /// Look up the physical address for a pinned virtual address.
    pub fn lookup_phys(&self, virt_addr: usize) -> Result<u64> {
        let mut i = 0;
        while i < MAX_PINNED_PAGES {
            if self.pages[i].in_use && self.pages[i].virt_addr == virt_addr {
                return Ok(self.pages[i].phys_addr);
            }
            i += 1;
        }
        Err(Error::NotFound)
    }

    /// Get the number of pinned pages.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Unpin all pages (e.g., on I/O completion or error cleanup).
    pub fn unpin_all(&mut self) {
        let mut i = 0;
        while i < MAX_PINNED_PAGES {
            self.pages[i] = PinnedPage::empty();
            i += 1;
        }
        self.count = 0;
    }
}

// ── DirectIo ────────────────────────────────────────────────────

/// Direct I/O engine.
///
/// Manages the direct I/O path for files opened with `O_DIRECT`.
/// Handles alignment validation, BIO request construction, page
/// pinning, and fallback to buffered I/O on misalignment.
pub struct DirectIo {
    /// Block device alignment requirements.
    align: AlignmentReq,
    /// BIO submission queue.
    bio_queue: BioQueue,
    /// Pinned page table.
    pin_table: PinTable,
    /// I/O vector table for scatter-gather.
    iov_table: IoVecTable,
    /// Block device identifier.
    device_id: u32,
    /// Total bytes transferred (for statistics).
    bytes_transferred: u64,
    /// Total direct I/O requests served.
    direct_count: u64,
    /// Total fallback-to-buffered requests.
    fallback_count: u64,
}

impl DirectIo {
    /// Create a new direct I/O engine for the given device.
    pub const fn new(device_id: u32, align: AlignmentReq) -> Self {
        Self {
            align,
            bio_queue: BioQueue::new(),
            pin_table: PinTable::new(),
            iov_table: IoVecTable::new(),
            device_id,
            bytes_transferred: 0,
            direct_count: 0,
            fallback_count: 0,
        }
    }

    /// Create a direct I/O engine with default 512-byte sector alignment.
    pub const fn with_defaults(device_id: u32) -> Self {
        Self::new(device_id, AlignmentReq::default_512())
    }

    /// Check whether a request can use the direct I/O path.
    ///
    /// Returns `Ok(true)` if aligned, `Ok(false)` if fallback needed.
    pub fn check_alignment(&self, file_offset: u64, buf_addr: usize, size: usize) -> bool {
        self.align.is_sector_aligned(file_offset)
            && self.align.is_addr_aligned(buf_addr)
            && self.align.is_size_aligned(size)
    }

    /// Submit a direct read request.
    ///
    /// The buffer at `buf_addr` must be sector-aligned and the pages
    /// must be pinned before calling this function.
    ///
    /// Returns the BIO request ID on success, or falls back to
    /// `Err(Error::InvalidArgument)` if alignment fails.
    pub fn submit_read(&mut self, file_offset: u64, buf_addr: usize, size: usize) -> Result<u64> {
        if size > MAX_DIRECT_IO_SIZE {
            return Err(Error::InvalidArgument);
        }
        if !self.check_alignment(file_offset, buf_addr, size) {
            self.fallback_count += 1;
            return Err(Error::InvalidArgument);
        }
        let sector = file_offset / self.align.sector_size as u64;
        let sector_count = (size as u64 / self.align.sector_size as u64) as u32;
        let id = self.bio_queue.enqueue(
            BioOp::Read,
            self.device_id,
            sector,
            sector_count,
            buf_addr,
            size,
        )?;
        self.direct_count += 1;
        Ok(id)
    }

    /// Submit a direct write request.
    ///
    /// Same alignment requirements as [`submit_read`](Self::submit_read).
    pub fn submit_write(&mut self, file_offset: u64, buf_addr: usize, size: usize) -> Result<u64> {
        if size > MAX_DIRECT_IO_SIZE {
            return Err(Error::InvalidArgument);
        }
        if !self.check_alignment(file_offset, buf_addr, size) {
            self.fallback_count += 1;
            return Err(Error::InvalidArgument);
        }
        let sector = file_offset / self.align.sector_size as u64;
        let sector_count = (size as u64 / self.align.sector_size as u64) as u32;
        let id = self.bio_queue.enqueue(
            BioOp::Write,
            self.device_id,
            sector,
            sector_count,
            buf_addr,
            size,
        )?;
        self.direct_count += 1;
        Ok(id)
    }

    /// Submit a scatter-gather direct read using an I/O vector table.
    ///
    /// All vectors in the table must meet alignment requirements.
    pub fn submit_readv(&mut self, file_offset: u64, iovecs: &IoVecTable) -> Result<u64> {
        if iovecs.total_bytes() > MAX_DIRECT_IO_SIZE {
            return Err(Error::InvalidArgument);
        }
        if !self.align.is_sector_aligned(file_offset) {
            self.fallback_count += 1;
            return Err(Error::InvalidArgument);
        }
        iovecs.validate_alignment(&self.align)?;
        // Submit one BIO per vector segment.
        let mut offset = file_offset;
        let mut last_id = 0u64;
        let mut i = 0;
        while i < iovecs.count() {
            let iov = iovecs.get(i)?;
            let sector = offset / self.align.sector_size as u64;
            let sector_count = (iov.len as u64 / self.align.sector_size as u64) as u32;
            last_id = self.bio_queue.enqueue(
                BioOp::Read,
                self.device_id,
                sector,
                sector_count,
                iov.base,
                iov.len,
            )?;
            offset += iov.len as u64;
            i += 1;
        }
        self.direct_count += 1;
        Ok(last_id)
    }

    /// Submit a scatter-gather direct write using an I/O vector table.
    pub fn submit_writev(&mut self, file_offset: u64, iovecs: &IoVecTable) -> Result<u64> {
        if iovecs.total_bytes() > MAX_DIRECT_IO_SIZE {
            return Err(Error::InvalidArgument);
        }
        if !self.align.is_sector_aligned(file_offset) {
            self.fallback_count += 1;
            return Err(Error::InvalidArgument);
        }
        iovecs.validate_alignment(&self.align)?;
        let mut offset = file_offset;
        let mut last_id = 0u64;
        let mut i = 0;
        while i < iovecs.count() {
            let iov = iovecs.get(i)?;
            let sector = offset / self.align.sector_size as u64;
            let sector_count = (iov.len as u64 / self.align.sector_size as u64) as u32;
            last_id = self.bio_queue.enqueue(
                BioOp::Write,
                self.device_id,
                sector,
                sector_count,
                iov.base,
                iov.len,
            )?;
            offset += iov.len as u64;
            i += 1;
        }
        self.direct_count += 1;
        Ok(last_id)
    }

    /// Submit a cache flush (write barrier) to the device.
    pub fn submit_flush(&mut self) -> Result<u64> {
        self.bio_queue
            .enqueue(BioOp::Flush, self.device_id, 0, 0, 0, 0)
    }

    /// Pin pages for a buffer range before DMA.
    ///
    /// `virt_addr` is the start of the user buffer. `size` is the transfer
    /// length. `phys_addrs` provides the physical address for each page
    /// (one per PAGE_SIZE-aligned page in the range).
    pub fn pin_pages(&mut self, virt_addr: usize, size: usize, phys_addrs: &[u64]) -> Result<()> {
        let page_start = virt_addr & !(PAGE_SIZE - 1);
        let page_end = (virt_addr + size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let num_pages = (page_end - page_start) / PAGE_SIZE;
        if phys_addrs.len() < num_pages {
            return Err(Error::InvalidArgument);
        }
        let mut i = 0;
        while i < num_pages {
            let va = page_start + i * PAGE_SIZE;
            self.pin_table.pin(va, phys_addrs[i])?;
            i += 1;
        }
        Ok(())
    }

    /// Unpin pages after DMA completes.
    pub fn unpin_pages(&mut self, virt_addr: usize, size: usize) -> Result<()> {
        let page_start = virt_addr & !(PAGE_SIZE - 1);
        let page_end = (virt_addr + size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let num_pages = (page_end - page_start) / PAGE_SIZE;
        let mut i = 0;
        while i < num_pages {
            let va = page_start + i * PAGE_SIZE;
            // Ignore errors for pages that may already have been unpinned.
            let _ = self.pin_table.unpin_by_addr(va);
            i += 1;
        }
        Ok(())
    }

    /// Process the next pending BIO request from the queue.
    ///
    /// Returns the request if one is available, or `None` if the queue
    /// is empty. The caller is responsible for dispatching the request
    /// to the block device driver.
    pub fn next_request(&mut self) -> Option<BioRequest> {
        self.bio_queue.dequeue()
    }

    /// Mark a request as completed and update statistics.
    pub fn complete_request(&mut self, request_id: u64, bytes: usize) -> Result<()> {
        self.bio_queue.complete_request(request_id, bytes)?;
        self.bytes_transferred += bytes as u64;
        Ok(())
    }

    /// Drain completed requests from the queue.
    pub fn drain_completed(&mut self) -> usize {
        self.bio_queue.drain_completed()
    }

    /// Get the alignment requirements.
    pub fn alignment(&self) -> &AlignmentReq {
        &self.align
    }

    /// Get the number of pending BIO requests.
    pub fn pending_requests(&self) -> usize {
        self.bio_queue.pending()
    }

    /// Get the number of pinned pages.
    pub fn pinned_pages(&self) -> usize {
        self.pin_table.count()
    }

    /// Get total bytes transferred via direct I/O.
    pub fn bytes_transferred(&self) -> u64 {
        self.bytes_transferred
    }

    /// Get the number of direct I/O requests served.
    pub fn direct_count(&self) -> u64 {
        self.direct_count
    }

    /// Get the number of fallback-to-buffered requests.
    pub fn fallback_count(&self) -> u64 {
        self.fallback_count
    }

    /// Get a mutable reference to the I/O vector table.
    pub fn iov_table_mut(&mut self) -> &mut IoVecTable {
        &mut self.iov_table
    }

    /// Release all resources (unpin pages, drain queue).
    pub fn cleanup(&mut self) {
        self.pin_table.unpin_all();
        while self.bio_queue.dequeue().is_some() {}
        self.iov_table.clear();
    }
}
