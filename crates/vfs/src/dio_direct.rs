// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Direct I/O — `O_DIRECT` bypass of the page cache.
//!
//! When a file is opened with `O_DIRECT`, read and write operations bypass the
//! kernel page cache and transfer data directly between the caller's buffer and
//! the block device.  This module implements the alignment validation, batch
//! submission, and completion tracking required for direct I/O.
//!
//! # Alignment requirements
//!
//! POSIX.1-2024 §open requires that `O_DIRECT` transfers satisfy three alignment
//! constraints simultaneously:
//!
//! 1. The file `offset` must be a multiple of the filesystem logical block size.
//! 2. The transfer `length` must be a multiple of the same block size.
//! 3. The user-space `buffer_addr` must be aligned to the block size.
//!
//! # Architecture
//!
//! ```text
//! do_direct_io(file_id, offset, buf, len, direction)
//!   │
//!   ├── check_alignment(offset, len, buffer_addr, &align)
//!   ├── DioSubmission::submit(request)
//!   │     └── 64-entry batch, returns token
//!   └── DioSubmission::complete(token) → bytes transferred
//! ```
//!
//! # References
//!
//! - Linux `fs/direct-io.c`, `include/linux/fs.h` (`kiocb`, `iov_iter`)
//! - POSIX.1-2024 `open(3)` (`O_DIRECT`)
//! - `man 2 pread`, `man 2 pwrite`

use oncrix_lib::{Error, Result};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum number of in-flight DIO submissions across all [`DirectIoSubsystem`] instances.
pub const MAX_DIO_SUBMISSIONS: usize = 16;

/// Batch size — number of requests that can be queued in a single [`DioSubmission`].
pub const DIO_BATCH_SIZE: usize = 64;

/// Default logical block size used when no filesystem-specific value is provided.
pub const DEFAULT_BLOCK_SIZE: u32 = 512;

/// Maximum single-transfer size for direct I/O (512 MiB).
pub const MAX_DIO_SIZE: u64 = 512 * 1024 * 1024;

// ── DioDirection ─────────────────────────────────────────────────────────────

/// Direction of a direct I/O transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DioDirection {
    /// Transfer data from block device into the user buffer.
    Read,
    /// Transfer data from the user buffer to the block device.
    Write,
}

// ── DioAlignment ─────────────────────────────────────────────────────────────

/// Alignment constraints for direct I/O on a particular file/device.
#[derive(Debug, Clone, Copy)]
pub struct DioAlignment {
    /// Minimum required alignment for offset, length, and buffer (in bytes).
    /// Must be a power of two.
    pub block_size: u32,
    /// Minimum transfer size (may equal `block_size`).
    pub min_io_size: u32,
    /// Optimal transfer size for throughput (may be a larger multiple).
    pub optimal_io_size: u32,
}

impl Default for DioAlignment {
    fn default() -> Self {
        Self {
            block_size: DEFAULT_BLOCK_SIZE,
            min_io_size: DEFAULT_BLOCK_SIZE,
            optimal_io_size: DEFAULT_BLOCK_SIZE * 8,
        }
    }
}

impl DioAlignment {
    /// Construct alignment info for a device with the given `block_size`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `block_size` is zero or not a power of two.
    pub fn new(block_size: u32) -> Result<Self> {
        if block_size == 0 || !block_size.is_power_of_two() {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            block_size,
            min_io_size: block_size,
            optimal_io_size: block_size * 8,
        })
    }

    /// Return `true` when `value` is aligned to `block_size`.
    pub fn is_aligned_u64(&self, value: u64) -> bool {
        (value & (self.block_size as u64 - 1)) == 0
    }

    /// Return `true` when a pointer-sized `addr` is aligned to `block_size`.
    pub fn is_aligned_usize(&self, addr: usize) -> bool {
        (addr & (self.block_size as usize - 1)) == 0
    }
}

// ── DioRequest ───────────────────────────────────────────────────────────────

/// A single direct I/O request.
#[derive(Debug, Clone, Copy)]
pub struct DioRequest {
    /// File identifier (fd or internal file id).
    pub file_id: u64,
    /// Byte offset in the file from which to read or write.
    pub offset: u64,
    /// Number of bytes to transfer.
    pub length: u64,
    /// Transfer direction.
    pub direction: DioDirection,
    /// User-space (or kernel) buffer address.  Must be aligned per [`DioAlignment`].
    pub buffer_addr: usize,
}

impl DioRequest {
    /// Validate that this request satisfies the given alignment constraints.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] on any alignment failure.
    pub fn check_alignment(&self, align: &DioAlignment) -> Result<()> {
        if !align.is_aligned_u64(self.offset) {
            return Err(Error::InvalidArgument);
        }
        if !align.is_aligned_u64(self.length) {
            return Err(Error::InvalidArgument);
        }
        if !align.is_aligned_usize(self.buffer_addr) {
            return Err(Error::InvalidArgument);
        }
        if self.length == 0 || self.length > MAX_DIO_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ── DioState ─────────────────────────────────────────────────────────────────

/// Per-file direct I/O state counters.
#[derive(Debug, Clone, Copy, Default)]
pub struct DioState {
    /// Number of requests currently in flight.
    pub in_flight_count: u32,
    /// Number of requests that have completed successfully.
    pub completed_count: u64,
    /// Number of requests that completed with an error.
    pub error_count: u64,
}

impl DioState {
    /// Construct zeroed state.
    pub const fn new() -> Self {
        Self {
            in_flight_count: 0,
            completed_count: 0,
            error_count: 0,
        }
    }
}

// ── DioToken ─────────────────────────────────────────────────────────────────

/// Opaque token returned by [`DioSubmission::submit`], used to poll for completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DioToken(pub u32);

// ── BatchEntry ───────────────────────────────────────────────────────────────

/// One slot in the submission batch ring.
#[derive(Clone, Copy)]
struct BatchEntry {
    /// The queued request.
    request: DioRequest,
    /// Token that was assigned to this slot.
    token: DioToken,
    /// Whether this slot contains an active request.
    active: bool,
    /// Whether the request has been "completed" (stub: always immediate).
    completed: bool,
    /// Simulated transfer result (bytes).
    result: u64,
}

impl Default for BatchEntry {
    fn default() -> Self {
        Self {
            request: DioRequest {
                file_id: 0,
                offset: 0,
                length: 0,
                direction: DioDirection::Read,
                buffer_addr: 0,
            },
            token: DioToken(0),
            active: false,
            completed: false,
            result: 0,
        }
    }
}

// ── DioSubmission ─────────────────────────────────────────────────────────────

/// A 64-entry batch queue for direct I/O requests.
///
/// In a real kernel this would interface with the block layer's `bio` machinery.
/// Here we provide a synchronous stub that marks requests as immediately completed.
pub struct DioSubmission {
    /// The ring buffer of batch entries.
    entries: [BatchEntry; DIO_BATCH_SIZE],
    /// Head index for the ring (next slot to use for submission).
    head: usize,
    /// Monotonically increasing token counter.
    next_token: u32,
    /// Number of slots currently occupied.
    count: usize,
}

impl Default for DioSubmission {
    fn default() -> Self {
        Self::new()
    }
}

impl DioSubmission {
    /// Construct an empty submission queue.
    pub const fn new() -> Self {
        Self {
            entries: [const {
                BatchEntry {
                    request: DioRequest {
                        file_id: 0,
                        offset: 0,
                        length: 0,
                        direction: DioDirection::Read,
                        buffer_addr: 0,
                    },
                    token: DioToken(0),
                    active: false,
                    completed: false,
                    result: 0,
                }
            }; DIO_BATCH_SIZE],
            head: 0,
            next_token: 1,
            count: 0,
        }
    }

    /// Enqueue `request` for direct I/O submission.
    ///
    /// In this stub, the request is immediately "completed" to simulate
    /// synchronous direct I/O semantics.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] when the batch queue is full.
    pub fn submit(&mut self, request: DioRequest) -> Result<DioToken> {
        if self.count >= DIO_BATCH_SIZE {
            return Err(Error::Busy);
        }
        let slot = self.head % DIO_BATCH_SIZE;
        let token = DioToken(self.next_token);
        self.next_token = self.next_token.wrapping_add(1).max(1);
        // Stub: immediately mark as completed with `length` bytes transferred.
        self.entries[slot] = BatchEntry {
            request,
            token,
            active: true,
            completed: true,
            result: request.length,
        };
        self.head = (self.head + 1) % DIO_BATCH_SIZE;
        self.count += 1;
        Ok(token)
    }

    /// Poll a previously submitted token for completion.
    ///
    /// Returns the number of bytes transferred on success.
    ///
    /// # Errors
    ///
    /// - [`Error::WouldBlock`] — the request is still in flight.
    /// - [`Error::NotFound`]   — no request with this token exists.
    pub fn poll(&self, token: DioToken) -> Result<u64> {
        for entry in &self.entries {
            if entry.active && entry.token == token {
                if !entry.completed {
                    return Err(Error::WouldBlock);
                }
                return Ok(entry.result);
            }
        }
        Err(Error::NotFound)
    }

    /// Consume a completed token, freeing the slot.
    ///
    /// Returns the number of bytes transferred.
    ///
    /// # Errors
    ///
    /// - [`Error::WouldBlock`] — the request is still in flight.
    /// - [`Error::NotFound`]   — no request with this token exists.
    pub fn complete(&mut self, token: DioToken) -> Result<u64> {
        let pos = self
            .entries
            .iter()
            .position(|e| e.active && e.token == token)
            .ok_or(Error::NotFound)?;
        if !self.entries[pos].completed {
            return Err(Error::WouldBlock);
        }
        let result = self.entries[pos].result;
        self.entries[pos] = BatchEntry::default();
        self.count = self.count.saturating_sub(1);
        Ok(result)
    }
}

// ── DirectIoSubsystem ─────────────────────────────────────────────────────────

/// The direct I/O subsystem — manages up to [`MAX_DIO_SUBMISSIONS`] active
/// [`DioSubmission`] queues (one per file or stream).
pub struct DirectIoSubsystem {
    /// Pool of submission queues.
    queues: [DioSubmission; MAX_DIO_SUBMISSIONS],
    /// Which queue slots are allocated to an active file.
    queue_active: [bool; MAX_DIO_SUBMISSIONS],
    /// Alignment profile used for validation.
    alignment: DioAlignment,
    /// Accumulated statistics.
    stats: DioStats,
}

impl Default for DirectIoSubsystem {
    fn default() -> Self {
        Self::new(DioAlignment::default())
    }
}

impl DirectIoSubsystem {
    /// Construct a new direct I/O subsystem with the given alignment profile.
    pub fn new(alignment: DioAlignment) -> Self {
        Self {
            queues: [const {
                DioSubmission {
                    entries: [const {
                        BatchEntry {
                            request: DioRequest {
                                file_id: 0,
                                offset: 0,
                                length: 0,
                                direction: DioDirection::Read,
                                buffer_addr: 0,
                            },
                            token: DioToken(0),
                            active: false,
                            completed: false,
                            result: 0,
                        }
                    }; DIO_BATCH_SIZE],
                    head: 0,
                    next_token: 1,
                    count: 0,
                }
            }; MAX_DIO_SUBMISSIONS],
            queue_active: [false; MAX_DIO_SUBMISSIONS],
            alignment,
            stats: DioStats::new(),
        }
    }

    /// Validate alignment for a proposed direct I/O transfer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if any alignment constraint is violated.
    pub fn check_alignment(&mut self, request: &DioRequest) -> Result<()> {
        let result = request.check_alignment(&self.alignment);
        if result.is_err() {
            self.stats.alignment_errors += 1;
        }
        result
    }

    /// Submit a direct I/O request using queue `queue_idx`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — alignment violation.
    /// - [`Error::Busy`]            — the selected queue is full.
    /// - [`Error::NotFound`]        — `queue_idx` is out of range or inactive.
    pub fn submit_dio(&mut self, queue_idx: usize, request: DioRequest) -> Result<DioToken> {
        request.check_alignment(&self.alignment).map_err(|_| {
            self.stats.alignment_errors += 1;
            Error::InvalidArgument
        })?;
        if queue_idx >= MAX_DIO_SUBMISSIONS || !self.queue_active[queue_idx] {
            return Err(Error::NotFound);
        }
        let token = self.queues[queue_idx].submit(request)?;
        match request.direction {
            DioDirection::Read => self.stats.total_reads += 1,
            DioDirection::Write => self.stats.total_writes += 1,
        }
        Ok(token)
    }

    /// Complete a previously submitted request in queue `queue_idx`.
    ///
    /// Updates byte counters in [`DioStats`].
    ///
    /// # Errors
    ///
    /// - [`Error::WouldBlock`] — the request is still in flight.
    /// - [`Error::NotFound`]   — token or queue not found.
    pub fn complete_dio(
        &mut self,
        queue_idx: usize,
        token: DioToken,
        direction: DioDirection,
    ) -> Result<usize> {
        if queue_idx >= MAX_DIO_SUBMISSIONS || !self.queue_active[queue_idx] {
            return Err(Error::NotFound);
        }
        let bytes = self.queues[queue_idx].complete(token)?;
        match direction {
            DioDirection::Read => self.stats.bytes_read += bytes,
            DioDirection::Write => self.stats.bytes_written += bytes,
        }
        Ok(bytes as usize)
    }

    /// Open a new submission queue and return its index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] when all queue slots are in use.
    pub fn open_queue(&mut self) -> Result<usize> {
        let idx = self
            .queue_active
            .iter()
            .position(|&a| !a)
            .ok_or(Error::OutOfMemory)?;
        self.queue_active[idx] = true;
        Ok(idx)
    }

    /// Close a submission queue, releasing its slot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] when `queue_idx` is not active.
    pub fn close_queue(&mut self, queue_idx: usize) -> Result<()> {
        if queue_idx >= MAX_DIO_SUBMISSIONS || !self.queue_active[queue_idx] {
            return Err(Error::NotFound);
        }
        self.queues[queue_idx] = DioSubmission::new();
        self.queue_active[queue_idx] = false;
        Ok(())
    }

    /// Return a reference to accumulated statistics.
    pub fn stats(&self) -> &DioStats {
        &self.stats
    }
}

// ── Top-level entry point ─────────────────────────────────────────────────────

/// Perform a direct I/O transfer for `file_id`.
///
/// This is the primary entry point analogous to `do_direct_io()` in the Linux
/// kernel.  It validates alignment, submits the request, and immediately collects
/// the result (synchronous stub).
///
/// # Parameters
///
/// - `file_id`   — internal file identifier.
/// - `offset`    — byte offset in the file.
/// - `buf`       — user/kernel buffer (address taken for alignment check).
/// - `len`       — number of bytes to transfer.
/// - `direction` — read or write.
/// - `subsys`    — the [`DirectIoSubsystem`] to use.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — alignment violation or `len` is zero / too large.
/// - [`Error::OutOfMemory`]     — no free submission queue.
/// - [`Error::Busy`]            — submission queue is full.
pub fn do_direct_io(
    file_id: u64,
    offset: u64,
    buf: &[u8],
    len: usize,
    direction: DioDirection,
    subsys: &mut DirectIoSubsystem,
) -> Result<usize> {
    let buffer_addr = buf.as_ptr() as usize;
    let request = DioRequest {
        file_id,
        offset,
        length: len as u64,
        direction,
        buffer_addr,
    };
    let qidx = subsys.open_queue()?;
    let token = match subsys.submit_dio(qidx, request) {
        Ok(t) => t,
        Err(e) => {
            let _ = subsys.close_queue(qidx);
            return Err(e);
        }
    };
    let bytes = match subsys.complete_dio(qidx, token, direction) {
        Ok(b) => b,
        Err(e) => {
            let _ = subsys.close_queue(qidx);
            return Err(e);
        }
    };
    subsys.close_queue(qidx)?;
    Ok(bytes)
}

// ── DioStats ─────────────────────────────────────────────────────────────────

/// Cumulative statistics for the direct I/O subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct DioStats {
    /// Total number of direct read operations submitted.
    pub total_reads: u64,
    /// Total number of direct write operations submitted.
    pub total_writes: u64,
    /// Total bytes transferred by direct reads.
    pub bytes_read: u64,
    /// Total bytes transferred by direct writes.
    pub bytes_written: u64,
    /// Number of requests rejected due to alignment violations.
    pub alignment_errors: u64,
}

impl DioStats {
    /// Construct zeroed stats.
    pub const fn new() -> Self {
        Self {
            total_reads: 0,
            total_writes: 0,
            bytes_read: 0,
            bytes_written: 0,
            alignment_errors: 0,
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn aligned_subsystem() -> DirectIoSubsystem {
        DirectIoSubsystem::new(DioAlignment::new(512).unwrap())
    }

    /// Build a properly aligned request.
    fn aligned_request(direction: DioDirection) -> DioRequest {
        // Use a 512-byte aligned static buffer address (stub: just pick a multiple).
        DioRequest {
            file_id: 1,
            offset: 512,
            length: 512,
            direction,
            buffer_addr: 512, // aligned to 512
        }
    }

    #[test]
    fn alignment_pass() {
        let req = aligned_request(DioDirection::Read);
        let align = DioAlignment::new(512).unwrap();
        assert!(req.check_alignment(&align).is_ok());
    }

    #[test]
    fn alignment_fail_offset() {
        let mut req = aligned_request(DioDirection::Read);
        req.offset = 100; // not aligned
        let align = DioAlignment::new(512).unwrap();
        assert!(req.check_alignment(&align).is_err());
    }

    #[test]
    fn alignment_fail_length() {
        let mut req = aligned_request(DioDirection::Write);
        req.length = 300; // not aligned
        let align = DioAlignment::new(512).unwrap();
        assert!(req.check_alignment(&align).is_err());
    }

    #[test]
    fn submit_and_complete() {
        let mut subsys = aligned_subsystem();
        let req = aligned_request(DioDirection::Read);
        // Use static buf with address that happens to be 512-aligned in test.
        // We construct a fake request directly rather than calling do_direct_io
        // to avoid real pointer alignment unpredictability in tests.
        let qidx = subsys.open_queue().unwrap();
        let token = subsys.submit_dio(qidx, req).unwrap();
        let bytes = subsys
            .complete_dio(qidx, token, DioDirection::Read)
            .unwrap();
        assert_eq!(bytes, 512);
        assert_eq!(subsys.stats().total_reads, 1);
        assert_eq!(subsys.stats().bytes_read, 512);
    }

    #[test]
    fn alignment_error_counted() {
        let mut subsys = aligned_subsystem();
        let bad_req = DioRequest {
            file_id: 1,
            offset: 100, // misaligned
            length: 512,
            direction: DioDirection::Write,
            buffer_addr: 512,
        };
        let qidx = subsys.open_queue().unwrap();
        assert!(subsys.submit_dio(qidx, bad_req).is_err());
        assert!(subsys.stats().alignment_errors > 0);
    }
}
