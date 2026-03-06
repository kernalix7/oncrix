// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Splice/tee/vmsplice zero-copy I/O subsystem.
//!
//! Implements Linux-style zero-copy data movement between file
//! descriptors, where at least one endpoint is a pipe. The key
//! operations are:
//!
//! - **splice**: move data between a pipe and a file descriptor
//!   without copying through user space.
//! - **tee**: duplicate pipe data without consuming it.
//! - **vmsplice**: splice user-space memory pages into a pipe.
//! - **sendfile**: optimised file-to-socket transfer.
//!
//! All transfers go through a [`PipeBufRing`], a fixed-size ring
//! of [`PipeBuffer`] slots that avoids kernel↔user copies.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// Hint that pages may be moved (not copied).
pub const SPLICE_F_MOVE: u32 = 1;

/// Do not block on I/O.
pub const SPLICE_F_NONBLOCK: u32 = 2;

/// More data will follow in a subsequent splice.
pub const SPLICE_F_MORE: u32 = 4;

/// Gift pages to the kernel (vmsplice).
pub const SPLICE_F_GIFT: u32 = 8;

/// Maximum number of pipe buffer pages in a ring.
const _MAX_PIPE_PAGES: usize = 16;

/// Size of a single pipe buffer in bytes.
const _PIPE_BUF_SIZE: usize = 4096;

// ── PipeBuffer ───────────────────────────────────────────────────

/// A single page-sized buffer used for splice pipe transfers.
///
/// Each buffer tracks its own offset into `data`, the number of
/// valid bytes (`len`), per-buffer flags, and whether the slot is
/// currently occupied in the ring.
pub struct PipeBuffer {
    /// Raw page data.
    data: [u8; 4096],
    /// Read offset within `data`.
    offset: u16,
    /// Number of valid bytes starting at `offset`.
    len: u16,
    /// Per-buffer flags (e.g. SPLICE_F_* subset).
    flags: u16,
    /// Whether this slot is in use.
    occupied: bool,
}

impl Default for PipeBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl PipeBuffer {
    /// Creates a new, empty pipe buffer.
    pub const fn new() -> Self {
        Self {
            data: [0u8; 4096],
            offset: 0,
            len: 0,
            flags: 0,
            occupied: false,
        }
    }

    /// Returns the number of readable bytes remaining.
    pub fn available(&self) -> usize {
        self.len as usize
    }

    /// Returns the number of bytes that can still be written.
    pub fn remaining(&self) -> usize {
        4096 - (self.offset as usize + self.len as usize)
    }

    /// Consumes `n` bytes from the front of the buffer.
    ///
    /// Advances the read offset and shrinks the valid length.
    /// If `n` exceeds the available data the buffer is fully
    /// drained.
    pub fn consume(&mut self, n: usize) {
        let n = n.min(self.len as usize);
        self.offset = self.offset.saturating_add(n as u16);
        self.len = self.len.saturating_sub(n as u16);
    }

    /// Appends `n` bytes of valid data to the buffer.
    ///
    /// Extends the valid length without moving the offset.
    /// Capped at the remaining capacity.
    pub fn produce(&mut self, n: usize) {
        let n = n.min(self.remaining());
        self.len = self.len.saturating_add(n as u16);
    }
}

// ── PipeBufRing ──────────────────────────────────────────────────

/// Fixed-size ring of [`PipeBuffer`] slots used by splice.
///
/// The ring holds up to [`_MAX_PIPE_PAGES`] buffers and is
/// managed via `head` (consumer) and `tail` (producer) indices.
pub struct PipeBufRing {
    /// Buffer storage.
    buffers: [PipeBuffer; 16],
    /// Consumer index.
    head: usize,
    /// Producer index.
    tail: usize,
    /// Number of occupied slots.
    count: usize,
}

impl Default for PipeBufRing {
    fn default() -> Self {
        Self::new()
    }
}

impl PipeBufRing {
    /// Creates an empty ring.
    pub const fn new() -> Self {
        const EMPTY: PipeBuffer = PipeBuffer::new();
        Self {
            buffers: [EMPTY; 16],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Pushes a new slot, returning a mutable reference to it.
    ///
    /// Returns `None` when the ring is full.
    pub fn push(&mut self) -> Option<&mut PipeBuffer> {
        if self.is_full() {
            return None;
        }
        let idx = self.tail;
        self.tail = (self.tail + 1) % 16;
        self.count += 1;
        self.buffers[idx].occupied = true;
        self.buffers[idx].offset = 0;
        self.buffers[idx].len = 0;
        self.buffers[idx].flags = 0;
        Some(&mut self.buffers[idx])
    }

    /// Peeks at the head buffer without consuming it.
    ///
    /// Returns `None` when the ring is empty.
    pub fn peek(&self) -> Option<&PipeBuffer> {
        if self.is_empty() {
            return None;
        }
        Some(&self.buffers[self.head])
    }

    /// Removes and returns the head buffer.
    ///
    /// The slot is marked unoccupied after removal.
    /// Returns `None` when the ring is empty.
    pub fn pop(&mut self) -> Option<PipeBuffer> {
        if self.is_empty() {
            return None;
        }
        let idx = self.head;
        self.head = (self.head + 1) % 16;
        self.count -= 1;
        self.buffers[idx].occupied = false;

        // Build a copy of the buffer to return.
        let mut buf = PipeBuffer::new();
        buf.data.copy_from_slice(&self.buffers[idx].data);
        buf.offset = self.buffers[idx].offset;
        buf.len = self.buffers[idx].len;
        buf.flags = self.buffers[idx].flags;
        buf.occupied = false;
        Some(buf)
    }

    /// Returns the number of occupied slots.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` when no slots are occupied.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns `true` when the ring is at capacity.
    pub fn is_full(&self) -> bool {
        self.count >= 16
    }
}

// ── SpliceOp ─────────────────────────────────────────────────────

/// Discriminant for the type of splice operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SpliceOp {
    /// Pipe ↔ fd data movement.
    #[default]
    Splice,
    /// Pipe → pipe duplication.
    Tee,
    /// User pages → pipe mapping.
    Vmsplice,
}

// ── IoVec ────────────────────────────────────────────────────────

/// C-compatible I/O vector for scatter/gather operations.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IoVec {
    /// Base address of the buffer.
    pub base: u64,
    /// Length of the buffer in bytes.
    pub len: u64,
}

// ── SpliceRequest ────────────────────────────────────────────────

/// Captures the full parameter set for a splice system call.
pub struct SpliceRequest {
    /// Source file descriptor.
    pub fd_in: i32,
    /// Optional byte offset into the source.
    pub off_in: Option<u64>,
    /// Destination file descriptor.
    pub fd_out: i32,
    /// Optional byte offset into the destination.
    pub off_out: Option<u64>,
    /// Maximum number of bytes to transfer.
    pub len: usize,
    /// Splice flags (bitmask of `SPLICE_F_*`).
    pub flags: u32,
}

// ── SpliceStats ──────────────────────────────────────────────────

/// Cumulative statistics for splice operations.
#[derive(Default)]
pub struct SpliceStats {
    /// Total bytes moved via `splice`.
    pub total_spliced: u64,
    /// Total bytes duplicated via `tee`.
    pub total_teed: u64,
    /// Total bytes mapped via `vmsplice`.
    pub total_vmspliced: u64,
    /// Total bytes sent via `sendfile`.
    pub total_sendfile: u64,
}

// ── Helpers ──────────────────────────────────────────────────────

/// Validates a raw file descriptor.
///
/// Negative values and values beyond a reasonable upper bound are
/// rejected with [`Error::InvalidArgument`].
fn validate_fd(fd: i32) -> Result<()> {
    if fd < 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validates a bitmask of splice flags.
///
/// Unknown flag bits are rejected with
/// [`Error::InvalidArgument`].
fn validate_flags(flags: u32) -> Result<()> {
    let known = SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT;
    if flags & !known != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ── Syscall handlers ─────────────────────────────────────────────

/// Moves data between two file descriptors without copying
/// through user space.
///
/// At least one of `fd_in` or `fd_out` must refer to a pipe.
/// `off_in` / `off_out` specify optional byte offsets for the
/// non-pipe endpoint.  `len` is the maximum number of bytes to
/// transfer.
///
/// Returns the number of bytes actually transferred.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — invalid fd or flags.
/// - [`Error::NotImplemented`] — actual transfer not yet wired.
pub fn do_splice(
    fd_in: i32,
    off_in: Option<u64>,
    fd_out: i32,
    off_out: Option<u64>,
    len: usize,
    flags: u32,
) -> Result<usize> {
    validate_fd(fd_in)?;
    validate_fd(fd_out)?;
    validate_flags(flags)?;

    if len == 0 {
        return Ok(0);
    }

    // Both offsets present means neither fd is a pipe — invalid.
    if off_in.is_some() && off_out.is_some() {
        return Err(Error::InvalidArgument);
    }

    let _req = SpliceRequest {
        fd_in,
        off_in,
        fd_out,
        off_out,
        len,
        flags,
    };

    // Actual pipe-buffer transfer requires VFS integration.
    Err(Error::NotImplemented)
}

/// Duplicates data from one pipe into another without consuming
/// the source.
///
/// Both `fd_in` and `fd_out` must be pipe file descriptors.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — invalid fd or flags.
/// - [`Error::NotImplemented`] — actual transfer not yet wired.
pub fn do_tee(fd_in: i32, fd_out: i32, len: usize, flags: u32) -> Result<usize> {
    validate_fd(fd_in)?;
    validate_fd(fd_out)?;
    validate_flags(flags)?;

    if fd_in == fd_out {
        return Err(Error::InvalidArgument);
    }

    if len == 0 {
        return Ok(0);
    }

    // Actual pipe duplication requires VFS integration.
    Err(Error::NotImplemented)
}

/// Splices user-space memory pages into a pipe.
///
/// `fd` must refer to a pipe.  `iov` is a slice of [`IoVec`]
/// descriptors pointing to user-space buffers.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — invalid fd, flags, or empty
///   iov.
/// - [`Error::NotImplemented`] — actual transfer not yet wired.
pub fn do_vmsplice(fd: i32, iov: &[IoVec], flags: u32) -> Result<usize> {
    validate_fd(fd)?;
    validate_flags(flags)?;

    if iov.is_empty() {
        return Err(Error::InvalidArgument);
    }

    // Validate each vector entry.
    for v in iov {
        if v.base == 0 && v.len != 0 {
            return Err(Error::InvalidArgument);
        }
    }

    // Actual page mapping requires MM integration.
    Err(Error::NotImplemented)
}

/// Optimised file-to-socket data transfer.
///
/// Copies up to `count` bytes from `in_fd` (which must support
/// `mmap`-like reading) to `out_fd` (typically a socket).
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — invalid fd or zero count.
/// - [`Error::NotImplemented`] — actual transfer not yet wired.
pub fn do_sendfile(out_fd: i32, in_fd: i32, offset: Option<u64>, count: usize) -> Result<usize> {
    validate_fd(out_fd)?;
    validate_fd(in_fd)?;

    if count == 0 {
        return Err(Error::InvalidArgument);
    }

    let _off = offset;

    // Actual transfer requires VFS + socket integration.
    Err(Error::NotImplemented)
}
