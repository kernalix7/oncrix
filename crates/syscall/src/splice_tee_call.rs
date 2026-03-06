// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended `splice(2)`, `tee(2)`, and `vmsplice(2)` syscall handlers with
//! advanced pipe buffer management and page-level tracking.
//!
//! This module complements [`splice_calls`](super::splice_calls) by adding
//! fine-grained page-based pipe buffer management, zero-copy page movement
//! and copy operations, and richer splice state tracking.
//!
//! # Architecture
//!
//! ```text
//! User space
//! ──────────
//! splice(fd_in, off_in, fd_out, off_out, len, flags)
//!       │
//!       ▼
//! ┌────────────────────────┐
//! │ SpliceInfo             │  ← validated arguments
//! │  ├── source descriptor │
//! │  ├── dest descriptor   │
//! │  └── SpliceFlags       │
//! └───────────┬────────────┘
//!             │
//!             ▼
//! ┌────────────────────────┐
//! │ PipeBuffer (page ring) │  ← zero-copy intermediary
//! │  ├── PageSlot[0]       │
//! │  ├── PageSlot[1]       │
//! │  └── ...               │
//! └───────────┬────────────┘
//!             │
//!     move_pages / copy_pages
//!             │
//!             ▼
//!      destination fd
//! ```
//!
//! # POSIX conformance
//!
//! `splice`, `tee`, and `vmsplice` are Linux extensions (since Linux 2.6.17).
//! POSIX.1-2024 does not define these syscalls.  The `iovec` structure used
//! by `vmsplice` follows the POSIX definition from `sys/uio.h`.
//!
//! # References
//!
//! - Linux `fs/splice.c`
//! - Linux `include/linux/pipe_fs_i.h`
//! - man: `splice(2)`, `tee(2)`, `vmsplice(2)`

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of page slots in a pipe buffer.
pub const PIPE_MAX_PAGES: usize = 16;

/// Size of a single page (4 KiB, standard x86_64).
pub const PAGE_SIZE: usize = 4096;

/// Maximum total bytes tracked in a pipe buffer.
pub const PIPE_BUF_MAX: usize = PIPE_MAX_PAGES * PAGE_SIZE;

/// Maximum number of bytes transferable in a single splice call.
pub const SPLICE_MAX_TRANSFER: usize = 1 << 26; // 64 MiB

/// Maximum number of `iovec` entries in a `vmsplice` call.
pub const VMSPLICE_MAX_IOVECS: usize = 16;

/// Maximum number of tracked splice operations for statistics.
pub const MAX_SPLICE_OPS: usize = 128;

// ---------------------------------------------------------------------------
// SpliceFlags — validated flag set
// ---------------------------------------------------------------------------

/// `SPLICE_F_MOVE`: hint to move pages rather than copy.
pub const SPLICE_F_MOVE: u32 = 0x01;
/// `SPLICE_F_NONBLOCK`: non-blocking operation.
pub const SPLICE_F_NONBLOCK: u32 = 0x02;
/// `SPLICE_F_MORE`: hint that more data follows.
pub const SPLICE_F_MORE: u32 = 0x04;
/// `SPLICE_F_GIFT`: donate pages to the pipe (for `vmsplice`).
pub const SPLICE_F_GIFT: u32 = 0x08;

/// Mask of all recognised splice flags.
const SPLICE_FLAGS_VALID: u32 = SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE | SPLICE_F_GIFT;

/// Validated set of splice/tee/vmsplice flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SpliceFlags(u32);

impl SpliceFlags {
    /// Parse and validate raw flags.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !SPLICE_FLAGS_VALID != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Return the raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether `SPLICE_F_MOVE` is set.
    pub const fn is_move(self) -> bool {
        self.0 & SPLICE_F_MOVE != 0
    }

    /// Whether `SPLICE_F_NONBLOCK` is set.
    pub const fn is_nonblock(self) -> bool {
        self.0 & SPLICE_F_NONBLOCK != 0
    }

    /// Whether `SPLICE_F_MORE` is set.
    pub const fn is_more(self) -> bool {
        self.0 & SPLICE_F_MORE != 0
    }

    /// Whether `SPLICE_F_GIFT` is set.
    pub const fn is_gift(self) -> bool {
        self.0 & SPLICE_F_GIFT != 0
    }
}

// ---------------------------------------------------------------------------
// PageSlot — individual page in the pipe buffer ring
// ---------------------------------------------------------------------------

/// State of a single page slot in the pipe buffer ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageState {
    /// Slot is empty and available for use.
    Empty,
    /// Slot contains data.
    Filled,
    /// Slot has been consumed but not yet released.
    Consumed,
}

/// A single page slot within the pipe buffer.
///
/// In a real kernel each slot holds a `struct page *` and an offset/length
/// within that page.  Here we track byte counts and state.
#[derive(Debug, Clone, Copy)]
pub struct PageSlot {
    /// State of this slot.
    pub state: PageState,
    /// Number of valid bytes in this page (0..`PAGE_SIZE`).
    pub bytes_used: usize,
    /// Offset within the page where valid data starts.
    pub offset: usize,
    /// Page frame number (PFN) — opaque identifier.
    pub pfn: u64,
    /// Reference count on this page (for shared tee pages).
    pub ref_count: u32,
}

impl PageSlot {
    /// Create an empty page slot.
    pub const fn empty() -> Self {
        Self {
            state: PageState::Empty,
            bytes_used: 0,
            offset: 0,
            pfn: 0,
            ref_count: 0,
        }
    }

    /// Create a filled page slot.
    pub const fn filled(bytes: usize, pfn: u64) -> Self {
        Self {
            state: PageState::Filled,
            bytes_used: bytes,
            offset: 0,
            pfn,
            ref_count: 1,
        }
    }

    /// Return `true` if this slot is empty.
    pub const fn is_empty(&self) -> bool {
        matches!(self.state, PageState::Empty)
    }

    /// Return `true` if this slot contains data.
    pub const fn is_filled(&self) -> bool {
        matches!(self.state, PageState::Filled)
    }

    /// Return the available space in this page.
    pub const fn free_space(&self) -> usize {
        PAGE_SIZE - self.offset - self.bytes_used
    }

    /// Consume this slot (mark as consumed, data has been read out).
    pub fn consume(&mut self) {
        self.state = PageState::Consumed;
    }

    /// Release this slot back to empty.
    pub fn release(&mut self) {
        *self = Self::empty();
    }
}

// ---------------------------------------------------------------------------
// PipeBuffer — ring of page slots
// ---------------------------------------------------------------------------

/// Pipe buffer modeled as a ring of page slots.
///
/// Data flows from `head` (write position) to `tail` (read position).
/// The buffer is full when all `PIPE_MAX_PAGES` slots are filled.
#[derive(Debug)]
pub struct PipeBuffer {
    /// The page slot ring.
    pages: [PageSlot; PIPE_MAX_PAGES],
    /// Write position (next slot to fill).
    head: usize,
    /// Read position (next slot to drain).
    tail: usize,
    /// Number of filled slots.
    filled_count: usize,
    /// Total bytes currently buffered.
    total_bytes: usize,
    /// Whether the write end is closed.
    pub write_closed: bool,
    /// Whether the read end is closed.
    pub read_closed: bool,
    /// Pipe identifier (fd number).
    pub pipe_fd: u32,
}

impl PipeBuffer {
    /// Create a new empty pipe buffer.
    pub const fn new(pipe_fd: u32) -> Self {
        Self {
            pages: [const { PageSlot::empty() }; PIPE_MAX_PAGES],
            head: 0,
            tail: 0,
            filled_count: 0,
            total_bytes: 0,
            write_closed: false,
            read_closed: false,
            pipe_fd,
        }
    }

    /// Return the total number of buffered bytes.
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Return the number of filled page slots.
    pub const fn filled_count(&self) -> usize {
        self.filled_count
    }

    /// Return `true` if the buffer has no data.
    pub const fn is_empty(&self) -> bool {
        self.filled_count == 0
    }

    /// Return `true` if all page slots are occupied.
    pub const fn is_full(&self) -> bool {
        self.filled_count >= PIPE_MAX_PAGES
    }

    /// Return the total free capacity in bytes.
    pub const fn free_bytes(&self) -> usize {
        PIPE_BUF_MAX - self.total_bytes
    }

    /// Return the number of empty page slots.
    pub const fn free_slots(&self) -> usize {
        PIPE_MAX_PAGES - self.filled_count
    }

    /// Push data into the pipe buffer.
    ///
    /// Fills page slots starting at `head`.  Returns the number of bytes
    /// actually pushed (may be less than `len` if the buffer fills up).
    ///
    /// # Errors
    ///
    /// * [`Error::WouldBlock`] — buffer is full.
    /// * [`Error::Interrupted`] — write end is closed.
    pub fn push(&mut self, len: usize, pfn_start: u64) -> Result<usize> {
        if self.write_closed {
            return Err(Error::Interrupted);
        }
        if self.is_full() {
            return Err(Error::WouldBlock);
        }

        let mut remaining = len.min(self.free_bytes());
        let mut pushed = 0usize;
        let mut pfn = pfn_start;

        while remaining > 0 && !self.is_full() {
            let chunk = remaining.min(PAGE_SIZE);
            self.pages[self.head] = PageSlot::filled(chunk, pfn);
            self.head = (self.head + 1) % PIPE_MAX_PAGES;
            self.filled_count += 1;
            self.total_bytes += chunk;
            pushed += chunk;
            remaining -= chunk;
            pfn = pfn.wrapping_add(1);
        }

        Ok(pushed)
    }

    /// Pop (drain) data from the pipe buffer.
    ///
    /// Consumes page slots starting at `tail`.  Returns the number of bytes
    /// actually drained.
    ///
    /// # Errors
    ///
    /// * [`Error::WouldBlock`] — buffer is empty.
    /// * [`Error::Interrupted`] — read end is closed.
    pub fn pop(&mut self, len: usize) -> Result<usize> {
        if self.read_closed {
            return Err(Error::Interrupted);
        }
        if self.is_empty() {
            return Err(Error::WouldBlock);
        }

        let mut remaining = len.min(self.total_bytes);
        let mut drained = 0usize;

        while remaining > 0 && !self.is_empty() {
            let slot = &mut self.pages[self.tail];
            if !slot.is_filled() {
                break;
            }
            let chunk = remaining.min(slot.bytes_used);
            if chunk >= slot.bytes_used {
                slot.release();
                self.filled_count -= 1;
                self.tail = (self.tail + 1) % PIPE_MAX_PAGES;
            } else {
                slot.bytes_used -= chunk;
                slot.offset += chunk;
            }
            self.total_bytes -= chunk;
            drained += chunk;
            remaining -= chunk;
        }

        Ok(drained)
    }

    /// Peek at the total bytes available without consuming them.
    pub const fn peek_bytes(&self) -> usize {
        self.total_bytes
    }
}

impl Default for PipeBuffer {
    fn default() -> Self {
        Self::new(0)
    }
}

// ---------------------------------------------------------------------------
// SpliceInfo — arguments for splice operations
// ---------------------------------------------------------------------------

/// Validated arguments for a `splice(2)` call.
#[derive(Debug, Clone, Copy)]
pub struct SpliceInfo {
    /// Source file descriptor.
    pub fd_in: u32,
    /// Source offset (None = use file position).
    pub off_in: Option<u64>,
    /// Destination file descriptor.
    pub fd_out: u32,
    /// Destination offset (None = use file position).
    pub off_out: Option<u64>,
    /// Number of bytes to transfer.
    pub len: usize,
    /// Validated flags.
    pub flags: SpliceFlags,
}

impl Default for SpliceInfo {
    fn default() -> Self {
        Self {
            fd_in: 0,
            off_in: None,
            fd_out: 0,
            off_out: None,
            len: 0,
            flags: SpliceFlags(0),
        }
    }
}

// ---------------------------------------------------------------------------
// TeeState — tee operation tracking
// ---------------------------------------------------------------------------

/// State and statistics for a tee operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct TeeState {
    /// Source pipe fd.
    pub src_fd: u32,
    /// Destination pipe fd.
    pub dst_fd: u32,
    /// Total bytes tee'd so far.
    pub bytes_teed: usize,
    /// Number of pages shared (reference count bumped, not copied).
    pub pages_shared: usize,
}

impl TeeState {
    /// Create a new tee state for the given pipe pair.
    pub const fn new(src_fd: u32, dst_fd: u32) -> Self {
        Self {
            src_fd,
            dst_fd,
            bytes_teed: 0,
            pages_shared: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// SpliceStats — global statistics
// ---------------------------------------------------------------------------

/// Accumulated statistics for the splice/tee/vmsplice subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct SpliceStats {
    /// Total `splice` calls.
    pub splice_calls: u64,
    /// Total `tee` calls.
    pub tee_calls: u64,
    /// Total `vmsplice` calls.
    pub vmsplice_calls: u64,
    /// Total bytes moved by splice.
    pub splice_bytes: u64,
    /// Total bytes tee'd.
    pub tee_bytes: u64,
    /// Total bytes moved by vmsplice.
    pub vmsplice_bytes: u64,
    /// Total page move operations.
    pub page_moves: u64,
    /// Total page copy operations.
    pub page_copies: u64,
}

impl SpliceStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            splice_calls: 0,
            tee_calls: 0,
            vmsplice_calls: 0,
            splice_bytes: 0,
            tee_bytes: 0,
            vmsplice_bytes: 0,
            page_moves: 0,
            page_copies: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// IoVec — POSIX iovec for vmsplice
// ---------------------------------------------------------------------------

/// POSIX `iovec` structure for scatter/gather I/O.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoVec {
    /// Base virtual address of the buffer.
    pub iov_base: u64,
    /// Length of the buffer in bytes.
    pub iov_len: usize,
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate a splice transfer length.
fn validate_len(len: usize) -> Result<()> {
    if len == 0 {
        return Err(Error::InvalidArgument);
    }
    if len > SPLICE_MAX_TRANSFER {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate that source and destination differ.
fn validate_distinct_fds(fd_in: u32, fd_out: u32) -> Result<()> {
    if fd_in == fd_out {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// move_pages — zero-copy page movement between buffers
// ---------------------------------------------------------------------------

/// Move pages from `src` to `dst`, transferring ownership.
///
/// Pages are removed from the source pipe and added to the destination pipe.
/// This is the "zero-copy" path when `SPLICE_F_MOVE` is set.
///
/// # Returns
///
/// Number of bytes moved.
///
/// # Errors
///
/// * [`Error::WouldBlock`] — Source empty or destination full.
/// * [`Error::Interrupted`] — A pipe end is closed.
pub fn move_pages(
    src: &mut PipeBuffer,
    dst: &mut PipeBuffer,
    max_bytes: usize,
    stats: &mut SpliceStats,
) -> Result<usize> {
    if src.read_closed || dst.write_closed {
        return Err(Error::Interrupted);
    }
    if src.is_empty() {
        return Err(Error::WouldBlock);
    }
    if dst.is_full() {
        return Err(Error::WouldBlock);
    }

    let mut moved = 0usize;
    let mut remaining = max_bytes;

    while remaining > 0 && !src.is_empty() && !dst.is_full() {
        let src_slot = &src.pages[src.tail];
        if !src_slot.is_filled() {
            break;
        }

        let bytes = src_slot.bytes_used.min(remaining);
        let pfn = src_slot.pfn;

        // Move the page reference to destination.
        dst.pages[dst.head] = PageSlot::filled(bytes, pfn);
        dst.head = (dst.head + 1) % PIPE_MAX_PAGES;
        dst.filled_count += 1;
        dst.total_bytes += bytes;

        // Release from source.
        src.pages[src.tail].release();
        src.filled_count -= 1;
        src.total_bytes -= bytes;
        src.tail = (src.tail + 1) % PIPE_MAX_PAGES;

        moved += bytes;
        remaining -= bytes;
        stats.page_moves += 1;
    }

    Ok(moved)
}

// ---------------------------------------------------------------------------
// copy_pages — page duplication (tee semantics)
// ---------------------------------------------------------------------------

/// Copy page references from `src` to `dst` without consuming the source.
///
/// The source pipe retains its data.  Page reference counts are incremented
/// (simulated by `ref_count` field).  This is the core of `tee(2)`.
///
/// # Returns
///
/// Number of bytes copied.
///
/// # Errors
///
/// * [`Error::WouldBlock`] — Source empty or destination full.
/// * [`Error::Interrupted`] — A pipe end is closed.
pub fn copy_pages(
    src: &mut PipeBuffer,
    dst: &mut PipeBuffer,
    max_bytes: usize,
    stats: &mut SpliceStats,
) -> Result<usize> {
    if src.read_closed || dst.write_closed {
        return Err(Error::Interrupted);
    }
    if src.is_empty() {
        return Err(Error::WouldBlock);
    }
    if dst.is_full() {
        return Err(Error::WouldBlock);
    }

    let mut copied = 0usize;
    let mut remaining = max_bytes;
    let mut read_idx = src.tail;
    let mut slots_checked = 0usize;

    while remaining > 0 && slots_checked < src.filled_count && !dst.is_full() {
        let src_slot = &src.pages[read_idx];
        if !src_slot.is_filled() {
            read_idx = (read_idx + 1) % PIPE_MAX_PAGES;
            slots_checked += 1;
            continue;
        }

        let bytes = src_slot.bytes_used.min(remaining);
        let pfn = src_slot.pfn;

        // Copy page reference to destination (bump ref count on source).
        dst.pages[dst.head] = PageSlot::filled(bytes, pfn);
        dst.pages[dst.head].ref_count = src_slot.ref_count + 1;
        dst.head = (dst.head + 1) % PIPE_MAX_PAGES;
        dst.filled_count += 1;
        dst.total_bytes += bytes;

        // Increment ref count on source page.
        src.pages[read_idx].ref_count += 1;

        copied += bytes;
        remaining -= bytes;
        read_idx = (read_idx + 1) % PIPE_MAX_PAGES;
        slots_checked += 1;
        stats.page_copies += 1;
    }

    Ok(copied)
}

// ---------------------------------------------------------------------------
// sys_splice — splice(2) handler
// ---------------------------------------------------------------------------

/// `splice(2)` — transfer data between a file descriptor and a pipe.
///
/// At least one of the two descriptors must be a pipe.  Data is moved
/// through the pipe buffer without copying through user space.
///
/// # Arguments
///
/// * `pipe`       — The pipe buffer (source or destination side).
/// * `pipe_is_in` — `true` if the pipe is the source (pipe -> fd_out).
/// * `info`       — Validated splice info.
/// * `stats`      — Statistics accumulator.
///
/// # Returns
///
/// Number of bytes transferred.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Invalid flags, zero length, `fd_in == fd_out`.
/// * [`Error::WouldBlock`]      — Non-blocking and no data/space available.
/// * [`Error::Interrupted`]     — A pipe end is closed.
pub fn sys_splice(
    pipe: &mut PipeBuffer,
    pipe_is_in: bool,
    info: &SpliceInfo,
    stats: &mut SpliceStats,
) -> Result<usize> {
    stats.splice_calls += 1;

    validate_len(info.len)?;
    validate_distinct_fds(info.fd_in, info.fd_out)?;

    // Offsets are not allowed on the pipe side.
    if pipe_is_in && info.off_in.is_some() {
        return Err(Error::InvalidArgument);
    }
    if !pipe_is_in && info.off_out.is_some() {
        return Err(Error::InvalidArgument);
    }

    let transferred = if pipe_is_in {
        // Pipe -> file/socket: drain from pipe.
        pipe.pop(info.len)?
    } else {
        // File/socket -> pipe: fill pipe.
        pipe.push(info.len, 0x1000)?
    };

    stats.splice_bytes += transferred as u64;
    Ok(transferred)
}

// ---------------------------------------------------------------------------
// sys_tee — tee(2) handler
// ---------------------------------------------------------------------------

/// `tee(2)` — duplicate data between two pipes without consuming the source.
///
/// Both `src` and `dst` must be pipes.  The source pipe retains its data;
/// the destination receives shared page references.
///
/// # Arguments
///
/// * `src`    — Source pipe buffer.
/// * `dst`    — Destination pipe buffer.
/// * `len`    — Maximum number of bytes to tee.
/// * `flags`  — Raw splice flags.
/// * `state`  — Tee state tracker (updated on success).
/// * `stats`  — Statistics accumulator.
///
/// # Returns
///
/// Number of bytes tee'd.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Invalid flags, zero length, same pipe.
/// * [`Error::WouldBlock`]      — Non-blocking and source empty / dest full.
/// * [`Error::Interrupted`]     — A pipe end is closed.
pub fn sys_tee(
    src: &mut PipeBuffer,
    dst: &mut PipeBuffer,
    len: usize,
    flags: u32,
    state: &mut TeeState,
    stats: &mut SpliceStats,
) -> Result<usize> {
    stats.tee_calls += 1;

    let _flags = SpliceFlags::from_raw(flags)?;
    validate_len(len)?;
    validate_distinct_fds(src.pipe_fd, dst.pipe_fd)?;

    let copied = copy_pages(src, dst, len, stats)?;

    state.bytes_teed += copied;
    state.pages_shared += 1;
    stats.tee_bytes += copied as u64;

    Ok(copied)
}

// ---------------------------------------------------------------------------
// sys_vmsplice — vmsplice(2) handler
// ---------------------------------------------------------------------------

/// `vmsplice(2)` — splice user-space pages into or out of a pipe.
///
/// When writing into the pipe, user-space virtual address ranges described
/// by `iov` are donated or copied into the pipe buffer.  When reading,
/// pipe data is copied out to the user-space buffers.
///
/// # Arguments
///
/// * `pipe`      — Target or source pipe buffer.
/// * `iov`       — Array of `iovec` structures.
/// * `iov_count` — Number of valid entries in `iov`.
/// * `flags`     — Raw splice flags.
/// * `into_pipe` — `true` = write iov data into pipe; `false` = read from pipe.
/// * `stats`     — Statistics accumulator.
///
/// # Returns
///
/// Number of bytes transferred.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Invalid flags, bad iov count, zero-length
///   iov entry, total length exceeds limit.
/// * [`Error::WouldBlock`]      — Non-blocking and pipe is full/empty.
/// * [`Error::Interrupted`]     — A pipe end is closed.
pub fn sys_vmsplice(
    pipe: &mut PipeBuffer,
    iov: &[IoVec],
    iov_count: usize,
    flags: u32,
    into_pipe: bool,
    stats: &mut SpliceStats,
) -> Result<usize> {
    stats.vmsplice_calls += 1;

    let _flags = SpliceFlags::from_raw(flags)?;

    if iov_count == 0 || iov_count > VMSPLICE_MAX_IOVECS {
        return Err(Error::InvalidArgument);
    }
    if iov.len() < iov_count {
        return Err(Error::InvalidArgument);
    }

    // Compute total length and validate each entry.
    let mut total_len: usize = 0;
    for v in &iov[..iov_count] {
        if v.iov_len == 0 {
            return Err(Error::InvalidArgument);
        }
        total_len = total_len.saturating_add(v.iov_len);
    }
    if total_len > SPLICE_MAX_TRANSFER {
        return Err(Error::InvalidArgument);
    }

    let transferred = if into_pipe {
        pipe.push(total_len, 0x2000)?
    } else {
        pipe.pop(total_len)?
    };

    stats.vmsplice_bytes += transferred as u64;
    Ok(transferred)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pipe(fd: u32) -> PipeBuffer {
        PipeBuffer::new(fd)
    }

    fn filled_pipe(fd: u32, bytes: usize) -> PipeBuffer {
        let mut pipe = PipeBuffer::new(fd);
        let _ = pipe.push(bytes, 0x100);
        pipe
    }

    // --- SpliceFlags ---

    #[test]
    fn flags_valid() {
        assert!(SpliceFlags::from_raw(0).is_ok());
        assert!(SpliceFlags::from_raw(SPLICE_F_MOVE).is_ok());
        assert!(SpliceFlags::from_raw(SPLICE_F_NONBLOCK | SPLICE_F_MORE).is_ok());
    }

    #[test]
    fn flags_invalid() {
        assert_eq!(
            SpliceFlags::from_raw(0xFFFF_0000),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn flags_accessors() {
        let f = SpliceFlags::from_raw(SPLICE_F_MOVE | SPLICE_F_NONBLOCK).unwrap();
        assert!(f.is_move());
        assert!(f.is_nonblock());
        assert!(!f.is_more());
        assert!(!f.is_gift());
    }

    // --- PageSlot ---

    #[test]
    fn page_slot_empty() {
        let slot = PageSlot::empty();
        assert!(slot.is_empty());
        assert!(!slot.is_filled());
        assert_eq!(slot.free_space(), PAGE_SIZE);
    }

    #[test]
    fn page_slot_filled() {
        let slot = PageSlot::filled(2048, 0x100);
        assert!(slot.is_filled());
        assert_eq!(slot.bytes_used, 2048);
        assert_eq!(slot.pfn, 0x100);
        assert_eq!(slot.ref_count, 1);
    }

    #[test]
    fn page_slot_consume_and_release() {
        let mut slot = PageSlot::filled(1024, 0x200);
        slot.consume();
        assert_eq!(slot.state, PageState::Consumed);
        slot.release();
        assert!(slot.is_empty());
    }

    // --- PipeBuffer ---

    #[test]
    fn pipe_new_is_empty() {
        let pipe = make_pipe(5);
        assert!(pipe.is_empty());
        assert!(!pipe.is_full());
        assert_eq!(pipe.total_bytes(), 0);
        assert_eq!(pipe.free_bytes(), PIPE_BUF_MAX);
    }

    #[test]
    fn pipe_push_and_pop() {
        let mut pipe = make_pipe(5);
        let pushed = pipe.push(8192, 0x100).unwrap();
        assert_eq!(pushed, 8192);
        assert_eq!(pipe.total_bytes(), 8192);

        let popped = pipe.pop(4096).unwrap();
        assert_eq!(popped, 4096);
        assert_eq!(pipe.total_bytes(), 4096);
    }

    #[test]
    fn pipe_push_capped_by_capacity() {
        let mut pipe = make_pipe(5);
        let pushed = pipe.push(PIPE_BUF_MAX + 1000, 0x100).unwrap();
        assert_eq!(pushed, PIPE_BUF_MAX);
        assert!(pipe.is_full());
    }

    #[test]
    fn pipe_push_full_returns_wouldblock() {
        let mut pipe = make_pipe(5);
        pipe.push(PIPE_BUF_MAX, 0x100).unwrap();
        assert_eq!(pipe.push(1, 0x200), Err(Error::WouldBlock));
    }

    #[test]
    fn pipe_pop_empty_returns_wouldblock() {
        let mut pipe = make_pipe(5);
        assert_eq!(pipe.pop(1), Err(Error::WouldBlock));
    }

    #[test]
    fn pipe_push_write_closed() {
        let mut pipe = make_pipe(5);
        pipe.write_closed = true;
        assert_eq!(pipe.push(1024, 0x100), Err(Error::Interrupted));
    }

    #[test]
    fn pipe_pop_read_closed() {
        let mut pipe = filled_pipe(5, 4096);
        pipe.read_closed = true;
        assert_eq!(pipe.pop(1024), Err(Error::Interrupted));
    }

    #[test]
    fn pipe_partial_pop() {
        let mut pipe = make_pipe(5);
        pipe.push(4096, 0x100).unwrap(); // fills 1 page
        let popped = pipe.pop(2048).unwrap();
        assert_eq!(popped, 2048);
        assert_eq!(pipe.total_bytes(), 2048);
    }

    // --- move_pages ---

    #[test]
    fn move_pages_transfers_data() {
        let mut src = filled_pipe(3, 8192);
        let mut dst = make_pipe(4);
        let mut stats = SpliceStats::new();

        let moved = move_pages(&mut src, &mut dst, 8192, &mut stats).unwrap();
        assert_eq!(moved, 8192);
        assert_eq!(src.total_bytes(), 0);
        assert_eq!(dst.total_bytes(), 8192);
        assert!(stats.page_moves > 0);
    }

    #[test]
    fn move_pages_capped_by_source() {
        let mut src = filled_pipe(3, 2048);
        let mut dst = make_pipe(4);
        let mut stats = SpliceStats::new();

        let moved = move_pages(&mut src, &mut dst, 8192, &mut stats).unwrap();
        assert_eq!(moved, 2048);
    }

    #[test]
    fn move_pages_empty_source_wouldblock() {
        let mut src = make_pipe(3);
        let mut dst = make_pipe(4);
        let mut stats = SpliceStats::new();

        assert_eq!(
            move_pages(&mut src, &mut dst, 1024, &mut stats),
            Err(Error::WouldBlock)
        );
    }

    #[test]
    fn move_pages_full_dest_wouldblock() {
        let mut src = filled_pipe(3, 4096);
        let mut dst = filled_pipe(4, PIPE_BUF_MAX);
        let mut stats = SpliceStats::new();

        assert_eq!(
            move_pages(&mut src, &mut dst, 1024, &mut stats),
            Err(Error::WouldBlock)
        );
    }

    #[test]
    fn move_pages_closed_pipe_interrupted() {
        let mut src = filled_pipe(3, 4096);
        src.read_closed = true;
        let mut dst = make_pipe(4);
        let mut stats = SpliceStats::new();

        assert_eq!(
            move_pages(&mut src, &mut dst, 1024, &mut stats),
            Err(Error::Interrupted)
        );
    }

    // --- copy_pages ---

    #[test]
    fn copy_pages_shares_without_consuming() {
        let mut src = filled_pipe(3, 8192);
        let mut dst = make_pipe(4);
        let mut stats = SpliceStats::new();

        let src_before = src.total_bytes();
        let copied = copy_pages(&mut src, &mut dst, 8192, &mut stats).unwrap();
        assert_eq!(copied, 8192);
        assert_eq!(src.total_bytes(), src_before); // source unchanged
        assert_eq!(dst.total_bytes(), 8192);
        assert!(stats.page_copies > 0);
    }

    #[test]
    fn copy_pages_empty_source_wouldblock() {
        let mut src = make_pipe(3);
        let mut dst = make_pipe(4);
        let mut stats = SpliceStats::new();

        assert_eq!(
            copy_pages(&mut src, &mut dst, 1024, &mut stats),
            Err(Error::WouldBlock)
        );
    }

    #[test]
    fn copy_pages_increments_ref_count() {
        let mut src = filled_pipe(3, 4096);
        let mut dst = make_pipe(4);
        let mut stats = SpliceStats::new();

        copy_pages(&mut src, &mut dst, 4096, &mut stats).unwrap();

        // Source page ref_count should be incremented.
        assert!(src.pages[src.tail].ref_count >= 2);
    }

    // --- sys_splice ---

    #[test]
    fn splice_pipe_to_file() {
        let mut pipe = filled_pipe(5, 8192);
        let mut stats = SpliceStats::new();
        let info = SpliceInfo {
            fd_in: 5,
            off_in: None,
            fd_out: 3,
            off_out: Some(0),
            len: 4096,
            flags: SpliceFlags(0),
        };

        let n = sys_splice(&mut pipe, true, &info, &mut stats).unwrap();
        assert_eq!(n, 4096);
        assert_eq!(stats.splice_calls, 1);
        assert_eq!(stats.splice_bytes, 4096);
    }

    #[test]
    fn splice_file_to_pipe() {
        let mut pipe = make_pipe(5);
        let mut stats = SpliceStats::new();
        let info = SpliceInfo {
            fd_in: 3,
            off_in: Some(0),
            fd_out: 5,
            off_out: None,
            len: 4096,
            flags: SpliceFlags(0),
        };

        let n = sys_splice(&mut pipe, false, &info, &mut stats).unwrap();
        assert_eq!(n, 4096);
        assert_eq!(pipe.total_bytes(), 4096);
    }

    #[test]
    fn splice_same_fd_rejected() {
        let mut pipe = filled_pipe(5, 4096);
        let mut stats = SpliceStats::new();
        let info = SpliceInfo {
            fd_in: 5,
            fd_out: 5,
            len: 1024,
            ..Default::default()
        };

        assert_eq!(
            sys_splice(&mut pipe, true, &info, &mut stats),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn splice_zero_len_rejected() {
        let mut pipe = filled_pipe(5, 4096);
        let mut stats = SpliceStats::new();
        let info = SpliceInfo {
            fd_in: 5,
            fd_out: 3,
            len: 0,
            ..Default::default()
        };

        assert_eq!(
            sys_splice(&mut pipe, true, &info, &mut stats),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn splice_offset_on_pipe_side_rejected() {
        let mut pipe = filled_pipe(5, 4096);
        let mut stats = SpliceStats::new();
        let info = SpliceInfo {
            fd_in: 5,
            off_in: Some(100), // pipe is input, offset not allowed
            fd_out: 3,
            len: 1024,
            ..Default::default()
        };

        assert_eq!(
            sys_splice(&mut pipe, true, &info, &mut stats),
            Err(Error::InvalidArgument)
        );
    }

    // --- sys_tee ---

    #[test]
    fn tee_duplicates_data() {
        let mut src = filled_pipe(3, 8192);
        let mut dst = make_pipe(4);
        let mut tee_state = TeeState::new(3, 4);
        let mut stats = SpliceStats::new();

        let src_before = src.total_bytes();
        let n = sys_tee(&mut src, &mut dst, 4096, 0, &mut tee_state, &mut stats).unwrap();
        assert_eq!(n, 4096);
        assert_eq!(src.total_bytes(), src_before); // source unchanged
        assert_eq!(dst.total_bytes(), 4096);
        assert_eq!(tee_state.bytes_teed, 4096);
        assert_eq!(stats.tee_calls, 1);
        assert_eq!(stats.tee_bytes, 4096);
    }

    #[test]
    fn tee_same_pipe_rejected() {
        let mut src = filled_pipe(3, 4096);
        let mut dst = PipeBuffer::new(3); // same fd
        let mut tee_state = TeeState::new(3, 3);
        let mut stats = SpliceStats::new();

        assert_eq!(
            sys_tee(&mut src, &mut dst, 1024, 0, &mut tee_state, &mut stats),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn tee_bad_flags_rejected() {
        let mut src = filled_pipe(3, 4096);
        let mut dst = make_pipe(4);
        let mut tee_state = TeeState::new(3, 4);
        let mut stats = SpliceStats::new();

        assert_eq!(
            sys_tee(&mut src, &mut dst, 1024, 0xDEAD, &mut tee_state, &mut stats),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn tee_zero_len_rejected() {
        let mut src = filled_pipe(3, 4096);
        let mut dst = make_pipe(4);
        let mut tee_state = TeeState::new(3, 4);
        let mut stats = SpliceStats::new();

        assert_eq!(
            sys_tee(&mut src, &mut dst, 0, 0, &mut tee_state, &mut stats),
            Err(Error::InvalidArgument)
        );
    }

    // --- sys_vmsplice ---

    #[test]
    fn vmsplice_into_pipe() {
        let mut pipe = make_pipe(5);
        let mut stats = SpliceStats::new();
        let iov = [
            IoVec {
                iov_base: 0x1000,
                iov_len: 1024,
            },
            IoVec {
                iov_base: 0x2000,
                iov_len: 2048,
            },
        ];

        let n = sys_vmsplice(&mut pipe, &iov, 2, 0, true, &mut stats).unwrap();
        assert_eq!(n, 3072);
        assert_eq!(pipe.total_bytes(), 3072);
        assert_eq!(stats.vmsplice_calls, 1);
        assert_eq!(stats.vmsplice_bytes, 3072);
    }

    #[test]
    fn vmsplice_from_pipe() {
        let mut pipe = filled_pipe(5, 4096);
        let mut stats = SpliceStats::new();
        let iov = [IoVec {
            iov_base: 0x1000,
            iov_len: 2048,
        }];

        let n = sys_vmsplice(&mut pipe, &iov, 1, 0, false, &mut stats).unwrap();
        assert_eq!(n, 2048);
        assert_eq!(pipe.total_bytes(), 2048);
    }

    #[test]
    fn vmsplice_zero_count_rejected() {
        let mut pipe = make_pipe(5);
        let mut stats = SpliceStats::new();

        assert_eq!(
            sys_vmsplice(&mut pipe, &[], 0, 0, true, &mut stats),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn vmsplice_too_many_iovecs_rejected() {
        let mut pipe = make_pipe(5);
        let mut stats = SpliceStats::new();
        let iov = [IoVec::default(); VMSPLICE_MAX_IOVECS + 1];

        assert_eq!(
            sys_vmsplice(
                &mut pipe,
                &iov,
                VMSPLICE_MAX_IOVECS + 1,
                0,
                true,
                &mut stats
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn vmsplice_zero_iov_len_rejected() {
        let mut pipe = make_pipe(5);
        let mut stats = SpliceStats::new();
        let iov = [IoVec {
            iov_base: 0x1000,
            iov_len: 0,
        }];

        assert_eq!(
            sys_vmsplice(&mut pipe, &iov, 1, 0, true, &mut stats),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn vmsplice_bad_flags_rejected() {
        let mut pipe = make_pipe(5);
        let mut stats = SpliceStats::new();
        let iov = [IoVec {
            iov_base: 0x1000,
            iov_len: 512,
        }];

        assert_eq!(
            sys_vmsplice(&mut pipe, &iov, 1, 0xBAD0, true, &mut stats),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn vmsplice_gift_flag_accepted() {
        let mut pipe = make_pipe(5);
        let mut stats = SpliceStats::new();
        let iov = [IoVec {
            iov_base: 0x1000,
            iov_len: 4096,
        }];

        let n = sys_vmsplice(&mut pipe, &iov, 1, SPLICE_F_GIFT, true, &mut stats).unwrap();
        assert_eq!(n, 4096);
    }

    // --- SpliceStats ---

    #[test]
    fn stats_accumulate() {
        let mut pipe = make_pipe(5);
        let mut stats = SpliceStats::new();

        for _ in 0..3 {
            let info = SpliceInfo {
                fd_in: 3,
                fd_out: 5,
                len: 1024,
                ..Default::default()
            };
            let _ = sys_splice(&mut pipe, false, &info, &mut stats);
        }
        assert_eq!(stats.splice_calls, 3);
    }

    // --- TeeState ---

    #[test]
    fn tee_state_accumulates() {
        let mut src = filled_pipe(3, 16384);
        let mut dst = make_pipe(4);
        let mut tee_state = TeeState::new(3, 4);
        let mut stats = SpliceStats::new();

        sys_tee(&mut src, &mut dst, 4096, 0, &mut tee_state, &mut stats).unwrap();
        sys_tee(&mut src, &mut dst, 4096, 0, &mut tee_state, &mut stats).unwrap();

        assert_eq!(tee_state.bytes_teed, 8192);
        assert_eq!(tee_state.pages_shared, 2);
    }
}
