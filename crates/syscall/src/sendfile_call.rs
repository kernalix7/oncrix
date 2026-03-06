// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `sendfile64(2)` syscall handler — efficient in-kernel file-to-socket
//! data transfer.
//!
//! `sendfile` copies data between two file descriptors entirely within the
//! kernel, avoiding the overhead of transferring data between kernel and user
//! space.  The canonical use case is a web server sending a file over a
//! network socket: the file data is read from the page cache and written
//! directly to the socket buffer.
//!
//! # Syscall summary
//!
//! | Syscall      | Handler              | Purpose                              |
//! |--------------|----------------------|--------------------------------------|
//! | `sendfile64` | [`sys_sendfile64`]   | File-to-fd transfer, 64-bit offset   |
//!
//! # Data flow
//!
//! ```text
//! User space                          Kernel space
//! ──────────                          ─────────────
//! sendfile64(out_fd, in_fd,           validate(in_fd, out_fd, count)
//!            offset, count)           resolve source offset
//!                                     do_sendfile():
//!                                       read from page cache
//!                                       write to socket buffer
//!                                     advance offset
//!                                 ◄── bytes_sent / -errno
//! ```
//!
//! # POSIX conformance
//!
//! `sendfile` is a Linux extension (since Linux 2.2).  POSIX.1-2024 does
//! not define this syscall.  BSD systems have a similar but not identical
//! `sendfile(2)`.  The Linux variant supports any writable destination fd,
//! not just sockets (since Linux 2.6.33).
//!
//! # References
//!
//! - Linux `fs/read_write.c` — `do_sendfile()`
//! - man: `sendfile(2)`, `sendfile64(2)`

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of bytes transferable in a single `sendfile` call.
pub const SENDFILE_MAX_COUNT: usize = 0x7FFF_F000; // ~2 GiB - 4 KiB (Linux limit)

/// Maximum file size supported by the stub.
pub const MAX_FILE_SIZE: u64 = 1 << 46; // 64 TiB

/// Minimum valid file descriptor number.
pub const MIN_FD: i32 = 0;

/// Maximum valid file descriptor number.
pub const MAX_FD: i32 = 1 << 20;

/// Syscall number for `sendfile64` (x86_64 Linux ABI).
pub const SYS_SENDFILE64: u64 = 40;

/// Maximum number of file descriptors tracked by the stub.
pub const MAX_FD_ENTRIES: usize = 64;

// ---------------------------------------------------------------------------
// FdCaps — file descriptor capability flags
// ---------------------------------------------------------------------------

/// File is open for reading.
pub const FD_CAP_READ: u32 = 1 << 0;
/// File is open for writing.
pub const FD_CAP_WRITE: u32 = 1 << 1;
/// File is a regular file.
pub const FD_CAP_REGULAR: u32 = 1 << 2;
/// File is a socket.
pub const FD_CAP_SOCKET: u32 = 1 << 3;
/// File is a pipe.
pub const FD_CAP_PIPE: u32 = 1 << 4;
/// File supports `mmap` (page-cache backed).
pub const FD_CAP_MMAP: u32 = 1 << 5;

// ---------------------------------------------------------------------------
// SendfileOffset — offset tracking
// ---------------------------------------------------------------------------

/// Offset state for `sendfile`.
///
/// If the caller provides an explicit offset, it is used (and updated on
/// return) without touching the file position.  If `None`, the file position
/// is used and advanced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendfileOffset {
    /// Use the file position (and advance it).
    FilePosition,
    /// Use and update the explicit offset.
    Explicit(u64),
}

impl SendfileOffset {
    /// Resolve to a concrete byte offset, given the current file position.
    pub const fn resolve(self, file_pos: u64) -> u64 {
        match self {
            Self::FilePosition => file_pos,
            Self::Explicit(off) => off,
        }
    }

    /// Create from an `Option<u64>`.
    pub fn from_option(opt: Option<u64>) -> Self {
        match opt {
            None => Self::FilePosition,
            Some(off) => Self::Explicit(off),
        }
    }
}

// ---------------------------------------------------------------------------
// SendfileState — per-system state
// ---------------------------------------------------------------------------

/// A stub file descriptor entry for the sendfile subsystem.
#[derive(Debug, Clone, Copy)]
pub struct FdEntry {
    /// Numeric file descriptor.
    pub fd: i32,
    /// Capability flags.
    pub caps: u32,
    /// File size in bytes (for regular files).
    pub size: u64,
    /// Current file position.
    pub position: u64,
    /// Whether this slot is in use.
    pub in_use: bool,
}

impl FdEntry {
    /// Create an empty, unused entry.
    const fn empty() -> Self {
        Self {
            fd: -1,
            caps: 0,
            size: 0,
            position: 0,
            in_use: false,
        }
    }
}

/// Stub file descriptor table for `sendfile`.
pub struct SendfileState {
    /// File descriptor entries.
    entries: [FdEntry; MAX_FD_ENTRIES],
    /// Number of active entries.
    count: usize,
}

impl SendfileState {
    /// Create an empty state.
    pub const fn new() -> Self {
        Self {
            entries: [const { FdEntry::empty() }; MAX_FD_ENTRIES],
            count: 0,
        }
    }

    /// Register a file descriptor.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] — table full.
    pub fn insert(&mut self, entry: FdEntry) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if !slot.in_use {
                *slot = entry;
                slot.in_use = true;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a file descriptor.
    pub fn find(&self, fd: i32) -> Option<&FdEntry> {
        self.entries.iter().find(|e| e.in_use && e.fd == fd)
    }

    /// Look up a file descriptor (mutable).
    pub fn find_mut(&mut self, fd: i32) -> Option<&mut FdEntry> {
        self.entries.iter_mut().find(|e| e.in_use && e.fd == fd)
    }

    /// Remove a file descriptor entry.
    pub fn remove(&mut self, fd: i32) {
        for slot in self.entries.iter_mut() {
            if slot.in_use && slot.fd == fd {
                *slot = FdEntry::empty();
                self.count = self.count.saturating_sub(1);
                return;
            }
        }
    }

    /// Return the number of active entries.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for SendfileState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TransferInfo — transfer result
// ---------------------------------------------------------------------------

/// Result of a successful `sendfile64` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferInfo {
    /// Number of bytes actually transferred.
    pub bytes_sent: usize,
    /// New source offset after the transfer.
    pub new_offset: u64,
    /// Whether the end of the source file was reached.
    pub eof_reached: bool,
}

// ---------------------------------------------------------------------------
// SendfileStats — statistics
// ---------------------------------------------------------------------------

/// Accumulated statistics for the `sendfile` subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct SendfileStats {
    /// Total `sendfile64` calls.
    pub total_calls: u64,
    /// Total bytes transferred.
    pub bytes_sent: u64,
    /// Number of short transfers (less than requested).
    pub short_transfers: u64,
    /// Number of EOF conditions encountered.
    pub eof_count: u64,
    /// Number of zero-byte transfers (offset at or past EOF).
    pub zero_transfers: u64,
}

impl SendfileStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_calls: 0,
            bytes_sent: 0,
            short_transfers: 0,
            eof_count: 0,
            zero_transfers: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate a file descriptor number.
fn validate_fd(fd: i32) -> Result<()> {
    if fd < MIN_FD || fd > MAX_FD {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate a transfer count.
fn validate_count(count: usize) -> Result<()> {
    if count == 0 {
        return Err(Error::InvalidArgument);
    }
    if count > SENDFILE_MAX_COUNT {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate an offset.
fn validate_offset(offset: u64) -> Result<()> {
    if offset > MAX_FILE_SIZE {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// setup_transfer — pre-transfer validation and resolution
// ---------------------------------------------------------------------------

/// Validate both file descriptors and resolve the source offset.
///
/// Checks:
/// - `in_fd` exists and is readable.
/// - `out_fd` exists and is writable.
/// - `in_fd` is a regular file (mmap-capable).
/// - `in_fd != out_fd`.
/// - Offset is within bounds.
///
/// # Returns
///
/// `(source_offset, source_size)` on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Bad fd, count, or offset.
/// * [`Error::NotFound`]        — fd not in table.
/// * [`Error::PermissionDenied`] — fd lacks required capability.
/// * [`Error::IoError`]         — in_fd is not a regular file.
fn setup_transfer(
    state: &SendfileState,
    in_fd: i32,
    out_fd: i32,
    offset: SendfileOffset,
    count: usize,
) -> Result<(u64, u64)> {
    validate_fd(in_fd)?;
    validate_fd(out_fd)?;
    validate_count(count)?;

    if in_fd == out_fd {
        return Err(Error::InvalidArgument);
    }

    let in_entry = state.find(in_fd).ok_or(Error::NotFound)?;
    let out_entry = state.find(out_fd).ok_or(Error::NotFound)?;

    // Capability checks.
    if in_entry.caps & FD_CAP_READ == 0 {
        return Err(Error::PermissionDenied);
    }
    if out_entry.caps & FD_CAP_WRITE == 0 {
        return Err(Error::PermissionDenied);
    }

    // Source must support mmap (regular file with page cache).
    if in_entry.caps & FD_CAP_MMAP == 0 {
        return Err(Error::IoError);
    }

    let src_offset = offset.resolve(in_entry.position);
    validate_offset(src_offset)?;

    Ok((src_offset, in_entry.size))
}

// ---------------------------------------------------------------------------
// handle_eof — end-of-file detection
// ---------------------------------------------------------------------------

/// Determine whether the source offset is at or past end-of-file.
///
/// # Returns
///
/// `true` if `offset >= file_size`.
pub const fn handle_eof(offset: u64, file_size: u64) -> bool {
    offset >= file_size
}

/// Compute the actual number of bytes available from `offset` given
/// the file size.  Returns 0 if already at/past EOF.
pub const fn available_bytes(offset: u64, file_size: u64, count: usize) -> usize {
    if offset >= file_size {
        return 0;
    }
    let avail = file_size - offset;
    if avail > count as u64 {
        count
    } else {
        avail as usize
    }
}

// ---------------------------------------------------------------------------
// do_sendfile — core transfer logic
// ---------------------------------------------------------------------------

/// Core `sendfile64` implementation.
///
/// Transfers up to `count` bytes from `in_fd` at the given offset to
/// `out_fd`.  A short transfer occurs when the source has fewer bytes
/// available than requested; this is not an error.
///
/// # Arguments
///
/// * `state`  — File descriptor table.
/// * `stats`  — Statistics accumulator.
/// * `out_fd` — Destination file descriptor (socket, pipe, or file).
/// * `in_fd`  — Source file descriptor (must be mmap-capable / regular file).
/// * `offset` — Source offset handling mode.
/// * `count`  — Maximum number of bytes to transfer.
///
/// # Returns
///
/// A [`TransferInfo`] on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Invalid fd, count, or offset.
/// * [`Error::NotFound`]        — fd not found.
/// * [`Error::PermissionDenied`] — Insufficient capabilities.
/// * [`Error::IoError`]         — Source is not a regular file.
pub fn do_sendfile(
    state: &mut SendfileState,
    stats: &mut SendfileStats,
    out_fd: i32,
    in_fd: i32,
    offset: SendfileOffset,
    count: usize,
) -> Result<TransferInfo> {
    stats.total_calls += 1;

    let (src_offset, src_size) = setup_transfer(state, in_fd, out_fd, offset, count)?;

    // EOF detection.
    let eof = handle_eof(src_offset, src_size);
    let actual = available_bytes(src_offset, src_size, count);

    if actual == 0 {
        stats.zero_transfers += 1;
        if eof {
            stats.eof_count += 1;
        }
        return Ok(TransferInfo {
            bytes_sent: 0,
            new_offset: src_offset,
            eof_reached: eof,
        });
    }

    // In a real kernel: read from page cache, write to socket/pipe buffer.
    // Stub: simulate the transfer by advancing offsets and sizes.

    let new_offset = src_offset + actual as u64;
    let eof_after = new_offset >= src_size;

    // Update source file position if using file position mode.
    if matches!(offset, SendfileOffset::FilePosition) {
        if let Some(entry) = state.find_mut(in_fd) {
            entry.position = new_offset;
        }
    }

    // Track statistics.
    stats.bytes_sent += actual as u64;
    if actual < count {
        stats.short_transfers += 1;
    }
    if eof_after {
        stats.eof_count += 1;
    }

    Ok(TransferInfo {
        bytes_sent: actual,
        new_offset,
        eof_reached: eof_after,
    })
}

// ---------------------------------------------------------------------------
// sys_sendfile64 — syscall entry point
// ---------------------------------------------------------------------------

/// `sendfile64(2)` — transfer data from a file to a socket/pipe/file.
///
/// This is the raw syscall entry point that converts register-width
/// arguments and delegates to [`do_sendfile`].
///
/// # Arguments
///
/// * `state`     — File descriptor table.
/// * `stats`     — Statistics accumulator.
/// * `out_fd`    — Raw destination fd.
/// * `in_fd`     — Raw source fd.
/// * `offset`    — Optional explicit offset (`None` = use file position).
/// * `count`     — Raw count from registers.
///
/// # Returns
///
/// A [`TransferInfo`] on success.
pub fn sys_sendfile64(
    state: &mut SendfileState,
    stats: &mut SendfileStats,
    out_fd: i32,
    in_fd: i32,
    offset: Option<u64>,
    count: usize,
) -> Result<TransferInfo> {
    let off = SendfileOffset::from_option(offset);
    do_sendfile(state, stats, out_fd, in_fd, off, count)
}

// ---------------------------------------------------------------------------
// sys_sendfile64_raw — raw register-width entry point
// ---------------------------------------------------------------------------

/// Process a raw `sendfile64` syscall from register-width values.
///
/// Validates that `out_fd` and `in_fd` fit in `i32`, `count` in `usize`,
/// and delegates to [`sys_sendfile64`].
pub fn sys_sendfile64_raw(
    state: &mut SendfileState,
    stats: &mut SendfileStats,
    out_fd: u64,
    in_fd: u64,
    offset: u64,
    count: u64,
    has_offset: bool,
) -> Result<TransferInfo> {
    let out = i32::try_from(out_fd).map_err(|_| Error::InvalidArgument)?;
    let inp = i32::try_from(in_fd).map_err(|_| Error::InvalidArgument)?;
    let cnt = usize::try_from(count).map_err(|_| Error::InvalidArgument)?;
    let off = if has_offset { Some(offset) } else { None };
    sys_sendfile64(state, stats, out, inp, off, cnt)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state() -> SendfileState {
        let mut s = SendfileState::new();
        // in_fd=3: readable, regular, mmap-capable, 8192 bytes
        s.insert(FdEntry {
            fd: 3,
            caps: FD_CAP_READ | FD_CAP_REGULAR | FD_CAP_MMAP,
            size: 8192,
            position: 0,
            in_use: true,
        })
        .unwrap();
        // out_fd=4: writable socket
        s.insert(FdEntry {
            fd: 4,
            caps: FD_CAP_WRITE | FD_CAP_SOCKET,
            size: 0,
            position: 0,
            in_use: true,
        })
        .unwrap();
        s
    }

    // --- SendfileOffset ---

    #[test]
    fn offset_file_position() {
        let off = SendfileOffset::FilePosition;
        assert_eq!(off.resolve(1024), 1024);
    }

    #[test]
    fn offset_explicit() {
        let off = SendfileOffset::Explicit(512);
        assert_eq!(off.resolve(1024), 512);
    }

    #[test]
    fn offset_from_option() {
        assert_eq!(
            SendfileOffset::from_option(None),
            SendfileOffset::FilePosition
        );
        assert_eq!(
            SendfileOffset::from_option(Some(100)),
            SendfileOffset::Explicit(100)
        );
    }

    // --- handle_eof ---

    #[test]
    fn eof_at_end() {
        assert!(handle_eof(8192, 8192));
    }

    #[test]
    fn eof_past_end() {
        assert!(handle_eof(9000, 8192));
    }

    #[test]
    fn not_eof() {
        assert!(!handle_eof(4096, 8192));
    }

    // --- available_bytes ---

    #[test]
    fn available_full() {
        assert_eq!(available_bytes(0, 8192, 4096), 4096);
    }

    #[test]
    fn available_partial() {
        assert_eq!(available_bytes(7000, 8192, 4096), 1192);
    }

    #[test]
    fn available_at_eof() {
        assert_eq!(available_bytes(8192, 8192, 4096), 0);
    }

    // --- validation ---

    #[test]
    fn validate_fd_negative() {
        assert_eq!(validate_fd(-1), Err(Error::InvalidArgument));
    }

    #[test]
    fn validate_fd_too_large() {
        assert_eq!(validate_fd(MAX_FD + 1), Err(Error::InvalidArgument));
    }

    #[test]
    fn validate_fd_ok() {
        assert!(validate_fd(3).is_ok());
    }

    #[test]
    fn validate_count_zero() {
        assert_eq!(validate_count(0), Err(Error::InvalidArgument));
    }

    #[test]
    fn validate_count_too_large() {
        assert_eq!(
            validate_count(SENDFILE_MAX_COUNT + 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_count_ok() {
        assert!(validate_count(4096).is_ok());
    }

    #[test]
    fn validate_offset_too_large() {
        assert_eq!(
            validate_offset(MAX_FILE_SIZE + 1),
            Err(Error::InvalidArgument)
        );
    }

    // --- SendfileState ---

    #[test]
    fn state_insert_and_find() {
        let s = make_state();
        assert!(s.find(3).is_some());
        assert!(s.find(4).is_some());
        assert!(s.find(99).is_none());
    }

    #[test]
    fn state_remove() {
        let mut s = make_state();
        s.remove(3);
        assert!(s.find(3).is_none());
        assert_eq!(s.count(), 1);
    }

    // --- do_sendfile ---

    #[test]
    fn sendfile_full_transfer() {
        let mut s = make_state();
        let mut stats = SendfileStats::new();

        let r = do_sendfile(&mut s, &mut stats, 4, 3, SendfileOffset::Explicit(0), 4096).unwrap();

        assert_eq!(r.bytes_sent, 4096);
        assert_eq!(r.new_offset, 4096);
        assert!(!r.eof_reached);
        assert_eq!(stats.bytes_sent, 4096);
        assert_eq!(stats.total_calls, 1);
    }

    #[test]
    fn sendfile_short_transfer() {
        let mut s = make_state();
        let mut stats = SendfileStats::new();

        // Request more than available.
        let r = do_sendfile(
            &mut s,
            &mut stats,
            4,
            3,
            SendfileOffset::Explicit(4000),
            8192,
        )
        .unwrap();

        assert_eq!(r.bytes_sent, 4192); // 8192 - 4000
        assert!(r.eof_reached);
        assert_eq!(stats.short_transfers, 1);
    }

    #[test]
    fn sendfile_at_eof() {
        let mut s = make_state();
        let mut stats = SendfileStats::new();

        let r = do_sendfile(
            &mut s,
            &mut stats,
            4,
            3,
            SendfileOffset::Explicit(8192),
            1024,
        )
        .unwrap();

        assert_eq!(r.bytes_sent, 0);
        assert!(r.eof_reached);
        assert_eq!(stats.zero_transfers, 1);
        assert_eq!(stats.eof_count, 1);
    }

    #[test]
    fn sendfile_advances_file_position() {
        let mut s = make_state();
        let mut stats = SendfileStats::new();

        do_sendfile(&mut s, &mut stats, 4, 3, SendfileOffset::FilePosition, 2048).unwrap();

        assert_eq!(s.find(3).unwrap().position, 2048);
    }

    #[test]
    fn sendfile_explicit_offset_does_not_advance_position() {
        let mut s = make_state();
        let mut stats = SendfileStats::new();

        do_sendfile(
            &mut s,
            &mut stats,
            4,
            3,
            SendfileOffset::Explicit(1024),
            2048,
        )
        .unwrap();

        // Position should remain 0 since we used explicit offset.
        assert_eq!(s.find(3).unwrap().position, 0);
    }

    #[test]
    fn sendfile_same_fd_rejected() {
        let mut s = make_state();
        let mut stats = SendfileStats::new();

        assert_eq!(
            do_sendfile(&mut s, &mut stats, 3, 3, SendfileOffset::Explicit(0), 1024),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn sendfile_missing_in_fd() {
        let mut s = make_state();
        let mut stats = SendfileStats::new();

        assert_eq!(
            do_sendfile(&mut s, &mut stats, 4, 99, SendfileOffset::Explicit(0), 1024),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn sendfile_missing_out_fd() {
        let mut s = make_state();
        let mut stats = SendfileStats::new();

        assert_eq!(
            do_sendfile(&mut s, &mut stats, 99, 3, SendfileOffset::Explicit(0), 1024),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn sendfile_non_readable_source() {
        let mut s = SendfileState::new();
        s.insert(FdEntry {
            fd: 3,
            caps: FD_CAP_WRITE | FD_CAP_REGULAR | FD_CAP_MMAP, // no READ
            size: 4096,
            position: 0,
            in_use: true,
        })
        .unwrap();
        s.insert(FdEntry {
            fd: 4,
            caps: FD_CAP_WRITE | FD_CAP_SOCKET,
            size: 0,
            position: 0,
            in_use: true,
        })
        .unwrap();
        let mut stats = SendfileStats::new();

        assert_eq!(
            do_sendfile(&mut s, &mut stats, 4, 3, SendfileOffset::Explicit(0), 1024),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn sendfile_non_writable_dest() {
        let mut s = SendfileState::new();
        s.insert(FdEntry {
            fd: 3,
            caps: FD_CAP_READ | FD_CAP_REGULAR | FD_CAP_MMAP,
            size: 4096,
            position: 0,
            in_use: true,
        })
        .unwrap();
        s.insert(FdEntry {
            fd: 4,
            caps: FD_CAP_READ | FD_CAP_SOCKET, // no WRITE
            size: 0,
            position: 0,
            in_use: true,
        })
        .unwrap();
        let mut stats = SendfileStats::new();

        assert_eq!(
            do_sendfile(&mut s, &mut stats, 4, 3, SendfileOffset::Explicit(0), 1024),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn sendfile_non_mmap_source() {
        let mut s = SendfileState::new();
        s.insert(FdEntry {
            fd: 3,
            caps: FD_CAP_READ | FD_CAP_PIPE, // pipe, not regular/mmap
            size: 4096,
            position: 0,
            in_use: true,
        })
        .unwrap();
        s.insert(FdEntry {
            fd: 4,
            caps: FD_CAP_WRITE | FD_CAP_SOCKET,
            size: 0,
            position: 0,
            in_use: true,
        })
        .unwrap();
        let mut stats = SendfileStats::new();

        assert_eq!(
            do_sendfile(&mut s, &mut stats, 4, 3, SendfileOffset::Explicit(0), 1024),
            Err(Error::IoError)
        );
    }

    // --- sys_sendfile64 ---

    #[test]
    fn sys_sendfile64_basic() {
        let mut s = make_state();
        let mut stats = SendfileStats::new();

        let r = sys_sendfile64(&mut s, &mut stats, 4, 3, Some(0), 2048).unwrap();
        assert_eq!(r.bytes_sent, 2048);
    }

    #[test]
    fn sys_sendfile64_no_offset() {
        let mut s = make_state();
        let mut stats = SendfileStats::new();

        let r = sys_sendfile64(&mut s, &mut stats, 4, 3, None, 1024).unwrap();
        assert_eq!(r.bytes_sent, 1024);
        assert_eq!(s.find(3).unwrap().position, 1024);
    }

    // --- sys_sendfile64_raw ---

    #[test]
    fn sys_sendfile64_raw_basic() {
        let mut s = make_state();
        let mut stats = SendfileStats::new();

        let r = sys_sendfile64_raw(&mut s, &mut stats, 4, 3, 0, 2048, true).unwrap();
        assert_eq!(r.bytes_sent, 2048);
    }

    #[test]
    fn sys_sendfile64_raw_no_offset() {
        let mut s = make_state();
        let mut stats = SendfileStats::new();

        let r = sys_sendfile64_raw(&mut s, &mut stats, 4, 3, 0, 1024, false).unwrap();
        assert_eq!(r.bytes_sent, 1024);
    }

    #[test]
    fn sys_sendfile64_raw_bad_fd() {
        let mut s = make_state();
        let mut stats = SendfileStats::new();

        // fd that exceeds i32
        let result = sys_sendfile64_raw(&mut s, &mut stats, u64::MAX, 3, 0, 1024, true);
        assert_eq!(result, Err(Error::InvalidArgument));
    }

    // --- Stats ---

    #[test]
    fn stats_accumulate() {
        let mut s = make_state();
        let mut stats = SendfileStats::new();

        do_sendfile(&mut s, &mut stats, 4, 3, SendfileOffset::Explicit(0), 2048).unwrap();
        do_sendfile(
            &mut s,
            &mut stats,
            4,
            3,
            SendfileOffset::Explicit(2048),
            2048,
        )
        .unwrap();

        assert_eq!(stats.total_calls, 2);
        assert_eq!(stats.bytes_sent, 4096);
    }

    #[test]
    fn stats_eof_and_short() {
        let mut s = make_state();
        let mut stats = SendfileStats::new();

        // Short transfer (request more than available).
        do_sendfile(
            &mut s,
            &mut stats,
            4,
            3,
            SendfileOffset::Explicit(7000),
            4096,
        )
        .unwrap();

        assert_eq!(stats.short_transfers, 1);
        assert_eq!(stats.eof_count, 1);
        assert_eq!(stats.bytes_sent, 1192);
    }

    // --- Multiple sequential transfers ---

    #[test]
    fn sequential_transfers_with_file_position() {
        let mut s = make_state();
        let mut stats = SendfileStats::new();

        let r1 = do_sendfile(&mut s, &mut stats, 4, 3, SendfileOffset::FilePosition, 2048).unwrap();
        assert_eq!(r1.bytes_sent, 2048);
        assert_eq!(s.find(3).unwrap().position, 2048);

        let r2 = do_sendfile(&mut s, &mut stats, 4, 3, SendfileOffset::FilePosition, 2048).unwrap();
        assert_eq!(r2.bytes_sent, 2048);
        assert_eq!(s.find(3).unwrap().position, 4096);

        assert_eq!(stats.total_calls, 2);
        assert_eq!(stats.bytes_sent, 4096);
    }

    // --- TransferInfo ---

    #[test]
    fn transfer_info_fields() {
        let info = TransferInfo {
            bytes_sent: 1024,
            new_offset: 1024,
            eof_reached: false,
        };
        assert_eq!(info.bytes_sent, 1024);
        assert!(!info.eof_reached);
    }
}
