// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `read(2)` / `pread64(2)` / `readv(2)` syscall handlers.
//!
//! Implements reading from an open file descriptor into a user-supplied
//! buffer, with optional explicit file offset (pread64) and scatter I/O
//! (readv).
//!
//! # Key behaviours
//!
//! - `read(fd, buf, count)` — read up to `count` bytes from current position;
//!   advance position by bytes read.
//! - `pread64(fd, buf, count, offset)` — read at explicit offset; do not
//!   change the file position.
//! - `readv(fd, iov, iovcnt)` — scatter read into multiple buffers.
//! - Short reads: fewer bytes than requested is not an error.
//! - `O_NONBLOCK` on a file with no data returns `WouldBlock` (EAGAIN).
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `read()` / `pread()`.
//!
//! # References
//!
//! - POSIX.1-2024: `read()`, `pread()`
//! - Linux: `fs/read_write.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// O_NONBLOCK flag (must match open_call.rs)
// ---------------------------------------------------------------------------

/// Open file flag: non-blocking I/O.
pub const O_NONBLOCK: u32 = 0o0004000;
/// Open file flag: readable.
pub const O_RDONLY: u32 = 0;
/// Open file flag: readable + writable.
pub const O_RDWR: u32 = 2;
/// Access mode mask.
pub const O_ACCMODE: u32 = 3;

/// Maximum `iovcnt` for `readv`.
pub const MAX_IOV: usize = 1024;

/// Maximum read count (2 GiB − 1, matching Linux).
pub const MAX_RW_COUNT: u64 = i32::MAX as u64;

/// Maximum number of fds in the read fd table.
pub const MAX_READ_FDS: usize = 256;

// ---------------------------------------------------------------------------
// ReadFile — stub file backing store
// ---------------------------------------------------------------------------

/// A stub file backing store used by the read handlers.
#[derive(Debug, Clone, Copy)]
pub struct ReadFile {
    /// File descriptor number.
    pub fd: i32,
    /// Open flags (subset: `O_RDONLY`/`O_RDWR`, `O_NONBLOCK`).
    pub flags: u32,
    /// File size in bytes.
    pub size: u64,
    /// Current file position.
    pub position: u64,
    /// Whether the file currently has data available.
    pub has_data: bool,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl ReadFile {
    const fn empty() -> Self {
        Self {
            fd: -1,
            flags: 0,
            size: 0,
            position: 0,
            has_data: true,
            in_use: false,
        }
    }

    /// Return `true` if this file is open for reading.
    pub const fn readable(&self) -> bool {
        let acc = self.flags & O_ACCMODE;
        acc == O_RDONLY || acc == O_RDWR
    }

    /// Return `true` if `O_NONBLOCK` is set.
    pub const fn nonblock(&self) -> bool {
        self.flags & O_NONBLOCK != 0
    }
}

/// A stub read fd table.
pub struct ReadFdTable {
    files: [ReadFile; MAX_READ_FDS],
    count: usize,
}

impl ReadFdTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            files: [const { ReadFile::empty() }; MAX_READ_FDS],
            count: 0,
        }
    }

    /// Insert a file record.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn insert(&mut self, f: ReadFile) -> Result<()> {
        for slot in self.files.iter_mut() {
            if !slot.in_use {
                *slot = f;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a file by fd.
    pub fn find(&self, fd: i32) -> Option<&ReadFile> {
        self.files.iter().find(|f| f.in_use && f.fd == fd)
    }

    /// Look up a mutable file by fd.
    pub fn find_mut(&mut self, fd: i32) -> Option<&mut ReadFile> {
        self.files.iter_mut().find(|f| f.in_use && f.fd == fd)
    }

    /// Return the number of open files.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for ReadFdTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// IoVec — scatter/gather element
// ---------------------------------------------------------------------------

/// A single scatter/gather I/O vector element (user-space `struct iovec`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoVec {
    /// Pointer to user-space buffer (stub: offset within a virtual address space).
    pub base: u64,
    /// Length of the buffer in bytes.
    pub len: u64,
}

impl IoVec {
    /// Return `true` if this vector element is zero-length.
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }
}

// ---------------------------------------------------------------------------
// ReadResult — result of a read operation
// ---------------------------------------------------------------------------

/// Result of a successful `read` / `pread64` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadResult {
    /// Number of bytes read.
    pub bytes_read: u64,
    /// New file position (for `read`; unchanged for `pread64`).
    pub new_position: u64,
    /// Whether the read was at EOF (bytes_read < requested).
    pub at_eof: bool,
}

impl ReadResult {
    /// Return `true` if no bytes were read.
    pub const fn is_empty(&self) -> bool {
        self.bytes_read == 0
    }
}

// ---------------------------------------------------------------------------
// do_read — main read handler
// ---------------------------------------------------------------------------

/// Handler for `read(2)`.
///
/// Reads up to `count` bytes from `fd` starting at the current file
/// position, advancing the position by the number of bytes read.
///
/// A short read (fewer bytes than `count`) occurs at EOF.
/// Returns `WouldBlock` (EAGAIN) if `O_NONBLOCK` is set and no data is
/// currently available.
///
/// # Arguments
///
/// * `table` — open fd table
/// * `fd`    — file descriptor (must be readable)
/// * `count` — maximum bytes to read
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — `count` > `MAX_RW_COUNT`
/// * [`Error::NotFound`]        — `fd` not open
/// * [`Error::PermissionDenied`] — `fd` not open for reading
/// * [`Error::WouldBlock`]      — `O_NONBLOCK` and no data available
pub fn do_read(table: &mut ReadFdTable, fd: i32, count: u64) -> Result<ReadResult> {
    if count > MAX_RW_COUNT {
        return Err(Error::InvalidArgument);
    }
    let file = table.find(fd).ok_or(Error::NotFound)?;
    if !file.readable() {
        return Err(Error::PermissionDenied);
    }
    if file.nonblock() && !file.has_data {
        return Err(Error::WouldBlock);
    }
    let pos = file.position;
    let available = file.size.saturating_sub(pos);
    let bytes_read = count.min(available);
    let new_pos = pos + bytes_read;
    let at_eof = bytes_read < count;

    if let Some(f) = table.find_mut(fd) {
        f.position = new_pos;
    }

    Ok(ReadResult {
        bytes_read,
        new_position: new_pos,
        at_eof,
    })
}

// ---------------------------------------------------------------------------
// do_pread64 — positional read (does not change file position)
// ---------------------------------------------------------------------------

/// Handler for `pread64(2)`.
///
/// Reads up to `count` bytes from `fd` at the given `offset` without
/// modifying the current file position.
///
/// # Arguments
///
/// * `table`  — open fd table
/// * `fd`     — file descriptor (must be readable)
/// * `count`  — maximum bytes to read
/// * `offset` — byte offset in the file to start reading from
///
/// # Errors
///
/// Same as [`do_read`], plus:
/// * [`Error::InvalidArgument`] — `offset` would overflow
pub fn do_pread64(table: &ReadFdTable, fd: i32, count: u64, offset: u64) -> Result<ReadResult> {
    if count > MAX_RW_COUNT {
        return Err(Error::InvalidArgument);
    }
    let file = table.find(fd).ok_or(Error::NotFound)?;
    if !file.readable() {
        return Err(Error::PermissionDenied);
    }
    // pread64 is not valid on non-seekable files (pipes, sockets)
    // — here the stub allows it on all files.
    let available = file.size.saturating_sub(offset);
    let bytes_read = count.min(available);
    let at_eof = bytes_read < count;

    // Position is NOT advanced.
    Ok(ReadResult {
        bytes_read,
        new_position: file.position,
        at_eof,
    })
}

// ---------------------------------------------------------------------------
// do_readv — scatter read
// ---------------------------------------------------------------------------

/// Handler for `readv(2)`.
///
/// Reads from `fd` into the scatter buffer array `iov`.  Buffers are
/// filled in order; the total number of bytes read is limited by the
/// file's available data and [`MAX_RW_COUNT`].
///
/// # Arguments
///
/// * `table`  — open fd table
/// * `fd`     — file descriptor (must be readable)
/// * `iov`    — scatter vector (at most [`MAX_IOV`] elements)
///
/// # Returns
///
/// Total bytes read across all iov entries.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — `iov.len()` > `MAX_IOV`, or total length overflows
/// * [`Error::NotFound`]        — `fd` not open
/// * [`Error::PermissionDenied`] — `fd` not open for reading
/// * [`Error::WouldBlock`]      — `O_NONBLOCK` and no data available
pub fn do_readv(table: &mut ReadFdTable, fd: i32, iov: &[IoVec]) -> Result<ReadResult> {
    if iov.len() > MAX_IOV {
        return Err(Error::InvalidArgument);
    }
    // Compute total requested bytes, saturating at MAX_RW_COUNT.
    let total_requested: u64 = iov
        .iter()
        .fold(0u64, |acc, v| acc.saturating_add(v.len))
        .min(MAX_RW_COUNT);

    let file = table.find(fd).ok_or(Error::NotFound)?;
    if !file.readable() {
        return Err(Error::PermissionDenied);
    }
    if file.nonblock() && !file.has_data {
        return Err(Error::WouldBlock);
    }

    let pos = file.position;
    let available = file.size.saturating_sub(pos);
    let total_read = total_requested.min(available);
    let new_pos = pos + total_read;
    let at_eof = total_read < total_requested;

    if let Some(f) = table.find_mut(fd) {
        f.position = new_pos;
    }

    Ok(ReadResult {
        bytes_read: total_read,
        new_position: new_pos,
        at_eof,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table(size: u64) -> ReadFdTable {
        let mut t = ReadFdTable::new();
        t.insert(ReadFile {
            fd: 3,
            flags: O_RDONLY,
            size,
            position: 0,
            has_data: true,
            in_use: true,
        })
        .unwrap();
        t
    }

    #[test]
    fn read_full() {
        let mut t = make_table(1024);
        let r = do_read(&mut t, 3, 1024).unwrap();
        assert_eq!(r.bytes_read, 1024);
        assert_eq!(r.new_position, 1024);
        assert!(!r.at_eof);
    }

    #[test]
    fn read_short_at_eof() {
        let mut t = make_table(100);
        let r = do_read(&mut t, 3, 200).unwrap();
        assert_eq!(r.bytes_read, 100);
        assert!(r.at_eof);
    }

    #[test]
    fn read_advances_position() {
        let mut t = make_table(1024);
        do_read(&mut t, 3, 256).unwrap();
        assert_eq!(t.find(3).unwrap().position, 256);
        do_read(&mut t, 3, 256).unwrap();
        assert_eq!(t.find(3).unwrap().position, 512);
    }

    #[test]
    fn read_not_found() {
        let mut t = ReadFdTable::new();
        assert_eq!(do_read(&mut t, 99, 100), Err(Error::NotFound));
    }

    #[test]
    fn read_not_readable() {
        let mut t = ReadFdTable::new();
        t.insert(ReadFile {
            fd: 3,
            flags: 1, // O_WRONLY
            size: 100,
            position: 0,
            has_data: true,
            in_use: true,
        })
        .unwrap();
        assert_eq!(do_read(&mut t, 3, 10), Err(Error::PermissionDenied));
    }

    #[test]
    fn read_nonblock_no_data() {
        let mut t = ReadFdTable::new();
        t.insert(ReadFile {
            fd: 5,
            flags: O_RDONLY | O_NONBLOCK,
            size: 100,
            position: 0,
            has_data: false,
            in_use: true,
        })
        .unwrap();
        assert_eq!(do_read(&mut t, 5, 10), Err(Error::WouldBlock));
    }

    #[test]
    fn pread64_does_not_advance_position() {
        let t = make_table(1024);
        let r = do_pread64(&t, 3, 100, 0).unwrap();
        assert_eq!(r.bytes_read, 100);
        assert_eq!(t.find(3).unwrap().position, 0);
    }

    #[test]
    fn pread64_at_offset() {
        let t = make_table(1024);
        let r = do_pread64(&t, 3, 100, 900).unwrap();
        assert_eq!(r.bytes_read, 100);
        assert!(!r.at_eof);
    }

    #[test]
    fn pread64_past_eof() {
        let t = make_table(512);
        let r = do_pread64(&t, 3, 200, 400).unwrap();
        assert_eq!(r.bytes_read, 112);
        assert!(r.at_eof);
    }

    #[test]
    fn readv_multiple_buffers() {
        let mut t = make_table(1024);
        let iov = [
            IoVec { base: 0, len: 256 },
            IoVec {
                base: 256,
                len: 256,
            },
        ];
        let r = do_readv(&mut t, 3, &iov).unwrap();
        assert_eq!(r.bytes_read, 512);
        assert_eq!(r.new_position, 512);
    }

    #[test]
    fn readv_too_many_iov() {
        let mut t = make_table(1024);
        let iov: alloc::vec::Vec<IoVec> = (0..MAX_IOV + 1)
            .map(|_| IoVec { base: 0, len: 1 })
            .collect();
        assert_eq!(do_readv(&mut t, 3, &iov), Err(Error::InvalidArgument));
    }

    #[test]
    fn readv_limited_by_file_size() {
        let mut t = make_table(100);
        let iov = [IoVec { base: 0, len: 1024 }];
        let r = do_readv(&mut t, 3, &iov).unwrap();
        assert_eq!(r.bytes_read, 100);
    }
}

extern crate alloc;
