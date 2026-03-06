// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `write(2)` / `pwrite64(2)` / `writev(2)` syscall handlers.
//!
//! Implements writing to an open file descriptor from a user-supplied
//! buffer, with optional explicit file offset (pwrite64) and gather I/O
//! (writev).
//!
//! # Key behaviours
//!
//! - `write(fd, buf, count)` — write up to `count` bytes at current position.
//!   Advance position by bytes written.
//! - `pwrite64(fd, buf, count, offset)` — write at explicit offset; do not
//!   change the file position.
//! - `writev(fd, iov, iovcnt)` — gather write from multiple buffers.
//! - `O_APPEND`: each write atomically seeks to end-of-file first.
//! - Broken pipe: writing to a pipe/socket with no reader delivers `SIGPIPE`
//!   and returns `IoError` (EPIPE).
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `write()` / `pwrite()`.
//!
//! # References
//!
//! - POSIX.1-2024: `write()`, `pwrite()`
//! - Linux: `fs/read_write.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Access mode: write-only.
pub const O_WRONLY: u32 = 1;
/// Access mode: read + write.
pub const O_RDWR: u32 = 2;
/// Access mode mask.
pub const O_ACCMODE: u32 = 3;
/// Append flag: writes always go to EOF.
pub const O_APPEND: u32 = 0o0002000;
/// Non-blocking flag.
pub const O_NONBLOCK: u32 = 0o0004000;

/// Maximum `iovcnt` for `writev`.
pub const MAX_IOV: usize = 1024;

/// Maximum write count (2 GiB − 1, matching Linux).
pub const MAX_RW_COUNT: u64 = i32::MAX as u64;

/// Maximum number of files in the write fd table.
pub const MAX_WRITE_FDS: usize = 256;

// ---------------------------------------------------------------------------
// WriteFile — stub file for the write layer
// ---------------------------------------------------------------------------

/// A stub file backing store for the write handlers.
#[derive(Debug, Clone, Copy)]
pub struct WriteFile {
    /// File descriptor number.
    pub fd: i32,
    /// Open flags subset: access mode, `O_APPEND`, `O_NONBLOCK`.
    pub flags: u32,
    /// Current file size in bytes.
    pub size: u64,
    /// Current file position.
    pub position: u64,
    /// Whether the "other end" is connected (pipe / socket).
    /// If `false` a write returns EPIPE.
    pub peer_connected: bool,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl WriteFile {
    const fn empty() -> Self {
        Self {
            fd: -1,
            flags: 0,
            size: 0,
            position: 0,
            peer_connected: true,
            in_use: false,
        }
    }

    /// Return `true` if this file is open for writing.
    pub const fn writable(&self) -> bool {
        let acc = self.flags & O_ACCMODE;
        acc == O_WRONLY || acc == O_RDWR
    }

    /// Return `true` if `O_APPEND` is set.
    pub const fn is_append(&self) -> bool {
        self.flags & O_APPEND != 0
    }
}

/// A stub write fd table.
pub struct WriteFdTable {
    files: [WriteFile; MAX_WRITE_FDS],
    count: usize,
}

impl WriteFdTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            files: [const { WriteFile::empty() }; MAX_WRITE_FDS],
            count: 0,
        }
    }

    /// Insert a file record.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn insert(&mut self, f: WriteFile) -> Result<()> {
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
    pub fn find(&self, fd: i32) -> Option<&WriteFile> {
        self.files.iter().find(|f| f.in_use && f.fd == fd)
    }

    /// Look up a mutable file by fd.
    pub fn find_mut(&mut self, fd: i32) -> Option<&mut WriteFile> {
        self.files.iter_mut().find(|f| f.in_use && f.fd == fd)
    }

    /// Return the number of open files.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for WriteFdTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// IoVec — scatter/gather element
// ---------------------------------------------------------------------------

/// A single gather I/O vector element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoVec {
    /// Pointer to user-space buffer (stub: virtual address offset).
    pub base: u64,
    /// Length of the buffer in bytes.
    pub len: u64,
}

// ---------------------------------------------------------------------------
// WriteResult — outcome of a write
// ---------------------------------------------------------------------------

/// Result of a successful `write` / `pwrite64` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteResult {
    /// Number of bytes written.
    pub bytes_written: u64,
    /// New file position (updated for `write`; unchanged for `pwrite64`).
    pub new_position: u64,
    /// New file size (may grow if writing past old EOF).
    pub new_size: u64,
}

impl WriteResult {
    /// Return `true` if no bytes were written.
    pub const fn is_empty(&self) -> bool {
        self.bytes_written == 0
    }
}

// ---------------------------------------------------------------------------
// do_write — main write handler
// ---------------------------------------------------------------------------

/// Handler for `write(2)`.
///
/// Writes up to `count` bytes to `fd` at the current file position
/// (or at EOF if `O_APPEND` is set), then advances the position.
///
/// # Arguments
///
/// * `table` — open fd table
/// * `fd`    — file descriptor (must be writable)
/// * `count` — bytes to write
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — `count` > `MAX_RW_COUNT`
/// * [`Error::NotFound`]         — `fd` not open
/// * [`Error::PermissionDenied`] — `fd` not open for writing
/// * [`Error::IoError`]          — broken pipe (EPIPE); caller should deliver
///   `SIGPIPE` to the process
pub fn do_write(table: &mut WriteFdTable, fd: i32, count: u64) -> Result<WriteResult> {
    if count > MAX_RW_COUNT {
        return Err(Error::InvalidArgument);
    }
    let file = table.find(fd).ok_or(Error::NotFound)?;
    if !file.writable() {
        return Err(Error::PermissionDenied);
    }
    if !file.peer_connected {
        // Broken pipe: deliver SIGPIPE / return EPIPE.
        return Err(Error::IoError);
    }
    // O_APPEND: atomic seek to EOF before write.
    let write_pos = if file.is_append() {
        file.size
    } else {
        file.position
    };
    let new_pos = write_pos + count;
    let new_size = new_pos.max(file.size);

    if let Some(f) = table.find_mut(fd) {
        f.position = new_pos;
        f.size = new_size;
    }

    Ok(WriteResult {
        bytes_written: count,
        new_position: new_pos,
        new_size,
    })
}

// ---------------------------------------------------------------------------
// do_pwrite64 — positional write
// ---------------------------------------------------------------------------

/// Handler for `pwrite64(2)`.
///
/// Writes `count` bytes to `fd` at `offset` without modifying the
/// current file position.
///
/// # Arguments
///
/// * `table`  — open fd table
/// * `fd`     — file descriptor (must be writable)
/// * `count`  — bytes to write
/// * `offset` — byte offset at which to start writing
///
/// # Errors
///
/// Same as [`do_write`].
pub fn do_pwrite64(
    table: &mut WriteFdTable,
    fd: i32,
    count: u64,
    offset: u64,
) -> Result<WriteResult> {
    if count > MAX_RW_COUNT {
        return Err(Error::InvalidArgument);
    }
    let file = table.find(fd).ok_or(Error::NotFound)?;
    if !file.writable() {
        return Err(Error::PermissionDenied);
    }
    if !file.peer_connected {
        return Err(Error::IoError);
    }
    let write_end = offset + count;
    let new_size = write_end.max(file.size);
    let saved_position = file.position;

    if let Some(f) = table.find_mut(fd) {
        f.size = new_size;
        // Position is NOT changed.
        f.position = saved_position;
    }

    Ok(WriteResult {
        bytes_written: count,
        new_position: saved_position,
        new_size,
    })
}

// ---------------------------------------------------------------------------
// do_writev — gather write
// ---------------------------------------------------------------------------

/// Handler for `writev(2)`.
///
/// Writes from the gather buffer array `iov` to `fd`.  Buffers are
/// consumed in order; the total is limited by [`MAX_RW_COUNT`].
///
/// # Arguments
///
/// * `table` — open fd table
/// * `fd`    — file descriptor (must be writable)
/// * `iov`   — gather vector (at most [`MAX_IOV`] elements)
///
/// # Returns
///
/// Total bytes written across all iov entries.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — `iov.len()` > `MAX_IOV`
/// * Same as [`do_write`] for other conditions
pub fn do_writev(table: &mut WriteFdTable, fd: i32, iov: &[IoVec]) -> Result<WriteResult> {
    if iov.len() > MAX_IOV {
        return Err(Error::InvalidArgument);
    }
    let total: u64 = iov
        .iter()
        .fold(0u64, |acc, v| acc.saturating_add(v.len))
        .min(MAX_RW_COUNT);

    do_write(table, fd, total)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn writable_file(fd: i32, size: u64, append: bool) -> WriteFile {
        WriteFile {
            fd,
            flags: if append {
                O_WRONLY | O_APPEND
            } else {
                O_WRONLY
            },
            size,
            position: 0,
            peer_connected: true,
            in_use: true,
        }
    }

    #[test]
    fn write_basic() {
        let mut t = WriteFdTable::new();
        t.insert(writable_file(3, 0, false)).unwrap();
        let r = do_write(&mut t, 3, 512).unwrap();
        assert_eq!(r.bytes_written, 512);
        assert_eq!(r.new_size, 512);
        assert_eq!(r.new_position, 512);
    }

    #[test]
    fn write_extends_size() {
        let mut t = WriteFdTable::new();
        t.insert(writable_file(3, 100, false)).unwrap();
        let r = do_write(&mut t, 3, 200).unwrap();
        assert_eq!(r.new_size, 200);
    }

    #[test]
    fn write_append_seeks_to_eof() {
        let mut t = WriteFdTable::new();
        t.insert(writable_file(3, 500, true)).unwrap();
        let r = do_write(&mut t, 3, 100).unwrap();
        // Should have written at offset 500 (EOF).
        assert_eq!(r.new_size, 600);
        assert_eq!(r.new_position, 600);
    }

    #[test]
    fn write_not_found() {
        let mut t = WriteFdTable::new();
        assert_eq!(do_write(&mut t, 99, 10), Err(Error::NotFound));
    }

    #[test]
    fn write_not_writable() {
        let mut t = WriteFdTable::new();
        t.insert(WriteFile {
            fd: 3,
            flags: 0, // O_RDONLY
            size: 0,
            position: 0,
            peer_connected: true,
            in_use: true,
        })
        .unwrap();
        assert_eq!(do_write(&mut t, 3, 10), Err(Error::PermissionDenied));
    }

    #[test]
    fn write_broken_pipe_epipe() {
        let mut t = WriteFdTable::new();
        t.insert(WriteFile {
            fd: 3,
            flags: O_WRONLY,
            size: 0,
            position: 0,
            peer_connected: false,
            in_use: true,
        })
        .unwrap();
        assert_eq!(do_write(&mut t, 3, 10), Err(Error::IoError));
    }

    #[test]
    fn pwrite64_does_not_advance_position() {
        let mut t = WriteFdTable::new();
        t.insert(writable_file(3, 0, false)).unwrap();
        let r = do_pwrite64(&mut t, 3, 100, 200).unwrap();
        assert_eq!(r.bytes_written, 100);
        assert_eq!(r.new_position, 0); // unchanged
        assert_eq!(r.new_size, 300);
    }

    #[test]
    fn writev_gather() {
        let mut t = WriteFdTable::new();
        t.insert(writable_file(3, 0, false)).unwrap();
        let iov = [
            IoVec { base: 0, len: 100 },
            IoVec {
                base: 100,
                len: 200,
            },
        ];
        let r = do_writev(&mut t, 3, &iov).unwrap();
        assert_eq!(r.bytes_written, 300);
    }

    #[test]
    fn writev_too_many_iov() {
        let mut t = WriteFdTable::new();
        t.insert(writable_file(3, 0, false)).unwrap();
        let iov: alloc::vec::Vec<IoVec> = (0..MAX_IOV + 1)
            .map(|_| IoVec { base: 0, len: 1 })
            .collect();
        assert_eq!(do_writev(&mut t, 3, &iov), Err(Error::InvalidArgument));
    }

    #[test]
    fn write_updates_size_correctly() {
        let mut t = WriteFdTable::new();
        t.insert(writable_file(3, 1000, false)).unwrap();
        // Write 100 bytes at position 0; size should stay at 1000.
        let r = do_write(&mut t, 3, 100).unwrap();
        assert_eq!(r.new_size, 1000);
    }
}

extern crate alloc;
