// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `lseek(2)` syscall handler.
//!
//! Repositions the file offset of an open file descriptor.  Supports all
//! POSIX whence values plus the Linux extensions `SEEK_DATA` and
//! `SEEK_HOLE`.
//!
//! # Whence values
//!
//! | Name | Value | Description |
//! |------|-------|-------------|
//! | `SEEK_SET`  | 0 | Set offset to `offset` bytes from start |
//! | `SEEK_CUR`  | 1 | Set offset to current + `offset` |
//! | `SEEK_END`  | 2 | Set offset to file size + `offset` |
//! | `SEEK_DATA` | 3 | Seek to next data region ≥ `offset` |
//! | `SEEK_HOLE` | 4 | Seek to next hole ≥ `offset` |
//!
//! # Key behaviours
//!
//! - Pipes and sockets return `ESPIPE` (`IoError`).
//! - Resulting offset must not be negative.
//! - Seeking past EOF is allowed (creates a "hole" if written to).
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `lseek()`.
//!
//! # References
//!
//! - POSIX.1-2024: `lseek()`
//! - Linux: `fs/read_write.c`, `vfs_llseek()`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Whence constants
// ---------------------------------------------------------------------------

/// Set offset to `offset` bytes from the beginning of the file.
pub const SEEK_SET: i32 = 0;
/// Set offset to current position plus `offset`.
pub const SEEK_CUR: i32 = 1;
/// Set offset to file size plus `offset`.
pub const SEEK_END: i32 = 2;
/// Seek to next data region (Linux extension).
pub const SEEK_DATA: i32 = 3;
/// Seek to next hole (Linux extension).
pub const SEEK_HOLE: i32 = 4;

/// Maximum file offset value.
pub const OFFSET_MAX: u64 = i64::MAX as u64;

/// Maximum number of files in the lseek fd table.
pub const MAX_LSEEK_FDS: usize = 256;

// ---------------------------------------------------------------------------
// SeekFile — stub file for lseek
// ---------------------------------------------------------------------------

/// File type for lseek purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeekFileKind {
    /// Seekable regular file or block device.
    Seekable,
    /// Pipe — `lseek` returns ESPIPE.
    Pipe,
    /// Socket — `lseek` returns ESPIPE.
    Socket,
}

/// A stub file for the lseek handler.
#[derive(Debug, Clone, Copy)]
pub struct SeekFile {
    /// File descriptor number.
    pub fd: i32,
    /// File kind (seekable or pipe/socket).
    pub kind: SeekFileKind,
    /// File size in bytes.
    pub size: u64,
    /// Current file position.
    pub position: u64,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl SeekFile {
    const fn empty() -> Self {
        Self {
            fd: -1,
            kind: SeekFileKind::Seekable,
            size: 0,
            position: 0,
            in_use: false,
        }
    }

    /// Return `true` if this file is seekable.
    pub const fn is_seekable(&self) -> bool {
        matches!(self.kind, SeekFileKind::Seekable)
    }
}

/// A stub lseek fd table.
pub struct LseekFdTable {
    files: [SeekFile; MAX_LSEEK_FDS],
    count: usize,
}

impl LseekFdTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            files: [const { SeekFile::empty() }; MAX_LSEEK_FDS],
            count: 0,
        }
    }

    /// Insert a file record.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn insert(&mut self, f: SeekFile) -> Result<()> {
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
    pub fn find(&self, fd: i32) -> Option<&SeekFile> {
        self.files.iter().find(|f| f.in_use && f.fd == fd)
    }

    /// Look up a mutable file by fd.
    pub fn find_mut(&mut self, fd: i32) -> Option<&mut SeekFile> {
        self.files.iter_mut().find(|f| f.in_use && f.fd == fd)
    }

    /// Return the number of open files.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for LseekFdTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Whence — typed whence value
// ---------------------------------------------------------------------------

/// A validated `whence` argument for `lseek`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Whence {
    /// `SEEK_SET` — absolute position.
    Set,
    /// `SEEK_CUR` — relative to current position.
    Cur,
    /// `SEEK_END` — relative to end of file.
    End,
    /// `SEEK_DATA` — next data extent.
    Data,
    /// `SEEK_HOLE` — next hole.
    Hole,
}

impl Whence {
    /// Construct from a raw `whence` argument.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for unknown values.
    pub fn from_raw(raw: i32) -> Result<Self> {
        match raw {
            SEEK_SET => Ok(Self::Set),
            SEEK_CUR => Ok(Self::Cur),
            SEEK_END => Ok(Self::End),
            SEEK_DATA => Ok(Self::Data),
            SEEK_HOLE => Ok(Self::Hole),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// compute_new_offset — resolve whence + offset
// ---------------------------------------------------------------------------

/// Compute the new file offset from `whence` and `offset`.
///
/// Returns the resolved absolute offset, or an error if the result
/// would be negative or overflow `OFFSET_MAX`.
fn compute_new_offset(file: &SeekFile, offset: i64, whence: Whence) -> Result<u64> {
    let new_off: i64 = match whence {
        Whence::Set => offset,
        Whence::Cur => (file.position as i64)
            .checked_add(offset)
            .ok_or(Error::InvalidArgument)?,
        Whence::End => (file.size as i64)
            .checked_add(offset)
            .ok_or(Error::InvalidArgument)?,
        Whence::Data => {
            // Stub: no sparse file support; treat entire file as data.
            // Return `offset` clamped to [0, size].
            let base = offset.max(0);
            if base as u64 > file.size {
                return Err(Error::InvalidArgument); // ENXIO
            }
            base
        }
        Whence::Hole => {
            // Stub: treat the file as having a single hole at EOF.
            // SEEK_HOLE returns the first offset ≥ `offset` that is a hole,
            // which for a fully-data file is `size`.
            let base = offset.max(0);
            if base as u64 > file.size {
                return Err(Error::InvalidArgument); // ENXIO
            }
            file.size as i64
        }
    };

    if new_off < 0 {
        return Err(Error::InvalidArgument);
    }
    let new_off_u = new_off as u64;
    if new_off_u > OFFSET_MAX {
        return Err(Error::InvalidArgument);
    }
    Ok(new_off_u)
}

// ---------------------------------------------------------------------------
// do_lseek — main handler
// ---------------------------------------------------------------------------

/// Handler for `lseek(2)`.
///
/// Repositions the file offset of `fd` according to `whence` and
/// `offset`, returning the new absolute offset.
///
/// # Arguments
///
/// * `table`  — open fd table
/// * `fd`     — file descriptor
/// * `offset` — byte offset (interpretation depends on `whence`)
/// * `whence` — raw whence value (one of the `SEEK_*` constants)
///
/// # Returns
///
/// The new file position as an absolute byte offset.
///
/// # Errors
///
/// * [`Error::NotFound`]        — `fd` not in the table
/// * [`Error::IoError`]         — `fd` is a pipe or socket (`ESPIPE`)
/// * [`Error::InvalidArgument`] — unknown `whence`, result < 0, or
///   `SEEK_DATA`/`SEEK_HOLE` past EOF (`ENXIO`)
pub fn do_lseek(table: &mut LseekFdTable, fd: i32, offset: i64, whence: i32) -> Result<u64> {
    let file = table.find(fd).ok_or(Error::NotFound)?;
    if !file.is_seekable() {
        return Err(Error::IoError); // ESPIPE
    }
    let whence = Whence::from_raw(whence)?;
    let new_off = compute_new_offset(file, offset, whence)?;

    if let Some(f) = table.find_mut(fd) {
        f.position = new_off;
    }

    Ok(new_off)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table(size: u64) -> LseekFdTable {
        let mut t = LseekFdTable::new();
        t.insert(SeekFile {
            fd: 3,
            kind: SeekFileKind::Seekable,
            size,
            position: 0,
            in_use: true,
        })
        .unwrap();
        t
    }

    #[test]
    fn seek_set() {
        let mut t = make_table(1024);
        let off = do_lseek(&mut t, 3, 100, SEEK_SET).unwrap();
        assert_eq!(off, 100);
        assert_eq!(t.find(3).unwrap().position, 100);
    }

    #[test]
    fn seek_cur() {
        let mut t = make_table(1024);
        do_lseek(&mut t, 3, 100, SEEK_SET).unwrap();
        let off = do_lseek(&mut t, 3, 50, SEEK_CUR).unwrap();
        assert_eq!(off, 150);
    }

    #[test]
    fn seek_end() {
        let mut t = make_table(1024);
        let off = do_lseek(&mut t, 3, 0, SEEK_END).unwrap();
        assert_eq!(off, 1024);
    }

    #[test]
    fn seek_end_negative_offset() {
        let mut t = make_table(1024);
        let off = do_lseek(&mut t, 3, -100, SEEK_END).unwrap();
        assert_eq!(off, 924);
    }

    #[test]
    fn seek_past_eof() {
        let mut t = make_table(100);
        let off = do_lseek(&mut t, 3, 200, SEEK_SET).unwrap();
        assert_eq!(off, 200); // allowed
    }

    #[test]
    fn seek_negative_result_rejected() {
        let mut t = make_table(100);
        assert_eq!(
            do_lseek(&mut t, 3, -1, SEEK_SET),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn seek_negative_relative_rejected() {
        let mut t = make_table(100);
        // position is 0, seek -1 relative gives -1 → error
        assert_eq!(
            do_lseek(&mut t, 3, -1, SEEK_CUR),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn seek_pipe_espipe() {
        let mut t = LseekFdTable::new();
        t.insert(SeekFile {
            fd: 4,
            kind: SeekFileKind::Pipe,
            size: 0,
            position: 0,
            in_use: true,
        })
        .unwrap();
        assert_eq!(do_lseek(&mut t, 4, 0, SEEK_SET), Err(Error::IoError));
    }

    #[test]
    fn seek_socket_espipe() {
        let mut t = LseekFdTable::new();
        t.insert(SeekFile {
            fd: 5,
            kind: SeekFileKind::Socket,
            size: 0,
            position: 0,
            in_use: true,
        })
        .unwrap();
        assert_eq!(do_lseek(&mut t, 5, 0, SEEK_SET), Err(Error::IoError));
    }

    #[test]
    fn seek_data_within_file() {
        let mut t = make_table(512);
        let off = do_lseek(&mut t, 3, 100, SEEK_DATA).unwrap();
        assert_eq!(off, 100);
    }

    #[test]
    fn seek_data_past_eof_rejected() {
        let mut t = make_table(512);
        assert_eq!(
            do_lseek(&mut t, 3, 513, SEEK_DATA),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn seek_hole_returns_size() {
        let mut t = make_table(512);
        let off = do_lseek(&mut t, 3, 0, SEEK_HOLE).unwrap();
        // Stub: no sparse file support → hole is at EOF.
        assert_eq!(off, 512);
    }

    #[test]
    fn seek_invalid_whence() {
        let mut t = make_table(100);
        assert_eq!(do_lseek(&mut t, 3, 0, 99), Err(Error::InvalidArgument));
    }

    #[test]
    fn seek_not_found() {
        let mut t = LseekFdTable::new();
        assert_eq!(do_lseek(&mut t, 99, 0, SEEK_SET), Err(Error::NotFound));
    }
}
