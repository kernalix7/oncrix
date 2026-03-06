// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getdents64(2)` syscall handler.
//!
//! Reads directory entries from an open directory file descriptor into a
//! caller-supplied buffer, using the `linux_dirent64` structure layout.
//!
//! # `linux_dirent64` layout
//!
//! ```text
//! struct linux_dirent64 {
//!     u64 d_ino;      /* inode number */
//!     s64 d_off;      /* offset to next dirent */
//!     u16 d_reclen;   /* length of this record */
//!     u8  d_type;     /* file type */
//!     char d_name[];  /* null-terminated filename */
//! };
//! ```
//!
//! # Key behaviours
//!
//! - Returns 0 when there are no more entries.
//! - Returns `InvalidArgument` if the buffer is too small for even one entry.
//! - File position is advanced through the directory.
//! - `.` and `..` entries are always emitted first.
//!
//! # POSIX Conformance
//!
//! Linux `getdents64` extension; POSIX equivalent is `readdir(3)`.
//!
//! # References
//!
//! - Linux: `fs/readdir.c`, `getdents64()`
//! - man `getdents(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// d_type constants
// ---------------------------------------------------------------------------

/// Unknown file type.
pub const DT_UNKNOWN: u8 = 0;
/// FIFO.
pub const DT_FIFO: u8 = 1;
/// Character device.
pub const DT_CHR: u8 = 2;
/// Directory.
pub const DT_DIR: u8 = 4;
/// Block device.
pub const DT_BLK: u8 = 6;
/// Regular file.
pub const DT_REG: u8 = 8;
/// Symbolic link.
pub const DT_LNK: u8 = 10;
/// Socket.
pub const DT_SOCK: u8 = 12;

/// Minimum size of a `linux_dirent64` record (fixed fields + 1-byte name + NUL).
pub const DIRENT64_MIN_RECLEN: usize = 8 + 8 + 2 + 1 + 1 + 1; // ~21 bytes

/// Maximum directory entry name length.
pub const NAME_MAX: usize = 255;

/// Maximum directory entries per stub directory.
pub const MAX_DIR_ENTRIES: usize = 64;

/// Maximum directory fds in the stub.
pub const MAX_DIR_FDS: usize = 64;

// ---------------------------------------------------------------------------
// LinuxDirent64 — one directory entry
// ---------------------------------------------------------------------------

/// A single `linux_dirent64` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxDirent64 {
    /// Inode number.
    pub d_ino: u64,
    /// Offset of the *next* directory entry (monotonically increasing cookie).
    pub d_off: u64,
    /// Record length (8-byte aligned).
    pub d_reclen: u16,
    /// File type (`DT_*` constants).
    pub d_type: u8,
    /// Filename (NUL-terminated).
    pub d_name: [u8; NAME_MAX + 1],
    /// Actual name length (not counting NUL).
    pub name_len: usize,
}

impl LinuxDirent64 {
    /// Construct a `LinuxDirent64` from raw components.
    ///
    /// The record length is rounded up to an 8-byte boundary.
    pub fn new(ino: u64, d_off: u64, name: &[u8], d_type: u8) -> Self {
        let nlen = name.len().min(NAME_MAX);
        // reclen = fixed header (19 bytes) + name + NUL, padded to 8 bytes.
        let raw = 19 + nlen + 1;
        let reclen = ((raw + 7) & !7) as u16;
        let mut buf = [0u8; NAME_MAX + 1];
        buf[..nlen].copy_from_slice(&name[..nlen]);
        Self {
            d_ino: ino,
            d_off,
            d_reclen: reclen,
            d_type,
            d_name: buf,
            name_len: nlen,
        }
    }

    /// Return the filename as a byte slice (without NUL).
    pub fn name(&self) -> &[u8] {
        &self.d_name[..self.name_len]
    }
}

// ---------------------------------------------------------------------------
// DirEntryRecord — stub directory entry
// ---------------------------------------------------------------------------

/// A stub directory entry stored in a [`DirFd`].
#[derive(Clone, Copy)]
pub struct DirEntryRecord {
    pub ino: u64,
    pub d_type: u8,
    pub name: [u8; NAME_MAX + 1],
    pub name_len: usize,
    pub in_use: bool,
}

impl DirEntryRecord {
    const fn empty() -> Self {
        Self {
            ino: 0,
            d_type: DT_UNKNOWN,
            name: [0u8; NAME_MAX + 1],
            name_len: 0,
            in_use: false,
        }
    }
}

// ---------------------------------------------------------------------------
// DirFd — an open directory file descriptor
// ---------------------------------------------------------------------------

/// An open directory file descriptor with its entries and read position.
pub struct DirFd {
    /// File descriptor number.
    pub fd: i32,
    /// Current read position (index into entries array).
    pub pos: usize,
    /// Entries (including `.` and `..`).
    pub entries: [DirEntryRecord; MAX_DIR_ENTRIES],
    /// Number of valid entries.
    pub entry_count: usize,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl DirFd {
    const fn empty() -> Self {
        Self {
            fd: -1,
            pos: 0,
            entries: [const { DirEntryRecord::empty() }; MAX_DIR_ENTRIES],
            entry_count: 0,
            in_use: false,
        }
    }

    /// Append a directory entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if full.
    pub fn push_entry(&mut self, ino: u64, d_type: u8, name: &[u8]) -> Result<()> {
        if self.entry_count >= MAX_DIR_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let nlen = name.len().min(NAME_MAX);
        let idx = self.entry_count;
        self.entries[idx].ino = ino;
        self.entries[idx].d_type = d_type;
        self.entries[idx].name[..nlen].copy_from_slice(&name[..nlen]);
        self.entries[idx].name_len = nlen;
        self.entries[idx].in_use = true;
        self.entry_count += 1;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DirFdTable
// ---------------------------------------------------------------------------

/// A stub table of open directory file descriptors.
pub struct DirFdTable {
    dirs: [DirFd; MAX_DIR_FDS],
    count: usize,
}

impl DirFdTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            dirs: [const { DirFd::empty() }; MAX_DIR_FDS],
            count: 0,
        }
    }

    /// Insert a new directory fd.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn insert(&mut self, dir: DirFd) -> Result<()> {
        for slot in self.dirs.iter_mut() {
            if !slot.in_use {
                *slot = dir;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a dir fd by number.
    pub fn find(&self, fd: i32) -> Option<&DirFd> {
        self.dirs.iter().find(|d| d.in_use && d.fd == fd)
    }

    /// Find a mutable dir fd by number.
    pub fn find_mut(&mut self, fd: i32) -> Option<&mut DirFd> {
        self.dirs.iter_mut().find(|d| d.in_use && d.fd == fd)
    }

    /// Return the number of open directory fds.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for DirFdTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// do_getdents64 — main handler
// ---------------------------------------------------------------------------

/// Handler for `getdents64(2)`.
///
/// Reads up to `buf_size` bytes of `linux_dirent64` records from the
/// directory `fd` starting at its current position.  Returns the total
/// number of bytes written into the buffer.
///
/// Returns `0` when there are no more entries.
///
/// # Arguments
///
/// * `table`    — open directory fd table
/// * `fd`       — open directory file descriptor
/// * `buf_size` — size of the caller's buffer in bytes
///
/// # Returns
///
/// Total bytes "written" (simulated), or 0 if at end-of-directory.
///
/// # Errors
///
/// * [`Error::NotFound`]        — `fd` not in the table
/// * [`Error::InvalidArgument`] — `buf_size` too small for one record
pub fn do_getdents64(
    table: &mut DirFdTable,
    fd: i32,
    buf_size: usize,
) -> Result<(usize, alloc::vec::Vec<LinuxDirent64>)> {
    let dir = table.find(fd).ok_or(Error::NotFound)?;

    if buf_size < DIRENT64_MIN_RECLEN {
        return Err(Error::InvalidArgument);
    }

    if dir.pos >= dir.entry_count {
        return Ok((0, alloc::vec::Vec::new()));
    }

    let mut entries: alloc::vec::Vec<LinuxDirent64> = alloc::vec::Vec::new();
    let mut total_bytes = 0usize;
    let start_pos = dir.pos;
    let entry_count = dir.entry_count;

    for i in start_pos..entry_count {
        let rec = &dir.entries[i];
        if !rec.in_use {
            continue;
        }
        let d_off = (i + 1) as u64;
        let dirent = LinuxDirent64::new(rec.ino, d_off, &rec.name[..rec.name_len], rec.d_type);
        let rec_size = dirent.d_reclen as usize;
        if total_bytes + rec_size > buf_size {
            break;
        }
        total_bytes += rec_size;
        entries.push(dirent);
    }

    // Advance the directory position.
    if let Some(dir_mut) = table.find_mut(fd) {
        dir_mut.pos = start_pos + entries.len();
    }

    Ok((total_bytes, entries))
}

extern crate alloc;

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dir(fd: i32) -> DirFd {
        let mut dir = DirFd::empty();
        dir.fd = fd;
        dir.in_use = true;
        dir.push_entry(1, DT_DIR, b".").unwrap();
        dir.push_entry(2, DT_DIR, b"..").unwrap();
        dir.push_entry(10, DT_REG, b"file.txt").unwrap();
        dir.push_entry(11, DT_DIR, b"subdir").unwrap();
        dir
    }

    #[test]
    fn getdents64_reads_entries() {
        let mut t = DirFdTable::new();
        t.insert(make_dir(3)).unwrap();
        let (bytes, entries) = do_getdents64(&mut t, 3, 4096).unwrap();
        assert!(bytes > 0);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].name(), b".");
        assert_eq!(entries[1].name(), b"..");
        assert_eq!(entries[2].name(), b"file.txt");
        assert_eq!(entries[3].name(), b"subdir");
    }

    #[test]
    fn getdents64_advances_position() {
        let mut t = DirFdTable::new();
        t.insert(make_dir(3)).unwrap();
        do_getdents64(&mut t, 3, 4096).unwrap();
        // Second call returns 0 (no more entries).
        let (bytes, entries) = do_getdents64(&mut t, 3, 4096).unwrap();
        assert_eq!(bytes, 0);
        assert!(entries.is_empty());
    }

    #[test]
    fn getdents64_buffer_too_small() {
        let mut t = DirFdTable::new();
        t.insert(make_dir(3)).unwrap();
        assert_eq!(do_getdents64(&mut t, 3, 5), Err(Error::InvalidArgument));
    }

    #[test]
    fn getdents64_not_found() {
        let mut t = DirFdTable::new();
        assert_eq!(do_getdents64(&mut t, 99, 4096), Err(Error::NotFound));
    }

    #[test]
    fn getdents64_limited_by_buf_size() {
        let mut t = DirFdTable::new();
        let mut dir = DirFd::empty();
        dir.fd = 3;
        dir.in_use = true;
        // Add 10 regular files.
        for i in 0u64..10 {
            let mut name = [0u8; 10];
            name[0] = b'f';
            name[1] = b'0' + i as u8;
            dir.push_entry(100 + i, DT_REG, &name[..2]).unwrap();
        }
        t.insert(dir).unwrap();

        // Small buffer: should fit just 1-2 entries.
        let small = 64;
        let (bytes, entries) = do_getdents64(&mut t, 3, small).unwrap();
        assert!(bytes <= small);
        assert!(!entries.is_empty());
    }

    #[test]
    fn linux_dirent64_reclen_aligned() {
        let d = LinuxDirent64::new(1, 1, b"name.txt", DT_REG);
        assert_eq!(d.d_reclen as usize % 8, 0);
    }

    #[test]
    fn linux_dirent64_name() {
        let d = LinuxDirent64::new(2, 2, b"README.md", DT_REG);
        assert_eq!(d.name(), b"README.md");
    }
}
