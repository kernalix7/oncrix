// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `copy_file_range(2)` syscall handler — kernel-side file copy.
//!
//! `copy_file_range` transfers up to `len` bytes between two open file
//! descriptors entirely within the kernel.  When source and destination
//! reside on the same filesystem, the kernel may use reflink (copy-on-write)
//! or server-side copy, bypassing the page cache entirely.
//!
//! # Syscall signature
//!
//! ```text
//! ssize_t copy_file_range(int fd_in, loff_t *off_in,
//!                         int fd_out, loff_t *off_out,
//!                         size_t len, unsigned int flags);
//! ```
//!
//! # Semantics
//!
//! - Both `fd_in` and `fd_out` must be regular files.
//! - `flags` must be 0 (all bits reserved).
//! - `off_in == NULL` uses the current file position and advances it.
//! - A short count is normal when source has fewer bytes than `len`.
//! - Cross-filesystem copies fall back to a read/write loop.
//!
//! # POSIX context
//!
//! `copy_file_range` is a Linux extension; POSIX.1-2024 does not standardise it.
//!
//! # Linux reference
//!
//! `fs/read_write.c` — `do_copy_file_range()`, `vfs_copy_file_range()`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// File capability flags
// ---------------------------------------------------------------------------

/// File is open for reading.
pub const FILE_READ: u32 = 1 << 0;
/// File is open for writing.
pub const FILE_WRITE: u32 = 1 << 1;
/// File is a regular file (not a socket, pipe, or special file).
pub const FILE_REGULAR: u32 = 1 << 2;
/// Filesystem supports server-side copy (e.g., btrfs reflink, NFS).
pub const FILE_SUPPORTS_COPY: u32 = 1 << 3;

/// Maximum supported file size.
pub const MAX_FILE_SIZE: u64 = 1 << 40;

// ---------------------------------------------------------------------------
// FileDescEntry — stub file descriptor
// ---------------------------------------------------------------------------

/// Stub representation of an open file descriptor.
#[derive(Debug, Clone, Copy)]
pub struct FileDescEntry {
    /// File descriptor number.
    pub fd: i32,
    /// Capability flags.
    pub caps: u32,
    /// Logical file size.
    pub size: u64,
    /// Current file position (advanced when offset pointer is null).
    pub pos: u64,
    /// Filesystem identifier (for same-fs detection).
    pub fs_id: u64,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl FileDescEntry {
    const fn empty() -> Self {
        Self {
            fd: -1,
            caps: 0,
            size: 0,
            pos: 0,
            fs_id: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// FdTable — stub file descriptor table
// ---------------------------------------------------------------------------

/// Maximum number of tracked file descriptors.
pub const MAX_FDS: usize = 64;

/// A stub table of open file descriptors.
pub struct FdTable {
    entries: [FileDescEntry; MAX_FDS],
    count: usize,
}

impl FdTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { FileDescEntry::empty() }; MAX_FDS],
            count: 0,
        }
    }

    /// Insert a file descriptor.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] — table is full.
    pub fn insert(&mut self, entry: FileDescEntry) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if !slot.active {
                *slot = entry;
                slot.active = true;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up by file descriptor number (shared).
    pub fn find(&self, fd: i32) -> Option<&FileDescEntry> {
        self.entries.iter().find(|e| e.active && e.fd == fd)
    }

    /// Look up by file descriptor number (mutable).
    pub fn find_mut(&mut self, fd: i32) -> Option<&mut FileDescEntry> {
        self.entries.iter_mut().find(|e| e.active && e.fd == fd)
    }

    /// Return the number of active descriptors.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for FdTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CopyStrategy
// ---------------------------------------------------------------------------

/// Copy strategy selected by the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyStrategy {
    /// Full reflink (copy-on-write) — same filesystem, no data moved.
    Reflink,
    /// Server-side copy — same filesystem with copy-offload capability.
    ServerSide,
    /// Page-cache splice — same filesystem, data in kernel page cache.
    PageCacheSplice,
    /// Read/write loop — cross-filesystem fallback.
    ReadWriteFallback,
}

impl CopyStrategy {
    /// Select the best copy strategy for the given file pair.
    pub fn select(table: &FdTable, fd_in: i32, fd_out: i32) -> Self {
        let in_fs = table.find(fd_in).map(|e| e.fs_id);
        let out_fs = table.find(fd_out).map(|e| e.fs_id);
        let same_fs = matches!((in_fs, out_fs), (Some(a), Some(b)) if a == b);

        if !same_fs {
            return Self::ReadWriteFallback;
        }
        let supports = table
            .find(fd_in)
            .map(|e| e.caps & FILE_SUPPORTS_COPY != 0)
            .unwrap_or(false);
        if supports {
            Self::ServerSide
        } else {
            Self::PageCacheSplice
        }
    }
}

// ---------------------------------------------------------------------------
// CopyResult
// ---------------------------------------------------------------------------

/// Result of a `copy_file_range` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CopyResult {
    /// Number of bytes copied.
    pub copied: u64,
    /// New position in `fd_in`.
    pub new_off_in: u64,
    /// New position in `fd_out`.
    pub new_off_out: u64,
    /// Strategy used.
    pub strategy: CopyStrategy,
}

impl CopyResult {
    /// Return `true` if any data was copied.
    pub const fn has_data(&self) -> bool {
        self.copied > 0
    }

    /// Return `true` if fewer than `requested` bytes were transferred.
    pub const fn short(&self, requested: u64) -> bool {
        self.copied < requested
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate both file descriptors and resolve effective offsets.
fn validate_and_resolve(
    table: &FdTable,
    fd_in: i32,
    off_in: Option<u64>,
    fd_out: i32,
    off_out: Option<u64>,
    len: u64,
) -> Result<(u64, bool, u64, bool)> {
    if len == 0 || len > MAX_FILE_SIZE {
        return Err(Error::InvalidArgument);
    }

    let in_e = table.find(fd_in).ok_or(Error::NotFound)?;
    let out_e = table.find(fd_out).ok_or(Error::NotFound)?;

    if in_e.caps & FILE_READ == 0 {
        return Err(Error::PermissionDenied);
    }
    if out_e.caps & FILE_WRITE == 0 {
        return Err(Error::PermissionDenied);
    }
    if in_e.caps & FILE_REGULAR == 0 || out_e.caps & FILE_REGULAR == 0 {
        return Err(Error::IoError);
    }

    let (src_off, src_explicit) = match off_in {
        Some(o) if o < MAX_FILE_SIZE => (o, true),
        Some(_) => return Err(Error::InvalidArgument),
        None => (in_e.pos, false),
    };

    let (dst_off, dst_explicit) = match off_out {
        Some(o) if o < MAX_FILE_SIZE => (o, true),
        Some(_) => return Err(Error::InvalidArgument),
        None => (out_e.pos, false),
    };

    // Overlap check for same-fd case.
    if fd_in == fd_out {
        let src_end = src_off.saturating_add(len);
        let dst_end = dst_off.saturating_add(len);
        if src_off < dst_end && dst_off < src_end {
            return Err(Error::InvalidArgument);
        }
    }

    Ok((src_off, src_explicit, dst_off, dst_explicit))
}

// ---------------------------------------------------------------------------
// do_sys_copy_file_range — primary handler
// ---------------------------------------------------------------------------

/// `copy_file_range(2)` syscall handler.
///
/// Copies up to `len` bytes from `fd_in` to `fd_out`.
///
/// # Arguments
///
/// * `table`   — Open file descriptor table.
/// * `fd_in`   — Source file descriptor (must be readable and regular).
/// * `off_in`  — Source offset, or `None` to use and advance `fd_in.pos`.
/// * `fd_out`  — Destination file descriptor (must be writable and regular).
/// * `off_out` — Destination offset, or `None` to use and advance `fd_out.pos`.
/// * `len`     — Number of bytes to copy.
/// * `flags`   — Reserved; must be 0.
///
/// # Returns
///
/// A [`CopyResult`] with the number of bytes copied and updated offsets.
///
/// # Errors
///
/// * [`Error::InvalidArgument`]   — `flags != 0`, `len == 0`, or overlapping
///   ranges on the same fd.
/// * [`Error::NotFound`]          — Unknown `fd_in` or `fd_out`.
/// * [`Error::PermissionDenied`]  — Missing read/write capability.
/// * [`Error::IoError`]           — Not a regular file.
pub fn do_sys_copy_file_range(
    table: &mut FdTable,
    fd_in: i32,
    off_in: Option<u64>,
    fd_out: i32,
    off_out: Option<u64>,
    len: u64,
    flags: u32,
) -> Result<CopyResult> {
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }

    let (src_off, src_explicit, dst_off, dst_explicit) =
        validate_and_resolve(table, fd_in, off_in, fd_out, off_out, len)?;

    // Select copy strategy before taking mutable refs.
    let strategy = CopyStrategy::select(table, fd_in, fd_out);

    // Determine how many bytes can actually be read from src.
    let in_size = table.find(fd_in).ok_or(Error::NotFound)?.size;
    let available = in_size.saturating_sub(src_off);
    let to_copy = len.min(available);

    // Update fd_in position if offset was implicit.
    let new_off_in = src_off + to_copy;
    if !src_explicit {
        if let Some(e) = table.find_mut(fd_in) {
            e.pos = new_off_in;
        }
    }

    // Update fd_out position and size.
    let new_off_out = dst_off + to_copy;
    if let Some(e) = table.find_mut(fd_out) {
        if new_off_out > e.size {
            e.size = new_off_out;
        }
        if !dst_explicit {
            e.pos = new_off_out;
        }
    }

    Ok(CopyResult {
        copied: to_copy,
        new_off_in,
        new_off_out,
        strategy,
    })
}

/// Cross-filesystem fallback for `copy_file_range`.
///
/// Delegates to [`do_sys_copy_file_range`].  In a real kernel the
/// implementation path diverges (read-into-page-cache / write-from-page-cache
/// loop) but the external API is identical.
pub fn do_copy_file_range_cross_fs(
    table: &mut FdTable,
    fd_in: i32,
    off_in: Option<u64>,
    fd_out: i32,
    off_out: Option<u64>,
    len: u64,
) -> Result<CopyResult> {
    do_sys_copy_file_range(table, fd_in, off_in, fd_out, off_out, len, 0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table() -> FdTable {
        let mut t = FdTable::new();
        t.insert(FileDescEntry {
            fd: 3,
            caps: FILE_READ | FILE_REGULAR,
            size: 4096,
            pos: 0,
            fs_id: 1,
            active: true,
        })
        .unwrap();
        t.insert(FileDescEntry {
            fd: 4,
            caps: FILE_WRITE | FILE_REGULAR,
            size: 0,
            pos: 0,
            fs_id: 1,
            active: true,
        })
        .unwrap();
        t
    }

    #[test]
    fn full_copy() {
        let mut t = make_table();
        let r = do_sys_copy_file_range(&mut t, 3, Some(0), 4, Some(0), 4096, 0).unwrap();
        assert_eq!(r.copied, 4096);
        assert_eq!(r.new_off_in, 4096);
        assert_eq!(r.new_off_out, 4096);
        assert_eq!(t.find(4).unwrap().size, 4096);
    }

    #[test]
    fn short_read_at_eof() {
        let mut t = make_table();
        let r = do_sys_copy_file_range(&mut t, 3, Some(2048), 4, Some(0), 8192, 0).unwrap();
        assert_eq!(r.copied, 2048);
        assert!(r.short(8192));
    }

    #[test]
    fn copy_at_eof_returns_zero() {
        let mut t = make_table();
        let r = do_sys_copy_file_range(&mut t, 3, Some(4096), 4, Some(0), 100, 0).unwrap();
        assert_eq!(r.copied, 0);
        assert!(!r.has_data());
    }

    #[test]
    fn implicit_offsets_advance_positions() {
        let mut t = make_table();
        do_sys_copy_file_range(&mut t, 3, None, 4, None, 512, 0).unwrap();
        assert_eq!(t.find(3).unwrap().pos, 512);
        assert_eq!(t.find(4).unwrap().pos, 512);
    }

    #[test]
    fn explicit_offsets_do_not_advance() {
        let mut t = make_table();
        do_sys_copy_file_range(&mut t, 3, Some(0), 4, Some(0), 512, 0).unwrap();
        assert_eq!(t.find(3).unwrap().pos, 0);
        assert_eq!(t.find(4).unwrap().pos, 0);
    }

    #[test]
    fn nonzero_flags_rejected() {
        let mut t = make_table();
        assert_eq!(
            do_sys_copy_file_range(&mut t, 3, None, 4, None, 100, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn zero_len_rejected() {
        let mut t = make_table();
        assert_eq!(
            do_sys_copy_file_range(&mut t, 3, None, 4, None, 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn missing_fd_in_not_found() {
        let mut t = make_table();
        assert_eq!(
            do_sys_copy_file_range(&mut t, 99, None, 4, None, 100, 0),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn non_readable_fd_in_denied() {
        let mut t = make_table();
        t.insert(FileDescEntry {
            fd: 5,
            caps: FILE_WRITE | FILE_REGULAR,
            size: 1000,
            pos: 0,
            fs_id: 1,
            active: true,
        })
        .unwrap();
        assert_eq!(
            do_sys_copy_file_range(&mut t, 5, None, 4, None, 100, 0),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn non_regular_rejected() {
        let mut t = make_table();
        t.insert(FileDescEntry {
            fd: 6,
            caps: FILE_READ | FILE_WRITE,
            size: 1000,
            pos: 0,
            fs_id: 1,
            active: true,
        })
        .unwrap();
        assert_eq!(
            do_sys_copy_file_range(&mut t, 6, None, 4, None, 100, 0),
            Err(Error::IoError)
        );
    }

    #[test]
    fn same_fd_overlap_rejected() {
        let mut t = FdTable::new();
        t.insert(FileDescEntry {
            fd: 10,
            caps: FILE_READ | FILE_WRITE | FILE_REGULAR,
            size: 4096,
            pos: 0,
            fs_id: 1,
            active: true,
        })
        .unwrap();
        assert_eq!(
            do_sys_copy_file_range(&mut t, 10, Some(0), 10, Some(100), 200, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn strategy_same_fs_without_copy_cap() {
        let t = make_table();
        let s = CopyStrategy::select(&t, 3, 4);
        assert_eq!(s, CopyStrategy::PageCacheSplice);
    }

    #[test]
    fn strategy_different_fs_fallback() {
        let mut t = make_table();
        t.insert(FileDescEntry {
            fd: 7,
            caps: FILE_WRITE | FILE_REGULAR,
            size: 0,
            pos: 0,
            fs_id: 99,
            active: true,
        })
        .unwrap();
        let s = CopyStrategy::select(&t, 3, 7);
        assert_eq!(s, CopyStrategy::ReadWriteFallback);
    }

    #[test]
    fn cross_fs_fallback_function() {
        let mut t = make_table();
        let r = do_copy_file_range_cross_fs(&mut t, 3, Some(0), 4, Some(0), 1024).unwrap();
        assert_eq!(r.copied, 1024);
    }
}
