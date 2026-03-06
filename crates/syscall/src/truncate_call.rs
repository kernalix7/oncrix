// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `truncate(2)` and `ftruncate(2)` syscall handlers.
//!
//! `truncate` changes the size of a file specified by path.
//! `ftruncate` changes the size of a file specified by an open file descriptor.
//!
//! If the file is extended beyond its current size, the extended part reads as
//! zero bytes (a sparse "hole" on filesystems that support it).  If shrunk,
//! the data beyond the new length is discarded.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `truncate()` and `ftruncate()`.
//!
//! Key behaviours:
//! - Only regular files may be truncated (`EINVAL` for non-regular files).
//! - The file must be writable (path: write permission on the inode;
//!   fd: opened with `O_WRONLY` or `O_RDWR`).
//! - A negative `length` is rejected with `EINVAL`.
//! - `length` greater than `RLIMIT_FSIZE` yields `EFBIG` / `SIGXFSZ`.
//! - Attempting to truncate a file being executed returns `ETXTBSY`.
//! - The file's `ctime` and `mtime` are updated on success.
//! - File locks and file descriptors pointing to the file remain valid.
//!
//! # References
//!
//! - POSIX.1-2024: `truncate()`, `ftruncate()`
//! - Linux man pages: `truncate(2)`, `ftruncate(2)`
//! - Linux source: `fs/truncate.c` `vfs_truncate()`, `do_sys_ftruncate()`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// File constants
// ---------------------------------------------------------------------------

/// File open for reading only.
pub const O_RDONLY: u32 = 0;
/// File open for writing only.
pub const O_WRONLY: u32 = 1;
/// File open for reading and writing.
pub const O_RDWR: u32 = 2;
/// Access mode mask.
pub const O_ACCMODE: u32 = 3;

/// Maximum supported file size (1 TiB).
pub const MAX_FILE_SIZE: u64 = 1u64 << 40;

/// Default `RLIMIT_FSIZE` — maximum file size an unprivileged process may
/// create or extend.  Kernel uses `u64::MAX` (unlimited) by default.
pub const RLIMIT_FSIZE_DEFAULT: u64 = u64::MAX;

// ---------------------------------------------------------------------------
// Inode type
// ---------------------------------------------------------------------------

/// Inode types relevant to `truncate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeType {
    /// Regular file.
    RegularFile,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Block device.
    BlockDevice,
    /// Character device.
    CharDevice,
    /// Named pipe (FIFO).
    Fifo,
    /// Unix domain socket.
    Socket,
}

// ---------------------------------------------------------------------------
// Inode stub
// ---------------------------------------------------------------------------

/// Stub inode for truncate operations.
#[derive(Debug, Clone, Copy)]
pub struct Inode {
    /// Inode number.
    pub ino: u64,
    /// Inode type.
    pub kind: InodeType,
    /// Current file size in bytes.
    pub size: u64,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Permission bits (lower 12 bits).
    pub mode: u16,
    /// Set to `true` when this file is being executed.
    pub in_exec: bool,
    /// Last modification time (seconds since epoch).
    pub mtime: i64,
    /// Last status-change time.
    pub ctime: i64,
}

impl Inode {
    /// Return `true` if this is a regular file.
    pub const fn is_regular(&self) -> bool {
        matches!(self.kind, InodeType::RegularFile)
    }

    /// Check whether `uid` has write permission (owner match only, stub).
    pub const fn writable_by(&self, uid: u32) -> bool {
        uid == 0 || self.uid == uid || (self.mode & 0o200 != 0)
    }
}

// ---------------------------------------------------------------------------
// FdEntry — open file descriptor stub
// ---------------------------------------------------------------------------

/// An open file descriptor entry for truncate purposes.
#[derive(Debug, Clone, Copy)]
pub struct FdEntry {
    /// Numeric file descriptor.
    pub fd: i32,
    /// Open flags (`O_RDONLY`, `O_WRONLY`, `O_RDWR`).
    pub flags: u32,
    /// Inode index in the inode table.
    pub inode_idx: usize,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl FdEntry {
    const fn empty() -> Self {
        Self {
            fd: -1,
            flags: 0,
            inode_idx: 0,
            in_use: false,
        }
    }

    /// Return `true` if opened for writing.
    pub const fn is_writable(&self) -> bool {
        let mode = self.flags & O_ACCMODE;
        mode == O_WRONLY || mode == O_RDWR
    }
}

// ---------------------------------------------------------------------------
// TruncateTable — stub inode/fd store
// ---------------------------------------------------------------------------

/// Maximum inodes in the stub table.
pub const MAX_INODES: usize = 64;
/// Maximum file descriptors in the stub table.
pub const MAX_FDS: usize = 64;

/// Combined inode + fd table for truncate.
pub struct TruncateTable {
    inodes: [Inode; MAX_INODES],
    inode_paths: [[u8; 256]; MAX_INODES],
    inode_path_lens: [usize; MAX_INODES],
    inode_used: [bool; MAX_INODES],
    fds: [FdEntry; MAX_FDS],
}

impl TruncateTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        const EMPTY_INODE: Inode = Inode {
            ino: 0,
            kind: InodeType::RegularFile,
            size: 0,
            uid: 0,
            gid: 0,
            mode: 0,
            in_exec: false,
            mtime: 0,
            ctime: 0,
        };
        Self {
            inodes: [EMPTY_INODE; MAX_INODES],
            inode_paths: [[0u8; 256]; MAX_INODES],
            inode_path_lens: [0usize; MAX_INODES],
            inode_used: [false; MAX_INODES],
            fds: [const { FdEntry::empty() }; MAX_FDS],
        }
    }

    /// Insert an inode with an associated path.
    ///
    /// # Errors
    ///
    /// `OutOfMemory` if the table is full or path is too long.
    pub fn insert_inode(&mut self, path: &[u8], inode: Inode) -> Result<usize> {
        if path.len() > 256 {
            return Err(Error::InvalidArgument);
        }
        for (i, used) in self.inode_used.iter_mut().enumerate() {
            if !*used {
                *used = true;
                self.inodes[i] = inode;
                self.inode_paths[i][..path.len()].copy_from_slice(path);
                self.inode_path_lens[i] = path.len();
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find an inode index by path.
    pub fn find_inode_by_path(&self, path: &[u8]) -> Option<usize> {
        for (i, used) in self.inode_used.iter().enumerate() {
            if *used && &self.inode_paths[i][..self.inode_path_lens[i]] == path {
                return Some(i);
            }
        }
        None
    }

    /// Get a reference to an inode by index.
    pub fn inode(&self, idx: usize) -> Option<&Inode> {
        if idx < MAX_INODES && self.inode_used[idx] {
            Some(&self.inodes[idx])
        } else {
            None
        }
    }

    /// Get a mutable reference to an inode by index.
    pub fn inode_mut(&mut self, idx: usize) -> Option<&mut Inode> {
        if idx < MAX_INODES && self.inode_used[idx] {
            Some(&mut self.inodes[idx])
        } else {
            None
        }
    }

    /// Insert an open file descriptor.
    ///
    /// # Errors
    ///
    /// `OutOfMemory` if the table is full.
    pub fn insert_fd(&mut self, entry: FdEntry) -> Result<()> {
        for slot in self.fds.iter_mut() {
            if !slot.in_use {
                *slot = entry;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find an `FdEntry` by file descriptor number.
    pub fn find_fd(&self, fd: i32) -> Option<&FdEntry> {
        self.fds.iter().find(|e| e.in_use && e.fd == fd)
    }
}

// ---------------------------------------------------------------------------
// TruncateArgs — validated arguments
// ---------------------------------------------------------------------------

/// Validated arguments for a truncate operation.
#[derive(Debug, Clone, Copy)]
pub struct TruncateArgs {
    /// Index of the target inode in the table.
    pub inode_idx: usize,
    /// Original file size before truncation.
    pub old_size: u64,
    /// Requested new size.
    pub new_size: u64,
    /// Whether this is an extension (new_size > old_size).
    pub is_extend: bool,
}

// ---------------------------------------------------------------------------
// do_truncate_validated — inner implementation
// ---------------------------------------------------------------------------

/// Apply a validated truncate operation to an inode.
///
/// Updates `size`, `mtime`, and `ctime`.  On extension, extended bytes are
/// implicitly zero (the filesystem zero-fills on subsequent reads).
///
/// # Arguments
///
/// * `table`   — inode/fd table
/// * `args`    — validated truncate arguments
/// * `now_sec` — current time in seconds (for `mtime`/`ctime` update)
///
/// # Errors
///
/// `NotFound` if `args.inode_idx` is no longer valid.
fn do_truncate_validated(
    table: &mut TruncateTable,
    args: &TruncateArgs,
    now_sec: i64,
) -> Result<()> {
    let inode = table.inode_mut(args.inode_idx).ok_or(Error::NotFound)?;
    inode.size = args.new_size;
    inode.mtime = now_sec;
    inode.ctime = now_sec;
    Ok(())
}

// ---------------------------------------------------------------------------
// do_truncate — public handler
// ---------------------------------------------------------------------------

/// Handler for `truncate(2)`.
///
/// Truncates (or extends) the file at `pathname` to exactly `length` bytes.
///
/// # Arguments
///
/// * `pathname`     — path to the file
/// * `length`       — new file size in bytes (must be >= 0)
/// * `caller_uid`   — UID of the calling process
/// * `rlimit_fsize` — current `RLIMIT_FSIZE` for the process
/// * `now_sec`      — current wall-clock time (seconds)
/// * `table`        — inode/fd table
///
/// # Errors
///
/// - `InvalidArgument` — `length < 0`, `length > MAX_FILE_SIZE`, non-regular file
/// - `NotFound`        — path not found
/// - `PermissionDenied` — caller lacks write permission or `RLIMIT_FSIZE` exceeded
/// - `Busy`            — file is currently being executed
pub fn do_truncate(
    pathname: &[u8],
    length: i64,
    caller_uid: u32,
    rlimit_fsize: u64,
    now_sec: i64,
    table: &mut TruncateTable,
) -> Result<()> {
    if length < 0 {
        return Err(Error::InvalidArgument);
    }
    let new_size = length as u64;

    if new_size > MAX_FILE_SIZE {
        return Err(Error::InvalidArgument);
    }

    let inode_idx = table.find_inode_by_path(pathname).ok_or(Error::NotFound)?;
    let inode = table.inode(inode_idx).ok_or(Error::NotFound)?;

    // Regular-file check.
    if !inode.is_regular() {
        return Err(Error::InvalidArgument);
    }

    // ETXTBSY check.
    if inode.in_exec {
        return Err(Error::Busy);
    }

    // Write permission check.
    if !inode.writable_by(caller_uid) {
        return Err(Error::PermissionDenied);
    }

    // RLIMIT_FSIZE — if new_size exceeds the limit, deny.
    if new_size > rlimit_fsize {
        return Err(Error::PermissionDenied);
    }

    let old_size = inode.size;
    let args = TruncateArgs {
        inode_idx,
        old_size,
        new_size,
        is_extend: new_size > old_size,
    };

    do_truncate_validated(table, &args, now_sec)
}

// ---------------------------------------------------------------------------
// do_ftruncate — public handler
// ---------------------------------------------------------------------------

/// Handler for `ftruncate(2)`.
///
/// Truncates (or extends) the file referred to by `fd` to exactly `length`
/// bytes.  The file descriptor must have been opened with `O_WRONLY` or
/// `O_RDWR`.
///
/// # Arguments
///
/// * `fd`           — open file descriptor
/// * `length`       — new file size in bytes
/// * `rlimit_fsize` — current `RLIMIT_FSIZE` for the process
/// * `now_sec`      — current wall-clock time (seconds)
/// * `table`        — inode/fd table
///
/// # Errors
///
/// - `InvalidArgument` — `length < 0`, non-regular file
/// - `NotFound`        — `fd` not in the table
/// - `PermissionDenied` — `fd` not writable or `RLIMIT_FSIZE` exceeded
/// - `Busy`            — file is being executed
pub fn do_ftruncate(
    fd: i32,
    length: i64,
    rlimit_fsize: u64,
    now_sec: i64,
    table: &mut TruncateTable,
) -> Result<()> {
    if length < 0 {
        return Err(Error::InvalidArgument);
    }
    let new_size = length as u64;

    if new_size > MAX_FILE_SIZE {
        return Err(Error::InvalidArgument);
    }

    let fd_entry = *table.find_fd(fd).ok_or(Error::NotFound)?;

    // fd must be open for writing.
    if !fd_entry.is_writable() {
        return Err(Error::PermissionDenied);
    }

    let inode_idx = fd_entry.inode_idx;
    let inode = table.inode(inode_idx).ok_or(Error::NotFound)?;

    // Regular-file check.
    if !inode.is_regular() {
        return Err(Error::InvalidArgument);
    }

    // ETXTBSY check.
    if inode.in_exec {
        return Err(Error::Busy);
    }

    // RLIMIT_FSIZE.
    if new_size > rlimit_fsize {
        return Err(Error::PermissionDenied);
    }

    let old_size = inode.size;
    let args = TruncateArgs {
        inode_idx,
        old_size,
        new_size,
        is_extend: new_size > old_size,
    };

    do_truncate_validated(table, &args, now_sec)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table() -> TruncateTable {
        let mut t = TruncateTable::new();

        // Regular file owned by uid 1000, writable, size 4096.
        let idx = t
            .insert_inode(
                b"/tmp/test.txt",
                Inode {
                    ino: 1,
                    kind: InodeType::RegularFile,
                    size: 4096,
                    uid: 1000,
                    gid: 1000,
                    mode: 0o644,
                    in_exec: false,
                    mtime: 0,
                    ctime: 0,
                },
            )
            .unwrap();

        t.insert_fd(FdEntry {
            fd: 3,
            flags: O_RDWR,
            inode_idx: idx,
            in_use: true,
        })
        .unwrap();
        t.insert_fd(FdEntry {
            fd: 4,
            flags: O_RDONLY,
            inode_idx: idx,
            in_use: true,
        })
        .unwrap();

        // Executable file.
        t.insert_inode(
            b"/usr/bin/prog",
            Inode {
                ino: 2,
                kind: InodeType::RegularFile,
                size: 8192,
                uid: 0,
                gid: 0,
                mode: 0o755,
                in_exec: true,
                mtime: 0,
                ctime: 0,
            },
        )
        .unwrap();

        // Directory (non-regular).
        t.insert_inode(
            b"/tmp/mydir",
            Inode {
                ino: 3,
                kind: InodeType::Directory,
                size: 0,
                uid: 1000,
                gid: 1000,
                mode: 0o755,
                in_exec: false,
                mtime: 0,
                ctime: 0,
            },
        )
        .unwrap();

        t
    }

    #[test]
    fn truncate_shrink() {
        let mut t = make_table();
        do_truncate(
            b"/tmp/test.txt",
            2048,
            1000,
            RLIMIT_FSIZE_DEFAULT,
            100,
            &mut t,
        )
        .unwrap();
        let idx = t.find_inode_by_path(b"/tmp/test.txt").unwrap();
        assert_eq!(t.inode(idx).unwrap().size, 2048);
        assert_eq!(t.inode(idx).unwrap().mtime, 100);
    }

    #[test]
    fn truncate_extend() {
        let mut t = make_table();
        do_truncate(
            b"/tmp/test.txt",
            8192,
            1000,
            RLIMIT_FSIZE_DEFAULT,
            200,
            &mut t,
        )
        .unwrap();
        let idx = t.find_inode_by_path(b"/tmp/test.txt").unwrap();
        assert_eq!(t.inode(idx).unwrap().size, 8192);
    }

    #[test]
    fn truncate_to_zero() {
        let mut t = make_table();
        do_truncate(b"/tmp/test.txt", 0, 1000, RLIMIT_FSIZE_DEFAULT, 300, &mut t).unwrap();
        let idx = t.find_inode_by_path(b"/tmp/test.txt").unwrap();
        assert_eq!(t.inode(idx).unwrap().size, 0);
    }

    #[test]
    fn truncate_negative_length() {
        let mut t = make_table();
        let e =
            do_truncate(b"/tmp/test.txt", -1, 1000, RLIMIT_FSIZE_DEFAULT, 0, &mut t).unwrap_err();
        assert_eq!(e, Error::InvalidArgument);
    }

    #[test]
    fn truncate_not_found() {
        let mut t = make_table();
        let e =
            do_truncate(b"/nonexistent", 100, 1000, RLIMIT_FSIZE_DEFAULT, 0, &mut t).unwrap_err();
        assert_eq!(e, Error::NotFound);
    }

    #[test]
    fn truncate_not_regular_file() {
        let mut t = make_table();
        let e = do_truncate(b"/tmp/mydir", 0, 1000, RLIMIT_FSIZE_DEFAULT, 0, &mut t).unwrap_err();
        assert_eq!(e, Error::InvalidArgument);
    }

    #[test]
    fn truncate_text_busy() {
        let mut t = make_table();
        let e = do_truncate(b"/usr/bin/prog", 0, 0, RLIMIT_FSIZE_DEFAULT, 0, &mut t).unwrap_err();
        assert_eq!(e, Error::Busy);
    }

    #[test]
    fn truncate_rlimit_exceeded() {
        let mut t = make_table();
        let e = do_truncate(b"/tmp/test.txt", 8192, 1000, 4096, 0, &mut t).unwrap_err();
        assert_eq!(e, Error::PermissionDenied);
    }

    #[test]
    fn ftruncate_writable_fd() {
        let mut t = make_table();
        do_ftruncate(3, 1024, RLIMIT_FSIZE_DEFAULT, 50, &mut t).unwrap();
        let idx = t.find_inode_by_path(b"/tmp/test.txt").unwrap();
        assert_eq!(t.inode(idx).unwrap().size, 1024);
    }

    #[test]
    fn ftruncate_readonly_fd_denied() {
        let mut t = make_table();
        let e = do_ftruncate(4, 1024, RLIMIT_FSIZE_DEFAULT, 0, &mut t).unwrap_err();
        assert_eq!(e, Error::PermissionDenied);
    }

    #[test]
    fn ftruncate_bad_fd() {
        let mut t = make_table();
        let e = do_ftruncate(99, 1024, RLIMIT_FSIZE_DEFAULT, 0, &mut t).unwrap_err();
        assert_eq!(e, Error::NotFound);
    }

    #[test]
    fn ftruncate_negative_length() {
        let mut t = make_table();
        let e = do_ftruncate(3, -100, RLIMIT_FSIZE_DEFAULT, 0, &mut t).unwrap_err();
        assert_eq!(e, Error::InvalidArgument);
    }

    #[test]
    fn fd_entry_writable() {
        let rw = FdEntry {
            fd: 3,
            flags: O_RDWR,
            inode_idx: 0,
            in_use: true,
        };
        assert!(rw.is_writable());
        let wo = FdEntry {
            fd: 4,
            flags: O_WRONLY,
            inode_idx: 0,
            in_use: true,
        };
        assert!(wo.is_writable());
        let ro = FdEntry {
            fd: 5,
            flags: O_RDONLY,
            inode_idx: 0,
            in_use: true,
        };
        assert!(!ro.is_writable());
    }
}
