// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `readlink(2)` and `readlinkat(2)` syscall handlers.
//!
//! `readlink` reads the value of a symbolic link: the target path that the
//! symlink points to.  Unlike `stat`, `readlink` does **not** follow the
//! final component of the path — it reads the link itself.
//!
//! `readlinkat` is the modern `*at`-style variant that supports:
//! - `dirfd = AT_FDCWD`: interpret `pathname` relative to CWD (same as
//!   `readlink`).
//! - `dirfd = <valid fd>`: interpret relative `pathname` relative to the
//!   directory referred to by `dirfd`.
//! - `AT_EMPTY_PATH`: when `pathname` is empty, operate on `dirfd` itself.
//! - `AT_SYMLINK_NOFOLLOW`: always set for `readlink`; the call never follows
//!   the final symlink component.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `readlink()` and `readlinkat()`.
//!
//! Key behaviours:
//! - The null terminator is NOT included in the returned buffer or count.
//! - If the target path is longer than `bufsiz`, the result is silently
//!   truncated to `bufsiz` bytes (no error).  The caller should use a buffer
//!   at least `PATH_MAX` bytes long.
//! - No specific permission is required to read a symlink (on Linux);
//!   only execute permission on the directories in the path is needed.
//! - Returns `EINVAL` if `pathname` refers to a non-symlink inode.
//!
//! # References
//!
//! - POSIX.1-2024: `readlink()`, `readlinkat()`
//! - Linux man pages: `readlink(2)`
//! - Linux source: `fs/stat.c` `vfs_readlink()`, `do_readlinkat()`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Path constants
// ---------------------------------------------------------------------------

/// Maximum length of a path component.
pub const PATH_MAX: usize = 4096;

/// Maximum length of a symlink target.
pub const SYMLINK_MAX: usize = PATH_MAX;

/// Magic value for `dirfd` meaning "use the current working directory".
pub const AT_FDCWD: i32 = -100;

/// Flag: if `pathname` is empty, operate on `dirfd` itself.
pub const AT_EMPTY_PATH: i32 = 0x1000;

/// Flag: do not follow symlinks in the final path component.
///
/// For `readlink`/`readlinkat` this flag is always implied.
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;

/// All valid flags for `readlinkat`.
const READLINKAT_VALID_FLAGS: i32 = AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW;

// ---------------------------------------------------------------------------
// Inode type
// ---------------------------------------------------------------------------

/// Inode types relevant to `readlink`.
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

/// Stub representation of a VFS inode for `readlink`.
#[derive(Debug, Clone)]
pub struct Inode {
    /// Inode number.
    pub ino: u64,
    /// Inode type.
    pub kind: InodeType,
    /// Symlink target (only meaningful when `kind == Symlink`).
    pub symlink_target: SymlinkTarget,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Permission bits (lower 9 bits).
    pub mode: u16,
}

/// Fixed-capacity storage for a symlink target.
#[derive(Debug, Clone, Copy)]
pub struct SymlinkTarget {
    buf: [u8; PATH_MAX],
    len: usize,
}

impl SymlinkTarget {
    /// Create an empty target.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; PATH_MAX],
            len: 0,
        }
    }

    /// Set the target from a byte slice.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` if `target.len() > SYMLINK_MAX`.
    pub fn set(&mut self, target: &[u8]) -> Result<()> {
        if target.len() > SYMLINK_MAX {
            return Err(Error::InvalidArgument);
        }
        self.buf[..target.len()].copy_from_slice(target);
        self.len = target.len();
        Ok(())
    }

    /// Return the target as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Length of the target in bytes.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Return `true` if the target is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for SymlinkTarget {
    fn default() -> Self {
        Self::new()
    }
}

impl Inode {
    /// Return `true` if this inode is a symbolic link.
    pub const fn is_symlink(&self) -> bool {
        matches!(self.kind, InodeType::Symlink)
    }
}

// ---------------------------------------------------------------------------
// ReadlinkFlags — validated flags for readlinkat
// ---------------------------------------------------------------------------

/// Validated flags for `readlinkat(2)`.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadlinkFlags(i32);

impl ReadlinkFlags {
    /// Parse and validate flags.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` if unknown bits are set.
    pub fn from_raw(raw: i32) -> Result<Self> {
        if raw & !READLINKAT_VALID_FLAGS != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Return `true` if `AT_EMPTY_PATH` is set.
    pub const fn empty_path(&self) -> bool {
        self.0 & AT_EMPTY_PATH != 0
    }
}

// ---------------------------------------------------------------------------
// VFS path resolution stub
// ---------------------------------------------------------------------------

/// Maximum entries in the inode table.
pub const INODE_TABLE_SIZE: usize = 64;

/// Stub VFS that maps paths to inodes.
pub struct VfsTable {
    entries: [VfsEntry; INODE_TABLE_SIZE],
    count: usize,
}

#[derive(Clone)]
struct VfsEntry {
    path: PathBuf,
    inode: Inode,
    in_use: bool,
}

impl VfsEntry {
    const fn empty() -> Self {
        Self {
            path: PathBuf::new(),
            inode: Inode {
                ino: 0,
                kind: InodeType::RegularFile,
                symlink_target: SymlinkTarget::new(),
                uid: 0,
                gid: 0,
                mode: 0,
            },
            in_use: false,
        }
    }
}

/// Fixed-capacity path string.
#[derive(Clone, Copy)]
pub struct PathBuf {
    buf: [u8; 256],
    len: usize,
}

impl PathBuf {
    /// Create an empty path.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; 256],
            len: 0,
        }
    }

    /// Set the path from a byte slice.
    pub fn set(&mut self, path: &[u8]) -> Result<()> {
        if path.len() >= 256 {
            return Err(Error::InvalidArgument);
        }
        self.buf[..path.len()].copy_from_slice(path);
        self.len = path.len();
        Ok(())
    }

    /// Return the path as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Return `true` if the path is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for PathBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl VfsTable {
    /// Create an empty VFS table.
    pub const fn new() -> Self {
        Self {
            entries: [const { VfsEntry::empty() }; INODE_TABLE_SIZE],
            count: 0,
        }
    }

    /// Register a path → inode mapping.
    ///
    /// # Errors
    ///
    /// `OutOfMemory` if the table is full.
    pub fn insert(&mut self, path: &[u8], inode: Inode) -> Result<()> {
        if self.count >= INODE_TABLE_SIZE {
            return Err(Error::OutOfMemory);
        }
        for slot in self.entries.iter_mut() {
            if !slot.in_use {
                slot.path.set(path)?;
                slot.inode = inode;
                slot.in_use = true;
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up an inode by path.
    pub fn lookup(&self, path: &[u8]) -> Option<&Inode> {
        self.entries
            .iter()
            .find(|e| e.in_use && e.path.as_bytes() == path)
            .map(|e| &e.inode)
    }
}

// ---------------------------------------------------------------------------
// ReadlinkResult — result of a readlink call
// ---------------------------------------------------------------------------

/// Result of a successful `readlink`/`readlinkat` call.
#[derive(Debug)]
pub struct ReadlinkResult {
    /// Number of bytes written to the output buffer.
    pub bytes_written: usize,
    /// Whether the result was truncated.
    pub truncated: bool,
}

// ---------------------------------------------------------------------------
// do_readlink_at — core logic
// ---------------------------------------------------------------------------

/// Core implementation shared by `readlink` and `readlinkat`.
///
/// Resolves `pathname` relative to `dirfd` (or CWD if `AT_FDCWD`), looks up
/// the inode, verifies it is a symlink, and copies the target path into
/// `buf_ptr` (user-space address representation) up to `bufsiz` bytes.
///
/// # Arguments
///
/// * `dirfd`    — directory fd, or `AT_FDCWD`
/// * `pathname` — path to resolve (may be empty with `AT_EMPTY_PATH`)
/// * `buf`      — kernel-side output buffer (simulates `copy_to_user`)
/// * `bufsiz`   — maximum bytes to write
/// * `flags`    — validated `ReadlinkFlags`
/// * `vfs`      — VFS path lookup table
///
/// # Returns
///
/// A [`ReadlinkResult`] on success.
///
/// # Errors
///
/// - `InvalidArgument` — `bufsiz` is 0, or inode is not a symlink
/// - `NotFound`        — path does not exist in VFS
/// - `PermissionDenied` — caller cannot traverse the directory
pub fn do_readlink_at(
    dirfd: i32,
    pathname: &[u8],
    buf: &mut [u8],
    bufsiz: usize,
    flags: ReadlinkFlags,
    vfs: &VfsTable,
) -> Result<ReadlinkResult> {
    if bufsiz == 0 {
        return Err(Error::InvalidArgument);
    }
    if bufsiz > PATH_MAX {
        return Err(Error::InvalidArgument);
    }

    // AT_EMPTY_PATH requires a valid dirfd.
    if pathname.is_empty() {
        if !flags.empty_path() {
            return Err(Error::InvalidArgument);
        }
        if dirfd == AT_FDCWD || dirfd < 0 {
            return Err(Error::NotFound);
        }
    }

    // Resolve path in VFS.
    let inode = vfs.lookup(pathname).ok_or(Error::NotFound)?;

    // Must be a symlink.
    if !inode.is_symlink() {
        return Err(Error::InvalidArgument);
    }

    let target = inode.symlink_target.as_bytes();
    let write_len = target.len().min(bufsiz).min(buf.len());

    buf[..write_len].copy_from_slice(&target[..write_len]);

    Ok(ReadlinkResult {
        bytes_written: write_len,
        truncated: target.len() > bufsiz,
    })
}

// ---------------------------------------------------------------------------
// do_readlink — public handler
// ---------------------------------------------------------------------------

/// Handler for `readlink(2)`.
///
/// Reads the target of the symbolic link at `pathname` into `buf`, up to
/// `bufsiz` bytes.  Does not follow the final symlink.
///
/// # Arguments
///
/// * `pathname` — path to the symbolic link
/// * `buf`      — kernel-side output buffer
/// * `bufsiz`   — size of `buf`
/// * `vfs`      — VFS path lookup table
///
/// # Returns
///
/// A [`ReadlinkResult`] with the number of bytes written.
///
/// # Errors
///
/// - `InvalidArgument` — `bufsiz == 0` or path is not a symlink
/// - `NotFound`        — path does not exist
pub fn do_readlink(
    pathname: &[u8],
    buf: &mut [u8],
    bufsiz: usize,
    vfs: &VfsTable,
) -> Result<ReadlinkResult> {
    let flags = ReadlinkFlags::from_raw(AT_SYMLINK_NOFOLLOW)?;
    do_readlink_at(AT_FDCWD, pathname, buf, bufsiz, flags, vfs)
}

// ---------------------------------------------------------------------------
// do_readlinkat — public handler
// ---------------------------------------------------------------------------

/// Handler for `readlinkat(2)`.
///
/// The `*at` variant of `readlink`, supporting both `AT_FDCWD` and directory
/// file descriptors.  Accepts `AT_EMPTY_PATH` to operate on `dirfd` itself.
///
/// # Arguments
///
/// * `dirfd`    — directory fd or `AT_FDCWD`
/// * `pathname` — path (may be empty if `AT_EMPTY_PATH` is set)
/// * `buf`      — kernel-side output buffer
/// * `bufsiz`   — size of `buf`
/// * `flags`    — raw flags integer
/// * `vfs`      — VFS path lookup table
///
/// # Returns
///
/// A [`ReadlinkResult`] with the number of bytes written.
///
/// # Errors
///
/// - `InvalidArgument` — bad flags, `bufsiz == 0`, or path is not a symlink
/// - `NotFound`        — path not found or `AT_EMPTY_PATH` with bad `dirfd`
pub fn do_readlinkat(
    dirfd: i32,
    pathname: &[u8],
    buf: &mut [u8],
    bufsiz: usize,
    flags: i32,
    vfs: &VfsTable,
) -> Result<ReadlinkResult> {
    let validated_flags = ReadlinkFlags::from_raw(flags)?;
    do_readlink_at(dirfd, pathname, buf, bufsiz, validated_flags, vfs)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_vfs() -> VfsTable {
        let mut vfs = VfsTable::new();

        let mut sym_target = SymlinkTarget::new();
        sym_target.set(b"/etc/real_config").unwrap();
        vfs.insert(
            b"/etc/config",
            Inode {
                ino: 1,
                kind: InodeType::Symlink,
                symlink_target: sym_target,
                uid: 0,
                gid: 0,
                mode: 0o777,
            },
        )
        .unwrap();

        vfs.insert(
            b"/etc/passwd",
            Inode {
                ino: 2,
                kind: InodeType::RegularFile,
                symlink_target: SymlinkTarget::new(),
                uid: 0,
                gid: 0,
                mode: 0o644,
            },
        )
        .unwrap();

        let mut long_target = SymlinkTarget::new();
        long_target
            .set(b"/very/long/target/path/that/exceeds/small/buffers")
            .unwrap();
        vfs.insert(
            b"/tmp/long_link",
            Inode {
                ino: 3,
                kind: InodeType::Symlink,
                symlink_target: long_target,
                uid: 1000,
                gid: 1000,
                mode: 0o777,
            },
        )
        .unwrap();

        vfs
    }

    #[test]
    fn readlink_basic() {
        let vfs = make_vfs();
        let mut buf = [0u8; 64];
        let r = do_readlink(b"/etc/config", &mut buf, 64, &vfs).unwrap();
        assert_eq!(r.bytes_written, b"/etc/real_config".len());
        assert!(!r.truncated);
        assert_eq!(&buf[..r.bytes_written], b"/etc/real_config");
    }

    #[test]
    fn readlink_truncation() {
        let vfs = make_vfs();
        let mut buf = [0u8; 8];
        let r = do_readlink(b"/tmp/long_link", &mut buf, 8, &vfs).unwrap();
        assert_eq!(r.bytes_written, 8);
        assert!(r.truncated);
    }

    #[test]
    fn readlink_not_symlink() {
        let vfs = make_vfs();
        let mut buf = [0u8; 64];
        let e = do_readlink(b"/etc/passwd", &mut buf, 64, &vfs).unwrap_err();
        assert_eq!(e, Error::InvalidArgument);
    }

    #[test]
    fn readlink_not_found() {
        let vfs = make_vfs();
        let mut buf = [0u8; 64];
        let e = do_readlink(b"/nonexistent", &mut buf, 64, &vfs).unwrap_err();
        assert_eq!(e, Error::NotFound);
    }

    #[test]
    fn readlink_zero_bufsiz() {
        let vfs = make_vfs();
        let mut buf = [0u8; 64];
        let e = do_readlink(b"/etc/config", &mut buf, 0, &vfs).unwrap_err();
        assert_eq!(e, Error::InvalidArgument);
    }

    #[test]
    fn readlinkat_at_fdcwd() {
        let vfs = make_vfs();
        let mut buf = [0u8; 64];
        let r = do_readlinkat(AT_FDCWD, b"/etc/config", &mut buf, 64, 0, &vfs).unwrap();
        assert_eq!(r.bytes_written, b"/etc/real_config".len());
    }

    #[test]
    fn readlinkat_bad_flags() {
        let vfs = make_vfs();
        let mut buf = [0u8; 64];
        let e = do_readlinkat(AT_FDCWD, b"/etc/config", &mut buf, 64, 0x9999, &vfs).unwrap_err();
        assert_eq!(e, Error::InvalidArgument);
    }

    #[test]
    fn readlinkat_empty_path_no_flag() {
        let vfs = make_vfs();
        let mut buf = [0u8; 64];
        let e = do_readlinkat(5, b"", &mut buf, 64, 0, &vfs).unwrap_err();
        assert_eq!(e, Error::InvalidArgument);
    }

    #[test]
    fn symlink_target_truncation_at_bufsiz() {
        let vfs = make_vfs();
        let target = b"/etc/real_config";
        let trunc_size = 5;
        let mut buf = [0u8; 5];
        let r = do_readlink(b"/etc/config", &mut buf, trunc_size, &vfs).unwrap();
        assert_eq!(r.bytes_written, trunc_size);
        assert!(r.truncated);
        assert_eq!(&buf[..trunc_size], &target[..trunc_size]);
    }

    #[test]
    fn readlink_flags_empty_path() {
        let f = ReadlinkFlags::from_raw(AT_EMPTY_PATH).unwrap();
        assert!(f.empty_path());
    }

    #[test]
    fn readlink_flags_invalid() {
        assert!(ReadlinkFlags::from_raw(0x1234).is_err());
    }
}
