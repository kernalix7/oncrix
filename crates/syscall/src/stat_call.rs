// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `stat(2)` / `fstat(2)` / `lstat(2)` / `fstatat(2)` syscall handlers.
//!
//! Retrieves file metadata (inode number, mode, ownership, timestamps,
//! size, and block counts) into a `struct stat`-compatible buffer.
//!
//! # Syscalls
//!
//! | Syscall | Handler | Description |
//! |---------|---------|-------------|
//! | `stat`    | [`do_stat`]    | Stat a path (follows symlinks) |
//! | `fstat`   | [`do_fstat`]   | Stat an open fd |
//! | `lstat`   | [`do_lstat`]   | Stat a path (does not follow symlinks) |
//! | `fstatat` | [`do_fstatat`] | Stat with dir-fd + flags |
//!
//! # Key types
//!
//! - [`StatBuf`]   — the kernel-visible stat structure
//! - [`StatEntry`] — a stub inode record
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `stat()` / `fstat()` / `lstat()`.
//!
//! # References
//!
//! - POSIX.1-2024: `stat()`, `fstat()`, `lstat()`
//! - Linux: `fs/stat.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// AT_* flags for fstatat
// ---------------------------------------------------------------------------

/// `AT_FDCWD` — use current working directory for relative paths.
pub const AT_FDCWD: i32 = -100;
/// `AT_SYMLINK_NOFOLLOW` — do not follow symlinks (like `lstat`).
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
/// `AT_EMPTY_PATH` — allow empty path to stat the fd itself.
pub const AT_EMPTY_PATH: u32 = 0x1000;

/// Maximum path length.
pub const PATH_MAX: usize = 4096;
/// Maximum number of inodes in the stat table.
pub const MAX_STAT_INODES: usize = 256;

// ---------------------------------------------------------------------------
// Timestamp — coarse time representation
// ---------------------------------------------------------------------------

/// A coarse timestamp (seconds + nanoseconds since Unix epoch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timestamp {
    /// Seconds since epoch.
    pub sec: i64,
    /// Nanoseconds within the second.
    pub nsec: u32,
}

impl Timestamp {
    /// Create a timestamp at the given second.
    pub const fn from_sec(sec: i64) -> Self {
        Self { sec, nsec: 0 }
    }
}

// ---------------------------------------------------------------------------
// FileMode bits
// ---------------------------------------------------------------------------

/// Mode bits: regular file.
pub const S_IFREG: u32 = 0o100000;
/// Mode bits: directory.
pub const S_IFDIR: u32 = 0o040000;
/// Mode bits: symlink.
pub const S_IFLNK: u32 = 0o120000;
/// Mode bits: character device.
pub const S_IFCHR: u32 = 0o020000;
/// Mode bits: block device.
pub const S_IFBLK: u32 = 0o060000;
/// Mode bits: FIFO.
pub const S_IFIFO: u32 = 0o010000;
/// Mode bits: socket.
pub const S_IFSOCK: u32 = 0o140000;
/// Mode type mask.
pub const S_IFMT: u32 = 0o170000;

// ---------------------------------------------------------------------------
// StatBuf — the stat structure
// ---------------------------------------------------------------------------

/// The kernel-visible `struct stat` buffer.
///
/// Matches the layout expected by POSIX `stat()`.  Fields use the
/// same types as `struct stat` in `<sys/stat.h>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StatBuf {
    /// ID of device containing the file.
    pub st_dev: u64,
    /// Inode number.
    pub st_ino: u64,
    /// File mode (type + permissions).
    pub st_mode: u32,
    /// Number of hard links.
    pub st_nlink: u32,
    /// User ID of file owner.
    pub st_uid: u32,
    /// Group ID of file owner.
    pub st_gid: u32,
    /// Device ID (for special files).
    pub st_rdev: u64,
    /// Total file size in bytes.
    pub st_size: u64,
    /// Block size for filesystem I/O.
    pub st_blksize: u64,
    /// Number of 512-byte blocks allocated.
    pub st_blocks: u64,
    /// Last access time.
    pub st_atime: Timestamp,
    /// Last data modification time.
    pub st_mtime: Timestamp,
    /// Last status change time.
    pub st_ctime: Timestamp,
}

impl StatBuf {
    /// Return the file type portion of `st_mode`.
    pub const fn file_type(&self) -> u32 {
        self.st_mode & S_IFMT
    }

    /// Return `true` if this stat describes a regular file.
    pub const fn is_regular(&self) -> bool {
        self.file_type() == S_IFREG
    }

    /// Return `true` if this stat describes a directory.
    pub const fn is_dir(&self) -> bool {
        self.file_type() == S_IFDIR
    }

    /// Return `true` if this stat describes a symlink.
    pub const fn is_symlink(&self) -> bool {
        self.file_type() == S_IFLNK
    }
}

// ---------------------------------------------------------------------------
// StatEntry — stub inode record
// ---------------------------------------------------------------------------

/// A stub inode record stored in the stat table.
#[derive(Debug, Clone, Copy)]
pub struct StatEntry {
    /// Inode number (also used as lookup key).
    pub ino: u64,
    /// Device ID.
    pub dev: u64,
    /// File mode.
    pub mode: u32,
    /// Number of hard links.
    pub nlink: u32,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Device ID for special files.
    pub rdev: u64,
    /// File size.
    pub size: u64,
    /// Preferred block size.
    pub blksize: u64,
    /// Timestamps.
    pub atime: Timestamp,
    pub mtime: Timestamp,
    pub ctime: Timestamp,
    /// Path hash (stub dentry: hash of the file path).
    pub path_hash: u64,
    /// Whether this is a symlink target inode (affects lstat behaviour).
    pub is_symlink_target: bool,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl StatEntry {
    const fn empty() -> Self {
        Self {
            ino: 0,
            dev: 0,
            mode: 0,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            size: 0,
            blksize: 4096,
            atime: Timestamp { sec: 0, nsec: 0 },
            mtime: Timestamp { sec: 0, nsec: 0 },
            ctime: Timestamp { sec: 0, nsec: 0 },
            path_hash: 0,
            is_symlink_target: false,
            in_use: false,
        }
    }

    /// Convert this entry into a [`StatBuf`].
    pub fn to_stat_buf(&self) -> StatBuf {
        let blocks = (self.size + 511) / 512;
        StatBuf {
            st_dev: self.dev,
            st_ino: self.ino,
            st_mode: self.mode,
            st_nlink: self.nlink,
            st_uid: self.uid,
            st_gid: self.gid,
            st_rdev: self.rdev,
            st_size: self.size,
            st_blksize: self.blksize,
            st_blocks: blocks,
            st_atime: self.atime,
            st_mtime: self.mtime,
            st_ctime: self.ctime,
        }
    }
}

// ---------------------------------------------------------------------------
// StatTable — inode table for stat lookup
// ---------------------------------------------------------------------------

/// A stub stat inode table.
pub struct StatTable {
    entries: [StatEntry; MAX_STAT_INODES],
    count: usize,
}

impl StatTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { StatEntry::empty() }; MAX_STAT_INODES],
            count: 0,
        }
    }

    /// Insert a stat entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn insert(&mut self, mut e: StatEntry) -> Result<u64> {
        for slot in self.entries.iter_mut() {
            if !slot.in_use {
                e.in_use = true;
                let ino = e.ino;
                *slot = e;
                self.count += 1;
                return Ok(ino);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a stat entry by inode number.
    pub fn find_by_ino(&self, ino: u64) -> Option<&StatEntry> {
        self.entries.iter().find(|e| e.in_use && e.ino == ino)
    }

    /// Find a stat entry by path hash (stub dentry lookup).
    pub fn find_by_path_hash(&self, hash: u64) -> Option<&StatEntry> {
        self.entries
            .iter()
            .find(|e| e.in_use && e.path_hash == hash)
    }

    /// Return the number of entries.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for StatTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FdStatEntry — fd → inode mapping
// ---------------------------------------------------------------------------

/// Maps an open fd to an inode entry.
#[derive(Clone, Copy)]
struct FdStatEntry {
    fd: i32,
    ino: u64,
    in_use: bool,
}

impl FdStatEntry {
    const fn empty() -> Self {
        Self {
            fd: -1,
            ino: 0,
            in_use: false,
        }
    }
}

/// Maximum number of open fds in the stat fd map.
pub const MAX_STAT_FDS: usize = 256;

/// A stub map from fd number to inode number.
pub struct StatFdMap {
    entries: [FdStatEntry; MAX_STAT_FDS],
}

impl StatFdMap {
    /// Create an empty map.
    pub const fn new() -> Self {
        Self {
            entries: [const { FdStatEntry::empty() }; MAX_STAT_FDS],
        }
    }

    /// Register an fd → ino mapping.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the map is full.
    pub fn register(&mut self, fd: i32, ino: u64) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if !slot.in_use {
                *slot = FdStatEntry {
                    fd,
                    ino,
                    in_use: true,
                };
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up the inode number for an fd.
    pub fn ino_for_fd(&self, fd: i32) -> Option<u64> {
        self.entries
            .iter()
            .find(|e| e.in_use && e.fd == fd)
            .map(|e| e.ino)
    }
}

impl Default for StatFdMap {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Path hash helper
// ---------------------------------------------------------------------------

/// Compute a simple FNV-1a hash for a byte path.
pub fn path_hash(path: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in path {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

// ---------------------------------------------------------------------------
// do_fstat — stat by fd
// ---------------------------------------------------------------------------

/// Handler for `fstat(2)`.
///
/// Fills `buf` with metadata of the file referred to by `fd`.
///
/// # Errors
///
/// * [`Error::NotFound`] — `fd` not open, or inode not found
pub fn do_fstat(inodes: &StatTable, fd_map: &StatFdMap, fd: i32) -> Result<StatBuf> {
    let ino = fd_map.ino_for_fd(fd).ok_or(Error::NotFound)?;
    let entry = inodes.find_by_ino(ino).ok_or(Error::NotFound)?;
    Ok(entry.to_stat_buf())
}

// ---------------------------------------------------------------------------
// do_stat — stat by path (follows symlinks)
// ---------------------------------------------------------------------------

/// Handler for `stat(2)`.
///
/// Resolves `path` (following symbolic links) and fills `buf` with
/// the target inode's metadata.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — empty or overlong path
/// * [`Error::NotFound`]        — path not found in the stub table
pub fn do_stat(inodes: &StatTable, path: &[u8]) -> Result<StatBuf> {
    if path.is_empty() || path.len() >= PATH_MAX {
        return Err(Error::InvalidArgument);
    }
    let hash = path_hash(path);
    // Follow symlinks: resolve until we reach a non-symlink entry.
    let entry = inodes.find_by_path_hash(hash).ok_or(Error::NotFound)?;
    // Stub: for simplicity follow by looking up the "target" (same hash).
    Ok(entry.to_stat_buf())
}

// ---------------------------------------------------------------------------
// do_lstat — stat by path (does not follow final symlink)
// ---------------------------------------------------------------------------

/// Handler for `lstat(2)`.
///
/// Like [`do_stat`] but returns metadata for the symbolic link itself
/// rather than its target.
///
/// # Errors
///
/// Same as [`do_stat`].
pub fn do_lstat(inodes: &StatTable, path: &[u8]) -> Result<StatBuf> {
    if path.is_empty() || path.len() >= PATH_MAX {
        return Err(Error::InvalidArgument);
    }
    let hash = path_hash(path);
    let entry = inodes.find_by_path_hash(hash).ok_or(Error::NotFound)?;
    Ok(entry.to_stat_buf())
}

// ---------------------------------------------------------------------------
// do_fstatat — stat with dirfd + flags
// ---------------------------------------------------------------------------

/// Handler for `fstatat(2)` (also known as `newfstatat`).
///
/// Combines `stat`, `lstat`, and fd-relative path lookup.
///
/// Supported flags:
/// - [`AT_SYMLINK_NOFOLLOW`] — do not follow symlinks (like `lstat`)
/// - [`AT_EMPTY_PATH`]       — stat the open file `dirfd` itself
///
/// # Arguments
///
/// * `inodes` — inode table
/// * `fd_map` — fd → ino map
/// * `dirfd`  — directory fd for relative paths, or `AT_FDCWD`
/// * `path`   — relative or absolute path
/// * `flags`  — `AT_SYMLINK_NOFOLLOW` and/or `AT_EMPTY_PATH`
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — unknown flags, or empty path without `AT_EMPTY_PATH`
/// * [`Error::NotFound`]        — path/fd not found
pub fn do_fstatat(
    inodes: &StatTable,
    fd_map: &StatFdMap,
    dirfd: i32,
    path: &[u8],
    flags: u32,
) -> Result<StatBuf> {
    let unknown = flags & !(AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH);
    if unknown != 0 {
        return Err(Error::InvalidArgument);
    }

    // AT_EMPTY_PATH: stat the fd itself.
    if flags & AT_EMPTY_PATH != 0 && path.is_empty() {
        return do_fstat(inodes, fd_map, dirfd);
    }

    if path.is_empty() {
        return Err(Error::InvalidArgument);
    }

    // AT_SYMLINK_NOFOLLOW → use lstat semantics.
    if flags & AT_SYMLINK_NOFOLLOW != 0 {
        do_lstat(inodes, path)
    } else {
        do_stat(inodes, path)
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tables() -> (StatTable, StatFdMap) {
        let mut inodes = StatTable::new();
        let mut fd_map = StatFdMap::new();

        // Regular file: ino=10, path="/etc/passwd"
        inodes
            .insert(StatEntry {
                ino: 10,
                dev: 1,
                mode: S_IFREG | 0o644,
                nlink: 1,
                uid: 0,
                gid: 0,
                rdev: 0,
                size: 2048,
                blksize: 4096,
                atime: Timestamp::from_sec(1000),
                mtime: Timestamp::from_sec(2000),
                ctime: Timestamp::from_sec(3000),
                path_hash: path_hash(b"/etc/passwd"),
                is_symlink_target: false,
                in_use: true,
            })
            .unwrap();

        // Directory: ino=5, path="/etc"
        inodes
            .insert(StatEntry {
                ino: 5,
                dev: 1,
                mode: S_IFDIR | 0o755,
                nlink: 2,
                uid: 0,
                gid: 0,
                rdev: 0,
                size: 4096,
                blksize: 4096,
                atime: Timestamp::from_sec(100),
                mtime: Timestamp::from_sec(200),
                ctime: Timestamp::from_sec(300),
                path_hash: path_hash(b"/etc"),
                is_symlink_target: false,
                in_use: true,
            })
            .unwrap();

        fd_map.register(3, 10).unwrap(); // fd 3 → ino 10
        fd_map.register(4, 5).unwrap(); // fd 4 → ino 5

        (inodes, fd_map)
    }

    #[test]
    fn fstat_regular_file() {
        let (inodes, fd_map) = make_tables();
        let buf = do_fstat(&inodes, &fd_map, 3).unwrap();
        assert_eq!(buf.st_ino, 10);
        assert_eq!(buf.st_size, 2048);
        assert!(buf.is_regular());
    }

    #[test]
    fn fstat_directory() {
        let (inodes, fd_map) = make_tables();
        let buf = do_fstat(&inodes, &fd_map, 4).unwrap();
        assert!(buf.is_dir());
    }

    #[test]
    fn fstat_not_found() {
        let (inodes, fd_map) = make_tables();
        assert_eq!(do_fstat(&inodes, &fd_map, 99), Err(Error::NotFound));
    }

    #[test]
    fn stat_by_path() {
        let (inodes, _) = make_tables();
        let buf = do_stat(&inodes, b"/etc/passwd").unwrap();
        assert_eq!(buf.st_ino, 10);
    }

    #[test]
    fn stat_empty_path_rejected() {
        let (inodes, _) = make_tables();
        assert_eq!(do_stat(&inodes, b""), Err(Error::InvalidArgument));
    }

    #[test]
    fn stat_not_found() {
        let (inodes, _) = make_tables();
        assert_eq!(do_stat(&inodes, b"/missing"), Err(Error::NotFound));
    }

    #[test]
    fn lstat_by_path() {
        let (inodes, _) = make_tables();
        let buf = do_lstat(&inodes, b"/etc/passwd").unwrap();
        assert_eq!(buf.st_ino, 10);
    }

    #[test]
    fn fstatat_empty_path_at_empty_path() {
        let (inodes, fd_map) = make_tables();
        let buf = do_fstatat(&inodes, &fd_map, 3, b"", AT_EMPTY_PATH).unwrap();
        assert_eq!(buf.st_ino, 10);
    }

    #[test]
    fn fstatat_symlink_nofollow() {
        let (inodes, fd_map) = make_tables();
        let buf = do_fstatat(
            &inodes,
            &fd_map,
            AT_FDCWD,
            b"/etc/passwd",
            AT_SYMLINK_NOFOLLOW,
        )
        .unwrap();
        assert_eq!(buf.st_ino, 10);
    }

    #[test]
    fn fstatat_unknown_flags_rejected() {
        let (inodes, fd_map) = make_tables();
        assert_eq!(
            do_fstatat(&inodes, &fd_map, AT_FDCWD, b"/etc", 0xFFFF),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn stat_buf_blocks_computed() {
        let (inodes, fd_map) = make_tables();
        let buf = do_fstat(&inodes, &fd_map, 3).unwrap();
        // 2048 bytes → 4 blocks of 512 bytes each.
        assert_eq!(buf.st_blocks, 4);
    }

    #[test]
    fn stat_buf_mode_predicates() {
        let mut buf = StatBuf::default();
        buf.st_mode = S_IFREG | 0o644;
        assert!(buf.is_regular());
        assert!(!buf.is_dir());
        assert!(!buf.is_symlink());

        buf.st_mode = S_IFDIR | 0o755;
        assert!(buf.is_dir());

        buf.st_mode = S_IFLNK | 0o777;
        assert!(buf.is_symlink());
    }
}
