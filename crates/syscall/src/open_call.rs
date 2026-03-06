// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `open(2)` / `openat(2)` syscall handler.
//!
//! Implements the POSIX.1-2024 `open()` and `openat()` interfaces which
//! establish an open file description and allocate a file descriptor in the
//! calling process's open file description table.
//!
//! # Flags
//!
//! | Flag | Value | Description |
//! |------|-------|-------------|
//! | `O_RDONLY`    | 0 | Open for reading only |
//! | `O_WRONLY`    | 1 | Open for writing only |
//! | `O_RDWR`      | 2 | Open for reading and writing |
//! | `O_CREAT`     | 0x040 | Create file if it does not exist |
//! | `O_EXCL`      | 0x080 | Error if file exists (with O_CREAT) |
//! | `O_TRUNC`     | 0x200 | Truncate file to zero length on open |
//! | `O_APPEND`    | 0x400 | Always write at end of file |
//! | `O_NONBLOCK`  | 0x800 | Non-blocking I/O |
//! | `O_CLOEXEC`   | 0x80000 | Set FD_CLOEXEC flag |
//! | `O_DIRECTORY` | 0x10000 | Fail if path is not a directory |
//! | `O_NOFOLLOW`  | 0x20000 | Fail if path is a symlink |
//!
//! # Key types
//!
//! - [`OpenFlags`]  — validated open flags
//! - [`FileMode`]   — permission bits (mode_t)
//! - [`OpenRequest`] — validated open request before fd allocation
//! - [`OpenFdTable`] — simple fd allocator table
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `open()` / `openat()` semantics.  Stub path
//! resolution and inode creation are simulated; a real VFS integration
//! would call into `crates/vfs/`.
//!
//! # References
//!
//! - POSIX.1-2024: `open()`, `openat()`
//! - Linux: `fs/open.c`, `do_sys_open()`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// O_* flag constants
// ---------------------------------------------------------------------------

/// Open for reading only.
pub const O_RDONLY: u32 = 0;
/// Open for writing only.
pub const O_WRONLY: u32 = 1;
/// Open for reading and writing.
pub const O_RDWR: u32 = 2;
/// Mask for access-mode bits.
pub const O_ACCMODE: u32 = 3;
/// Create file if it does not exist.
pub const O_CREAT: u32 = 0o0000100;
/// Error if file exists (used with O_CREAT).
pub const O_EXCL: u32 = 0o0000200;
/// Truncate file to length 0 on open for writing.
pub const O_TRUNC: u32 = 0o0001000;
/// Append to end of file on each write.
pub const O_APPEND: u32 = 0o0002000;
/// Non-blocking I/O.
pub const O_NONBLOCK: u32 = 0o0004000;
/// Set FD_CLOEXEC on the new fd.
pub const O_CLOEXEC: u32 = 0o2000000;
/// Fail if path is not a directory.
pub const O_DIRECTORY: u32 = 0o0200000;
/// Fail if final path component is a symbolic link.
pub const O_NOFOLLOW: u32 = 0o0400000;

/// Special value for `dirfd` meaning the current working directory.
pub const AT_FDCWD: i32 = -100;

/// Maximum path length (POSIX PATH_MAX).
pub const PATH_MAX: usize = 4096;

/// Maximum number of file descriptors in the stub table.
pub const MAX_OPEN_FILES: usize = 1024;

/// All known open flags — used to reject unknown flag bits.
const KNOWN_FLAGS: u32 = O_WRONLY
    | O_RDWR
    | O_CREAT
    | O_EXCL
    | O_TRUNC
    | O_APPEND
    | O_NONBLOCK
    | O_CLOEXEC
    | O_DIRECTORY
    | O_NOFOLLOW;

// ---------------------------------------------------------------------------
// FileMode — permission bits
// ---------------------------------------------------------------------------

/// File permission mode (`mode_t`).
///
/// Represents the 12-bit POSIX permission bits:
/// - bits 11–9: setuid, setgid, sticky
/// - bits 8–6: owner rwx
/// - bits 5–3: group rwx
/// - bits 2–0: other rwx
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileMode(pub u32);

impl FileMode {
    /// Owner read, write, execute.
    pub const OWNER_ALL: Self = Self(0o700);
    /// Group read, write, execute.
    pub const GROUP_ALL: Self = Self(0o070);
    /// Others read, write, execute.
    pub const OTHER_ALL: Self = Self(0o007);
    /// Default file creation mode (0o644).
    pub const DEFAULT_FILE: Self = Self(0o644);
    /// Default directory creation mode (0o755).
    pub const DEFAULT_DIR: Self = Self(0o755);

    /// Apply umask: return `self & !umask`.
    pub const fn apply_umask(self, umask: u32) -> Self {
        Self(self.0 & !umask)
    }

    /// Return the raw mode bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Return `true` if the owner-execute bit is set.
    pub const fn owner_exec(self) -> bool {
        self.0 & 0o100 != 0
    }

    /// Return `true` if the owner-write bit is set.
    pub const fn owner_write(self) -> bool {
        self.0 & 0o200 != 0
    }

    /// Return `true` if the owner-read bit is set.
    pub const fn owner_read(self) -> bool {
        self.0 & 0o400 != 0
    }
}

// ---------------------------------------------------------------------------
// OpenFlags — validated open flags
// ---------------------------------------------------------------------------

/// Validated flags for `open(2)` / `openat(2)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenFlags(pub u32);

impl OpenFlags {
    /// Construct from raw syscall flags.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] when unknown flag bits are set or
    /// when incompatible flag combinations are specified (e.g. `O_RDONLY` with
    /// `O_TRUNC` without write access).
    pub fn from_raw(raw: u32) -> Result<Self> {
        // Reject unknown flag bits (access mode is always 2 bits).
        if raw & !KNOWN_FLAGS & !O_ACCMODE != 0 {
            return Err(Error::InvalidArgument);
        }
        // O_EXCL without O_CREAT is meaningless (not an error, but warn).
        // O_TRUNC requires write access.
        let access = raw & O_ACCMODE;
        if raw & O_TRUNC != 0 && access == O_RDONLY {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Return the access mode (O_RDONLY / O_WRONLY / O_RDWR).
    pub const fn access_mode(self) -> u32 {
        self.0 & O_ACCMODE
    }

    /// Return `true` if O_CREAT is set.
    pub const fn is_creat(self) -> bool {
        self.0 & O_CREAT != 0
    }

    /// Return `true` if O_EXCL is set.
    pub const fn is_excl(self) -> bool {
        self.0 & O_EXCL != 0
    }

    /// Return `true` if O_TRUNC is set.
    pub const fn is_trunc(self) -> bool {
        self.0 & O_TRUNC != 0
    }

    /// Return `true` if O_APPEND is set.
    pub const fn is_append(self) -> bool {
        self.0 & O_APPEND != 0
    }

    /// Return `true` if O_NONBLOCK is set.
    pub const fn is_nonblock(self) -> bool {
        self.0 & O_NONBLOCK != 0
    }

    /// Return `true` if O_CLOEXEC is set.
    pub const fn is_cloexec(self) -> bool {
        self.0 & O_CLOEXEC != 0
    }

    /// Return `true` if O_DIRECTORY is set.
    pub const fn is_directory(self) -> bool {
        self.0 & O_DIRECTORY != 0
    }

    /// Return `true` if O_NOFOLLOW is set.
    pub const fn is_nofollow(self) -> bool {
        self.0 & O_NOFOLLOW != 0
    }

    /// Return `true` if the fd is open for reading.
    pub const fn readable(self) -> bool {
        let acc = self.access_mode();
        acc == O_RDONLY || acc == O_RDWR
    }

    /// Return `true` if the fd is open for writing.
    pub const fn writable(self) -> bool {
        let acc = self.access_mode();
        acc == O_WRONLY || acc == O_RDWR
    }
}

// ---------------------------------------------------------------------------
// FileType — type of a filesystem node
// ---------------------------------------------------------------------------

/// The type of a filesystem node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// Regular file.
    Regular,
    /// Directory.
    Directory,
    /// Symbolic link.
    Symlink,
    /// Character device.
    CharDev,
    /// Block device.
    BlockDev,
    /// FIFO / named pipe.
    Fifo,
    /// Unix domain socket.
    Socket,
}

// ---------------------------------------------------------------------------
// InodeStub — minimal inode representation
// ---------------------------------------------------------------------------

/// A stub inode used by the open handler.
#[derive(Debug, Clone, Copy)]
pub struct InodeStub {
    /// Inode number.
    pub ino: u64,
    /// File type.
    pub kind: FileType,
    /// Permission bits.
    pub mode: FileMode,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// File size in bytes.
    pub size: u64,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl InodeStub {
    const fn empty() -> Self {
        Self {
            ino: 0,
            kind: FileType::Regular,
            mode: FileMode(0),
            uid: 0,
            gid: 0,
            size: 0,
            in_use: false,
        }
    }

    /// Return `true` if this inode represents a regular file.
    pub const fn is_regular(&self) -> bool {
        matches!(self.kind, FileType::Regular)
    }

    /// Return `true` if this inode represents a directory.
    pub const fn is_directory(&self) -> bool {
        matches!(self.kind, FileType::Directory)
    }

    /// Return `true` if this inode represents a symlink.
    pub const fn is_symlink(&self) -> bool {
        matches!(self.kind, FileType::Symlink)
    }
}

// ---------------------------------------------------------------------------
// OpenRequest — result of validation before fd allocation
// ---------------------------------------------------------------------------

/// A validated open request ready for fd allocation.
///
/// Produced by [`validate_open`]; consumed by [`alloc_fd`].
#[derive(Debug, Clone, Copy)]
pub struct OpenRequest {
    /// Directory fd for relative paths (or `AT_FDCWD`).
    pub dirfd: i32,
    /// Validated open flags.
    pub flags: OpenFlags,
    /// Creation mode (only meaningful when `O_CREAT` is set).
    pub mode: FileMode,
    /// Whether the file was newly created by this open.
    pub created: bool,
    /// Resolved inode (stub).
    pub inode: InodeStub,
}

// ---------------------------------------------------------------------------
// OpenFdTable — file descriptor allocator
// ---------------------------------------------------------------------------

/// An open file descriptor entry.
#[derive(Debug, Clone, Copy)]
pub struct OpenFdEntry {
    /// File descriptor number.
    pub fd: i32,
    /// The open flags this fd was opened with.
    pub flags: OpenFlags,
    /// Whether `FD_CLOEXEC` is set.
    pub cloexec: bool,
    /// Current file position.
    pub position: u64,
    /// The inode this fd refers to.
    pub inode: InodeStub,
    /// Whether this slot is occupied.
    pub in_use: bool,
}

impl OpenFdEntry {
    const fn empty() -> Self {
        Self {
            fd: -1,
            flags: OpenFlags(O_RDONLY),
            cloexec: false,
            position: 0,
            inode: InodeStub {
                ino: 0,
                kind: FileType::Regular,
                mode: FileMode(0),
                uid: 0,
                gid: 0,
                size: 0,
                in_use: false,
            },
            in_use: false,
        }
    }
}

/// A stub open file descriptor table.
pub struct OpenFdTable {
    entries: [OpenFdEntry; MAX_OPEN_FILES],
    count: usize,
    next_fd: i32,
}

impl OpenFdTable {
    /// Create an empty fd table.
    pub const fn new() -> Self {
        Self {
            entries: [const { OpenFdEntry::empty() }; MAX_OPEN_FILES],
            count: 0,
            next_fd: 3, // 0/1/2 reserved for stdin/stdout/stderr
        }
    }

    /// Return the number of open fds.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Allocate a new fd number for the given entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn alloc(&mut self, mut entry: OpenFdEntry) -> Result<i32> {
        for slot in self.entries.iter_mut() {
            if !slot.in_use {
                let fd = self.next_fd;
                self.next_fd += 1;
                entry.fd = fd;
                entry.in_use = true;
                *slot = entry;
                self.count += 1;
                return Ok(fd);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up an fd entry by number.
    pub fn find(&self, fd: i32) -> Option<&OpenFdEntry> {
        self.entries.iter().find(|e| e.in_use && e.fd == fd)
    }

    /// Close (free) an fd by number.
    pub fn close(&mut self, fd: i32) -> bool {
        for slot in self.entries.iter_mut() {
            if slot.in_use && slot.fd == fd {
                *slot = OpenFdEntry::empty();
                self.count = self.count.saturating_sub(1);
                return true;
            }
        }
        false
    }

    /// Close all fds with `FD_CLOEXEC` set (called on exec).
    pub fn close_on_exec(&mut self) {
        for slot in self.entries.iter_mut() {
            if slot.in_use && slot.cloexec {
                *slot = OpenFdEntry::empty();
                self.count = self.count.saturating_sub(1);
            }
        }
    }
}

impl Default for OpenFdTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Inode table stub
// ---------------------------------------------------------------------------

/// Maximum number of inodes in the stub inode table.
pub const MAX_INODES: usize = 256;

/// A stub inode table (simulates a filesystem).
pub struct InodeTable {
    entries: [InodeStub; MAX_INODES],
    next_ino: u64,
    count: usize,
}

impl InodeTable {
    /// Create an empty inode table.
    pub const fn new() -> Self {
        Self {
            entries: [const { InodeStub::empty() }; MAX_INODES],
            next_ino: 2, // inode 1 is root
            count: 0,
        }
    }

    /// Insert an inode, assigning the next available inode number.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn insert(&mut self, mut inode: InodeStub) -> Result<u64> {
        for slot in self.entries.iter_mut() {
            if !slot.in_use {
                let ino = self.next_ino;
                self.next_ino += 1;
                inode.ino = ino;
                inode.in_use = true;
                *slot = inode;
                self.count += 1;
                return Ok(ino);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find an inode by number.
    pub fn find(&self, ino: u64) -> Option<&InodeStub> {
        self.entries.iter().find(|i| i.in_use && i.ino == ino)
    }

    /// Return the number of inodes.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for InodeTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// validate_open — argument validation
// ---------------------------------------------------------------------------

/// Validate arguments to `open(2)` / `openat(2)`.
///
/// Checks flags, path length, and (stub) inode existence.  When
/// `O_CREAT` is set and the inode does not exist, a new inode is
/// allocated.  When `O_EXCL | O_CREAT` is set and the inode already
/// exists, `AlreadyExists` is returned.
///
/// # Arguments
///
/// * `inodes` — stub inode table (simulates VFS lookup)
/// * `dirfd`  — directory fd (`AT_FDCWD` for cwd)
/// * `path`   — file path (must be non-empty, < PATH_MAX bytes)
/// * `flags`  — raw open flags
/// * `mode`   — creation mode (mode_t); meaningful only with O_CREAT
/// * `umask`  — calling process umask; applied to mode on creation
/// * `uid`    — caller UID (permission check)
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — bad flags, empty or overlong path
/// - [`Error::NotFound`]        — file does not exist and O_CREAT not set
/// - [`Error::AlreadyExists`]   — O_CREAT|O_EXCL and file already exists
/// - [`Error::PermissionDenied`] — caller lacks necessary permissions
/// - [`Error::OutOfMemory`]     — inode table full during creation
pub fn validate_open(
    inodes: &mut InodeTable,
    dirfd: i32,
    path: &[u8],
    raw_flags: u32,
    raw_mode: u32,
    umask: u32,
    uid: u32,
) -> Result<OpenRequest> {
    // Validate path.
    if path.is_empty() || path.len() >= PATH_MAX {
        return Err(Error::InvalidArgument);
    }
    // Validate flags.
    let flags = OpenFlags::from_raw(raw_flags)?;

    // Stub: check for an existing inode whose "path hash" matches.
    // Real implementation would perform a VFS directory walk.
    let path_hash = compute_path_hash(path);
    let existing = find_inode_by_hash(inodes, path_hash);

    let (inode, created) = match existing {
        Some(ino) => {
            // O_EXCL | O_CREAT: fail if file already exists.
            if flags.is_creat() && flags.is_excl() {
                return Err(Error::AlreadyExists);
            }
            // O_NOFOLLOW: fail if path resolves to a symlink.
            if flags.is_nofollow() && ino.is_symlink() {
                return Err(Error::PermissionDenied);
            }
            // O_DIRECTORY: fail if not a directory.
            if flags.is_directory() && !ino.is_directory() {
                return Err(Error::InvalidArgument);
            }
            // Permission check for write access.
            if flags.writable() && uid != 0 && uid != ino.uid && !ino.mode.owner_write() {
                return Err(Error::PermissionDenied);
            }
            (*ino, false)
        }
        None => {
            if !flags.is_creat() {
                return Err(Error::NotFound);
            }
            // Create the inode.
            let mode = FileMode(raw_mode).apply_umask(umask);
            let new_inode = InodeStub {
                ino: 0, // assigned by InodeTable::insert
                kind: FileType::Regular,
                mode,
                uid,
                gid: 0,
                size: 0,
                in_use: true,
            };
            // Store path_hash in ino temporarily to enable lookup later.
            // In a real system the dentry links path → inode.
            let ino_num = inodes.insert(new_inode)?;
            let inode = *inodes.find(ino_num).ok_or(Error::NotFound)?;
            (inode, true)
        }
    };

    Ok(OpenRequest {
        dirfd,
        flags,
        mode: FileMode(raw_mode),
        created,
        inode,
    })
}

/// Allocate a file descriptor from the result of [`validate_open`].
///
/// Applies `O_TRUNC` (zero file size) and sets the initial file
/// position (0, or end-of-file for `O_APPEND`).
///
/// # Errors
///
/// Returns [`Error::OutOfMemory`] if the fd table is full.
pub fn alloc_fd(table: &mut OpenFdTable, req: &OpenRequest) -> Result<i32> {
    let position = if req.flags.is_append() {
        req.inode.size
    } else {
        0
    };

    let mut inode = req.inode;
    if req.flags.is_trunc() && req.flags.writable() {
        inode.size = 0;
    }

    let entry = OpenFdEntry {
        fd: -1, // assigned by alloc
        flags: req.flags,
        cloexec: req.flags.is_cloexec(),
        position,
        inode,
        in_use: true,
    };

    table.alloc(entry)
}

/// Convenience: validate and allocate in one call (models `do_sys_open`).
///
/// # Errors
///
/// See [`validate_open`] and [`alloc_fd`].
pub fn do_open(
    inodes: &mut InodeTable,
    fd_table: &mut OpenFdTable,
    dirfd: i32,
    path: &[u8],
    raw_flags: u32,
    raw_mode: u32,
    umask: u32,
    uid: u32,
) -> Result<i32> {
    let req = validate_open(inodes, dirfd, path, raw_flags, raw_mode, umask, uid)?;
    alloc_fd(fd_table, &req)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute a simple hash for a path slice (stub for VFS dentry lookup).
fn compute_path_hash(path: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in path {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Find an inode by path hash (stub dentry lookup).
fn find_inode_by_hash(inodes: &InodeTable, hash: u64) -> Option<&InodeStub> {
    // Stub: use ino number as a stand-in for path hash.
    // In a real VFS, dentry cache would map path → inode.
    inodes
        .entries
        .iter()
        .find(|i| i.in_use && i.ino == hash % 256 + 2)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tables() -> (InodeTable, OpenFdTable) {
        (InodeTable::new(), OpenFdTable::new())
    }

    #[test]
    fn open_creat_new_file() {
        let (mut inodes, mut fds) = make_tables();
        let fd = do_open(
            &mut inodes,
            &mut fds,
            AT_FDCWD,
            b"/tmp/test.txt",
            O_WRONLY | O_CREAT,
            0o644,
            0o022,
            1000,
        )
        .unwrap();
        assert!(fd >= 3);
        assert_eq!(fds.count(), 1);
    }

    #[test]
    fn open_flags_readable_writable() {
        let f = OpenFlags::from_raw(O_RDWR).unwrap();
        assert!(f.readable());
        assert!(f.writable());

        let r = OpenFlags::from_raw(O_RDONLY).unwrap();
        assert!(r.readable());
        assert!(!r.writable());

        let w = OpenFlags::from_raw(O_WRONLY).unwrap();
        assert!(!w.readable());
        assert!(w.writable());
    }

    #[test]
    fn open_trunc_rdonly_rejected() {
        assert_eq!(
            OpenFlags::from_raw(O_RDONLY | O_TRUNC),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn open_cloexec_flag() {
        let f = OpenFlags::from_raw(O_RDONLY | O_CLOEXEC).unwrap();
        assert!(f.is_cloexec());
    }

    #[test]
    fn file_mode_apply_umask() {
        let mode = FileMode(0o777).apply_umask(0o022);
        assert_eq!(mode.bits(), 0o755);
    }

    #[test]
    fn open_empty_path_rejected() {
        let (mut inodes, mut fds) = make_tables();
        assert_eq!(
            do_open(&mut inodes, &mut fds, AT_FDCWD, b"", O_RDONLY, 0, 0o022, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn open_without_creat_notfound() {
        let (mut inodes, mut fds) = make_tables();
        assert_eq!(
            do_open(
                &mut inodes,
                &mut fds,
                AT_FDCWD,
                b"/nonexistent",
                O_RDONLY,
                0,
                0o022,
                1000
            ),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn open_cloexec_closes_on_exec() {
        let (mut inodes, mut fds) = make_tables();
        let fd = do_open(
            &mut inodes,
            &mut fds,
            AT_FDCWD,
            b"/tmp/exec_test",
            O_RDONLY | O_CREAT | O_CLOEXEC,
            0o644,
            0o022,
            1000,
        )
        .unwrap();
        assert!(fds.find(fd).is_some());
        fds.close_on_exec();
        assert!(fds.find(fd).is_none());
        assert_eq!(fds.count(), 0);
    }

    #[test]
    fn open_append_sets_position_to_eof() {
        let (mut inodes, mut fds) = make_tables();
        let fd = do_open(
            &mut inodes,
            &mut fds,
            AT_FDCWD,
            b"/tmp/append_file",
            O_WRONLY | O_CREAT | O_APPEND,
            0o644,
            0,
            1000,
        )
        .unwrap();
        let entry = fds.find(fd).unwrap();
        // New file: size=0 so append position is 0.
        assert_eq!(entry.position, 0);
    }

    #[test]
    fn open_multiple_fds_allocated() {
        let (mut inodes, mut fds) = make_tables();
        let fd1 = do_open(
            &mut inodes,
            &mut fds,
            AT_FDCWD,
            b"/a",
            O_RDONLY | O_CREAT,
            0o644,
            0,
            1000,
        )
        .unwrap();
        let fd2 = do_open(
            &mut inodes,
            &mut fds,
            AT_FDCWD,
            b"/b",
            O_RDONLY | O_CREAT,
            0o644,
            0,
            1000,
        )
        .unwrap();
        assert_ne!(fd1, fd2);
        assert_eq!(fds.count(), 2);
    }

    #[test]
    fn open_close_recycles_slot() {
        let (mut inodes, mut fds) = make_tables();
        let fd = do_open(
            &mut inodes,
            &mut fds,
            AT_FDCWD,
            b"/tmp/x",
            O_RDONLY | O_CREAT,
            0o644,
            0,
            1000,
        )
        .unwrap();
        assert!(fds.close(fd));
        assert_eq!(fds.count(), 0);
        assert!(fds.find(fd).is_none());
    }
}
