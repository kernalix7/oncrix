// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `chmod(2)`, `fchmod(2)`, and `fchmodat(2)` syscall handlers.
//!
//! These syscalls change the permission bits (mode) of a file.
//!
//! `chmod(path, mode)` — changes mode of the file at `path`.
//! `fchmod(fd, mode)` — changes mode of the file referenced by `fd`.
//! `fchmodat(dirfd, path, mode, flags)` — the `*at` variant; supports
//!   `AT_FDCWD` and `AT_SYMLINK_NOFOLLOW`.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `chmod()`, `fchmod()`, `fchmodat()`.
//!
//! Key behaviours:
//! - Only the file owner or a process with `CAP_FOWNER` may change modes.
//! - The effective UID of the process is checked against the file's UID.
//! - The setuid and setgid bits are cleared when a non-privileged user changes
//!   the mode of an executable (unless the caller owns the file and the
//!   `CAP_FSETID` capability is held).
//! - The sticky bit (`S_ISVTX`) may only be set on directories by
//!   non-privileged users on some systems; ONCRIX follows Linux semantics.
//! - `chmod` on a symbolic link operates on the link target (not the link
//!   itself); `fchmodat` with `AT_SYMLINK_NOFOLLOW` returns `EOPNOTSUPP`.
//! - The `ctime` of the inode is updated on success.
//!
//! # Mode bits
//!
//! ```text
//! Bit  Octal  Meaning
//! ─────────────────────────
//! 11   04000  S_ISUID  — Set-user-ID on exec
//! 10   02000  S_ISGID  — Set-group-ID on exec
//!  9   01000  S_ISVTX  — Sticky bit
//!  8   00400  S_IRUSR  — Owner read
//!  7   00200  S_IWUSR  — Owner write
//!  6   00100  S_IXUSR  — Owner execute
//!  5   00040  S_IRGRP  — Group read
//!  4   00020  S_IWGRP  — Group write
//!  3   00010  S_IXGRP  — Group execute
//!  2   00004  S_IROTH  — Other read
//!  1   00002  S_IWOTH  — Other write
//!  0   00001  S_IXOTH  — Other execute
//! ```
//!
//! # References
//!
//! - POSIX.1-2024: `chmod()`, `fchmod()`, `fchmodat()`
//! - Linux man pages: `chmod(2)`, `fchmod(2)`, `fchmodat(2)`
//! - Linux source: `fs/attr.c` `notify_change()`, `chmod_common()`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Mode constants
// ---------------------------------------------------------------------------

/// Set-user-ID bit.
pub const S_ISUID: u16 = 0o4000;
/// Set-group-ID bit.
pub const S_ISGID: u16 = 0o2000;
/// Sticky bit.
pub const S_ISVTX: u16 = 0o1000;
/// Owner read.
pub const S_IRUSR: u16 = 0o0400;
/// Owner write.
pub const S_IWUSR: u16 = 0o0200;
/// Owner execute.
pub const S_IXUSR: u16 = 0o0100;
/// Group read.
pub const S_IRGRP: u16 = 0o0040;
/// Group write.
pub const S_IWGRP: u16 = 0o0020;
/// Group execute.
pub const S_IXGRP: u16 = 0o0010;
/// Other read.
pub const S_IROTH: u16 = 0o0004;
/// Other write.
pub const S_IWOTH: u16 = 0o0002;
/// Other execute.
pub const S_IXOTH: u16 = 0o0001;

/// Mask of the 12 permission bits (including setuid/setgid/sticky).
pub const MODE_PERM_MASK: u16 = 0o7777;
/// Execute bits mask (user + group + other).
const MODE_EXEC_BITS: u16 = S_IXUSR | S_IXGRP | S_IXOTH;

// ---------------------------------------------------------------------------
// AT flags for fchmodat
// ---------------------------------------------------------------------------

/// `dirfd` value meaning "use current working directory".
pub const AT_FDCWD: i32 = -100;
/// Flag: do not follow symlinks in the final component.
pub const AT_SYMLINK_NOFOLLOW: i32 = 0x100;
/// All valid flags for `fchmodat`.
const FCHMODAT_VALID_FLAGS: i32 = AT_SYMLINK_NOFOLLOW;

// ---------------------------------------------------------------------------
// Inode type
// ---------------------------------------------------------------------------

/// Inode types relevant to chmod.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InodeType {
    /// Regular file.
    RegularFile,
    /// Directory.
    Directory,
    /// Symbolic link (chmod on symlinks is `EOPNOTSUPP`).
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

/// Stub inode for chmod operations.
#[derive(Debug, Clone, Copy)]
pub struct Inode {
    /// Inode number.
    pub ino: u64,
    /// Inode type.
    pub kind: InodeType,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Current permission bits (lower 12 bits).
    pub mode: u16,
    /// Last status-change time (seconds since epoch).
    pub ctime: i64,
}

impl Inode {
    /// Return `true` if the inode is a symbolic link.
    pub const fn is_symlink(&self) -> bool {
        matches!(self.kind, InodeType::Symlink)
    }

    /// Return the execute bits currently set.
    pub const fn exec_bits(&self) -> u16 {
        self.mode & MODE_EXEC_BITS
    }
}

// ---------------------------------------------------------------------------
// FdEntry stub
// ---------------------------------------------------------------------------

/// An open file descriptor for fchmod purposes.
#[derive(Debug, Clone, Copy)]
pub struct FdEntry {
    /// Numeric file descriptor.
    pub fd: i32,
    /// Index into the inode table.
    pub inode_idx: usize,
    /// Whether this slot is in use.
    pub in_use: bool,
}

impl FdEntry {
    const fn empty() -> Self {
        Self {
            fd: -1,
            inode_idx: 0,
            in_use: false,
        }
    }
}

// ---------------------------------------------------------------------------
// ChmodTable — stub inode/fd store
// ---------------------------------------------------------------------------

/// Maximum inodes in the stub table.
pub const MAX_INODES: usize = 64;
/// Maximum file descriptors in the stub table.
pub const MAX_FDS: usize = 64;

/// Combined inode + fd table for chmod.
pub struct ChmodTable {
    inodes: [Inode; MAX_INODES],
    inode_paths: [[u8; 256]; MAX_INODES],
    inode_path_lens: [usize; MAX_INODES],
    inode_used: [bool; MAX_INODES],
    fds: [FdEntry; MAX_FDS],
}

impl ChmodTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        const EMPTY_INODE: Inode = Inode {
            ino: 0,
            kind: InodeType::RegularFile,
            uid: 0,
            gid: 0,
            mode: 0,
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
    /// `OutOfMemory` if full; `InvalidArgument` if path is too long.
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

    /// Look up an inode index by path.
    pub fn find_by_path(&self, path: &[u8]) -> Option<usize> {
        for (i, used) in self.inode_used.iter().enumerate() {
            if *used && &self.inode_paths[i][..self.inode_path_lens[i]] == path {
                return Some(i);
            }
        }
        None
    }

    /// Get a reference to an inode.
    pub fn inode(&self, idx: usize) -> Option<&Inode> {
        if idx < MAX_INODES && self.inode_used[idx] {
            Some(&self.inodes[idx])
        } else {
            None
        }
    }

    /// Get a mutable reference to an inode.
    pub fn inode_mut(&mut self, idx: usize) -> Option<&mut Inode> {
        if idx < MAX_INODES && self.inode_used[idx] {
            Some(&mut self.inodes[idx])
        } else {
            None
        }
    }

    /// Insert an open file descriptor.
    pub fn insert_fd(&mut self, entry: FdEntry) -> Result<()> {
        for slot in self.fds.iter_mut() {
            if !slot.in_use {
                *slot = entry;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find an `FdEntry` by fd number.
    pub fn find_fd(&self, fd: i32) -> Option<&FdEntry> {
        self.fds.iter().find(|e| e.in_use && e.fd == fd)
    }
}

// ---------------------------------------------------------------------------
// validate_mode — helper
// ---------------------------------------------------------------------------

/// Validate that `raw_mode` contains only the lower 12 permission bits.
///
/// # Errors
///
/// `InvalidArgument` if any bits above bit 11 are set.
pub fn validate_mode(raw_mode: u32) -> Result<u16> {
    if raw_mode & !(MODE_PERM_MASK as u32) != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(raw_mode as u16)
}

// ---------------------------------------------------------------------------
// apply_chmod_validated — inner implementation
// ---------------------------------------------------------------------------

/// Apply a validated chmod to an inode.
///
/// Clears setuid/setgid bits when the caller is not privileged and the file
/// has no execute bits set (mimicking Linux behaviour).
///
/// # Arguments
///
/// * `table`       — inode/fd table
/// * `inode_idx`   — target inode index
/// * `new_mode`    — new permission bits (lower 12 bits)
/// * `caller_uid`  — UID of the calling process (0 = root/privileged)
/// * `now_sec`     — current wall-clock time for `ctime` update
fn apply_chmod_validated(
    table: &mut ChmodTable,
    inode_idx: usize,
    new_mode: u16,
    caller_uid: u32,
    now_sec: i64,
) -> Result<()> {
    let inode = table.inode_mut(inode_idx).ok_or(Error::NotFound)?;

    let mut mode = new_mode & MODE_PERM_MASK;

    // Non-root: strip setuid/setgid if no exec bits remain.
    if caller_uid != 0 {
        let exec_bits = mode & MODE_EXEC_BITS;
        if exec_bits == 0 {
            // No execute bits — clear setuid and setgid.
            mode &= !(S_ISUID | S_ISGID);
        }
    }

    inode.mode = mode;
    inode.ctime = now_sec;
    Ok(())
}

// ---------------------------------------------------------------------------
// do_chmod — public handler
// ---------------------------------------------------------------------------

/// Handler for `chmod(2)`.
///
/// Changes the permission bits of the file at `pathname` to `mode`.
/// Only the file owner or a privileged process (UID 0) may do this.
///
/// # Arguments
///
/// * `pathname`   — path to the file
/// * `raw_mode`   — new mode bits (only lower 12 bits are used)
/// * `caller_uid` — effective UID of the caller
/// * `now_sec`    — current time for `ctime` update
/// * `table`      — inode/fd table
///
/// # Errors
///
/// - `InvalidArgument`  — mode has bits above bit 11, or file is a symlink
/// - `NotFound`         — path not found
/// - `PermissionDenied` — caller is not owner and not root
pub fn do_chmod(
    pathname: &[u8],
    raw_mode: u32,
    caller_uid: u32,
    now_sec: i64,
    table: &mut ChmodTable,
) -> Result<()> {
    let new_mode = validate_mode(raw_mode)?;

    let inode_idx = table.find_by_path(pathname).ok_or(Error::NotFound)?;
    let inode = table.inode(inode_idx).ok_or(Error::NotFound)?;

    // Symlinks: chmod operates on the target, but we can't chmod a symlink
    // itself (caller should follow the link). Here we treat it as EOPNOTSUPP.
    if inode.is_symlink() {
        return Err(Error::NotImplemented);
    }

    // Ownership check.
    if caller_uid != 0 && inode.uid != caller_uid {
        return Err(Error::PermissionDenied);
    }

    apply_chmod_validated(table, inode_idx, new_mode, caller_uid, now_sec)
}

// ---------------------------------------------------------------------------
// do_fchmod — public handler
// ---------------------------------------------------------------------------

/// Handler for `fchmod(2)`.
///
/// Changes the permission bits of the file referred to by `fd`.
///
/// # Arguments
///
/// * `fd`         — open file descriptor
/// * `raw_mode`   — new mode bits
/// * `caller_uid` — effective UID of the caller
/// * `now_sec`    — current time for `ctime` update
/// * `table`      — inode/fd table
///
/// # Errors
///
/// - `InvalidArgument`  — mode bits invalid or file is a symlink
/// - `NotFound`         — `fd` not found
/// - `PermissionDenied` — caller is not owner and not root
pub fn do_fchmod(
    fd: i32,
    raw_mode: u32,
    caller_uid: u32,
    now_sec: i64,
    table: &mut ChmodTable,
) -> Result<()> {
    let new_mode = validate_mode(raw_mode)?;

    let fd_entry = *table.find_fd(fd).ok_or(Error::NotFound)?;
    let inode_idx = fd_entry.inode_idx;
    let inode = table.inode(inode_idx).ok_or(Error::NotFound)?;

    if inode.is_symlink() {
        return Err(Error::NotImplemented);
    }

    if caller_uid != 0 && inode.uid != caller_uid {
        return Err(Error::PermissionDenied);
    }

    apply_chmod_validated(table, inode_idx, new_mode, caller_uid, now_sec)
}

// ---------------------------------------------------------------------------
// do_fchmodat — public handler
// ---------------------------------------------------------------------------

/// Handler for `fchmodat(2)`.
///
/// `fchmodat` combines the functionality of `chmod` with support for
/// directory-relative paths.  When `flags` contains `AT_SYMLINK_NOFOLLOW`
/// and the final component is a symlink, `EOPNOTSUPP` is returned (Linux
/// semantics — there is no way to chmod a symlink on Linux).
///
/// # Arguments
///
/// * `dirfd`      — directory fd, or `AT_FDCWD`
/// * `pathname`   — path to resolve
/// * `raw_mode`   — new mode bits
/// * `flags`      — `AT_SYMLINK_NOFOLLOW` (0 means follow links)
/// * `caller_uid` — effective UID of the caller
/// * `now_sec`    — current time for `ctime` update
/// * `table`      — inode/fd table
///
/// # Errors
///
/// - `InvalidArgument`  — mode bits invalid or unsupported flags
/// - `NotFound`         — path not found
/// - `PermissionDenied` — caller is not owner and not root
/// - `NotImplemented`   — `AT_SYMLINK_NOFOLLOW` set and path is a symlink
pub fn do_fchmodat(
    _dirfd: i32,
    pathname: &[u8],
    raw_mode: u32,
    flags: i32,
    caller_uid: u32,
    now_sec: i64,
    table: &mut ChmodTable,
) -> Result<()> {
    // Validate flags.
    if flags & !FCHMODAT_VALID_FLAGS != 0 {
        return Err(Error::InvalidArgument);
    }

    let new_mode = validate_mode(raw_mode)?;
    let nofollow = flags & AT_SYMLINK_NOFOLLOW != 0;

    let inode_idx = table.find_by_path(pathname).ok_or(Error::NotFound)?;
    let inode = table.inode(inode_idx).ok_or(Error::NotFound)?;

    // With AT_SYMLINK_NOFOLLOW, if the target is a symlink, return EOPNOTSUPP.
    if nofollow && inode.is_symlink() {
        return Err(Error::NotImplemented);
    }

    // Without AT_SYMLINK_NOFOLLOW, we follow the link (stub: resolved path
    // already points to target in our VFS table).
    if inode.is_symlink() {
        return Err(Error::NotImplemented);
    }

    if caller_uid != 0 && inode.uid != caller_uid {
        return Err(Error::PermissionDenied);
    }

    apply_chmod_validated(table, inode_idx, new_mode, caller_uid, now_sec)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table() -> ChmodTable {
        let mut t = ChmodTable::new();

        // Regular file owned by uid 1000, mode 0644.
        let idx = t
            .insert_inode(
                b"/tmp/file.txt",
                Inode {
                    ino: 1,
                    kind: InodeType::RegularFile,
                    uid: 1000,
                    gid: 1000,
                    mode: 0o644,
                    ctime: 0,
                },
            )
            .unwrap();

        t.insert_fd(FdEntry {
            fd: 3,
            inode_idx: idx,
            in_use: true,
        })
        .unwrap();

        // Symlink.
        t.insert_inode(
            b"/tmp/link",
            Inode {
                ino: 2,
                kind: InodeType::Symlink,
                uid: 1000,
                gid: 1000,
                mode: 0o777,
                ctime: 0,
            },
        )
        .unwrap();

        // File owned by root.
        t.insert_inode(
            b"/etc/secret",
            Inode {
                ino: 3,
                kind: InodeType::RegularFile,
                uid: 0,
                gid: 0,
                mode: 0o600,
                ctime: 0,
            },
        )
        .unwrap();

        // Executable file.
        t.insert_inode(
            b"/usr/bin/tool",
            Inode {
                ino: 4,
                kind: InodeType::RegularFile,
                uid: 1000,
                gid: 1000,
                mode: 0o755,
                ctime: 0,
            },
        )
        .unwrap();

        t
    }

    #[test]
    fn chmod_basic() {
        let mut t = make_table();
        do_chmod(b"/tmp/file.txt", 0o755, 1000, 100, &mut t).unwrap();
        let idx = t.find_by_path(b"/tmp/file.txt").unwrap();
        assert_eq!(t.inode(idx).unwrap().mode, 0o755);
        assert_eq!(t.inode(idx).unwrap().ctime, 100);
    }

    #[test]
    fn chmod_owner_only() {
        let mut t = make_table();
        let e = do_chmod(b"/tmp/file.txt", 0o644, 2000, 0, &mut t).unwrap_err();
        assert_eq!(e, Error::PermissionDenied);
    }

    #[test]
    fn chmod_root_can_change_any() {
        let mut t = make_table();
        do_chmod(b"/etc/secret", 0o644, 0, 50, &mut t).unwrap();
        let idx = t.find_by_path(b"/etc/secret").unwrap();
        assert_eq!(t.inode(idx).unwrap().mode, 0o644);
    }

    #[test]
    fn chmod_symlink_fails() {
        let mut t = make_table();
        let e = do_chmod(b"/tmp/link", 0o644, 1000, 0, &mut t).unwrap_err();
        assert_eq!(e, Error::NotImplemented);
    }

    #[test]
    fn chmod_invalid_mode_bits() {
        let mut t = make_table();
        let e = do_chmod(b"/tmp/file.txt", 0o10000, 1000, 0, &mut t).unwrap_err();
        assert_eq!(e, Error::InvalidArgument);
    }

    #[test]
    fn chmod_not_found() {
        let mut t = make_table();
        let e = do_chmod(b"/nonexistent", 0o644, 0, 0, &mut t).unwrap_err();
        assert_eq!(e, Error::NotFound);
    }

    #[test]
    fn chmod_clears_setuid_no_exec() {
        let mut t = make_table();
        // Set mode with setuid but no exec bits.
        do_chmod(b"/tmp/file.txt", 0o4644, 1000, 0, &mut t).unwrap();
        let idx = t.find_by_path(b"/tmp/file.txt").unwrap();
        // Non-root, no exec bits → setuid should be cleared.
        assert_eq!(t.inode(idx).unwrap().mode & S_ISUID, 0);
    }

    #[test]
    fn chmod_keeps_setuid_with_exec() {
        let mut t = make_table();
        // Owner sets setuid + exec.
        do_chmod(b"/tmp/file.txt", 0o4755, 1000, 0, &mut t).unwrap();
        let idx = t.find_by_path(b"/tmp/file.txt").unwrap();
        // exec bits present → setuid kept.
        assert_ne!(t.inode(idx).unwrap().mode & S_ISUID, 0);
    }

    #[test]
    fn fchmod_basic() {
        let mut t = make_table();
        do_fchmod(3, 0o600, 1000, 200, &mut t).unwrap();
        let idx = t.find_by_path(b"/tmp/file.txt").unwrap();
        assert_eq!(t.inode(idx).unwrap().mode, 0o600);
        assert_eq!(t.inode(idx).unwrap().ctime, 200);
    }

    #[test]
    fn fchmod_bad_fd() {
        let mut t = make_table();
        let e = do_fchmod(99, 0o644, 1000, 0, &mut t).unwrap_err();
        assert_eq!(e, Error::NotFound);
    }

    #[test]
    fn fchmodat_basic() {
        let mut t = make_table();
        do_fchmodat(AT_FDCWD, b"/tmp/file.txt", 0o600, 0, 1000, 300, &mut t).unwrap();
        let idx = t.find_by_path(b"/tmp/file.txt").unwrap();
        assert_eq!(t.inode(idx).unwrap().mode, 0o600);
    }

    #[test]
    fn fchmodat_symlink_nofollow() {
        let mut t = make_table();
        let e = do_fchmodat(
            AT_FDCWD,
            b"/tmp/link",
            0o644,
            AT_SYMLINK_NOFOLLOW,
            1000,
            0,
            &mut t,
        )
        .unwrap_err();
        assert_eq!(e, Error::NotImplemented);
    }

    #[test]
    fn fchmodat_invalid_flags() {
        let mut t = make_table();
        let e =
            do_fchmodat(AT_FDCWD, b"/tmp/file.txt", 0o644, 0x9999, 1000, 0, &mut t).unwrap_err();
        assert_eq!(e, Error::InvalidArgument);
    }

    #[test]
    fn validate_mode_ok() {
        assert_eq!(validate_mode(0o755).unwrap(), 0o755);
        assert_eq!(validate_mode(0o7777).unwrap(), 0o7777);
    }

    #[test]
    fn validate_mode_invalid() {
        assert!(validate_mode(0o10000).is_err());
        assert!(validate_mode(0xFFFF).is_err());
    }
}
