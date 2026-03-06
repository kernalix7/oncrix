// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `faccessat2(2)` — file access permission checking syscall.
//!
//! Implements POSIX `access()` and the Linux extension `faccessat2()`,
//! which checks whether the calling process can access the file at a
//! given path with the specified permissions.
//!
//! # Differences from `access(2)` / `faccessat(2)`
//!
//! `faccessat2` adds a `flags` argument that allows:
//! - `AT_EACCESS`           — use effective UID/GID instead of real.
//! - `AT_SYMLINK_NOFOLLOW`  — do not follow trailing symlinks.
//! - `AT_EMPTY_PATH`        — operate on the fd itself (empty path).
//!
//! # POSIX reference
//!
//! - `access()`:    POSIX.1-2024, `.TheOpenGroup/susv5-html/functions/access.html`
//! - `faccessat()`: POSIX.1-2024, `.TheOpenGroup/susv5-html/functions/faccessat.html`
//!
//! # Structures
//!
//! - [`AccessMode`] — permission bits (`R_OK`, `W_OK`, `X_OK`, `F_OK`).
//! - [`AccessFlags`] — flag constants for `faccessat2`.
//! - [`Credentials`] — real and effective UID/GID of the caller.
//! - [`PathEntry`] — stub filesystem entry for permission checks.
//! - [`PathTable`] — stub path lookup table.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Access mode constants (POSIX <unistd.h>)
// ---------------------------------------------------------------------------

/// Test for existence only.
pub const F_OK: u32 = 0;

/// Test for read permission.
pub const R_OK: u32 = 4;

/// Test for write permission.
pub const W_OK: u32 = 2;

/// Test for execute permission.
pub const X_OK: u32 = 1;

/// All valid access mode bits combined.
const MODE_VALID: u32 = R_OK | W_OK | X_OK;

// ---------------------------------------------------------------------------
// faccessat2 flags
// ---------------------------------------------------------------------------

/// Flags for [`do_faccessat2`].
pub struct AccessFlags;

impl AccessFlags {
    /// Use effective UID/GID rather than real UID/GID for the check.
    ///
    /// By default, POSIX `access()` uses the real UID/GID, which is
    /// what set-UID programs need to verify whether the *real* user
    /// has permission. `AT_EACCESS` switches to effective credentials,
    /// which is useful when the caller genuinely wants to know if the
    /// *process itself* can access the file.
    pub const AT_EACCESS: u32 = 0x200;

    /// Do not follow symbolic links.
    ///
    /// When set, the permission check applies to the symlink itself
    /// rather than the file it points to. Without this flag, trailing
    /// symlinks are resolved.
    pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;

    /// Interpret an empty path relative to `dirfd`.
    ///
    /// When set and `path` is empty, the check operates on the file
    /// referred to by `dirfd` directly. This is analogous to
    /// `fstat(dirfd)` but for access checks.
    pub const AT_EMPTY_PATH: u32 = 0x1000;
}

/// All valid flag bits for `faccessat2`.
const FLAGS_VALID: u32 =
    AccessFlags::AT_EACCESS | AccessFlags::AT_SYMLINK_NOFOLLOW | AccessFlags::AT_EMPTY_PATH;

// ---------------------------------------------------------------------------
// Special dirfd value
// ---------------------------------------------------------------------------

/// Use the current working directory as the base for relative paths.
///
/// Matches the POSIX/Linux `AT_FDCWD` value (-100 as an unsigned i32).
pub const AT_FDCWD: i32 = -100;

/// Maximum valid file descriptor number.
const FD_MAX: i32 = 1_048_576;

/// Maximum path length in bytes.
const PATH_MAX: usize = 4096;

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/// Real and effective UID/GID of the calling process.
///
/// Used by the access-checking logic to determine which credential
/// set to use (real vs effective) depending on the flags.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Credentials {
    /// Real user ID.
    pub ruid: u32,
    /// Real group ID.
    pub rgid: u32,
    /// Effective user ID.
    pub euid: u32,
    /// Effective group ID.
    pub egid: u32,
    /// Supplementary group IDs (up to 32).
    pub groups: [u32; 32],
    /// Number of valid entries in `groups`.
    pub ngroups: usize,
}

impl Credentials {
    /// Create root credentials (all UIDs/GIDs are 0).
    pub const fn root() -> Self {
        Self {
            ruid: 0,
            rgid: 0,
            euid: 0,
            egid: 0,
            groups: [0u32; 32],
            ngroups: 0,
        }
    }

    /// Return the UID to use for access checking.
    ///
    /// If `use_effective` is `true` (i.e., `AT_EACCESS` is set),
    /// returns the effective UID; otherwise returns the real UID.
    pub const fn check_uid(&self, use_effective: bool) -> u32 {
        if use_effective { self.euid } else { self.ruid }
    }

    /// Return the GID to use for access checking.
    pub const fn check_gid(&self, use_effective: bool) -> u32 {
        if use_effective { self.egid } else { self.rgid }
    }

    /// Return `true` if the given GID matches the primary or any
    /// supplementary group.
    pub fn in_group(&self, gid: u32, use_effective: bool) -> bool {
        let primary = self.check_gid(use_effective);
        if primary == gid {
            return true;
        }
        let mut i = 0;
        while i < self.ngroups {
            if self.groups[i] == gid {
                return true;
            }
            i += 1;
        }
        false
    }
}

// ---------------------------------------------------------------------------
// File permission bits (POSIX <sys/stat.h>)
// ---------------------------------------------------------------------------

/// Owner read permission.
pub const S_IRUSR: u32 = 0o400;
/// Owner write permission.
pub const S_IWUSR: u32 = 0o200;
/// Owner execute permission.
pub const S_IXUSR: u32 = 0o100;

/// Group read permission.
pub const S_IRGRP: u32 = 0o040;
/// Group write permission.
pub const S_IWGRP: u32 = 0o020;
/// Group execute permission.
pub const S_IXGRP: u32 = 0o010;

/// Other read permission.
pub const S_IROTH: u32 = 0o004;
/// Other write permission.
pub const S_IWOTH: u32 = 0o002;
/// Other execute permission.
pub const S_IXOTH: u32 = 0o001;

/// Set-user-ID on execution.
pub const S_ISUID: u32 = 0o4000;
/// Set-group-ID on execution.
pub const S_ISGID: u32 = 0o2000;
/// Sticky bit.
pub const S_ISVTX: u32 = 0o1000;

/// Mask for all permission bits (rwxrwxrwx + setuid/setgid/sticky).
const PERM_MASK: u32 = 0o7777;

// ---------------------------------------------------------------------------
// File types (subset for stub)
// ---------------------------------------------------------------------------

/// File type: regular file.
pub const S_IFREG: u32 = 0o100000;
/// File type: directory.
pub const S_IFDIR: u32 = 0o040000;
/// File type: symbolic link.
pub const S_IFLNK: u32 = 0o120000;

/// File type mask.
const S_IFMT: u32 = 0o170000;

// ---------------------------------------------------------------------------
// PathEntry — stub filesystem entry
// ---------------------------------------------------------------------------

/// Maximum number of entries in the stub path table.
const MAX_PATH_ENTRIES: usize = 128;

/// Maximum path component length.
const NAME_MAX: usize = 255;

/// A stub filesystem entry for testing access permission logic.
///
/// In a real kernel, this would come from the VFS inode layer.
pub struct PathEntry {
    /// Full path (null-terminated bytes, up to [`NAME_MAX`]).
    path: [u8; NAME_MAX + 1],
    /// Length of the valid path bytes.
    path_len: usize,
    /// Owner UID.
    uid: u32,
    /// Owner GID.
    gid: u32,
    /// File mode (type + permission bits).
    mode: u32,
    /// Whether this is a symbolic link target (after resolution).
    is_symlink: bool,
    /// Target path for symlinks (empty if not a symlink).
    link_target: [u8; NAME_MAX + 1],
    /// Length of the link target.
    link_target_len: usize,
    /// Whether this slot is in use.
    in_use: bool,
}

impl PathEntry {
    /// Create an empty, inactive entry.
    const fn new() -> Self {
        Self {
            path: [0u8; NAME_MAX + 1],
            path_len: 0,
            uid: 0,
            gid: 0,
            mode: 0,
            is_symlink: false,
            link_target: [0u8; NAME_MAX + 1],
            link_target_len: 0,
            in_use: false,
        }
    }

    /// Return the file type portion of the mode.
    pub const fn file_type(&self) -> u32 {
        self.mode & S_IFMT
    }

    /// Return the permission bits portion of the mode.
    pub const fn permissions(&self) -> u32 {
        self.mode & PERM_MASK
    }

    /// Return `true` if this is a symbolic link.
    pub const fn is_symlink(&self) -> bool {
        self.is_symlink
    }

    /// Return the owner UID.
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// Return the owner GID.
    pub const fn gid(&self) -> u32 {
        self.gid
    }

    /// Return the file mode.
    pub const fn mode(&self) -> u32 {
        self.mode
    }
}

// ---------------------------------------------------------------------------
// PathTable — stub path lookup table
// ---------------------------------------------------------------------------

/// Stub filesystem path table for testing access checks.
///
/// In a real kernel, path lookup would traverse the VFS dcache
/// and inode layer. This table provides a flat lookup by path
/// for unit testing and stub implementation.
pub struct PathTable {
    /// Entry slots.
    entries: [PathEntry; MAX_PATH_ENTRIES],
    /// Number of active entries.
    count: usize,
}

impl PathTable {
    /// Create an empty path table.
    pub const fn new() -> Self {
        Self {
            entries: [const { PathEntry::new() }; MAX_PATH_ENTRIES],
            count: 0,
        }
    }

    /// Return the number of active entries.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if the table is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Register a regular file entry.
    ///
    /// # Errors
    ///
    /// - `OutOfMemory` — table full.
    /// - `InvalidArgument` — path too long or empty.
    pub fn add_file(&mut self, path: &[u8], uid: u32, gid: u32, mode: u32) -> Result<()> {
        self.add_entry(path, uid, gid, S_IFREG | (mode & PERM_MASK), false, &[])
    }

    /// Register a directory entry.
    pub fn add_dir(&mut self, path: &[u8], uid: u32, gid: u32, mode: u32) -> Result<()> {
        self.add_entry(path, uid, gid, S_IFDIR | (mode & PERM_MASK), false, &[])
    }

    /// Register a symbolic link entry.
    pub fn add_symlink(
        &mut self,
        path: &[u8],
        uid: u32,
        gid: u32,
        mode: u32,
        target: &[u8],
    ) -> Result<()> {
        self.add_entry(path, uid, gid, S_IFLNK | (mode & PERM_MASK), true, target)
    }

    /// Look up an entry by path, optionally following symlinks.
    ///
    /// When `follow_symlinks` is `true` and the entry is a symlink,
    /// the lookup follows one level of indirection.
    pub fn lookup(&self, path: &[u8], follow_symlinks: bool) -> Option<&PathEntry> {
        let entry = self.find_by_path(path)?;

        if follow_symlinks && entry.is_symlink && entry.link_target_len > 0 {
            // Follow one level of symlink.
            let target = &entry.link_target[..entry.link_target_len];
            return self.find_by_path(target);
        }

        Some(entry)
    }

    // --- internal ---

    /// Add a raw entry to the table.
    fn add_entry(
        &mut self,
        path: &[u8],
        uid: u32,
        gid: u32,
        mode: u32,
        is_symlink: bool,
        target: &[u8],
    ) -> Result<()> {
        if path.is_empty() || path.len() > NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        if is_symlink && target.len() > NAME_MAX {
            return Err(Error::InvalidArgument);
        }

        let slot_idx = self
            .entries
            .iter()
            .position(|e| !e.in_use)
            .ok_or(Error::OutOfMemory)?;

        let slot = &mut self.entries[slot_idx];
        slot.path[..path.len()].copy_from_slice(path);
        slot.path_len = path.len();
        slot.uid = uid;
        slot.gid = gid;
        slot.mode = mode;
        slot.is_symlink = is_symlink;
        if is_symlink {
            slot.link_target[..target.len()].copy_from_slice(target);
            slot.link_target_len = target.len();
        }
        slot.in_use = true;

        self.count += 1;
        Ok(())
    }

    /// Find an entry by exact path match.
    fn find_by_path(&self, path: &[u8]) -> Option<&PathEntry> {
        self.entries
            .iter()
            .find(|e| e.in_use && e.path_len == path.len() && e.path[..e.path_len] == *path)
    }
}

impl Default for PathTable {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Permission checking core
// ---------------------------------------------------------------------------

/// Check whether `creds` has access `mode` to the file described by
/// `entry`.
///
/// Follows the standard POSIX DAC (Discretionary Access Control)
/// algorithm:
///
/// 1. Root (UID 0) bypasses read and write checks. For execute,
///    root is allowed if at least one execute bit is set.
/// 2. If the caller is the file owner, use the owner permission
///    bits.
/// 3. If the caller is in the file's group, use the group
///    permission bits.
/// 4. Otherwise, use the other permission bits.
///
/// `use_effective` selects effective vs real credentials.
fn check_permission(
    entry: &PathEntry,
    mode: u32,
    creds: &Credentials,
    use_effective: bool,
) -> Result<()> {
    // F_OK: existence check only — the entry exists.
    if mode == F_OK {
        return Ok(());
    }

    let uid = creds.check_uid(use_effective);
    let perm = entry.permissions();

    // Root (UID 0) bypass.
    if uid == 0 {
        // Root can read and write anything.
        // For execute, at least one execute bit must be set.
        if mode & X_OK != 0 {
            if perm & (S_IXUSR | S_IXGRP | S_IXOTH) == 0 {
                return Err(Error::PermissionDenied);
            }
        }
        return Ok(());
    }

    // Owner check.
    if uid == entry.uid {
        let owner_bits = (perm >> 6) & 0o7;
        return check_bits(owner_bits, mode);
    }

    // Group check.
    if creds.in_group(entry.gid, use_effective) {
        let group_bits = (perm >> 3) & 0o7;
        return check_bits(group_bits, mode);
    }

    // Other check.
    let other_bits = perm & 0o7;
    check_bits(other_bits, mode)
}

/// Compare the requested `mode` bits against the granted `bits`.
///
/// `bits` is a 3-bit octal value (rwx). Returns `Ok(())` if all
/// requested permissions are granted.
fn check_bits(bits: u32, mode: u32) -> Result<()> {
    if mode & R_OK != 0 && bits & 0o4 == 0 {
        return Err(Error::PermissionDenied);
    }
    if mode & W_OK != 0 && bits & 0o2 == 0 {
        return Err(Error::PermissionDenied);
    }
    if mode & X_OK != 0 && bits & 0o1 == 0 {
        return Err(Error::PermissionDenied);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Path validation
// ---------------------------------------------------------------------------

/// Validate a user-space path buffer.
///
/// Returns `Ok(slice)` containing the path bytes (without trailing
/// NUL) if valid, or an error if the path is too long or contains
/// interior NUL bytes.
fn validate_path(path: &[u8]) -> Result<&[u8]> {
    if path.is_empty() {
        // Empty path is allowed only with AT_EMPTY_PATH.
        return Ok(path);
    }

    if path.len() > PATH_MAX {
        return Err(Error::InvalidArgument);
    }

    // Find the NUL terminator (if any) and trim.
    let effective_len = path.iter().position(|&b| b == 0).unwrap_or(path.len());

    // Check for interior NULs in the remaining portion.
    if effective_len < path.len() {
        let after_nul = &path[effective_len + 1..];
        if after_nul.iter().any(|&b| b != 0) {
            return Err(Error::InvalidArgument);
        }
    }

    Ok(&path[..effective_len])
}

/// Validate the `dirfd` argument.
///
/// Accepts `AT_FDCWD` or any non-negative fd up to `FD_MAX`.
fn validate_dirfd(dirfd: i32) -> Result<()> {
    if dirfd == AT_FDCWD {
        return Ok(());
    }
    if dirfd < 0 || dirfd > FD_MAX {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Syscall handler functions
// ---------------------------------------------------------------------------

/// `faccessat2` — check file accessibility with flags.
///
/// Checks whether the calling process can access the file at `path`
/// (relative to `dirfd`) with the permissions specified by `mode`.
///
/// # Arguments
///
/// - `table`  — Path lookup table (stub filesystem).
/// - `creds`  — Caller's real and effective credentials.
/// - `dirfd`  — Base directory fd, or `AT_FDCWD` for cwd.
/// - `path`   — Path to check (may be empty with `AT_EMPTY_PATH`).
/// - `mode`   — Permission bits to check (`F_OK`, `R_OK`, `W_OK`,
///              `X_OK`), OR'd together.
/// - `flags`  — `AT_EACCESS`, `AT_SYMLINK_NOFOLLOW`, `AT_EMPTY_PATH`.
///
/// # Errors
///
/// - `InvalidArgument` — unknown flags, invalid mode, or bad path.
/// - `NotFound` — path does not exist.
/// - `PermissionDenied` — access denied.
///
/// # POSIX conformance
///
/// - `access()` uses real UID/GID by default.
/// - `AT_EACCESS` switches to effective credentials.
/// - `F_OK` checks existence only.
/// - Symlinks are followed unless `AT_SYMLINK_NOFOLLOW` is set.
pub fn do_faccessat2(
    table: &PathTable,
    creds: &Credentials,
    dirfd: i32,
    path: &[u8],
    mode: u32,
    flags: u32,
) -> Result<()> {
    // Validate flags.
    if flags & !FLAGS_VALID != 0 {
        return Err(Error::InvalidArgument);
    }

    // Validate mode — must be F_OK or a combination of R_OK|W_OK|X_OK.
    if mode != F_OK && (mode & !MODE_VALID) != 0 {
        return Err(Error::InvalidArgument);
    }

    // Validate dirfd.
    validate_dirfd(dirfd)?;

    // Validate and trim path.
    let clean_path = validate_path(path)?;

    // Handle AT_EMPTY_PATH.
    if clean_path.is_empty() {
        if flags & AccessFlags::AT_EMPTY_PATH == 0 {
            return Err(Error::InvalidArgument);
        }
        // With AT_EMPTY_PATH and an empty path, the check is on
        // dirfd itself. In a real kernel, we would look up the
        // inode for dirfd. Stub: return Ok if dirfd is valid.
        if dirfd == AT_FDCWD {
            return Ok(());
        }
        // Stub: accept any valid fd.
        return Ok(());
    }

    // Determine whether to follow symlinks.
    let follow = flags & AccessFlags::AT_SYMLINK_NOFOLLOW == 0;

    // Determine credential mode.
    let use_effective = flags & AccessFlags::AT_EACCESS != 0;

    // Look up the path.
    let entry = table.lookup(clean_path, follow).ok_or(Error::NotFound)?;

    // When AT_SYMLINK_NOFOLLOW is set and the entry is a symlink,
    // we check the symlink itself — existence is already confirmed.
    // Symlinks have all permissions in practice (lrwxrwxrwx), but
    // we still run through the DAC check on the actual mode bits
    // stored in the entry.

    check_permission(entry, mode, creds, use_effective)
}

/// `access` — POSIX access check using real UID/GID.
///
/// Equivalent to `faccessat2(AT_FDCWD, path, mode, 0)`.
///
/// # Errors
///
/// Same as [`do_faccessat2`].
pub fn do_access(table: &PathTable, creds: &Credentials, path: &[u8], mode: u32) -> Result<()> {
    do_faccessat2(table, creds, AT_FDCWD, path, mode, 0)
}

/// `faccessat` — POSIX access check relative to a directory fd.
///
/// Equivalent to `faccessat2(dirfd, path, mode, flags)`, but the
/// POSIX `faccessat` only defines `AT_EACCESS` and
/// `AT_SYMLINK_NOFOLLOW`. We accept the same flag set for
/// compatibility.
///
/// # Errors
///
/// Same as [`do_faccessat2`].
pub fn do_faccessat(
    table: &PathTable,
    creds: &Credentials,
    dirfd: i32,
    path: &[u8],
    mode: u32,
    flags: u32,
) -> Result<()> {
    do_faccessat2(table, creds, dirfd, path, mode, flags)
}

/// `euidaccess` / `eaccess` — access check using effective UID/GID.
///
/// Equivalent to `faccessat2(AT_FDCWD, path, mode, AT_EACCESS)`.
///
/// # Errors
///
/// Same as [`do_faccessat2`].
pub fn do_euidaccess(table: &PathTable, creds: &Credentials, path: &[u8], mode: u32) -> Result<()> {
    do_faccessat2(table, creds, AT_FDCWD, path, mode, AccessFlags::AT_EACCESS)
}
