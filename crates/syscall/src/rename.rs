// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `renameat2(2)` syscall handler.
//!
//! Implements fd-relative file renaming with extended flags
//! (`RENAME_NOREPLACE`, `RENAME_EXCHANGE`, `RENAME_WHITEOUT`).
//!
//! Reference: Linux `renameat2(2)`, POSIX.1-2024 `renameat()`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// RenameFlags
// ---------------------------------------------------------------------------

/// Flags for the `renameat2` system call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenameFlags(u32);

impl RenameFlags {
    /// Do not overwrite the destination if it already exists.
    pub const RENAME_NOREPLACE: Self = Self(1);

    /// Atomically exchange the source and destination.
    pub const RENAME_EXCHANGE: Self = Self(2);

    /// Create a whiteout object at the source location (overlay fs).
    pub const RENAME_WHITEOUT: Self = Self(4);

    /// Mask of all valid rename flags.
    const ALL: u32 = 1 | 2 | 4;

    /// Create `RenameFlags` from a raw `u32` value.
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Return the raw `u32` value.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Test whether a specific flag is set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

// ---------------------------------------------------------------------------
// AT_FDCWD
// ---------------------------------------------------------------------------

/// Special `dirfd` value meaning "use the current working directory".
const AT_FDCWD: i32 = -100;

// ---------------------------------------------------------------------------
// RenameatArgs — repr(C) argument block
// ---------------------------------------------------------------------------

/// Arguments for the `renameat2` system call.
///
/// Packed as `repr(C)` so it can be copied directly from user space
/// via `copy_from_user`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RenameatArgs {
    /// Directory fd for the old (source) pathname.
    pub olddirfd: i32,
    /// User-space pointer to the old pathname string.
    pub oldpath_ptr: u64,
    /// Directory fd for the new (destination) pathname.
    pub newdirfd: i32,
    /// User-space pointer to the new pathname string.
    pub newpath_ptr: u64,
    /// Flags bitmask (see [`RenameFlags`]).
    pub flags: u32,
}

impl Default for RenameatArgs {
    fn default() -> Self {
        Self {
            olddirfd: AT_FDCWD,
            oldpath_ptr: 0,
            newdirfd: AT_FDCWD,
            newpath_ptr: 0,
            flags: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// ResolvedRename — resolved path pair
// ---------------------------------------------------------------------------

/// Maximum path length in bytes for a resolved rename component.
const RENAME_PATH_MAX: usize = 256;

/// A pair of resolved pathnames for a rename operation.
#[derive(Debug, Clone)]
pub struct ResolvedRename {
    /// Resolved old (source) path bytes.
    pub old_path: [u8; RENAME_PATH_MAX],
    /// Valid length of `old_path`.
    pub old_len: usize,
    /// Resolved new (destination) path bytes.
    pub new_path: [u8; RENAME_PATH_MAX],
    /// Valid length of `new_path`.
    pub new_len: usize,
}

impl Default for ResolvedRename {
    fn default() -> Self {
        Self {
            old_path: [0u8; RENAME_PATH_MAX],
            old_len: 0,
            new_path: [0u8; RENAME_PATH_MAX],
            new_len: 0,
        }
    }
}

impl ResolvedRename {
    /// Return the old path as a byte slice.
    pub fn old_as_bytes(&self) -> &[u8] {
        &self.old_path[..self.old_len]
    }

    /// Return the new path as a byte slice.
    pub fn new_as_bytes(&self) -> &[u8] {
        &self.new_path[..self.new_len]
    }
}

// ---------------------------------------------------------------------------
// Flag validation
// ---------------------------------------------------------------------------

/// Validate `renameat2` flags.
///
/// `RENAME_NOREPLACE` and `RENAME_EXCHANGE` are mutually exclusive
/// because NOREPLACE forbids overwriting while EXCHANGE requires both
/// paths to exist and be swapped atomically.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown flag bits are set, or
///   both `RENAME_NOREPLACE` and `RENAME_EXCHANGE` are specified.
pub fn validate_rename_flags(flags: u32) -> Result<()> {
    // Reject unknown flags.
    if flags & !RenameFlags::ALL != 0 {
        return Err(Error::InvalidArgument);
    }

    let f = RenameFlags::from_raw(flags);

    // NOREPLACE and EXCHANGE are mutually exclusive.
    if f.contains(RenameFlags::RENAME_NOREPLACE) && f.contains(RenameFlags::RENAME_EXCHANGE) {
        return Err(Error::InvalidArgument);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// do_renameat2 — main syscall handler
// ---------------------------------------------------------------------------

/// `renameat2` — rename a file relative to directory file descriptors.
///
/// Validates flags and path pointers, resolves both pathnames, and
/// dispatches the rename operation to the VFS layer.
///
/// # Flags
///
/// - [`RenameFlags::RENAME_NOREPLACE`] — fail if the destination exists.
/// - [`RenameFlags::RENAME_EXCHANGE`] — atomically swap source and
///   destination.
/// - [`RenameFlags::RENAME_WHITEOUT`] — leave a whiteout at the source
///   (used by overlay file systems).
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — invalid flags (see
///   [`validate_rename_flags`]), or null path pointers.
/// - [`Error::NotFound`] — the source path does not exist.
/// - [`Error::AlreadyExists`] — `RENAME_NOREPLACE` is set and the
///   destination already exists.
pub fn do_renameat2(args: &RenameatArgs) -> Result<()> {
    validate_rename_flags(args.flags)?;

    // Both path pointers must be non-null.
    if args.oldpath_ptr == 0 || args.newpath_ptr == 0 {
        return Err(Error::InvalidArgument);
    }

    // Stub: in a real kernel we would copy_from_user to retrieve path
    // bytes.  Use placeholders for now.
    let old_name = b"/stub/old";
    let new_name = b"/stub/new";

    // Build resolved paths.
    let mut resolved = ResolvedRename::default();

    if old_name.len() > RENAME_PATH_MAX || new_name.len() > RENAME_PATH_MAX {
        return Err(Error::InvalidArgument);
    }

    resolved.old_path[..old_name.len()].copy_from_slice(old_name);
    resolved.old_len = old_name.len();

    resolved.new_path[..new_name.len()].copy_from_slice(new_name);
    resolved.new_len = new_name.len();

    let flags = RenameFlags::from_raw(args.flags);

    // Dispatch based on flags.
    if flags.contains(RenameFlags::RENAME_EXCHANGE) {
        // Stub: atomically exchange old_path and new_path entries.
        let _old = resolved.old_as_bytes();
        let _new = resolved.new_as_bytes();
        return Err(Error::NotImplemented);
    }

    if flags.contains(RenameFlags::RENAME_NOREPLACE) {
        // Stub: check that new_path does not exist, then rename.
        let _old = resolved.old_as_bytes();
        let _new = resolved.new_as_bytes();
        return Err(Error::NotImplemented);
    }

    // Default rename (possibly with RENAME_WHITEOUT).
    // Stub: vfs_rename(old_path, new_path, flags)
    let _old = resolved.old_as_bytes();
    let _new = resolved.new_as_bytes();
    Err(Error::NotImplemented)
}
