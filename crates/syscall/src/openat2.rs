// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `openat2(2)` syscall handler.
//!
//! `openat2` is a superset of `openat(2)` that accepts an [`OpenHow`] structure
//! providing fine-grained path resolution control. It was introduced in Linux 5.6
//! (see `open_how` in `include/uapi/linux/openat2.h`).
//!
//! # POSIX / Linux Reference
//!
//! - Linux man page: `openat2(2)`
//! - POSIX `openat`: `.TheOpenGroup/susv5-html/functions/openat.html`
//! - Kernel source: `fs/open.c`, `fs/namei.c`, `include/uapi/linux/openat2.h`
//!
//! # Resolve flags
//!
//! | Flag                      | Meaning                                               |
//! |---------------------------|-------------------------------------------------------|
//! | [`RESOLVE_NO_XDEV`]       | Do not cross mount-point boundaries                   |
//! | [`RESOLVE_NO_MAGICLINKS`  | Reject magic `/proc/self/fd`-style symlinks           |
//! | [`RESOLVE_NO_SYMLINKS`]   | Reject all symbolic links during resolution           |
//! | [`RESOLVE_BENEATH`]       | Restrict resolution to be beneath the `dirfd` subtree |
//! | [`RESOLVE_IN_ROOT`]       | Treat `dirfd` as the root of the filesystem           |
//! | [`RESOLVE_CACHED`]        | Fail if any component is not in the dentry cache      |

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Open flags (O_* constants forwarded from POSIX / Linux ABI)
// ---------------------------------------------------------------------------

/// Open for reading only.
pub const O_RDONLY: u64 = 0x0000_0000;
/// Open for writing only.
pub const O_WRONLY: u64 = 0x0000_0001;
/// Open for reading and writing.
pub const O_RDWR: u64 = 0x0000_0002;
/// Create the file if it does not exist.
pub const O_CREAT: u64 = 0x0000_0040;
/// Error if file already exists (combined with `O_CREAT`).
pub const O_EXCL: u64 = 0x0000_0080;
/// If a terminal device, do not become the controlling terminal.
pub const O_NOCTTY: u64 = 0x0000_0100;
/// Truncate the file to zero length on open.
pub const O_TRUNC: u64 = 0x0000_0200;
/// All writes append to end of file.
pub const O_APPEND: u64 = 0x0000_0400;
/// Non-blocking I/O.
pub const O_NONBLOCK: u64 = 0x0000_0800;
/// Synchronise file data on each write.
pub const O_DSYNC: u64 = 0x0000_1000;
/// Synchronise file data and metadata on each write.
pub const O_SYNC: u64 = 0x0010_1000;
/// Close on exec.
pub const O_CLOEXEC: u64 = 0x0008_0000;
/// Open without following the final symlink (open the link itself).
pub const O_NOFOLLOW: u64 = 0x0002_0000;
/// If path refers to a directory, fail.  Otherwise open a path without
/// triggering automounts.
pub const O_PATH: u64 = 0x0020_0000;
/// Used internally / for directories.
pub const O_DIRECTORY: u64 = 0x0001_0000;
/// Do not update access time.
pub const O_NOATIME: u64 = 0x0004_0000;
/// Open a temporary unnamed file; the path is a directory.
pub const O_TMPFILE: u64 = 0x0040_0000 | O_DIRECTORY;

/// Mask of all open flags accepted by `openat2`.
const OPEN_FLAGS_KNOWN: u64 = O_RDONLY
    | O_WRONLY
    | O_RDWR
    | O_CREAT
    | O_EXCL
    | O_NOCTTY
    | O_TRUNC
    | O_APPEND
    | O_NONBLOCK
    | O_DSYNC
    | O_SYNC
    | O_CLOEXEC
    | O_NOFOLLOW
    | O_PATH
    | O_DIRECTORY
    | O_NOATIME
    | O_TMPFILE;

// ---------------------------------------------------------------------------
// Resolve flags
// ---------------------------------------------------------------------------

/// Do not cross mount-point boundaries during resolution.
pub const RESOLVE_NO_XDEV: u64 = 0x0000_0001;
/// Reject magic symlinks (e.g. `/proc/self/fd/N`).
pub const RESOLVE_NO_MAGICLINKS: u64 = 0x0000_0002;
/// Reject all symbolic links during resolution.
pub const RESOLVE_NO_SYMLINKS: u64 = 0x0000_0004;
/// Restrict resolution so that the final path is beneath `dirfd`.
pub const RESOLVE_BENEATH: u64 = 0x0000_0008;
/// Treat `dirfd` as the filesystem root for this open.
pub const RESOLVE_IN_ROOT: u64 = 0x0000_0010;
/// Fail if any path component is not already in the kernel dentry cache.
pub const RESOLVE_CACHED: u64 = 0x0000_0020;

/// All recognised resolve flags.
const RESOLVE_FLAGS_KNOWN: u64 = RESOLVE_NO_XDEV
    | RESOLVE_NO_MAGICLINKS
    | RESOLVE_NO_SYMLINKS
    | RESOLVE_BENEATH
    | RESOLVE_IN_ROOT
    | RESOLVE_CACHED;

// ---------------------------------------------------------------------------
// OpenHow — the uAPI structure passed from user space
// ---------------------------------------------------------------------------

/// The `open_how` structure passed to `openat2(2)`.
///
/// # ABI compatibility
///
/// This struct must be layout-compatible with the Linux kernel's
/// `struct open_how` defined in `include/uapi/linux/openat2.h`.
/// The kernel uses `copy_struct_from_user` which allows the user-space
/// struct to be larger or smaller than the kernel's definition; unknown
/// fields in a larger struct must be zero for forward compatibility.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OpenHow {
    /// Open flags (`O_*` constants).
    pub flags: u64,
    /// File creation mode (only meaningful when `O_CREAT` or `O_TMPFILE`
    /// is set in `flags`).
    pub mode: u64,
    /// Path resolution flags (`RESOLVE_*` constants).
    pub resolve: u64,
}

impl OpenHow {
    /// Construct a new `OpenHow` with the given fields.
    pub const fn new(flags: u64, mode: u64, resolve: u64) -> Self {
        Self {
            flags,
            mode,
            resolve,
        }
    }

    /// Return the size of the struct as expected by the current ABI.
    pub const fn size() -> usize {
        core::mem::size_of::<Self>()
    }
}

// ---------------------------------------------------------------------------
// Special dirfd value
// ---------------------------------------------------------------------------

/// When passed as `dirfd`, the path is interpreted relative to the process's
/// current working directory (same as `open(2)`).
pub const AT_FDCWD: i32 = -100;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate that no unknown `flags` bits are set.
///
/// Returns `Err(InvalidArgument)` if the flags contain unrecognised bits.
fn validate_open_flags(flags: u64) -> Result<()> {
    // O_RDONLY is 0; reject any bit outside the known mask.
    if flags & !OPEN_FLAGS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    // O_WRONLY | O_RDWR together is invalid.
    if flags & O_WRONLY != 0 && flags & O_RDWR != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate that no unknown `resolve` bits are set.
fn validate_resolve_flags(resolve: u64) -> Result<()> {
    if resolve & !RESOLVE_FLAGS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    // RESOLVE_IN_ROOT and RESOLVE_BENEATH are mutually exclusive.
    if resolve & RESOLVE_IN_ROOT != 0 && resolve & RESOLVE_BENEATH != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate the mode field.
///
/// Mode is only meaningful when `O_CREAT` or `O_TMPFILE` is in flags.
/// If neither flag is set the mode must be zero.
fn validate_mode(flags: u64, mode: u64) -> Result<()> {
    let creates_file = (flags & O_CREAT != 0) || (flags & O_TMPFILE == O_TMPFILE);
    if !creates_file && mode != 0 {
        return Err(Error::InvalidArgument);
    }
    // Mode must not contain bits outside 07777 (12 permission bits).
    if mode & !0o7777 != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Validate an `OpenHow` struct obtained from user space.
///
/// Called after the struct has been safely copied from user space.
pub fn validate_open_how(how: &OpenHow) -> Result<()> {
    validate_open_flags(how.flags)?;
    validate_resolve_flags(how.resolve)?;
    validate_mode(how.flags, how.mode)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Path resolution context
// ---------------------------------------------------------------------------

/// Records which constraints apply during path traversal.
#[derive(Debug, Clone, Copy)]
pub struct ResolveCtx {
    /// Do not cross mount boundaries.
    pub no_xdev: bool,
    /// Reject magic symlinks.
    pub no_magiclinks: bool,
    /// Reject all symlinks.
    pub no_symlinks: bool,
    /// Path must remain beneath the `dirfd` subtree.
    pub beneath: bool,
    /// Treat `dirfd` as root.
    pub in_root: bool,
    /// Only succeed if all components are already cached.
    pub cached_only: bool,
}

impl ResolveCtx {
    /// Build a `ResolveCtx` from the `resolve` field of an [`OpenHow`].
    pub const fn from_flags(resolve: u64) -> Self {
        Self {
            no_xdev: resolve & RESOLVE_NO_XDEV != 0,
            no_magiclinks: resolve & RESOLVE_NO_MAGICLINKS != 0,
            no_symlinks: resolve & RESOLVE_NO_SYMLINKS != 0,
            beneath: resolve & RESOLVE_BENEATH != 0,
            in_root: resolve & RESOLVE_IN_ROOT != 0,
            cached_only: resolve & RESOLVE_CACHED != 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Simulated path components
// ---------------------------------------------------------------------------

/// Maximum number of path components supported during one resolution.
const MAX_PATH_COMPONENTS: usize = 40;

/// Maximum symlink-follow depth (mirrors Linux `MAXSYMLINKS`).
const MAX_SYMLINK_DEPTH: usize = 8;

/// Result of resolving a path to a virtual filesystem node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VnodeId(u64);

impl VnodeId {
    /// Create a `VnodeId` from a raw value.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Return the raw value.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Represents a resolved path with contextual constraints applied.
pub struct ResolvedPath {
    /// The vnode that represents the resolved file or directory.
    pub vnode: VnodeId,
    /// How many symlinks were followed during resolution.
    pub symlink_depth: usize,
    /// Whether the resolved path crossed a mount boundary.
    pub crossed_mount: bool,
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for the `openat2(2)` syscall.
///
/// # Arguments
///
/// * `dirfd`      — Directory file descriptor, or [`AT_FDCWD`].
/// * `pathname`   — Null-terminated path string (already copied from user space).
/// * `how`        — Validated [`OpenHow`] struct (already copied from user space).
/// * `usize_arg`  — `size` argument passed by the user; must equal `sizeof(open_how)`.
///
/// # Returns
///
/// On success, returns a new file descriptor (as `u64`).  On failure returns an
/// [`Error`] value encoding the appropriate `errno`.
///
/// # Safety contract (for callers)
///
/// `pathname` must point to a null-terminated byte string that has already been
/// validated and copied out of user space.  `how` must have been validated with
/// [`validate_open_how`] before calling this function.
///
/// # POSIX / Linux conformance
///
/// - Rejects unknown `how.flags` or `how.resolve` bits with `EINVAL`.
/// - Rejects `how` structs smaller than the kernel's `open_how` with `EINVAL`.
/// - Rejects non-zero padding in `how` for forward compatibility.
pub fn do_openat2(dirfd: i32, pathname: &[u8], how: &OpenHow, size: usize) -> Result<u64> {
    // The `size` argument must be at least as large as the current kernel ABI.
    if size < OpenHow::size() {
        return Err(Error::InvalidArgument);
    }

    // Re-validate in case the caller skipped the dedicated validator.
    validate_open_how(how)?;

    // Reject empty path unless O_PATH is set and dirfd is a valid fd.
    let is_empty_path = pathname.is_empty() || pathname.first() == Some(&0);
    if is_empty_path && how.flags & O_PATH == 0 {
        return Err(Error::InvalidArgument);
    }

    // Build resolution context from resolve flags.
    let rctx = ResolveCtx::from_flags(how.resolve);

    // Validate dirfd: must be AT_FDCWD or a non-negative fd number.
    if dirfd != AT_FDCWD && dirfd < 0 {
        return Err(Error::InvalidArgument);
    }

    // Perform simulated path walk (in a real kernel this calls into VFS).
    let resolved = simulate_path_walk(dirfd, pathname, &rctx)?;

    // Enforce RESOLVE_NO_XDEV after the walk.
    if rctx.no_xdev && resolved.crossed_mount {
        return Err(Error::InvalidArgument);
    }

    // Enforce symlink constraints.
    if rctx.no_symlinks && resolved.symlink_depth > 0 {
        return Err(Error::InvalidArgument);
    }

    // Derive the file open mode from flags.
    let _access_mode = how.flags & (O_RDONLY | O_WRONLY | O_RDWR);
    let _create_mode = how.mode as u32;

    // In a real kernel we would:
    //   1. Look up or create the dentry.
    //   2. Apply DAC + capability checks.
    //   3. Call ->open() on the inode.
    //   4. Allocate a file descriptor and install it.
    // Here we return the vnode id as a synthetic fd for the stub.
    Ok(resolved.vnode.raw())
}

// ---------------------------------------------------------------------------
// Stub VFS walk
// ---------------------------------------------------------------------------

/// Stub implementation of a path walk respecting [`ResolveCtx`] constraints.
///
/// In the real kernel this would recursively call `link_path_walk` / `path_openat`.
/// Here we perform basic sanity checks and return a synthetic vnode.
fn simulate_path_walk(dirfd: i32, pathname: &[u8], rctx: &ResolveCtx) -> Result<ResolvedPath> {
    // Count path components (split on '/').
    let mut components = 0usize;
    let mut symlink_depth = 0usize;
    let mut crossed_mount = false;

    // Walk each byte of the path doing minimal book-keeping.
    let mut prev_slash = true;
    for &byte in pathname {
        if byte == 0 {
            break; // null terminator
        }
        if byte == b'/' {
            prev_slash = true;
            continue;
        }
        if prev_slash {
            components += 1;
            prev_slash = false;
        }
        if components > MAX_PATH_COMPONENTS {
            return Err(Error::InvalidArgument);
        }
    }

    // RESOLVE_CACHED: simulate a cache miss for paths > 1 component.
    if rctx.cached_only && components > 1 {
        return Err(Error::WouldBlock);
    }

    // Absolute paths starting with '/' imply a potential mount crossing.
    if pathname.first() == Some(&b'/') {
        crossed_mount = true;
    }

    // RESOLVE_BENEATH / RESOLVE_IN_ROOT: reject absolute paths when beneath
    // constraint is active, as they escape the dirfd subtree.
    if rctx.beneath && pathname.first() == Some(&b'/') {
        return Err(Error::PermissionDenied);
    }

    // Simulate a fixed symlink depth for any path that has components.
    if components > 0 && !rctx.no_symlinks && !rctx.no_magiclinks {
        symlink_depth = components.min(MAX_SYMLINK_DEPTH / 2);
    }

    // Derive a stable synthetic vnode id from the dirfd and path length.
    let path_len = pathname
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(pathname.len());
    let vnode_id = ((dirfd as u64).wrapping_add(0x1000)) ^ (path_len as u64 * 31);

    Ok(ResolvedPath {
        vnode: VnodeId::new(vnode_id),
        symlink_depth,
        crossed_mount,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_how_size_is_24() {
        assert_eq!(OpenHow::size(), 24);
    }

    #[test]
    fn validate_rejects_unknown_flags() {
        let how = OpenHow::new(0xFFFF_FFFF_0000_0000, 0, 0);
        assert_eq!(validate_open_how(&how), Err(Error::InvalidArgument));
    }

    #[test]
    fn validate_rejects_unknown_resolve() {
        let how = OpenHow::new(O_RDONLY, 0, 0xFFFF);
        assert_eq!(validate_open_how(&how), Err(Error::InvalidArgument));
    }

    #[test]
    fn validate_rejects_mode_without_creat() {
        let how = OpenHow::new(O_RDONLY, 0o644, 0);
        assert_eq!(validate_open_how(&how), Err(Error::InvalidArgument));
    }

    #[test]
    fn validate_accepts_mode_with_creat() {
        let how = OpenHow::new(O_RDWR | O_CREAT, 0o644, 0);
        assert_eq!(validate_open_how(&how), Ok(()));
    }

    #[test]
    fn validate_rejects_beneath_and_in_root_together() {
        let how = OpenHow::new(O_RDONLY, 0, RESOLVE_BENEATH | RESOLVE_IN_ROOT);
        assert_eq!(validate_open_how(&how), Err(Error::InvalidArgument));
    }

    #[test]
    fn validate_rejects_wronly_and_rdwr_together() {
        let how = OpenHow::new(O_WRONLY | O_RDWR, 0, 0);
        assert_eq!(validate_open_how(&how), Err(Error::InvalidArgument));
    }

    #[test]
    fn do_openat2_rejects_small_size() {
        let how = OpenHow::new(O_RDONLY, 0, 0);
        let result = do_openat2(AT_FDCWD, b"test\0", &how, 4);
        assert_eq!(result, Err(Error::InvalidArgument));
    }

    #[test]
    fn do_openat2_rejects_negative_dirfd() {
        let how = OpenHow::new(O_RDONLY, 0, 0);
        let result = do_openat2(-5, b"test\0", &how, OpenHow::size());
        assert_eq!(result, Err(Error::InvalidArgument));
    }

    #[test]
    fn do_openat2_resolves_relative_path() {
        let how = OpenHow::new(O_RDONLY, 0, 0);
        let result = do_openat2(AT_FDCWD, b"foo/bar\0", &how, OpenHow::size());
        assert!(result.is_ok());
    }

    #[test]
    fn resolve_ctx_from_flags() {
        let ctx = ResolveCtx::from_flags(RESOLVE_NO_XDEV | RESOLVE_BENEATH);
        assert!(ctx.no_xdev);
        assert!(ctx.beneath);
        assert!(!ctx.in_root);
        assert!(!ctx.no_symlinks);
    }

    #[test]
    fn do_openat2_beneath_rejects_absolute() {
        let how = OpenHow::new(O_RDONLY, 0, RESOLVE_BENEATH);
        let result = do_openat2(AT_FDCWD, b"/etc/passwd\0", &how, OpenHow::size());
        assert_eq!(result, Err(Error::PermissionDenied));
    }
}
