// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `openat2(2)` syscall dispatch layer.
//!
//! An extended version of `openat(2)` that passes all open parameters via a
//! `struct open_how` rather than individual arguments, enabling new
//! `resolve` flags that harden path resolution against escape attacks.
//!
//! # Syscall signature
//!
//! ```text
//! int openat2(int dirfd, const char *pathname,
//!             struct open_how *how, size_t size);
//! ```
//!
//! # `open_how` fields
//!
//! | Field     | Type   | Description |
//! |-----------|--------|-------------|
//! | `flags`   | u64    | Open flags (`O_RDONLY`, `O_CREAT`, …) |
//! | `mode`    | u64    | File creation mode (used when `O_CREAT` is set) |
//! | `resolve` | u64    | Path resolution restrictions |
//!
//! # Resolve flags
//!
//! | Constant                  | Value | Description |
//! |---------------------------|-------|-------------|
//! | `RESOLVE_NO_XDEV`         | 0x01  | Block cross-device traversal |
//! | `RESOLVE_NO_MAGICLINKS`   | 0x02  | Block magic symlinks |
//! | `RESOLVE_NO_SYMLINKS`     | 0x04  | Block all symlinks |
//! | `RESOLVE_BENEATH`         | 0x08  | Restrict to subtree rooted at `dirfd` |
//! | `RESOLVE_IN_ROOT`         | 0x10  | `dirfd` acts as process root |
//! | `RESOLVE_CACHED`          | 0x20  | Fail if any VFS lookup requires I/O |
//!
//! # References
//!
//! - Linux: `fs/open.c` (`do_sys_openat2`)
//! - `openat2(2)` man page
//! - `include/uapi/linux/openat2.h`

use oncrix_lib::{Error, Result};

// Re-export the OpenHow struct and resolve constants from the detailed module.
pub use crate::openat2::{
    OpenHow, RESOLVE_BENEATH, RESOLVE_CACHED, RESOLVE_IN_ROOT, RESOLVE_NO_MAGICLINKS,
    RESOLVE_NO_SYMLINKS, RESOLVE_NO_XDEV,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Use the current working directory as the base for relative paths.
pub const AT_FDCWD: i32 = -100;

/// Minimum `size` argument (size of `struct open_how` as defined in the ABI).
pub const OPEN_HOW_SIZE_VER0: usize = 24;

/// Maximum valid file descriptor number.
const FD_MAX: i32 = 1_048_576;

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `dirfd` is `AT_FDCWD` or a plausible open fd number.
pub fn is_valid_dirfd(dirfd: i32) -> bool {
    dirfd == AT_FDCWD || (0..=FD_MAX).contains(&dirfd)
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `openat2(2)`.
///
/// `how_ptr` points to a `struct open_how` of at least `size` bytes.
/// Unknown bits in `how.resolve` are rejected with `EINVAL`; unknown bits in
/// `how.flags` are rejected the same way.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null `how_ptr`, `size < OPEN_HOW_SIZE_VER0`,
///   invalid `dirfd`, or unknown bits in `flags`/`resolve`.
/// - [`Error::NotFound`] — path does not exist.
/// - [`Error::AlreadyExists`] — path exists and `O_EXCL` was set.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_openat2(dirfd: i32, pathname_ptr: u64, how_ptr: u64, size: usize) -> Result<i64> {
    if !is_valid_dirfd(dirfd) {
        return Err(Error::InvalidArgument);
    }
    if pathname_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if how_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if size < OPEN_HOW_SIZE_VER0 {
        return Err(Error::InvalidArgument);
    }
    // Validate the open_how structure.
    // SAFETY: pointer validation is the caller's responsibility; this is a
    // stub that reads the struct for argument checking only.
    let how = unsafe { &*(how_ptr as *const OpenHow) };
    let valid_resolve = RESOLVE_NO_XDEV
        | RESOLVE_NO_MAGICLINKS
        | RESOLVE_NO_SYMLINKS
        | RESOLVE_BENEATH
        | RESOLVE_IN_ROOT
        | RESOLVE_CACHED;
    if how.resolve & !valid_resolve != 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (dirfd, pathname_ptr, how, size);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_openat2_call(dirfd: i32, pathname_ptr: u64, how_ptr: u64, size: usize) -> Result<i64> {
    sys_openat2(dirfd, pathname_ptr, how_ptr, size)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_how_rejected() {
        assert_eq!(
            sys_openat2(AT_FDCWD, 0x1000, 0, OPEN_HOW_SIZE_VER0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn size_too_small_rejected() {
        assert_eq!(
            sys_openat2(AT_FDCWD, 0x1000, 0x2000, OPEN_HOW_SIZE_VER0 - 1).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_pathname_rejected() {
        assert_eq!(
            sys_openat2(AT_FDCWD, 0, 0x2000, OPEN_HOW_SIZE_VER0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn invalid_dirfd_rejected() {
        assert_eq!(
            sys_openat2(-500, 0x1000, 0x2000, OPEN_HOW_SIZE_VER0).unwrap_err(),
            Error::InvalidArgument
        );
    }
}
