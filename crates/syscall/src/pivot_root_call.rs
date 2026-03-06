// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `pivot_root(2)` syscall handler.
//!
//! Changes the root filesystem of the calling process's mount namespace.
//! `new_root` becomes the new root directory; `put_old` receives the old root.
//!
//! # Key behaviours
//!
//! - Requires `CAP_SYS_ADMIN`.
//! - `new_root` must be a mountpoint, not the same as the current root.
//! - `put_old` must be under `new_root`.
//! - Neither `new_root` nor `put_old` may have a filesystem mounted on top.
//! - After the call, the old root is accessible at `put_old`.
//! - Commonly used with `chroot` in container runtimes.
//!
//! # References
//!
//! - Linux man pages: `pivot_root(2)`
//! - Linux source: `fs/namespace.c` (`sys_pivot_root`)

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Path validation helpers
// ---------------------------------------------------------------------------

/// Check that `haystack` starts with `prefix` (for path containment check).
fn path_starts_with(haystack: &[u8], prefix: &[u8]) -> bool {
    if prefix.len() > haystack.len() {
        return false;
    }
    if &haystack[..prefix.len()] != prefix {
        return false;
    }
    // Either exact match or next char is '/'.
    haystack.len() == prefix.len() || haystack[prefix.len()] == b'/'
}

// ---------------------------------------------------------------------------
// Filesystem root state
// ---------------------------------------------------------------------------

/// Represents the current root directory state for `pivot_root`.
#[derive(Debug, Clone, Copy)]
pub struct RootState {
    /// Current root path (absolute, e.g. `/`).
    pub root: [u8; 256],
    /// Length of root path.
    pub root_len: usize,
}

impl RootState {
    /// Construct with the given root path.
    pub fn new(root: &[u8]) -> Self {
        let mut r = Self {
            root: [0u8; 256],
            root_len: root.len().min(255),
        };
        r.root[..r.root_len].copy_from_slice(&root[..r.root_len]);
        r
    }

    /// Root path as a byte slice.
    pub fn root_path(&self) -> &[u8] {
        &self.root[..self.root_len]
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `pivot_root(2)`.
///
/// Validates the arguments and updates `state` to reflect the new root.
///
/// # Arguments
///
/// * `state`         — Mutable root state to update.
/// * `new_root`      — Path to the new root directory (must be a mountpoint).
/// * `put_old`       — Path under `new_root` where the old root will be placed.
/// * `cap_sys_admin` — Whether the caller has `CAP_SYS_ADMIN`.
/// * `new_root_is_mount` — Whether `new_root` is a mountpoint.
/// * `put_old_is_mount`  — Whether `put_old` has nothing mounted on it.
///
/// # Errors
///
/// | `Error`           | Condition                                         |
/// |-------------------|---------------------------------------------------|
/// | `PermissionDenied`| Caller lacks `CAP_SYS_ADMIN`                      |
/// | `InvalidArgument` | `new_root` is not a mountpoint                    |
/// | `InvalidArgument` | `put_old` is not under `new_root`                 |
/// | `InvalidArgument` | `new_root` or `put_old` is the current root       |
/// | `Busy`            | Something is mounted on `put_old`                 |
pub fn do_pivot_root(
    state: &mut RootState,
    new_root: &[u8],
    put_old: &[u8],
    cap_sys_admin: bool,
    new_root_is_mount: bool,
    put_old_has_mount: bool,
) -> Result<()> {
    if !cap_sys_admin {
        return Err(Error::PermissionDenied);
    }
    if new_root.is_empty() || put_old.is_empty() {
        return Err(Error::InvalidArgument);
    }
    if !new_root_is_mount {
        return Err(Error::InvalidArgument);
    }
    // put_old must be under new_root.
    if !path_starts_with(put_old, new_root) {
        return Err(Error::InvalidArgument);
    }
    // put_old must not have anything mounted on it.
    if put_old_has_mount {
        return Err(Error::Busy);
    }
    // new_root must not be the current root.
    if new_root == state.root_path() {
        return Err(Error::InvalidArgument);
    }

    // Update state: new_root becomes the new root.
    let new_len = new_root.len().min(255);
    state.root[..new_len].copy_from_slice(&new_root[..new_len]);
    state.root[new_len] = 0;
    state.root_len = new_len;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pivot_ok() {
        let mut state = RootState::new(b"/");
        do_pivot_root(
            &mut state,
            b"/newroot",
            b"/newroot/oldroot",
            true,
            true,
            false,
        )
        .unwrap();
        assert_eq!(state.root_path(), b"/newroot");
    }

    #[test]
    fn pivot_no_cap() {
        let mut state = RootState::new(b"/");
        assert_eq!(
            do_pivot_root(&mut state, b"/newroot", b"/newroot/old", false, true, false),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn pivot_not_mountpoint() {
        let mut state = RootState::new(b"/");
        assert_eq!(
            do_pivot_root(&mut state, b"/newroot", b"/newroot/old", true, false, false),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn pivot_put_old_not_under_new_root() {
        let mut state = RootState::new(b"/");
        assert_eq!(
            do_pivot_root(&mut state, b"/newroot", b"/other/old", true, true, false),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn pivot_put_old_busy() {
        let mut state = RootState::new(b"/");
        assert_eq!(
            do_pivot_root(&mut state, b"/newroot", b"/newroot/old", true, true, true),
            Err(Error::Busy)
        );
    }

    #[test]
    fn path_starts_with_exact() {
        assert!(path_starts_with(b"/newroot", b"/newroot"));
    }

    #[test]
    fn path_starts_with_subdir() {
        assert!(path_starts_with(b"/newroot/old", b"/newroot"));
    }

    #[test]
    fn path_starts_with_false() {
        assert!(!path_starts_with(b"/other", b"/newroot"));
    }
}
