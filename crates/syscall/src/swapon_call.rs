// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `swapon(2)` syscall handler — enable a swap area.
//!
//! `swapon` designates the block device or file identified by `path` as a
//! swap area.  Requires `CAP_SYS_ADMIN`.
//!
//! # Syscall signature
//!
//! ```text
//! int swapon(const char *path, int swapflags);
//! ```
//!
//! # Flags
//!
//! | Flag | Value | Description |
//! |------|-------|-------------|
//! | `SWAP_FLAG_PREFER` | 0x8000 | Set swap priority from `SWAP_FLAG_PRIO_MASK` |
//! | `SWAP_FLAG_PRIO_MASK` | 0x7fff | Priority value mask |
//! | `SWAP_FLAG_PRIO_SHIFT` | 0 | Shift for priority in flags |
//! | `SWAP_FLAG_DISCARD` | 0x10000 | Enable discard for freed pages |
//! | `SWAP_FLAG_DISCARD_ONCE` | 0x20000 | Discard entire swap area at swapon |
//! | `SWAP_FLAG_DISCARD_PAGES` | 0x40000 | Discard freed pages individually |
//!
//! # References
//!
//! - Linux: `mm/swapfile.c`
//! - `swapon(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Capability required to enable swap.
pub const CAP_SYS_ADMIN: u32 = 21;

/// Use the supplied priority rather than kernel-assigned.
pub const SWAP_FLAG_PREFER: i32 = 0x8000;
/// Bitmask for priority value within flags.
pub const SWAP_FLAG_PRIO_MASK: i32 = 0x7fff;
/// Enable discard on freed swap pages.
pub const SWAP_FLAG_DISCARD: i32 = 0x10000;
/// Discard entire swap area once at `swapon` time.
pub const SWAP_FLAG_DISCARD_ONCE: i32 = 0x20000;
/// Discard individual freed pages.
pub const SWAP_FLAG_DISCARD_PAGES: i32 = 0x40000;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Parsed swapon flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct SwapFlags {
    /// User-specified priority (valid only when `prefer` is true).
    pub priority: i32,
    /// Whether `SWAP_FLAG_PREFER` was set.
    pub prefer: bool,
    /// Enable discard for freed pages.
    pub discard: bool,
    /// Discard the entire area at swapon.
    pub discard_once: bool,
    /// Discard individual freed pages.
    pub discard_pages: bool,
}

impl SwapFlags {
    /// Parse raw swap flags into a structured representation.
    pub fn parse(flags: i32) -> Result<Self> {
        let known = SWAP_FLAG_PREFER
            | SWAP_FLAG_PRIO_MASK
            | SWAP_FLAG_DISCARD
            | SWAP_FLAG_DISCARD_ONCE
            | SWAP_FLAG_DISCARD_PAGES;
        if flags & !known != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            priority: flags & SWAP_FLAG_PRIO_MASK,
            prefer: flags & SWAP_FLAG_PREFER != 0,
            discard: flags & SWAP_FLAG_DISCARD != 0,
            discard_once: flags & SWAP_FLAG_DISCARD_ONCE != 0,
            discard_pages: flags & SWAP_FLAG_DISCARD_PAGES != 0,
        })
    }
}

/// Information about an active swap area.
#[derive(Debug, Clone, Copy)]
pub struct SwapAreaInfo {
    /// Virtual path pointer (user-space string).
    pub path_ptr: u64,
    /// Effective priority.
    pub priority: i32,
    /// Parsed flags.
    pub flags: SwapFlags,
}

impl SwapAreaInfo {
    /// Create a new info record.
    pub const fn new(path_ptr: u64, priority: i32, flags: SwapFlags) -> Self {
        Self {
            path_ptr,
            priority,
            flags,
        }
    }
}

impl Default for SwapAreaInfo {
    fn default() -> Self {
        Self::new(0, 0, SwapFlags::default())
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `swapon(2)` syscall.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null path or unknown flags.
/// - [`Error::PermissionDenied`] — caller lacks `CAP_SYS_ADMIN`.
/// - [`Error::NotImplemented`] — swap subsystem not yet wired.
pub fn sys_swapon(path: u64, swapflags: i32, caps: u64) -> Result<i64> {
    if caps & (1u64 << CAP_SYS_ADMIN) == 0 {
        return Err(Error::PermissionDenied);
    }
    if path == 0 {
        return Err(Error::InvalidArgument);
    }
    let flags = SwapFlags::parse(swapflags)?;
    do_swapon(path, &flags)
}

fn do_swapon(path: u64, flags: &SwapFlags) -> Result<i64> {
    let _ = (path, flags);
    // TODO: Open and validate the swap area, build the swap map, and register
    // with the MM subsystem.
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_swapon_syscall(path: u64, swapflags: i32, caps: u64) -> Result<i64> {
    sys_swapon(path, swapflags, caps)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_cap_rejected() {
        assert_eq!(sys_swapon(1, 0, 0).unwrap_err(), Error::PermissionDenied);
    }

    #[test]
    fn null_path_rejected() {
        let caps = 1u64 << CAP_SYS_ADMIN;
        assert_eq!(sys_swapon(0, 0, caps).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn unknown_flags_rejected() {
        let caps = 1u64 << CAP_SYS_ADMIN;
        assert_eq!(
            sys_swapon(1, 0x1000_0000, caps).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn prefer_flag_parsed() {
        let f = SwapFlags::parse(SWAP_FLAG_PREFER | 5).unwrap();
        assert!(f.prefer);
        assert_eq!(f.priority, 5);
    }

    #[test]
    fn discard_flag_parsed() {
        let f = SwapFlags::parse(SWAP_FLAG_DISCARD).unwrap();
        assert!(f.discard);
    }

    #[test]
    fn swap_area_info_default() {
        let info = SwapAreaInfo::default();
        assert_eq!(info.path_ptr, 0);
    }
}
