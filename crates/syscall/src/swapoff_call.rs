// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `swapoff(2)` syscall handler — disable a swap area.
//!
//! `swapoff` stops using the swap area specified by `path` and causes the
//! kernel to page all data back into RAM.  Requires `CAP_SYS_ADMIN`.
//!
//! # Syscall signature
//!
//! ```text
//! int swapoff(const char *path);
//! ```
//!
//! # References
//!
//! - Linux: `mm/swapfile.c`
//! - `swapoff(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Capability required to disable swap.
pub const CAP_SYS_ADMIN: u32 = 21;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Request parameters for `swapoff`.
#[derive(Debug, Clone, Copy)]
pub struct SwapoffRequest {
    /// User-space pointer to the NUL-terminated path of the swap area.
    pub path: u64,
}

impl SwapoffRequest {
    /// Create a new request.
    pub const fn new(path: u64) -> Self {
        Self { path }
    }

    /// Validate the request.
    pub fn validate(&self) -> Result<()> {
        if self.path == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for SwapoffRequest {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Statistics from a swapoff operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct SwapoffStats {
    /// Number of pages moved back to RAM during swapoff.
    pub pages_reclaimed: u64,
}

impl SwapoffStats {
    /// Create a new statistics record.
    pub const fn new() -> Self {
        Self { pages_reclaimed: 0 }
    }
}

/// Current state of a swap area that can be queried before removal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapAreaStatus {
    /// The swap area is active and accepting pages.
    Active,
    /// The swap area is in the process of being deactivated.
    Deactivating,
    /// The swap area has been fully removed.
    Removed,
}

impl Default for SwapAreaStatus {
    fn default() -> Self {
        Self::Active
    }
}

/// Describes a single active swap area entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct SwapEntry {
    /// Total size of the swap area in pages.
    pub total_pages: u64,
    /// Number of pages currently in use.
    pub used_pages: u64,
    /// Priority of this swap area (higher priority used first).
    pub priority: i32,
    /// Current status of the swap area.
    pub status: SwapAreaStatus,
}

impl SwapEntry {
    /// Create a new swap entry.
    pub const fn new(total_pages: u64, used_pages: u64, priority: i32) -> Self {
        Self {
            total_pages,
            used_pages,
            priority,
            status: SwapAreaStatus::Active,
        }
    }

    /// Return the number of free pages in this swap area.
    pub fn free_pages(&self) -> u64 {
        self.total_pages.saturating_sub(self.used_pages)
    }

    /// Return usage as a percentage (0–100).
    pub fn usage_percent(&self) -> u64 {
        if self.total_pages == 0 {
            return 0;
        }
        (self.used_pages * 100) / self.total_pages
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `swapoff(2)` syscall.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — null path pointer.
/// - [`Error::PermissionDenied`] — caller lacks `CAP_SYS_ADMIN`.
/// - [`Error::NotFound`] — path does not match any active swap area.
/// - [`Error::OutOfMemory`] — insufficient RAM to hold all paged-out data.
/// - [`Error::NotImplemented`] — swap subsystem not yet wired.
pub fn sys_swapoff(path: u64, caps: u64) -> Result<i64> {
    if caps & (1u64 << CAP_SYS_ADMIN) == 0 {
        return Err(Error::PermissionDenied);
    }
    let req = SwapoffRequest::new(path);
    req.validate()?;
    do_swapoff(&req)
}

fn do_swapoff(req: &SwapoffRequest) -> Result<i64> {
    let _ = req;
    // TODO: Locate the swap area by path, page all swapped-out content back
    // into RAM, and deregister the swap area from the MM subsystem.
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_swapoff_syscall(path: u64, caps: u64) -> Result<i64> {
    sys_swapoff(path, caps)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_cap_rejected() {
        assert_eq!(sys_swapoff(1, 0).unwrap_err(), Error::PermissionDenied);
    }

    #[test]
    fn null_path_rejected() {
        let caps = 1u64 << CAP_SYS_ADMIN;
        assert_eq!(sys_swapoff(0, caps).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn valid_path_with_cap_reaches_subsystem() {
        let caps = 1u64 << CAP_SYS_ADMIN;
        assert_eq!(
            sys_swapoff(0x1000, caps).unwrap_err(),
            Error::NotImplemented
        );
    }

    #[test]
    fn stats_default_zero() {
        let stats = SwapoffStats::default();
        assert_eq!(stats.pages_reclaimed, 0);
    }

    #[test]
    fn request_default_null_path() {
        let req = SwapoffRequest::default();
        assert_eq!(req.path, 0);
        assert!(req.validate().is_err());
    }

    #[test]
    fn request_valid_path() {
        let req = SwapoffRequest::new(0x2000);
        assert!(req.validate().is_ok());
    }
}
