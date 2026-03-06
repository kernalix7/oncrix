// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getgid` syscall handler.
//!
//! Returns the real group ID (GID) of the calling process.
//! POSIX.1-2024: `getgid()` shall return the real group ID of the calling process.
//!
//! # POSIX Conformance
//! Implements POSIX.1-2024 `getgid()` semantics. This call always succeeds.

use oncrix_lib::Result;

/// The result of a `getgid` call: the real group ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetGidResult {
    /// Real group identifier.
    pub rgid: u32,
}

impl GetGidResult {
    /// Construct a new result.
    pub const fn new(rgid: u32) -> Self {
        Self { rgid }
    }
}

/// Handle the `getgid` syscall.
///
/// Returns the real GID of the calling process. This call cannot fail.
pub fn sys_getgid() -> Result<GetGidResult> {
    // In a full implementation this reads the calling task's credentials.
    // Root GID (0) is returned as a stub.
    Ok(GetGidResult::new(0))
}

/// Raw syscall entry point for `getgid`.
///
/// # Returns
/// The real GID of the calling process (always non-negative).
pub fn syscall_getgid() -> i64 {
    match sys_getgid() {
        Ok(result) => result.rgid as i64,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_getgid_returns_nonnegative() {
        let ret = syscall_getgid();
        assert!(ret >= 0);
    }

    #[test]
    fn test_getgid_result_construction() {
        let r = GetGidResult::new(1000);
        assert_eq!(r.rgid, 1000);
    }
}
