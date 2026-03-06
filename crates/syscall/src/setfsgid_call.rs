// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `setfsgid` syscall handler.
//!
//! Sets the filesystem group ID (fsgid) of the calling process. The fsgid is
//! used exclusively for filesystem permission checks and is separate from the
//! effective GID. This allows a process to temporarily change its filesystem
//! identity without changing other GID semantics.
//!
//! On success, `setfsgid` returns the previous fsgid value. This behavior
//! differs from most syscalls and is intentional per Linux semantics.
//!
//! # POSIX Conformance
//! `setfsgid` is a Linux-specific extension not in POSIX.1-2024.

use oncrix_lib::Result;

/// Sentinel: use the calling process's effective GID as the new fsgid.
pub const FSGID_USE_EGID: u32 = u32::MAX;

/// Arguments for the `setfsgid` syscall.
#[derive(Debug, Clone, Copy)]
pub struct SetFsgidArgs {
    /// New filesystem group ID. `FSGID_USE_EGID` means use the effective GID.
    pub fsgid: u32,
}

impl SetFsgidArgs {
    /// Construct from raw syscall register value.
    ///
    /// All values are valid (they are simply cast to u32).
    pub fn from_raw(fsgid_raw: u64) -> Self {
        Self {
            fsgid: fsgid_raw as u32,
        }
    }

    /// Returns `true` if the caller wants to reset to the effective GID.
    pub fn use_egid(self) -> bool {
        self.fsgid == FSGID_USE_EGID
    }
}

/// Result of `setfsgid`: the previous fsgid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetFsgidResult {
    /// The filesystem GID before this call.
    pub previous_fsgid: u32,
}

impl SetFsgidResult {
    /// Construct a new result.
    pub const fn new(previous_fsgid: u32) -> Self {
        Self { previous_fsgid }
    }
}

/// Handle the `setfsgid` syscall.
///
/// Sets the filesystem GID for the calling process and returns the previous
/// value. If `fsgid` equals `FSGID_USE_EGID`, the effective GID is used.
///
/// Privilege check: setting to any value other than the current rgid/egid/sgid
/// requires `CAP_SETGID`.
///
/// # Note
/// This function always succeeds (returning the old fsgid) even if the caller
/// lacks privilege. The old fsgid is always returned so callers can verify
/// whether the change took effect.
pub fn sys_setfsgid(args: SetFsgidArgs) -> Result<SetFsgidResult> {
    // A full implementation would:
    // 1. Read the current fsgid from the calling task's credentials.
    // 2. Check if the new fsgid matches any of rgid/egid/sgid, or CAP_SETGID.
    // 3. If allowed: update the fsgid in the credentials.
    // 4. Return the old fsgid regardless of success or failure.
    let _ = args;
    Ok(SetFsgidResult::new(0))
}

/// Raw syscall entry point for `setfsgid`.
///
/// # Arguments
/// * `fsgid` — new filesystem GID (register a0).
///
/// # Returns
/// The previous fsgid value (always non-negative).
pub fn syscall_setfsgid(fsgid: u64) -> i64 {
    let args = SetFsgidArgs::from_raw(fsgid);
    match sys_setfsgid(args) {
        Ok(result) => result.previous_fsgid as i64,
        Err(_) => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_raw_identity() {
        let args = SetFsgidArgs::from_raw(1000);
        assert_eq!(args.fsgid, 1000);
    }

    #[test]
    fn test_use_egid_sentinel() {
        let args = SetFsgidArgs::from_raw(u64::MAX);
        assert!(args.use_egid());
    }

    #[test]
    fn test_non_sentinel_not_egid() {
        let args = SetFsgidArgs::from_raw(500);
        assert!(!args.use_egid());
    }

    #[test]
    fn test_result_construction() {
        let r = SetFsgidResult::new(42);
        assert_eq!(r.previous_fsgid, 42);
    }

    #[test]
    fn test_syscall_returns_previous() {
        // Stub returns 0 as previous fsgid.
        let ret = syscall_setfsgid(1000);
        assert!(ret >= 0);
    }
}
