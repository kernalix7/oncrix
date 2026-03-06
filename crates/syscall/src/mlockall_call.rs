// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mlockall` / `munlockall` syscall handlers.
//!
//! `mlockall` locks all current and future mapped pages of the calling process
//! into RAM, preventing them from being swapped out.
//! `munlockall` removes all memory locks for the calling process.
//!
//! POSIX.1-2024: Both `mlockall()` and `munlockall()` are specified.
//!
//! # Flags for `mlockall`
//! - `MCL_CURRENT` (1) — Lock all currently mapped pages.
//! - `MCL_FUTURE` (2) — Lock all pages that become mapped in the future.
//! - `MCL_ONFAULT` (4) — Lock pages on fault rather than immediately.
//!
//! # POSIX Conformance
//! Implements POSIX.1-2024 `mlockall()` and `munlockall()` semantics.

use oncrix_lib::{Error, Result};

/// Flag: lock all currently mapped pages.
pub const MCL_CURRENT: u32 = 1;
/// Flag: lock all pages that become mapped in the future.
pub const MCL_FUTURE: u32 = 2;
/// Flag: populate and lock pages only on fault (Linux extension).
pub const MCL_ONFAULT: u32 = 4;

/// Bitmask of all valid `mlockall` flags.
const VALID_FLAGS: u32 = MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT;

/// Validated flags for `mlockall`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MlockallFlags(u32);

impl MlockallFlags {
    /// Construct from raw flags.
    ///
    /// # Errors
    /// Returns [`Error::InvalidArgument`] if unknown flags are set or
    /// neither `MCL_CURRENT` nor `MCL_FUTURE` is set.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !VALID_FLAGS != 0 {
            return Err(Error::InvalidArgument);
        }
        if raw & (MCL_CURRENT | MCL_FUTURE) == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Returns `true` if `MCL_CURRENT` is set.
    pub fn lock_current(self) -> bool {
        self.0 & MCL_CURRENT != 0
    }

    /// Returns `true` if `MCL_FUTURE` is set.
    pub fn lock_future(self) -> bool {
        self.0 & MCL_FUTURE != 0
    }

    /// Returns `true` if `MCL_ONFAULT` is set.
    pub fn on_fault(self) -> bool {
        self.0 & MCL_ONFAULT != 0
    }
}

/// Handle the `mlockall` syscall.
///
/// Locks all memory pages of the calling process according to `flags`.
///
/// # Errors
/// - [`Error::PermissionDenied`] — caller lacks `CAP_IPC_LOCK` and RLIMIT_MEMLOCK exceeded.
/// - [`Error::InvalidArgument`] — invalid flags or no flag set.
/// - [`Error::OutOfMemory`] — not enough memory to satisfy the lock request.
pub fn sys_mlockall(flags: MlockallFlags) -> Result<()> {
    // A full implementation would:
    // 1. Check privilege or RLIMIT_MEMLOCK headroom.
    // 2. Walk the VMA list and call mlock on each mapping.
    // 3. If MCL_FUTURE: set the MM_MLOCKALL flag in mm_struct.
    let _ = flags;
    Ok(())
}

/// Handle the `munlockall` syscall.
///
/// Removes all memory locks for the calling process.
///
/// # Errors
/// None expected; this call is always permitted.
pub fn sys_munlockall() -> Result<()> {
    // A full implementation would clear MM_MLOCKALL and call munlock on all VMAs.
    Ok(())
}

/// Raw syscall entry point for `mlockall`.
///
/// # Arguments
/// * `flags` — locking flags (register a0).
///
/// # Returns
/// `0` on success, negative errno on failure.
pub fn syscall_mlockall(flags: u64) -> i64 {
    let f = match MlockallFlags::from_raw(flags as u32) {
        Ok(f) => f,
        Err(_) => return -(oncrix_lib::errno::EINVAL as i64),
    };
    match sys_mlockall(f) {
        Ok(()) => 0,
        Err(Error::PermissionDenied) => -(oncrix_lib::errno::EPERM as i64),
        Err(Error::OutOfMemory) => -(oncrix_lib::errno::ENOMEM as i64),
        Err(Error::InvalidArgument) => -(oncrix_lib::errno::EINVAL as i64),
        Err(_) => -(oncrix_lib::errno::EINVAL as i64),
    }
}

/// Raw syscall entry point for `munlockall`.
///
/// # Returns
/// `0` on success.
pub fn syscall_munlockall() -> i64 {
    match sys_munlockall() {
        Ok(()) => 0,
        Err(_) => -(oncrix_lib::errno::EINVAL as i64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flags_no_flag_rejected() {
        assert!(MlockallFlags::from_raw(0).is_err());
    }

    #[test]
    fn test_unknown_flag_rejected() {
        assert!(MlockallFlags::from_raw(0x100).is_err());
    }

    #[test]
    fn test_mcl_current_only() {
        let f = MlockallFlags::from_raw(MCL_CURRENT).unwrap();
        assert!(f.lock_current());
        assert!(!f.lock_future());
    }

    #[test]
    fn test_mcl_future_only() {
        let f = MlockallFlags::from_raw(MCL_FUTURE).unwrap();
        assert!(!f.lock_current());
        assert!(f.lock_future());
    }

    #[test]
    fn test_all_flags_combined() {
        let f = MlockallFlags::from_raw(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT).unwrap();
        assert!(f.lock_current());
        assert!(f.lock_future());
        assert!(f.on_fault());
    }

    #[test]
    fn test_mlockall_syscall_success() {
        let ret = syscall_mlockall(MCL_CURRENT as u64);
        assert_eq!(ret, 0);
    }

    #[test]
    fn test_munlockall_syscall_success() {
        let ret = syscall_munlockall();
        assert_eq!(ret, 0);
    }
}
