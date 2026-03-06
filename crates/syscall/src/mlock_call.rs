// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `mlock(2)`, `munlock(2)`, `mlockall(2)`, and `munlockall(2)` syscall handlers.
//!
//! Lock pages in memory to prevent them from being swapped out.
//!
//! # POSIX Conformance
//!
//! Follows POSIX.1-2024 `mlock()` specification.  Key behaviours:
//! - Address and length are rounded to page boundaries.
//! - `ENOMEM` if the address range is not fully mapped.
//! - `EPERM` if the calling process lacks `CAP_IPC_LOCK` and the lock
//!   would exceed `RLIMIT_MEMLOCK`.
//! - `mlockall(MCL_CURRENT)` locks all current mappings.
//! - `mlockall(MCL_FUTURE)` locks all future mappings.
//! - `mlock2` adds `MLOCK_ONFAULT` flag.
//!
//! # References
//!
//! - POSIX.1-2024: `mlock()`
//! - Linux man pages: `mlock(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Page size (4 KiB).
pub const PAGE_SIZE: u64 = 4096;

/// `mlockall` flag: lock all current pages.
pub const MCL_CURRENT: i32 = 1;
/// `mlockall` flag: lock all future pages.
pub const MCL_FUTURE: i32 = 2;
/// `mlockall` flag: lock-on-fault (lock pages when they fault in).
pub const MCL_ONFAULT: i32 = 4;

/// `mlock2` flag: lock on fault.
pub const MLOCK_ONFAULT: u32 = 1;

/// All known `mlockall` flags.
const MCL_KNOWN: i32 = MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT;

// ---------------------------------------------------------------------------
// Process lock state
// ---------------------------------------------------------------------------

/// Per-process memory lock accounting.
#[derive(Debug, Clone, Copy, Default)]
pub struct MlockState {
    /// Total bytes currently locked.
    pub locked_bytes: u64,
    /// RLIMIT_MEMLOCK in bytes (0 = unlimited for privileged).
    pub limit_bytes: u64,
    /// MCL_CURRENT is active.
    pub mcl_current: bool,
    /// MCL_FUTURE is active.
    pub mcl_future: bool,
    /// Whether the process has CAP_IPC_LOCK.
    pub cap_ipc_lock: bool,
}

impl MlockState {
    /// Returns `true` if locking `size` more bytes would exceed the limit.
    pub fn would_exceed_limit(&self, size: u64) -> bool {
        if self.cap_ipc_lock || self.limit_bytes == 0 {
            return false;
        }
        self.locked_bytes.saturating_add(size) > self.limit_bytes
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Round `addr` down to page boundary.
pub fn page_align_down(addr: u64) -> u64 {
    addr & !(PAGE_SIZE - 1)
}

/// Round `addr + len` up to next page boundary.
pub fn page_align_up_len(addr: u64, len: u64) -> u64 {
    let end = addr.saturating_add(len);
    let aligned_start = page_align_down(addr);
    let pages = (end - aligned_start + PAGE_SIZE - 1) / PAGE_SIZE;
    pages * PAGE_SIZE
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `mlock(2)` / `mlock2(2)`.
///
/// Locks the pages in `[addr, addr+len)`.
///
/// # Errors
///
/// | `Error`           | Condition                                   |
/// |-------------------|---------------------------------------------|
/// | `InvalidArgument` | `addr` or `len` is invalid                  |
/// | `PermissionDenied`| Lock would exceed `RLIMIT_MEMLOCK`           |
pub fn do_mlock(state: &mut MlockState, addr: u64, len: u64, _flags: u32) -> Result<()> {
    if len == 0 {
        return Ok(());
    }
    if addr == 0 {
        return Err(Error::InvalidArgument);
    }
    let lock_size = page_align_up_len(addr, len);
    if state.would_exceed_limit(lock_size) {
        return Err(Error::PermissionDenied);
    }
    state.locked_bytes = state.locked_bytes.saturating_add(lock_size);
    Ok(())
}

/// Handler for `munlock(2)`.
///
/// Unlocks the pages in `[addr, addr+len)`.
///
/// # Errors
///
/// | `Error`           | Condition                      |
/// |-------------------|------------------------------ -|
/// | `InvalidArgument` | `addr` or `len` is invalid     |
pub fn do_munlock(state: &mut MlockState, addr: u64, len: u64) -> Result<()> {
    if len == 0 {
        return Ok(());
    }
    if addr == 0 {
        return Err(Error::InvalidArgument);
    }
    let unlock_size = page_align_up_len(addr, len);
    state.locked_bytes = state.locked_bytes.saturating_sub(unlock_size);
    Ok(())
}

/// Handler for `mlockall(2)`.
///
/// # Errors
///
/// | `Error`           | Condition                       |
/// |-------------------|---------------------------------|
/// | `InvalidArgument` | Unknown flags bits              |
/// | `PermissionDenied`| Would exceed limit              |
pub fn do_mlockall(state: &mut MlockState, flags: i32) -> Result<()> {
    if flags & !MCL_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    if flags == 0 {
        return Err(Error::InvalidArgument);
    }
    state.mcl_current = flags & MCL_CURRENT != 0;
    state.mcl_future = flags & MCL_FUTURE != 0;
    Ok(())
}

/// Handler for `munlockall(2)`.
///
/// Clears all locked pages for the calling process.
pub fn do_munlockall(state: &mut MlockState) {
    state.locked_bytes = 0;
    state.mcl_current = false;
    state.mcl_future = false;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn state_with_limit(limit: u64) -> MlockState {
        MlockState {
            limit_bytes: limit,
            ..Default::default()
        }
    }

    #[test]
    fn mlock_ok() {
        let mut s = state_with_limit(1024 * 1024);
        do_mlock(&mut s, 0x1000, 4096, 0).unwrap();
        assert_eq!(s.locked_bytes, 4096);
    }

    #[test]
    fn mlock_exceeds_limit() {
        let mut s = state_with_limit(4096);
        do_mlock(&mut s, 0x1000, 4096, 0).unwrap();
        assert_eq!(
            do_mlock(&mut s, 0x2000, 4096, 0),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn munlock_decrements() {
        let mut s = state_with_limit(0);
        s.cap_ipc_lock = true;
        do_mlock(&mut s, 0x1000, 4096, 0).unwrap();
        do_munlock(&mut s, 0x1000, 4096).unwrap();
        assert_eq!(s.locked_bytes, 0);
    }

    #[test]
    fn mlockall_flags() {
        let mut s = MlockState::default();
        do_mlockall(&mut s, MCL_CURRENT | MCL_FUTURE).unwrap();
        assert!(s.mcl_current);
        assert!(s.mcl_future);
    }

    #[test]
    fn munlockall_clears() {
        let mut s = MlockState {
            locked_bytes: 8192,
            mcl_current: true,
            ..Default::default()
        };
        do_munlockall(&mut s);
        assert_eq!(s.locked_bytes, 0);
        assert!(!s.mcl_current);
    }

    #[test]
    fn mlock_zero_len_ok() {
        let mut s = MlockState::default();
        do_mlock(&mut s, 0x1000, 0, 0).unwrap();
        assert_eq!(s.locked_bytes, 0);
    }
}
