// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `shmctl(2)` syscall dispatch layer.
//!
//! Performs control operations on System V shared memory segments.
//!
//! # Syscall signature
//!
//! ```text
//! int shmctl(int shmid, int cmd, struct shmid_ds *buf);
//! ```
//!
//! # POSIX reference
//!
//! - POSIX.1-2024: `shmctl()` in `<sys/shm.h>`
//! - `.TheOpenGroup/susv5-html/functions/shmctl.html`
//!
//! # References
//!
//! - Linux: `ipc/shm.c` (`sys_shmctl`)
//! - `shmctl(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Command constants
// ---------------------------------------------------------------------------

/// Remove the shared memory segment.
pub const IPC_RMID: i32 = 0;
/// Set fields from `shmid_ds`.
pub const IPC_SET: i32 = 1;
/// Copy status into `shmid_ds`.
pub const IPC_STAT: i32 = 2;
/// Linux: get info about all shared memory segments.
pub const IPC_INFO: i32 = 3;
/// Lock the segment in memory (Linux).
pub const SHM_LOCK: i32 = 11;
/// Unlock the segment (Linux).
pub const SHM_UNLOCK: i32 = 12;
/// Linux: copy-on-write status info.
pub const SHM_STAT: i32 = 13;
/// Linux: get extended info.
pub const SHM_INFO: i32 = 14;

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Returns `true` if `cmd` is a recognised shmctl command.
pub fn is_valid_cmd(cmd: i32) -> bool {
    matches!(
        cmd,
        IPC_RMID | IPC_SET | IPC_STAT | IPC_INFO | SHM_LOCK | SHM_UNLOCK | SHM_STAT | SHM_INFO
    )
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `shmctl(2)`.
///
/// `buf_ptr` is a user-space pointer to `struct shmid_ds`; may be null for
/// commands that do not use it (e.g., `IPC_RMID`).
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — `shmid < 0` or unknown `cmd`.
/// - [`Error::NotFound`] — segment does not exist.
/// - [`Error::PermissionDenied`] — insufficient privilege.
/// - [`Error::NotImplemented`] — stub.
pub fn sys_shmctl(shmid: i32, cmd: i32, buf_ptr: u64) -> Result<i64> {
    if shmid < 0 {
        return Err(Error::InvalidArgument);
    }
    if !is_valid_cmd(cmd) {
        return Err(Error::InvalidArgument);
    }
    // IPC_SET and IPC_STAT require a non-null buf pointer.
    if (cmd == IPC_SET || cmd == IPC_STAT || cmd == SHM_STAT) && buf_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    let _ = (shmid, cmd, buf_ptr);
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_shmctl_call(shmid: i32, cmd: i32, buf_ptr: u64) -> Result<i64> {
    sys_shmctl(shmid, cmd, buf_ptr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_shmid_rejected() {
        assert_eq!(
            sys_shmctl(-1, IPC_STAT, 0x1000).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn unknown_cmd_rejected() {
        assert_eq!(sys_shmctl(0, 99, 0).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn ipc_stat_null_buf_rejected() {
        assert_eq!(
            sys_shmctl(0, IPC_STAT, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn ipc_rmid_reaches_stub() {
        let r = sys_shmctl(0, IPC_RMID, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn shm_lock_reaches_stub() {
        let r = sys_shmctl(1, SHM_LOCK, 0);
        assert_eq!(r.unwrap_err(), Error::NotImplemented);
    }
}
