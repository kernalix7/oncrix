// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `acct(2)` syscall handler — enable or disable process accounting.
//!
//! When accounting is enabled, the kernel writes a `struct acct` record to the
//! accounting file for each process that terminates.  Passing a null pointer
//! disables accounting.  Requires `CAP_SYS_PACCT`.
//!
//! # Syscall signature
//!
//! ```text
//! int acct(const char *filename);
//! ```
//!
//! # POSIX / Linux compliance
//!
//! The `acct` function is defined in XSI (X/Open System Interfaces) but is
//! optional.  Requires `CAP_SYS_PACCT` privilege.
//!
//! # References
//!
//! - Linux: `kernel/acct.c`, `include/uapi/linux/acct.h`
//! - `acct(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Capability required to enable/disable process accounting.
pub const CAP_SYS_PACCT: u32 = 20;

/// Account record version written by Linux.
pub const ACCT_VERSION: u8 = 3;

/// Flag: the process was a 64-bit process.
pub const AFORK: u8 = 0x01;
/// Flag: process dumped core.
pub const ACORE: u8 = 0x08;
/// Flag: process exceeded cpu rlimit.
pub const AXSIG: u8 = 0x10;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Minimal representation of an accounting record header.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct AcctRecord {
    /// Version of the record format.
    pub ac_version: u8,
    /// Flags (AFORK, ACORE, AXSIG, …).
    pub ac_flag: u8,
    /// User accounting name (truncated to 16 bytes).
    pub ac_comm: [u8; 16],
    /// Elapsed real time (encoded).
    pub ac_etime: u32,
    /// User CPU time used (encoded).
    pub ac_utime: u32,
    /// System CPU time used (encoded).
    pub ac_stime: u32,
    /// PID of the process.
    pub ac_pid: u32,
    /// UID of the process.
    pub ac_uid: u32,
    /// GID of the process.
    pub ac_gid: u32,
    /// Exit status.
    pub ac_exitcode: u32,
}

impl AcctRecord {
    /// Create a new zeroed accounting record.
    pub const fn new() -> Self {
        Self {
            ac_version: ACCT_VERSION,
            ac_flag: 0,
            ac_comm: [0u8; 16],
            ac_etime: 0,
            ac_utime: 0,
            ac_stime: 0,
            ac_pid: 0,
            ac_uid: 0,
            ac_gid: 0,
            ac_exitcode: 0,
        }
    }
}

/// Configuration for enabling process accounting.
#[derive(Debug, Clone, Copy)]
pub struct AcctConfig {
    /// User-space pointer to the accounting file path.
    pub path_ptr: u64,
}

impl AcctConfig {
    /// Create a new configuration.
    pub const fn new(path_ptr: u64) -> Self {
        Self { path_ptr }
    }

    /// Return whether this request disables accounting.
    pub fn is_disable(&self) -> bool {
        self.path_ptr == 0
    }
}

impl Default for AcctConfig {
    fn default() -> Self {
        Self::new(0)
    }
}

/// Current state of the accounting subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountingState {
    /// Accounting is currently disabled.
    Disabled,
    /// Accounting is enabled and writing to the given file path (pointer).
    Enabled,
}

impl Default for AccountingState {
    fn default() -> Self {
        Self::Disabled
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `acct(2)` syscall.
///
/// Passing `filename = 0` (null pointer) disables accounting.
/// Passing a non-null pointer enables accounting to that file.
///
/// # Errors
///
/// - [`Error::PermissionDenied`] — caller lacks `CAP_SYS_PACCT`.
/// - [`Error::NotImplemented`] — accounting subsystem not yet wired.
pub fn sys_acct(filename: u64, caps: u64) -> Result<i64> {
    if caps & (1u64 << CAP_SYS_PACCT) == 0 {
        return Err(Error::PermissionDenied);
    }
    if filename == 0 {
        do_acct_disable()
    } else {
        do_acct_enable(filename)
    }
}

fn do_acct_disable() -> Result<i64> {
    // TODO: Close the accounting file and stop writing records.
    Err(Error::NotImplemented)
}

fn do_acct_enable(path_ptr: u64) -> Result<i64> {
    let _ = path_ptr;
    // TODO: Open the file and start writing acct records.
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_acct_syscall(filename: u64, caps: u64) -> Result<i64> {
    sys_acct(filename, caps)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_cap_rejected() {
        assert_eq!(sys_acct(0, 0).unwrap_err(), Error::PermissionDenied);
    }

    #[test]
    fn with_cap_null_filename_reaches_subsystem() {
        let caps = 1u64 << CAP_SYS_PACCT;
        // Should fail with NotImplemented (not PermissionDenied).
        assert_eq!(sys_acct(0, caps).unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn with_cap_valid_filename_reaches_subsystem() {
        let caps = 1u64 << CAP_SYS_PACCT;
        assert_eq!(sys_acct(0x1000, caps).unwrap_err(), Error::NotImplemented);
    }

    #[test]
    fn acct_record_version() {
        let rec = AcctRecord::new();
        assert_eq!(rec.ac_version, ACCT_VERSION);
    }

    #[test]
    fn accounting_state_default_disabled() {
        let state = AccountingState::default();
        assert_eq!(state, AccountingState::Disabled);
    }

    #[test]
    fn acct_record_default() {
        let rec = AcctRecord::default();
        assert_eq!(rec.ac_pid, 0);
    }
}
