// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `nfsservctl(2)` syscall dispatch layer.
//!
//! This syscall was used to control the in-kernel NFS server.  It was removed
//! in Linux 3.1 (replaced by a userspace NFS daemon using `/proc/fs/nfsd/`).
//!
//! ONCRIX provides a stub that unconditionally returns `ENOSYS` (not
//! implemented), matching the behaviour of modern Linux kernels.
//!
//! # Syscall signature (historical)
//!
//! ```text
//! long nfsservctl(int cmd, struct nfsctl_arg *argp,
//!                 union nfsctl_res *resp);
//! ```
//!
//! # References
//!
//! - Linux: removed in v3.1 (`fs/nfsctl.c`)
//! - `nfsservctl(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Command constants (historical, for documentation only)
// ---------------------------------------------------------------------------

/// Export a filesystem.
pub const NFSCTL_SVC: i32 = 0;
/// Add a client.
pub const NFSCTL_ADDCLIENT: i32 = 1;
/// Delete a client.
pub const NFSCTL_DELCLIENT: i32 = 2;
/// Export a path.
pub const NFSCTL_EXPORT: i32 = 3;
/// Unexport a path.
pub const NFSCTL_UNEXPORT: i32 = 4;
/// Get file handle for path.
pub const NFSCTL_GETFH: i32 = 5;

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle `nfsservctl(2)`.
///
/// Always returns `NotImplemented` — this syscall was removed in Linux 3.1.
/// Modern NFS server management is done via `/proc/fs/nfsd/`.
///
/// # Errors
///
/// - [`Error::NotImplemented`] — always; syscall is removed.
pub fn sys_nfsservctl(_cmd: i32, _argp: u64, _resp: u64) -> Result<i64> {
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_nfsservctl_call(cmd: i32, argp: u64, resp: u64) -> Result<i64> {
    sys_nfsservctl(cmd, argp, resp)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn always_returns_not_implemented() {
        assert_eq!(
            sys_nfsservctl(NFSCTL_SVC, 0, 0).unwrap_err(),
            Error::NotImplemented
        );
    }

    #[test]
    fn any_cmd_returns_not_implemented() {
        assert_eq!(
            sys_nfsservctl(99, 0x1000, 0x2000).unwrap_err(),
            Error::NotImplemented
        );
    }
}
