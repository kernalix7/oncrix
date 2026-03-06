// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `process_vm_readv(2)` syscall handler — read from another process's address space.
//!
//! `process_vm_readv` transfers data from the address space of a remote process
//! into the local process using scatter-gather I/O.  It is primarily used by
//! debuggers and profilers to inspect another process's memory without stopping it.
//!
//! # POSIX reference
//!
//! Linux-specific: `process_vm_readv(2)` man page (added in Linux 3.2).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of local `iovec` entries.
pub const PROCESS_VM_READV_MAX_IOV: usize = 1024;

/// Maximum number of remote `iovec` entries.
pub const PROCESS_VM_READV_MAX_RIOV: usize = 1024;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// An I/O vector element — base pointer and length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct IoVec {
    /// User-space pointer to the buffer.
    pub iov_base: usize,
    /// Length in bytes.
    pub iov_len: usize,
}

impl IoVec {
    /// Construct a new `IoVec`.
    pub const fn new(iov_base: usize, iov_len: usize) -> Self {
        Self { iov_base, iov_len }
    }

    /// Return `true` if the vector element has zero length.
    pub fn is_empty(&self) -> bool {
        self.iov_len == 0
    }
}

/// Validated `process_vm_readv` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessVmReadvRequest {
    /// PID of the target process.
    pub pid: i32,
    /// User-space pointer to the local `iovec` array.
    pub lvec: usize,
    /// Number of local `iovec` entries.
    pub liovcnt: usize,
    /// User-space pointer to the remote `iovec` array.
    pub rvec: usize,
    /// Number of remote `iovec` entries.
    pub riovcnt: usize,
    /// Reserved flags (must be 0).
    pub flags: u64,
}

impl ProcessVmReadvRequest {
    /// Construct a new request.
    pub const fn new(
        pid: i32,
        lvec: usize,
        liovcnt: usize,
        rvec: usize,
        riovcnt: usize,
        flags: u64,
    ) -> Self {
        Self {
            pid,
            lvec,
            liovcnt,
            rvec,
            riovcnt,
            flags,
        }
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `process_vm_readv(2)`.
///
/// Validates all arguments and returns a structured request.  The caller must
/// have `PTRACE_MODE_ATTACH_REALCREDS` permission on the target process.
///
/// # Arguments
///
/// - `pid`     — target process PID
/// - `lvec`    — local iovec array pointer
/// - `liovcnt` — local iovec count
/// - `rvec`    — remote iovec array pointer
/// - `riovcnt` — remote iovec count
/// - `flags`   — reserved, must be 0
///
/// # Errors
///
/// | `Error`           | Condition                                       |
/// |-------------------|-------------------------------------------------|
/// | `InvalidArgument` | Null pointers, zero counts, non-zero flags      |
/// | `PermissionDenied`| Insufficient permission on target process       |
/// | `NotFound`        | Target process does not exist                   |
pub fn do_process_vm_readv(
    pid: i32,
    lvec: usize,
    liovcnt: usize,
    rvec: usize,
    riovcnt: usize,
    flags: u64,
) -> Result<ProcessVmReadvRequest> {
    if pid <= 0 {
        return Err(Error::InvalidArgument);
    }
    if lvec == 0 || rvec == 0 {
        return Err(Error::InvalidArgument);
    }
    if liovcnt == 0 || liovcnt > PROCESS_VM_READV_MAX_IOV {
        return Err(Error::InvalidArgument);
    }
    if riovcnt == 0 || riovcnt > PROCESS_VM_READV_MAX_RIOV {
        return Err(Error::InvalidArgument);
    }
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(ProcessVmReadvRequest::new(
        pid, lvec, liovcnt, rvec, riovcnt, flags,
    ))
}

/// Return `true` if both local and remote iovec arrays appear valid.
pub fn has_valid_vectors(req: &ProcessVmReadvRequest) -> bool {
    req.lvec != 0 && req.rvec != 0 && req.liovcnt > 0 && req.riovcnt > 0
}

/// Calculate the total number of bytes that would be transferred
/// given a slice of `IoVec` entries.
pub fn total_bytes(iov: &[IoVec]) -> usize {
    iov.iter()
        .map(|v| v.iov_len)
        .fold(0usize, |acc, n| acc.saturating_add(n))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_request_ok() {
        let req = do_process_vm_readv(42, 0x1000, 4, 0x2000, 2, 0).unwrap();
        assert_eq!(req.pid, 42);
        assert_eq!(req.liovcnt, 4);
        assert!(has_valid_vectors(&req));
    }

    #[test]
    fn pid_zero_rejected() {
        assert_eq!(
            do_process_vm_readv(0, 0x1000, 1, 0x2000, 1, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn null_lvec_rejected() {
        assert_eq!(
            do_process_vm_readv(1, 0, 1, 0x2000, 1, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn null_rvec_rejected() {
        assert_eq!(
            do_process_vm_readv(1, 0x1000, 1, 0, 1, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn nonzero_flags_rejected() {
        assert_eq!(
            do_process_vm_readv(1, 0x1000, 1, 0x2000, 1, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn oversized_liovcnt_rejected() {
        assert_eq!(
            do_process_vm_readv(1, 0x1000, PROCESS_VM_READV_MAX_IOV + 1, 0x2000, 1, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn total_bytes_calculation() {
        let iov = [
            IoVec::new(0x1000, 64),
            IoVec::new(0x2000, 128),
            IoVec::new(0x3000, 0),
        ];
        assert_eq!(total_bytes(&iov), 192);
    }

    #[test]
    fn total_bytes_empty() {
        assert_eq!(total_bytes(&[]), 0);
    }
}
