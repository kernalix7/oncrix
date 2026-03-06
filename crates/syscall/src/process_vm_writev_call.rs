// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `process_vm_writev(2)` syscall handler — write into another process's address space.
//!
//! `process_vm_writev` transfers data from the local process into the address
//! space of a remote process using scatter-gather I/O.  It is the write
//! counterpart of `process_vm_readv(2)`.
//!
//! # POSIX reference
//!
//! Linux-specific: `process_vm_writev(2)` man page (added in Linux 3.2).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of local `iovec` entries.
pub const PROCESS_VM_WRITEV_MAX_IOV: usize = 1024;

/// Maximum number of remote `iovec` entries.
pub const PROCESS_VM_WRITEV_MAX_RIOV: usize = 1024;

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

/// Transfer direction for diagnostic purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmTransferDir {
    /// Reading from the remote process.
    Read,
    /// Writing into the remote process.
    Write,
}

impl Default for VmTransferDir {
    fn default() -> Self {
        Self::Write
    }
}

/// Validated `process_vm_writev` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessVmWritevRequest {
    /// PID of the target process.
    pub pid: i32,
    /// User-space pointer to the local `iovec` array (source buffers).
    pub lvec: usize,
    /// Number of local `iovec` entries.
    pub liovcnt: usize,
    /// User-space pointer to the remote `iovec` array (destination regions).
    pub rvec: usize,
    /// Number of remote `iovec` entries.
    pub riovcnt: usize,
    /// Reserved flags (must be 0).
    pub flags: u64,
}

impl ProcessVmWritevRequest {
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

    /// Transfer direction (always `Write` for this syscall).
    pub fn direction(&self) -> VmTransferDir {
        VmTransferDir::Write
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `process_vm_writev(2)`.
///
/// Validates all arguments and returns a structured request.  The caller must
/// have `PTRACE_MODE_ATTACH_REALCREDS` permission on the target process.
///
/// # Arguments
///
/// - `pid`     — target process PID (must be > 0)
/// - `lvec`    — local iovec array pointer (source data)
/// - `liovcnt` — local iovec count
/// - `rvec`    — remote iovec array pointer (destination regions)
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
pub fn do_process_vm_writev(
    pid: i32,
    lvec: usize,
    liovcnt: usize,
    rvec: usize,
    riovcnt: usize,
    flags: u64,
) -> Result<ProcessVmWritevRequest> {
    if pid <= 0 {
        return Err(Error::InvalidArgument);
    }
    if lvec == 0 || rvec == 0 {
        return Err(Error::InvalidArgument);
    }
    if liovcnt == 0 || liovcnt > PROCESS_VM_WRITEV_MAX_IOV {
        return Err(Error::InvalidArgument);
    }
    if riovcnt == 0 || riovcnt > PROCESS_VM_WRITEV_MAX_RIOV {
        return Err(Error::InvalidArgument);
    }
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(ProcessVmWritevRequest::new(
        pid, lvec, liovcnt, rvec, riovcnt, flags,
    ))
}

/// Return `true` if both local and remote iovec arrays appear valid.
pub fn has_valid_vectors(req: &ProcessVmWritevRequest) -> bool {
    req.lvec != 0 && req.rvec != 0 && req.liovcnt > 0 && req.riovcnt > 0
}

/// Calculate the total number of bytes that would be written
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
        let req = do_process_vm_writev(42, 0x1000, 4, 0x2000, 2, 0).unwrap();
        assert_eq!(req.pid, 42);
        assert_eq!(req.riovcnt, 2);
        assert_eq!(req.direction(), VmTransferDir::Write);
        assert!(has_valid_vectors(&req));
    }

    #[test]
    fn pid_zero_rejected() {
        assert_eq!(
            do_process_vm_writev(0, 0x1000, 1, 0x2000, 1, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn null_lvec_rejected() {
        assert_eq!(
            do_process_vm_writev(1, 0, 1, 0x2000, 1, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn null_rvec_rejected() {
        assert_eq!(
            do_process_vm_writev(1, 0x1000, 1, 0, 1, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn nonzero_flags_rejected() {
        assert_eq!(
            do_process_vm_writev(1, 0x1000, 1, 0x2000, 1, 0xFF),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn oversized_riovcnt_rejected() {
        assert_eq!(
            do_process_vm_writev(1, 0x1000, 1, 0x2000, PROCESS_VM_WRITEV_MAX_RIOV + 1, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn total_bytes_calculation() {
        let iov = [IoVec::new(0x1000, 16), IoVec::new(0x2000, 32)];
        assert_eq!(total_bytes(&iov), 48);
    }
}
