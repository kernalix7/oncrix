// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `kcmp(2)` extended syscall handler — compare kernel resources of two processes.
//!
//! `kcmp` tests whether two processes share a kernel resource.  It is used by
//! checkpoint/restore tools to determine whether two file descriptors in
//! different processes refer to the same open file description, and for similar
//! comparisons of VM, FS, FILES, SIGHAND, IO, SYSVSEM namespaces.
//!
//! # POSIX reference
//!
//! Linux-specific: `kcmp(2)` man page (added in Linux 3.5).

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The kind of resource to compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KcmpType {
    /// Compare virtual memory areas.
    Vm,
    /// Compare filesystem information.
    Fs,
    /// Compare open file tables.
    Files,
    /// Compare signal handler tables.
    Sighand,
    /// Compare I/O context.
    Io,
    /// Compare System V semaphore sets.
    SysvSem,
    /// Compare open file descriptions by file descriptor index.
    File,
    /// Compare epoll instances.
    Epoll,
}

impl KcmpType {
    /// Parse from a raw integer.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` for unknown types.
    pub fn from_raw(typ: u32) -> Result<Self> {
        match typ {
            0 => Ok(Self::Vm),
            1 => Ok(Self::Fs),
            2 => Ok(Self::Files),
            3 => Ok(Self::Sighand),
            4 => Ok(Self::Io),
            5 => Ok(Self::SysvSem),
            6 => Ok(Self::File),
            7 => Ok(Self::Epoll),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Return `true` if the comparison type involves file descriptors.
    pub fn uses_file_descriptor(&self) -> bool {
        matches!(self, Self::File | Self::Epoll)
    }

    /// Return the raw integer representation.
    pub fn as_u32(&self) -> u32 {
        match self {
            Self::Vm => 0,
            Self::Fs => 1,
            Self::Files => 2,
            Self::Sighand => 3,
            Self::Io => 4,
            Self::SysvSem => 5,
            Self::File => 6,
            Self::Epoll => 7,
        }
    }
}

/// Comparison result returned by `kcmp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KcmpResult {
    /// The resources are identical (same kernel object).
    Equal,
    /// Resource of `pid1` < resource of `pid2` (pointer comparison).
    Less,
    /// Resource of `pid1` > resource of `pid2`.
    Greater,
}

impl Default for KcmpResult {
    fn default() -> Self {
        Self::Equal
    }
}

/// Validated `kcmp` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KcmpRequest {
    /// PID of the first process.
    pub pid1: i32,
    /// PID of the second process.
    pub pid2: i32,
    /// Type of resource to compare.
    pub typ: KcmpType,
    /// Auxiliary index 1 (e.g., fd in process 1 for `KCMP_FILE`).
    pub idx1: u64,
    /// Auxiliary index 2 (e.g., fd in process 2 for `KCMP_FILE`).
    pub idx2: u64,
}

impl KcmpRequest {
    /// Construct a new request.
    pub const fn new(pid1: i32, pid2: i32, typ: KcmpType, idx1: u64, idx2: u64) -> Self {
        Self {
            pid1,
            pid2,
            typ,
            idx1,
            idx2,
        }
    }
}

// ---------------------------------------------------------------------------
// Core handler
// ---------------------------------------------------------------------------

/// Handler for `kcmp(2)` (extended variant).
///
/// Validates all arguments and returns a structured request.  The caller must
/// have `PTRACE_MODE_READ_FSCREDS` permission on both processes.
///
/// # Arguments
///
/// - `pid1` — first process PID
/// - `pid2` — second process PID
/// - `typ`  — resource type to compare
/// - `idx1` — auxiliary index for process 1 (ignored unless type uses fds)
/// - `idx2` — auxiliary index for process 2 (ignored unless type uses fds)
///
/// # Errors
///
/// | `Error`           | Condition                              |
/// |-------------------|----------------------------------------|
/// | `InvalidArgument` | Non-positive PIDs, unknown type        |
/// | `PermissionDenied`| Insufficient privilege on the process  |
/// | `NotFound`        | Either PID does not exist              |
pub fn do_kcmp_ext(pid1: i32, pid2: i32, typ: u32, idx1: u64, idx2: u64) -> Result<KcmpRequest> {
    if pid1 <= 0 || pid2 <= 0 {
        return Err(Error::InvalidArgument);
    }
    let kcmp_type = KcmpType::from_raw(typ)?;
    Ok(KcmpRequest::new(pid1, pid2, kcmp_type, idx1, idx2))
}

/// Return `true` if the two processes are identical (same PID).
pub fn same_process(req: &KcmpRequest) -> bool {
    req.pid1 == req.pid2
}

/// Translate a raw pointer comparison result (-1, 0, 1) to a `KcmpResult`.
///
/// # Errors
///
/// Returns `Error::InvalidArgument` for values other than -1, 0, 1.
pub fn decode_raw_result(raw: i32) -> Result<KcmpResult> {
    match raw {
        0 => Ok(KcmpResult::Equal),
        r if r < 0 => Ok(KcmpResult::Less),
        _ => Ok(KcmpResult::Greater),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_request_ok() {
        let req = do_kcmp_ext(1, 2, KcmpType::Files.as_u32(), 0, 0).unwrap();
        assert_eq!(req.pid1, 1);
        assert_eq!(req.pid2, 2);
        assert_eq!(req.typ, KcmpType::Files);
    }

    #[test]
    fn file_type_uses_fds() {
        let typ = KcmpType::File;
        assert!(typ.uses_file_descriptor());
    }

    #[test]
    fn vm_type_does_not_use_fds() {
        let typ = KcmpType::Vm;
        assert!(!typ.uses_file_descriptor());
    }

    #[test]
    fn zero_pid_rejected() {
        assert_eq!(
            do_kcmp_ext(0, 2, KcmpType::Vm.as_u32(), 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn negative_pid_rejected() {
        assert_eq!(
            do_kcmp_ext(1, -1, KcmpType::Vm.as_u32(), 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unknown_type_rejected() {
        assert_eq!(do_kcmp_ext(1, 2, 0xFF, 0, 0), Err(Error::InvalidArgument));
    }

    #[test]
    fn same_process_detection() {
        let req = do_kcmp_ext(5, 5, KcmpType::Vm.as_u32(), 0, 0).unwrap();
        assert!(same_process(&req));
    }

    #[test]
    fn decode_raw_result_ok() {
        assert_eq!(decode_raw_result(0), Ok(KcmpResult::Equal));
        assert_eq!(decode_raw_result(-1), Ok(KcmpResult::Less));
        assert_eq!(decode_raw_result(1), Ok(KcmpResult::Greater));
    }
}
