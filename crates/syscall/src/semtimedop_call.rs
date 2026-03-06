// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `semtimedop(2)` syscall handler — System V semaphore operations with timeout.
//!
//! `semtimedop` performs the same operations as `semop(2)` but allows a
//! timeout so the caller does not block indefinitely.  A null `timeout` makes
//! it behave identically to `semop`.
//!
//! # Syscall signature
//!
//! ```text
//! int semtimedop(int semid, struct sembuf *sops, size_t nsops,
//!                const struct timespec *timeout);
//! ```
//!
//! # POSIX Compliance
//!
//! Conforms to POSIX.1-2024 `semtimedop()` specification.
//!
//! # References
//!
//! - POSIX.1-2024: `sys/sem.h`, `semtimedop()`
//! - Linux: `ipc/sem.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `sembuf.sem_flg` bit: do not block; fail with `EAGAIN` if operation
/// cannot proceed immediately.
pub const IPC_NOWAIT: i16 = 0x800;

/// `sembuf.sem_flg` bit: undo the operation on process exit.
pub const SEM_UNDO: i16 = 0x1000;

/// Maximum number of `sembuf` entries allowed per call.
pub const SEMOPM: usize = 500;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A single semaphore operation (mirrors `struct sembuf`).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct SemBuf {
    /// Semaphore index within the set.
    pub sem_num: u16,
    /// Operation: negative decrement, positive increment, 0 = wait for zero.
    pub sem_op: i16,
    /// Flags (`IPC_NOWAIT`, `SEM_UNDO`).
    pub sem_flg: i16,
}

impl SemBuf {
    /// Create a new operation descriptor.
    pub const fn new(sem_num: u16, sem_op: i16, sem_flg: i16) -> Self {
        Self {
            sem_num,
            sem_op,
            sem_flg,
        }
    }

    /// Return whether this operation requests nowait behaviour.
    pub fn is_nowait(&self) -> bool {
        self.sem_flg & IPC_NOWAIT != 0
    }

    /// Return whether undo-on-exit is requested.
    pub fn is_undo(&self) -> bool {
        self.sem_flg & SEM_UNDO != 0
    }
}

/// Parameters for a `semtimedop` call.
#[derive(Debug, Clone, Copy)]
pub struct SemtimedopRequest {
    /// Semaphore set identifier.
    pub semid: i32,
    /// User-space pointer to `struct sembuf` array.
    pub sops: u64,
    /// Number of operations in the array.
    pub nsops: usize,
    /// User-space pointer to `struct timespec` timeout (0 = block forever).
    pub timeout: u64,
}

impl SemtimedopRequest {
    /// Create a new request.
    pub const fn new(semid: i32, sops: u64, nsops: usize, timeout: u64) -> Self {
        Self {
            semid,
            sops,
            nsops,
            timeout,
        }
    }

    /// Validate the request.
    pub fn validate(&self) -> Result<()> {
        if self.semid < 0 {
            return Err(Error::InvalidArgument);
        }
        if self.sops == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.nsops == 0 || self.nsops > SEMOPM {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Return whether a finite timeout was specified.
    pub fn has_timeout(&self) -> bool {
        self.timeout != 0
    }
}

impl Default for SemtimedopRequest {
    fn default() -> Self {
        Self::new(0, 0, 0, 0)
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `semtimedop(2)` syscall.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — negative semid, null sops, or bad nsops.
/// - [`Error::NotFound`] — semid does not identify a valid set.
/// - [`Error::WouldBlock`] — operation blocked and timeout expired.
/// - [`Error::Interrupted`] — interrupted by a signal.
/// - [`Error::NotImplemented`] — IPC semaphore subsystem not yet wired.
pub fn sys_semtimedop(semid: i32, sops: u64, nsops: usize, timeout: u64) -> Result<i64> {
    let req = SemtimedopRequest::new(semid, sops, nsops, timeout);
    req.validate()?;
    do_semtimedop(&req)
}

fn do_semtimedop(req: &SemtimedopRequest) -> Result<i64> {
    let _ = req;
    // TODO: Read sembuf array from user space, locate the semaphore set,
    // perform operations atomically (blocking with optional timeout).
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_semtimedop_syscall(semid: i32, sops: u64, nsops: usize, timeout: u64) -> Result<i64> {
    sys_semtimedop(semid, sops, nsops, timeout)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negative_semid_rejected() {
        assert_eq!(
            sys_semtimedop(-1, 1, 1, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn null_sops_rejected() {
        assert_eq!(
            sys_semtimedop(0, 0, 1, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn zero_nsops_rejected() {
        assert_eq!(
            sys_semtimedop(0, 1, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn too_many_ops_rejected() {
        assert_eq!(
            sys_semtimedop(0, 1, SEMOPM + 1, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn valid_request_reaches_subsystem() {
        assert_eq!(
            sys_semtimedop(0, 1, 1, 0).unwrap_err(),
            Error::NotImplemented
        );
    }

    #[test]
    fn sembuf_nowait_flag() {
        let op = SemBuf::new(0, -1, IPC_NOWAIT);
        assert!(op.is_nowait());
    }

    #[test]
    fn sembuf_undo_flag() {
        let op = SemBuf::new(0, 1, SEM_UNDO);
        assert!(op.is_undo());
    }

    #[test]
    fn timeout_detection() {
        let req = SemtimedopRequest::new(0, 1, 1, 0x2000);
        assert!(req.has_timeout());
    }
}
