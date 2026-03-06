// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `semop` and `semtimedop` syscall implementations.
//!
//! `semop` performs a set of atomic operations on a System V semaphore
//! array. `semtimedop` extends `semop` with a timeout.
//!
//! POSIX Reference: susv5 functions/semop.html
//! POSIX.1-2024 — semop is required; semtimedop is Linux-specific.

use oncrix_lib::{Error, Result};

/// Maximum operations per semop call.
pub const SEMOPM: u32 = 500;

/// Maximum value of a single semaphore (SEMVMX).
pub const SEMVMX: u16 = 32767;

/// Semaphore operation structure (matches `struct sembuf` ABI).
///
/// Each entry in the operations array describes one atomic adjustment.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SemBuf {
    /// Semaphore index within the array.
    pub sem_num: u16,
    /// Operation value: positive (V), negative (P), or zero (wait-for-zero).
    pub sem_op: i16,
    /// Flags: IPC_NOWAIT and/or SEM_UNDO.
    pub sem_flg: i16,
}

impl SemBuf {
    /// Create a P (acquire) operation on semaphore `num`.
    pub const fn acquire(num: u16, flags: i16) -> Self {
        Self {
            sem_num: num,
            sem_op: -1,
            sem_flg: flags,
        }
    }

    /// Create a V (release) operation on semaphore `num`.
    pub const fn release(num: u16, flags: i16) -> Self {
        Self {
            sem_num: num,
            sem_op: 1,
            sem_flg: flags,
        }
    }

    /// Create a wait-for-zero operation on semaphore `num`.
    pub const fn wait_zero(num: u16, flags: i16) -> Self {
        Self {
            sem_num: num,
            sem_op: 0,
            sem_flg: flags,
        }
    }

    /// Return true if IPC_NOWAIT is set.
    pub fn is_nowait(&self) -> bool {
        (self.sem_flg & IPC_NOWAIT) != 0
    }

    /// Return true if SEM_UNDO is requested.
    pub fn is_undo(&self) -> bool {
        (self.sem_flg & SEM_UNDO) != 0
    }
}

/// IPC_NOWAIT flag: return EAGAIN instead of blocking.
pub const IPC_NOWAIT: i16 = 0x0800;
/// SEM_UNDO flag: undo the operation on process exit.
pub const SEM_UNDO: i16 = 0x1000;

/// Timespec for semtimedop timeout.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct TimeSpec {
    /// Seconds.
    pub tv_sec: i64,
    /// Nanoseconds (0..999_999_999).
    pub tv_nsec: i64,
}

impl TimeSpec {
    /// Check that the nanoseconds field is valid.
    pub fn is_valid(&self) -> bool {
        self.tv_nsec >= 0 && self.tv_nsec < 1_000_000_000 && self.tv_sec >= 0
    }
}

/// Arguments for the `semop` syscall.
#[derive(Debug)]
pub struct SemopArgs {
    /// System V semaphore identifier.
    pub semid: i32,
    /// Pointer to the user-space `SemBuf` array.
    pub sops_ptr: usize,
    /// Number of operations in the array.
    pub nsops: u32,
}

/// Arguments for the `semtimedop` syscall.
#[derive(Debug)]
pub struct SemtimedopArgs {
    /// System V semaphore identifier.
    pub semid: i32,
    /// Pointer to the user-space `SemBuf` array.
    pub sops_ptr: usize,
    /// Number of operations in the array.
    pub nsops: u32,
    /// Pointer to timeout (NULL = block forever).
    pub timeout_ptr: usize,
}

/// Validate `semop` arguments.
///
/// Checks that semid is non-negative, sops_ptr is non-null, and nsops
/// is within the SEMOPM limit.
pub fn validate_semop_args(semid: i32, sops_ptr: usize, nsops: u32) -> Result<()> {
    if semid < 0 {
        return Err(Error::InvalidArgument);
    }
    if sops_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if nsops == 0 || nsops > SEMOPM {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Handle the `semop` syscall.
///
/// Performs `nsops` atomic semaphore operations on the array identified
/// by `semid`. Blocks until all operations can complete unless IPC_NOWAIT
/// is set in any operation's flags.
///
/// Returns 0 on success, or an error.
pub fn sys_semop(args: &SemopArgs) -> Result<i64> {
    validate_semop_args(args.semid, args.sops_ptr, args.nsops)?;
    // Stub: real implementation would:
    // 1. Look up the semaphore array by semid.
    // 2. Check IPC_R permission.
    // 3. copy_from_user the SemBuf array.
    // 4. Perform operations atomically under the semaphore lock.
    // 5. Block if any operation cannot complete.
    // 6. Return 0 on success.
    Err(Error::NotImplemented)
}

/// Handle the `semtimedop` syscall.
///
/// Same as `semop` but blocks for at most the duration given by `timeout`.
/// If NULL, blocks indefinitely.
///
/// Returns 0 on success, or `Err(WouldBlock)` on timeout.
pub fn sys_semtimedop(args: &SemtimedopArgs) -> Result<i64> {
    validate_semop_args(args.semid, args.sops_ptr, args.nsops)?;
    // Stub: real implementation extends semop with timed wait.
    Err(Error::NotImplemented)
}

/// Check whether a semaphore operation value would overflow SEMVMX.
///
/// Returns `Err(InvalidArgument)` if adding `delta` to `current_val`
/// would exceed SEMVMX or go below 0.
pub fn check_semaphore_bounds(current_val: u16, delta: i16) -> Result<u16> {
    let new_val = (current_val as i32) + (delta as i32);
    if new_val < 0 || new_val > (SEMVMX as i32) {
        return Err(Error::InvalidArgument);
    }
    Ok(new_val as u16)
}
