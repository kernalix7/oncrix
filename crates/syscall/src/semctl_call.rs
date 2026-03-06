// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `semctl` syscall implementation.
//!
//! Performs control operations on a System V semaphore set identified
//! by `semid`. Operations include getting/setting individual semaphore
//! values, removing the semaphore set, and managing permissions.
//!
//! POSIX Reference: susv5 functions/semctl.html
//! POSIX.1-2024 mandatory.

use oncrix_lib::{Error, Result};

/// Maximum value of a semaphore (SEMVMX).
pub const SEMVMX: u16 = 32767;

/// `semctl` commands.
pub struct SemctlCmd;

impl SemctlCmd {
    /// Get the value of a single semaphore.
    pub const GETVAL: i32 = 12;
    /// Set the value of a single semaphore.
    pub const SETVAL: i32 = 16;
    /// Get all semaphore values.
    pub const GETALL: i32 = 13;
    /// Set all semaphore values.
    pub const SETALL: i32 = 17;
    /// Get the number of processes waiting for the semaphore to increase.
    pub const GETNCNT: i32 = 14;
    /// Get the number of processes waiting for the semaphore to reach zero.
    pub const GETZCNT: i32 = 15;
    /// Get the PID of the process that last called semop on this semaphore.
    pub const GETPID: i32 = 11;
    /// Get the IPC status structure (ipc_perm + semaphore count).
    pub const IPC_STAT: i32 = 2;
    /// Set the IPC status structure.
    pub const IPC_SET: i32 = 1;
    /// Remove the semaphore set.
    pub const IPC_RMID: i32 = 0;
    /// Get the IPC info structure (semaphore limits).
    pub const IPC_INFO: i32 = 3;
    /// Get semaphore-specific info.
    pub const SEM_INFO: i32 = 19;
    /// Get semaphore status.
    pub const SEM_STAT: i32 = 18;
}

/// IPC permission structure embedded in `ipc_perm`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IpcPerm {
    /// Key supplied to semget.
    pub key: i32,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Creator UID.
    pub cuid: u32,
    /// Creator GID.
    pub cgid: u32,
    /// Access mode.
    pub mode: u16,
    /// Sequence number.
    pub seq: u16,
    /// Padding.
    pub _pad: [u32; 2],
}

impl IpcPerm {
    /// Create an IpcPerm entry for a new semaphore set.
    pub const fn new(key: i32, uid: u32, gid: u32, mode: u16) -> Self {
        Self {
            key,
            uid,
            gid,
            cuid: uid,
            cgid: gid,
            mode,
            seq: 0,
            _pad: [0, 0],
        }
    }

    /// Check if the mode allows read access for the given uid/gid.
    pub fn allows_read(&self, uid: u32, gid: u32) -> bool {
        if uid == self.uid {
            return (self.mode & 0o400) != 0;
        }
        if gid == self.gid {
            return (self.mode & 0o040) != 0;
        }
        (self.mode & 0o004) != 0
    }
}

/// The union argument to `semctl` — only one field is relevant per command.
#[derive(Clone, Copy)]
pub union SemctlUnion {
    /// Used for SETVAL: new value for a single semaphore.
    pub val: i32,
    /// Used for IPC_STAT / IPC_SET: pointer to semid_ds structure.
    pub buf_ptr: usize,
    /// Used for GETALL / SETALL: pointer to array of u16 values.
    pub array_ptr: usize,
}

/// Arguments for the `semctl` syscall.
#[derive(Debug)]
pub struct SemctlArgs {
    /// Semaphore set identifier.
    pub semid: i32,
    /// Index of the semaphore within the set (for single-semaphore ops).
    pub semnum: i32,
    /// Command (SemctlCmd constants).
    pub cmd: i32,
    /// Union argument (interpreted based on cmd).
    pub arg_val: i64,
}

/// Validate `semctl` arguments.
///
/// Checks that semid and semnum are non-negative and that the command
/// is a known value.
pub fn validate_semctl_args(args: &SemctlArgs) -> Result<()> {
    if args.semid < 0 {
        return Err(Error::InvalidArgument);
    }
    if args.semnum < 0 {
        return Err(Error::InvalidArgument);
    }
    let known_cmds = [
        SemctlCmd::GETVAL,
        SemctlCmd::SETVAL,
        SemctlCmd::GETALL,
        SemctlCmd::SETALL,
        SemctlCmd::GETNCNT,
        SemctlCmd::GETZCNT,
        SemctlCmd::GETPID,
        SemctlCmd::IPC_STAT,
        SemctlCmd::IPC_SET,
        SemctlCmd::IPC_RMID,
        SemctlCmd::IPC_INFO,
        SemctlCmd::SEM_INFO,
        SemctlCmd::SEM_STAT,
    ];
    if !known_cmds.contains(&args.cmd) {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Handle the `semctl` syscall.
///
/// Dispatches to the appropriate operation based on `cmd`:
/// - Read operations (GETVAL, GETNCNT, etc.) return the value directly.
/// - Modification operations (SETVAL, IPC_RMID) require write permission.
/// - IPC_STAT / IPC_SET copy the semid_ds structure to/from user space.
///
/// Returns a non-negative value on success (or 0), or an error.
pub fn sys_semctl(args: &SemctlArgs) -> Result<i64> {
    validate_semctl_args(args)?;
    match args.cmd {
        SemctlCmd::IPC_RMID => sys_semctl_rmid(args.semid),
        SemctlCmd::GETVAL => sys_semctl_getval(args.semid, args.semnum),
        SemctlCmd::SETVAL => sys_semctl_setval(args.semid, args.semnum, args.arg_val as i32),
        _ => Err(Error::NotImplemented),
    }
}

/// Remove the semaphore set identified by `semid`.
fn sys_semctl_rmid(semid: i32) -> Result<i64> {
    // Stub: real implementation removes the IPC object and wakes waiters.
    let _ = semid;
    Err(Error::NotImplemented)
}

/// Return the value of semaphore `semnum` in set `semid`.
fn sys_semctl_getval(semid: i32, semnum: i32) -> Result<i64> {
    // Stub: real implementation reads the semaphore array.
    let _ = (semid, semnum);
    Err(Error::NotImplemented)
}

/// Set the value of semaphore `semnum` in set `semid` to `val`.
fn sys_semctl_setval(semid: i32, semnum: i32, val: i32) -> Result<i64> {
    if val < 0 || (val as u32) > (SEMVMX as u32) {
        return Err(Error::InvalidArgument);
    }
    // Stub: real implementation updates the semaphore and wakes waiters.
    let _ = (semid, semnum);
    Err(Error::NotImplemented)
}
