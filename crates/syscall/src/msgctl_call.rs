// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `msgctl` syscall implementation.
//!
//! Performs control operations on a System V message queue identified
//! by `msqid`. Operations include getting/setting queue attributes,
//! removing the queue, and querying IPC limits.
//!
//! POSIX Reference: susv5 functions/msgctl.html
//! POSIX.1-2024 mandatory.

use oncrix_lib::{Error, Result};

/// `msgctl` commands.
pub struct MsgctlCmd;

impl MsgctlCmd {
    /// Get the msqid_ds structure for the queue.
    pub const IPC_STAT: i32 = 2;
    /// Set attributes from a msqid_ds structure.
    pub const IPC_SET: i32 = 1;
    /// Remove the message queue.
    pub const IPC_RMID: i32 = 0;
    /// Get IPC limits (kernel-level info).
    pub const IPC_INFO: i32 = 3;
    /// Get message queue specific info.
    pub const MSG_INFO: i32 = 12;
    /// Get msqid_ds by position in the kernel table.
    pub const MSG_STAT: i32 = 11;
    /// Extended stat with 64-bit timestamps.
    pub const MSG_STAT_ANY: i32 = 13;
}

/// IPC permission structure for message queues.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IpcPerm {
    /// Key supplied to msgget.
    pub key: i32,
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Creator UID.
    pub cuid: u32,
    /// Creator GID.
    pub cgid: u32,
    /// Access mode bits.
    pub mode: u16,
    /// Sequence number.
    pub seq: u16,
    /// Padding.
    pub _pad: [u32; 2],
}

impl IpcPerm {
    /// Create a new permission structure.
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

    /// Check if the mode grants write permission for a given uid/gid.
    pub fn allows_write(&self, uid: u32, gid: u32) -> bool {
        if uid == self.uid {
            return (self.mode & 0o200) != 0;
        }
        if gid == self.gid {
            return (self.mode & 0o020) != 0;
        }
        (self.mode & 0o002) != 0
    }
}

/// Message queue status structure (mirrors `struct msqid_ds`).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MsqidDs {
    /// IPC permission structure.
    pub msg_perm: IpcPerm,
    /// Time of last msgsnd.
    pub msg_stime: u64,
    /// Time of last msgrcv.
    pub msg_rtime: u64,
    /// Time of last msgctl change.
    pub msg_ctime: u64,
    /// Number of bytes in the queue.
    pub msg_cbytes: u64,
    /// Number of messages in the queue.
    pub msg_qnum: u64,
    /// Maximum bytes allowed in the queue.
    pub msg_qbytes: u64,
    /// PID of last msgsnd.
    pub msg_lspid: i32,
    /// PID of last msgrcv.
    pub msg_lrpid: i32,
    /// Padding.
    pub _pad: [u32; 4],
}

impl MsqidDs {
    /// Create a new MsqidDs with given permissions and byte limit.
    pub const fn new(perm: IpcPerm, qbytes: u64) -> Self {
        Self {
            msg_perm: perm,
            msg_stime: 0,
            msg_rtime: 0,
            msg_ctime: 0,
            msg_cbytes: 0,
            msg_qnum: 0,
            msg_qbytes: qbytes,
            msg_lspid: 0,
            msg_lrpid: 0,
            _pad: [0; 4],
        }
    }

    /// Check if there is room for `bytes` more bytes in the queue.
    pub fn has_capacity(&self, bytes: u64) -> bool {
        self.msg_cbytes.saturating_add(bytes) <= self.msg_qbytes
    }
}

/// Arguments for the `msgctl` syscall.
#[derive(Debug)]
pub struct MsgctlArgs {
    /// Message queue identifier.
    pub msqid: i32,
    /// Command (MsgctlCmd constants).
    pub cmd: i32,
    /// Pointer to user-space `MsqidDs` buffer (NULL for IPC_RMID).
    pub buf_ptr: usize,
}

/// Validate `msgctl` arguments.
pub fn validate_msgctl_args(args: &MsgctlArgs) -> Result<()> {
    if args.msqid < 0 {
        return Err(Error::InvalidArgument);
    }
    let known_cmds = [
        MsgctlCmd::IPC_STAT,
        MsgctlCmd::IPC_SET,
        MsgctlCmd::IPC_RMID,
        MsgctlCmd::IPC_INFO,
        MsgctlCmd::MSG_INFO,
        MsgctlCmd::MSG_STAT,
        MsgctlCmd::MSG_STAT_ANY,
    ];
    if !known_cmds.contains(&args.cmd) {
        return Err(Error::InvalidArgument);
    }
    // buf_ptr must be non-null for IPC_STAT and IPC_SET.
    if matches!(args.cmd, MsgctlCmd::IPC_STAT | MsgctlCmd::IPC_SET) && args.buf_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Handle the `msgctl` syscall.
///
/// Dispatches to the appropriate operation:
/// - IPC_STAT: copies queue status to user space.
/// - IPC_SET: reads new settings from user space and applies them.
/// - IPC_RMID: removes the queue and wakes all waiting processes.
///
/// Returns 0 on success, or an error.
pub fn sys_msgctl(args: &MsgctlArgs) -> Result<i64> {
    validate_msgctl_args(args)?;
    match args.cmd {
        MsgctlCmd::IPC_RMID => {
            // Stub: real implementation destroys the queue.
            Err(Error::NotImplemented)
        }
        MsgctlCmd::IPC_STAT => {
            // Stub: real implementation copies MsqidDs to user space.
            Err(Error::NotImplemented)
        }
        MsgctlCmd::IPC_SET => {
            // Stub: real implementation reads MsqidDs from user space.
            Err(Error::NotImplemented)
        }
        _ => Err(Error::NotImplemented),
    }
}

/// Check whether `new_qbytes` is within the system limit (MSGMNB).
///
/// Only root (CAP_SYS_RESOURCE) can raise qbytes above the system default.
pub fn validate_qbytes(new_qbytes: u64, system_limit: u64) -> Result<()> {
    if new_qbytes > system_limit {
        return Err(Error::PermissionDenied);
    }
    Ok(())
}
