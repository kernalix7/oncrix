// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `quotactl_fd` syscall implementation.
//!
//! `quotactl_fd` is a modern variant of `quotactl` that operates on an
//! open file descriptor instead of a pathname, avoiding TOCTOU races.
//! Introduced in Linux 5.14.
//!
//! Linux-specific. Not in POSIX.

use oncrix_lib::{Error, Result};

/// Quota type: user quota.
pub const USRQUOTA: u32 = 0;
/// Quota type: group quota.
pub const GRPQUOTA: u32 = 1;
/// Quota type: project quota.
pub const PRJQUOTA: u32 = 2;

/// quotactl_fd sub-commands.
pub struct QuotaCmd;

impl QuotaCmd {
    /// Get disk quota for a user/group/project.
    pub const Q_GETQUOTA: u32 = 0x0300;
    /// Set disk quota for a user/group/project.
    pub const Q_SETQUOTA: u32 = 0x0301;
    /// Get quota information for the filesystem.
    pub const Q_GETINFO: u32 = 0x0305;
    /// Set quota information for the filesystem.
    pub const Q_SETINFO: u32 = 0x0306;
    /// Get the quota format for the filesystem.
    pub const Q_GETFMT: u32 = 0x0307;
    /// Sync quota to disk.
    pub const Q_SYNC: u32 = 0x0600;
}

/// Disk quota structure reported to user space.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DqBlk {
    /// Block hard limit (512-byte units).
    pub dqb_bhardlimit: u64,
    /// Block soft limit.
    pub dqb_bsoftlimit: u64,
    /// Current usage in 512-byte units.
    pub dqb_curspace: u64,
    /// Inode hard limit.
    pub dqb_ihardlimit: u64,
    /// Inode soft limit.
    pub dqb_isoftlimit: u64,
    /// Current inode count.
    pub dqb_curinodes: u64,
    /// Block soft limit grace time.
    pub dqb_btime: u64,
    /// Inode soft limit grace time.
    pub dqb_itime: u64,
    /// Bitmask of valid fields.
    pub dqb_valid: u32,
    /// Padding to align to 8 bytes.
    pub _pad: u32,
}

impl DqBlk {
    /// Create an empty DqBlk (all zeros).
    pub const fn new() -> Self {
        Self {
            dqb_bhardlimit: 0,
            dqb_bsoftlimit: 0,
            dqb_curspace: 0,
            dqb_ihardlimit: 0,
            dqb_isoftlimit: 0,
            dqb_curinodes: 0,
            dqb_btime: 0,
            dqb_itime: 0,
            dqb_valid: 0,
            _pad: 0,
        }
    }

    /// Check if the block hard limit is set.
    pub fn has_block_hard_limit(&self) -> bool {
        self.dqb_bhardlimit > 0
    }

    /// Check if the inode hard limit is set.
    pub fn has_inode_hard_limit(&self) -> bool {
        self.dqb_ihardlimit > 0
    }
}

/// Arguments for the `quotactl_fd` syscall.
#[derive(Debug)]
pub struct QuotactlFdArgs {
    /// Open file descriptor on the filesystem to operate on.
    pub fd: i32,
    /// Quota sub-command (QuotaCmd constants).
    pub cmd: u32,
    /// ID of the user/group/project to query (ignored for Q_GETINFO etc.).
    pub id: u32,
    /// Pointer to user-space data buffer (DqBlk or similar).
    pub addr: usize,
}

/// Validate quotactl_fd arguments.
///
/// Checks the fd is non-negative, the command is known, and the quota
/// type embedded in the command is one of USRQUOTA / GRPQUOTA / PRJQUOTA.
pub fn validate_quotactl_fd_args(args: &QuotactlFdArgs) -> Result<()> {
    if args.fd < 0 {
        return Err(Error::InvalidArgument);
    }
    let qtype = args.cmd & 0xFF;
    if qtype > PRJQUOTA {
        return Err(Error::InvalidArgument);
    }
    let subcmd = args.cmd & 0xFF00;
    let known_subcmds = [
        QuotaCmd::Q_GETQUOTA,
        QuotaCmd::Q_SETQUOTA,
        QuotaCmd::Q_GETINFO,
        QuotaCmd::Q_SETINFO,
        QuotaCmd::Q_GETFMT,
        QuotaCmd::Q_SYNC,
    ];
    if !known_subcmds.contains(&subcmd) {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Handle the `quotactl_fd` syscall.
///
/// Operates on the filesystem identified by `fd` instead of a path,
/// avoiding TOCTOU vulnerabilities present in the original `quotactl`.
///
/// Returns 0 on success, or an error.
pub fn sys_quotactl_fd(args: &QuotactlFdArgs) -> Result<i64> {
    validate_quotactl_fd_args(args)?;
    // Stub: real implementation would:
    // 1. Look up the vfsmount from fd.
    // 2. Dispatch to the filesystem's quota operations based on subcmd.
    // 3. For Q_GETQUOTA/Q_SETQUOTA: copy_from/to_user the DqBlk.
    // 4. For Q_GETINFO/Q_SETINFO: copy fs-level quota metadata.
    // 5. Check CAP_SYS_ADMIN for write commands.
    Err(Error::NotImplemented)
}

/// Build a combined quotactl command word from a sub-command and quota type.
///
/// The resulting value is suitable for the `cmd` field of `QuotactlFdArgs`.
pub fn make_quota_cmd(subcmd: u32, qtype: u32) -> u32 {
    (subcmd & 0xFF00) | (qtype & 0xFF)
}

/// Check whether a quota command is read-only (does not require CAP_SYS_ADMIN).
pub fn is_read_only_cmd(cmd: u32) -> bool {
    let subcmd = cmd & 0xFF00;
    matches!(
        subcmd,
        QuotaCmd::Q_GETQUOTA | QuotaCmd::Q_GETINFO | QuotaCmd::Q_GETFMT
    )
}
