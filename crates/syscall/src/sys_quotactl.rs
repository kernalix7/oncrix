// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `quotactl(2)` extended syscall handler — full quota state management.
//!
//! This module provides the full in-kernel quota state machine for
//! `quotactl(2)`.  It implements the Linux quota subsystem's command handlers
//! (`Q_QUOTAON`, `Q_QUOTAOFF`, `Q_GETQUOTA`, `Q_SETQUOTA`, `Q_SYNC`,
//! `Q_GETINFO`, `Q_SETINFO`, `Q_GETFMT`) for all three quota types
//! (user, group, project).
//!
//! # XFS quota extension
//!
//! XFS uses its own `Q_X*` command set (e.g., `Q_XQUOTAON`, `Q_XGETQUOTA`).
//! These are dispatched to a separate XFS path.
//!
//! # Permission model
//!
//! Administrative commands (`Q_QUOTAON`, `Q_QUOTAOFF`, `Q_SETQUOTA`,
//! `Q_SETINFO`) require `CAP_SYS_ADMIN`.  Read-only queries may be performed
//! by any process for its own identity.
//!
//! # References
//!
//! - Linux: `fs/quota/quota.c`, `include/uapi/linux/quota.h`
//! - man: `quotactl(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Quota types
// ---------------------------------------------------------------------------

/// User-quota type.
pub const USRQUOTA: i32 = 0;
/// Group-quota type.
pub const GRPQUOTA: i32 = 1;
/// Project-quota type (XFS / ext4 project IDs).
pub const PRJQUOTA: i32 = 2;

// ---------------------------------------------------------------------------
// Base command codes
// ---------------------------------------------------------------------------

/// Enable quota accounting/enforcement for a filesystem.
pub const Q_QUOTAON: i32 = 0x0100;
/// Disable quota accounting for a filesystem.
pub const Q_QUOTAOFF: i32 = 0x0200;
/// Get quota limits and usage for a specific ID.
pub const Q_GETQUOTA: i32 = 0x0300;
/// Set quota limits for a specific ID.
pub const Q_SETQUOTA: i32 = 0x0400;
/// Flush dirty quota blocks to disk.
pub const Q_SYNC: i32 = 0x0600;
/// Get filesystem quota information (grace times etc.).
pub const Q_GETINFO: i32 = 0x0700;
/// Set filesystem quota information.
pub const Q_SETINFO: i32 = 0x0800;
/// Get the quota format currently in use.
pub const Q_GETFMT: i32 = 0x0900;

// ---------------------------------------------------------------------------
// XFS quota command codes
// ---------------------------------------------------------------------------

/// XFS: enable quota accounting.
pub const Q_XQUOTAON: i32 = 0x5100;
/// XFS: disable quota accounting.
pub const Q_XQUOTAOFF: i32 = 0x5200;
/// XFS: get quota limits for an ID.
pub const Q_XGETQUOTA: i32 = 0x5300;
/// XFS: set quota limits for an ID.
pub const Q_XSETQLIM: i32 = 0x5400;
/// XFS: get aggregate quota statistics.
pub const Q_XGETQSTAT: i32 = 0x5500;
/// XFS: free unused disk space used by the quota subsystem.
pub const Q_XQUOTARM: i32 = 0x5600;
/// XFS: flush quota to disk.
pub const Q_XQUOTASYNC: i32 = 0x5700;

// ---------------------------------------------------------------------------
// Quota format identifiers
// ---------------------------------------------------------------------------

/// Original quota format (v1).
pub const QFMT_VFS_OLD: u32 = 1;
/// Standard VFS quota format v2.
pub const QFMT_VFS_V0: u32 = 2;
/// OCFS2 / XFS quota format.
pub const QFMT_OCFS2: u32 = 3;
/// VFS v1 format (used in Linux 2.4+).
pub const QFMT_VFS_V1: u32 = 4;

// ---------------------------------------------------------------------------
// Quota limit and usage structures
// ---------------------------------------------------------------------------

/// Per-ID quota limits and current usage.
///
/// Matches `struct dqblk` from `<sys/quota.h>` / `include/uapi/linux/quota.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Dqblk {
    /// Absolute limit on disk blocks allocated (in 1 KiB units).
    pub dqb_bhardlimit: u64,
    /// Preferred limit on disk blocks (soft limit, in 1 KiB units).
    pub dqb_bsoftlimit: u64,
    /// Current disk blocks used (in 1 KiB units).
    pub dqb_curspace: u64,
    /// Absolute limit on number of allocated inodes.
    pub dqb_ihardlimit: u64,
    /// Preferred inode limit (soft limit).
    pub dqb_isoftlimit: u64,
    /// Current number of inodes used.
    pub dqb_curinodes: u64,
    /// Time limit for excessive disk use (Unix timestamp).
    pub dqb_btime: u64,
    /// Time limit for excessive inode use (Unix timestamp).
    pub dqb_itime: u64,
    /// Bitmask of fields that are valid (QIF_* flags).
    pub dqb_valid: u32,
    /// Reserved padding.
    pub _pad: u32,
}

/// `dqb_valid` bits — which `Dqblk` fields the kernel should honour.
pub const QIF_BLIMITS: u32 = 1 << 0;
/// Inode limits field is valid.
pub const QIF_ILIMITS: u32 = 1 << 1;
/// Block time field is valid.
pub const QIF_BTIME: u32 = 1 << 2;
/// Inode time field is valid.
pub const QIF_ITIME: u32 = 1 << 3;
/// Current usage fields are valid.
pub const QIF_USAGE: u32 = 1 << 4;
/// All fields are valid.
pub const QIF_ALL: u32 = QIF_BLIMITS | QIF_ILIMITS | QIF_BTIME | QIF_ITIME | QIF_USAGE;

/// Filesystem-level quota information (grace periods, etc.).
///
/// Matches `struct dqinfo` from `include/uapi/linux/quota.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Dqinfo {
    /// Default block grace period in seconds.
    pub dqi_bgrace: u64,
    /// Default inode grace period in seconds.
    pub dqi_igrace: u64,
    /// Bitmask of fields that are valid.
    pub dqi_flags: u32,
    /// Reserved.
    pub dqi_valid: u32,
}

// ---------------------------------------------------------------------------
// Per-filesystem quota state
// ---------------------------------------------------------------------------

/// Maximum number of filesystems with active quota.
pub const MAX_QUOTA_FS: usize = 16;

/// Maximum number of per-ID quota entries per quota type per filesystem.
pub const MAX_QUOTA_ENTRIES: usize = 64;

/// Per-ID quota entry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QuotaEntry {
    /// Subject ID (UID, GID, or project ID).
    pub id: u32,
    /// Whether this slot is occupied.
    pub in_use: bool,
    /// Quota limits and usage.
    pub dqblk: Dqblk,
}

/// Per-quota-type state for a single filesystem.
#[derive(Debug, Clone, Copy)]
pub struct QuotaTypeState {
    /// Whether quota is enabled for this type.
    pub enabled: bool,
    /// Active quota format.
    pub format: u32,
    /// Filesystem-level info (grace times).
    pub info: Dqinfo,
    /// Per-ID entries.
    pub entries: [QuotaEntry; MAX_QUOTA_ENTRIES],
    /// Number of active entries.
    pub entry_count: usize,
}

impl Default for QuotaTypeState {
    fn default() -> Self {
        Self {
            enabled: false,
            format: 0,
            info: Dqinfo::default(),
            entries: [QuotaEntry {
                id: 0,
                in_use: false,
                dqblk: Dqblk {
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
                },
            }; MAX_QUOTA_ENTRIES],
            entry_count: 0,
        }
    }
}

impl QuotaTypeState {
    /// Find a quota entry by subject ID.
    pub fn find_entry(&self, id: u32) -> Option<usize> {
        self.entries.iter().position(|e| e.in_use && e.id == id)
    }

    /// Find or allocate a quota entry for `id`.
    pub fn find_or_alloc_entry(&mut self, id: u32) -> Result<usize> {
        if let Some(idx) = self.find_entry(id) {
            return Ok(idx);
        }
        let idx = self
            .entries
            .iter()
            .position(|e| !e.in_use)
            .ok_or(Error::OutOfMemory)?;
        self.entries[idx].in_use = true;
        self.entries[idx].id = id;
        self.entries[idx].dqblk = Dqblk::default();
        self.entry_count += 1;
        Ok(idx)
    }
}

/// Quota state for a single mounted filesystem.
#[derive(Debug, Clone, Copy)]
pub struct FsQuotaState {
    /// Whether this slot is active.
    pub in_use: bool,
    /// Synthetic device ID identifying this filesystem.
    pub dev_id: u32,
    /// Per-quota-type state: index 0 = user, 1 = group, 2 = project.
    pub types: [QuotaTypeState; 3],
}

impl Default for FsQuotaState {
    fn default() -> Self {
        Self {
            in_use: false,
            dev_id: 0,
            types: [
                QuotaTypeState::default(),
                QuotaTypeState::default(),
                QuotaTypeState::default(),
            ],
        }
    }
}

/// Global quota state table.
pub struct QuotaState {
    filesystems: [FsQuotaState; MAX_QUOTA_FS],
    count: usize,
}

impl QuotaState {
    /// Create an empty quota state table.
    pub const fn new() -> Self {
        Self {
            filesystems: [FsQuotaState {
                in_use: false,
                dev_id: 0,
                types: [QuotaTypeState {
                    enabled: false,
                    format: 0,
                    info: Dqinfo {
                        dqi_bgrace: 0,
                        dqi_igrace: 0,
                        dqi_flags: 0,
                        dqi_valid: 0,
                    },
                    entries: [QuotaEntry {
                        id: 0,
                        in_use: false,
                        dqblk: Dqblk {
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
                        },
                    }; MAX_QUOTA_ENTRIES],
                    entry_count: 0,
                }; 3],
            }; MAX_QUOTA_FS],
            count: 0,
        }
    }

    /// Find a filesystem slot by device ID, or allocate a new one.
    fn find_or_alloc_fs(&mut self, dev_id: u32) -> Result<usize> {
        if let Some(idx) = self
            .filesystems
            .iter()
            .position(|f| f.in_use && f.dev_id == dev_id)
        {
            return Ok(idx);
        }
        let idx = self
            .filesystems
            .iter()
            .position(|f| !f.in_use)
            .ok_or(Error::OutOfMemory)?;
        self.filesystems[idx].in_use = true;
        self.filesystems[idx].dev_id = dev_id;
        self.count += 1;
        Ok(idx)
    }

    /// Find an existing filesystem slot.
    fn find_fs(&self, dev_id: u32) -> Option<usize> {
        self.filesystems
            .iter()
            .position(|f| f.in_use && f.dev_id == dev_id)
    }

    /// Return the number of active filesystem quota entries.
    pub const fn count(&self) -> usize {
        self.count
    }
}

// ---------------------------------------------------------------------------
// Quota type index conversion
// ---------------------------------------------------------------------------

fn quota_type_index(quota_type: i32) -> Result<usize> {
    match quota_type {
        USRQUOTA => Ok(0),
        GRPQUOTA => Ok(1),
        PRJQUOTA => Ok(2),
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Command handlers
// ---------------------------------------------------------------------------

/// Enable quota accounting for `dev_id` and `quota_type`.
///
/// Requires `CAP_SYS_ADMIN`.
///
/// # Arguments
///
/// * `state`      — Global quota state table.
/// * `dev_id`     — Device ID identifying the filesystem.
/// * `quota_type` — `USRQUOTA`, `GRPQUOTA`, or `PRJQUOTA`.
/// * `format`     — Quota format to enable (e.g. `QFMT_VFS_V1`).
/// * `has_admin`  — Whether caller holds `CAP_SYS_ADMIN`.
///
/// # Errors
///
/// - [`Error::PermissionDenied`] — `has_admin` is false.
/// - [`Error::InvalidArgument`]  — Unknown quota type.
/// - [`Error::Busy`]             — Quota already enabled.
/// - [`Error::OutOfMemory`]      — No free filesystem quota slots.
pub fn do_q_quotaon(
    state: &mut QuotaState,
    dev_id: u32,
    quota_type: i32,
    format: u32,
    has_admin: bool,
) -> Result<()> {
    if !has_admin {
        return Err(Error::PermissionDenied);
    }
    let tidx = quota_type_index(quota_type)?;
    let fidx = state.find_or_alloc_fs(dev_id)?;
    let qt = &mut state.filesystems[fidx].types[tidx];
    if qt.enabled {
        return Err(Error::Busy);
    }
    qt.enabled = true;
    qt.format = format;
    Ok(())
}

/// Disable quota accounting for `dev_id` and `quota_type`.
///
/// Requires `CAP_SYS_ADMIN`.
///
/// # Errors
///
/// - [`Error::PermissionDenied`] — `has_admin` is false.
/// - [`Error::NotFound`]         — Filesystem not found or quota not enabled.
pub fn do_q_quotaoff(
    state: &mut QuotaState,
    dev_id: u32,
    quota_type: i32,
    has_admin: bool,
) -> Result<()> {
    if !has_admin {
        return Err(Error::PermissionDenied);
    }
    let tidx = quota_type_index(quota_type)?;
    let fidx = state.find_fs(dev_id).ok_or(Error::NotFound)?;
    let qt = &mut state.filesystems[fidx].types[tidx];
    if !qt.enabled {
        return Err(Error::NotFound);
    }
    qt.enabled = false;
    Ok(())
}

/// Get quota limits and usage for subject `id`.
///
/// # Errors
///
/// - [`Error::NotFound`]        — Quota not enabled or ID has no entry.
/// - [`Error::InvalidArgument`] — Unknown quota type.
pub fn do_q_getquota(state: &QuotaState, dev_id: u32, quota_type: i32, id: u32) -> Result<Dqblk> {
    let tidx = quota_type_index(quota_type)?;
    let fidx = state.find_fs(dev_id).ok_or(Error::NotFound)?;
    let qt = &state.filesystems[fidx].types[tidx];
    if !qt.enabled {
        return Err(Error::NotFound);
    }
    let eidx = qt.find_entry(id).ok_or(Error::NotFound)?;
    Ok(qt.entries[eidx].dqblk)
}

/// Set quota limits for subject `id`.
///
/// Requires `CAP_SYS_ADMIN`.
///
/// # Errors
///
/// - [`Error::PermissionDenied`] — `has_admin` is false.
/// - [`Error::NotFound`]         — Quota not enabled on this filesystem.
/// - [`Error::OutOfMemory`]      — Too many quota entries.
pub fn do_q_setquota(
    state: &mut QuotaState,
    dev_id: u32,
    quota_type: i32,
    id: u32,
    dqblk: &Dqblk,
    has_admin: bool,
) -> Result<()> {
    if !has_admin {
        return Err(Error::PermissionDenied);
    }
    let tidx = quota_type_index(quota_type)?;
    let fidx = state.find_fs(dev_id).ok_or(Error::NotFound)?;
    let qt = &mut state.filesystems[fidx].types[tidx];
    if !qt.enabled {
        return Err(Error::NotFound);
    }
    let eidx = qt.find_or_alloc_entry(id)?;
    qt.entries[eidx].dqblk = *dqblk;
    Ok(())
}

/// Flush quota changes for `dev_id` to stable storage (no-op in stub).
///
/// Requires `CAP_SYS_ADMIN`.
///
/// # Errors
///
/// - [`Error::PermissionDenied`] — `has_admin` is false.
pub fn do_q_sync(state: &QuotaState, dev_id: Option<u32>, has_admin: bool) -> Result<()> {
    if !has_admin {
        return Err(Error::PermissionDenied);
    }
    // If dev_id is Some, validate that the filesystem exists.
    if let Some(id) = dev_id {
        if state.find_fs(id).is_none() {
            return Err(Error::NotFound);
        }
    }
    // Stub: nothing to flush.
    Ok(())
}

/// Get filesystem-level quota information (grace periods, flags).
///
/// # Errors
///
/// - [`Error::NotFound`]        — Quota not enabled on this filesystem.
/// - [`Error::InvalidArgument`] — Unknown quota type.
pub fn do_q_getinfo(state: &QuotaState, dev_id: u32, quota_type: i32) -> Result<Dqinfo> {
    let tidx = quota_type_index(quota_type)?;
    let fidx = state.find_fs(dev_id).ok_or(Error::NotFound)?;
    let qt = &state.filesystems[fidx].types[tidx];
    if !qt.enabled {
        return Err(Error::NotFound);
    }
    Ok(qt.info)
}

/// Set filesystem-level quota information.
///
/// Requires `CAP_SYS_ADMIN`.
pub fn do_q_setinfo(
    state: &mut QuotaState,
    dev_id: u32,
    quota_type: i32,
    info: &Dqinfo,
    has_admin: bool,
) -> Result<()> {
    if !has_admin {
        return Err(Error::PermissionDenied);
    }
    let tidx = quota_type_index(quota_type)?;
    let fidx = state.find_fs(dev_id).ok_or(Error::NotFound)?;
    let qt = &mut state.filesystems[fidx].types[tidx];
    if !qt.enabled {
        return Err(Error::NotFound);
    }
    qt.info = *info;
    Ok(())
}

/// Get the quota format currently in use.
///
/// # Errors
///
/// - [`Error::NotFound`]        — Quota not enabled.
/// - [`Error::InvalidArgument`] — Unknown quota type.
pub fn do_q_getfmt(state: &QuotaState, dev_id: u32, quota_type: i32) -> Result<u32> {
    let tidx = quota_type_index(quota_type)?;
    let fidx = state.find_fs(dev_id).ok_or(Error::NotFound)?;
    let qt = &state.filesystems[fidx].types[tidx];
    if !qt.enabled {
        return Err(Error::NotFound);
    }
    Ok(qt.format)
}

// ---------------------------------------------------------------------------
// XFS quota extension (stub)
// ---------------------------------------------------------------------------

/// Handle XFS quota commands.
///
/// XFS uses a different command namespace (`Q_X*`).  This stub validates
/// the command and returns `NotImplemented` for all XFS-specific operations.
///
/// # Errors
///
/// - [`Error::InvalidArgument`]  — Unknown XFS command.
/// - [`Error::NotImplemented`]   — Command is valid but not yet implemented.
pub fn do_xfs_quotactl(cmd: i32, _dev_id: u32, _id: u32, _has_admin: bool) -> Result<()> {
    match cmd {
        Q_XQUOTAON | Q_XQUOTAOFF | Q_XGETQUOTA | Q_XSETQLIM | Q_XGETQSTAT | Q_XQUOTARM
        | Q_XQUOTASYNC => Err(Error::NotImplemented),
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_state(dev: u32, qt: i32, fmt: u32) -> QuotaState {
        let mut s = QuotaState::new();
        do_q_quotaon(&mut s, dev, qt, fmt, true).unwrap();
        s
    }

    #[test]
    fn quotaon_requires_admin() {
        let mut s = QuotaState::new();
        assert_eq!(
            do_q_quotaon(&mut s, 1, USRQUOTA, QFMT_VFS_V1, false),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn quotaon_and_off_roundtrip() {
        let mut s = QuotaState::new();
        do_q_quotaon(&mut s, 1, USRQUOTA, QFMT_VFS_V1, true).unwrap();
        do_q_quotaoff(&mut s, 1, USRQUOTA, true).unwrap();
    }

    #[test]
    fn double_quotaon_returns_busy() {
        let mut s = QuotaState::new();
        do_q_quotaon(&mut s, 1, GRPQUOTA, QFMT_VFS_V1, true).unwrap();
        assert_eq!(
            do_q_quotaon(&mut s, 1, GRPQUOTA, QFMT_VFS_V1, true),
            Err(Error::Busy)
        );
    }

    #[test]
    fn getquota_after_setquota() {
        let mut s = enabled_state(2, USRQUOTA, QFMT_VFS_V1);
        let dqblk = Dqblk {
            dqb_bhardlimit: 1024,
            dqb_bsoftlimit: 512,
            dqb_valid: QIF_BLIMITS,
            ..Dqblk::default()
        };
        do_q_setquota(&mut s, 2, USRQUOTA, 1000, &dqblk, true).unwrap();
        let got = do_q_getquota(&s, 2, USRQUOTA, 1000).unwrap();
        assert_eq!(got.dqb_bhardlimit, 1024);
        assert_eq!(got.dqb_bsoftlimit, 512);
    }

    #[test]
    fn setquota_requires_admin() {
        let mut s = enabled_state(2, USRQUOTA, QFMT_VFS_V1);
        assert_eq!(
            do_q_setquota(&mut s, 2, USRQUOTA, 1000, &Dqblk::default(), false),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn getquota_unknown_id_returns_notfound() {
        let s = enabled_state(2, USRQUOTA, QFMT_VFS_V1);
        assert_eq!(do_q_getquota(&s, 2, USRQUOTA, 9999), Err(Error::NotFound));
    }

    #[test]
    fn getfmt_returns_format() {
        let s = enabled_state(3, GRPQUOTA, QFMT_VFS_V0);
        assert_eq!(do_q_getfmt(&s, 3, GRPQUOTA), Ok(QFMT_VFS_V0));
    }

    #[test]
    fn getinfo_setinfo_roundtrip() {
        let mut s = enabled_state(4, PRJQUOTA, QFMT_VFS_V1);
        let info = Dqinfo {
            dqi_bgrace: 7 * 86400,
            dqi_igrace: 7 * 86400,
            dqi_flags: 0,
            dqi_valid: 0,
        };
        do_q_setinfo(&mut s, 4, PRJQUOTA, &info, true).unwrap();
        let got = do_q_getinfo(&s, 4, PRJQUOTA).unwrap();
        assert_eq!(got.dqi_bgrace, 7 * 86400);
    }

    #[test]
    fn sync_unknown_fs_returns_notfound() {
        let s = QuotaState::new();
        assert_eq!(do_q_sync(&s, Some(99), true), Err(Error::NotFound));
    }

    #[test]
    fn sync_null_fs_syncs_all() {
        let s = QuotaState::new();
        assert_eq!(do_q_sync(&s, None, true), Ok(()));
    }

    #[test]
    fn invalid_quota_type_rejected() {
        let s = QuotaState::new();
        assert_eq!(do_q_getfmt(&s, 1, 99), Err(Error::InvalidArgument));
    }

    #[test]
    fn xfs_known_cmd_returns_not_implemented() {
        assert_eq!(
            do_xfs_quotactl(Q_XQUOTAON, 1, 0, true),
            Err(Error::NotImplemented)
        );
        assert_eq!(
            do_xfs_quotactl(Q_XGETQUOTA, 1, 0, true),
            Err(Error::NotImplemented)
        );
    }

    #[test]
    fn xfs_unknown_cmd_returns_invalid_argument() {
        assert_eq!(
            do_xfs_quotactl(0xDEAD, 1, 0, true),
            Err(Error::InvalidArgument)
        );
    }
}
