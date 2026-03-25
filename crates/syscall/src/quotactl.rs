// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `quotactl(2)` syscall handler — disk quota management.
//!
//! Provides the kernel-side interface for POSIX/Linux disk quota operations.
//! Quota enforcement tracks per-user and per-group disk usage and enforces
//! soft/hard limits on block and inode consumption.
//!
//! # Supported commands
//!
//! | Command          | Value | Description                              |
//! |------------------|-------|------------------------------------------|
//! | `Q_QUOTAON`      | 0x0100 | Enable quotas on a filesystem           |
//! | `Q_QUOTAOFF`     | 0x0200 | Disable quotas on a filesystem          |
//! | `Q_GETQUOTA`     | 0x0300 | Get disk quota limits and usage         |
//! | `Q_SETQUOTA`     | 0x0400 | Set disk quota limits                   |
//! | `Q_GETINFO`      | 0x0700 | Get quota subsystem information         |
//! | `Q_SETINFO`      | 0x0800 | Set quota subsystem parameters          |
//! | `Q_GETFMT`       | 0x0900 | Get quota format used on filesystem     |
//! | `Q_SYNC`         | 0x0600 | Sync quota file to disk                 |
//!
//! # Quota types
//!
//! - `USRQUOTA` (0) — per-user quotas
//! - `GRPQUOTA` (1) — per-group quotas
//! - `PRJQUOTA` (2) — per-project quotas (Linux extension)
//!
//! # XFS quota commands
//!
//! XFS uses a separate command namespace (`Q_X*`) operating on
//! `struct fs_disk_quota` and `struct fs_quota_stat` rather than `dqblk`.
//!
//! | Command         | Value    | Description                              |
//! |-----------------|----------|------------------------------------------|
//! | `Q_XQUOTAON`   | 0x110001 | Enable XFS quotas                        |
//! | `Q_XQUOTAOFF`  | 0x110002 | Disable XFS quotas                       |
//! | `Q_XGETQUOTA`  | 0x110003 | Get XFS disk quota for an ID             |
//! | `Q_XSETQLIM`   | 0x110004 | Set XFS quota limits for an ID           |
//! | `Q_XGETQSTAT`  | 0x110005 | Get XFS quota subsystem statistics       |
//! | `Q_XQUOTARM`   | 0x110006 | Remove XFS quota files                   |
//! | `Q_XGETQSTATV` | 0x110008 | Get extended XFS quota statistics        |
//! | `Q_XGETNEXTQUOTA` | 0x110009 | Iterate XFS quota entries              |
//!
//! # Reference
//!
//! - Linux: `fs/quota/`, `include/uapi/linux/quota.h`
//! - Linux: `include/uapi/linux/dqblk_xfs.h`
//! - `man 2 quotactl`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Quota command constants
// ---------------------------------------------------------------------------

/// Enable quotas on a filesystem.
pub const Q_QUOTAON: i32 = 0x0100;
/// Disable quotas on a filesystem.
pub const Q_QUOTAOFF: i32 = 0x0200;
/// Get disk quota limits and current usage for an ID.
pub const Q_GETQUOTA: i32 = 0x0300;
/// Set disk quota limits for an ID.
pub const Q_SETQUOTA: i32 = 0x0400;
/// Sync quota data to disk.
pub const Q_SYNC: i32 = 0x0600;
/// Get quota subsystem information (grace times, flags).
pub const Q_GETINFO: i32 = 0x0700;
/// Set quota subsystem parameters.
pub const Q_SETINFO: i32 = 0x0800;
/// Get the quota format currently in use.
pub const Q_GETFMT: i32 = 0x0900;

// ---------------------------------------------------------------------------
// XFS quota command constants (mirrors <linux/dqblk_xfs.h>)
// ---------------------------------------------------------------------------

/// XFS: enable quota enforcement on a filesystem.
pub const Q_XQUOTAON: i32 = 0x0001; // sub-command inside XFS ioctl space
/// XFS: disable quota enforcement on a filesystem.
pub const Q_XQUOTAOFF: i32 = 0x0002;
/// XFS: get disk quota limits and usage for an ID.
pub const Q_XGETQUOTA: i32 = 0x0003;
/// XFS: set quota limits for an ID.
pub const Q_XSETQLIM: i32 = 0x0004;
/// XFS: get quota subsystem statistics.
pub const Q_XGETQSTAT: i32 = 0x0005;
/// XFS: remove quota files (wipe accounting data).
pub const Q_XQUOTARM: i32 = 0x0006;
/// XFS: get extended quota statistics (v2).
pub const Q_XGETQSTATV: i32 = 0x0008;
/// XFS: get next quota entry (for iteration).
pub const Q_XGETNEXTQUOTA: i32 = 0x0009;

// ---------------------------------------------------------------------------
// XFS quota flag bits (fs_disk_quota.d_fieldmask / quota-on flags)
// ---------------------------------------------------------------------------

/// XFS quota flag: user quota accounting enabled.
pub const XFS_QUOTA_UDQ_ACCT: u16 = 0x0001;
/// XFS quota flag: user quota enforcement enabled.
pub const XFS_QUOTA_UDQ_ENFD: u16 = 0x0002;
/// XFS quota flag: group quota accounting enabled.
pub const XFS_QUOTA_GDQ_ACCT: u16 = 0x0004;
/// XFS quota flag: group quota enforcement enabled.
pub const XFS_QUOTA_GDQ_ENFD: u16 = 0x0008;
/// XFS quota flag: project quota accounting enabled.
pub const XFS_QUOTA_PDQ_ACCT: u16 = 0x0010;
/// XFS quota flag: project quota enforcement enabled.
pub const XFS_QUOTA_PDQ_ENFD: u16 = 0x0020;

// ---------------------------------------------------------------------------
// XFS fs_disk_quota field mask bits
// ---------------------------------------------------------------------------

/// Valid bit: soft block limit field is set.
pub const FS_DQ_BSOFT: u32 = 0x0001;
/// Valid bit: hard block limit field is set.
pub const FS_DQ_BHARD: u32 = 0x0002;
/// Valid bit: soft inode limit field is set.
pub const FS_DQ_ISOFT: u32 = 0x0004;
/// Valid bit: hard inode limit field is set.
pub const FS_DQ_IHARD: u32 = 0x0008;
/// Valid bit: soft real-time block limit is set.
pub const FS_DQ_RTBSOFT: u32 = 0x0010;
/// Valid bit: hard real-time block limit is set.
pub const FS_DQ_RTBHARD: u32 = 0x0020;
/// Valid bit: block grace time field is set.
pub const FS_DQ_BTIMER: u32 = 0x0040;
/// Valid bit: inode grace time field is set.
pub const FS_DQ_ITIMER: u32 = 0x0080;
/// Valid bit: real-time block grace time is set.
pub const FS_DQ_RTBTIMER: u32 = 0x0100;
/// Valid bit: block warning count is set.
pub const FS_DQ_BWARNS: u32 = 0x0200;
/// Valid bit: inode warning count is set.
pub const FS_DQ_IWARNS: u32 = 0x0400;
/// Valid bit: real-time block warning count is set.
pub const FS_DQ_RTBWARNS: u32 = 0x0800;

// ---------------------------------------------------------------------------
// Quota type constants
// ---------------------------------------------------------------------------

/// Per-user quotas.
pub const USRQUOTA: i32 = 0;
/// Per-group quotas.
pub const GRPQUOTA: i32 = 1;
/// Per-project quotas.
pub const PRJQUOTA: i32 = 2;

// ---------------------------------------------------------------------------
// Quota format identifiers
// ---------------------------------------------------------------------------

/// Original quota format (v1, deprecated).
pub const QFMT_VFS_OLD: u32 = 1;
/// Standard VFS quota format (v2).
pub const QFMT_VFS_V0: u32 = 2;
/// VFS quota format v1 (extends v0 with 64-bit counters).
pub const QFMT_VFS_V1: u32 = 4;

// ---------------------------------------------------------------------------
// QuotaType
// ---------------------------------------------------------------------------

/// Classification of quota subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum QuotaType {
    /// Per-user quotas.
    User = 0,
    /// Per-group quotas.
    Group = 1,
    /// Per-project quotas.
    Project = 2,
}

impl QuotaType {
    /// Convert a raw `i32` to a [`QuotaType`].
    ///
    /// Returns `Err(InvalidArgument)` for unrecognised values.
    pub fn from_raw(raw: i32) -> Result<Self> {
        match raw {
            0 => Ok(Self::User),
            1 => Ok(Self::Group),
            2 => Ok(Self::Project),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// DiskQuota — per-ID limits and usage
// ---------------------------------------------------------------------------

/// Disk quota information for a single user/group/project.
///
/// Mirrors `struct dqblk` from `<sys/quota.h>` (POSIX / Linux).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct DiskQuota {
    /// Hard limit on disk blocks (512-byte units).
    pub block_hard_limit: u64,
    /// Soft limit on disk blocks.
    pub block_soft_limit: u64,
    /// Current block usage.
    pub block_current: u64,
    /// Hard limit on inodes.
    pub inode_hard_limit: u64,
    /// Soft limit on inodes.
    pub inode_soft_limit: u64,
    /// Current inode usage.
    pub inode_current: u64,
    /// Time limit for excessive block usage (UNIX timestamp).
    pub block_time: i64,
    /// Time limit for excessive inode usage (UNIX timestamp).
    pub inode_time: i64,
    /// Valid field bitmask (which fields are set/returned).
    pub valid: u32,
}

impl DiskQuota {
    /// Create a new zeroed quota entry.
    pub const fn new() -> Self {
        Self {
            block_hard_limit: 0,
            block_soft_limit: 0,
            block_current: 0,
            inode_hard_limit: 0,
            inode_soft_limit: 0,
            inode_current: 0,
            block_time: 0,
            inode_time: 0,
            valid: 0,
        }
    }

    /// Returns `true` if the current block usage exceeds the soft limit.
    pub fn block_soft_exceeded(&self) -> bool {
        self.block_soft_limit > 0 && self.block_current > self.block_soft_limit
    }

    /// Returns `true` if the current block usage is at or above the hard limit.
    pub fn block_hard_exceeded(&self) -> bool {
        self.block_hard_limit > 0 && self.block_current >= self.block_hard_limit
    }

    /// Returns `true` if the current inode usage exceeds the soft limit.
    pub fn inode_soft_exceeded(&self) -> bool {
        self.inode_soft_limit > 0 && self.inode_current > self.inode_soft_limit
    }

    /// Returns `true` if the current inode usage is at or above the hard limit.
    pub fn inode_hard_exceeded(&self) -> bool {
        self.inode_hard_limit > 0 && self.inode_current >= self.inode_hard_limit
    }
}

// ---------------------------------------------------------------------------
// QuotaInfo — filesystem-wide quota parameters
// ---------------------------------------------------------------------------

/// Filesystem-wide quota subsystem information.
///
/// Mirrors `struct dqinfo` from `<sys/quota.h>`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct QuotaInfo {
    /// Default block grace time in seconds.
    pub block_grace_time: u64,
    /// Default inode grace time in seconds.
    pub inode_grace_time: u64,
    /// Quota flags (format-specific).
    pub flags: u32,
    /// Valid field bitmask.
    pub valid: u32,
}

// ---------------------------------------------------------------------------
// FsXDiskQuota — XFS per-ID quota structure
// ---------------------------------------------------------------------------

/// XFS per-user/group/project quota limits and accounting.
///
/// Mirrors `struct fs_disk_quota` from `<linux/dqblk_xfs.h>`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct FsXDiskQuota {
    /// Version (must be `FS_DQUOT_VERSION`).
    pub d_version: i8,
    /// Quota type: `XFS_USER_QUOTA`, `XFS_GROUP_QUOTA`, or `XFS_PROJ_QUOTA`.
    pub d_flags: i8,
    /// Bitmask of valid / dirty fields (see `FS_DQ_*`).
    pub d_fieldmask: u32,
    /// ID this quota applies to (UID / GID / project ID).
    pub d_id: u32,
    /// Absolute limit on disk blocks (1024-byte units).
    pub d_blk_hardlimit: u64,
    /// Preferred limit on disk blocks.
    pub d_blk_softlimit: u64,
    /// Maximum number of allocated inodes.
    pub d_ino_hardlimit: u64,
    /// Preferred inode limit.
    pub d_ino_softlimit: u64,
    /// Current disk block usage.
    pub d_bcount: u64,
    /// Current allocated inode count.
    pub d_icount: u64,
    /// Time limit for excessive block usage (UNIX timestamp, 0 = not exceeded).
    pub d_btimer: i32,
    /// Time limit for excessive inode usage.
    pub d_itimer: i32,
    /// Warnings issued about block usage.
    pub d_bwarns: u16,
    /// Warnings issued about inode usage.
    pub d_iwarns: u16,
    /// Padding for alignment.
    pub d_padding2: u32,
    /// Absolute limit on real-time blocks.
    pub d_rtb_hardlimit: u64,
    /// Preferred real-time block limit.
    pub d_rtb_softlimit: u64,
    /// Current real-time block usage.
    pub d_rtbcount: u64,
    /// Time limit for excessive real-time block usage.
    pub d_rtbtimer: i32,
    /// Warnings issued for real-time block usage.
    pub d_rtbwarns: u16,
    /// Padding.
    pub d_padding3: u16,
    /// Reserved for future use.
    pub d_padding4: [u8; 8],
}

impl FsXDiskQuota {
    /// Create a new zeroed XFS quota structure.
    pub const fn new() -> Self {
        Self {
            d_version: 1,
            d_flags: 0,
            d_fieldmask: 0,
            d_id: 0,
            d_blk_hardlimit: 0,
            d_blk_softlimit: 0,
            d_ino_hardlimit: 0,
            d_ino_softlimit: 0,
            d_bcount: 0,
            d_icount: 0,
            d_btimer: 0,
            d_itimer: 0,
            d_bwarns: 0,
            d_iwarns: 0,
            d_padding2: 0,
            d_rtb_hardlimit: 0,
            d_rtb_softlimit: 0,
            d_rtbcount: 0,
            d_rtbtimer: 0,
            d_rtbwarns: 0,
            d_padding3: 0,
            d_padding4: [0; 8],
        }
    }

    /// Returns `true` if the block hard limit is exceeded.
    pub fn blk_hard_exceeded(&self) -> bool {
        self.d_blk_hardlimit > 0 && self.d_bcount >= self.d_blk_hardlimit
    }

    /// Returns `true` if the block soft limit is exceeded.
    pub fn blk_soft_exceeded(&self) -> bool {
        self.d_blk_softlimit > 0 && self.d_bcount > self.d_blk_softlimit
    }

    /// Returns `true` if the inode hard limit is exceeded.
    pub fn ino_hard_exceeded(&self) -> bool {
        self.d_ino_hardlimit > 0 && self.d_icount >= self.d_ino_hardlimit
    }

    /// Returns `true` if the inode soft limit is exceeded.
    pub fn ino_soft_exceeded(&self) -> bool {
        self.d_ino_softlimit > 0 && self.d_icount > self.d_ino_softlimit
    }

    /// Convert from a [`DiskQuota`] (VFS format) to XFS format.
    pub fn from_vfs(id: u32, dq: &DiskQuota) -> Self {
        Self {
            d_version: 1,
            d_flags: 0,
            d_fieldmask: FS_DQ_BSOFT | FS_DQ_BHARD | FS_DQ_ISOFT | FS_DQ_IHARD,
            d_id: id,
            d_blk_hardlimit: dq.block_hard_limit,
            d_blk_softlimit: dq.block_soft_limit,
            d_ino_hardlimit: dq.inode_hard_limit,
            d_ino_softlimit: dq.inode_soft_limit,
            d_bcount: dq.block_current,
            d_icount: dq.inode_current,
            d_btimer: dq.block_time as i32,
            d_itimer: dq.inode_time as i32,
            ..Self::new()
        }
    }

    /// Convert to [`DiskQuota`] (VFS format).
    pub fn to_vfs(&self) -> DiskQuota {
        DiskQuota {
            block_hard_limit: self.d_blk_hardlimit,
            block_soft_limit: self.d_blk_softlimit,
            block_current: self.d_bcount,
            inode_hard_limit: self.d_ino_hardlimit,
            inode_soft_limit: self.d_ino_softlimit,
            inode_current: self.d_icount,
            block_time: self.d_btimer as i64,
            inode_time: self.d_itimer as i64,
            valid: self.d_fieldmask,
        }
    }
}

// ---------------------------------------------------------------------------
// FsQuotaStat — XFS filesystem-wide quota statistics
// ---------------------------------------------------------------------------

/// Per-quota-type accounting statistics returned by `Q_XGETQSTAT`.
///
/// Mirrors `struct fs_qfilestat` from `<linux/dqblk_xfs.h>`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct FsQFileStat {
    /// Inode number of the quota file.
    pub qfs_ino: u64,
    /// Number of disk blocks used by the quota file.
    pub qfs_nblks: u64,
    /// Number of extents in the quota file.
    pub qfs_nextents: u32,
    /// Padding.
    pub qfs_pad: u32,
}

/// Filesystem-wide XFS quota statistics.
///
/// Mirrors `struct fs_quota_stat` from `<linux/dqblk_xfs.h>`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct FsQuotaStat {
    /// Version (must be `FS_QSTAT_VERSION`).
    pub qs_version: i8,
    /// Reserved.
    pub qs_pad: u8,
    /// Quota flags (see `XFS_QUOTA_*`).
    pub qs_flags: u16,
    /// Number of active quota entries (inuse).
    pub qs_incoredqs: u32,
    /// User quota file info.
    pub qs_uquota: FsQFileStat,
    /// Group quota file info.
    pub qs_gquota: FsQFileStat,
    /// Default block quota warning limit.
    pub qs_bwarnlimit: u16,
    /// Default inode quota warning limit.
    pub qs_iwarnlimit: u16,
    /// Default real-time block warning limit.
    pub qs_rtbwarnlimit: u16,
    /// Padding.
    pub qs_pad2: u16,
    /// Default block grace time (seconds).
    pub qs_btimelimit: u32,
    /// Default inode grace time (seconds).
    pub qs_itimelimit: u32,
    /// Default real-time block grace time.
    pub qs_rtbtimelimit: u32,
    /// Highest project ID with an active quota entry.
    pub qs_pquota: FsQFileStat,
}

// ---------------------------------------------------------------------------
// QuotaState — per-filesystem quota registry
// ---------------------------------------------------------------------------

/// Maximum number of quota entries per quota table (one table per type).
const QUOTA_MAX_ENTRIES: usize = 64;

/// A single quota entry in the in-kernel table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QuotaEntry {
    /// The UID/GID/project ID this entry belongs to.
    id: u32,
    /// Quota data.
    quota: DiskQuota,
}

/// Per-filesystem, per-type quota table.
#[derive(Debug)]
struct QuotaTable {
    entries: [Option<QuotaEntry>; QUOTA_MAX_ENTRIES],
    count: usize,
    enabled: bool,
    info: QuotaInfo,
}

impl QuotaTable {
    const fn new() -> Self {
        Self {
            entries: [None; QUOTA_MAX_ENTRIES],
            count: 0,
            enabled: false,
            info: QuotaInfo {
                block_grace_time: 604800,
                inode_grace_time: 604800,
                flags: 0,
                valid: 0,
            },
        }
    }

    fn find_index(&self, id: u32) -> Option<usize> {
        self.entries[..self.count]
            .iter()
            .position(|e| e.map_or(false, |e| e.id == id))
    }

    fn get(&self, id: u32) -> Option<&DiskQuota> {
        let idx = self.find_index(id)?;
        self.entries[idx].as_ref().map(|e| &e.quota)
    }

    fn set(&mut self, id: u32, quota: DiskQuota) -> Result<()> {
        if let Some(idx) = self.find_index(id) {
            if let Some(entry) = self.entries[idx].as_mut() {
                entry.quota = quota;
            }
            return Ok(());
        }
        if self.count >= QUOTA_MAX_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = Some(QuotaEntry { id, quota });
        self.count += 1;
        Ok(())
    }
}

/// Maximum number of filesystems with quotas enabled simultaneously.
const QUOTA_MAX_FILESYSTEMS: usize = 8;

/// Quota filesystem slot.
struct QuotaFs {
    /// Unique filesystem identifier (e.g. device number stub).
    fsid: u32,
    /// Tables indexed by QuotaType (User=0, Group=1, Project=2).
    tables: [QuotaTable; 3],
}

impl QuotaFs {
    fn new(fsid: u32) -> Self {
        Self {
            fsid,
            tables: [QuotaTable::new(), QuotaTable::new(), QuotaTable::new()],
        }
    }
}

/// Global quota state.
pub struct QuotaState {
    filesystems: [Option<QuotaFs>; QUOTA_MAX_FILESYSTEMS],
    count: usize,
}

impl QuotaState {
    /// Create an empty quota state.
    pub const fn new() -> Self {
        Self {
            filesystems: [const { None }; QUOTA_MAX_FILESYSTEMS],
            count: 0,
        }
    }

    fn find_fs(&self, fsid: u32) -> Option<usize> {
        self.filesystems[..self.count]
            .iter()
            .position(|f| f.as_ref().map_or(false, |f| f.fsid == fsid))
    }

    fn find_or_insert_fs(&mut self, fsid: u32) -> Result<usize> {
        if let Some(idx) = self.find_fs(fsid) {
            return Ok(idx);
        }
        if self.count >= QUOTA_MAX_FILESYSTEMS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.filesystems[idx] = Some(QuotaFs::new(fsid));
        self.count += 1;
        Ok(idx)
    }

    /// Enable quotas for the given filesystem and quota type.
    pub fn quota_on(&mut self, fsid: u32, qtype: QuotaType) -> Result<()> {
        let idx = self.find_or_insert_fs(fsid)?;
        if let Some(fs) = self.filesystems[idx].as_mut() {
            fs.tables[qtype as usize].enabled = true;
        }
        Ok(())
    }

    /// Disable quotas for the given filesystem and quota type.
    pub fn quota_off(&mut self, fsid: u32, qtype: QuotaType) -> Result<()> {
        let idx = self.find_fs(fsid).ok_or(Error::NotFound)?;
        if let Some(fs) = self.filesystems[idx].as_mut() {
            fs.tables[qtype as usize].enabled = false;
        }
        Ok(())
    }

    /// Get quota data for an ID on a filesystem.
    pub fn get_quota(&self, fsid: u32, qtype: QuotaType, id: u32) -> Result<DiskQuota> {
        let idx = self.find_fs(fsid).ok_or(Error::NotFound)?;
        if let Some(fs) = &self.filesystems[idx] {
            let table = &fs.tables[qtype as usize];
            if !table.enabled {
                return Err(Error::NotImplemented);
            }
            return table.get(id).copied().ok_or(Error::NotFound);
        }
        Err(Error::NotFound)
    }

    /// Set quota limits for an ID on a filesystem.
    pub fn set_quota(
        &mut self,
        fsid: u32,
        qtype: QuotaType,
        id: u32,
        quota: DiskQuota,
    ) -> Result<()> {
        let idx = self.find_or_insert_fs(fsid)?;
        if let Some(fs) = self.filesystems[idx].as_mut() {
            let table = &mut fs.tables[qtype as usize];
            if !table.enabled {
                return Err(Error::NotImplemented);
            }
            table.set(id, quota)
        } else {
            Err(Error::NotFound)
        }
    }

    /// Get filesystem-wide quota info.
    pub fn get_info(&self, fsid: u32, qtype: QuotaType) -> Result<QuotaInfo> {
        let idx = self.find_fs(fsid).ok_or(Error::NotFound)?;
        if let Some(fs) = &self.filesystems[idx] {
            return Ok(fs.tables[qtype as usize].info);
        }
        Err(Error::NotFound)
    }

    /// Set filesystem-wide quota info.
    pub fn set_info(&mut self, fsid: u32, qtype: QuotaType, info: QuotaInfo) -> Result<()> {
        let idx = self.find_or_insert_fs(fsid)?;
        if let Some(fs) = self.filesystems[idx].as_mut() {
            fs.tables[qtype as usize].info = info;
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    /// Get the quota format identifier for a filesystem.
    pub fn get_fmt(&self, fsid: u32) -> Result<u32> {
        let _ = self.find_fs(fsid).ok_or(Error::NotFound)?;
        // ONCRIX uses the v1 VFS quota format.
        Ok(QFMT_VFS_V1)
    }

    // -----------------------------------------------------------------------
    // XFS quota operations
    // -----------------------------------------------------------------------

    /// Enable XFS quota accounting / enforcement.
    ///
    /// `flags` is a bitmask of `XFS_QUOTA_*` bits selecting which quota
    /// types to activate.  Multiple bits may be set in one call.
    pub fn xfs_quota_on(&mut self, fsid: u32, flags: u16) -> Result<()> {
        let idx = self.find_or_insert_fs(fsid)?;
        if let Some(fs) = self.filesystems[idx].as_mut() {
            if flags & (XFS_QUOTA_UDQ_ACCT | XFS_QUOTA_UDQ_ENFD) != 0 {
                fs.tables[QuotaType::User as usize].enabled = true;
            }
            if flags & (XFS_QUOTA_GDQ_ACCT | XFS_QUOTA_GDQ_ENFD) != 0 {
                fs.tables[QuotaType::Group as usize].enabled = true;
            }
            if flags & (XFS_QUOTA_PDQ_ACCT | XFS_QUOTA_PDQ_ENFD) != 0 {
                fs.tables[QuotaType::Project as usize].enabled = true;
            }
        }
        Ok(())
    }

    /// Disable XFS quota accounting / enforcement.
    ///
    /// `flags` selects which quota types to deactivate.
    pub fn xfs_quota_off(&mut self, fsid: u32, flags: u16) -> Result<()> {
        let idx = self.find_fs(fsid).ok_or(Error::NotFound)?;
        if let Some(fs) = self.filesystems[idx].as_mut() {
            if flags & (XFS_QUOTA_UDQ_ACCT | XFS_QUOTA_UDQ_ENFD) != 0 {
                fs.tables[QuotaType::User as usize].enabled = false;
            }
            if flags & (XFS_QUOTA_GDQ_ACCT | XFS_QUOTA_GDQ_ENFD) != 0 {
                fs.tables[QuotaType::Group as usize].enabled = false;
            }
            if flags & (XFS_QUOTA_PDQ_ACCT | XFS_QUOTA_PDQ_ENFD) != 0 {
                fs.tables[QuotaType::Project as usize].enabled = false;
            }
        }
        Ok(())
    }

    /// Get XFS disk quota limits and usage for an ID.
    ///
    /// Returns [`FsXDiskQuota`] translated from the VFS-format entry.
    pub fn xfs_get_quota(&self, fsid: u32, qtype: QuotaType, id: u32) -> Result<FsXDiskQuota> {
        let dq = self.get_quota(fsid, qtype, id)?;
        Ok(FsXDiskQuota::from_vfs(id, &dq))
    }

    /// Set XFS quota limits for an ID.
    ///
    /// Only fields indicated by `d_fieldmask` in `xdq` are applied;
    /// unchanged fields keep their previous values.
    pub fn xfs_set_qlim(&mut self, fsid: u32, qtype: QuotaType, xdq: &FsXDiskQuota) -> Result<()> {
        let id = xdq.d_id;

        // Fetch existing or default entry.
        let existing = self.get_quota(fsid, qtype, id).unwrap_or_default();
        let mut vfs = existing;

        let mask = xdq.d_fieldmask;
        if mask & FS_DQ_BHARD != 0 {
            vfs.block_hard_limit = xdq.d_blk_hardlimit;
        }
        if mask & FS_DQ_BSOFT != 0 {
            vfs.block_soft_limit = xdq.d_blk_softlimit;
        }
        if mask & FS_DQ_IHARD != 0 {
            vfs.inode_hard_limit = xdq.d_ino_hardlimit;
        }
        if mask & FS_DQ_ISOFT != 0 {
            vfs.inode_soft_limit = xdq.d_ino_softlimit;
        }
        if mask & FS_DQ_BTIMER != 0 {
            vfs.block_time = xdq.d_btimer as i64;
        }
        if mask & FS_DQ_ITIMER != 0 {
            vfs.inode_time = xdq.d_itimer as i64;
        }

        self.set_quota(fsid, qtype, id, vfs)
    }

    /// Get XFS filesystem-wide quota statistics.
    pub fn xfs_get_qstat(&self, fsid: u32) -> Result<FsQuotaStat> {
        let idx = self.find_fs(fsid).ok_or(Error::NotFound)?;
        if let Some(fs) = &self.filesystems[idx] {
            let u_table = &fs.tables[QuotaType::User as usize];
            let g_table = &fs.tables[QuotaType::Group as usize];

            let mut flags: u16 = 0;
            if u_table.enabled {
                flags |= XFS_QUOTA_UDQ_ACCT | XFS_QUOTA_UDQ_ENFD;
            }
            if g_table.enabled {
                flags |= XFS_QUOTA_GDQ_ACCT | XFS_QUOTA_GDQ_ENFD;
            }
            if fs.tables[QuotaType::Project as usize].enabled {
                flags |= XFS_QUOTA_PDQ_ACCT | XFS_QUOTA_PDQ_ENFD;
            }

            let total_entries = u_table.count + g_table.count;
            return Ok(FsQuotaStat {
                qs_version: 1,
                qs_pad: 0,
                qs_flags: flags,
                qs_incoredqs: total_entries as u32,
                qs_uquota: FsQFileStat {
                    qfs_ino: 0,
                    qfs_nblks: u_table.count as u64,
                    qfs_nextents: u_table.count as u32,
                    qfs_pad: 0,
                },
                qs_gquota: FsQFileStat {
                    qfs_ino: 0,
                    qfs_nblks: g_table.count as u64,
                    qfs_nextents: g_table.count as u32,
                    qfs_pad: 0,
                },
                qs_bwarnlimit: 5,
                qs_iwarnlimit: 5,
                qs_rtbwarnlimit: 5,
                qs_pad2: 0,
                qs_btimelimit: u_table.info.block_grace_time as u32,
                qs_itimelimit: u_table.info.inode_grace_time as u32,
                qs_rtbtimelimit: u_table.info.block_grace_time as u32,
                qs_pquota: FsQFileStat::default(),
            });
        }
        Err(Error::NotFound)
    }

    /// Remove XFS quota accounting data (wipe quota files).
    ///
    /// `flags` selects which quota types to wipe (same bitmask as
    /// `xfs_quota_on`).  Quotas must already be disabled before removal.
    pub fn xfs_quota_rm(&mut self, fsid: u32, flags: u16) -> Result<()> {
        let idx = self.find_fs(fsid).ok_or(Error::NotFound)?;
        if let Some(fs) = self.filesystems[idx].as_mut() {
            if flags & (XFS_QUOTA_UDQ_ACCT | XFS_QUOTA_UDQ_ENFD) != 0 {
                let t = &mut fs.tables[QuotaType::User as usize];
                if t.enabled {
                    return Err(Error::InvalidArgument);
                }
                *t = QuotaTable::new();
            }
            if flags & (XFS_QUOTA_GDQ_ACCT | XFS_QUOTA_GDQ_ENFD) != 0 {
                let t = &mut fs.tables[QuotaType::Group as usize];
                if t.enabled {
                    return Err(Error::InvalidArgument);
                }
                *t = QuotaTable::new();
            }
            if flags & (XFS_QUOTA_PDQ_ACCT | XFS_QUOTA_PDQ_ENFD) != 0 {
                let t = &mut fs.tables[QuotaType::Project as usize];
                if t.enabled {
                    return Err(Error::InvalidArgument);
                }
                *t = QuotaTable::new();
            }
        }
        Ok(())
    }

    /// Iterate XFS quota entries starting after `next_id`.
    ///
    /// Returns the next [`FsXDiskQuota`] with an ID strictly greater than
    /// `next_id`, or `Err(NotFound)` when the table is exhausted.
    pub fn xfs_get_next_quota(
        &self,
        fsid: u32,
        qtype: QuotaType,
        next_id: u32,
    ) -> Result<FsXDiskQuota> {
        let idx = self.find_fs(fsid).ok_or(Error::NotFound)?;
        if let Some(fs) = &self.filesystems[idx] {
            let table = &fs.tables[qtype as usize];
            if !table.enabled {
                return Err(Error::NotImplemented);
            }
            // Find the entry with the smallest ID > next_id.
            let mut best: Option<(u32, &DiskQuota)> = None;
            for entry in table.entries[..table.count].iter().flatten() {
                if entry.id > next_id {
                    if best.map_or(true, |(bid, _)| entry.id < bid) {
                        best = Some((entry.id, &entry.quota));
                    }
                }
            }
            if let Some((id, dq)) = best {
                return Ok(FsXDiskQuota::from_vfs(id, dq));
            }
        }
        Err(Error::NotFound)
    }
}

// ---------------------------------------------------------------------------
// Syscall entry points
// ---------------------------------------------------------------------------

/// `quotactl` — perform a disk quota operation.
///
/// # Arguments
///
/// * `cmd`   — encoded command: high 16 bits = quota type, low 16 bits = command code.
/// * `fsid`  — opaque filesystem identifier (device number in Linux).
/// * `id`    — UID / GID / project ID relevant to the command.
/// * `state` — mutable reference to the global [`QuotaState`].
///
/// Returns `Ok(())` on success, or an appropriate `Error` variant.
pub fn do_quotactl(cmd: i32, fsid: u32, id: u32, state: &mut QuotaState) -> Result<()> {
    // Decode quota type from the high 16 bits of cmd.
    let raw_type = (cmd >> 16) & 0xFFFF;
    // Decode the actual command from the low 16 bits.
    let raw_cmd = cmd & 0xFFFF;

    let qtype = QuotaType::from_raw(raw_type)?;

    match raw_cmd {
        x if x == Q_QUOTAON => state.quota_on(fsid, qtype),
        x if x == Q_QUOTAOFF => state.quota_off(fsid, qtype),
        x if x == Q_SYNC => {
            // Sync is a no-op at this stub level; real impl flushes
            // the quota file buffers to disk.
            let _ = (fsid, id, qtype);
            Ok(())
        }
        _ => Err(Error::InvalidArgument),
    }
}

/// `quotactl_get_quota` — retrieve quota limits and usage for an ID.
///
/// Returns the [`DiskQuota`] entry for `id` on the filesystem identified
/// by `fsid`, or an error if quotas are not enabled for that type.
pub fn do_quotactl_get(
    fsid: u32,
    qtype: QuotaType,
    id: u32,
    state: &QuotaState,
) -> Result<DiskQuota> {
    state.get_quota(fsid, qtype, id)
}

/// `quotactl_set_quota` — install quota limits for an ID.
///
/// Writes the provided [`DiskQuota`] into the in-kernel table.  Quotas
/// must already be enabled for this type on the filesystem.
pub fn do_quotactl_set(
    fsid: u32,
    qtype: QuotaType,
    id: u32,
    quota: DiskQuota,
    state: &mut QuotaState,
) -> Result<()> {
    state.set_quota(fsid, qtype, id, quota)
}

/// `quotactl_get_info` — read filesystem-wide quota parameters.
pub fn do_quotactl_get_info(fsid: u32, qtype: QuotaType, state: &QuotaState) -> Result<QuotaInfo> {
    state.get_info(fsid, qtype)
}

/// `quotactl_set_info` — write filesystem-wide quota parameters.
pub fn do_quotactl_set_info(
    fsid: u32,
    qtype: QuotaType,
    info: QuotaInfo,
    state: &mut QuotaState,
) -> Result<()> {
    state.set_info(fsid, qtype, info)
}

/// `quotactl_get_fmt` — return the quota format identifier for a filesystem.
///
/// Returns one of the `QFMT_VFS_*` constants.
pub fn do_quotactl_get_fmt(fsid: u32, state: &QuotaState) -> Result<u32> {
    state.get_fmt(fsid)
}

// ---------------------------------------------------------------------------
// XFS quota syscall entry points
// ---------------------------------------------------------------------------

/// `Q_XQUOTAON` — enable XFS quota accounting / enforcement.
///
/// `flags` is a bitmask of `XFS_QUOTA_UDQ_ACCT`, `XFS_QUOTA_GDQ_ENFD`,
/// etc., selecting which quota types to activate.
pub fn do_xquotaon(fsid: u32, flags: u16, state: &mut QuotaState) -> Result<()> {
    if flags == 0 {
        return Err(Error::InvalidArgument);
    }
    state.xfs_quota_on(fsid, flags)
}

/// `Q_XQUOTAOFF` — disable XFS quota accounting / enforcement.
pub fn do_xquotaoff(fsid: u32, flags: u16, state: &mut QuotaState) -> Result<()> {
    if flags == 0 {
        return Err(Error::InvalidArgument);
    }
    state.xfs_quota_off(fsid, flags)
}

/// `Q_XGETQUOTA` — get XFS disk quota limits and usage for an ID.
///
/// Returns the [`FsXDiskQuota`] for `id` on the filesystem identified by
/// `fsid`.  The quota type is determined by the high 16 bits of `cmd` (as
/// with the VFS commands).
pub fn do_xgetquota(
    fsid: u32,
    qtype: QuotaType,
    id: u32,
    state: &QuotaState,
) -> Result<FsXDiskQuota> {
    state.xfs_get_quota(fsid, qtype, id)
}

/// `Q_XSETQLIM` — set XFS quota limits for an ID.
///
/// Only fields indicated by `xdq.d_fieldmask` are modified.
pub fn do_xsetqlim(
    fsid: u32,
    qtype: QuotaType,
    xdq: &FsXDiskQuota,
    state: &mut QuotaState,
) -> Result<()> {
    if xdq.d_fieldmask == 0 {
        // Nothing to set — treat as a no-op.
        return Ok(());
    }
    state.xfs_set_qlim(fsid, qtype, xdq)
}

/// `Q_XGETQSTAT` — get XFS filesystem-wide quota statistics.
pub fn do_xgetqstat(fsid: u32, state: &QuotaState) -> Result<FsQuotaStat> {
    state.xfs_get_qstat(fsid)
}

/// `Q_XQUOTARM` — remove XFS quota accounting data.
///
/// Quotas must be disabled (`Q_XQUOTAOFF`) before removal.
/// `flags` selects which quota types to wipe.
pub fn do_xquotarm(fsid: u32, flags: u16, state: &mut QuotaState) -> Result<()> {
    if flags == 0 {
        return Err(Error::InvalidArgument);
    }
    state.xfs_quota_rm(fsid, flags)
}

/// `Q_XGETNEXTQUOTA` — iterate XFS quota entries.
///
/// Returns the next quota entry whose ID is strictly greater than `next_id`.
/// Callers can iterate the entire table by starting with `next_id = 0` and
/// incrementing `next_id` to `returned_entry.d_id` on each call.
pub fn do_xgetnextquota(
    fsid: u32,
    qtype: QuotaType,
    next_id: u32,
    state: &QuotaState,
) -> Result<FsXDiskQuota> {
    state.xfs_get_next_quota(fsid, qtype, next_id)
}
