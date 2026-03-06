// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! XFS quota management.
//!
//! XFS supports three quota types simultaneously:
//!
//! | Type  | ID type | Description                    |
//! |-------|---------|--------------------------------|
//! | User  | UID     | Per-user disk usage limits      |
//! | Group | GID     | Per-group disk usage limits     |
//! | Project | ProjectID | Per-project (directory tree) limits |
//!
//! Quota information is stored in dedicated quota inodes (`uquotino`,
//! `gquotino`, `pquotino`) in the superblock.
//!
//! # Grace periods
//!
//! When a soft limit is exceeded a grace timer starts. Writes are denied only
//! after the timer expires (hard limit always enforced immediately).
//!
//! # References
//!
//! - Linux `fs/xfs/xfs_dquot.c`, `xfs_quota.c`, `xfs_quota_ops.c`
//! - XFS Filesystem Structure: quota section

use oncrix_lib::{Error, Result};

/// Maximum number of quota entries per type.
pub const MAX_DQUOTS: usize = 512;

/// Quota type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfsQuotaType {
    User,
    Group,
    Project,
}

/// Disk usage counters for one dquot.
#[derive(Debug, Clone, Copy, Default)]
pub struct XfsDqUsage {
    /// Current block count (in 512-byte blocks).
    pub blocks: u64,
    /// Current inode count.
    pub inodes: u64,
    /// Current realtime block count.
    pub rtblocks: u64,
}

/// Hard and soft limits for one dquot.
#[derive(Debug, Clone, Copy, Default)]
pub struct XfsDqLimits {
    /// Hard block limit (0 = no limit).
    pub blk_hardlimit: u64,
    /// Soft block limit (0 = no limit).
    pub blk_softlimit: u64,
    /// Hard inode limit (0 = no limit).
    pub ino_hardlimit: u64,
    /// Soft inode limit (0 = no limit).
    pub ino_softlimit: u64,
    /// Hard realtime block limit.
    pub rtblk_hardlimit: u64,
    /// Soft realtime block limit.
    pub rtblk_softlimit: u64,
}

/// Grace period timer state for soft limit overages.
#[derive(Debug, Clone, Copy, Default)]
pub struct XfsDqTimers {
    /// Block soft-limit timer expiry (Unix timestamp, 0 = not started).
    pub blk_timer: u64,
    /// Inode soft-limit timer expiry.
    pub ino_timer: u64,
    /// Realtime block soft-limit timer expiry.
    pub rtblk_timer: u64,
}

/// One disk quota entry (dquot).
#[derive(Debug, Clone)]
pub struct XfsDquot {
    /// Quota type.
    pub qtype: XfsQuotaType,
    /// ID (UID, GID, or project ID).
    pub id: u32,
    /// Current disk usage.
    pub usage: XfsDqUsage,
    /// Enforcement limits.
    pub limits: XfsDqLimits,
    /// Grace timers.
    pub timers: XfsDqTimers,
    /// Whether this dquot is active.
    pub active: bool,
}

impl XfsDquot {
    /// Create a new, zeroed dquot.
    pub fn new(qtype: XfsQuotaType, id: u32) -> Self {
        Self {
            qtype,
            id,
            usage: XfsDqUsage::default(),
            limits: XfsDqLimits::default(),
            timers: XfsDqTimers::default(),
            active: true,
        }
    }

    /// Check whether writing `blocks` would violate block hard limit.
    pub fn exceeds_blk_hard(&self, blocks: u64) -> bool {
        self.limits.blk_hardlimit != 0
            && self.usage.blocks.saturating_add(blocks) > self.limits.blk_hardlimit
    }

    /// Check whether current usage exceeds block soft limit.
    pub fn over_blk_soft(&self) -> bool {
        self.limits.blk_softlimit != 0 && self.usage.blocks > self.limits.blk_softlimit
    }

    /// Check whether creating one more inode violates inode hard limit.
    pub fn exceeds_ino_hard(&self) -> bool {
        self.limits.ino_hardlimit != 0
            && self.usage.inodes.saturating_add(1) > self.limits.ino_hardlimit
    }

    /// Charge `blocks` blocks and `inodes` inodes to this dquot.
    pub fn charge(&mut self, blocks: u64, inodes: u64) {
        self.usage.blocks = self.usage.blocks.saturating_add(blocks);
        self.usage.inodes = self.usage.inodes.saturating_add(inodes);
    }

    /// Uncharge `blocks` blocks and `inodes` inodes from this dquot.
    pub fn uncharge(&mut self, blocks: u64, inodes: u64) {
        self.usage.blocks = self.usage.blocks.saturating_sub(blocks);
        self.usage.inodes = self.usage.inodes.saturating_sub(inodes);
    }
}

/// Per-type quota table.
pub struct XfsQuotaTable {
    qtype: XfsQuotaType,
    dquots: [Option<XfsDquot>; MAX_DQUOTS],
    count: usize,
    /// Quota accounting enabled.
    acct_enabled: bool,
    /// Quota enforcement enabled.
    enf_enabled: bool,
    /// Default grace period for block soft limit (seconds).
    pub blk_grace_secs: u64,
    /// Default grace period for inode soft limit (seconds).
    pub ino_grace_secs: u64,
}

impl XfsQuotaTable {
    /// Create a new quota table of the given type.
    pub const fn new(qtype: XfsQuotaType) -> Self {
        Self {
            qtype,
            dquots: [const { None }; MAX_DQUOTS],
            count: 0,
            acct_enabled: false,
            enf_enabled: false,
            blk_grace_secs: 7 * 24 * 3600,
            ino_grace_secs: 7 * 24 * 3600,
        }
    }

    /// Enable accounting (does not enable enforcement).
    pub fn enable_acct(&mut self) {
        self.acct_enabled = true;
    }

    /// Enable enforcement (implies accounting).
    pub fn enable_enf(&mut self) {
        self.acct_enabled = true;
        self.enf_enabled = true;
    }

    /// Whether accounting is active.
    pub fn is_acct_on(&self) -> bool {
        self.acct_enabled
    }

    /// Whether enforcement is active.
    pub fn is_enf_on(&self) -> bool {
        self.enf_enabled
    }

    /// Find or create a dquot for `id`.
    pub fn get_or_create(&mut self, id: u32) -> Result<&mut XfsDquot> {
        // Try to find existing.
        let pos = self.dquots[..self.count]
            .iter()
            .position(|d| d.as_ref().map(|d| d.id == id).unwrap_or(false));
        if let Some(idx) = pos {
            return Ok(self.dquots[idx].as_mut().unwrap());
        }
        // Create new.
        if self.count >= MAX_DQUOTS {
            return Err(Error::OutOfMemory);
        }
        self.dquots[self.count] = Some(XfsDquot::new(self.qtype, id));
        let idx = self.count;
        self.count += 1;
        Ok(self.dquots[idx].as_mut().unwrap())
    }

    /// Find an existing dquot (immutable).
    pub fn find(&self, id: u32) -> Option<&XfsDquot> {
        self.dquots[..self.count]
            .iter()
            .filter_map(|d| d.as_ref())
            .find(|d| d.id == id)
    }

    /// Find an existing dquot (mutable).
    pub fn find_mut(&mut self, id: u32) -> Option<&mut XfsDquot> {
        self.dquots[..self.count]
            .iter_mut()
            .filter_map(|d| d.as_mut())
            .find(|d| d.id == id)
    }

    /// Check whether `id` may allocate `blocks` more blocks (enforcement).
    ///
    /// Returns `PermissionDenied` if the hard limit is exceeded.
    /// If accounting is off or enforcement is off, always returns `Ok`.
    pub fn check_blk_limit(&self, id: u32, blocks: u64) -> Result<()> {
        if !self.enf_enabled {
            return Ok(());
        }
        if let Some(dq) = self.find(id) {
            if dq.exceeds_blk_hard(blocks) {
                return Err(Error::PermissionDenied);
            }
        }
        Ok(())
    }

    /// Check whether `id` may create one more inode.
    pub fn check_ino_limit(&self, id: u32) -> Result<()> {
        if !self.enf_enabled {
            return Ok(());
        }
        if let Some(dq) = self.find(id) {
            if dq.exceeds_ino_hard() {
                return Err(Error::PermissionDenied);
            }
        }
        Ok(())
    }

    /// Charge usage to `id`.
    pub fn charge(&mut self, id: u32, blocks: u64, inodes: u64) -> Result<()> {
        if !self.acct_enabled {
            return Ok(());
        }
        let dq = self.get_or_create(id)?;
        dq.charge(blocks, inodes);
        Ok(())
    }

    /// Uncharge usage from `id`.
    pub fn uncharge(&mut self, id: u32, blocks: u64, inodes: u64) {
        if !self.acct_enabled {
            return;
        }
        if let Some(dq) = self.find_mut(id) {
            dq.uncharge(blocks, inodes);
        }
    }

    /// Iterate all active dquots.
    pub fn iter(&self) -> impl Iterator<Item = &XfsDquot> {
        self.dquots[..self.count].iter().filter_map(|d| d.as_ref())
    }
}

/// Combined user + group + project quota state for one XFS filesystem.
pub struct XfsQuotaState {
    pub user: XfsQuotaTable,
    pub group: XfsQuotaTable,
    pub project: XfsQuotaTable,
}

impl XfsQuotaState {
    /// Create with all quota types disabled.
    pub const fn new() -> Self {
        Self {
            user: XfsQuotaTable::new(XfsQuotaType::User),
            group: XfsQuotaTable::new(XfsQuotaType::Group),
            project: XfsQuotaTable::new(XfsQuotaType::Project),
        }
    }

    /// Charge all three quota IDs simultaneously, failing atomically.
    pub fn charge_all(
        &mut self,
        uid: u32,
        gid: u32,
        projid: u32,
        blocks: u64,
        inodes: u64,
    ) -> Result<()> {
        // Pre-flight checks.
        self.user.check_blk_limit(uid, blocks)?;
        self.group.check_blk_limit(gid, blocks)?;
        self.project.check_blk_limit(projid, blocks)?;
        self.user.check_ino_limit(uid)?;
        self.group.check_ino_limit(gid)?;
        self.project.check_ino_limit(projid)?;
        // Commit.
        self.user.charge(uid, blocks, inodes)?;
        self.group.charge(gid, blocks, inodes)?;
        self.project.charge(projid, blocks, inodes)?;
        Ok(())
    }

    /// Uncharge all three quota IDs simultaneously.
    pub fn uncharge_all(&mut self, uid: u32, gid: u32, projid: u32, blocks: u64, inodes: u64) {
        self.user.uncharge(uid, blocks, inodes);
        self.group.uncharge(gid, blocks, inodes);
        self.project.uncharge(projid, blocks, inodes);
    }
}

impl Default for XfsQuotaState {
    fn default() -> Self {
        Self::new()
    }
}
