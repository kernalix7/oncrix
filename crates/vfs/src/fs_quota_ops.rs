// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Filesystem quota operations.
//!
//! Provides the VFS-facing quota operation interface, bridging generic
//! quota policy (limits, usage tracking, grace periods) to the
//! filesystem-specific enforcement hooks.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  VFS layer                                                      │
//! │  write() / mkdir() / mknod()                                   │
//! │       │                                                         │
//! │       ▼  quota_check_block() / quota_check_inode()             │
//! │  ┌──────────────────────────────────────────────────────────┐   │
//! │  │  FsQuotaOps  (this module)                              │   │
//! │  │  ┌─────────────────────┐  ┌──────────────────────────┐  │   │
//! │  │  │  QuotaPolicy        │  │  QuotaAccounting         │  │   │
//! │  │  │  (limits, grace)    │  │  (per-id usage + state)  │  │   │
//! │  │  └─────────────────────┘  └──────────────────────────┘  │   │
//! │  └──────────────────────────────────────────────────────────┘   │
//! │       │                                                         │
//! │       ▼  fs-specific quotactl hook                              │
//! │  ext2 / xfs / fat16 backend                                    │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Quota types
//!
//! - **User quota**: enforced per UID.
//! - **Group quota**: enforced per GID.
//! - **Project quota**: enforced per project ID (xfs / ext4 feature).
//!
//! # Grace period model
//!
//! When usage exceeds the soft limit, a grace timer starts. Once the
//! timer expires, the soft limit is enforced as a hard limit. The
//! default grace period is 7 days (604 800 seconds).
//!
//! # References
//!
//! Linux `fs/quota/`, `include/linux/quota.h`;
//! `quotactl(2)` man page; XFS quota documentation.

extern crate alloc;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of quota entries per type (user, group, project).
pub const MAX_QUOTA_ENTRIES: usize = 256;

/// Default soft-limit grace period in seconds (7 days).
pub const DEFAULT_GRACE_SECS: u64 = 604_800;

/// Maximum number of filesystems with quota enabled simultaneously.
pub const MAX_QUOTA_FS: usize = 8;

/// Quota version 2 magic number (from Linux `quota_v2.h`).
pub const QUOTA_V2_MAGIC: u32 = 0xd9c01f11;

// ── quotactl commands ────────────────────────────────────────────────────────

/// Turn quota on for a filesystem.
pub const Q_QUOTAON: u32 = 0x0100;
/// Turn quota off for a filesystem.
pub const Q_QUOTAOFF: u32 = 0x0200;
/// Set limits for an ID.
pub const Q_SETQUOTA: u32 = 0x0400;
/// Get quota info for an ID.
pub const Q_GETQUOTA: u32 = 0x0500;
/// Sync quota to disk.
pub const Q_SYNC: u32 = 0x0600;
/// Get filesystem quota statistics.
pub const Q_GETINFO: u32 = 0x0700;
/// Set filesystem quota parameters.
pub const Q_SETINFO: u32 = 0x0800;

// ── QuotaType ────────────────────────────────────────────────────────────────

/// Identifies what an ID refers to in a quota entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum QuotaType {
    /// Per-user (UID) quota.
    #[default]
    User = 0,
    /// Per-group (GID) quota.
    Group = 1,
    /// Per-project quota.
    Project = 2,
}

// ── QuotaState ───────────────────────────────────────────────────────────────

/// Operational state of a quota entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QuotaState {
    /// Quota is disabled for this ID.
    #[default]
    Off,
    /// Within all limits.
    Ok,
    /// Over soft limit; grace period active.
    SoftExceeded,
    /// Grace period expired; soft limit acts as hard.
    GraceExpired,
    /// Hard limit reached; allocations denied.
    HardExceeded,
}

// ── QuotaLimits ──────────────────────────────────────────────────────────────

/// Configurable limits for one quota entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QuotaLimits {
    /// Hard block limit in filesystem blocks (0 = unlimited).
    pub block_hard: u64,
    /// Soft block limit (0 = unlimited).
    pub block_soft: u64,
    /// Hard inode limit (0 = unlimited).
    pub inode_hard: u64,
    /// Soft inode limit (0 = unlimited).
    pub inode_soft: u64,
}

// ── QuotaEntry ───────────────────────────────────────────────────────────────

/// Per-ID quota entry (usage and limits).
#[derive(Debug, Clone, Copy, Default)]
pub struct QuotaEntry {
    /// Subject ID (UID, GID, or project ID).
    pub id: u32,
    /// Quota type.
    pub qtype: QuotaType,
    /// Configured limits.
    pub limits: QuotaLimits,
    /// Current block usage (in filesystem blocks).
    pub block_usage: u64,
    /// Current inode usage.
    pub inode_usage: u64,
    /// Timestamp (seconds since epoch) when grace period started for blocks.
    pub block_grace_start: u64,
    /// Timestamp when grace period started for inodes.
    pub inode_grace_start: u64,
    /// Operational state.
    pub state: QuotaState,
}

impl QuotaEntry {
    /// Create a new quota entry with zeroed usage.
    pub fn new(id: u32, qtype: QuotaType) -> Self {
        Self {
            id,
            qtype,
            ..Default::default()
        }
    }

    // ── Block quota ──────────────────────────────────────────────────────────

    /// Check whether allocating `blocks` additional blocks is allowed.
    ///
    /// Returns `Err(PermissionDenied)` if the hard limit would be exceeded
    /// or the grace period has expired and the soft limit is also exceeded.
    pub fn check_block_alloc(&self, blocks: u64, now_secs: u64, grace: u64) -> Result<()> {
        let new_usage = self.block_usage.saturating_add(blocks);

        // Hard limit check.
        if self.limits.block_hard > 0 && new_usage > self.limits.block_hard {
            return Err(Error::PermissionDenied);
        }
        // Soft limit + grace check.
        if self.limits.block_soft > 0 && new_usage > self.limits.block_soft {
            if self.block_grace_start > 0 {
                let elapsed = now_secs.saturating_sub(self.block_grace_start);
                if elapsed >= grace {
                    return Err(Error::PermissionDenied);
                }
            }
        }
        Ok(())
    }

    /// Check whether allocating one additional inode is allowed.
    pub fn check_inode_alloc(&self, now_secs: u64, grace: u64) -> Result<()> {
        let new_usage = self.inode_usage.saturating_add(1);
        if self.limits.inode_hard > 0 && new_usage > self.limits.inode_hard {
            return Err(Error::PermissionDenied);
        }
        if self.limits.inode_soft > 0 && new_usage > self.limits.inode_soft {
            if self.inode_grace_start > 0 {
                let elapsed = now_secs.saturating_sub(self.inode_grace_start);
                if elapsed >= grace {
                    return Err(Error::PermissionDenied);
                }
            }
        }
        Ok(())
    }

    /// Record `blocks` allocated; update state and start grace timer if needed.
    pub fn alloc_blocks(&mut self, blocks: u64, now_secs: u64) {
        self.block_usage = self.block_usage.saturating_add(blocks);
        self.update_block_state(now_secs);
    }

    /// Record `blocks` freed.
    pub fn free_blocks(&mut self, blocks: u64, now_secs: u64) {
        self.block_usage = self.block_usage.saturating_sub(blocks);
        self.update_block_state(now_secs);
    }

    /// Record one inode allocated.
    pub fn alloc_inode(&mut self, now_secs: u64) {
        self.inode_usage = self.inode_usage.saturating_add(1);
        self.update_inode_state(now_secs);
    }

    /// Record one inode freed.
    pub fn free_inode(&mut self, now_secs: u64) {
        self.inode_usage = self.inode_usage.saturating_sub(1);
        self.update_inode_state(now_secs);
    }

    // ── State update helpers ─────────────────────────────────────────────────

    fn update_block_state(&mut self, now_secs: u64) {
        if self.limits.block_hard > 0 && self.block_usage > self.limits.block_hard {
            self.state = QuotaState::HardExceeded;
        } else if self.limits.block_soft > 0 && self.block_usage > self.limits.block_soft {
            if self.block_grace_start == 0 {
                self.block_grace_start = now_secs;
            }
            self.state = QuotaState::SoftExceeded;
        } else {
            self.block_grace_start = 0;
            self.state = QuotaState::Ok;
        }
    }

    fn update_inode_state(&mut self, now_secs: u64) {
        if self.limits.inode_hard > 0 && self.inode_usage > self.limits.inode_hard {
            self.state = QuotaState::HardExceeded;
        } else if self.limits.inode_soft > 0 && self.inode_usage > self.limits.inode_soft {
            if self.inode_grace_start == 0 {
                self.inode_grace_start = now_secs;
            }
            self.state = QuotaState::SoftExceeded;
        } else {
            self.inode_grace_start = 0;
            // Only reset to Ok if blocks are also ok.
            if self.state == QuotaState::SoftExceeded {
                self.state = QuotaState::Ok;
            }
        }
    }
}

// ── QuotaTable ───────────────────────────────────────────────────────────────

/// Fixed-capacity quota table for a single quota type.
pub struct QuotaTable {
    /// Stored entries (keyed by ID).
    entries: [Option<QuotaEntry>; MAX_QUOTA_ENTRIES],
    /// Number of active entries.
    count: usize,
    /// Whether quota is currently enabled for this type.
    pub enabled: bool,
    /// Grace period in seconds.
    pub grace_secs: u64,
}

impl QuotaTable {
    /// Create a new, disabled quota table.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; MAX_QUOTA_ENTRIES],
            count: 0,
            enabled: false,
            grace_secs: DEFAULT_GRACE_SECS,
        }
    }

    /// Find an entry by ID (mutable).
    fn find_mut(&mut self, id: u32) -> Option<&mut QuotaEntry> {
        self.entries.iter_mut().flatten().find(|e| e.id == id)
    }

    /// Find an entry by ID (immutable).
    pub fn find(&self, id: u32) -> Option<&QuotaEntry> {
        self.entries.iter().flatten().find(|e| e.id == id)
    }

    /// Insert or update quota limits for `id`.
    pub fn set_limits(&mut self, id: u32, qtype: QuotaType, limits: QuotaLimits) -> Result<()> {
        if let Some(entry) = self.find_mut(id) {
            entry.limits = limits;
            return Ok(());
        }
        if self.count >= MAX_QUOTA_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let mut entry = QuotaEntry::new(id, qtype);
        entry.limits = limits;
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove the quota entry for `id`.
    pub fn remove(&mut self, id: u32) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if slot.as_ref().map(|e| e.id == id).unwrap_or(false) {
                *slot = None;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Check a block allocation for `id`.
    pub fn check_block(&self, id: u32, blocks: u64, now_secs: u64) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        match self.find(id) {
            Some(entry) => entry.check_block_alloc(blocks, now_secs, self.grace_secs),
            None => Ok(()), // No entry = no limit.
        }
    }

    /// Check an inode allocation for `id`.
    pub fn check_inode(&self, id: u32, now_secs: u64) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        match self.find(id) {
            Some(entry) => entry.check_inode_alloc(now_secs, self.grace_secs),
            None => Ok(()),
        }
    }

    /// Record a block allocation for `id`.
    pub fn record_block_alloc(&mut self, id: u32, blocks: u64, now_secs: u64) {
        if let Some(entry) = self.find_mut(id) {
            entry.alloc_blocks(blocks, now_secs);
        }
    }

    /// Record a block free for `id`.
    pub fn record_block_free(&mut self, id: u32, blocks: u64, now_secs: u64) {
        if let Some(entry) = self.find_mut(id) {
            entry.free_blocks(blocks, now_secs);
        }
    }

    /// Record an inode allocation for `id`.
    pub fn record_inode_alloc(&mut self, id: u32, now_secs: u64) {
        if let Some(entry) = self.find_mut(id) {
            entry.alloc_inode(now_secs);
        }
    }

    /// Record an inode free for `id`.
    pub fn record_inode_free(&mut self, id: u32, now_secs: u64) {
        if let Some(entry) = self.find_mut(id) {
            entry.free_inode(now_secs);
        }
    }

    /// Return the number of active quota entries.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Iterate all active entries.
    pub fn iter(&self) -> impl Iterator<Item = &QuotaEntry> {
        self.entries.iter().flatten()
    }
}

impl Default for QuotaTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── FsQuotaOps ───────────────────────────────────────────────────────────────

/// Per-filesystem quota operations controller.
///
/// Holds one [`QuotaTable`] per quota type and provides the
/// filesystem-facing enforcement API.
pub struct FsQuotaOps {
    /// User quota table.
    pub user: QuotaTable,
    /// Group quota table.
    pub group: QuotaTable,
    /// Project quota table.
    pub project: QuotaTable,
    /// Total block checks performed.
    pub block_checks: u64,
    /// Total inode checks performed.
    pub inode_checks: u64,
    /// Total allocation denials.
    pub denials: u64,
}

impl FsQuotaOps {
    /// Create a new quota operations controller (all quota types disabled).
    pub const fn new() -> Self {
        Self {
            user: QuotaTable::new(),
            group: QuotaTable::new(),
            project: QuotaTable::new(),
            block_checks: 0,
            inode_checks: 0,
            denials: 0,
        }
    }

    /// Return the table for `qtype`.
    pub fn table(&self, qtype: QuotaType) -> &QuotaTable {
        match qtype {
            QuotaType::User => &self.user,
            QuotaType::Group => &self.group,
            QuotaType::Project => &self.project,
        }
    }

    /// Return the mutable table for `qtype`.
    pub fn table_mut(&mut self, qtype: QuotaType) -> &mut QuotaTable {
        match qtype {
            QuotaType::User => &mut self.user,
            QuotaType::Group => &mut self.group,
            QuotaType::Project => &mut self.project,
        }
    }

    // ── quotactl interface ───────────────────────────────────────────────────

    /// Enable or disable quota for `qtype`.
    pub fn set_enabled(&mut self, qtype: QuotaType, enabled: bool) {
        self.table_mut(qtype).enabled = enabled;
    }

    /// Set quota limits for `id` of type `qtype`.
    pub fn set_quota(&mut self, qtype: QuotaType, id: u32, limits: QuotaLimits) -> Result<()> {
        self.table_mut(qtype).set_limits(id, qtype, limits)
    }

    /// Get quota info for `id` of type `qtype`.
    pub fn get_quota(&self, qtype: QuotaType, id: u32) -> Option<&QuotaEntry> {
        self.table(qtype).find(id)
    }

    /// Remove quota entry for `id` of type `qtype`.
    pub fn del_quota(&mut self, qtype: QuotaType, id: u32) -> Result<()> {
        self.table_mut(qtype).remove(id)
    }

    /// Set the grace period (seconds) for `qtype`.
    pub fn set_grace(&mut self, qtype: QuotaType, secs: u64) {
        self.table_mut(qtype).grace_secs = secs;
    }

    // ── Enforcement hooks ────────────────────────────────────────────────────

    /// Check whether allocating `blocks` blocks is allowed for the given UIDs/GIDs/projects.
    ///
    /// `uid`, `gid`, `project` are the IDs to check against their respective tables.
    pub fn check_block_alloc(
        &mut self,
        uid: u32,
        gid: u32,
        project: u32,
        blocks: u64,
        now_secs: u64,
    ) -> Result<()> {
        self.block_checks += 1;
        if let Err(e) = self.user.check_block(uid, blocks, now_secs) {
            self.denials += 1;
            return Err(e);
        }
        if let Err(e) = self.group.check_block(gid, blocks, now_secs) {
            self.denials += 1;
            return Err(e);
        }
        if let Err(e) = self.project.check_block(project, blocks, now_secs) {
            self.denials += 1;
            return Err(e);
        }
        Ok(())
    }

    /// Check whether allocating one inode is allowed for the given IDs.
    pub fn check_inode_alloc(
        &mut self,
        uid: u32,
        gid: u32,
        project: u32,
        now_secs: u64,
    ) -> Result<()> {
        self.inode_checks += 1;
        if let Err(e) = self.user.check_inode(uid, now_secs) {
            self.denials += 1;
            return Err(e);
        }
        if let Err(e) = self.group.check_inode(gid, now_secs) {
            self.denials += 1;
            return Err(e);
        }
        if let Err(e) = self.project.check_inode(project, now_secs) {
            self.denials += 1;
            return Err(e);
        }
        Ok(())
    }

    /// Record that `blocks` blocks were allocated on behalf of `uid`/`gid`/`project`.
    pub fn record_alloc(&mut self, uid: u32, gid: u32, project: u32, blocks: u64, now_secs: u64) {
        self.user.record_block_alloc(uid, blocks, now_secs);
        self.group.record_block_alloc(gid, blocks, now_secs);
        self.project.record_block_alloc(project, blocks, now_secs);
    }

    /// Record that `blocks` blocks were freed on behalf of `uid`/`gid`/`project`.
    pub fn record_free(&mut self, uid: u32, gid: u32, project: u32, blocks: u64, now_secs: u64) {
        self.user.record_block_free(uid, blocks, now_secs);
        self.group.record_block_free(gid, blocks, now_secs);
        self.project.record_block_free(project, blocks, now_secs);
    }

    /// Record that one inode was allocated.
    pub fn record_inode_alloc(&mut self, uid: u32, gid: u32, project: u32, now_secs: u64) {
        self.user.record_inode_alloc(uid, now_secs);
        self.group.record_inode_alloc(gid, now_secs);
        self.project.record_inode_alloc(project, now_secs);
    }

    /// Record that one inode was freed.
    pub fn record_inode_free(&mut self, uid: u32, gid: u32, project: u32, now_secs: u64) {
        self.user.record_inode_free(uid, now_secs);
        self.group.record_inode_free(gid, now_secs);
        self.project.record_inode_free(project, now_secs);
    }

    // ── Statistics ───────────────────────────────────────────────────────────

    /// Return a snapshot of quota operation statistics.
    pub fn stats(&self) -> QuotaOpsStats {
        QuotaOpsStats {
            user_entries: self.user.count(),
            group_entries: self.group.count(),
            project_entries: self.project.count(),
            user_enabled: self.user.enabled,
            group_enabled: self.group.enabled,
            project_enabled: self.project.enabled,
            block_checks: self.block_checks,
            inode_checks: self.inode_checks,
            denials: self.denials,
        }
    }
}

impl Default for FsQuotaOps {
    fn default() -> Self {
        Self::new()
    }
}

// ── QuotaOpsStats ─────────────────────────────────────────────────────────────

/// Snapshot of quota operations statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct QuotaOpsStats {
    /// Number of user quota entries.
    pub user_entries: usize,
    /// Number of group quota entries.
    pub group_entries: usize,
    /// Number of project quota entries.
    pub project_entries: usize,
    /// Whether user quota is enabled.
    pub user_enabled: bool,
    /// Whether group quota is enabled.
    pub group_enabled: bool,
    /// Whether project quota is enabled.
    pub project_enabled: bool,
    /// Total block allocation checks.
    pub block_checks: u64,
    /// Total inode allocation checks.
    pub inode_checks: u64,
    /// Total allocation denials.
    pub denials: u64,
}

// ── QuotaCommand ─────────────────────────────────────────────────────────────

/// Parsed `quotactl(2)` command.
#[derive(Debug, Clone, Copy)]
pub struct QuotaCommand {
    /// Command code (Q_QUOTAON, Q_SETQUOTA, etc.).
    pub cmd: u32,
    /// Quota type.
    pub qtype: QuotaType,
    /// Subject ID (for per-ID commands).
    pub id: u32,
}

impl QuotaCommand {
    /// Create a new quota command.
    pub fn new(cmd: u32, qtype: QuotaType, id: u32) -> Self {
        Self { cmd, qtype, id }
    }

    /// Validate that `cmd` is a known quota command.
    pub fn is_valid(&self) -> bool {
        matches!(
            self.cmd,
            Q_QUOTAON | Q_QUOTAOFF | Q_SETQUOTA | Q_GETQUOTA | Q_SYNC | Q_GETINFO | Q_SETINFO
        )
    }
}

/// Dispatch a `QuotaCommand` against `ops`.
///
/// Returns `Ok(())` on success or a relevant error. For `Q_GETQUOTA`
/// the quota data is not returned here (callers inspect `ops` directly).
pub fn dispatch_quotactl(ops: &mut FsQuotaOps, cmd: &QuotaCommand, now_secs: u64) -> Result<()> {
    if !cmd.is_valid() {
        return Err(Error::InvalidArgument);
    }
    match cmd.cmd {
        Q_QUOTAON => ops.set_enabled(cmd.qtype, true),
        Q_QUOTAOFF => ops.set_enabled(cmd.qtype, false),
        Q_SYNC => {
            // Simulate quota sync: validate all entries.
            let _ = now_secs;
        }
        Q_GETQUOTA => {
            // Caller reads directly from ops.get_quota().
            if ops.get_quota(cmd.qtype, cmd.id).is_none() {
                return Err(Error::NotFound);
            }
        }
        Q_SETQUOTA | Q_GETINFO | Q_SETINFO => {
            // Handled by higher-level callers with additional data.
        }
        _ => return Err(Error::NotImplemented),
    }
    Ok(())
}

// ── DiskQuota / DqBlk — Linux-compatible naming ───────────────────────────────

/// Linux-compatible disk quota block info (`struct if_dqblk`).
///
/// Maps directly to the fields exposed by `quotactl(2)` with Q_GETQUOTA /
/// Q_SETQUOTA. All block quantities are in filesystem blocks.
#[derive(Debug, Clone, Copy, Default)]
pub struct DqBlk {
    /// Absolute hard block limit (0 = unlimited).
    pub dqb_bhardlimit: u64,
    /// Preferred soft block limit (0 = unlimited).
    pub dqb_bsoftlimit: u64,
    /// Current block usage.
    pub dqb_curspace: u64,
    /// Absolute hard inode limit (0 = unlimited).
    pub dqb_ihardlimit: u64,
    /// Preferred soft inode limit (0 = unlimited).
    pub dqb_isoftlimit: u64,
    /// Current inode count.
    pub dqb_curinodes: u64,
    /// Block grace time (absolute expiry timestamp, 0 = not over soft limit).
    pub dqb_btime: u64,
    /// Inode grace time (absolute expiry timestamp, 0 = not over soft limit).
    pub dqb_itime: u64,
    /// Valid flags (which fields are meaningful).
    pub dqb_valid: u32,
}

/// Bit flags for `DqBlk::dqb_valid`.
pub const QIF_BLIMITS: u32 = 1;
pub const QIF_SPACE: u32 = 2;
pub const QIF_ILIMITS: u32 = 4;
pub const QIF_INODES: u32 = 8;
pub const QIF_BTIME: u32 = 16;
pub const QIF_ITIME: u32 = 32;
pub const QIF_ALL: u32 = QIF_BLIMITS | QIF_SPACE | QIF_ILIMITS | QIF_INODES | QIF_BTIME | QIF_ITIME;

/// Convenience alias matching Linux's `struct dquot` usage pattern.
pub type DiskQuota = QuotaEntry;

impl QuotaEntry {
    /// Populate a [`DqBlk`] from this entry.
    ///
    /// `grace_secs` is the configured grace period for the parent table.
    pub fn to_dqblk(&self, grace_secs: u64) -> DqBlk {
        let btime = if self.block_grace_start > 0 {
            self.block_grace_start.saturating_add(grace_secs)
        } else {
            0
        };
        let itime = if self.inode_grace_start > 0 {
            self.inode_grace_start.saturating_add(grace_secs)
        } else {
            0
        };
        DqBlk {
            dqb_bhardlimit: self.limits.block_hard,
            dqb_bsoftlimit: self.limits.block_soft,
            dqb_curspace: self.block_usage,
            dqb_ihardlimit: self.limits.inode_hard,
            dqb_isoftlimit: self.limits.inode_soft,
            dqb_curinodes: self.inode_usage,
            dqb_btime: btime,
            dqb_itime: itime,
            dqb_valid: QIF_ALL,
        }
    }

    /// Update limits and usage from a [`DqBlk`].
    pub fn from_dqblk(&mut self, dqb: &DqBlk) {
        if dqb.dqb_valid & QIF_BLIMITS != 0 {
            self.limits.block_hard = dqb.dqb_bhardlimit;
            self.limits.block_soft = dqb.dqb_bsoftlimit;
        }
        if dqb.dqb_valid & QIF_SPACE != 0 {
            self.block_usage = dqb.dqb_curspace;
        }
        if dqb.dqb_valid & QIF_ILIMITS != 0 {
            self.limits.inode_hard = dqb.dqb_ihardlimit;
            self.limits.inode_soft = dqb.dqb_isoftlimit;
        }
        if dqb.dqb_valid & QIF_INODES != 0 {
            self.inode_usage = dqb.dqb_curinodes;
        }
    }
}

// ── QuotaV2 on-disk format ────────────────────────────────────────────────────

/// Quota v2 on-disk file header (matches Linux `struct v2_disk_dqheader`).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct QuotaV2Header {
    /// Magic number (`QUOTA_V2_MAGIC`).
    pub magic: u32,
    /// File format version (2 for v2).
    pub version: u32,
}

/// Quota v2 on-disk info block (matches Linux `struct v2_disk_dqinfo`).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct QuotaV2Info {
    /// Default block grace time in seconds.
    pub dqi_bgrace: u32,
    /// Default inode grace time in seconds.
    pub dqi_igrace: u32,
    /// Flags.
    pub dqi_flags: u32,
    /// Number of entries in the file.
    pub dqi_blocks: u32,
    /// Number of free list head entries.
    pub dqi_free_blk: u32,
    /// Number of free info entries.
    pub dqi_free_entry: u32,
}

/// Quota v2 on-disk per-entry record (matches Linux `struct v2r1_disk_dqblk`).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct QuotaV2DqBlk {
    /// Subject ID.
    pub dqb_id: u32,
    /// Padding for alignment.
    pub dqb_pad: u32,
    /// Disk hard block limit.
    pub dqb_ihardlimit: u64,
    /// Disk soft block limit.
    pub dqb_isoftlimit: u64,
    /// Current inode count.
    pub dqb_curinodes: u64,
    /// Hard space limit (bytes).
    pub dqb_bhardlimit: u64,
    /// Soft space limit (bytes).
    pub dqb_bsoftlimit: u64,
    /// Current space used (bytes).
    pub dqb_curspace: u64,
    /// Block grace expiry (absolute seconds).
    pub dqb_btime: u64,
    /// Inode grace expiry (absolute seconds).
    pub dqb_itime: u64,
}

impl QuotaV2DqBlk {
    /// Convert from a [`DqBlk`] and ID.
    pub fn from_dqblk(id: u32, dqb: &DqBlk) -> Self {
        Self {
            dqb_id: id,
            dqb_pad: 0,
            dqb_ihardlimit: dqb.dqb_ihardlimit,
            dqb_isoftlimit: dqb.dqb_isoftlimit,
            dqb_curinodes: dqb.dqb_curinodes,
            dqb_bhardlimit: dqb.dqb_bhardlimit,
            dqb_bsoftlimit: dqb.dqb_bsoftlimit,
            dqb_curspace: dqb.dqb_curspace,
            dqb_btime: dqb.dqb_btime,
            dqb_itime: dqb.dqb_itime,
        }
    }

    /// Convert to a [`DqBlk`].
    pub fn to_dqblk(&self) -> DqBlk {
        DqBlk {
            dqb_bhardlimit: self.dqb_bhardlimit,
            dqb_bsoftlimit: self.dqb_bsoftlimit,
            dqb_curspace: self.dqb_curspace,
            dqb_ihardlimit: self.dqb_ihardlimit,
            dqb_isoftlimit: self.dqb_isoftlimit,
            dqb_curinodes: self.dqb_curinodes,
            dqb_btime: self.dqb_btime,
            dqb_itime: self.dqb_itime,
            dqb_valid: QIF_ALL,
        }
    }
}

// ── Quota v2 file serialisation ───────────────────────────────────────────────

/// Serialise a quota v2 database for `table` into `out`.
///
/// Layout: `QuotaV2Header` (8 bytes) + `QuotaV2Info` (24 bytes) +
/// one `QuotaV2DqBlk` (80 bytes) per entry.
pub fn quota_v2_write(table: &QuotaTable, grace_secs: u64, out: &mut Vec<u8>) {
    let hdr = QuotaV2Header {
        magic: QUOTA_V2_MAGIC,
        version: 2,
    };
    let info = QuotaV2Info {
        dqi_bgrace: grace_secs as u32,
        dqi_igrace: grace_secs as u32,
        dqi_flags: 0,
        dqi_blocks: table.count() as u32,
        dqi_free_blk: 0,
        dqi_free_entry: 0,
    };
    // Header
    out.extend_from_slice(&hdr.magic.to_le_bytes());
    out.extend_from_slice(&hdr.version.to_le_bytes());
    // Info
    out.extend_from_slice(&info.dqi_bgrace.to_le_bytes());
    out.extend_from_slice(&info.dqi_igrace.to_le_bytes());
    out.extend_from_slice(&info.dqi_flags.to_le_bytes());
    out.extend_from_slice(&info.dqi_blocks.to_le_bytes());
    out.extend_from_slice(&info.dqi_free_blk.to_le_bytes());
    out.extend_from_slice(&info.dqi_free_entry.to_le_bytes());
    // Entries
    for entry in table.iter() {
        let dqb = entry.to_dqblk(grace_secs);
        let rec = QuotaV2DqBlk::from_dqblk(entry.id, &dqb);
        out.extend_from_slice(&rec.dqb_id.to_le_bytes());
        out.extend_from_slice(&rec.dqb_pad.to_le_bytes());
        out.extend_from_slice(&rec.dqb_ihardlimit.to_le_bytes());
        out.extend_from_slice(&rec.dqb_isoftlimit.to_le_bytes());
        out.extend_from_slice(&rec.dqb_curinodes.to_le_bytes());
        out.extend_from_slice(&rec.dqb_bhardlimit.to_le_bytes());
        out.extend_from_slice(&rec.dqb_bsoftlimit.to_le_bytes());
        out.extend_from_slice(&rec.dqb_curspace.to_le_bytes());
        out.extend_from_slice(&rec.dqb_btime.to_le_bytes());
        out.extend_from_slice(&rec.dqb_itime.to_le_bytes());
    }
}

// ── sync_dquot ────────────────────────────────────────────────────────────────

/// Sync (flush) all dirty quota entries in `ops` to an in-memory buffer.
///
/// In a real kernel this would write to the quota file on disk; here we
/// serialise to `buf` in quota-v2 format for each enabled type.
pub fn sync_dquot(ops: &FsQuotaOps, buf: &mut Vec<u8>) {
    if ops.user.enabled {
        quota_v2_write(&ops.user, ops.user.grace_secs, buf);
    }
    if ops.group.enabled {
        quota_v2_write(&ops.group, ops.group.grace_secs, buf);
    }
    if ops.project.enabled {
        quota_v2_write(&ops.project, ops.project.grace_secs, buf);
    }
}

// ── get_dqblk / set_dqblk ────────────────────────────────────────────────────

/// Get quota block info for (`qtype`, `id`) in Linux `DqBlk` form.
pub fn get_dqblk(ops: &FsQuotaOps, qtype: QuotaType, id: u32) -> Result<DqBlk> {
    let table = ops.table(qtype);
    match table.find(id) {
        Some(entry) => Ok(entry.to_dqblk(table.grace_secs)),
        None => Err(Error::NotFound),
    }
}

/// Set quota limits/usage for (`qtype`, `id`) from a [`DqBlk`].
pub fn set_dqblk(ops: &mut FsQuotaOps, qtype: QuotaType, id: u32, dqb: &DqBlk) -> Result<()> {
    let table = ops.table_mut(qtype);
    if let Some(entry) = table.find_mut(id) {
        entry.from_dqblk(dqb);
        return Ok(());
    }
    // Entry doesn't exist — create it.
    let limits = QuotaLimits {
        block_hard: dqb.dqb_bhardlimit,
        block_soft: dqb.dqb_bsoftlimit,
        inode_hard: dqb.dqb_ihardlimit,
        inode_soft: dqb.dqb_isoftlimit,
    };
    table.set_limits(id, qtype, limits)
}

// ── quota_on / quota_off ──────────────────────────────────────────────────────

/// Enable quota for `qtype` on `ops`, optionally setting the grace period.
pub fn quota_on(ops: &mut FsQuotaOps, qtype: QuotaType, grace_secs: Option<u64>) {
    if let Some(secs) = grace_secs {
        ops.set_grace(qtype, secs);
    }
    ops.set_enabled(qtype, true);
}

/// Disable quota for `qtype` on `ops`.
pub fn quota_off(ops: &mut FsQuotaOps, qtype: QuotaType) {
    ops.set_enabled(qtype, false);
}

// ── warn_soft_limit ───────────────────────────────────────────────────────────

/// Soft-limit warning record emitted when an operation brings usage over the soft limit.
#[derive(Debug, Clone, Copy)]
pub struct SoftLimitWarning {
    /// Quota type.
    pub qtype: QuotaType,
    /// Subject ID.
    pub id: u32,
    /// Whether the block soft limit was exceeded.
    pub block_exceeded: bool,
    /// Whether the inode soft limit was exceeded.
    pub inode_exceeded: bool,
    /// Current block usage at time of warning.
    pub block_usage: u64,
    /// Current inode usage at time of warning.
    pub inode_usage: u64,
    /// Grace expiry timestamp for blocks (0 = not started).
    pub block_grace_expiry: u64,
    /// Grace expiry timestamp for inodes (0 = not started).
    pub inode_grace_expiry: u64,
}

/// Check `entry` against its soft limits and return a warning if either is exceeded.
///
/// Returns `None` if no soft limit is exceeded.
pub fn warn_soft_limit(entry: &QuotaEntry, grace_secs: u64) -> Option<SoftLimitWarning> {
    let block_exceeded = entry.limits.block_soft > 0
        && entry.block_usage > entry.limits.block_soft
        && entry.limits.block_hard == 0
        || (entry.limits.block_soft > 0 && entry.block_usage > entry.limits.block_soft);
    let inode_exceeded = entry.limits.inode_soft > 0 && entry.inode_usage > entry.limits.inode_soft;

    if !block_exceeded && !inode_exceeded {
        return None;
    }

    let block_grace_expiry = if entry.block_grace_start > 0 {
        entry.block_grace_start.saturating_add(grace_secs)
    } else {
        0
    };
    let inode_grace_expiry = if entry.inode_grace_start > 0 {
        entry.inode_grace_start.saturating_add(grace_secs)
    } else {
        0
    };

    Some(SoftLimitWarning {
        qtype: entry.qtype,
        id: entry.id,
        block_exceeded,
        inode_exceeded,
        block_usage: entry.block_usage,
        inode_usage: entry.inode_usage,
        block_grace_expiry,
        inode_grace_expiry,
    })
}

/// Scan all entries in `table` and collect soft-limit warnings.
pub fn collect_soft_warnings(table: &QuotaTable) -> Vec<SoftLimitWarning> {
    table
        .iter()
        .filter_map(|e| warn_soft_limit(e, table.grace_secs))
        .collect()
}
