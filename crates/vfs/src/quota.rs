// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Filesystem disk quota management.
//!
//! Implements per-user, per-group, and per-project disk quotas
//! with soft/hard limits and grace periods, following the
//! traditional Unix quota model (`quotactl(2)`).
//!
//! # Quota enforcement
//!
//! - **Hard limit**: allocation is unconditionally denied.
//! - **Soft limit**: allocation is allowed but a grace period
//!   starts; once expired, the soft limit becomes a hard limit.
//!
//! # References
//!
//! - POSIX.1-2024 (no mandatory quota API, but common extension)
//! - Linux `quotactl(2)`, `<sys/quota.h>`

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum number of quota entries the table can hold.
pub const MAX_QUOTA_ENTRIES: usize = 128;

/// Default grace period in seconds (7 days = 604 800 s).
pub const QUOTA_GRACE_PERIOD: u64 = 604_800;

/// `quotactl` flag: block hard limit is set.
pub const _QIF_BLIMITS: u32 = 1;
/// `quotactl` flag: inode hard limit is set.
pub const _QIF_ILIMITS: u32 = 2;
/// `quotactl` flag: block usage is set.
pub const _QIF_USAGE: u32 = 4;
/// `quotactl` flag: inode usage is set.
pub const _QIF_IUSAGE: u32 = 8;
/// `quotactl` flag: all fields are set.
pub const _QIF_ALL: u32 = _QIF_BLIMITS | _QIF_ILIMITS | _QIF_USAGE | _QIF_IUSAGE;

// ── QuotaType ───────────────────────────────────────────────────

/// Identifies the kind of quota (user, group, or project).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum QuotaType {
    /// Per-user quota.
    #[default]
    User = 0,
    /// Per-group quota.
    Group = 1,
    /// Per-project quota.
    Project = 2,
}

// ── QuotaState ──────────────────────────────────────────────────

/// Current enforcement state of a quota entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QuotaState {
    /// Quota tracking is disabled.
    #[default]
    Off,
    /// Quota is active and within limits.
    On,
    /// Usage exceeds soft limit (hard limit not yet reached).
    Exceeded,
    /// Soft limit exceeded; grace timer is running.
    GracePeriod,
}

// ── QuotaLimits ─────────────────────────────────────────────────

/// Soft and hard limits for blocks and inodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QuotaLimits {
    /// Hard block limit (0 = unlimited).
    pub block_hard: u64,
    /// Soft block limit (0 = unlimited).
    pub block_soft: u64,
    /// Hard inode limit (0 = unlimited).
    pub inode_hard: u64,
    /// Soft inode limit (0 = unlimited).
    pub inode_soft: u64,
}

// ── QuotaUsage ──────────────────────────────────────────────────

/// Current resource usage tracked by the quota subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QuotaUsage {
    /// Number of blocks currently in use.
    pub blocks_used: u64,
    /// Number of inodes currently in use.
    pub inodes_used: u64,
    /// Timestamp when block grace period expires (0 = none).
    pub block_grace_expires: u64,
    /// Timestamp when inode grace period expires (0 = none).
    pub inode_grace_expires: u64,
}

// ── QuotaEntry ──────────────────────────────────────────────────

/// A single quota record for one (id, type) pair.
#[derive(Debug, Clone, Copy)]
pub struct QuotaEntry {
    /// User, group, or project identifier.
    pub id: u32,
    /// Whether this is a user, group, or project quota.
    pub quota_type: QuotaType,
    /// Configured limits.
    pub limits: QuotaLimits,
    /// Current usage counters.
    pub usage: QuotaUsage,
    /// Enforcement state.
    pub state: QuotaState,
    /// Whether this entry slot is in use.
    pub active: bool,
    /// Number of warnings issued to the user.
    pub warnings_issued: u32,
}

impl QuotaEntry {
    /// Create a blank, inactive entry.
    const fn empty() -> Self {
        Self {
            id: 0,
            quota_type: QuotaType::User,
            limits: QuotaLimits {
                block_hard: 0,
                block_soft: 0,
                inode_hard: 0,
                inode_soft: 0,
            },
            usage: QuotaUsage {
                blocks_used: 0,
                inodes_used: 0,
                block_grace_expires: 0,
                inode_grace_expires: 0,
            },
            state: QuotaState::Off,
            active: false,
            warnings_issued: 0,
        }
    }
}

// ── QuotaTable ──────────────────────────────────────────────────

/// Fixed-size table that stores all quota entries for a filesystem.
pub struct QuotaTable {
    /// Quota entry slots.
    entries: [QuotaEntry; MAX_QUOTA_ENTRIES],
    /// Number of active entries.
    count: usize,
    /// Grace period for block soft-limit violations (seconds).
    pub grace_period_blocks: u64,
    /// Grace period for inode soft-limit violations (seconds).
    pub grace_period_inodes: u64,
}

impl Default for QuotaTable {
    fn default() -> Self {
        Self::new()
    }
}

impl QuotaTable {
    /// Create a new, empty quota table with default grace periods.
    pub const fn new() -> Self {
        Self {
            entries: [QuotaEntry::empty(); MAX_QUOTA_ENTRIES],
            count: 0,
            grace_period_blocks: QUOTA_GRACE_PERIOD,
            grace_period_inodes: QUOTA_GRACE_PERIOD,
        }
    }

    /// Set or update the quota limits for `(id, qtype)`.
    ///
    /// If no entry exists yet a new one is created. Returns
    /// [`Error::OutOfMemory`] when the table is full.
    pub fn set_quota(&mut self, id: u32, qtype: QuotaType, limits: QuotaLimits) -> Result<()> {
        // Try to update an existing entry first.
        if let Some(e) = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.id == id && e.quota_type == qtype)
        {
            e.limits = limits;
            e.state = QuotaState::On;
            return Ok(());
        }

        // Allocate a new slot.
        let slot = self
            .entries
            .iter_mut()
            .find(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = QuotaEntry {
            id,
            quota_type: qtype,
            limits,
            usage: QuotaUsage::default(),
            state: QuotaState::On,
            active: true,
            warnings_issued: 0,
        };
        self.count += 1;
        Ok(())
    }

    /// Look up an active quota entry by `(id, qtype)`.
    pub fn get_quota(&self, id: u32, qtype: QuotaType) -> Result<&QuotaEntry> {
        self.entries
            .iter()
            .find(|e| e.active && e.id == id && e.quota_type == qtype)
            .ok_or(Error::NotFound)
    }

    /// Remove a quota entry. Returns [`Error::NotFound`] if absent.
    pub fn remove_quota(&mut self, id: u32, qtype: QuotaType) -> Result<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.id == id && e.quota_type == qtype)
            .ok_or(Error::NotFound)?;

        entry.active = false;
        entry.state = QuotaState::Off;
        self.count -= 1;
        Ok(())
    }

    /// Check whether allocating `blocks` additional blocks is
    /// allowed under the quota for `(id, qtype)`.
    ///
    /// - Hard limit exceeded → [`Error::PermissionDenied`]
    /// - Soft limit exceeded → grace period starts (or enforced
    ///   once expired)
    /// - No matching entry → allocation is allowed.
    pub fn check_block_alloc(
        &mut self,
        id: u32,
        qtype: QuotaType,
        blocks: u64,
        now: u64,
    ) -> Result<()> {
        let gp = self.grace_period_blocks;
        let entry = match self.find_entry_mut(id, qtype) {
            Some(e) => e,
            None => return Ok(()),
        };

        let new_usage = entry.usage.blocks_used.saturating_add(blocks);

        // Hard limit check.
        if entry.limits.block_hard > 0 && new_usage > entry.limits.block_hard {
            return Err(Error::PermissionDenied);
        }

        // Soft limit check.
        if entry.limits.block_soft > 0 && new_usage > entry.limits.block_soft {
            if entry.usage.block_grace_expires == 0 {
                // Start grace period.
                entry.usage.block_grace_expires = now.saturating_add(gp);
                entry.state = QuotaState::GracePeriod;
            } else if now >= entry.usage.block_grace_expires {
                // Grace period expired — deny.
                return Err(Error::PermissionDenied);
            }
        }

        Ok(())
    }

    /// Check whether allocating one additional inode is allowed.
    ///
    /// Semantics mirror [`Self::check_block_alloc`].
    pub fn check_inode_alloc(&mut self, id: u32, qtype: QuotaType, now: u64) -> Result<()> {
        let gp = self.grace_period_inodes;
        let entry = match self.find_entry_mut(id, qtype) {
            Some(e) => e,
            None => return Ok(()),
        };

        let new_usage = entry.usage.inodes_used.saturating_add(1);

        if entry.limits.inode_hard > 0 && new_usage > entry.limits.inode_hard {
            return Err(Error::PermissionDenied);
        }

        if entry.limits.inode_soft > 0 && new_usage > entry.limits.inode_soft {
            if entry.usage.inode_grace_expires == 0 {
                entry.usage.inode_grace_expires = now.saturating_add(gp);
                entry.state = QuotaState::GracePeriod;
            } else if now >= entry.usage.inode_grace_expires {
                return Err(Error::PermissionDenied);
            }
        }

        Ok(())
    }

    /// Charge `blocks` to the quota after a successful allocation.
    ///
    /// Callers must invoke [`Self::check_block_alloc`] first.
    pub fn charge_blocks(
        &mut self,
        id: u32,
        qtype: QuotaType,
        blocks: u64,
        now: u64,
    ) -> Result<()> {
        self.check_block_alloc(id, qtype, blocks, now)?;

        let entry = match self.find_entry_mut(id, qtype) {
            Some(e) => e,
            None => return Ok(()),
        };

        entry.usage.blocks_used = entry.usage.blocks_used.saturating_add(blocks);
        Self::update_state(entry);
        Ok(())
    }

    /// Charge one inode to the quota after a successful allocation.
    ///
    /// Callers must invoke [`Self::check_inode_alloc`] first.
    pub fn charge_inode(&mut self, id: u32, qtype: QuotaType, now: u64) -> Result<()> {
        self.check_inode_alloc(id, qtype, now)?;

        let entry = match self.find_entry_mut(id, qtype) {
            Some(e) => e,
            None => return Ok(()),
        };

        entry.usage.inodes_used = entry.usage.inodes_used.saturating_add(1);
        Self::update_state(entry);
        Ok(())
    }

    /// Release `blocks` from the usage counter.
    pub fn release_blocks(&mut self, id: u32, qtype: QuotaType, blocks: u64) -> Result<()> {
        let entry = self.find_entry_mut(id, qtype).ok_or(Error::NotFound)?;

        entry.usage.blocks_used = entry.usage.blocks_used.saturating_sub(blocks);

        // Clear grace if back under soft limit.
        if entry.limits.block_soft == 0 || entry.usage.blocks_used <= entry.limits.block_soft {
            entry.usage.block_grace_expires = 0;
        }
        Self::update_state(entry);
        Ok(())
    }

    /// Release one inode from the usage counter.
    pub fn release_inode(&mut self, id: u32, qtype: QuotaType) -> Result<()> {
        let entry = self.find_entry_mut(id, qtype).ok_or(Error::NotFound)?;

        entry.usage.inodes_used = entry.usage.inodes_used.saturating_sub(1);

        if entry.limits.inode_soft == 0 || entry.usage.inodes_used <= entry.limits.inode_soft {
            entry.usage.inode_grace_expires = 0;
        }
        Self::update_state(entry);
        Ok(())
    }

    /// Stub: synchronise in-memory quota data to persistent storage.
    ///
    /// Currently returns `Ok(())` — will be wired to the VFS
    /// superblock write path once on-disk quota formats are
    /// implemented.
    pub fn sync(&self) -> Result<()> {
        Ok(())
    }

    /// Return the number of active quota entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no active quota entries exist.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    // ── private helpers ─────────────────────────────────────────

    /// Locate a mutable reference to the entry for `(id, qtype)`.
    fn find_entry_mut(&mut self, id: u32, qtype: QuotaType) -> Option<&mut QuotaEntry> {
        self.entries
            .iter_mut()
            .find(|e| e.active && e.id == id && e.quota_type == qtype)
    }

    /// Recalculate the [`QuotaState`] of an entry based on its
    /// current usage and limits.
    fn update_state(entry: &mut QuotaEntry) {
        let blocks_over_soft =
            entry.limits.block_soft > 0 && entry.usage.blocks_used > entry.limits.block_soft;
        let inodes_over_soft =
            entry.limits.inode_soft > 0 && entry.usage.inodes_used > entry.limits.inode_soft;

        if blocks_over_soft || inodes_over_soft {
            let has_grace =
                entry.usage.block_grace_expires > 0 || entry.usage.inode_grace_expires > 0;
            entry.state = if has_grace {
                QuotaState::GracePeriod
            } else {
                QuotaState::Exceeded
            };
        } else {
            entry.state = QuotaState::On;
        }
    }
}

// ── QuotaInfo ───────────────────────────────────────────────────

/// Summary structure returned by `quotactl` for reporting.
#[derive(Debug, Clone, Copy, Default)]
pub struct QuotaInfo {
    /// Configured limits.
    pub limits: QuotaLimits,
    /// Current usage.
    pub usage: QuotaUsage,
    /// Block grace period (seconds).
    pub grace_period_blocks: u64,
    /// Inode grace period (seconds).
    pub grace_period_inodes: u64,
}
