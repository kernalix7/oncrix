// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Quota operations interface — get/set limits and usage tracking.
//!
//! Provides the `QuotaOps` trait and supporting types for filesystem quota
//! management, covering both user and group quotas (POSIX.1-2024).

use oncrix_lib::{Error, Result};

/// Maximum number of quota entries per quota type.
pub const MAX_QUOTA_ENTRIES: usize = 128;

/// Quota type — corresponds to POSIX `USRQUOTA` / `GRPQUOTA`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaType {
    /// User quota (indexed by uid).
    User,
    /// Group quota (indexed by gid).
    Group,
    /// Project quota (indexed by project ID).
    Project,
}

/// Quota limits for a single entity (user/group/project).
#[derive(Debug, Clone, Copy, Default)]
pub struct QuotaLimits {
    /// Soft block limit (in filesystem blocks).
    pub block_soft: u64,
    /// Hard block limit (in filesystem blocks).
    pub block_hard: u64,
    /// Soft inode limit.
    pub inode_soft: u64,
    /// Hard inode limit.
    pub inode_hard: u64,
    /// Grace period for soft-limit excess (seconds; 0 = use filesystem default).
    pub block_grace: u32,
    /// Grace period for soft inode-limit excess (seconds).
    pub inode_grace: u32,
}

/// Current quota usage for a single entity.
#[derive(Debug, Clone, Copy, Default)]
pub struct QuotaUsage {
    /// Number of blocks currently used.
    pub blocks_used: u64,
    /// Number of inodes currently used.
    pub inodes_used: u64,
    /// Timestamp when the block soft-limit was first exceeded (0 = none).
    pub block_grace_start: i64,
    /// Timestamp when the inode soft-limit was first exceeded (0 = none).
    pub inode_grace_start: i64,
}

/// Combined quota entry (limits + usage).
#[derive(Debug, Clone, Copy, Default)]
pub struct QuotaEntry {
    /// Entity identifier (uid / gid / project id).
    pub id: u32,
    /// Whether this entry is valid/active.
    pub active: bool,
    /// Quota limits.
    pub limits: QuotaLimits,
    /// Current usage.
    pub usage: QuotaUsage,
}

impl QuotaEntry {
    /// Create a new active entry with zero limits and usage.
    pub const fn new(id: u32) -> Self {
        Self {
            id,
            active: true,
            limits: QuotaLimits {
                block_soft: 0,
                block_hard: 0,
                inode_soft: 0,
                inode_hard: 0,
                block_grace: 0,
                inode_grace: 0,
            },
            usage: QuotaUsage {
                blocks_used: 0,
                inodes_used: 0,
                block_grace_start: 0,
                inode_grace_start: 0,
            },
        }
    }

    /// Check whether a block allocation of `delta` blocks would be allowed.
    pub fn check_block_limit(&self, delta: u64, now: i64) -> Result<()> {
        let new_usage = self.usage.blocks_used.saturating_add(delta);
        if self.limits.block_hard > 0 && new_usage > self.limits.block_hard {
            return Err(Error::PermissionDenied);
        }
        if self.limits.block_soft > 0 && new_usage > self.limits.block_soft {
            // Check grace period.
            if self.usage.block_grace_start > 0 {
                let grace = self.limits.block_grace as i64;
                if grace > 0 && (now - self.usage.block_grace_start) > grace {
                    return Err(Error::PermissionDenied);
                }
            }
        }
        Ok(())
    }

    /// Check whether an inode allocation would be allowed.
    pub fn check_inode_limit(&self, delta: u64, now: i64) -> Result<()> {
        let new_usage = self.usage.inodes_used.saturating_add(delta);
        if self.limits.inode_hard > 0 && new_usage > self.limits.inode_hard {
            return Err(Error::PermissionDenied);
        }
        if self.limits.inode_soft > 0 && new_usage > self.limits.inode_soft {
            if self.usage.inode_grace_start > 0 {
                let grace = self.limits.inode_grace as i64;
                if grace > 0 && (now - self.usage.inode_grace_start) > grace {
                    return Err(Error::PermissionDenied);
                }
            }
        }
        Ok(())
    }
}

/// Quota operations that a filesystem must implement to support quotas.
pub trait QuotaOps {
    /// Enable quota accounting for the given type on this filesystem.
    fn quota_on(&mut self, sb_id: u64, qtype: QuotaType) -> Result<()>;

    /// Disable quota accounting.
    fn quota_off(&mut self, sb_id: u64, qtype: QuotaType) -> Result<()>;

    /// Read the quota entry for a given entity ID.
    fn get_quota(&self, sb_id: u64, qtype: QuotaType, id: u32) -> Result<QuotaEntry>;

    /// Write (set) limits for a given entity ID.
    fn set_quota(
        &mut self,
        sb_id: u64,
        qtype: QuotaType,
        id: u32,
        limits: QuotaLimits,
    ) -> Result<()>;

    /// Record a block allocation delta (positive = alloc, negative = free).
    fn alloc_block(&mut self, sb_id: u64, uid: u32, gid: u32, delta: i64) -> Result<()>;

    /// Record an inode allocation delta.
    fn alloc_inode(&mut self, sb_id: u64, uid: u32, gid: u32, delta: i64) -> Result<()>;

    /// Sync quota data to disk.
    fn sync_quotas(&mut self, sb_id: u64) -> Result<()>;
}

/// In-memory quota table for a single quota type.
pub struct QuotaTable {
    entries: [QuotaEntry; MAX_QUOTA_ENTRIES],
    qtype: QuotaType,
    enabled: bool,
    count: usize,
}

impl QuotaTable {
    /// Create a new, disabled quota table.
    pub fn new(qtype: QuotaType) -> Self {
        Self {
            entries: [const { QuotaEntry::new(0) }; MAX_QUOTA_ENTRIES],
            qtype,
            enabled: false,
            count: 0,
        }
    }

    /// Enable this quota table.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable this quota table.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Return the quota type.
    pub fn qtype(&self) -> QuotaType {
        self.qtype
    }

    /// Find an entry by ID, or return None.
    pub fn find(&self, id: u32) -> Option<&QuotaEntry> {
        self.entries[..self.count]
            .iter()
            .find(|e| e.id == id && e.active)
    }

    /// Find an entry by ID (mutable), or return None.
    pub fn find_mut(&mut self, id: u32) -> Option<&mut QuotaEntry> {
        let count = self.count;
        self.entries[..count]
            .iter_mut()
            .find(|e| e.id == id && e.active)
    }

    /// Get or create an entry for the given ID.
    pub fn get_or_create(&mut self, id: u32) -> Result<&mut QuotaEntry> {
        // Check if exists.
        let count = self.count;
        if let Some(pos) = self.entries[..count]
            .iter()
            .position(|e| e.id == id && e.active)
        {
            return Ok(&mut self.entries[pos]);
        }
        // Allocate new slot.
        if self.count >= MAX_QUOTA_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.entries[idx] = QuotaEntry::new(id);
        self.count += 1;
        Ok(&mut self.entries[idx])
    }

    /// Apply a block delta to an entity's usage.
    pub fn apply_block_delta(&mut self, id: u32, delta: i64) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let entry = self.get_or_create(id)?;
        if delta >= 0 {
            entry.usage.blocks_used = entry.usage.blocks_used.saturating_add(delta as u64);
        } else {
            entry.usage.blocks_used = entry.usage.blocks_used.saturating_sub((-delta) as u64);
        }
        Ok(())
    }

    /// Apply an inode delta.
    pub fn apply_inode_delta(&mut self, id: u32, delta: i64) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let entry = self.get_or_create(id)?;
        if delta >= 0 {
            entry.usage.inodes_used = entry.usage.inodes_used.saturating_add(delta as u64);
        } else {
            entry.usage.inodes_used = entry.usage.inodes_used.saturating_sub((-delta) as u64);
        }
        Ok(())
    }

    /// Return number of active entries.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Return whether quota is enabled on this table.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Check whether an operation is allowed given the quota state.
///
/// If `enabled` is false the check always passes.
pub fn quota_check_blocks(entry: &QuotaEntry, delta: u64, now: i64) -> Result<()> {
    if !entry.active {
        return Ok(());
    }
    entry.check_block_limit(delta, now)
}

/// Check inode quota.
pub fn quota_check_inodes(entry: &QuotaEntry, delta: u64, now: i64) -> Result<()> {
    if !entry.active {
        return Ok(());
    }
    entry.check_inode_limit(delta, now)
}
