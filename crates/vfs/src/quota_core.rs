// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Disk quota core — dquot operations.
//!
//! Provides the quota enforcement layer for disk usage limits on a
//! per-user and per-group basis. This module tracks block and inode
//! consumption against configurable soft and hard limits, enforcing
//! POSIX-compatible quota semantics.
//!
//! # Quota types
//!
//! - `USRQUOTA` — per-user quota
//! - `GRPQUOTA` — per-group quota
//! - `PRJQUOTA` — per-project quota
//!
//! # Limit semantics
//!
//! - **Hard limit**: Absolute maximum; writes fail if exceeded.
//! - **Soft limit**: Advisory; grace period applies before enforcement.
//! - **Grace period**: Time allowed to exceed the soft limit (default: 7 days).
//!
//! # References
//!
//! - Linux `quota(1)`, `quotactl(2)`, `dquot.c`
//! - POSIX.1-2024 — `statvfs` structure (quota-adjacent)

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// User quota type.
pub const USRQUOTA: u32 = 0;
/// Group quota type.
pub const GRPQUOTA: u32 = 1;
/// Project quota type.
pub const PRJQUOTA: u32 = 2;

/// Maximum number of dquot entries tracked.
pub const MAX_DQUOTS: usize = 512;

/// Default grace period for soft-limit violations (7 days in seconds).
pub const DEFAULT_GRACE_SECS: u64 = 7 * 24 * 3600;

// ── DquotId ──────────────────────────────────────────────────────────

/// Identity of a quota subject (user, group, or project).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DquotId {
    /// Quota type (`USRQUOTA`, `GRPQUOTA`, or `PRJQUOTA`).
    pub qtype: u32,
    /// Numeric ID (UID, GID, or project ID).
    pub id: u32,
}

impl DquotId {
    /// Create a new `DquotId`.
    pub const fn new(qtype: u32, id: u32) -> Self {
        Self { qtype, id }
    }
}

// ── DquotLimits ──────────────────────────────────────────────────────

/// Block and inode limits for a single quota subject.
#[derive(Debug, Clone, Copy, Default)]
pub struct DquotLimits {
    /// Hard limit on blocks (in 1-KiB units).
    pub block_hardlimit: u64,
    /// Soft limit on blocks (in 1-KiB units).
    pub block_softlimit: u64,
    /// Hard limit on inodes.
    pub inode_hardlimit: u64,
    /// Soft limit on inodes.
    pub inode_softlimit: u64,
    /// Grace period for block soft-limit violations (seconds).
    pub block_grace_secs: u64,
    /// Grace period for inode soft-limit violations (seconds).
    pub inode_grace_secs: u64,
}

impl DquotLimits {
    /// Create limits with the default grace periods.
    pub const fn with_defaults() -> Self {
        Self {
            block_hardlimit: 0,
            block_softlimit: 0,
            inode_hardlimit: 0,
            inode_softlimit: 0,
            block_grace_secs: DEFAULT_GRACE_SECS,
            inode_grace_secs: DEFAULT_GRACE_SECS,
        }
    }
}

// ── DquotUsage ───────────────────────────────────────────────────────

/// Current usage and grace-period state for a single quota subject.
#[derive(Debug, Clone, Copy, Default)]
pub struct DquotUsage {
    /// Current block usage (1-KiB units).
    pub blocks: u64,
    /// Current inode usage.
    pub inodes: u64,
    /// Timestamp when the block soft-limit grace began (0 = not started).
    pub block_grace_start: u64,
    /// Timestamp when the inode soft-limit grace began (0 = not started).
    pub inode_grace_start: u64,
}

// ── Dquot ────────────────────────────────────────────────────────────

/// A single disk quota entry (dquot).
#[derive(Debug, Clone, Copy)]
pub struct Dquot {
    /// Identity of the quota subject.
    pub id: DquotId,
    /// Configured limits.
    pub limits: DquotLimits,
    /// Current usage.
    pub usage: DquotUsage,
    /// Whether this entry is active (in use).
    pub active: bool,
}

impl Dquot {
    /// Create a new quota entry.
    pub const fn new(id: DquotId) -> Self {
        Self {
            id,
            limits: DquotLimits::with_defaults(),
            usage: DquotUsage {
                blocks: 0,
                inodes: 0,
                block_grace_start: 0,
                inode_grace_start: 0,
            },
            active: true,
        }
    }

    /// Check whether the block allocation of `delta` blocks is permitted.
    ///
    /// Returns `Err(PermissionDenied)` if it would exceed the hard limit,
    /// or if the soft-limit grace period has expired.
    pub fn check_block_alloc(&self, delta: u64, now_secs: u64) -> Result<()> {
        let new_blocks = self.usage.blocks.saturating_add(delta);
        if self.limits.block_hardlimit > 0 && new_blocks > self.limits.block_hardlimit {
            return Err(Error::PermissionDenied);
        }
        if self.limits.block_softlimit > 0 && new_blocks > self.limits.block_softlimit {
            if self.usage.block_grace_start > 0 {
                let elapsed = now_secs.saturating_sub(self.usage.block_grace_start);
                if elapsed >= self.limits.block_grace_secs {
                    return Err(Error::PermissionDenied);
                }
            }
        }
        Ok(())
    }

    /// Check whether allocating `delta` inodes is permitted.
    pub fn check_inode_alloc(&self, delta: u64, now_secs: u64) -> Result<()> {
        let new_inodes = self.usage.inodes.saturating_add(delta);
        if self.limits.inode_hardlimit > 0 && new_inodes > self.limits.inode_hardlimit {
            return Err(Error::PermissionDenied);
        }
        if self.limits.inode_softlimit > 0 && new_inodes > self.limits.inode_softlimit {
            if self.usage.inode_grace_start > 0 {
                let elapsed = now_secs.saturating_sub(self.usage.inode_grace_start);
                if elapsed >= self.limits.inode_grace_secs {
                    return Err(Error::PermissionDenied);
                }
            }
        }
        Ok(())
    }

    /// Charge `delta` blocks; starts grace timer if soft limit is crossed.
    pub fn charge_blocks(&mut self, delta: u64, now_secs: u64) {
        self.usage.blocks = self.usage.blocks.saturating_add(delta);
        if self.limits.block_softlimit > 0
            && self.usage.blocks > self.limits.block_softlimit
            && self.usage.block_grace_start == 0
        {
            self.usage.block_grace_start = now_secs;
        }
    }

    /// Release `delta` blocks; resets grace timer if back under soft limit.
    pub fn release_blocks(&mut self, delta: u64) {
        self.usage.blocks = self.usage.blocks.saturating_sub(delta);
        if self.limits.block_softlimit == 0 || self.usage.blocks <= self.limits.block_softlimit {
            self.usage.block_grace_start = 0;
        }
    }

    /// Charge `delta` inodes; starts grace timer if soft limit is crossed.
    pub fn charge_inodes(&mut self, delta: u64, now_secs: u64) {
        self.usage.inodes = self.usage.inodes.saturating_add(delta);
        if self.limits.inode_softlimit > 0
            && self.usage.inodes > self.limits.inode_softlimit
            && self.usage.inode_grace_start == 0
        {
            self.usage.inode_grace_start = now_secs;
        }
    }

    /// Release `delta` inodes; resets grace timer if back under soft limit.
    pub fn release_inodes(&mut self, delta: u64) {
        self.usage.inodes = self.usage.inodes.saturating_sub(delta);
        if self.limits.inode_softlimit == 0 || self.usage.inodes <= self.limits.inode_softlimit {
            self.usage.inode_grace_start = 0;
        }
    }
}

// ── QuotaTable ───────────────────────────────────────────────────────

/// System-wide quota table.
pub struct QuotaTable {
    entries: [Option<Dquot>; MAX_DQUOTS],
    count: usize,
}

impl QuotaTable {
    /// Create an empty quota table.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; MAX_DQUOTS],
            count: 0,
        }
    }

    /// Find a dquot entry (immutable).
    pub fn find(&self, id: DquotId) -> Option<&Dquot> {
        for slot in self.entries.iter() {
            if let Some(d) = slot {
                if d.id == id && d.active {
                    return Some(d);
                }
            }
        }
        None
    }

    /// Find a dquot entry (mutable), creating it if absent.
    pub fn find_or_create(&mut self, id: DquotId) -> Result<&mut Dquot> {
        // Check if it already exists.
        for i in 0..MAX_DQUOTS {
            if let Some(d) = &self.entries[i] {
                if d.id == id && d.active {
                    return Ok(self.entries[i].as_mut().ok_or(Error::NotFound)?);
                }
            }
        }
        if self.count >= MAX_DQUOTS {
            return Err(Error::OutOfMemory);
        }
        let free_idx = (0..MAX_DQUOTS)
            .find(|&i| self.entries[i].is_none())
            .ok_or(Error::OutOfMemory)?;
        self.entries[free_idx] = Some(Dquot::new(id));
        self.count += 1;
        Ok(self.entries[free_idx].as_mut().ok_or(Error::OutOfMemory)?)
    }

    /// Remove a dquot entry.
    pub fn remove(&mut self, id: DquotId) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if let Some(d) = slot {
                if d.id == id {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Check and charge block allocation for `id`.
    pub fn alloc_blocks(&mut self, id: DquotId, delta: u64, now_secs: u64) -> Result<()> {
        let dq = self.find_or_create(id)?;
        dq.check_block_alloc(delta, now_secs)?;
        dq.charge_blocks(delta, now_secs);
        Ok(())
    }

    /// Release block usage for `id`.
    pub fn free_blocks(&mut self, id: DquotId, delta: u64) -> Result<()> {
        let dq = self.find_or_create(id)?;
        dq.release_blocks(delta);
        Ok(())
    }

    /// Check and charge inode allocation for `id`.
    pub fn alloc_inodes(&mut self, id: DquotId, delta: u64, now_secs: u64) -> Result<()> {
        let dq = self.find_or_create(id)?;
        dq.check_inode_alloc(delta, now_secs)?;
        dq.charge_inodes(delta, now_secs);
        Ok(())
    }

    /// Release inode usage for `id`.
    pub fn free_inodes(&mut self, id: DquotId, delta: u64) -> Result<()> {
        let dq = self.find_or_create(id)?;
        dq.release_inodes(delta);
        Ok(())
    }

    /// Returns the number of active quota entries.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for QuotaTable {
    fn default() -> Self {
        Self::new()
    }
}

// Global quota operations are performed through a QuotaTable instance
// held by the VFS superblock, avoiding `static mut`.
