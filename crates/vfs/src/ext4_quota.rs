// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ext4 disk quota support.
//!
//! Implements per-UID, per-GID, and per-project disk quota tracking for ext4.
//! Quota accounting records the number of blocks and inodes in use for each
//! entity and enforces soft and hard limits, with a configurable grace period
//! for soft-limit violations.
//!
//! # Design
//!
//! - [`QuotaType`] — UID / GID / Project selector
//! - [`QuotaLimits`] — hard/soft block and inode limits
//! - [`QuotaUsage`] — live usage counters
//! - [`DiskQuota`] — combines limits + usage + grace-period state
//! - [`QuotaTable`] — fixed-size table of all active quota entries
//! - `charge` / `release` — accounting helpers
//! - `enforce_limits` — returns an error when a hard limit is exceeded
//!
//! # References
//!
//! - Linux `fs/ext4/super.c` (quota ops), `fs/quota/dquot.c`
//! - POSIX `quotactl` — `susv5-html/functions/quotactl.html`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of quota entries in [`QuotaTable`].
pub const MAX_QUOTA_ENTRIES: usize = 256;

/// Default grace period for soft-limit violations, in seconds (7 days).
pub const DEFAULT_GRACE_SECONDS: u64 = 7 * 24 * 3600;

/// Sentinel value meaning "no limit".
pub const QUOTA_NO_LIMIT: u64 = 0;

/// Block size used for quota accounting (512-byte units, matching POSIX dqblk).
pub const QUOTA_BLOCK_SIZE: u32 = 512;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Which principal a quota entry tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaType {
    /// Per-user quota (UID-based).
    User,
    /// Per-group quota (GID-based).
    Group,
    /// Per-project quota (project-ID-based, ext4 project feature).
    Project,
}

/// Hard and soft limits for a single quota entity.
#[derive(Debug, Clone, Copy, Default)]
pub struct QuotaLimits {
    /// Hard block limit in 512-byte units; 0 = no limit.
    pub block_hard: u64,
    /// Soft block limit in 512-byte units; 0 = no limit.
    pub block_soft: u64,
    /// Hard inode limit; 0 = no limit.
    pub inode_hard: u64,
    /// Soft inode limit; 0 = no limit.
    pub inode_soft: u64,
}

/// Current resource usage for a single quota entity.
#[derive(Debug, Clone, Copy, Default)]
pub struct QuotaUsage {
    /// Blocks currently allocated (512-byte units).
    pub blocks: u64,
    /// Inodes currently allocated.
    pub inodes: u64,
}

/// State of a soft-limit violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GraceState {
    /// No violation in progress.
    #[default]
    Ok,
    /// Soft limit exceeded; grace period expires at `deadline`.
    Grace { deadline: u64 },
    /// Grace period expired; writes must be rejected.
    Expired,
}

/// A single disk quota entry combining limits, usage, and grace state.
#[derive(Debug, Default)]
pub struct DiskQuota {
    /// Quota type (user / group / project).
    pub quota_type: Option<QuotaType>,
    /// Principal ID (UID / GID / project-ID).
    pub id: u32,
    /// Resource limits.
    pub limits: QuotaLimits,
    /// Current resource usage.
    pub usage: QuotaUsage,
    /// Block grace state.
    pub block_grace: GraceState,
    /// Inode grace state.
    pub inode_grace: GraceState,
    /// Whether this entry is active.
    pub active: bool,
}

impl DiskQuota {
    /// Create a new active quota entry.
    pub fn new(quota_type: QuotaType, id: u32, limits: QuotaLimits) -> Self {
        Self {
            quota_type: Some(quota_type),
            id,
            limits,
            usage: QuotaUsage::default(),
            block_grace: GraceState::Ok,
            inode_grace: GraceState::Ok,
            active: true,
        }
    }

    /// Charge `blocks` 512-byte units and `inodes` inodes against this entry.
    ///
    /// Updates grace state when soft limits are crossed.  Returns
    /// [`Error::PermissionDenied`] when a hard limit would be exceeded.
    pub fn charge(&mut self, blocks: u64, inodes: u64, now: u64) -> Result<()> {
        self.enforce_block_limit(self.usage.blocks + blocks, now)?;
        self.enforce_inode_limit(self.usage.inodes + inodes, now)?;
        self.usage.blocks += blocks;
        self.usage.inodes += inodes;
        self.update_grace(now);
        Ok(())
    }

    /// Release `blocks` and `inodes` previously charged to this entry.
    pub fn release(&mut self, blocks: u64, inodes: u64) {
        self.usage.blocks = self.usage.blocks.saturating_sub(blocks);
        self.usage.inodes = self.usage.inodes.saturating_sub(inodes);
        // Reset grace if usage drops back below soft limit.
        if self.limits.block_soft == QUOTA_NO_LIMIT || self.usage.blocks <= self.limits.block_soft {
            self.block_grace = GraceState::Ok;
        }
        if self.limits.inode_soft == QUOTA_NO_LIMIT || self.usage.inodes <= self.limits.inode_soft {
            self.inode_grace = GraceState::Ok;
        }
    }

    /// Check block hard/grace limits for a prospective new total.
    fn enforce_block_limit(&self, new_total: u64, now: u64) -> Result<()> {
        if self.limits.block_hard != QUOTA_NO_LIMIT && new_total > self.limits.block_hard {
            return Err(Error::PermissionDenied);
        }
        if self.limits.block_soft != QUOTA_NO_LIMIT && new_total > self.limits.block_soft {
            if let GraceState::Expired = self.block_grace {
                return Err(Error::PermissionDenied);
            }
            if let GraceState::Grace { deadline } = self.block_grace {
                if now >= deadline {
                    return Err(Error::PermissionDenied);
                }
            }
        }
        Ok(())
    }

    /// Check inode hard/grace limits for a prospective new total.
    fn enforce_inode_limit(&self, new_total: u64, now: u64) -> Result<()> {
        if self.limits.inode_hard != QUOTA_NO_LIMIT && new_total > self.limits.inode_hard {
            return Err(Error::PermissionDenied);
        }
        if self.limits.inode_soft != QUOTA_NO_LIMIT && new_total > self.limits.inode_soft {
            if let GraceState::Expired = self.inode_grace {
                return Err(Error::PermissionDenied);
            }
            if let GraceState::Grace { deadline } = self.inode_grace {
                if now >= deadline {
                    return Err(Error::PermissionDenied);
                }
            }
        }
        Ok(())
    }

    /// Refresh grace state based on current usage and `now`.
    fn update_grace(&mut self, now: u64) {
        if self.limits.block_soft != QUOTA_NO_LIMIT && self.usage.blocks > self.limits.block_soft {
            if self.block_grace == GraceState::Ok {
                self.block_grace = GraceState::Grace {
                    deadline: now + DEFAULT_GRACE_SECONDS,
                };
            }
        }
        if self.limits.inode_soft != QUOTA_NO_LIMIT && self.usage.inodes > self.limits.inode_soft {
            if self.inode_grace == GraceState::Ok {
                self.inode_grace = GraceState::Grace {
                    deadline: now + DEFAULT_GRACE_SECONDS,
                };
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Quota table
// ---------------------------------------------------------------------------

/// Fixed-size table of disk quota entries for a mounted ext4 filesystem.
pub struct QuotaTable {
    entries: [DiskQuota; MAX_QUOTA_ENTRIES],
    count: usize,
    /// Whether quota accounting is enabled on this filesystem.
    pub enabled: bool,
}

impl Default for QuotaTable {
    fn default() -> Self {
        Self::new()
    }
}

impl QuotaTable {
    /// Create an empty, disabled quota table.
    pub fn new() -> Self {
        // DiskQuota has all-zero Default, so we can use array init.
        Self {
            entries: core::array::from_fn(|_| DiskQuota::default()),
            count: 0,
            enabled: false,
        }
    }

    /// Enable quota accounting.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable quota accounting (entries are retained but not enforced).
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Insert or update a quota entry for `(quota_type, id)`.
    ///
    /// Returns [`Error::OutOfMemory`] when the table is full.
    pub fn set_quota(&mut self, quota_type: QuotaType, id: u32, limits: QuotaLimits) -> Result<()> {
        // Search for an existing entry.
        for entry in self.entries[..self.count].iter_mut() {
            if entry.active && entry.id == id && entry.quota_type == Some(quota_type) {
                entry.limits = limits;
                return Ok(());
            }
        }
        // Allocate a new slot.
        if self.count >= MAX_QUOTA_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = DiskQuota::new(quota_type, id, limits);
        self.count += 1;
        Ok(())
    }

    /// Remove the quota entry for `(quota_type, id)`.
    pub fn remove_quota(&mut self, quota_type: QuotaType, id: u32) {
        if let Some(pos) = self.entries[..self.count]
            .iter()
            .position(|e| e.active && e.id == id && e.quota_type == Some(quota_type))
        {
            self.entries[pos].active = false;
        }
    }

    /// Charge resources to `(quota_type, id)`.  No-op when quota is disabled.
    pub fn charge(
        &mut self,
        quota_type: QuotaType,
        id: u32,
        blocks: u64,
        inodes: u64,
        now: u64,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if let Some(pos) = self.entries[..self.count]
            .iter()
            .position(|e| e.active && e.id == id && e.quota_type == Some(quota_type))
        {
            self.entries[pos].charge(blocks, inodes, now)?;
        }
        Ok(())
    }

    /// Release resources from `(quota_type, id)`.  No-op when quota is disabled.
    pub fn release(&mut self, quota_type: QuotaType, id: u32, blocks: u64, inodes: u64) {
        if !self.enabled {
            return;
        }
        if let Some(pos) = self.entries[..self.count]
            .iter()
            .position(|e| e.active && e.id == id && e.quota_type == Some(quota_type))
        {
            self.entries[pos].release(blocks, inodes);
        }
    }

    /// Look up usage for `(quota_type, id)`.
    pub fn get_usage(&self, quota_type: QuotaType, id: u32) -> Option<QuotaUsage> {
        self.entries[..self.count]
            .iter()
            .find(|e| e.active && e.id == id && e.quota_type == Some(quota_type))
            .map(|e| e.usage)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(bh: u64, bs: u64, ih: u64, is: u64) -> QuotaLimits {
        QuotaLimits {
            block_hard: bh,
            block_soft: bs,
            inode_hard: ih,
            inode_soft: is,
        }
    }

    #[test]
    fn charge_and_release() {
        let mut table = QuotaTable::new();
        table.enable();
        table
            .set_quota(QuotaType::User, 1000, limits(1000, 800, 100, 80))
            .unwrap();
        table.charge(QuotaType::User, 1000, 100, 5, 0).unwrap();
        let usage = table.get_usage(QuotaType::User, 1000).unwrap();
        assert_eq!(usage.blocks, 100);
        assert_eq!(usage.inodes, 5);
        table.release(QuotaType::User, 1000, 50, 2);
        let usage = table.get_usage(QuotaType::User, 1000).unwrap();
        assert_eq!(usage.blocks, 50);
    }

    #[test]
    fn hard_limit_enforced() {
        let mut table = QuotaTable::new();
        table.enable();
        table
            .set_quota(QuotaType::User, 42, limits(100, 80, 0, 0))
            .unwrap();
        let result = table.charge(QuotaType::User, 42, 101, 0, 0);
        assert!(matches!(result, Err(Error::PermissionDenied)));
    }

    #[test]
    fn disabled_quota_allows_all() {
        let mut table = QuotaTable::new();
        // quota is disabled by default
        table
            .set_quota(QuotaType::Group, 5, limits(1, 1, 1, 1))
            .unwrap();
        // charge beyond limits — should succeed because quota is disabled
        assert!(table.charge(QuotaType::Group, 5, 9999, 9999, 0).is_ok());
    }
}
