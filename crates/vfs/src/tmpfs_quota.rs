// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! tmpfs disk quota support.
//!
//! Implements per-user and per-group resource limits for tmpfs mounts,
//! tracking inode and block usage against configurable soft and hard limits.
//!
//! # Quota semantics
//!
//! - **Hard limit**: absolute ceiling; allocation fails if it would be exceeded.
//! - **Soft limit**: advisory threshold; may be exceeded temporarily (grace
//!   period not implemented here — just a flag).
//! - **Grace period**: tracked as a boolean `over_soft` flag.
//!
//! # Design
//!
//! - [`QuotaId`] — user or group identifier
//! - [`QuotaLimits`] — soft and hard limits for inodes and blocks
//! - [`QuotaUsage`] — current inode and block usage for one subject
//! - [`TmpfsQuota`] — quota table for one tmpfs mount
//! - `quota_check` — validate a proposed allocation
//! - `quota_charge` — record an allocation
//! - `quota_uncharge` — record a release
//!
//! # References
//!
//! - Linux `fs/quota/dquot.c`
//! - `include/linux/quota.h`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of quota entries in a single tmpfs mount table.
const MAX_QUOTA_ENTRIES: usize = 128;

/// Quota type: user quota.
pub const QUOTA_TYPE_USER: u8 = 0;

/// Quota type: group quota.
pub const QUOTA_TYPE_GROUP: u8 = 1;

// ---------------------------------------------------------------------------
// QuotaId
// ---------------------------------------------------------------------------

/// Identifier for a quota subject (UID or GID).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuotaId {
    /// User or group ID.
    pub id: u32,
    /// Quota type (`QUOTA_TYPE_USER` or `QUOTA_TYPE_GROUP`).
    pub quota_type: u8,
}

impl QuotaId {
    /// Create a user quota ID.
    pub const fn user(uid: u32) -> Self {
        Self {
            id: uid,
            quota_type: QUOTA_TYPE_USER,
        }
    }

    /// Create a group quota ID.
    pub const fn group(gid: u32) -> Self {
        Self {
            id: gid,
            quota_type: QUOTA_TYPE_GROUP,
        }
    }
}

// ---------------------------------------------------------------------------
// QuotaLimits
// ---------------------------------------------------------------------------

/// Resource limits for a quota subject.
#[derive(Clone, Copy, Debug, Default)]
pub struct QuotaLimits {
    /// Soft limit on inode count (0 = no limit).
    pub inode_soft: u64,
    /// Hard limit on inode count (0 = no limit).
    pub inode_hard: u64,
    /// Soft limit on block count (in 1 KiB blocks; 0 = no limit).
    pub block_soft: u64,
    /// Hard limit on block count (0 = no limit).
    pub block_hard: u64,
}

// ---------------------------------------------------------------------------
// QuotaUsage
// ---------------------------------------------------------------------------

/// Current resource usage for one quota subject.
#[derive(Clone, Copy, Debug, Default)]
pub struct QuotaUsage {
    /// Number of inodes owned.
    pub inodes: u64,
    /// Number of 1 KiB blocks in use.
    pub blocks: u64,
    /// Whether usage exceeds the soft inode limit.
    pub over_soft_inodes: bool,
    /// Whether usage exceeds the soft block limit.
    pub over_soft_blocks: bool,
}

// ---------------------------------------------------------------------------
// Quota entry
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
struct QuotaEntry {
    id: QuotaId,
    limits: QuotaLimits,
    usage: QuotaUsage,
    active: bool,
}

impl QuotaEntry {
    const fn empty() -> Self {
        Self {
            id: QuotaId {
                id: 0,
                quota_type: 0,
            },
            limits: QuotaLimits {
                inode_soft: 0,
                inode_hard: 0,
                block_soft: 0,
                block_hard: 0,
            },
            usage: QuotaUsage {
                inodes: 0,
                blocks: 0,
                over_soft_inodes: false,
                over_soft_blocks: false,
            },
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// TmpfsQuota
// ---------------------------------------------------------------------------

/// Per-mount quota table for a tmpfs instance.
pub struct TmpfsQuota {
    entries: [QuotaEntry; MAX_QUOTA_ENTRIES],
    count: usize,
}

impl TmpfsQuota {
    /// Create an empty quota table.
    pub const fn new() -> Self {
        Self {
            entries: [const { QuotaEntry::empty() }; MAX_QUOTA_ENTRIES],
            count: 0,
        }
    }

    /// Set (or update) limits for a quota subject.
    ///
    /// Creates a new entry if `id` is not yet tracked.
    /// Returns `Err(OutOfMemory)` if the table is full.
    pub fn set_limits(&mut self, id: QuotaId, limits: QuotaLimits) -> Result<()> {
        if let Some(e) = self.find_entry_mut(id) {
            e.limits = limits;
            return Ok(());
        }
        if self.count >= MAX_QUOTA_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = QuotaEntry {
            id,
            limits,
            usage: QuotaUsage::default(),
            active: true,
        };
        self.count += 1;
        Ok(())
    }

    /// Check whether allocating `inodes` inodes and `blocks` blocks for `id`
    /// would violate the hard limit.
    ///
    /// Returns `Ok(())` if the allocation is permitted.
    /// Returns `Err(PermissionDenied)` if it would exceed the hard limit.
    /// Returns `Ok(())` (with no entry update) if `id` has no quota set.
    pub fn quota_check(&self, id: QuotaId, inodes: u64, blocks: u64) -> Result<()> {
        let e = match self.find_entry(id) {
            Some(e) => e,
            None => return Ok(()), // no quota set for this id
        };
        if e.limits.inode_hard > 0 && e.usage.inodes.saturating_add(inodes) > e.limits.inode_hard {
            return Err(Error::PermissionDenied);
        }
        if e.limits.block_hard > 0 && e.usage.blocks.saturating_add(blocks) > e.limits.block_hard {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }

    /// Record an allocation of `inodes` inodes and `blocks` blocks for `id`.
    ///
    /// Automatically creates an entry with zero limits if `id` is unknown.
    /// Updates the `over_soft_*` flags if the soft limit is exceeded.
    ///
    /// Returns `Err(OutOfMemory)` if a new entry would overflow the table.
    pub fn quota_charge(&mut self, id: QuotaId, inodes: u64, blocks: u64) -> Result<()> {
        // Ensure we have an entry.
        if self.find_entry(id).is_none() {
            if self.count >= MAX_QUOTA_ENTRIES {
                return Err(Error::OutOfMemory);
            }
            self.entries[self.count] = QuotaEntry {
                id,
                limits: QuotaLimits::default(),
                usage: QuotaUsage::default(),
                active: true,
            };
            self.count += 1;
        }

        let e = self.find_entry_mut(id).unwrap();
        e.usage.inodes = e.usage.inodes.saturating_add(inodes);
        e.usage.blocks = e.usage.blocks.saturating_add(blocks);

        if e.limits.inode_soft > 0 && e.usage.inodes > e.limits.inode_soft {
            e.usage.over_soft_inodes = true;
        }
        if e.limits.block_soft > 0 && e.usage.blocks > e.limits.block_soft {
            e.usage.over_soft_blocks = true;
        }
        Ok(())
    }

    /// Record a release of `inodes` inodes and `blocks` blocks for `id`.
    ///
    /// No-op if `id` has no quota entry (e.g., was never charged).
    /// Updates the `over_soft_*` flags if usage drops below the soft limit.
    pub fn quota_uncharge(&mut self, id: QuotaId, inodes: u64, blocks: u64) {
        let e = match self.find_entry_mut(id) {
            Some(e) => e,
            None => return,
        };
        e.usage.inodes = e.usage.inodes.saturating_sub(inodes);
        e.usage.blocks = e.usage.blocks.saturating_sub(blocks);

        if e.limits.inode_soft > 0 && e.usage.inodes <= e.limits.inode_soft {
            e.usage.over_soft_inodes = false;
        }
        if e.limits.block_soft > 0 && e.usage.blocks <= e.limits.block_soft {
            e.usage.over_soft_blocks = false;
        }
    }

    /// Return the current usage for `id`, or `None` if no entry exists.
    pub fn get_usage(&self, id: QuotaId) -> Option<QuotaUsage> {
        self.find_entry(id).map(|e| e.usage)
    }

    /// Return the limits for `id`, or `None` if no entry exists.
    pub fn get_limits(&self, id: QuotaId) -> Option<QuotaLimits> {
        self.find_entry(id).map(|e| e.limits)
    }

    /// Remove the quota entry for `id`.
    ///
    /// Returns `Err(NotFound)` if no entry exists.
    pub fn remove(&mut self, id: QuotaId) -> Result<()> {
        let idx = self.entries[..self.count]
            .iter()
            .position(|e| e.active && e.id == id)
            .ok_or(Error::NotFound)?;
        self.entries[idx] = self.entries[self.count - 1];
        self.entries[self.count - 1] = QuotaEntry::empty();
        self.count -= 1;
        Ok(())
    }

    /// Return the number of active quota entries.
    pub fn entry_count(&self) -> usize {
        self.count
    }

    // ── Private helpers ────────────────────────────────────────────

    fn find_entry(&self, id: QuotaId) -> Option<&QuotaEntry> {
        self.entries[..self.count]
            .iter()
            .find(|e| e.active && e.id == id)
    }

    fn find_entry_mut(&mut self, id: QuotaId) -> Option<&mut QuotaEntry> {
        self.entries[..self.count]
            .iter_mut()
            .find(|e| e.active && e.id == id)
    }
}
