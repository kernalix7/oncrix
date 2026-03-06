// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! btrfs quota groups (qgroups).
//!
//! btrfs quota groups allow per-subvolume and hierarchical disk usage tracking
//! and enforcement. Each qgroup is identified by a `(level, subvolid)` pair
//! encoded as a 64-bit key: `(level << 48) | subvolid`.
//!
//! # Hierarchy
//!
//! ```text
//! qgroup 1/0  (level-1 parent)
//!   └── qgroup 0/256  (subvol 256)
//!   └── qgroup 0/257  (subvol 257)
//! ```
//!
//! Usage charged to a leaf qgroup propagates up through all ancestor groups.
//!
//! # References
//!
//! - Linux `fs/btrfs/qgroup.c`, `fs/btrfs/qgroup.h`
//! - btrfs documentation: `Documentation/filesystems/btrfs.rst`

use oncrix_lib::{Error, Result};

/// Maximum number of qgroups in one filesystem.
pub const MAX_QGROUPS: usize = 256;
/// Maximum number of qgroup relations (parent-child edges).
pub const MAX_QGROUP_RELATIONS: usize = 512;

/// 64-bit qgroup ID encoding `(level << 48) | subvolid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct QgroupId(pub u64);

impl QgroupId {
    /// Construct a qgroup ID from level and subvolume ID.
    pub const fn new(level: u16, subvolid: u64) -> Self {
        QgroupId(((level as u64) << 48) | (subvolid & 0x0000_ffff_ffff_ffff))
    }

    /// Extract the level (upper 16 bits).
    pub fn level(self) -> u16 {
        (self.0 >> 48) as u16
    }

    /// Extract the subvolume/object ID (lower 48 bits).
    pub fn subvolid(self) -> u64 {
        self.0 & 0x0000_ffff_ffff_ffff
    }
}

/// Disk usage limits for a qgroup.
#[derive(Debug, Clone, Copy, Default)]
pub struct QgroupLimit {
    /// Flags indicating which limits are active (bitmask).
    pub flags: u64,
    /// Maximum exclusive referenced bytes (`0` = unlimited).
    pub max_rfer: u64,
    /// Maximum exclusive exclusive bytes (`0` = unlimited).
    pub max_excl: u64,
    /// Soft limit for referenced bytes (rsv headroom).
    pub rsv_rfer: u64,
    /// Soft limit for exclusive bytes.
    pub rsv_excl: u64,
}

/// Runtime usage counters for a qgroup.
#[derive(Debug, Clone, Copy, Default)]
pub struct QgroupInfo {
    /// Current referenced bytes (shared + exclusive).
    pub rfer: u64,
    /// Current compressed referenced bytes.
    pub rfer_cmpr: u64,
    /// Current exclusively owned bytes.
    pub excl: u64,
    /// Current compressed exclusive bytes.
    pub excl_cmpr: u64,
}

/// A single quota group entry.
#[derive(Debug, Clone)]
pub struct Qgroup {
    /// Unique identifier.
    pub id: QgroupId,
    /// Usage counters.
    pub info: QgroupInfo,
    /// Enforcement limits.
    pub limit: QgroupLimit,
    /// Whether this qgroup is currently active.
    pub active: bool,
}

impl Qgroup {
    /// Create a new, empty qgroup.
    pub fn new(id: QgroupId) -> Self {
        Self {
            id,
            info: QgroupInfo::default(),
            limit: QgroupLimit::default(),
            active: true,
        }
    }

    /// Check whether charging `bytes` of referenced usage would exceed `max_rfer`.
    pub fn would_exceed_rfer(&self, bytes: u64) -> bool {
        if self.limit.max_rfer == 0 {
            return false;
        }
        self.info.rfer.saturating_add(bytes) > self.limit.max_rfer
    }

    /// Check whether charging `bytes` of exclusive usage would exceed `max_excl`.
    pub fn would_exceed_excl(&self, bytes: u64) -> bool {
        if self.limit.max_excl == 0 {
            return false;
        }
        self.info.excl.saturating_add(bytes) > self.limit.max_excl
    }
}

/// A directed parent-child relation between two qgroups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QgroupRelation {
    /// Child qgroup ID.
    pub child: QgroupId,
    /// Parent qgroup ID.
    pub parent: QgroupId,
}

/// In-memory quota group table for one btrfs filesystem.
pub struct QgroupTable {
    qgroups: [Option<Qgroup>; MAX_QGROUPS],
    qgroup_count: usize,
    relations: [QgroupRelation; MAX_QGROUP_RELATIONS],
    relation_count: usize,
    /// Quota enabled on this filesystem.
    enabled: bool,
}

impl QgroupTable {
    /// Create an empty qgroup table.
    pub const fn new() -> Self {
        Self {
            qgroups: [const { None }; MAX_QGROUPS],
            qgroup_count: 0,
            relations: [QgroupRelation {
                child: QgroupId(0),
                parent: QgroupId(0),
            }; MAX_QGROUP_RELATIONS],
            relation_count: 0,
            enabled: false,
        }
    }

    /// Enable quota accounting.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable quota accounting.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Whether quota is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Create a new qgroup. Returns `AlreadyExists` if `id` is taken.
    pub fn create(&mut self, id: QgroupId) -> Result<()> {
        if self.find(id).is_some() {
            return Err(Error::AlreadyExists);
        }
        if self.qgroup_count >= MAX_QGROUPS {
            return Err(Error::OutOfMemory);
        }
        self.qgroups[self.qgroup_count] = Some(Qgroup::new(id));
        self.qgroup_count += 1;
        Ok(())
    }

    /// Destroy a qgroup by ID. Returns `NotFound` if absent.
    pub fn destroy(&mut self, id: QgroupId) -> Result<()> {
        let pos = self.qgroups[..self.qgroup_count]
            .iter()
            .position(|q| q.as_ref().map(|q| q.id == id).unwrap_or(false));
        match pos {
            None => Err(Error::NotFound),
            Some(idx) => {
                self.qgroup_count -= 1;
                self.qgroups[idx] = self.qgroups[self.qgroup_count].take();
                // Remove relations involving this qgroup.
                let mut i = 0;
                while i < self.relation_count {
                    let r = self.relations[i];
                    if r.child == id || r.parent == id {
                        self.relation_count -= 1;
                        self.relations[i] = self.relations[self.relation_count];
                    } else {
                        i += 1;
                    }
                }
                Ok(())
            }
        }
    }

    /// Find a qgroup by ID (immutable).
    pub fn find(&self, id: QgroupId) -> Option<&Qgroup> {
        self.qgroups[..self.qgroup_count]
            .iter()
            .filter_map(|q| q.as_ref())
            .find(|q| q.id == id)
    }

    /// Find a qgroup by ID (mutable).
    pub fn find_mut(&mut self, id: QgroupId) -> Option<&mut Qgroup> {
        self.qgroups[..self.qgroup_count]
            .iter_mut()
            .filter_map(|q| q.as_mut())
            .find(|q| q.id == id)
    }

    /// Add a parent-child relation. Returns `AlreadyExists` if it exists.
    pub fn add_relation(&mut self, child: QgroupId, parent: QgroupId) -> Result<()> {
        if self.find(child).is_none() || self.find(parent).is_none() {
            return Err(Error::NotFound);
        }
        for i in 0..self.relation_count {
            if self.relations[i].child == child && self.relations[i].parent == parent {
                return Err(Error::AlreadyExists);
            }
        }
        if self.relation_count >= MAX_QGROUP_RELATIONS {
            return Err(Error::OutOfMemory);
        }
        self.relations[self.relation_count] = QgroupRelation { child, parent };
        self.relation_count += 1;
        Ok(())
    }

    /// Remove a parent-child relation.
    pub fn remove_relation(&mut self, child: QgroupId, parent: QgroupId) -> Result<()> {
        let pos = self.relations[..self.relation_count]
            .iter()
            .position(|r| r.child == child && r.parent == parent);
        match pos {
            None => Err(Error::NotFound),
            Some(idx) => {
                self.relation_count -= 1;
                self.relations[idx] = self.relations[self.relation_count];
                Ok(())
            }
        }
    }

    /// Charge `rfer_delta` referenced bytes and `excl_delta` exclusive bytes to
    /// qgroup `id` and all its ancestors.
    ///
    /// If quota is not enabled, this is a no-op.
    /// Returns `PermissionDenied` if any limit would be exceeded.
    pub fn charge(&mut self, id: QgroupId, rfer_delta: i64, excl_delta: i64) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        // Collect ancestors (breadth-first, bounded by MAX_QGROUPS).
        let mut to_charge = [QgroupId(0); MAX_QGROUPS];
        let mut tc_count = 0usize;
        to_charge[tc_count] = id;
        tc_count += 1;

        let mut visited = 0usize;
        while visited < tc_count {
            let cur = to_charge[visited];
            visited += 1;
            for i in 0..self.relation_count {
                let r = self.relations[i];
                if r.child == cur {
                    // Check not already in list.
                    let already = to_charge[..tc_count].iter().any(|&x| x == r.parent);
                    if !already && tc_count < MAX_QGROUPS {
                        to_charge[tc_count] = r.parent;
                        tc_count += 1;
                    }
                }
            }
        }

        // Pre-flight limit check.
        for i in 0..tc_count {
            let qg = self.find(to_charge[i]).ok_or(Error::NotFound)?;
            if rfer_delta > 0 && qg.would_exceed_rfer(rfer_delta as u64) {
                return Err(Error::PermissionDenied);
            }
            if excl_delta > 0 && qg.would_exceed_excl(excl_delta as u64) {
                return Err(Error::PermissionDenied);
            }
        }

        // Apply deltas.
        for i in 0..tc_count {
            if let Some(qg) = self.find_mut(to_charge[i]) {
                if rfer_delta >= 0 {
                    qg.info.rfer = qg.info.rfer.saturating_add(rfer_delta as u64);
                } else {
                    qg.info.rfer = qg.info.rfer.saturating_sub((-rfer_delta) as u64);
                }
                if excl_delta >= 0 {
                    qg.info.excl = qg.info.excl.saturating_add(excl_delta as u64);
                } else {
                    qg.info.excl = qg.info.excl.saturating_sub((-excl_delta) as u64);
                }
            }
        }
        Ok(())
    }

    /// Set limits for a qgroup.
    pub fn set_limit(&mut self, id: QgroupId, limit: QgroupLimit) -> Result<()> {
        let qg = self.find_mut(id).ok_or(Error::NotFound)?;
        qg.limit = limit;
        Ok(())
    }

    /// Iterate all qgroups.
    pub fn iter(&self) -> impl Iterator<Item = &Qgroup> {
        self.qgroups[..self.qgroup_count]
            .iter()
            .filter_map(|q| q.as_ref())
    }
}

impl Default for QgroupTable {
    fn default() -> Self {
        Self::new()
    }
}
