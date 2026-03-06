// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VFS mount namespace management.
//!
//! A mount namespace (mnt_namespace) is a container for a set of mount
//! points.  Processes within the same namespace share the same filesystem
//! view; `clone(CLONE_NEWNS)` or `unshare(CLONE_NEWNS)` creates a new
//! independent namespace.  This module models the namespace lifecycle and
//! the per-namespace mount tree.

use oncrix_lib::{Error, Result};

/// Maximum number of concurrent mount namespaces.
pub const MNT_NS_MAX: usize = 1024;

/// Maximum number of mounts per namespace.
pub const MNT_NS_MAX_MOUNTS: usize = 100_000;

/// Unique namespace identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MntNsId(pub u64);

impl MntNsId {
    /// The initial (root) mount namespace.
    pub const INIT: Self = Self(1);
}

/// State of a mount namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MntNsState {
    /// Namespace is alive and referenced by at least one process.
    Active,
    /// Namespace is being torn down (no more references).
    Zombie,
}

/// Statistics for one mount namespace.
#[derive(Debug, Clone, Copy, Default)]
pub struct MntNsStats {
    /// Number of mounts in this namespace.
    pub mount_count: u32,
    /// Peak mount count.
    pub peak_mounts: u32,
    /// Total `mount()` syscalls executed in this namespace.
    pub total_mounts: u64,
    /// Total `umount()` syscalls.
    pub total_umounts: u64,
}

/// A mount namespace.
pub struct MntNamespace {
    /// Namespace ID.
    pub id: MntNsId,
    /// Number of tasks sharing this namespace.
    pub ref_count: u32,
    /// Current state.
    pub state: MntNsState,
    /// User namespace ID that created this namespace (simplified: just a uid).
    pub owner_uid: u32,
    /// Statistics.
    pub stats: MntNsStats,
    /// Whether this namespace is locked (cannot be modified by unprivileged users).
    pub locked: bool,
    /// Parent namespace ID (0 for the initial namespace).
    pub parent_id: MntNsId,
}

impl MntNamespace {
    /// Create a new active mount namespace.
    pub fn new(id: MntNsId, owner_uid: u32, parent_id: MntNsId) -> Self {
        Self {
            id,
            ref_count: 1,
            state: MntNsState::Active,
            owner_uid,
            stats: MntNsStats::default(),
            locked: false,
            parent_id,
        }
    }

    /// Record a mount operation.
    pub fn on_mount(&mut self) -> Result<()> {
        if self.stats.mount_count as usize >= MNT_NS_MAX_MOUNTS {
            return Err(Error::OutOfMemory);
        }
        self.stats.mount_count += 1;
        self.stats.total_mounts += 1;
        if self.stats.mount_count > self.stats.peak_mounts {
            self.stats.peak_mounts = self.stats.mount_count;
        }
        Ok(())
    }

    /// Record an umount operation.
    pub fn on_umount(&mut self) -> Result<()> {
        if self.stats.mount_count == 0 {
            return Err(Error::InvalidArgument);
        }
        self.stats.mount_count -= 1;
        self.stats.total_umounts += 1;
        Ok(())
    }

    /// Increment reference count.
    pub fn get(&mut self) {
        self.ref_count += 1;
    }

    /// Decrement reference count.  Returns `true` if zero.
    pub fn put(&mut self) -> bool {
        if self.ref_count > 0 {
            self.ref_count -= 1;
        }
        if self.ref_count == 0 {
            self.state = MntNsState::Zombie;
            true
        } else {
            false
        }
    }

    /// Whether this namespace is the initial (root) namespace.
    pub fn is_init_ns(&self) -> bool {
        self.id == MntNsId::INIT
    }
}

/// Global mount namespace registry.
pub struct MntNsRegistry {
    namespaces: [Option<MntNamespace>; MNT_NS_MAX],
    count: usize,
    next_id: u64,
}

impl MntNsRegistry {
    /// Create a registry pre-populated with the initial namespace.
    pub fn new() -> Self {
        let mut reg = Self {
            namespaces: [const { None }; MNT_NS_MAX],
            count: 0,
            next_id: 2,
        };
        // Insert the initial namespace.
        let init_ns = MntNamespace::new(MntNsId::INIT, 0, MntNsId::INIT);
        reg.namespaces[0] = Some(init_ns);
        reg.count = 1;
        reg
    }

    /// Create a new namespace as a child of `parent`.
    pub fn create(&mut self, owner_uid: u32, parent_id: MntNsId) -> Result<MntNsId> {
        if self.count >= MNT_NS_MAX {
            return Err(Error::OutOfMemory);
        }
        let id = MntNsId(self.next_id);
        self.next_id += 1;
        let ns = MntNamespace::new(id, owner_uid, parent_id);
        for slot in &mut self.namespaces {
            if slot.is_none() {
                *slot = Some(ns);
                self.count += 1;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a namespace by ID.
    pub fn get(&self, id: MntNsId) -> Option<&MntNamespace> {
        self.namespaces
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|ns| ns.id == id)
    }

    /// Look up a mutable namespace by ID.
    pub fn get_mut(&mut self, id: MntNsId) -> Option<&mut MntNamespace> {
        self.namespaces
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|ns| ns.id == id)
    }

    /// Remove a zombie namespace from the registry.
    pub fn reap(&mut self, id: MntNsId) -> Result<()> {
        for slot in &mut self.namespaces {
            if slot
                .as_ref()
                .map(|ns| ns.id == id && ns.state == MntNsState::Zombie)
                == Some(true)
            {
                *slot = None;
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Number of live namespaces.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for MntNsRegistry {
    fn default() -> Self {
        Self::new()
    }
}
