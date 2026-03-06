// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Mount namespace management.
//!
//! Provides isolated mount trees per namespace for container
//! isolation. Supports mount propagation (private, shared, slave,
//! unbindable), pivot_root, and reference counting.
//!
//! Reference: Linux `fs/namespace.c`, `fs/pnode.c`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// Maximum number of mount namespaces.
const MAX_MNT_NS: usize = 64;

/// Maximum mount entries per namespace.
const MAX_MOUNTS_PER_NS: usize = 64;

/// Maximum mount point path length.
const MAX_MOUNT_PATH: usize = 128;

/// Maximum filesystem type name length.
const MAX_FS_TYPE: usize = 32;

/// ID for the initial (root) mount namespace.
const INIT_MNT_NS_ID: u64 = 1;

/// Maximum depth for nested mount namespaces.
const MAX_NS_DEPTH: u32 = 32;

// ── Mount propagation types ─────────────────────────────────────

/// Mount event propagation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationType {
    /// Events are not propagated.
    Private,
    /// Events propagate bidirectionally among peers.
    Shared,
    /// Receives events from master, does not propagate.
    Slave,
    /// Cannot be bind-mounted; events not propagated.
    Unbindable,
}

/// Mount flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct MountFlags(u32);

impl MountFlags {
    /// No flags.
    pub const NONE: Self = Self(0);
    /// Read-only mount.
    pub const RDONLY: Self = Self(1 << 0);
    /// Suppress access time updates.
    pub const NOATIME: Self = Self(1 << 1);
    /// No setuid/setgid.
    pub const NOSUID: Self = Self(1 << 2);
    /// No device special files.
    pub const NODEV: Self = Self(1 << 3);
    /// No execution.
    pub const NOEXEC: Self = Self(1 << 4);
    /// Bind mount.
    pub const BIND: Self = Self(1 << 5);
    /// Check if a flag is set.
    pub const fn contains(self, flag: Self) -> bool {
        (self.0 & flag.0) == flag.0
    }
    /// Raw value.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// A single mount point within a namespace.
#[derive(Debug, Clone, Copy)]
struct MountEntry {
    /// Mount ID (unique within the namespace).
    mount_id: u64,
    /// Parent mount ID (0 for root mount).
    parent_id: u64,
    /// Mount point path.
    mount_point: [u8; MAX_MOUNT_PATH],
    /// Length of mount_point.
    mount_point_len: u32,
    /// Filesystem type name.
    fs_type: [u8; MAX_FS_TYPE],
    /// Length of fs_type.
    fs_type_len: u32,
    /// Mount flags.
    flags: MountFlags,
    /// Propagation type.
    propagation: PropagationType,
    /// Shared peer group ID (0 if not shared).
    peer_group: u64,
    /// Master group ID for slave mounts (0 if not slave).
    master_group: u64,
    /// Whether this entry is active.
    active: bool,
}

/// Namespace state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NsState {
    /// Slot is free.
    Free,
    /// Namespace is active.
    Active,
}

/// A mount namespace.
#[derive(Debug, Clone, Copy)]
struct MntNamespace {
    /// Namespace ID.
    id: u64,
    /// Parent namespace ID (0 for root ns).
    parent_id: u64,
    /// Reference count.
    ref_count: u32,
    /// Depth in the namespace hierarchy.
    depth: u32,
    /// Mount entries.
    mounts: [MountEntry; MAX_MOUNTS_PER_NS],
    /// Number of active mounts.
    mount_count: u32,
    /// Next mount ID.
    next_mount_id: u64,
    /// Root mount ID.
    root_mount_id: u64,
    /// Lifecycle state.
    state: NsState,
}

/// Statistics for mount namespace operations.
#[derive(Debug, Clone, Copy)]
pub struct MntNsStats {
    /// Total namespaces created.
    pub total_created: u64,
    /// Total namespaces destroyed.
    pub total_destroyed: u64,
    /// Total mount operations.
    pub total_mounts: u64,
    /// Total unmount operations.
    pub total_unmounts: u64,
    /// Total pivot_root operations.
    pub total_pivots: u64,
    /// Current active namespace count.
    pub active_count: u32,
}

/// Global mount namespace manager.
pub struct MntNamespaceTable {
    /// Namespace pool.
    namespaces: [MntNamespace; MAX_MNT_NS],
    /// Next namespace ID.
    next_ns_id: u64,
    /// Next peer group ID.
    next_peer_group: u64,
    /// Statistics.
    stats: MntNsStats,
}

impl MntNamespaceTable {
    /// Create a new mount namespace table.
    pub const fn new() -> Self {
        let entry = MountEntry {
            mount_id: 0,
            parent_id: 0,
            mount_point: [0u8; MAX_MOUNT_PATH],
            mount_point_len: 0,
            fs_type: [0u8; MAX_FS_TYPE],
            fs_type_len: 0,
            flags: MountFlags::NONE,
            propagation: PropagationType::Private,
            peer_group: 0,
            master_group: 0,
            active: false,
        };
        let ns = MntNamespace {
            id: 0,
            parent_id: 0,
            ref_count: 0,
            depth: 0,
            mounts: [entry; MAX_MOUNTS_PER_NS],
            mount_count: 0,
            next_mount_id: 1,
            root_mount_id: 0,
            state: NsState::Free,
        };
        Self {
            namespaces: [ns; MAX_MNT_NS],
            next_ns_id: INIT_MNT_NS_ID,
            next_peer_group: 1,
            stats: MntNsStats {
                total_created: 0,
                total_destroyed: 0,
                total_mounts: 0,
                total_unmounts: 0,
                total_pivots: 0,
                active_count: 0,
            },
        }
    }

    /// Create a new empty mount namespace.
    pub fn create_ns(&mut self, parent_id: u64) -> Result<u64> {
        let parent_depth = if parent_id == 0 {
            0
        } else {
            let pidx = self.find_ns(parent_id)?;
            let d = self.namespaces[pidx].depth + 1;
            if d >= MAX_NS_DEPTH {
                return Err(Error::InvalidArgument);
            }
            d
        };
        let pos = self
            .namespaces
            .iter()
            .position(|n| n.state == NsState::Free)
            .ok_or(Error::OutOfMemory)?;
        let ns_id = self.next_ns_id;
        self.next_ns_id += 1;
        let ns = &mut self.namespaces[pos];
        ns.id = ns_id;
        ns.parent_id = parent_id;
        ns.ref_count = 1;
        ns.depth = parent_depth;
        ns.mount_count = 0;
        ns.next_mount_id = 1;
        ns.root_mount_id = 0;
        ns.state = NsState::Active;
        self.stats.total_created += 1;
        self.stats.active_count += 1;
        Ok(ns_id)
    }

    /// Clone a mount namespace, copying its mount tree.
    pub fn clone_ns(&mut self, source_id: u64) -> Result<u64> {
        let src_idx = self.find_ns(source_id)?;
        let parent_id = self.namespaces[src_idx].parent_id;
        let src_mounts = self.namespaces[src_idx].mounts;
        let src_count = self.namespaces[src_idx].mount_count;
        let src_next_mid = self.namespaces[src_idx].next_mount_id;
        let src_root = self.namespaces[src_idx].root_mount_id;
        let src_depth = self.namespaces[src_idx].depth;
        let pos = self
            .namespaces
            .iter()
            .position(|n| n.state == NsState::Free)
            .ok_or(Error::OutOfMemory)?;
        let ns_id = self.next_ns_id;
        self.next_ns_id += 1;
        let ns = &mut self.namespaces[pos];
        ns.id = ns_id;
        ns.parent_id = parent_id;
        ns.ref_count = 1;
        ns.depth = src_depth;
        ns.mounts = src_mounts;
        ns.mount_count = src_count;
        ns.next_mount_id = src_next_mid;
        ns.root_mount_id = src_root;
        ns.state = NsState::Active;
        // Convert shared mounts to private in clone.
        for m in &mut ns.mounts[..src_count as usize] {
            if m.active && m.propagation == PropagationType::Shared {
                m.propagation = PropagationType::Private;
                m.peer_group = 0;
            }
        }
        self.stats.total_created += 1;
        self.stats.active_count += 1;
        Ok(ns_id)
    }

    /// Add a mount point to a namespace.
    pub fn add_mount(
        &mut self,
        ns_id: u64,
        parent_mount_id: u64,
        mount_point: &[u8],
        fs_type: &[u8],
        flags: MountFlags,
    ) -> Result<u64> {
        if mount_point.is_empty() || mount_point.len() > MAX_MOUNT_PATH {
            return Err(Error::InvalidArgument);
        }
        if fs_type.len() > MAX_FS_TYPE {
            return Err(Error::InvalidArgument);
        }
        let ns_idx = self.find_ns(ns_id)?;
        let ns = &mut self.namespaces[ns_idx];
        if ns.mount_count as usize >= MAX_MOUNTS_PER_NS {
            return Err(Error::OutOfMemory);
        }
        let slot_pos = ns
            .mounts
            .iter()
            .position(|m| !m.active)
            .ok_or(Error::OutOfMemory)?;
        let mid = ns.next_mount_id;
        ns.next_mount_id += 1;
        let entry = &mut ns.mounts[slot_pos];
        entry.mount_id = mid;
        entry.parent_id = parent_mount_id;
        entry.mount_point[..mount_point.len()].copy_from_slice(mount_point);
        entry.mount_point_len = mount_point.len() as u32;
        if !fs_type.is_empty() {
            entry.fs_type[..fs_type.len()].copy_from_slice(fs_type);
            entry.fs_type_len = fs_type.len() as u32;
        }
        entry.flags = flags;
        entry.propagation = PropagationType::Private;
        entry.peer_group = 0;
        entry.master_group = 0;
        entry.active = true;
        ns.mount_count += 1;
        if ns.root_mount_id == 0 {
            ns.root_mount_id = mid;
        }
        self.stats.total_mounts += 1;
        Ok(mid)
    }

    /// Remove a mount from a namespace.
    pub fn remove_mount(&mut self, ns_id: u64, mount_id: u64) -> Result<()> {
        let ns_idx = self.find_ns(ns_id)?;
        let ns = &mut self.namespaces[ns_idx];
        let pos = ns
            .mounts
            .iter()
            .position(|m| m.active && m.mount_id == mount_id)
            .ok_or(Error::NotFound)?;
        // Cannot unmount root.
        if mount_id == ns.root_mount_id {
            return Err(Error::PermissionDenied);
        }
        // Check for children.
        let has_children = ns
            .mounts
            .iter()
            .any(|m| m.active && m.parent_id == mount_id);
        if has_children {
            return Err(Error::Busy);
        }
        ns.mounts[pos].active = false;
        ns.mount_count = ns.mount_count.saturating_sub(1);
        self.stats.total_unmounts += 1;
        Ok(())
    }

    /// Perform pivot_root: swap root and old_root.
    ///
    /// The new root mount becomes the namespace root and the
    /// previous root is moved to old_root_mount.
    pub fn pivot_root(&mut self, ns_id: u64, new_root_mount_id: u64) -> Result<()> {
        let ns_idx = self.find_ns(ns_id)?;
        let ns = &mut self.namespaces[ns_idx];
        let found = ns
            .mounts
            .iter()
            .any(|m| m.active && m.mount_id == new_root_mount_id);
        if !found {
            return Err(Error::NotFound);
        }
        ns.root_mount_id = new_root_mount_id;
        self.stats.total_pivots += 1;
        Ok(())
    }

    /// Set mount propagation type.
    pub fn set_propagation(
        &mut self,
        ns_id: u64,
        mount_id: u64,
        prop: PropagationType,
    ) -> Result<()> {
        let ns_idx = self.find_ns(ns_id)?;
        let ns = &mut self.namespaces[ns_idx];
        let pos = ns
            .mounts
            .iter()
            .position(|m| m.active && m.mount_id == mount_id)
            .ok_or(Error::NotFound)?;
        ns.mounts[pos].propagation = prop;
        if prop == PropagationType::Shared {
            let pg = self.next_peer_group;
            self.next_peer_group += 1;
            ns.mounts[pos].peer_group = pg;
        } else {
            ns.mounts[pos].peer_group = 0;
        }
        Ok(())
    }

    /// Increment the reference count on a namespace.
    pub fn get_ns_ref(&mut self, ns_id: u64) -> Result<()> {
        let idx = self.find_ns(ns_id)?;
        self.namespaces[idx].ref_count += 1;
        Ok(())
    }

    /// Decrement the reference count, freeing if zero.
    pub fn put_ns_ref(&mut self, ns_id: u64) -> Result<()> {
        let idx = self.find_ns(ns_id)?;
        let ns = &mut self.namespaces[idx];
        ns.ref_count = ns.ref_count.saturating_sub(1);
        if ns.ref_count == 0 {
            ns.state = NsState::Free;
            self.stats.total_destroyed += 1;
            self.stats.active_count = self.stats.active_count.saturating_sub(1);
        }
        Ok(())
    }

    /// Return statistics.
    pub fn stats(&self) -> &MntNsStats {
        &self.stats
    }

    // ── Internal helpers ────────────────────────────────────────

    /// Find a namespace by ID.
    fn find_ns(&self, ns_id: u64) -> Result<usize> {
        self.namespaces
            .iter()
            .position(|n| n.state == NsState::Active && n.id == ns_id)
            .ok_or(Error::NotFound)
    }
}
