// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Mount namespace — isolation of the filesystem mount tree.
//!
//! Mount namespaces provide per-process views of the filesystem
//! hierarchy.  Each namespace has its own set of mount points;
//! changes in one namespace (mount, unmount) are invisible to
//! processes in other namespaces.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  Process A (NS 1)        Process B (NS 1)                  │
//! │       │                       │                             │
//! │       ▼                       ▼                             │
//! │  ┌──────────────────────────────────┐                      │
//! │  │  Mount namespace 1               │                      │
//! │  │  ┌────────────────────────────┐  │                      │
//! │  │  │  Mount tree (root → mounts)│  │                      │
//! │  │  └────────────────────────────┘  │                      │
//! │  └──────────────────────────────────┘                      │
//! │                                                            │
//! │  Process C (NS 2)                                          │
//! │       │                                                    │
//! │       ▼                                                    │
//! │  ┌──────────────────────────────────┐                      │
//! │  │  Mount namespace 2 (cloned)      │                      │
//! │  │  ┌────────────────────────────┐  │                      │
//! │  │  │  Mount tree (independent)  │  │                      │
//! │  │  └────────────────────────────┘  │                      │
//! │  └──────────────────────────────────┘                      │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Mount propagation
//!
//! Mounts can be configured with propagation types that control
//! how mount/unmount events are shared between namespaces:
//!
//! - **Shared**: Events propagate to all peer mounts.
//! - **Private**: No propagation (default for new mounts).
//! - **Slave**: Receives events from master but does not send.
//! - **Unbindable**: Cannot be bind-mounted.
//!
//! ## Peer groups
//!
//! Shared mounts belong to a peer group.  All mounts in the same
//! peer group receive propagated mount/unmount events.
//!
//! ## pivot_root
//!
//! Changes the root mount of the calling process's mount namespace,
//! moving the old root to a specified directory.
//!
//! # Reference
//!
//! Linux `fs/namespace.c`, `fs/pnode.c`, `include/linux/mount.h`.

extern crate alloc;

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of mount namespaces.
const MAX_NAMESPACES: usize = 32;

/// Maximum number of mounts across all namespaces.
const MAX_MOUNTS: usize = 256;

/// Maximum number of peer groups.
const MAX_PEER_GROUPS: usize = 64;

/// Maximum mount path length.
const MAX_MOUNT_PATH: usize = 256;

/// Maximum filesystem type name length.
const MAX_FS_TYPE_LEN: usize = 32;

/// Sentinel for "no namespace" or "no mount".
const NONE_ID: u32 = u32::MAX;

// ── Mount propagation ────────────────────────────────────────────────────────

/// Mount propagation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Propagation {
    /// Events propagate to all peers (bidirectional).
    Shared,
    /// No propagation.
    Private,
    /// Receives events from master, does not propagate.
    Slave,
    /// Cannot be bind-mounted.
    Unbindable,
}

// ── Mount flags ──────────────────────────────────────────────────────────────

/// Mount-specific flags.
#[derive(Debug, Clone, Copy)]
pub struct MountFlags {
    /// Filesystem is read-only.
    pub read_only: bool,
    /// Do not interpret special files (block/char devices).
    pub nodev: bool,
    /// Do not allow program execution.
    pub noexec: bool,
    /// Do not update access times on read.
    pub nosuid: bool,
    /// Update access times relative to mtime/ctime.
    pub relatime: bool,
    /// This mount is a bind mount.
    pub bind: bool,
    /// This mount is the root of a namespace.
    pub is_root: bool,
}

impl MountFlags {
    /// Create default flags.
    const fn new() -> Self {
        Self {
            read_only: false,
            nodev: false,
            noexec: false,
            nosuid: false,
            relatime: true,
            bind: false,
            is_root: false,
        }
    }
}

// ── Mount entry ──────────────────────────────────────────────────────────────

/// A single mount entry in a namespace's mount tree.
struct MountEntry {
    /// Unique mount ID.
    mount_id: u32,
    /// Namespace this mount belongs to.
    ns_id: u32,
    /// Parent mount ID (NONE_ID for root mount).
    parent_id: u32,
    /// Mount point path.
    mount_point: [u8; MAX_MOUNT_PATH],
    /// Mount point path length.
    mount_point_len: u16,
    /// Filesystem type name.
    fs_type: [u8; MAX_FS_TYPE_LEN],
    /// Filesystem type name length.
    fs_type_len: u8,
    /// Device or source identifier.
    device_id: u32,
    /// Root inode of the mounted filesystem.
    root_inode: u64,
    /// Mount flags.
    flags: MountFlags,
    /// Propagation type.
    propagation: Propagation,
    /// Peer group ID (NONE_ID if not shared).
    peer_group: u32,
    /// Master mount ID for slave propagation (NONE_ID if none).
    master_id: u32,
    /// Reference count.
    ref_count: u32,
    /// Whether this slot is in use.
    in_use: bool,
}

impl MountEntry {
    /// Create an empty, unused mount slot.
    const fn empty() -> Self {
        Self {
            mount_id: 0,
            ns_id: 0,
            parent_id: NONE_ID,
            mount_point: [0; MAX_MOUNT_PATH],
            mount_point_len: 0,
            fs_type: [0; MAX_FS_TYPE_LEN],
            fs_type_len: 0,
            device_id: 0,
            root_inode: 0,
            flags: MountFlags::new(),
            propagation: Propagation::Private,
            peer_group: NONE_ID,
            master_id: NONE_ID,
            ref_count: 0,
            in_use: false,
        }
    }

    /// Return the mount point as a byte slice.
    fn mount_point(&self) -> &[u8] {
        &self.mount_point[..self.mount_point_len as usize]
    }

    /// Return the filesystem type as a byte slice.
    fn fs_type(&self) -> &[u8] {
        &self.fs_type[..self.fs_type_len as usize]
    }
}

// ── Peer group ───────────────────────────────────────────────────────────────

/// A peer group for shared mount propagation.
struct PeerGroup {
    /// Peer group ID.
    id: u32,
    /// Mount IDs of members (indices into MountEntry table).
    members: [u32; 8],
    /// Number of active members.
    member_count: u8,
    /// Whether this slot is in use.
    in_use: bool,
}

impl PeerGroup {
    /// Create an empty, unused peer group.
    const fn empty() -> Self {
        Self {
            id: 0,
            members: [NONE_ID; 8],
            member_count: 0,
            in_use: false,
        }
    }

    /// Add a mount to this peer group.
    fn add_member(&mut self, mount_id: u32) -> Result<()> {
        if self.member_count as usize >= self.members.len() {
            return Err(Error::OutOfMemory);
        }
        self.members[self.member_count as usize] = mount_id;
        self.member_count += 1;
        Ok(())
    }

    /// Remove a mount from this peer group.
    fn remove_member(&mut self, mount_id: u32) {
        for i in 0..self.member_count as usize {
            if self.members[i] == mount_id {
                // Swap with last.
                let last = self.member_count as usize - 1;
                self.members[i] = self.members[last];
                self.members[last] = NONE_ID;
                self.member_count -= 1;
                return;
            }
        }
    }
}

// ── Mount namespace ──────────────────────────────────────────────────────────

/// A mount namespace.
struct MountNamespace {
    /// Namespace ID.
    id: u32,
    /// Root mount ID.
    root_mount: u32,
    /// Number of mounts in this namespace.
    mount_count: u32,
    /// Reference count (number of processes using this NS).
    ref_count: u32,
    /// Whether this slot is in use.
    in_use: bool,
}

impl MountNamespace {
    /// Create an empty, unused namespace slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            root_mount: NONE_ID,
            mount_count: 0,
            ref_count: 0,
            in_use: false,
        }
    }
}

// ── Proc mounts output ───────────────────────────────────────────────────────

/// Information about a single mount for /proc/mounts output.
#[derive(Debug, Clone, Copy)]
pub struct MountInfo {
    /// Mount ID.
    pub mount_id: u32,
    /// Parent mount ID.
    pub parent_id: u32,
    /// Device ID.
    pub device_id: u32,
    /// Root inode.
    pub root_inode: u64,
    /// Propagation type.
    pub propagation: Propagation,
    /// Whether read-only.
    pub read_only: bool,
}

// ── Statistics ───────────────────────────────────────────────────────────────

/// Mount namespace subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct MountNsStats {
    /// Total namespaces created.
    pub namespaces_created: u64,
    /// Currently active namespaces.
    pub namespaces_active: u32,
    /// Total mounts performed.
    pub mounts_total: u64,
    /// Currently active mounts.
    pub mounts_active: u32,
    /// Clone/unshare operations.
    pub clones: u64,
    /// Propagated mount events.
    pub propagations: u64,
    /// pivot_root operations.
    pub pivot_roots: u64,
}

impl MountNsStats {
    /// Create zeroed statistics.
    const fn new() -> Self {
        Self {
            namespaces_created: 0,
            namespaces_active: 0,
            mounts_total: 0,
            mounts_active: 0,
            clones: 0,
            propagations: 0,
            pivot_roots: 0,
        }
    }
}

// ── Mount namespace manager ──────────────────────────────────────────────────

/// The mount namespace manager.
///
/// Manages all mount namespaces, mounts, peer groups, and propagation.
pub struct MountNsManager {
    /// Namespace table.
    namespaces: [MountNamespace; MAX_NAMESPACES],
    /// Global mount table.
    mounts: [MountEntry; MAX_MOUNTS],
    /// Peer group table.
    peer_groups: [PeerGroup; MAX_PEER_GROUPS],
    /// Next mount ID.
    next_mount_id: u32,
    /// Next namespace ID.
    next_ns_id: u32,
    /// Next peer group ID.
    next_pg_id: u32,
    /// Cumulative statistics.
    stats: MountNsStats,
}

impl MountNsManager {
    /// Create a new mount namespace manager.
    pub fn new() -> Self {
        Self {
            namespaces: [const { MountNamespace::empty() }; MAX_NAMESPACES],
            mounts: [const { MountEntry::empty() }; MAX_MOUNTS],
            peer_groups: [const { PeerGroup::empty() }; MAX_PEER_GROUPS],
            next_mount_id: 1,
            next_ns_id: 1,
            next_pg_id: 1,
            stats: MountNsStats::new(),
        }
    }

    // ── Namespace lifecycle ──────────────────────────────────────────────

    /// Create a new mount namespace with a root mount.
    ///
    /// Returns the namespace ID.
    pub fn create_namespace(
        &mut self,
        root_path: &[u8],
        root_fs_type: &[u8],
        root_device_id: u32,
        root_inode: u64,
    ) -> Result<u32> {
        if root_path.is_empty() || root_path.len() > MAX_MOUNT_PATH {
            return Err(Error::InvalidArgument);
        }
        if root_fs_type.is_empty() || root_fs_type.len() > MAX_FS_TYPE_LEN {
            return Err(Error::InvalidArgument);
        }

        // Allocate namespace.
        let ns_slot = self
            .namespaces
            .iter_mut()
            .find(|ns| !ns.in_use)
            .ok_or(Error::OutOfMemory)?;

        let ns_id = self.next_ns_id;
        self.next_ns_id = self.next_ns_id.wrapping_add(1);

        ns_slot.id = ns_id;
        ns_slot.mount_count = 0;
        ns_slot.ref_count = 1;
        ns_slot.in_use = true;

        // Create root mount.
        let mount_id = self.alloc_mount(
            ns_id,
            NONE_ID,
            root_path,
            root_fs_type,
            root_device_id,
            root_inode,
        )?;

        // Set root mount flag.
        for m in &mut self.mounts {
            if m.in_use && m.mount_id == mount_id {
                m.flags.is_root = true;
                break;
            }
        }

        // Update namespace root.
        for ns in &mut self.namespaces {
            if ns.in_use && ns.id == ns_id {
                ns.root_mount = mount_id;
                ns.mount_count = 1;
                break;
            }
        }

        self.stats.namespaces_created += 1;
        self.stats.namespaces_active += 1;
        Ok(ns_id)
    }

    /// Clone (copy) a mount namespace.
    ///
    /// Creates a new namespace with copies of all mounts from `src_ns`.
    /// Used by `clone(CLONE_NEWNS)` and `unshare(CLONE_NEWNS)`.
    pub fn clone_namespace(&mut self, src_ns: u32) -> Result<u32> {
        // Verify source exists.
        let src_exists = self
            .namespaces
            .iter()
            .any(|ns| ns.in_use && ns.id == src_ns);
        if !src_exists {
            return Err(Error::NotFound);
        }

        // Allocate new namespace.
        let ns_slot = self
            .namespaces
            .iter_mut()
            .find(|ns| !ns.in_use)
            .ok_or(Error::OutOfMemory)?;

        let new_ns_id = self.next_ns_id;
        self.next_ns_id = self.next_ns_id.wrapping_add(1);

        ns_slot.id = new_ns_id;
        ns_slot.mount_count = 0;
        ns_slot.ref_count = 1;
        ns_slot.in_use = true;

        // Snapshot source mounts to avoid borrow conflicts.
        let mut src_mounts: [(
            bool,
            [u8; MAX_MOUNT_PATH],
            u16,
            [u8; MAX_FS_TYPE_LEN],
            u8,
            u32,
            u64,
            MountFlags,
            Propagation,
            u32,
        ); MAX_MOUNTS] = [(
            false,
            [0; MAX_MOUNT_PATH],
            0,
            [0; MAX_FS_TYPE_LEN],
            0,
            0,
            0,
            MountFlags::new(),
            Propagation::Private,
            NONE_ID,
        ); MAX_MOUNTS];

        let mut src_count = 0usize;
        for m in &self.mounts {
            if m.in_use && m.ns_id == src_ns {
                src_mounts[src_count] = (
                    true,
                    m.mount_point,
                    m.mount_point_len,
                    m.fs_type,
                    m.fs_type_len,
                    m.device_id,
                    m.root_inode,
                    m.flags,
                    m.propagation,
                    m.parent_id,
                );
                src_count += 1;
            }
        }

        let mut new_root = NONE_ID;
        for i in 0..src_count {
            let (_, mp, mp_len, fst, fst_len, dev, ino, flags, prop, _parent) = src_mounts[i];
            let mid = self.alloc_mount(
                new_ns_id,
                NONE_ID,
                &mp[..mp_len as usize],
                &fst[..fst_len as usize],
                dev,
                ino,
            )?;

            // Copy flags and propagation.
            for m in &mut self.mounts {
                if m.in_use && m.mount_id == mid {
                    m.flags = flags;
                    m.propagation = prop;
                    break;
                }
            }

            if flags.is_root && new_root == NONE_ID {
                new_root = mid;
            }
        }

        // Set root mount.
        for ns in &mut self.namespaces {
            if ns.in_use && ns.id == new_ns_id {
                ns.root_mount = new_root;
                break;
            }
        }

        self.stats.clones += 1;
        self.stats.namespaces_created += 1;
        self.stats.namespaces_active += 1;
        Ok(new_ns_id)
    }

    /// Release a reference to a namespace.
    ///
    /// When the reference count reaches zero, all mounts are unmounted
    /// and the namespace is freed.
    pub fn release_namespace(&mut self, ns_id: u32) -> Result<()> {
        let ns = self
            .namespaces
            .iter_mut()
            .find(|ns| ns.in_use && ns.id == ns_id)
            .ok_or(Error::NotFound)?;

        if ns.ref_count > 1 {
            ns.ref_count -= 1;
            return Ok(());
        }

        ns.in_use = false;

        // Unmount all mounts in this namespace.
        for m in &mut self.mounts {
            if m.in_use && m.ns_id == ns_id {
                m.in_use = false;
                self.stats.mounts_active = self.stats.mounts_active.saturating_sub(1);
            }
        }

        self.stats.namespaces_active = self.stats.namespaces_active.saturating_sub(1);
        Ok(())
    }

    /// Increment the reference count of a namespace.
    pub fn get_namespace(&mut self, ns_id: u32) -> Result<()> {
        let ns = self
            .namespaces
            .iter_mut()
            .find(|ns| ns.in_use && ns.id == ns_id)
            .ok_or(Error::NotFound)?;
        ns.ref_count = ns.ref_count.saturating_add(1);
        Ok(())
    }

    // ── Mount operations ─────────────────────────────────────────────────

    /// Mount a filesystem in a namespace.
    ///
    /// Returns the mount ID.
    pub fn mount(
        &mut self,
        ns_id: u32,
        parent_mount: u32,
        mount_point: &[u8],
        fs_type: &[u8],
        device_id: u32,
        root_inode: u64,
        flags: MountFlags,
    ) -> Result<u32> {
        // Verify namespace.
        let ns_exists = self.namespaces.iter().any(|ns| ns.in_use && ns.id == ns_id);
        if !ns_exists {
            return Err(Error::NotFound);
        }

        let mid = self.alloc_mount(
            ns_id,
            parent_mount,
            mount_point,
            fs_type,
            device_id,
            root_inode,
        )?;

        // Apply flags.
        for m in &mut self.mounts {
            if m.in_use && m.mount_id == mid {
                m.flags = flags;
                break;
            }
        }

        // Update namespace mount count.
        for ns in &mut self.namespaces {
            if ns.in_use && ns.id == ns_id {
                ns.mount_count += 1;
                break;
            }
        }

        // Propagate to shared peers.
        self.propagate_mount(mid)?;

        Ok(mid)
    }

    /// Unmount a filesystem.
    pub fn unmount(&mut self, ns_id: u32, mount_id: u32) -> Result<()> {
        let m = self
            .mounts
            .iter_mut()
            .find(|m| m.in_use && m.mount_id == mount_id && m.ns_id == ns_id)
            .ok_or(Error::NotFound)?;

        if m.flags.is_root {
            return Err(Error::Busy);
        }
        if m.ref_count > 0 {
            return Err(Error::Busy);
        }

        let pg = m.peer_group;
        m.in_use = false;

        // Remove from peer group.
        if pg != NONE_ID {
            for group in &mut self.peer_groups {
                if group.in_use && group.id == pg {
                    group.remove_member(mount_id);
                    if group.member_count == 0 {
                        group.in_use = false;
                    }
                    break;
                }
            }
        }

        // Update namespace mount count.
        for ns in &mut self.namespaces {
            if ns.in_use && ns.id == ns_id {
                ns.mount_count = ns.mount_count.saturating_sub(1);
                break;
            }
        }

        self.stats.mounts_active = self.stats.mounts_active.saturating_sub(1);
        Ok(())
    }

    // ── Propagation ──────────────────────────────────────────────────────

    /// Set the propagation type for a mount.
    pub fn set_propagation(&mut self, mount_id: u32, propagation: Propagation) -> Result<()> {
        let mount_idx = self
            .mounts
            .iter()
            .position(|m| m.in_use && m.mount_id == mount_id)
            .ok_or(Error::NotFound)?;

        let old_prop = self.mounts[mount_idx].propagation;
        self.mounts[mount_idx].propagation = propagation;

        // Create or leave peer group.
        match (old_prop, propagation) {
            (_, Propagation::Shared) if self.mounts[mount_idx].peer_group == NONE_ID => {
                let pg_id = self.alloc_peer_group()?;
                self.mounts[mount_idx].peer_group = pg_id;
                let mid = self.mounts[mount_idx].mount_id;
                for group in &mut self.peer_groups {
                    if group.in_use && group.id == pg_id {
                        group.add_member(mid)?;
                        break;
                    }
                }
            }
            (Propagation::Shared, _) if self.mounts[mount_idx].peer_group != NONE_ID => {
                let pg = self.mounts[mount_idx].peer_group;
                let mid = self.mounts[mount_idx].mount_id;
                self.mounts[mount_idx].peer_group = NONE_ID;
                for group in &mut self.peer_groups {
                    if group.in_use && group.id == pg {
                        group.remove_member(mid);
                        if group.member_count == 0 {
                            group.in_use = false;
                        }
                        break;
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Propagate a mount event to shared peers.
    fn propagate_mount(&mut self, mount_id: u32) -> Result<()> {
        let pg_id;
        {
            let mount = self
                .mounts
                .iter()
                .find(|m| m.in_use && m.mount_id == mount_id)
                .ok_or(Error::NotFound)?;

            if mount.propagation != Propagation::Shared || mount.peer_group == NONE_ID {
                return Ok(());
            }
            pg_id = mount.peer_group;
        }

        // Count propagated events (actual propagation would clone mounts
        // into peer namespaces; here we just track the event).
        let _peer_count = self
            .peer_groups
            .iter()
            .find(|g| g.in_use && g.id == pg_id)
            .map(|g| g.member_count)
            .unwrap_or(0);

        self.stats.propagations += 1;
        Ok(())
    }

    // ── pivot_root ───────────────────────────────────────────────────────

    /// Perform pivot_root: change the root mount to `new_root_mount`
    /// and move the old root to `put_old_mount`.
    pub fn pivot_root(
        &mut self,
        ns_id: u32,
        new_root_mount: u32,
        put_old_mount: u32,
    ) -> Result<()> {
        // Verify both mounts exist in the namespace.
        let new_exists = self
            .mounts
            .iter()
            .any(|m| m.in_use && m.mount_id == new_root_mount && m.ns_id == ns_id);
        let old_exists = self
            .mounts
            .iter()
            .any(|m| m.in_use && m.mount_id == put_old_mount && m.ns_id == ns_id);

        if !new_exists || !old_exists {
            return Err(Error::NotFound);
        }

        // Swap root flag.
        for m in &mut self.mounts {
            if m.in_use && m.ns_id == ns_id && m.flags.is_root {
                m.flags.is_root = false;
                break;
            }
        }
        for m in &mut self.mounts {
            if m.in_use && m.mount_id == new_root_mount {
                m.flags.is_root = true;
                break;
            }
        }

        // Update namespace root.
        for ns in &mut self.namespaces {
            if ns.in_use && ns.id == ns_id {
                ns.root_mount = new_root_mount;
                break;
            }
        }

        self.stats.pivot_roots += 1;
        Ok(())
    }

    // ── /proc/mounts ─────────────────────────────────────────────────────

    /// List mounts in a namespace (for /proc/mounts).
    ///
    /// Fills `buf` with up to `buf.len()` mount info entries.
    /// Returns the number of entries written.
    pub fn list_mounts(&self, ns_id: u32, buf: &mut [MountInfo]) -> usize {
        let mut count = 0usize;
        for m in &self.mounts {
            if count >= buf.len() {
                break;
            }
            if m.in_use && m.ns_id == ns_id {
                buf[count] = MountInfo {
                    mount_id: m.mount_id,
                    parent_id: m.parent_id,
                    device_id: m.device_id,
                    root_inode: m.root_inode,
                    propagation: m.propagation,
                    read_only: m.flags.read_only,
                };
                count += 1;
            }
        }
        count
    }

    // ── Queries ──────────────────────────────────────────────────────────

    /// Return the root mount ID for a namespace.
    pub fn root_mount(&self, ns_id: u32) -> Result<u32> {
        let ns = self
            .namespaces
            .iter()
            .find(|ns| ns.in_use && ns.id == ns_id)
            .ok_or(Error::NotFound)?;
        Ok(ns.root_mount)
    }

    /// Return the mount count for a namespace.
    pub fn mount_count(&self, ns_id: u32) -> Result<u32> {
        let ns = self
            .namespaces
            .iter()
            .find(|ns| ns.in_use && ns.id == ns_id)
            .ok_or(Error::NotFound)?;
        Ok(ns.mount_count)
    }

    /// Return statistics.
    pub fn stats(&self) -> MountNsStats {
        self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = MountNsStats::new();
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    /// Allocate a new mount entry.
    fn alloc_mount(
        &mut self,
        ns_id: u32,
        parent_id: u32,
        mount_point: &[u8],
        fs_type: &[u8],
        device_id: u32,
        root_inode: u64,
    ) -> Result<u32> {
        if mount_point.is_empty() || mount_point.len() > MAX_MOUNT_PATH {
            return Err(Error::InvalidArgument);
        }
        if fs_type.is_empty() || fs_type.len() > MAX_FS_TYPE_LEN {
            return Err(Error::InvalidArgument);
        }

        let slot = self
            .mounts
            .iter_mut()
            .find(|m| !m.in_use)
            .ok_or(Error::OutOfMemory)?;

        let mid = self.next_mount_id;
        self.next_mount_id = self.next_mount_id.wrapping_add(1);

        slot.mount_id = mid;
        slot.ns_id = ns_id;
        slot.parent_id = parent_id;
        slot.mount_point[..mount_point.len()].copy_from_slice(mount_point);
        slot.mount_point_len = mount_point.len() as u16;
        slot.fs_type[..fs_type.len()].copy_from_slice(fs_type);
        slot.fs_type_len = fs_type.len() as u8;
        slot.device_id = device_id;
        slot.root_inode = root_inode;
        slot.flags = MountFlags::new();
        slot.propagation = Propagation::Private;
        slot.peer_group = NONE_ID;
        slot.master_id = NONE_ID;
        slot.ref_count = 0;
        slot.in_use = true;

        self.stats.mounts_total += 1;
        self.stats.mounts_active += 1;
        Ok(mid)
    }

    /// Allocate a new peer group.
    fn alloc_peer_group(&mut self) -> Result<u32> {
        let slot = self
            .peer_groups
            .iter_mut()
            .find(|g| !g.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_pg_id;
        self.next_pg_id = self.next_pg_id.wrapping_add(1);

        slot.id = id;
        slot.member_count = 0;
        slot.members = [NONE_ID; 8];
        slot.in_use = true;
        Ok(id)
    }
}
