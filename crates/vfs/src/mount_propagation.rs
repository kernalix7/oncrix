// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Mount namespace propagation — shared/slave/private/unbindable mount events.
//!
//! When a mount or unmount occurs, the propagation subsystem determines which
//! other mount points in the same or related namespaces should receive the
//! same event.  This is the mechanism behind `mount --make-shared`,
//! `mount --make-slave`, `mount --make-private`, and `mount --make-unbindable`.
//!
//! # Architecture
//!
//! ```text
//! +-------------------------------------------------------------+
//! |  mount(target="/mnt/data", ...)                              |
//! |       |                                                      |
//! |       v                                                      |
//! |  PropagationEngine::propagate_mount()                        |
//! |       |                                                      |
//! |       v                                                      |
//! |  +----------------------------------------------+            |
//! |  | PropagationGroup (peer group)                |            |
//! |  | +---+ +---+ +---+                            |            |
//! |  | | A | | B | | C |  <-- shared peers          |            |
//! |  | +---+ +---+ +---+                            |            |
//! |  |   |                                          |            |
//! |  |   v                                          |            |
//! |  | +------+                                     |            |
//! |  | | Slave| <- receives events, cannot send     |            |
//! |  | +------+                                     |            |
//! |  +----------------------------------------------+            |
//! |       |                                                      |
//! |       v                                                      |
//! |  MountEvent queued for each affected peer                    |
//! +-------------------------------------------------------------+
//! ```
//!
//! # Propagation types
//!
//! | Type          | Receives events? | Sends events? |
//! |---------------|-----------------|---------------|
//! | Shared        | Yes             | Yes           |
//! | Slave         | Yes (from master)| No           |
//! | Private       | No              | No            |
//! | Unbindable    | No              | No (+ cannot be bind-mounted) |
//!
//! # Peer groups
//!
//! Shared mounts belong to a peer group.  When a mount/unmount event occurs
//! on any member of the group, all other shared members and all slave
//! members receive the propagated event.
//!
//! # Reference
//!
//! Linux `fs/pnode.c`, `fs/pnode.h`, `fs/namespace.c`,
//! `Documentation/filesystems/sharedsubtree.rst`.

extern crate alloc;

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of propagation groups.
const MAX_GROUPS: usize = 64;

/// Maximum number of mount peers tracked globally.
const MAX_PEERS: usize = 256;

/// Maximum number of pending mount events.
const MAX_EVENTS: usize = 128;

/// Maximum number of slave mounts per group.
const MAX_SLAVES_PER_GROUP: usize = 16;

/// Maximum number of shared peers per group.
const MAX_PEERS_PER_GROUP: usize = 16;

/// Maximum mount path length.
const MAX_PATH_LEN: usize = 256;

/// Sentinel for "no ID".
const NONE_ID: u32 = u32::MAX;

// ── PropagationType ──────────────────────────────────────────────────────────

/// Mount propagation type controlling event flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationType {
    /// Events propagate bidirectionally among all peers.
    Shared,
    /// Events flow from master to slave only.
    Slave,
    /// No propagation whatsoever.
    Private,
    /// No propagation and cannot be bind-mounted.
    Unbindable,
}

impl PropagationType {
    /// Whether this propagation type receives mount events.
    pub fn receives_events(self) -> bool {
        matches!(self, Self::Shared | Self::Slave)
    }

    /// Whether this propagation type sends mount events.
    pub fn sends_events(self) -> bool {
        matches!(self, Self::Shared)
    }

    /// Whether this mount can be bind-mounted.
    pub fn can_bind(self) -> bool {
        !matches!(self, Self::Unbindable)
    }
}

// ── MountEventKind ───────────────────────────────────────────────────────────

/// Kind of propagated mount event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountEventKind {
    /// A new filesystem was mounted.
    Mount,
    /// A filesystem was unmounted.
    Umount,
    /// A bind mount was created.
    BindMount,
    /// Mount options were remounted (changed).
    Remount,
    /// Mount was moved to a new location.
    Move,
}

// ── MountEvent ───────────────────────────────────────────────────────────────

/// A propagated mount event delivered to affected peers.
#[derive(Debug, Clone, Copy)]
pub struct MountEvent {
    /// Kind of event.
    pub kind: MountEventKind,
    /// Source mount peer ID that originated the event.
    pub source_peer: u32,
    /// Target peer ID receiving this event.
    pub target_peer: u32,
    /// Group ID the event is propagated through.
    pub group_id: u32,
    /// Mount point path.
    path: [u8; MAX_PATH_LEN],
    /// Mount point path length.
    path_len: u16,
    /// Device ID of the mounted filesystem.
    pub device_id: u32,
    /// Timestamp (monotonic ticks).
    pub timestamp: u64,
    /// Whether this event has been delivered.
    pub delivered: bool,
    /// Whether this slot is in use.
    in_use: bool,
}

impl MountEvent {
    /// Create an empty, unused event slot.
    const fn empty() -> Self {
        Self {
            kind: MountEventKind::Mount,
            source_peer: NONE_ID,
            target_peer: NONE_ID,
            group_id: NONE_ID,
            path: [0; MAX_PATH_LEN],
            path_len: 0,
            device_id: 0,
            timestamp: 0,
            delivered: false,
            in_use: false,
        }
    }

    /// Return the mount point path as a byte slice.
    pub fn path(&self) -> &[u8] {
        &self.path[..self.path_len as usize]
    }
}

// ── MountPeer ────────────────────────────────────────────────────────────────

/// A single mount peer — a mount point with propagation state.
#[derive(Debug, Clone, Copy)]
pub struct MountPeer {
    /// Unique peer ID.
    pub peer_id: u32,
    /// Mount ID this peer corresponds to.
    pub mount_id: u32,
    /// Propagation type for this peer.
    pub propagation: PropagationType,
    /// Group this peer belongs to (NONE_ID for private/unbindable).
    pub group_id: u32,
    /// Master peer ID for slave mounts (NONE_ID if not a slave).
    pub master_id: u32,
    /// Namespace ID this mount lives in.
    pub namespace_id: u32,
    /// Mount point path.
    path: [u8; MAX_PATH_LEN],
    /// Mount point path length.
    path_len: u16,
    /// Whether this slot is in use.
    in_use: bool,
}

impl MountPeer {
    /// Create an empty, unused peer slot.
    const fn empty() -> Self {
        Self {
            peer_id: 0,
            mount_id: 0,
            propagation: PropagationType::Private,
            group_id: NONE_ID,
            master_id: NONE_ID,
            namespace_id: 0,
            path: [0; MAX_PATH_LEN],
            path_len: 0,
            in_use: false,
        }
    }

    /// Return the mount point path as a byte slice.
    pub fn path(&self) -> &[u8] {
        &self.path[..self.path_len as usize]
    }

    /// Whether this peer receives propagated events.
    pub fn receives_events(&self) -> bool {
        self.propagation.receives_events()
    }

    /// Whether this peer sends propagated events.
    pub fn sends_events(&self) -> bool {
        self.propagation.sends_events()
    }
}

// ── PropagationGroup ─────────────────────────────────────────────────────────

/// A propagation group containing shared peers and their slaves.
///
/// When an event occurs on any shared peer, all other shared peers
/// and all slaves receive the propagated event.
struct PropagationGroup {
    /// Group ID.
    id: u32,
    /// Shared peer IDs.
    shared_peers: [u32; MAX_PEERS_PER_GROUP],
    /// Number of shared peers.
    shared_count: u8,
    /// Slave peer IDs.
    slave_peers: [u32; MAX_SLAVES_PER_GROUP],
    /// Number of slave peers.
    slave_count: u8,
    /// Whether this slot is in use.
    in_use: bool,
    /// Generation counter for change detection.
    generation: u64,
}

impl PropagationGroup {
    /// Create an empty, unused group slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            shared_peers: [NONE_ID; MAX_PEERS_PER_GROUP],
            shared_count: 0,
            slave_peers: [NONE_ID; MAX_SLAVES_PER_GROUP],
            slave_count: 0,
            in_use: false,
            generation: 0,
        }
    }

    /// Add a shared peer to this group.
    fn add_shared(&mut self, peer_id: u32) -> Result<()> {
        if self.shared_count as usize >= MAX_PEERS_PER_GROUP {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicates.
        for i in 0..self.shared_count as usize {
            if self.shared_peers[i] == peer_id {
                return Err(Error::AlreadyExists);
            }
        }
        self.shared_peers[self.shared_count as usize] = peer_id;
        self.shared_count += 1;
        self.generation += 1;
        Ok(())
    }

    /// Remove a shared peer from this group.
    fn remove_shared(&mut self, peer_id: u32) -> bool {
        for i in 0..self.shared_count as usize {
            if self.shared_peers[i] == peer_id {
                let last = self.shared_count as usize - 1;
                self.shared_peers[i] = self.shared_peers[last];
                self.shared_peers[last] = NONE_ID;
                self.shared_count -= 1;
                self.generation += 1;
                return true;
            }
        }
        false
    }

    /// Add a slave peer to this group.
    fn add_slave(&mut self, peer_id: u32) -> Result<()> {
        if self.slave_count as usize >= MAX_SLAVES_PER_GROUP {
            return Err(Error::OutOfMemory);
        }
        for i in 0..self.slave_count as usize {
            if self.slave_peers[i] == peer_id {
                return Err(Error::AlreadyExists);
            }
        }
        self.slave_peers[self.slave_count as usize] = peer_id;
        self.slave_count += 1;
        self.generation += 1;
        Ok(())
    }

    /// Remove a slave peer from this group.
    fn remove_slave(&mut self, peer_id: u32) -> bool {
        for i in 0..self.slave_count as usize {
            if self.slave_peers[i] == peer_id {
                let last = self.slave_count as usize - 1;
                self.slave_peers[i] = self.slave_peers[last];
                self.slave_peers[last] = NONE_ID;
                self.slave_count -= 1;
                self.generation += 1;
                return true;
            }
        }
        false
    }

    /// Total member count (shared + slave).
    fn total_members(&self) -> usize {
        self.shared_count as usize + self.slave_count as usize
    }
}

// ── PropagationStats ─────────────────────────────────────────────────────────

/// Statistics for the propagation engine.
#[derive(Debug, Clone, Copy, Default)]
pub struct PropagationStats {
    /// Total mount events propagated.
    pub events_propagated: u64,
    /// Total umount events propagated.
    pub umount_events_propagated: u64,
    /// Events dropped due to queue overflow.
    pub events_dropped: u64,
    /// Active propagation groups.
    pub active_groups: u32,
    /// Active mount peers.
    pub active_peers: u32,
    /// Pending undelivered events.
    pub pending_events: u32,
}

// ── PropagationEngine ────────────────────────────────────────────────────────

/// Mount propagation engine managing groups, peers, and event delivery.
///
/// The engine maintains a fixed-size table of propagation groups and
/// mount peers.  When a mount or unmount event occurs, it walks the
/// affected group's peer list and queues events for each recipient.
pub struct PropagationEngine {
    /// Propagation groups.
    groups: [PropagationGroup; MAX_GROUPS],
    /// Mount peers.
    peers: [MountPeer; MAX_PEERS],
    /// Pending mount events.
    events: [MountEvent; MAX_EVENTS],
    /// Next group ID to allocate.
    next_group_id: u32,
    /// Next peer ID to allocate.
    next_peer_id: u32,
    /// Monotonic timestamp counter.
    timestamp: u64,
    /// Cumulative statistics.
    stats: PropagationStats,
}

impl PropagationEngine {
    /// Create a new propagation engine.
    pub const fn new() -> Self {
        Self {
            groups: [const { PropagationGroup::empty() }; MAX_GROUPS],
            peers: [const { MountPeer::empty() }; MAX_PEERS],
            events: [const { MountEvent::empty() }; MAX_EVENTS],
            next_group_id: 1,
            next_peer_id: 1,
            timestamp: 0,
            stats: PropagationStats {
                events_propagated: 0,
                umount_events_propagated: 0,
                events_dropped: 0,
                active_groups: 0,
                active_peers: 0,
                pending_events: 0,
            },
        }
    }

    // ── Group management ─────────────────────────────────────────

    /// Create a new propagation group, returning its ID.
    pub fn create_group(&mut self) -> Result<u32> {
        let slot = self
            .groups
            .iter_mut()
            .find(|g| !g.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_group_id;
        self.next_group_id += 1;
        slot.id = id;
        slot.shared_count = 0;
        slot.slave_count = 0;
        slot.in_use = true;
        slot.generation = 0;
        self.stats.active_groups += 1;
        Ok(id)
    }

    /// Destroy a propagation group.
    ///
    /// All peers in the group are moved to private propagation.
    pub fn destroy_group(&mut self, group_id: u32) -> Result<()> {
        let group = self
            .groups
            .iter_mut()
            .find(|g| g.in_use && g.id == group_id)
            .ok_or(Error::NotFound)?;

        // Collect peer IDs before modifying.
        let mut peer_ids = [NONE_ID; MAX_PEERS_PER_GROUP + MAX_SLAVES_PER_GROUP];
        let mut count = 0usize;
        for i in 0..group.shared_count as usize {
            peer_ids[count] = group.shared_peers[i];
            count += 1;
        }
        for i in 0..group.slave_count as usize {
            peer_ids[count] = group.slave_peers[i];
            count += 1;
        }

        group.shared_count = 0;
        group.slave_count = 0;
        group.in_use = false;

        // Move affected peers to private.
        for pid in &peer_ids[..count] {
            if let Some(peer) = self
                .peers
                .iter_mut()
                .find(|p| p.in_use && p.peer_id == *pid)
            {
                peer.propagation = PropagationType::Private;
                peer.group_id = NONE_ID;
                peer.master_id = NONE_ID;
            }
        }

        self.stats.active_groups = self.stats.active_groups.saturating_sub(1);
        Ok(())
    }

    // ── Peer management ──────────────────────────────────────────

    /// Register a new mount peer, returning its peer ID.
    pub fn register_peer(&mut self, mount_id: u32, namespace_id: u32, path: &[u8]) -> Result<u32> {
        if path.is_empty() || path.len() > MAX_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        let slot = self
            .peers
            .iter_mut()
            .find(|p| !p.in_use)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_peer_id;
        self.next_peer_id += 1;
        slot.peer_id = id;
        slot.mount_id = mount_id;
        slot.propagation = PropagationType::Private;
        slot.group_id = NONE_ID;
        slot.master_id = NONE_ID;
        slot.namespace_id = namespace_id;
        slot.path[..path.len()].copy_from_slice(path);
        slot.path_len = path.len() as u16;
        slot.in_use = true;
        self.stats.active_peers += 1;
        Ok(id)
    }

    /// Unregister a mount peer.
    pub fn unregister_peer(&mut self, peer_id: u32) -> Result<()> {
        let peer = self
            .peers
            .iter_mut()
            .find(|p| p.in_use && p.peer_id == peer_id)
            .ok_or(Error::NotFound)?;

        let group_id = peer.group_id;
        let propagation = peer.propagation;
        peer.in_use = false;
        peer.group_id = NONE_ID;

        // Remove from group if applicable.
        if group_id != NONE_ID {
            if let Some(group) = self
                .groups
                .iter_mut()
                .find(|g| g.in_use && g.id == group_id)
            {
                match propagation {
                    PropagationType::Shared => {
                        group.remove_shared(peer_id);
                    }
                    PropagationType::Slave => {
                        group.remove_slave(peer_id);
                    }
                    PropagationType::Private | PropagationType::Unbindable => {}
                }
                // Auto-destroy empty groups.
                if group.total_members() == 0 {
                    group.in_use = false;
                    self.stats.active_groups = self.stats.active_groups.saturating_sub(1);
                }
            }
        }

        self.stats.active_peers = self.stats.active_peers.saturating_sub(1);
        Ok(())
    }

    // ── Propagation control ──────────────────────────────────────

    /// Set the propagation type for a mount peer.
    ///
    /// When changing to `Shared`, a new group is created if the peer
    /// does not already belong to one.  When changing to `Slave`, the
    /// peer must already be in a group (it stays but becomes read-only).
    /// When changing to `Private` or `Unbindable`, the peer is removed
    /// from its group.
    pub fn set_propagation(&mut self, peer_id: u32, prop_type: PropagationType) -> Result<()> {
        // Find peer index.
        let peer_idx = self
            .peers
            .iter()
            .position(|p| p.in_use && p.peer_id == peer_id)
            .ok_or(Error::NotFound)?;

        let old_group = self.peers[peer_idx].group_id;
        let old_prop = self.peers[peer_idx].propagation;

        // Remove from old group if needed.
        if old_group != NONE_ID
            && (prop_type == PropagationType::Private || prop_type == PropagationType::Unbindable)
        {
            if let Some(group) = self
                .groups
                .iter_mut()
                .find(|g| g.in_use && g.id == old_group)
            {
                match old_prop {
                    PropagationType::Shared => {
                        group.remove_shared(peer_id);
                    }
                    PropagationType::Slave => {
                        group.remove_slave(peer_id);
                    }
                    _ => {}
                }
                if group.total_members() == 0 {
                    group.in_use = false;
                    self.stats.active_groups = self.stats.active_groups.saturating_sub(1);
                }
            }
            self.peers[peer_idx].group_id = NONE_ID;
            self.peers[peer_idx].master_id = NONE_ID;
        }

        match prop_type {
            PropagationType::Shared => {
                if old_group == NONE_ID
                    || old_prop == PropagationType::Private
                    || old_prop == PropagationType::Unbindable
                {
                    // Create a new group for this peer.
                    let gid = self.create_group()?;
                    if let Some(group) = self.groups.iter_mut().find(|g| g.in_use && g.id == gid) {
                        group.add_shared(peer_id)?;
                    }
                    self.peers[peer_idx].group_id = gid;
                } else if old_prop == PropagationType::Slave {
                    // Promote slave to shared within same group.
                    if let Some(group) = self
                        .groups
                        .iter_mut()
                        .find(|g| g.in_use && g.id == old_group)
                    {
                        group.remove_slave(peer_id);
                        group.add_shared(peer_id)?;
                    }
                }
                self.peers[peer_idx].master_id = NONE_ID;
            }
            PropagationType::Slave => {
                if old_group == NONE_ID {
                    return Err(Error::InvalidArgument);
                }
                if old_prop == PropagationType::Shared {
                    // Demote shared to slave within same group.
                    if let Some(group) = self
                        .groups
                        .iter_mut()
                        .find(|g| g.in_use && g.id == old_group)
                    {
                        group.remove_shared(peer_id);
                        group.add_slave(peer_id)?;
                    }
                }
                // Find a shared peer as master.
                if let Some(group) = self.groups.iter().find(|g| g.in_use && g.id == old_group) {
                    if group.shared_count > 0 {
                        self.peers[peer_idx].master_id = group.shared_peers[0];
                    }
                }
            }
            PropagationType::Private | PropagationType::Unbindable => {
                // Already removed from group above.
            }
        }

        self.peers[peer_idx].propagation = prop_type;
        Ok(())
    }

    // ── Event propagation ────────────────────────────────────────

    /// Propagate a mount event from a source peer to all affected peers.
    ///
    /// The source peer must be `Shared`; the event is delivered to all
    /// other shared peers and all slaves in the same group.
    pub fn propagate_mount(
        &mut self,
        source_peer_id: u32,
        kind: MountEventKind,
        device_id: u32,
    ) -> Result<u32> {
        let peer_idx = self
            .peers
            .iter()
            .position(|p| p.in_use && p.peer_id == source_peer_id)
            .ok_or(Error::NotFound)?;

        if !self.peers[peer_idx].propagation.sends_events() {
            return Ok(0);
        }

        let group_id = self.peers[peer_idx].group_id;
        if group_id == NONE_ID {
            return Ok(0);
        }

        // Collect path from source peer.
        let mut path_buf = [0u8; MAX_PATH_LEN];
        let path_len = self.peers[peer_idx].path_len;
        path_buf[..path_len as usize]
            .copy_from_slice(&self.peers[peer_idx].path[..path_len as usize]);

        self.timestamp += 1;
        let ts = self.timestamp;
        let mut delivered_count: u32 = 0;

        // Find the group and collect target peer IDs.
        let mut targets = [NONE_ID; MAX_PEERS_PER_GROUP + MAX_SLAVES_PER_GROUP];
        let mut target_count = 0usize;

        if let Some(group) = self.groups.iter().find(|g| g.in_use && g.id == group_id) {
            for i in 0..group.shared_count as usize {
                if group.shared_peers[i] != source_peer_id {
                    targets[target_count] = group.shared_peers[i];
                    target_count += 1;
                }
            }
            for i in 0..group.slave_count as usize {
                targets[target_count] = group.slave_peers[i];
                target_count += 1;
            }
        }

        // Queue events for each target.
        for tid in &targets[..target_count] {
            if let Some(slot) = self.events.iter_mut().find(|e| !e.in_use) {
                slot.kind = kind;
                slot.source_peer = source_peer_id;
                slot.target_peer = *tid;
                slot.group_id = group_id;
                slot.path[..path_len as usize].copy_from_slice(&path_buf[..path_len as usize]);
                slot.path_len = path_len;
                slot.device_id = device_id;
                slot.timestamp = ts;
                slot.delivered = false;
                slot.in_use = true;
                delivered_count += 1;
                self.stats.pending_events += 1;
            } else {
                self.stats.events_dropped += 1;
            }
        }

        match kind {
            MountEventKind::Umount => {
                self.stats.umount_events_propagated += delivered_count as u64;
            }
            _ => {
                self.stats.events_propagated += delivered_count as u64;
            }
        }

        Ok(delivered_count)
    }

    /// Propagate an unmount event from a source peer.
    ///
    /// Convenience wrapper around [`propagate_mount`](Self::propagate_mount)
    /// with [`MountEventKind::Umount`].
    pub fn propagate_umount(&mut self, source_peer_id: u32, device_id: u32) -> Result<u32> {
        self.propagate_mount(source_peer_id, MountEventKind::Umount, device_id)
    }

    // ── Event consumption ────────────────────────────────────────

    /// Read and consume the next pending event for a given peer.
    ///
    /// Returns `None` if no events are pending for this peer.
    pub fn consume_event(&mut self, peer_id: u32) -> Option<MountEvent> {
        for ev in &mut self.events {
            if ev.in_use && !ev.delivered && ev.target_peer == peer_id {
                ev.delivered = true;
                ev.in_use = false;
                self.stats.pending_events = self.stats.pending_events.saturating_sub(1);
                return Some(*ev);
            }
        }
        None
    }

    /// Drain all pending events for a peer into a caller-supplied buffer.
    ///
    /// Returns the number of events written.
    pub fn drain_events(&mut self, peer_id: u32, buf: &mut [MountEvent]) -> usize {
        let mut count = 0usize;
        for ev in &mut self.events {
            if count >= buf.len() {
                break;
            }
            if ev.in_use && !ev.delivered && ev.target_peer == peer_id {
                buf[count] = *ev;
                ev.delivered = true;
                ev.in_use = false;
                self.stats.pending_events = self.stats.pending_events.saturating_sub(1);
                count += 1;
            }
        }
        count
    }

    // ── Peer queries ─────────────────────────────────────────────

    /// Find all peers in the same propagation group as the given peer.
    ///
    /// Writes peer IDs into `buf` and returns the number written.
    pub fn find_peers(&self, peer_id: u32, buf: &mut [u32]) -> Result<usize> {
        let peer = self
            .peers
            .iter()
            .find(|p| p.in_use && p.peer_id == peer_id)
            .ok_or(Error::NotFound)?;

        let group_id = peer.group_id;
        if group_id == NONE_ID {
            return Ok(0);
        }

        let group = self
            .groups
            .iter()
            .find(|g| g.in_use && g.id == group_id)
            .ok_or(Error::NotFound)?;

        let mut count = 0usize;
        for i in 0..group.shared_count as usize {
            if count >= buf.len() {
                break;
            }
            if group.shared_peers[i] != peer_id {
                buf[count] = group.shared_peers[i];
                count += 1;
            }
        }
        for i in 0..group.slave_count as usize {
            if count >= buf.len() {
                break;
            }
            if group.slave_peers[i] != peer_id {
                buf[count] = group.slave_peers[i];
                count += 1;
            }
        }

        Ok(count)
    }

    /// Look up a peer by its peer ID.
    pub fn get_peer(&self, peer_id: u32) -> Option<&MountPeer> {
        self.peers.iter().find(|p| p.in_use && p.peer_id == peer_id)
    }

    /// Look up a peer by its mount ID.
    pub fn find_peer_by_mount(&self, mount_id: u32) -> Option<&MountPeer> {
        self.peers
            .iter()
            .find(|p| p.in_use && p.mount_id == mount_id)
    }

    /// Return the number of active peers.
    pub fn peer_count(&self) -> usize {
        self.peers.iter().filter(|p| p.in_use).count()
    }

    /// Return the number of active groups.
    pub fn group_count(&self) -> usize {
        self.groups.iter().filter(|g| g.in_use).count()
    }

    /// Return the number of pending events.
    pub fn pending_event_count(&self) -> usize {
        self.events
            .iter()
            .filter(|e| e.in_use && !e.delivered)
            .count()
    }

    // ── Add peer to existing group ───────────────────────────────

    /// Add a peer to an existing propagation group as a shared member.
    pub fn add_peer_to_group(&mut self, peer_id: u32, group_id: u32) -> Result<()> {
        // Validate peer exists.
        let peer_idx = self
            .peers
            .iter()
            .position(|p| p.in_use && p.peer_id == peer_id)
            .ok_or(Error::NotFound)?;

        if self.peers[peer_idx].group_id != NONE_ID {
            return Err(Error::Busy);
        }

        let group = self
            .groups
            .iter_mut()
            .find(|g| g.in_use && g.id == group_id)
            .ok_or(Error::NotFound)?;

        group.add_shared(peer_id)?;
        self.peers[peer_idx].group_id = group_id;
        self.peers[peer_idx].propagation = PropagationType::Shared;
        Ok(())
    }

    /// Add a peer to an existing propagation group as a slave.
    pub fn add_slave_to_group(&mut self, peer_id: u32, group_id: u32) -> Result<()> {
        let peer_idx = self
            .peers
            .iter()
            .position(|p| p.in_use && p.peer_id == peer_id)
            .ok_or(Error::NotFound)?;

        if self.peers[peer_idx].group_id != NONE_ID {
            return Err(Error::Busy);
        }

        let group = self
            .groups
            .iter_mut()
            .find(|g| g.in_use && g.id == group_id)
            .ok_or(Error::NotFound)?;

        // Find a shared peer as master.
        let master = if group.shared_count > 0 {
            group.shared_peers[0]
        } else {
            NONE_ID
        };

        group.add_slave(peer_id)?;
        self.peers[peer_idx].group_id = group_id;
        self.peers[peer_idx].propagation = PropagationType::Slave;
        self.peers[peer_idx].master_id = master;
        Ok(())
    }

    // ── Statistics ────────────────────────────────────────────────

    /// Return current propagation statistics.
    pub fn stats(&self) -> PropagationStats {
        self.stats
    }

    /// Reset statistics counters.
    pub fn reset_stats(&mut self) {
        self.stats.events_propagated = 0;
        self.stats.umount_events_propagated = 0;
        self.stats.events_dropped = 0;
    }

    // ── Garbage collection ───────────────────────────────────────

    /// Purge all delivered events, freeing their slots.
    pub fn gc_events(&mut self) -> usize {
        let mut freed = 0usize;
        for ev in &mut self.events {
            if ev.in_use && ev.delivered {
                ev.in_use = false;
                freed += 1;
            }
        }
        freed
    }

    /// Purge all events older than the given timestamp.
    pub fn gc_events_before(&mut self, before_ts: u64) -> usize {
        let mut freed = 0usize;
        for ev in &mut self.events {
            if ev.in_use && ev.timestamp < before_ts {
                if !ev.delivered {
                    self.stats.pending_events = self.stats.pending_events.saturating_sub(1);
                }
                ev.in_use = false;
                freed += 1;
            }
        }
        freed
    }
}
