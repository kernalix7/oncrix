// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! fsnotify core framework — unified filesystem notification backend.
//!
//! Provides the common infrastructure shared by `inotify`, `fanotify`,
//! and any future notification subsystem. Front-ends register
//! notification groups and attach marks to inodes, mounts, or
//! whole filesystems. When a VFS operation occurs, the fsnotify
//! dispatch path walks the connector list attached to the affected
//! object, merges duplicate events, and delivers them in group
//! priority order.
//!
//! # Architecture
//!
//! ```text
//! VFS operation (e.g. vfs_write)
//!   → fsnotify_parent()           — check parent-directory marks
//!     → fsnotify()                — main dispatch
//!       → connector_list on inode/mount/sb
//!         → for each mark's group (sorted by priority)
//!           → group.handle_event()  — coalesce + enqueue
//! ```
//!
//! # Structures
//!
//! - [`FsnotifyMask`] — event bit-mask (filesystem-event flags)
//! - [`MarkType`] — inode, mount, or filesystem mark
//! - [`FsnotifyMark`] — a single mark binding a mask to an object
//! - [`Connector`] — per-object list of marks; bridges object → groups
//! - [`FsnotifyEvent`] — a queued filesystem notification event
//! - [`GroupBackend`] — front-end callback interface (inotify / fanotify)
//! - [`FsnotifyGroup`] — a notification subscriber with priority, marks, queue
//! - [`OverflowPolicy`] — what to do when the event queue is full
//! - [`FsnotifyRegistry`] — global registry of all active groups

#[allow(dead_code)]
use oncrix_lib::{Error, Result};

// ── Event Mask Constants ─────────────────────────────────────────

/// File was accessed (read).
pub const FS_ACCESS: u64 = 0x0000_0000_0000_0001;
/// File data was modified.
pub const FS_MODIFY: u64 = 0x0000_0000_0000_0002;
/// Inode metadata changed.
pub const FS_ATTRIB: u64 = 0x0000_0000_0000_0004;
/// Writable file descriptor was closed.
pub const FS_CLOSE_WRITE: u64 = 0x0000_0000_0000_0008;
/// Read-only file descriptor was closed.
pub const FS_CLOSE_NOWRITE: u64 = 0x0000_0000_0000_0010;
/// File was opened.
pub const FS_OPEN: u64 = 0x0000_0000_0000_0020;
/// File/dir moved out of a watched directory.
pub const FS_MOVED_FROM: u64 = 0x0000_0000_0000_0040;
/// File/dir moved into a watched directory.
pub const FS_MOVED_TO: u64 = 0x0000_0000_0000_0080;
/// File/dir created inside a watched directory.
pub const FS_CREATE: u64 = 0x0000_0000_0000_0100;
/// File/dir deleted from a watched directory.
pub const FS_DELETE: u64 = 0x0000_0000_0000_0200;
/// Watched inode itself was deleted.
pub const FS_DELETE_SELF: u64 = 0x0000_0000_0000_0400;
/// Watched inode itself was moved.
pub const FS_MOVE_SELF: u64 = 0x0000_0000_0000_0800;
/// File opened for execution.
pub const FS_OPEN_EXEC: u64 = 0x0000_0000_0000_1000;
/// File or directory overflow event generated.
pub const FS_Q_OVERFLOW: u64 = 0x0000_0000_0000_4000;
/// Directory entry was created (name event).
pub const FS_DN_CREATE: u64 = 0x0000_0000_0001_0000;
/// Directory entry was deleted.
pub const FS_DN_DELETE: u64 = 0x0000_0000_0002_0000;
/// Directory entry was renamed.
pub const FS_DN_RENAME: u64 = 0x0000_0000_0004_0000;
/// inotify IN_ISDIR flag — event target is a directory.
pub const FS_ISDIR: u64 = 0x0000_0001_0000_0000;
/// Permission check before open.
pub const FS_OPEN_PERM: u64 = 0x0000_0010_0000_0000;
/// Permission check before access.
pub const FS_ACCESS_PERM: u64 = 0x0000_0020_0000_0000;
/// Permission check before open-for-exec.
pub const FS_OPEN_EXEC_PERM: u64 = 0x0000_0040_0000_0000;

/// All non-permission event bits combined.
pub const FS_ALL_EVENTS: u64 = FS_ACCESS
    | FS_MODIFY
    | FS_ATTRIB
    | FS_CLOSE_WRITE
    | FS_CLOSE_NOWRITE
    | FS_OPEN
    | FS_MOVED_FROM
    | FS_MOVED_TO
    | FS_CREATE
    | FS_DELETE
    | FS_DELETE_SELF
    | FS_MOVE_SELF
    | FS_OPEN_EXEC
    | FS_Q_OVERFLOW
    | FS_DN_CREATE
    | FS_DN_DELETE
    | FS_DN_RENAME;

// ── Capacity Constants ───────────────────────────────────────────

/// Maximum number of groups in the global registry.
const MAX_GROUPS: usize = 32;

/// Maximum number of marks per group.
const MAX_MARKS_PER_GROUP: usize = 128;

/// Maximum number of events in a group's event queue.
const MAX_EVENTS_PER_GROUP: usize = 256;

/// Maximum number of connectors (one per watched object).
const MAX_CONNECTORS: usize = 512;

/// Maximum number of marks attached to a single connector.
const MAX_MARKS_PER_CONNECTOR: usize = 16;

// ── FsnotifyMask ─────────────────────────────────────────────────

/// A bitfield of filesystem event flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FsnotifyMask(pub u64);

impl FsnotifyMask {
    /// Create a mask from raw bits.
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// Return the raw bits.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Return `true` if `other` has any bits set that `self` also has.
    pub fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    /// Return `true` if all bits in `other` are set in `self`.
    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Compute the union of two masks.
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Compute the intersection of two masks.
    pub fn intersection(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Return `true` if the mask is empty.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }
}

// ── MarkType ─────────────────────────────────────────────────────

/// The type of object a [`FsnotifyMark`] is attached to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MarkType {
    /// Mark is attached to a specific inode.
    #[default]
    Inode,
    /// Mark is attached to a mount point (watches all inodes on that mount).
    Mount,
    /// Mark is attached to a whole filesystem/superblock.
    Filesystem,
}

// ── FsnotifyMark ─────────────────────────────────────────────────

/// A single notification mark — binds an event mask to a watched object.
///
/// Each mark is owned by exactly one [`FsnotifyGroup`] and attached to
/// a [`Connector`] on the watched object. When a VFS event fires on the
/// object the connector walks all marks and notifies the owning group
/// if the event mask matches.
#[derive(Debug)]
pub struct FsnotifyMark {
    /// Unique mark identifier within its group.
    pub mark_id: u32,
    /// Type of object being watched.
    pub mark_type: MarkType,
    /// Opaque object identifier (inode number, mount ID, or sb ID).
    pub object_id: u64,
    /// Event mask — which events this mark subscribes to.
    pub mask: FsnotifyMask,
    /// Ignored mask — events to suppress even if matched.
    pub ignored_mask: FsnotifyMask,
    /// ID of the group this mark belongs to.
    pub group_id: u32,
    /// Mark flags.
    pub flags: MarkFlags,
}

impl FsnotifyMark {
    /// Create a new mark.
    pub fn new(
        mark_id: u32,
        mark_type: MarkType,
        object_id: u64,
        mask: FsnotifyMask,
        group_id: u32,
    ) -> Self {
        Self {
            mark_id,
            mark_type,
            object_id,
            mask,
            ignored_mask: FsnotifyMask::from_bits(0),
            group_id,
            flags: MarkFlags::default(),
        }
    }

    /// Return `true` if this mark would fire for `event`.
    pub fn matches(&self, event: FsnotifyMask) -> bool {
        let effective = self
            .mask
            .intersection(event.intersection(self.ignored_mask.complement()));
        !effective.is_empty()
    }
}

// ── MarkFlags ────────────────────────────────────────────────────

/// Control flags on a [`FsnotifyMark`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MarkFlags(pub u32);

impl MarkFlags {
    /// Remove the mark after the first event fires.
    pub const ONESHOT: Self = Self(0x0000_0001);
    /// Suppress events for the process that owns the mark.
    pub const IGNORED_SURV_MODIFY: Self = Self(0x0000_0002);
    /// Mark is currently being removed (tombstone).
    pub const REMOVED: Self = Self(0x0000_0004);

    /// Test whether a flag is set.
    pub fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 != 0
    }
}

// ── FsnotifyMask complement helper ───────────────────────────────

impl FsnotifyMask {
    /// Return the bitwise complement of this mask.
    pub fn complement(self) -> Self {
        Self(!self.0)
    }
}

// ── Connector ────────────────────────────────────────────────────

/// Per-object connector list.
///
/// Attached to an inode, mount point, or superblock. When an event fires
/// on the object, the VFS calls [`Connector::dispatch`] to walk all
/// attached marks and notify the owning groups.
#[derive(Debug)]
pub struct Connector {
    /// The object type this connector is attached to.
    pub object_type: MarkType,
    /// Opaque object identifier.
    pub object_id: u64,
    /// Aggregated event mask across all attached marks.
    pub aggregate_mask: FsnotifyMask,
    /// Mark entries: (group_id, mark_id) pairs.
    marks: [(u32, u32); MAX_MARKS_PER_CONNECTOR],
    mark_count: usize,
}

impl Connector {
    /// Create a new connector for an object.
    pub fn new(object_type: MarkType, object_id: u64) -> Self {
        Self {
            object_type,
            object_id,
            aggregate_mask: FsnotifyMask::from_bits(0),
            marks: [(0, 0); MAX_MARKS_PER_CONNECTOR],
            mark_count: 0,
        }
    }

    /// Attach a mark to this connector.
    ///
    /// Returns `Err(Error::OutOfMemory)` if the connector is full.
    pub fn attach_mark(&mut self, group_id: u32, mark_id: u32, mask: FsnotifyMask) -> Result<()> {
        if self.mark_count >= MAX_MARKS_PER_CONNECTOR {
            return Err(Error::OutOfMemory);
        }
        self.marks[self.mark_count] = (group_id, mark_id);
        self.mark_count += 1;
        self.aggregate_mask = self.aggregate_mask.union(mask);
        Ok(())
    }

    /// Detach a mark from this connector.
    pub fn detach_mark(&mut self, group_id: u32, mark_id: u32) {
        for i in 0..self.mark_count {
            if self.marks[i] == (group_id, mark_id) {
                self.marks[i] = self.marks[self.mark_count - 1];
                self.mark_count -= 1;
                return;
            }
        }
    }

    /// Return an iterator over (group_id, mark_id) pairs.
    pub fn iter_marks(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        self.marks[..self.mark_count].iter().copied()
    }

    /// Return `true` if any attached mark subscribes to `event`.
    pub fn interested_in(&self, event: FsnotifyMask) -> bool {
        self.aggregate_mask.intersects(event)
    }

    /// Return the number of attached marks.
    pub fn mark_count(&self) -> usize {
        self.mark_count
    }
}

// ── FsnotifyEvent ────────────────────────────────────────────────

/// A queued filesystem notification event.
#[derive(Debug, Clone, Copy)]
pub struct FsnotifyEvent {
    /// Event mask (which events occurred).
    pub mask: FsnotifyMask,
    /// Opaque object identifier (inode / mount / sb).
    pub object_id: u64,
    /// Cookie for correlating paired events (e.g. MOVED_FROM / MOVED_TO).
    pub cookie: u32,
    /// Timestamp (ticks) when the event was generated.
    pub timestamp: u64,
    /// Whether the target is a directory.
    pub is_dir: bool,
}

impl FsnotifyEvent {
    /// Create a new event.
    pub const fn new(mask: FsnotifyMask, object_id: u64, cookie: u32, timestamp: u64) -> Self {
        Self {
            mask,
            object_id,
            cookie,
            timestamp,
            is_dir: false,
        }
    }

    /// Return `true` if this event can be merged with `other`.
    ///
    /// Two events are mergeable when they have the same object and mask
    /// (coalescing avoids queue flooding for repeated identical events).
    pub fn can_merge_with(self, other: Self) -> bool {
        self.object_id == other.object_id && self.mask == other.mask && self.cookie == 0
    }
}

// ── OverflowPolicy ───────────────────────────────────────────────

/// How a group handles events when its queue is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OverflowPolicy {
    /// Drop the oldest event and enqueue the new one.
    #[default]
    DropOldest,
    /// Drop the new event (oldest is preserved).
    DropNewest,
    /// Enqueue a synthetic overflow event and drop new events.
    SynthOverflow,
}

// ── GroupBackend ─────────────────────────────────────────────────

/// Front-end identity — which notification API this group belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GroupBackend {
    /// Group is an inotify instance.
    #[default]
    Inotify,
    /// Group is a fanotify instance.
    Fanotify,
    /// Other or unset.
    Other,
}

// ── FsnotifyGroup ────────────────────────────────────────────────

/// A notification subscriber — one per `inotify_init` or `fanotify_init` call.
///
/// The group holds:
/// - A priority (lower value = higher priority in dispatch order)
/// - A set of marks defining what the group watches
/// - A fixed-size event ring buffer
#[derive(Debug)]
pub struct FsnotifyGroup {
    /// Unique group identifier.
    pub group_id: u32,
    /// Front-end backend type.
    pub backend: GroupBackend,
    /// Dispatch priority (lower = higher priority).
    pub priority: u32,
    /// Overflow handling policy.
    pub overflow_policy: OverflowPolicy,
    /// Marks owned by this group: (mark_id, FsnotifyMark) pairs.
    marks: [(u32, Option<FsnotifyMark>); MAX_MARKS_PER_GROUP],
    mark_count: usize,
    next_mark_id: u32,
    /// Event ring buffer.
    events: [Option<FsnotifyEvent>; MAX_EVENTS_PER_GROUP],
    event_head: usize,
    event_tail: usize,
    event_count: usize,
    /// Total overflow counter.
    pub overflow_count: u64,
}

impl FsnotifyGroup {
    /// Create a new group.
    pub fn new(group_id: u32, backend: GroupBackend, priority: u32) -> Self {
        Self {
            group_id,
            backend,
            priority,
            overflow_policy: OverflowPolicy::SynthOverflow,
            marks: core::array::from_fn(|_| (0, None)),
            mark_count: 0,
            next_mark_id: 1,
            events: [None; MAX_EVENTS_PER_GROUP],
            event_head: 0,
            event_tail: 0,
            event_count: 0,
            overflow_count: 0,
        }
    }

    /// Add a mark to this group.
    ///
    /// Returns the new mark's ID or `Err(Error::OutOfMemory)`.
    pub fn add_mark(
        &mut self,
        mark_type: MarkType,
        object_id: u64,
        mask: FsnotifyMask,
    ) -> Result<u32> {
        if self.mark_count >= MAX_MARKS_PER_GROUP {
            return Err(Error::OutOfMemory);
        }
        let mark_id = self.next_mark_id;
        self.next_mark_id += 1;
        let mark = FsnotifyMark::new(mark_id, mark_type, object_id, mask, self.group_id);
        for slot in self.marks.iter_mut() {
            if slot.1.is_none() {
                *slot = (mark_id, Some(mark));
                self.mark_count += 1;
                return Ok(mark_id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a mark by ID.
    pub fn remove_mark(&mut self, mark_id: u32) -> Result<()> {
        for slot in self.marks.iter_mut() {
            if slot.0 == mark_id && slot.1.is_some() {
                slot.1 = None;
                self.mark_count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Look up a mark by ID.
    pub fn get_mark(&self, mark_id: u32) -> Option<&FsnotifyMark> {
        for slot in &self.marks {
            if slot.0 == mark_id {
                return slot.1.as_ref();
            }
        }
        None
    }

    /// Enqueue an event for this group.
    ///
    /// If the queue is full, the configured [`OverflowPolicy`] is applied.
    pub fn enqueue(&mut self, event: FsnotifyEvent) -> Result<()> {
        // Try to merge with the most recent queued event.
        if self.event_count > 0 {
            let tail = (self.event_tail + MAX_EVENTS_PER_GROUP - 1) % MAX_EVENTS_PER_GROUP;
            if let Some(last) = self.events[tail] {
                if last.can_merge_with(event) {
                    // Merged — no new slot needed.
                    return Ok(());
                }
            }
        }

        if self.event_count >= MAX_EVENTS_PER_GROUP {
            self.overflow_count += 1;
            match self.overflow_policy {
                OverflowPolicy::DropNewest => return Ok(()),
                OverflowPolicy::DropOldest => {
                    // Advance head to discard oldest.
                    self.event_head = (self.event_head + 1) % MAX_EVENTS_PER_GROUP;
                    self.event_count -= 1;
                }
                OverflowPolicy::SynthOverflow => {
                    // Replace the oldest with an overflow event and drop new.
                    let overflow_event = FsnotifyEvent::new(
                        FsnotifyMask::from_bits(FS_Q_OVERFLOW),
                        0,
                        0,
                        event.timestamp,
                    );
                    self.events[self.event_head] = Some(overflow_event);
                    self.event_head = (self.event_head + 1) % MAX_EVENTS_PER_GROUP;
                    return Ok(());
                }
            }
        }

        self.events[self.event_tail] = Some(event);
        self.event_tail = (self.event_tail + 1) % MAX_EVENTS_PER_GROUP;
        self.event_count += 1;
        Ok(())
    }

    /// Dequeue the oldest event.
    ///
    /// Returns `None` if the queue is empty.
    pub fn dequeue(&mut self) -> Option<FsnotifyEvent> {
        if self.event_count == 0 {
            return None;
        }
        let ev = self.events[self.event_head].take();
        self.event_head = (self.event_head + 1) % MAX_EVENTS_PER_GROUP;
        self.event_count -= 1;
        ev
    }

    /// Return the number of pending events.
    pub fn pending_events(&self) -> usize {
        self.event_count
    }

    /// Return the number of marks.
    pub fn mark_count(&self) -> usize {
        self.mark_count
    }

    /// Check whether this group has a mark interested in `event` on `object_id`.
    pub fn interested_in(&self, object_id: u64, event: FsnotifyMask) -> bool {
        for slot in &self.marks {
            if let Some(mark) = &slot.1 {
                if mark.object_id == object_id && mark.matches(event) {
                    return true;
                }
            }
        }
        false
    }
}

// ── FsnotifyRegistry ─────────────────────────────────────────────

/// Global registry of all active fsnotify groups and connectors.
///
/// The VFS calls [`FsnotifyRegistry::dispatch`] on every filesystem
/// operation. The registry walks the connector attached to the affected
/// object and fans out the event to all interested groups in priority order.
#[derive(Debug)]
pub struct FsnotifyRegistry {
    groups: [Option<FsnotifyGroup>; MAX_GROUPS],
    group_count: usize,
    next_group_id: u32,
    connectors: [Option<Connector>; MAX_CONNECTORS],
    connector_count: usize,
}

impl FsnotifyRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            groups: [const { None }; MAX_GROUPS],
            group_count: 0,
            next_group_id: 1,
            connectors: [const { None }; MAX_CONNECTORS],
            connector_count: 0,
        }
    }

    // ── Group management ──────────────────────────────────────────

    /// Create a new group and return its ID.
    ///
    /// Returns `Err(Error::OutOfMemory)` if the registry is full.
    pub fn create_group(&mut self, backend: GroupBackend, priority: u32) -> Result<u32> {
        if self.group_count >= MAX_GROUPS {
            return Err(Error::OutOfMemory);
        }
        let group_id = self.next_group_id;
        self.next_group_id += 1;
        let group = FsnotifyGroup::new(group_id, backend, priority);
        for slot in self.groups.iter_mut() {
            if slot.is_none() {
                *slot = Some(group);
                self.group_count += 1;
                return Ok(group_id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Destroy a group and remove all its marks from connectors.
    pub fn destroy_group(&mut self, group_id: u32) -> Result<()> {
        let slot = self.find_group_slot(group_id).ok_or(Error::NotFound)?;
        let group = self.groups[slot].take().ok_or(Error::NotFound)?;
        self.group_count -= 1;

        // Remove all marks from their connectors.
        for (mark_id, mark_opt) in &group.marks {
            if let Some(mark) = mark_opt {
                if let Some(ci) = self.find_connector(mark.mark_type, mark.object_id) {
                    if let Some(conn) = self.connectors[ci].as_mut() {
                        conn.detach_mark(group.group_id, *mark_id);
                    }
                }
            }
        }
        Ok(())
    }

    /// Return a reference to a group by ID.
    pub fn get_group(&self, group_id: u32) -> Option<&FsnotifyGroup> {
        let slot = self.find_group_slot(group_id)?;
        self.groups[slot].as_ref()
    }

    /// Return a mutable reference to a group by ID.
    pub fn get_group_mut(&mut self, group_id: u32) -> Option<&mut FsnotifyGroup> {
        let slot = self.find_group_slot(group_id)?;
        self.groups[slot].as_mut()
    }

    // ── Mark management ───────────────────────────────────────────

    /// Add a mark to a group and attach it to the object's connector.
    ///
    /// Creates the connector if one does not yet exist for the object.
    pub fn add_mark(
        &mut self,
        group_id: u32,
        mark_type: MarkType,
        object_id: u64,
        mask: FsnotifyMask,
    ) -> Result<u32> {
        // Add mark to group.
        let group_slot = self.find_group_slot(group_id).ok_or(Error::NotFound)?;
        let mark_id = {
            let group = self.groups[group_slot].as_mut().ok_or(Error::NotFound)?;
            group.add_mark(mark_type, object_id, mask)?
        };

        // Attach mark to connector (create if needed).
        let ci = match self.find_connector(mark_type, object_id) {
            Some(i) => i,
            None => {
                if self.connector_count >= MAX_CONNECTORS {
                    // Rollback the mark addition.
                    if let Some(group) = self.groups[group_slot].as_mut() {
                        let _ = group.remove_mark(mark_id);
                    }
                    return Err(Error::OutOfMemory);
                }
                let conn = Connector::new(mark_type, object_id);
                let conn_len = self.connectors.len();
                let free_slot = self.connectors.iter().position(|s| s.is_none());
                match free_slot {
                    Some(idx) => {
                        self.connectors[idx] = Some(conn);
                        self.connector_count += 1;
                    }
                    None => {
                        if let Some(group) = self.groups[group_slot].as_mut() {
                            let _ = group.remove_mark(mark_id);
                        }
                        let _ = conn_len; // suppress unused
                        return Err(Error::OutOfMemory);
                    }
                }
                self.find_connector(mark_type, object_id)
                    .ok_or(Error::OutOfMemory)?
            }
        };

        let conn = self.connectors[ci].as_mut().ok_or(Error::NotFound)?;
        conn.attach_mark(group_id, mark_id, mask)?;
        Ok(mark_id)
    }

    /// Remove a mark from a group and detach it from its connector.
    pub fn remove_mark(&mut self, group_id: u32, mark_id: u32) -> Result<()> {
        let group_slot = self.find_group_slot(group_id).ok_or(Error::NotFound)?;

        // Look up mark details before removing.
        let (mark_type, object_id) = {
            let group = self.groups[group_slot].as_ref().ok_or(Error::NotFound)?;
            let mark = group.get_mark(mark_id).ok_or(Error::NotFound)?;
            (mark.mark_type, mark.object_id)
        };

        // Detach from connector.
        if let Some(ci) = self.find_connector(mark_type, object_id) {
            if let Some(conn) = self.connectors[ci].as_mut() {
                conn.detach_mark(group_id, mark_id);
                // Remove empty connectors.
                if conn.mark_count() == 0 {
                    self.connectors[ci] = None;
                    self.connector_count -= 1;
                }
            }
        }

        // Remove from group.
        let group = self.groups[group_slot].as_mut().ok_or(Error::NotFound)?;
        group.remove_mark(mark_id)
    }

    // ── Event dispatch ────────────────────────────────────────────

    /// Main dispatch entry point.
    ///
    /// Called by VFS operations when a filesystem event occurs.
    /// Walks the connector for the affected object and fans out the
    /// event to all matching groups in ascending priority order.
    pub fn dispatch(
        &mut self,
        mark_type: MarkType,
        object_id: u64,
        mask: FsnotifyMask,
        cookie: u32,
        timestamp: u64,
    ) -> Result<()> {
        let ci = match self.find_connector(mark_type, object_id) {
            Some(i) => i,
            None => return Ok(()), // No watchers — fast path.
        };

        // Collect matching (group_id, priority) pairs.
        let mut targets: [(u32, u32); MAX_MARKS_PER_CONNECTOR] = [(0, 0); MAX_MARKS_PER_CONNECTOR];
        let mut target_count = 0usize;

        {
            let conn = self.connectors[ci].as_ref().ok_or(Error::NotFound)?;
            if !conn.interested_in(mask) {
                return Ok(());
            }
            for (group_id, _mark_id) in conn.iter_marks() {
                if let Some(gslot) = self.find_group_slot(group_id) {
                    if let Some(group) = &self.groups[gslot] {
                        if group.interested_in(object_id, mask)
                            && target_count < MAX_MARKS_PER_CONNECTOR
                        {
                            targets[target_count] = (group_id, group.priority);
                            target_count += 1;
                        }
                    }
                }
            }
        }

        // Sort by priority (simple insertion sort — small array).
        for i in 1..target_count {
            let key = targets[i];
            let mut j = i;
            while j > 0 && targets[j - 1].1 > key.1 {
                targets[j] = targets[j - 1];
                j -= 1;
            }
            targets[j] = key;
        }

        // Deliver the event to each group in priority order.
        let event = FsnotifyEvent::new(mask, object_id, cookie, timestamp);
        for &(group_id, _priority) in &targets[..target_count] {
            if let Some(gslot) = self.find_group_slot(group_id) {
                if let Some(group) = self.groups[gslot].as_mut() {
                    let _ = group.enqueue(event);
                }
            }
        }
        Ok(())
    }

    /// Read the next pending event from a group (consumer API).
    pub fn read_event(&mut self, group_id: u32) -> Option<FsnotifyEvent> {
        let slot = self.find_group_slot(group_id)?;
        self.groups[slot].as_mut()?.dequeue()
    }

    /// Return the number of pending events for a group.
    pub fn pending_events(&self, group_id: u32) -> usize {
        let slot = match self.find_group_slot(group_id) {
            Some(s) => s,
            None => return 0,
        };
        self.groups[slot].as_ref().map_or(0, |g| g.pending_events())
    }

    // ── Statistics ────────────────────────────────────────────────

    /// Return the total number of registered groups.
    pub fn group_count(&self) -> usize {
        self.group_count
    }

    /// Return the total number of live connectors.
    pub fn connector_count(&self) -> usize {
        self.connector_count
    }

    // ── Internal helpers ──────────────────────────────────────────

    fn find_group_slot(&self, group_id: u32) -> Option<usize> {
        for (i, slot) in self.groups.iter().enumerate() {
            if let Some(g) = slot {
                if g.group_id == group_id {
                    return Some(i);
                }
            }
        }
        None
    }

    fn find_connector(&self, mark_type: MarkType, object_id: u64) -> Option<usize> {
        for (i, slot) in self.connectors.iter().enumerate() {
            if let Some(c) = slot {
                if c.object_type == mark_type && c.object_id == object_id {
                    return Some(i);
                }
            }
        }
        None
    }
}

impl Default for FsnotifyRegistry {
    fn default() -> Self {
        Self::new()
    }
}
