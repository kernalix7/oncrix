// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! fsnotify group management — notification group lifecycle and event delivery.
//!
//! A notification group is the core abstraction connecting filesystem event
//! producers (VFS operations) with consumers (user-space applications via
//! `inotify_init()` or `fanotify_init()`).  Each group owns a set of marks
//! (watches) and an event queue.
//!
//! # Architecture
//!
//! ```text
//! +-------------------------------------------------------------+
//! |  VFS operation (write, rename, unlink, ...)                  |
//! |       |                                                      |
//! |       v                                                      |
//! |  fsnotify dispatch (notify.rs / fsnotify.rs)                 |
//! |       |                                                      |
//! |       v                                                      |
//! |  +----------------------------------------------+            |
//! |  | NotifyGroupRegistry                          |            |
//! |  | +------------------------------------------+ |            |
//! |  | | Group 0: inotify, prio 0                 | |            |
//! |  | |  marks: [inode:42, inode:99]             | |            |
//! |  | |  queue: [ev, ev, ev, ...]                | |            |
//! |  | +------------------------------------------+ |            |
//! |  | +------------------------------------------+ |            |
//! |  | | Group 1: fanotify, prio 1                | |            |
//! |  | |  marks: [mount:/mnt/data]                | |            |
//! |  | |  queue: [ev, ...]                        | |            |
//! |  | +------------------------------------------+ |            |
//! |  +----------------------------------------------+            |
//! |       |                                                      |
//! |       v                                                      |
//! |  User reads /dev/inotify fd  -->  dequeue events             |
//! +-------------------------------------------------------------+
//! ```
//!
//! # Event merging
//!
//! Consecutive identical events (same mask, same inode, same name) are
//! coalesced into a single event to reduce queue pressure.
//!
//! # Priority
//!
//! Groups are processed in priority order. Higher-priority groups
//! (e.g., fanotify permission groups) are notified before lower-priority
//! ones.
//!
//! # Reference
//!
//! Linux `fs/notify/group.c`, `fs/notify/mark.c`,
//! `include/linux/fsnotify_backend.h`.

extern crate alloc;

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of notification groups.
const MAX_GROUPS: usize = 32;

/// Maximum marks (watches) per group.
const MAX_MARKS_PER_GROUP: usize = 64;

/// Maximum pending events per group.
const MAX_EVENTS_PER_GROUP: usize = 256;

/// Maximum filename length stored in an event.
const MAX_NAME_LEN: usize = 255;

/// Sentinel for "no entry".
const NONE_IDX: u32 = u32::MAX;

// ── Event mask constants ─────────────────────────────────────────────────────

/// File was accessed (read).
pub const NOTIFY_ACCESS: u64 = 0x0001;
/// File data was modified.
pub const NOTIFY_MODIFY: u64 = 0x0002;
/// Inode metadata changed.
pub const NOTIFY_ATTRIB: u64 = 0x0004;
/// Writable file descriptor closed.
pub const NOTIFY_CLOSE_WRITE: u64 = 0x0008;
/// Read-only file descriptor closed.
pub const NOTIFY_CLOSE_NOWRITE: u64 = 0x0010;
/// File was opened.
pub const NOTIFY_OPEN: u64 = 0x0020;
/// File moved out of a watched directory.
pub const NOTIFY_MOVED_FROM: u64 = 0x0040;
/// File moved into a watched directory.
pub const NOTIFY_MOVED_TO: u64 = 0x0080;
/// File/dir created in watched directory.
pub const NOTIFY_CREATE: u64 = 0x0100;
/// File/dir deleted from watched directory.
pub const NOTIFY_DELETE: u64 = 0x0200;
/// Watched inode itself was deleted.
pub const NOTIFY_DELETE_SELF: u64 = 0x0400;
/// Watched inode itself was moved.
pub const NOTIFY_MOVE_SELF: u64 = 0x0800;
/// Queue overflow.
pub const NOTIFY_OVERFLOW: u64 = 0x4000;
/// Event target is a directory.
pub const NOTIFY_ISDIR: u64 = 0x0001_0000;
/// Permission check event (fanotify).
pub const NOTIFY_OPEN_PERM: u64 = 0x0010_0000;
/// Permission check before access (fanotify).
pub const NOTIFY_ACCESS_PERM: u64 = 0x0020_0000;

/// All data-change events combined.
pub const NOTIFY_ALL_EVENTS: u64 = NOTIFY_ACCESS
    | NOTIFY_MODIFY
    | NOTIFY_ATTRIB
    | NOTIFY_CLOSE_WRITE
    | NOTIFY_CLOSE_NOWRITE
    | NOTIFY_OPEN
    | NOTIFY_MOVED_FROM
    | NOTIFY_MOVED_TO
    | NOTIFY_CREATE
    | NOTIFY_DELETE
    | NOTIFY_DELETE_SELF
    | NOTIFY_MOVE_SELF;

// ── GroupType ────────────────────────────────────────────────────────────────

/// Type of notification group backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupType {
    /// inotify-based group.
    Inotify,
    /// fanotify-based group.
    Fanotify,
    /// dnotify (legacy directory notify).
    Dnotify,
}

// ── MarkType ─────────────────────────────────────────────────────────────────

/// Type of object a mark is attached to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkType {
    /// Mark attached to an inode.
    Inode,
    /// Mark attached to a mount point.
    Mount,
    /// Mark attached to a superblock (filesystem-wide).
    Superblock,
}

// ── NotifyPermission ─────────────────────────────────────────────────────────

/// Permission response from a fanotify permission group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyPermission {
    /// Allow the operation.
    Allow,
    /// Deny the operation.
    Deny,
    /// No permission check required.
    NoCheck,
}

// ── GroupMark ────────────────────────────────────────────────────────────────

/// A mark (watch) attached to a filesystem object by a notification group.
#[derive(Clone, Copy)]
pub struct GroupMark {
    /// Unique mark ID within the group.
    pub mark_id: u32,
    /// Type of object being watched.
    pub mark_type: MarkType,
    /// Object identifier (inode number, mount ID, or superblock ID).
    pub object_id: u64,
    /// Event mask — which events this mark subscribes to.
    pub mask: u64,
    /// Ignored mask — events that are suppressed for this mark.
    pub ignored_mask: u64,
    /// Whether this is a one-shot mark (auto-removed after first event).
    pub oneshot: bool,
    /// Whether this mark is active.
    pub active: bool,
    /// Reference count.
    pub ref_count: u32,
}

impl GroupMark {
    /// Create an empty, inactive mark.
    const fn empty() -> Self {
        Self {
            mark_id: 0,
            mark_type: MarkType::Inode,
            object_id: 0,
            mask: 0,
            ignored_mask: 0,
            oneshot: false,
            active: false,
            ref_count: 0,
        }
    }

    /// Whether a given event mask matches this mark.
    pub fn matches_event(&self, event_mask: u64) -> bool {
        self.active && (self.mask & event_mask) != 0 && (self.ignored_mask & event_mask) == 0
    }
}

// ── NotifyEvent ──────────────────────────────────────────────────────────────

/// A queued filesystem notification event.
#[derive(Clone, Copy)]
pub struct NotifyEvent {
    /// Event mask (which events occurred).
    pub mask: u64,
    /// Object identifier (inode number).
    pub object_id: u64,
    /// Cookie for correlating MOVED_FROM/MOVED_TO pairs.
    pub cookie: u32,
    /// Mark ID that triggered this event.
    pub mark_id: u32,
    /// Filename associated with the event (for directory events).
    name: [u8; MAX_NAME_LEN],
    /// Filename length.
    name_len: u8,
    /// Timestamp (monotonic ticks).
    pub timestamp: u64,
    /// Whether this event requires a permission response.
    pub needs_permission: bool,
    /// Permission response (if applicable).
    pub permission: NotifyPermission,
    /// Whether this slot is in use.
    in_use: bool,
}

impl NotifyEvent {
    /// Create an empty, unused event.
    const fn empty() -> Self {
        Self {
            mask: 0,
            object_id: 0,
            cookie: 0,
            mark_id: 0,
            name: [0; MAX_NAME_LEN],
            name_len: 0,
            timestamp: 0,
            needs_permission: false,
            permission: NotifyPermission::NoCheck,
            in_use: false,
        }
    }

    /// Return the event name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Whether this event can be merged with another event.
    fn can_merge_with(&self, other: &NotifyEvent) -> bool {
        self.mask == other.mask
            && self.object_id == other.object_id
            && self.name_len == other.name_len
            && self.name[..self.name_len as usize] == other.name[..other.name_len as usize]
            && !self.needs_permission
            && !other.needs_permission
    }
}

// ── EventQueue ───────────────────────────────────────────────────────────────

/// Ring-buffer event queue for a notification group.
struct EventQueue {
    /// Event storage.
    events: [NotifyEvent; MAX_EVENTS_PER_GROUP],
    /// Read index (consumer).
    read_idx: usize,
    /// Write index (producer).
    write_idx: usize,
    /// Number of events in the queue.
    count: usize,
    /// Number of events dropped due to overflow.
    overflow_count: u64,
}

impl EventQueue {
    /// Create an empty event queue.
    const fn new() -> Self {
        Self {
            events: [const { NotifyEvent::empty() }; MAX_EVENTS_PER_GROUP],
            read_idx: 0,
            write_idx: 0,
            count: 0,
            overflow_count: 0,
        }
    }

    /// Whether the queue is empty.
    fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Whether the queue is full.
    fn is_full(&self) -> bool {
        self.count >= MAX_EVENTS_PER_GROUP
    }

    /// Number of pending events.
    fn pending(&self) -> usize {
        self.count
    }

    /// Try to merge with the last queued event.
    fn try_merge(&self, event: &NotifyEvent) -> bool {
        if self.count == 0 {
            return false;
        }
        let last_idx = if self.write_idx == 0 {
            MAX_EVENTS_PER_GROUP - 1
        } else {
            self.write_idx - 1
        };
        self.events[last_idx].in_use && self.events[last_idx].can_merge_with(event)
    }

    /// Enqueue an event.
    fn enqueue(&mut self, event: NotifyEvent) -> Result<()> {
        if self.is_full() {
            self.overflow_count += 1;
            return Err(Error::OutOfMemory);
        }

        // Try to merge with the previous event.
        if self.try_merge(&event) {
            return Ok(());
        }

        self.events[self.write_idx] = event;
        self.events[self.write_idx].in_use = true;
        self.write_idx = (self.write_idx + 1) % MAX_EVENTS_PER_GROUP;
        self.count += 1;
        Ok(())
    }

    /// Dequeue the next event.
    fn dequeue(&mut self) -> Option<NotifyEvent> {
        if self.is_empty() {
            return None;
        }
        let event = self.events[self.read_idx];
        self.events[self.read_idx].in_use = false;
        self.read_idx = (self.read_idx + 1) % MAX_EVENTS_PER_GROUP;
        self.count -= 1;
        Some(event)
    }

    /// Peek at the next event without removing it.
    fn peek(&self) -> Option<&NotifyEvent> {
        if self.is_empty() {
            return None;
        }
        Some(&self.events[self.read_idx])
    }

    /// Flush all events from the queue.
    fn flush(&mut self) -> usize {
        let flushed = self.count;
        for ev in &mut self.events {
            ev.in_use = false;
        }
        self.read_idx = 0;
        self.write_idx = 0;
        self.count = 0;
        flushed
    }
}

// ── NotifyGroup ──────────────────────────────────────────────────────────────

/// A filesystem notification group.
///
/// Owns a set of marks and an event queue. When a VFS operation matches
/// one of the group's marks, an event is queued for user-space consumption.
struct NotifyGroup {
    /// Unique group ID.
    id: u32,
    /// Group type (inotify, fanotify, dnotify).
    group_type: GroupType,
    /// Priority (higher = notified first).
    priority: u32,
    /// Marks owned by this group.
    marks: [GroupMark; MAX_MARKS_PER_GROUP],
    /// Number of active marks.
    mark_count: usize,
    /// Next mark ID to allocate.
    next_mark_id: u32,
    /// Event queue.
    queue: EventQueue,
    /// Whether this group is active.
    active: bool,
    /// Owner process ID.
    owner_pid: u32,
    /// Maximum allowed marks.
    max_marks: usize,
    /// Whether permission events are enabled (fanotify only).
    permission_events: bool,
    /// Monotonic timestamp counter.
    timestamp: u64,
}

impl NotifyGroup {
    /// Create an empty, inactive group.
    const fn empty() -> Self {
        Self {
            id: 0,
            group_type: GroupType::Inotify,
            priority: 0,
            marks: [const { GroupMark::empty() }; MAX_MARKS_PER_GROUP],
            mark_count: 0,
            next_mark_id: 1,
            queue: EventQueue::new(),
            active: false,
            owner_pid: 0,
            max_marks: MAX_MARKS_PER_GROUP,
            permission_events: false,
            timestamp: 0,
        }
    }
}

// ── NotifyGroupRegistry ──────────────────────────────────────────────────────

/// Global registry of all active notification groups.
///
/// Provides group lifecycle management and event dispatch.
pub struct NotifyGroupRegistry {
    /// Registered groups.
    groups: [NotifyGroup; MAX_GROUPS],
    /// Next group ID to allocate.
    next_group_id: u32,
    /// Total events dispatched.
    total_events: u64,
    /// Total events dropped across all groups.
    total_drops: u64,
}

impl NotifyGroupRegistry {
    /// Create a new empty registry.
    pub const fn new() -> Self {
        Self {
            groups: [const { NotifyGroup::empty() }; MAX_GROUPS],
            next_group_id: 1,
            total_events: 0,
            total_drops: 0,
        }
    }

    // ── Group lifecycle ──────────────────────────────────────────

    /// Create a new notification group, returning its ID.
    pub fn create_group(
        &mut self,
        group_type: GroupType,
        priority: u32,
        owner_pid: u32,
    ) -> Result<u32> {
        let slot = self
            .groups
            .iter_mut()
            .find(|g| !g.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_group_id;
        self.next_group_id += 1;

        slot.id = id;
        slot.group_type = group_type;
        slot.priority = priority;
        slot.mark_count = 0;
        slot.next_mark_id = 1;
        slot.queue.flush();
        slot.active = true;
        slot.owner_pid = owner_pid;
        slot.permission_events = matches!(group_type, GroupType::Fanotify);
        slot.timestamp = 0;

        Ok(id)
    }

    /// Destroy a notification group and release all its marks.
    pub fn destroy_group(&mut self, group_id: u32) -> Result<()> {
        let group = self
            .groups
            .iter_mut()
            .find(|g| g.active && g.id == group_id)
            .ok_or(Error::NotFound)?;

        // Deactivate all marks.
        for mark in &mut group.marks {
            mark.active = false;
        }
        group.mark_count = 0;
        group.queue.flush();
        group.active = false;

        Ok(())
    }

    // ── Mark management ──────────────────────────────────────────

    /// Add a mark (watch) to a group.
    ///
    /// Returns the mark ID on success.
    pub fn add_mark(
        &mut self,
        group_id: u32,
        mark_type: MarkType,
        object_id: u64,
        mask: u64,
    ) -> Result<u32> {
        let group = self
            .groups
            .iter_mut()
            .find(|g| g.active && g.id == group_id)
            .ok_or(Error::NotFound)?;

        if group.mark_count >= group.max_marks {
            return Err(Error::OutOfMemory);
        }

        // Check if a mark already exists for this object.
        for mark in &mut group.marks {
            if mark.active && mark.object_id == object_id && mark.mark_type as u8 == mark_type as u8
            {
                // Update existing mark's mask.
                mark.mask |= mask;
                return Ok(mark.mark_id);
            }
        }

        // Allocate a new mark.
        let slot = group
            .marks
            .iter_mut()
            .find(|m| !m.active)
            .ok_or(Error::OutOfMemory)?;

        let mark_id = group.next_mark_id;
        group.next_mark_id += 1;

        slot.mark_id = mark_id;
        slot.mark_type = mark_type;
        slot.object_id = object_id;
        slot.mask = mask;
        slot.ignored_mask = 0;
        slot.oneshot = false;
        slot.active = true;
        slot.ref_count = 1;
        group.mark_count += 1;

        Ok(mark_id)
    }

    /// Remove a mark from a group.
    pub fn remove_mark(&mut self, group_id: u32, mark_id: u32) -> Result<()> {
        let group = self
            .groups
            .iter_mut()
            .find(|g| g.active && g.id == group_id)
            .ok_or(Error::NotFound)?;

        let mark = group
            .marks
            .iter_mut()
            .find(|m| m.active && m.mark_id == mark_id)
            .ok_or(Error::NotFound)?;

        mark.active = false;
        mark.ref_count = 0;
        group.mark_count = group.mark_count.saturating_sub(1);

        Ok(())
    }

    /// Update the event mask on an existing mark.
    pub fn update_mark_mask(&mut self, group_id: u32, mark_id: u32, new_mask: u64) -> Result<()> {
        let group = self
            .groups
            .iter_mut()
            .find(|g| g.active && g.id == group_id)
            .ok_or(Error::NotFound)?;

        let mark = group
            .marks
            .iter_mut()
            .find(|m| m.active && m.mark_id == mark_id)
            .ok_or(Error::NotFound)?;

        mark.mask = new_mask;
        Ok(())
    }

    /// Set the ignored mask on a mark.
    pub fn set_ignored_mask(&mut self, group_id: u32, mark_id: u32, ignored: u64) -> Result<()> {
        let group = self
            .groups
            .iter_mut()
            .find(|g| g.active && g.id == group_id)
            .ok_or(Error::NotFound)?;

        let mark = group
            .marks
            .iter_mut()
            .find(|m| m.active && m.mark_id == mark_id)
            .ok_or(Error::NotFound)?;

        mark.ignored_mask = ignored;
        Ok(())
    }

    // ── Event dispatch ───────────────────────────────────────────

    /// Queue an event to all groups that have a matching mark.
    ///
    /// The event is dispatched to groups in priority order (highest first).
    /// Returns the number of groups that received the event.
    pub fn queue_event(
        &mut self,
        object_id: u64,
        mask: u64,
        name: &[u8],
        cookie: u32,
    ) -> Result<u32> {
        let name_len = name.len().min(MAX_NAME_LEN);
        let mut dispatched = 0u32;

        // Sort groups by priority (simple selection: process highest first).
        let mut order = [NONE_IDX; MAX_GROUPS];
        let mut order_count = 0usize;

        // Collect active group indices.
        for (i, g) in self.groups.iter().enumerate() {
            if g.active {
                order[order_count] = i as u32;
                order_count += 1;
            }
        }

        // Sort by priority descending (bubble sort on small array).
        for i in 0..order_count {
            for j in (i + 1)..order_count {
                let gi = order[i] as usize;
                let gj = order[j] as usize;
                if self.groups[gi].priority < self.groups[gj].priority {
                    order.swap(i, j);
                }
            }
        }

        // Dispatch to each matching group.
        for idx in &order[..order_count] {
            let g_idx = *idx as usize;
            let group = &mut self.groups[g_idx];

            // Check if any mark matches.
            let mut mark_id = 0u32;
            let mut matched = false;
            for mark in &mut group.marks {
                if mark.matches_event(mask)
                    && (mark.mark_type == MarkType::Superblock || mark.object_id == object_id)
                {
                    mark_id = mark.mark_id;
                    matched = true;

                    // Handle oneshot marks.
                    if mark.oneshot {
                        mark.active = false;
                        group.mark_count = group.mark_count.saturating_sub(1);
                    }
                    break;
                }
            }

            if !matched {
                continue;
            }

            group.timestamp += 1;
            let ts = group.timestamp;
            let needs_perm =
                group.permission_events && (mask & (NOTIFY_OPEN_PERM | NOTIFY_ACCESS_PERM)) != 0;

            let mut event = NotifyEvent::empty();
            event.mask = mask;
            event.object_id = object_id;
            event.cookie = cookie;
            event.mark_id = mark_id;
            if name_len > 0 {
                event.name[..name_len].copy_from_slice(&name[..name_len]);
            }
            event.name_len = name_len as u8;
            event.timestamp = ts;
            event.needs_permission = needs_perm;
            event.permission = NotifyPermission::NoCheck;

            match group.queue.enqueue(event) {
                Ok(()) => {
                    dispatched += 1;
                    self.total_events += 1;
                }
                Err(_) => {
                    self.total_drops += 1;
                }
            }
        }

        Ok(dispatched)
    }

    // ── Event consumption ────────────────────────────────────────

    /// Read (dequeue) the next event from a group.
    pub fn read_event(&mut self, group_id: u32) -> Result<Option<NotifyEvent>> {
        let group = self
            .groups
            .iter_mut()
            .find(|g| g.active && g.id == group_id)
            .ok_or(Error::NotFound)?;

        Ok(group.queue.dequeue())
    }

    /// Read multiple events from a group into a caller-supplied buffer.
    ///
    /// Returns the number of events read.
    pub fn read_events(&mut self, group_id: u32, buf: &mut [NotifyEvent]) -> Result<usize> {
        let group = self
            .groups
            .iter_mut()
            .find(|g| g.active && g.id == group_id)
            .ok_or(Error::NotFound)?;

        let mut count = 0usize;
        while count < buf.len() {
            if let Some(ev) = group.queue.dequeue() {
                buf[count] = ev;
                count += 1;
            } else {
                break;
            }
        }
        Ok(count)
    }

    /// Peek at the next event without removing it.
    pub fn peek_event(&self, group_id: u32) -> Result<Option<&NotifyEvent>> {
        let group = self
            .groups
            .iter()
            .find(|g| g.active && g.id == group_id)
            .ok_or(Error::NotFound)?;

        Ok(group.queue.peek())
    }

    /// Respond to a permission event.
    pub fn respond_permission(
        &mut self,
        group_id: u32,
        cookie: u32,
        response: NotifyPermission,
    ) -> Result<()> {
        let _ = (group_id, cookie, response);
        // Permission event response is a no-op in this model —
        // a real implementation would unblock the waiting VFS thread.
        Ok(())
    }

    // ── Queries ──────────────────────────────────────────────────

    /// Return the number of pending events for a group.
    pub fn pending_events(&self, group_id: u32) -> Result<usize> {
        let group = self
            .groups
            .iter()
            .find(|g| g.active && g.id == group_id)
            .ok_or(Error::NotFound)?;

        Ok(group.queue.pending())
    }

    /// Return the number of active groups.
    pub fn active_group_count(&self) -> usize {
        self.groups.iter().filter(|g| g.active).count()
    }

    /// Return total events dispatched across all groups.
    pub fn total_events_dispatched(&self) -> u64 {
        self.total_events
    }

    /// Return total events dropped across all groups.
    pub fn total_events_dropped(&self) -> u64 {
        self.total_drops
    }

    /// Flush all events from a group's queue.
    pub fn flush_events(&mut self, group_id: u32) -> Result<usize> {
        let group = self
            .groups
            .iter_mut()
            .find(|g| g.active && g.id == group_id)
            .ok_or(Error::NotFound)?;

        Ok(group.queue.flush())
    }
}
