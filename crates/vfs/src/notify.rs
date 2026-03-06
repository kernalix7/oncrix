// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Filesystem access notification (fanotify-style).
//!
//! Provides a mechanism for user-space applications to monitor
//! filesystem events such as file access, modification, open, and
//! close. Supports both notification-only and permission-based
//! modes, following the Linux `fanotify(7)` model.
//!
//! # Architecture
//!
//! - **Groups** collect events matching registered marks.
//! - **Marks** bind an event mask to an inode or mount point.
//! - Events are delivered through a per-group ring buffer and
//!   consumed via [`FanotifyRegistry::read_event`].
//!
//! # References
//!
//! - Linux `fanotify_init(2)`, `fanotify_mark(2)`
//! - Linux `fanotify(7)`

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// File was accessed (read).
pub const FAN_ACCESS: u64 = 0x01;
/// File was modified (write).
pub const FAN_MODIFY: u64 = 0x02;
/// Writable file was closed.
pub const FAN_CLOSE_WRITE: u64 = 0x08;
/// Non-writable file was closed.
pub const FAN_CLOSE_NOWRITE: u64 = 0x10;
/// File was opened.
pub const FAN_OPEN: u64 = 0x20;
/// Permission check before opening a file.
pub const FAN_OPEN_PERM: u64 = 0x10000;
/// Permission check before reading a file.
pub const FAN_ACCESS_PERM: u64 = 0x20000;
/// Event occurred against a directory.
pub const FAN_ONDIR: u64 = 0x40000000;
/// Generate events for immediate children of a directory.
pub const FAN_EVENT_ON_CHILD: u64 = 0x08000000;
/// Any close event (write or non-write).
pub const FAN_CLOSE: u64 = FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE;
/// Permission response: allow the operation.
pub const FAN_ALLOW: u32 = 0x01;
/// Permission response: deny the operation.
pub const FAN_DENY: u32 = 0x02;

/// Maximum number of fanotify groups.
pub const MAX_FANOTIFY_GROUPS: usize = 16;
/// Maximum number of marks per group.
pub const MAX_FANOTIFY_MARKS: usize = 128;
/// Maximum number of events in the per-group ring buffer.
pub const MAX_FANOTIFY_EVENTS: usize = 256;

// ── Event Types ─────────────────────────────────────────────────

/// Types of filesystem events that can be observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FanotifyEventType {
    /// File was accessed (read).
    #[default]
    Access,
    /// File was modified (write).
    Modify,
    /// Writable file was closed.
    CloseWrite,
    /// Non-writable file was closed.
    CloseNoWrite,
    /// File was opened.
    Open,
    /// Permission check: file open request.
    OpenPerm,
    /// Permission check: file access request.
    AccessPerm,
}

// ── Event ───────────────────────────────────────────────────────

/// A single filesystem notification event.
#[derive(Debug, Clone, Copy)]
pub struct FanotifyEvent {
    /// The type of event that occurred.
    pub event_type: FanotifyEventType,
    /// Raw event mask bits.
    pub mask: u64,
    /// File descriptor associated with the event.
    pub fd: i32,
    /// PID of the process that triggered the event.
    pub pid: u64,
    /// Inode number of the affected file.
    pub inode: u64,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
}

// ── Mark ────────────────────────────────────────────────────────

/// A mark binding an event mask to an inode or mount point.
#[derive(Debug, Clone, Copy)]
pub struct FanotifyMark {
    /// Bitmask of events to monitor.
    pub mask: u64,
    /// Inode number being watched.
    pub inode: u64,
    /// Mount point identifier.
    pub mount_id: u32,
    /// Additional mark flags.
    pub flags: u32,
    /// Whether this mark is currently active.
    pub active: bool,
}

// ── Group ───────────────────────────────────────────────────────

/// A fanotify group that collects events for matching marks.
pub struct FanotifyGroup {
    /// Unique group identifier.
    pub id: u32,
    /// Group-level flags.
    pub flags: u32,
    /// Aggregate event mask for this group.
    pub event_mask: u64,
    /// Array of marks registered with this group.
    marks: [FanotifyMark; MAX_FANOTIFY_MARKS],
    /// Number of active marks.
    mark_count: usize,
    /// Ring buffer of pending events.
    events: [FanotifyEvent; MAX_FANOTIFY_EVENTS],
    /// Ring buffer head index (next read position).
    head: usize,
    /// Ring buffer tail index (next write position).
    tail: usize,
    /// Number of events currently in the ring buffer.
    count: usize,
    /// PID of the process that owns this group.
    pub owner_pid: u64,
    /// Whether this group is active.
    pub active: bool,
    /// Whether this group handles permission events.
    pub permission_mode: bool,
}

impl FanotifyGroup {
    /// Default mark value used for array initialization.
    const EMPTY_MARK: FanotifyMark = FanotifyMark {
        mask: 0,
        inode: 0,
        mount_id: 0,
        flags: 0,
        active: false,
    };

    /// Default event value used for array initialization.
    const EMPTY_EVENT: FanotifyEvent = FanotifyEvent {
        event_type: FanotifyEventType::Access,
        mask: 0,
        fd: -1,
        pid: 0,
        inode: 0,
        timestamp_ns: 0,
    };

    /// Creates a new fanotify group with the given parameters.
    pub fn new(id: u32, flags: u32, owner_pid: u64) -> Self {
        Self {
            id,
            flags,
            event_mask: 0,
            marks: [Self::EMPTY_MARK; MAX_FANOTIFY_MARKS],
            mark_count: 0,
            events: [Self::EMPTY_EVENT; MAX_FANOTIFY_EVENTS],
            head: 0,
            tail: 0,
            count: 0,
            owner_pid,
            active: true,
            permission_mode: false,
        }
    }

    /// Adds a mark to watch the given inode with the specified
    /// event mask.
    ///
    /// Returns [`Error::OutOfMemory`] if the mark table is full,
    /// or [`Error::AlreadyExists`] if the inode is already marked.
    pub fn add_mark(&mut self, mask: u64, inode: u64, mount_id: u32, flags: u32) -> Result<()> {
        // Check for duplicate inode.
        for i in 0..self.mark_count {
            if self.marks[i].active && self.marks[i].inode == inode {
                return Err(Error::AlreadyExists);
            }
        }

        if self.mark_count >= MAX_FANOTIFY_MARKS {
            return Err(Error::OutOfMemory);
        }

        self.marks[self.mark_count] = FanotifyMark {
            mask,
            inode,
            mount_id,
            flags,
            active: true,
        };
        self.mark_count += 1;
        self.event_mask |= mask;
        Ok(())
    }

    /// Removes the mark associated with the given inode.
    ///
    /// Returns [`Error::NotFound`] if no mark exists for the
    /// inode.
    pub fn remove_mark(&mut self, inode: u64) -> Result<()> {
        for i in 0..self.mark_count {
            if self.marks[i].active && self.marks[i].inode == inode {
                self.marks[i].active = false;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Modifies the event mask for the mark on the given inode.
    ///
    /// Returns [`Error::NotFound`] if no active mark exists for
    /// the inode.
    pub fn modify_mark(&mut self, inode: u64, mask: u64) -> Result<()> {
        for i in 0..self.mark_count {
            if self.marks[i].active && self.marks[i].inode == inode {
                self.marks[i].mask = mask;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Pushes an event into the ring buffer.
    ///
    /// If the buffer is full the oldest event is silently dropped.
    pub fn push_event(&mut self, event: FanotifyEvent) {
        self.events[self.tail] = event;
        self.tail = (self.tail + 1) % MAX_FANOTIFY_EVENTS;

        if self.count == MAX_FANOTIFY_EVENTS {
            // Overwrite oldest — advance head.
            self.head = (self.head + 1) % MAX_FANOTIFY_EVENTS;
        } else {
            self.count += 1;
        }
    }

    /// Pops the oldest event from the ring buffer.
    ///
    /// Returns `None` if no events are pending.
    pub fn pop_event(&mut self) -> Option<FanotifyEvent> {
        if self.count == 0 {
            return None;
        }
        let event = self.events[self.head];
        self.head = (self.head + 1) % MAX_FANOTIFY_EVENTS;
        self.count -= 1;
        Some(event)
    }

    /// Returns the number of pending events in the ring buffer.
    pub fn pending_events(&self) -> usize {
        self.count
    }

    /// Checks whether any active mark in this group matches the
    /// given inode and event mask.
    pub fn matches(&self, inode: u64, mask: u64) -> bool {
        (0..self.mark_count).any(|i| {
            self.marks[i].active && self.marks[i].inode == inode && (self.marks[i].mask & mask) != 0
        })
    }
}

// ── Registry ────────────────────────────────────────────────────

/// Global registry of fanotify groups.
///
/// Provides creation, destruction, and event dispatch across all
/// active groups.
pub struct FanotifyRegistry {
    /// Registered groups (slot is `None` when empty).
    groups: [Option<FanotifyGroup>; MAX_FANOTIFY_GROUPS],
    /// Next group id to assign.
    next_id: u32,
    /// Number of active groups.
    count: usize,
}

impl FanotifyRegistry {
    /// Creates a new, empty fanotify registry.
    pub const fn new() -> Self {
        const NONE: Option<FanotifyGroup> = None;
        Self {
            groups: [NONE; MAX_FANOTIFY_GROUPS],
            next_id: 1,
            count: 0,
        }
    }

    /// Creates a new fanotify group owned by the given process.
    ///
    /// Returns the group id on success, or
    /// [`Error::OutOfMemory`] if the maximum number of groups has
    /// been reached.
    pub fn create_group(&mut self, flags: u32, pid: u64) -> Result<u32> {
        let slot = self.groups.iter().position(|g| g.is_none());
        let slot = match slot {
            Some(s) => s,
            None => return Err(Error::OutOfMemory),
        };

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.groups[slot] = Some(FanotifyGroup::new(id, flags, pid));
        self.count += 1;
        Ok(id)
    }

    /// Destroys the fanotify group with the given id.
    ///
    /// Returns [`Error::NotFound`] if no group with the id
    /// exists.
    pub fn destroy_group(&mut self, id: u32) -> Result<()> {
        let slot = self.find_group_index(id)?;
        self.groups[slot] = None;
        self.count -= 1;
        Ok(())
    }

    /// Adds a mark to the specified group.
    ///
    /// Returns [`Error::NotFound`] if the group does not exist.
    pub fn add_mark(
        &mut self,
        group_id: u32,
        mask: u64,
        inode: u64,
        mount_id: u32,
        flags: u32,
    ) -> Result<()> {
        let slot = self.find_group_index(group_id)?;
        if let Some(g) = &mut self.groups[slot] {
            g.add_mark(mask, inode, mount_id, flags)
        } else {
            Err(Error::NotFound)
        }
    }

    /// Removes the mark for the given inode from the specified
    /// group.
    ///
    /// Returns [`Error::NotFound`] if the group or mark does not
    /// exist.
    pub fn remove_mark(&mut self, group_id: u32, inode: u64) -> Result<()> {
        let slot = self.find_group_index(group_id)?;
        if let Some(g) = &mut self.groups[slot] {
            g.remove_mark(inode)
        } else {
            Err(Error::NotFound)
        }
    }

    /// Dispatches a filesystem event to every group whose marks
    /// match the given inode and mask.
    pub fn notify(&mut self, inode: u64, mask: u64, fd: i32, pid: u64, timestamp: u64) {
        let event_type = mask_to_event_type(mask);
        let event = FanotifyEvent {
            event_type,
            mask,
            fd,
            pid,
            inode,
            timestamp_ns: timestamp,
        };

        for g in self.groups.iter_mut().flatten() {
            if g.active && g.matches(inode, mask) {
                g.push_event(event);
            }
        }
    }

    /// Reads (pops) the next event from the specified group.
    ///
    /// Returns `Ok(None)` when no events are pending.
    pub fn read_event(&mut self, group_id: u32) -> Result<Option<FanotifyEvent>> {
        let slot = self.find_group_index(group_id)?;
        if let Some(g) = &mut self.groups[slot] {
            Ok(g.pop_event())
        } else {
            Err(Error::NotFound)
        }
    }

    /// Responds to a permission event (stub).
    ///
    /// In a full implementation this would unblock the requesting
    /// process and either allow or deny the operation.
    ///
    /// Returns [`Error::NotFound`] if the group does not exist.
    pub fn respond_permission(&mut self, group_id: u32, _fd: i32, _allow: bool) -> Result<()> {
        let slot = self.find_group_index(group_id)?;
        if self.groups[slot].is_some() {
            // Stub: permission response handling is not yet
            // implemented.
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    /// Returns the number of active groups.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no groups are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Finds the slot index for the group with the given id.
    fn find_group_index(&self, id: u32) -> Result<usize> {
        self.groups
            .iter()
            .position(|slot| matches!(slot, Some(g) if g.id == id))
            .ok_or(Error::NotFound)
    }
}

impl Default for FanotifyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helpers ─────────────────────────────────────────────────────

/// Converts a raw event mask to the best-matching event type.
fn mask_to_event_type(mask: u64) -> FanotifyEventType {
    if mask & FAN_ACCESS_PERM != 0 {
        FanotifyEventType::AccessPerm
    } else if mask & FAN_OPEN_PERM != 0 {
        FanotifyEventType::OpenPerm
    } else if mask & FAN_MODIFY != 0 {
        FanotifyEventType::Modify
    } else if mask & FAN_CLOSE_WRITE != 0 {
        FanotifyEventType::CloseWrite
    } else if mask & FAN_CLOSE_NOWRITE != 0 {
        FanotifyEventType::CloseNoWrite
    } else if mask & FAN_OPEN != 0 {
        FanotifyEventType::Open
    } else {
        FanotifyEventType::Access
    }
}
