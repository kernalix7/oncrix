// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! fanotify — filesystem-wide event monitoring.
//!
//! fanotify provides an interface for monitoring filesystem events at the
//! mount or filesystem level. Unlike inotify (which watches specific paths),
//! fanotify can intercept events before they complete, allowing access control
//! decisions (permission events).
//!
//! # Event types
//!
//! - `FAN_ACCESS` — file was accessed (read)
//! - `FAN_MODIFY` — file was modified (write)
//! - `FAN_OPEN` — file was opened
//! - `FAN_CLOSE_WRITE` — writable file was closed
//! - `FAN_CLOSE_NOWRITE` — read-only file was closed
//! - `FAN_OPEN_PERM` — permission check on open (blocking)
//! - `FAN_ACCESS_PERM` — permission check on read (blocking)
//!
//! # References
//!
//! - Linux `fanotify(7)`, `fanotify_init(2)`, `fanotify_mark(2)`

use oncrix_lib::{Error, Result};

// ── Event mask constants ─────────────────────────────────────────────

/// File was accessed (read).
pub const FAN_ACCESS: u64 = 0x0000_0001;
/// File was modified (written).
pub const FAN_MODIFY: u64 = 0x0000_0002;
/// File or directory was closed after write.
pub const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
/// File or directory was closed without write.
pub const FAN_CLOSE_NOWRITE: u64 = 0x0000_0010;
/// File or directory was opened.
pub const FAN_OPEN: u64 = 0x0000_0020;
/// File was opened for execution (permission check).
pub const FAN_OPEN_EXEC: u64 = 0x0000_1000;
/// Permission event for open/exec.
pub const FAN_OPEN_PERM: u64 = 0x0001_0000;
/// Permission event for read.
pub const FAN_ACCESS_PERM: u64 = 0x0002_0000;
/// Filesystem-wide event (mark whole mount point).
pub const FAN_MARK_MOUNT: u32 = 0x0000_0010;
/// Mark a specific inode.
pub const FAN_MARK_INODE: u32 = 0x0000_0000;
/// Allow access (response to permission event).
pub const FAN_ALLOW: u32 = 0x01;
/// Deny access (response to permission event).
pub const FAN_DENY: u32 = 0x02;

/// Maximum fanotify groups system-wide.
pub const MAX_FANOTIFY_GROUPS: usize = 32;
/// Maximum queued events per group.
pub const MAX_QUEUED_EVENTS: usize = 128;

// ── FanotifyEvent ────────────────────────────────────────────────────

/// A single fanotify event.
#[derive(Debug, Clone, Copy)]
pub struct FanotifyEvent {
    /// Event mask indicating which event(s) occurred.
    pub mask: u64,
    /// Inode number of the affected file.
    pub ino: u64,
    /// PID of the process that triggered the event.
    pub pid: u32,
    /// Whether this is a permission event (requires a response).
    pub is_perm: bool,
    /// Response for permission events (`FAN_ALLOW` or `FAN_DENY`).
    pub response: u32,
}

impl FanotifyEvent {
    /// Create a new non-permission event.
    pub const fn new(mask: u64, ino: u64, pid: u32) -> Self {
        Self {
            mask,
            ino,
            pid,
            is_perm: false,
            response: 0,
        }
    }

    /// Create a permission event (requires explicit allow/deny response).
    pub const fn new_perm(mask: u64, ino: u64, pid: u32) -> Self {
        Self {
            mask,
            ino,
            pid,
            is_perm: true,
            response: 0,
        }
    }
}

// ── FanotifyMark ─────────────────────────────────────────────────────

/// A mark entry: watches a specific inode or mount.
#[derive(Debug, Clone, Copy)]
pub struct FanotifyMark {
    /// Inode number (or mount ID when `is_mount` is true).
    pub id: u64,
    /// Mask of events to watch.
    pub mask: u64,
    /// Whether this mark covers a whole mount point.
    pub is_mount: bool,
    /// Ignored event mask.
    pub ignored_mask: u64,
}

impl FanotifyMark {
    /// Create a new inode mark.
    pub const fn new_inode(ino: u64, mask: u64) -> Self {
        Self {
            id: ino,
            mask,
            is_mount: false,
            ignored_mask: 0,
        }
    }

    /// Create a new mount mark.
    pub const fn new_mount(mount_id: u64, mask: u64) -> Self {
        Self {
            id: mount_id,
            mask,
            is_mount: true,
            ignored_mask: 0,
        }
    }

    /// Returns `true` if the given event mask matches this mark.
    pub fn matches(&self, event_mask: u64) -> bool {
        (self.mask & event_mask) != 0 && (self.ignored_mask & event_mask) == 0
    }
}

// ── FanotifyGroup ────────────────────────────────────────────────────

/// Maximum number of marks per group.
const MAX_MARKS_PER_GROUP: usize = 64;

/// A fanotify group (created by `fanotify_init`).
pub struct FanotifyGroup {
    /// Group ID (file descriptor value in userspace).
    pub id: u32,
    /// Marks registered by this group.
    marks: [Option<FanotifyMark>; MAX_MARKS_PER_GROUP],
    mark_count: usize,
    /// Pending event queue.
    events: [Option<FanotifyEvent>; MAX_QUEUED_EVENTS],
    event_head: usize,
    event_tail: usize,
    event_count: usize,
    /// Whether this group is active.
    pub active: bool,
}

impl FanotifyGroup {
    /// Create a new fanotify group with the given ID.
    pub const fn new(id: u32) -> Self {
        Self {
            id,
            marks: [const { None }; MAX_MARKS_PER_GROUP],
            mark_count: 0,
            events: [const { None }; MAX_QUEUED_EVENTS],
            event_head: 0,
            event_tail: 0,
            event_count: 0,
            active: true,
        }
    }

    /// Add or update a mark.
    pub fn add_mark(&mut self, mark: FanotifyMark) -> Result<()> {
        // Update existing mark if same id+type.
        for slot in self.marks.iter_mut() {
            if let Some(m) = slot {
                if m.id == mark.id && m.is_mount == mark.is_mount {
                    m.mask |= mark.mask;
                    m.ignored_mask = mark.ignored_mask;
                    return Ok(());
                }
            }
        }
        if self.mark_count >= MAX_MARKS_PER_GROUP {
            return Err(Error::OutOfMemory);
        }
        for slot in self.marks.iter_mut() {
            if slot.is_none() {
                *slot = Some(mark);
                self.mark_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a mark by ID and type.
    pub fn remove_mark(&mut self, id: u64, is_mount: bool) -> Result<()> {
        for slot in self.marks.iter_mut() {
            if let Some(m) = slot {
                if m.id == id && m.is_mount == is_mount {
                    *slot = None;
                    self.mark_count = self.mark_count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Returns `true` if this group is interested in the event.
    pub fn interested_in(&self, ino: u64, event_mask: u64) -> bool {
        for slot in self.marks.iter() {
            if let Some(m) = slot {
                if !m.is_mount && m.id == ino && m.matches(event_mask) {
                    return true;
                }
            }
        }
        false
    }

    /// Queue an event for this group.
    pub fn enqueue(&mut self, event: FanotifyEvent) -> Result<()> {
        if self.event_count >= MAX_QUEUED_EVENTS {
            return Err(Error::OutOfMemory);
        }
        self.events[self.event_tail] = Some(event);
        self.event_tail = (self.event_tail + 1) % MAX_QUEUED_EVENTS;
        self.event_count += 1;
        Ok(())
    }

    /// Dequeue the next pending event.
    pub fn dequeue(&mut self) -> Option<FanotifyEvent> {
        if self.event_count == 0 {
            return None;
        }
        let ev = self.events[self.event_head].take();
        self.event_head = (self.event_head + 1) % MAX_QUEUED_EVENTS;
        self.event_count = self.event_count.saturating_sub(1);
        ev
    }

    /// Returns the number of queued events.
    pub fn pending(&self) -> usize {
        self.event_count
    }
}

// ── FanotifySubsystem ────────────────────────────────────────────────

/// Global fanotify subsystem.
pub struct FanotifySubsystem {
    groups: [Option<FanotifyGroup>; MAX_FANOTIFY_GROUPS],
    count: usize,
    next_id: u32,
}

impl FanotifySubsystem {
    /// Create an empty fanotify subsystem.
    pub const fn new() -> Self {
        Self {
            groups: [const { None }; MAX_FANOTIFY_GROUPS],
            count: 0,
            next_id: 1,
        }
    }

    /// Initialize a new fanotify group; returns its ID.
    pub fn init(&mut self) -> Result<u32> {
        if self.count >= MAX_FANOTIFY_GROUPS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        for slot in self.groups.iter_mut() {
            if slot.is_none() {
                *slot = Some(FanotifyGroup::new(id));
                self.count += 1;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a group by ID (mutable).
    pub fn group_mut(&mut self, id: u32) -> Option<&mut FanotifyGroup> {
        for slot in self.groups.iter_mut() {
            if let Some(g) = slot {
                if g.id == id {
                    return Some(g);
                }
            }
        }
        None
    }

    /// Destroy a group by ID.
    pub fn destroy(&mut self, id: u32) -> Result<()> {
        for slot in self.groups.iter_mut() {
            if let Some(g) = slot {
                if g.id == id {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Dispatch an event to all interested groups.
    pub fn dispatch(&mut self, ino: u64, event_mask: u64, pid: u32) {
        let is_perm = (event_mask & (FAN_OPEN_PERM | FAN_ACCESS_PERM)) != 0;
        for slot in self.groups.iter_mut() {
            if let Some(g) = slot {
                if g.active && g.interested_in(ino, event_mask) {
                    let ev = if is_perm {
                        FanotifyEvent::new_perm(event_mask, ino, pid)
                    } else {
                        FanotifyEvent::new(event_mask, ino, pid)
                    };
                    let _ = g.enqueue(ev);
                }
            }
        }
    }

    /// Returns the number of active groups.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for FanotifySubsystem {
    fn default() -> Self {
        Self::new()
    }
}
// Global operations performed through owned instance, avoiding static mut.
