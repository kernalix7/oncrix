// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Inotify file monitoring subsystem.
//!
//! Provides per-inode event monitoring following the Linux
//! `inotify(7)` model. User-space applications create an inotify
//! instance, add watches on inodes, and receive events through a
//! per-instance ring buffer.
//!
//! # Architecture
//!
//! - **Instances** own a set of watches and an event queue.
//! - **Watches** bind an event mask to an inode identifier.
//! - The global [`InotifyRegistry`] broadcasts filesystem events
//!   to every instance whose watches match the affected inode.
//!
//! # References
//!
//! - Linux `inotify_init(2)`, `inotify_add_watch(2)`,
//!   `inotify_rm_watch(2)`
//! - Linux `inotify(7)`

use oncrix_lib::{Error, Result};

// ── Event Mask Constants ────────────────────────────────────────

/// File was accessed (read).
pub const IN_ACCESS: u32 = 0x0000_0001;
/// File was modified (write).
pub const IN_MODIFY: u32 = 0x0000_0002;
/// Metadata changed (permissions, timestamps, etc.).
pub const IN_ATTRIB: u32 = 0x0000_0004;
/// Writable file was closed.
pub const IN_CLOSE_WRITE: u32 = 0x0000_0008;
/// Non-writable file was closed.
pub const IN_CLOSE_NOWRITE: u32 = 0x0000_0010;
/// File was opened.
pub const IN_OPEN: u32 = 0x0000_0020;
/// File/directory was moved out of watched directory.
pub const IN_MOVED_FROM: u32 = 0x0000_0040;
/// File/directory was moved into watched directory.
pub const IN_MOVED_TO: u32 = 0x0000_0080;
/// File/directory was created in watched directory.
pub const IN_CREATE: u32 = 0x0000_0100;
/// File/directory was deleted from watched directory.
pub const IN_DELETE: u32 = 0x0000_0200;
/// Watched file/directory itself was deleted.
pub const IN_DELETE_SELF: u32 = 0x0000_0400;
/// Watched file/directory itself was moved.
pub const IN_MOVE_SELF: u32 = 0x0000_0800;

/// Combination of all event bits.
pub const IN_ALL_EVENTS: u32 = IN_ACCESS
    | IN_MODIFY
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_CLOSE_NOWRITE
    | IN_OPEN
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
    | IN_DELETE_SELF
    | IN_MOVE_SELF;

/// Only monitor for a single event, then remove the watch.
pub const IN_ONESHOT: u32 = 0x8000_0000;
/// Only watch if the target is a directory.
pub const IN_ONLYDIR: u32 = 0x0100_0000;
/// Do not follow symbolic links.
pub const IN_DONT_FOLLOW: u32 = 0x0200_0000;

// ── Capacity Constants ──────────────────────────────────────────

/// Maximum watches per inotify instance.
const MAX_WATCHES: usize = 64;
/// Maximum pending events per inotify instance.
const MAX_EVENTS: usize = 128;
/// Maximum inotify instances in the global registry.
const MAX_INSTANCES: usize = 32;
/// Maximum filename length stored in an event.
const MAX_NAME_LEN: usize = 256;

// ── InotifyEvent ────────────────────────────────────────────────

/// A single inotify event delivered to user space.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct InotifyEvent {
    /// Watch descriptor that triggered this event.
    pub wd: i32,
    /// Bitmask of event types.
    pub mask: u32,
    /// Cookie for correlating `IN_MOVED_FROM` / `IN_MOVED_TO`.
    pub cookie: u32,
    /// Length of the name stored in [`Self::name`].
    pub name_len: u32,
    /// Null-padded filename associated with the event.
    pub name: [u8; MAX_NAME_LEN],
}

impl Default for InotifyEvent {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl InotifyEvent {
    /// Sentinel value used for array initialization.
    const EMPTY: Self = Self {
        wd: -1,
        mask: 0,
        cookie: 0,
        name_len: 0,
        name: [0u8; MAX_NAME_LEN],
    };
}

// ── InotifyWatch ────────────────────────────────────────────────

/// A watch binding an event mask to an inode.
#[derive(Debug, Clone, Copy)]
pub struct InotifyWatch {
    /// Watch descriptor (unique within the owning instance).
    pub wd: i32,
    /// Inode identifier being watched.
    pub inode_id: u64,
    /// Bitmask of events to monitor.
    pub mask: u32,
    /// Whether this watch slot is active.
    pub active: bool,
}

impl Default for InotifyWatch {
    fn default() -> Self {
        Self::EMPTY
    }
}

impl InotifyWatch {
    /// Sentinel value used for array initialization.
    const EMPTY: Self = Self {
        wd: -1,
        inode_id: 0,
        mask: 0,
        active: false,
    };
}

// ── InotifyInstance ─────────────────────────────────────────────

/// A single inotify instance owned by a process.
///
/// Each instance maintains its own set of watches and a ring
/// buffer of pending events.
pub struct InotifyInstance {
    /// Unique instance identifier.
    pub id: u64,
    /// Array of watch slots.
    watches: [InotifyWatch; MAX_WATCHES],
    /// Number of active watches.
    watch_count: usize,
    /// Ring buffer of pending events.
    events: [InotifyEvent; MAX_EVENTS],
    /// Ring buffer read position.
    event_head: usize,
    /// Ring buffer write position.
    event_tail: usize,
    /// Number of events in the ring buffer.
    event_count: usize,
    /// PID of the owning process.
    pub owner_pid: u64,
    /// Whether this instance slot is in use.
    pub in_use: bool,
    /// Next watch descriptor to assign.
    next_wd: i32,
}

impl InotifyInstance {
    /// Creates a new inotify instance.
    fn new(id: u64, owner_pid: u64) -> Self {
        Self {
            id,
            watches: [InotifyWatch::EMPTY; MAX_WATCHES],
            watch_count: 0,
            events: [InotifyEvent::EMPTY; MAX_EVENTS],
            event_head: 0,
            event_tail: 0,
            event_count: 0,
            owner_pid,
            in_use: true,
            next_wd: 1,
        }
    }

    /// Sentinel value used for registry array initialization.
    const EMPTY: Self = Self {
        id: 0,
        watches: [InotifyWatch::EMPTY; MAX_WATCHES],
        watch_count: 0,
        events: [InotifyEvent::EMPTY; MAX_EVENTS],
        event_head: 0,
        event_tail: 0,
        event_count: 0,
        owner_pid: 0,
        in_use: false,
        next_wd: 1,
    };

    /// Adds a watch for the given inode with the specified mask.
    ///
    /// If the inode is already watched, the mask is updated instead
    /// of creating a duplicate. Returns the watch descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the watch table is full.
    pub fn add_watch(&mut self, inode_id: u64, mask: u32) -> Result<i32> {
        // Update existing watch if one already matches.
        for watch in self.watches.iter_mut().take(self.watch_count) {
            if watch.active && watch.inode_id == inode_id {
                watch.mask = mask;
                return Ok(watch.wd);
            }
        }

        if self.watch_count >= MAX_WATCHES {
            return Err(Error::OutOfMemory);
        }

        let wd = self.next_wd;
        self.next_wd = self.next_wd.wrapping_add(1);

        self.watches[self.watch_count] = InotifyWatch {
            wd,
            inode_id,
            mask,
            active: true,
        };
        self.watch_count += 1;
        Ok(wd)
    }

    /// Removes the watch with the given descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no active watch with that
    /// descriptor exists.
    pub fn remove_watch(&mut self, wd: i32) -> Result<()> {
        for watch in self.watches.iter_mut().take(self.watch_count) {
            if watch.active && watch.wd == wd {
                watch.active = false;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Generates an event for the given inode if any active watch
    /// matches.
    ///
    /// If the matching watch has [`IN_ONESHOT`] set, the watch is
    /// automatically deactivated after generating the event.
    pub fn generate_event(&mut self, inode_id: u64, mask: u32, cookie: u32, name: &[u8]) {
        let mut oneshot_wd: Option<i32> = None;

        // Find a matching watch.
        let matched = self.watches.iter().take(self.watch_count).any(|w| {
            if w.active && w.inode_id == inode_id && (w.mask & mask) != 0 {
                if w.mask & IN_ONESHOT != 0 {
                    oneshot_wd = Some(w.wd);
                }
                true
            } else {
                false
            }
        });

        if !matched {
            return;
        }

        // Build the event.
        let wd = self
            .watches
            .iter()
            .take(self.watch_count)
            .find(|w| w.active && w.inode_id == inode_id && (w.mask & mask) != 0)
            .map(|w| w.wd)
            .unwrap_or(-1);

        let mut event = InotifyEvent {
            wd,
            mask,
            cookie,
            name_len: 0,
            name: [0u8; MAX_NAME_LEN],
        };

        // Copy the filename (truncated to buffer size).
        let copy_len = name.len().min(MAX_NAME_LEN);
        event.name[..copy_len].copy_from_slice(&name[..copy_len]);
        event.name_len = copy_len as u32;

        // Push into ring buffer.
        self.events[self.event_tail] = event;
        self.event_tail = (self.event_tail + 1) % MAX_EVENTS;

        if self.event_count == MAX_EVENTS {
            // Overwrite oldest event.
            self.event_head = (self.event_head + 1) % MAX_EVENTS;
        } else {
            self.event_count += 1;
        }

        // Handle oneshot watches.
        if let Some(wd) = oneshot_wd {
            for watch in self.watches.iter_mut().take(self.watch_count) {
                if watch.wd == wd {
                    watch.active = false;
                    break;
                }
            }
        }
    }

    /// Reads (pops) the oldest pending event from the ring buffer.
    ///
    /// Returns `None` when no events are pending.
    pub fn read_event(&mut self) -> Option<InotifyEvent> {
        if self.event_count == 0 {
            return None;
        }
        let event = self.events[self.event_head];
        self.event_head = (self.event_head + 1) % MAX_EVENTS;
        self.event_count -= 1;
        Some(event)
    }

    /// Returns the number of pending events.
    pub fn pending_events(&self) -> usize {
        self.event_count
    }
}

// ── InotifyRegistry ─────────────────────────────────────────────

/// Global registry of inotify instances.
///
/// Provides creation, destruction, and event broadcast across all
/// active instances.
pub struct InotifyRegistry {
    /// Fixed-size array of instance slots.
    instances: [InotifyInstance; MAX_INSTANCES],
    /// Number of active instances.
    count: usize,
    /// Next instance id to assign.
    next_id: u64,
}

impl InotifyRegistry {
    /// Creates a new, empty registry.
    pub const fn new() -> Self {
        Self {
            instances: [InotifyInstance::EMPTY; MAX_INSTANCES],
            count: 0,
            next_id: 1,
        }
    }

    /// Creates a new inotify instance owned by the given process.
    ///
    /// Returns the instance id on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the maximum number of
    /// instances has been reached.
    pub fn inotify_init(&mut self, pid: u64) -> Result<u64> {
        let slot = self.instances.iter().position(|inst| !inst.in_use);
        let slot = match slot {
            Some(s) => s,
            None => return Err(Error::OutOfMemory),
        };

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.instances[slot] = InotifyInstance::new(id, pid);
        self.count += 1;
        Ok(id)
    }

    /// Adds a watch to the specified instance.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the instance does not exist,
    /// or [`Error::OutOfMemory`] if the watch table is full.
    pub fn inotify_add_watch(&mut self, id: u64, inode_id: u64, mask: u32) -> Result<i32> {
        let inst = self.find_instance_mut(id)?;
        inst.add_watch(inode_id, mask)
    }

    /// Removes a watch from the specified instance.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the instance or watch does
    /// not exist.
    pub fn inotify_rm_watch(&mut self, id: u64, wd: i32) -> Result<()> {
        let inst = self.find_instance_mut(id)?;
        inst.remove_watch(wd)
    }

    /// Broadcasts a filesystem event to every instance that has a
    /// matching watch on the given inode.
    pub fn notify(&mut self, inode_id: u64, mask: u32, cookie: u32, name: &[u8]) {
        for inst in &mut self.instances {
            if inst.in_use {
                inst.generate_event(inode_id, mask, cookie, name);
            }
        }
    }

    /// Reads the next pending event from the specified instance.
    ///
    /// Returns `Ok(None)` when no events are pending.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the instance does not exist.
    pub fn read(&mut self, id: u64) -> Result<Option<InotifyEvent>> {
        let inst = self.find_instance_mut(id)?;
        Ok(inst.read_event())
    }

    /// Closes and releases the specified inotify instance.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the instance does not exist.
    pub fn close(&mut self, id: u64) -> Result<()> {
        let inst = self.find_instance_mut(id)?;
        inst.in_use = false;
        self.count -= 1;
        Ok(())
    }

    /// Returns the number of active instances.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no instances are active.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Finds a mutable reference to the instance with the given id.
    fn find_instance_mut(&mut self, id: u64) -> Result<&mut InotifyInstance> {
        self.instances
            .iter_mut()
            .find(|inst| inst.in_use && inst.id == id)
            .ok_or(Error::NotFound)
    }
}

impl Default for InotifyRegistry {
    fn default() -> Self {
        Self::new()
    }
}
