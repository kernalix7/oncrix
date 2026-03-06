// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! inotify filesystem event monitoring subsystem.
//!
//! Provides a mechanism for monitoring filesystem events (file
//! creation, deletion, modification, access, etc.) compatible with
//! the Linux inotify API. An [`InotifyInstance`] watches a set of
//! inodes for filesystem events and queues [`InotifyEvent`] records
//! that user space reads via `read(2)`.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────┐
//! │               InotifyRegistry                    │
//! │  (up to MAX_INSTANCES inotify instances)         │
//! │  ┌──────────┐ ┌──────────┐     ┌──────────┐     │
//! │  │  inst 0  │ │  inst 1  │ ... │  inst N  │     │
//! │  └──────────┘ └──────────┘     └──────────┘     │
//! └──────────────────────────────────────────────────┘
//!          │
//!          ▼
//! ┌──────────────────────────────────────────────────┐
//! │              InotifyInstance                      │
//! │  watches: [InotifyWatch; MAX_WATCHES]            │
//! │  event_queue: ring buffer of InotifyEvent        │
//! │  ┌────────────┐  ┌────────────┐                  │
//! │  │ watch wd=1 │  │ watch wd=2 │  ...             │
//! │  │ inode=42   │  │ inode=99   │                  │
//! │  │ mask=0x3   │  │ mask=0x100 │                  │
//! │  └────────────┘  └────────────┘                  │
//! └──────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! VFS operations (create, unlink, write, open, etc.) call
//! [`InotifyInstance::emit_event`] with the affected inode and
//! event mask. If the inode is being watched with a matching mask,
//! an event is queued. User space reads events via the inotify
//! file descriptor.
//!
//! # POSIX Reference
//!
//! inotify is a Linux extension (not POSIX). ONCRIX provides it
//! for compatibility with software that depends on filesystem
//! change notifications (systemd, inotifywait, cargo-watch, etc.).

use oncrix_lib::{Error, Result};

// ── Event mask constants ────────────────────────────────────────

/// File was accessed (e.g., read).
pub const IN_ACCESS: u32 = 0x0000_0001;

/// File was modified (e.g., write).
pub const IN_MODIFY: u32 = 0x0000_0002;

/// Metadata changed (e.g., permissions, timestamps).
pub const IN_ATTRIB: u32 = 0x0000_0004;

/// Writable file was closed.
pub const IN_CLOSE_WRITE: u32 = 0x0000_0008;

/// Non-writable file was closed.
pub const IN_CLOSE_NOWRITE: u32 = 0x0000_0010;

/// File was opened.
pub const IN_OPEN: u32 = 0x0000_0020;

/// File was moved from watched directory.
pub const IN_MOVED_FROM: u32 = 0x0000_0040;

/// File was moved into watched directory.
pub const IN_MOVED_TO: u32 = 0x0000_0080;

/// File/directory was created in watched directory.
pub const IN_CREATE: u32 = 0x0000_0100;

/// File/directory was deleted in watched directory.
pub const IN_DELETE: u32 = 0x0000_0200;

/// Watched file/directory was itself deleted.
pub const IN_DELETE_SELF: u32 = 0x0000_0400;

/// Watched file/directory was itself moved.
pub const IN_MOVE_SELF: u32 = 0x0000_0800;

/// Mask covering all supported event types.
const IN_ALL_EVENTS: u32 = IN_ACCESS
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

// ── Flag constants ──────────────────────────────────────────────

/// Set the `O_NONBLOCK` flag on the inotify file descriptor.
pub const IN_NONBLOCK: u32 = 0x0000_0800;

/// Set the close-on-exec flag on the inotify file descriptor.
pub const IN_CLOEXEC: u32 = 0x0008_0000;

/// Only monitor for one event, then remove the watch.
pub const IN_ONESHOT: u32 = 0x8000_0000;

/// Add events to an existing watch instead of replacing the mask.
pub const IN_MASK_ADD: u32 = 0x2000_0000;

/// Valid flags for `inotify_init1`.
const INIT_VALID_FLAGS: u32 = IN_NONBLOCK | IN_CLOEXEC;

/// Valid flags that may appear in an `inotify_add_watch` mask
/// alongside event bits.
///
/// Used by callers to validate masks before passing to
/// [`InotifyInstance::add_watch`].
pub const WATCH_VALID_FLAGS: u32 = IN_ONESHOT | IN_MASK_ADD;

// ── InotifyEvent ────────────────────────────────────────────────

/// Maximum length of the name field in an inotify event.
const MAX_NAME_LEN: usize = 256;

/// An inotify event delivered to user space.
///
/// Corresponds to `struct inotify_event` from `<sys/inotify.h>`.
/// The `name` field holds the filename (null-padded) when the
/// event relates to a child of a watched directory.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct InotifyEvent {
    /// Watch descriptor that generated this event.
    pub wd: i32,
    /// Bitmask of event types that occurred.
    pub mask: u32,
    /// Cookie for correlating `IN_MOVED_FROM`/`IN_MOVED_TO` pairs.
    pub cookie: u32,
    /// Length of the name (including null padding), or 0 if unnamed.
    pub len: u32,
    /// Null-terminated filename (only set for directory watches).
    pub name: [u8; MAX_NAME_LEN],
    /// Actual number of valid bytes in `name` (excluding padding).
    pub name_len: usize,
}

impl InotifyEvent {
    /// Create an empty event with all fields zeroed.
    const fn empty() -> Self {
        Self {
            wd: 0,
            mask: 0,
            cookie: 0,
            len: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
        }
    }
}

// ── InotifyWatch ────────────────────────────────────────────────

/// Internal bookkeeping for a single inotify watch.
///
/// Each watch monitors a specific inode for a set of events
/// specified by `mask`.
#[derive(Debug, Clone, Copy)]
pub struct InotifyWatch {
    /// Watch descriptor assigned when this watch was created.
    pub wd: i32,
    /// Inode number being watched.
    pub inode: u64,
    /// Bitmask of events to monitor.
    pub mask: u32,
    /// Whether this watch is currently active.
    pub active: bool,
}

impl InotifyWatch {
    /// Create an inactive (empty) watch slot.
    const fn empty() -> Self {
        Self {
            wd: 0,
            inode: 0,
            mask: 0,
            active: false,
        }
    }
}

// ── InotifyInstance ─────────────────────────────────────────────

/// Maximum number of watches per inotify instance.
const MAX_WATCHES: usize = 64;

/// Maximum number of queued events per inotify instance.
const MAX_EVENTS: usize = 128;

/// An inotify instance that monitors inodes for filesystem events.
///
/// Each instance maintains an array of [`InotifyWatch`] entries and
/// a ring-buffer event queue. VFS operations generate events via
/// [`emit_event`](InotifyInstance::emit_event), and user space
/// consumes them via [`read_event`](InotifyInstance::read_event).
pub struct InotifyInstance {
    /// Watched inode entries (fixed-size array).
    watches: [InotifyWatch; MAX_WATCHES],
    /// Ring buffer of queued events.
    events: [InotifyEvent; MAX_EVENTS],
    /// Write index into the event ring buffer.
    event_head: usize,
    /// Read index into the event ring buffer.
    event_tail: usize,
    /// Number of events currently in the queue.
    event_count: usize,
    /// Next watch descriptor to assign.
    next_wd: i32,
    /// Instance flags (`IN_NONBLOCK`, `IN_CLOEXEC`).
    flags: u32,
    /// Whether this instance slot is in use.
    in_use: bool,
}

impl InotifyInstance {
    /// Create a new, empty inotify instance with the given flags.
    ///
    /// The instance starts with no watches and an empty event queue.
    /// Valid flags are [`IN_NONBLOCK`] and [`IN_CLOEXEC`].
    pub const fn new(flags: u32) -> Self {
        Self {
            watches: [const { InotifyWatch::empty() }; MAX_WATCHES],
            events: [const { InotifyEvent::empty() }; MAX_EVENTS],
            event_head: 0,
            event_tail: 0,
            event_count: 0,
            next_wd: 1,
            flags,
            in_use: false,
        }
    }

    /// Add a watch for the given inode with the specified event mask.
    ///
    /// If the inode is already watched, the behavior depends on
    /// whether [`IN_MASK_ADD`] is set in `mask`:
    /// - With `IN_MASK_ADD`: the new events are OR-ed into the
    ///   existing mask.
    /// - Without `IN_MASK_ADD`: the mask is replaced entirely.
    ///
    /// Returns the watch descriptor on success, or:
    /// - `Err(InvalidArgument)` if `mask` has no valid event bits
    /// - `Err(OutOfMemory)` if all watch slots are full
    pub fn add_watch(&mut self, inode: u64, mask: u32) -> Result<i32> {
        // Extract event bits and flags separately.
        let event_bits = mask & IN_ALL_EVENTS;
        if event_bits == 0 {
            return Err(Error::InvalidArgument);
        }

        let add_flag = mask & IN_MASK_ADD != 0;
        let oneshot = mask & IN_ONESHOT != 0;

        // Check if inode is already watched — update in place.
        for watch in &mut self.watches {
            if watch.active && watch.inode == inode {
                if add_flag {
                    watch.mask |= event_bits;
                } else {
                    watch.mask = event_bits;
                }
                if oneshot {
                    watch.mask |= IN_ONESHOT;
                }
                return Ok(watch.wd);
            }
        }

        // Allocate a new watch slot.
        for watch in &mut self.watches {
            if !watch.active {
                let wd = self.next_wd;
                self.next_wd = self.next_wd.saturating_add(1);
                let combined = if oneshot {
                    event_bits | IN_ONESHOT
                } else {
                    event_bits
                };
                *watch = InotifyWatch {
                    wd,
                    inode,
                    mask: combined,
                    active: true,
                };
                return Ok(wd);
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Remove a watch by its watch descriptor.
    ///
    /// Returns `Err(NotFound)` if no active watch matches `wd`.
    pub fn remove_watch(&mut self, wd: i32) -> Result<()> {
        for watch in &mut self.watches {
            if watch.active && watch.wd == wd {
                *watch = InotifyWatch::empty();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Emit a filesystem event for the given inode.
    ///
    /// Scans all active watches. For each watch that monitors `inode`
    /// and whose mask overlaps with `mask`, an [`InotifyEvent`] is
    /// enqueued. The optional `name` is included when the event
    /// relates to a child entry within a watched directory.
    ///
    /// If the event queue is full, the event is silently dropped
    /// (matching Linux behavior when the inotify buffer overflows).
    ///
    /// Watches with [`IN_ONESHOT`] are automatically deactivated
    /// after their first matching event.
    pub fn emit_event(&mut self, inode: u64, mask: u32, name: &str) {
        // Collect indices to deactivate after iteration so we
        // avoid double-mutable-borrow issues.
        let mut deactivate = [false; MAX_WATCHES];

        for (idx, watch) in self.watches.iter().enumerate() {
            if !watch.active {
                continue;
            }
            if watch.inode != inode {
                continue;
            }
            // Check if the watch mask intersects with the event.
            let effective = watch.mask & IN_ALL_EVENTS;
            if effective & mask == 0 {
                continue;
            }

            // Build the event.
            let mut event = InotifyEvent::empty();
            event.wd = watch.wd;
            event.mask = mask;

            // Copy the name if present.
            let name_bytes = name.as_bytes();
            if !name_bytes.is_empty() {
                let copy_len = if name_bytes.len() < MAX_NAME_LEN {
                    name_bytes.len()
                } else {
                    MAX_NAME_LEN.saturating_sub(1)
                };
                let mut i = 0;
                while i < copy_len {
                    event.name[i] = name_bytes[i];
                    i = i.saturating_add(1);
                }
                event.name_len = copy_len;
                // len includes null terminator, aligned to
                // natural boundary for user-space parsing.
                event.len = (copy_len.saturating_add(1)) as u32;
            }

            // Enqueue the event (drop if queue is full).
            if self.event_count < MAX_EVENTS {
                self.events[self.event_head] = event;
                self.event_head = (self.event_head.saturating_add(1)) % MAX_EVENTS;
                self.event_count = self.event_count.saturating_add(1);
            }

            // Mark oneshot watches for deactivation.
            if watch.mask & IN_ONESHOT != 0 {
                deactivate[idx] = true;
            }
        }

        // Deactivate oneshot watches that fired.
        for (idx, should_deactivate) in deactivate.iter().enumerate() {
            if *should_deactivate {
                self.watches[idx] = InotifyWatch::empty();
            }
        }
    }

    /// Dequeue a single event from the event queue.
    ///
    /// Returns `None` if the queue is empty. Events are returned
    /// in FIFO order.
    pub fn read_event(&mut self) -> Option<InotifyEvent> {
        if self.event_count == 0 {
            return None;
        }
        let event = self.events[self.event_tail];
        self.event_tail = (self.event_tail.saturating_add(1)) % MAX_EVENTS;
        self.event_count = self.event_count.saturating_sub(1);
        Some(event)
    }

    /// Check whether there are queued events available to read.
    pub fn has_events(&self) -> bool {
        self.event_count > 0
    }

    /// Return the instance flags.
    pub fn flags(&self) -> u32 {
        self.flags
    }
}

// ── InotifyRegistry ─────────────────────────────────────────────

/// Maximum number of concurrent inotify instances system-wide.
const MAX_INSTANCES: usize = 32;

/// Global registry of inotify instances.
///
/// Manages the creation, lookup, and destruction of
/// [`InotifyInstance`] objects. Each instance is identified by a
/// numeric ID (returned by [`create`](InotifyRegistry::create) and
/// used as an inotify file descriptor in user space).
pub struct InotifyRegistry {
    /// Fixed array of inotify instance slots.
    instances: [InotifyInstance; MAX_INSTANCES],
}

impl Default for InotifyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl InotifyRegistry {
    /// Create an empty registry with no active instances.
    pub const fn new() -> Self {
        Self {
            instances: [const { InotifyInstance::new(0) }; MAX_INSTANCES],
        }
    }

    /// Allocate a new inotify instance with the given flags.
    ///
    /// Returns the instance ID (inotify fd) on success, or
    /// `Err(InvalidArgument)` if `flags` contains invalid bits, or
    /// `Err(OutOfMemory)` if all slots are occupied.
    pub fn create(&mut self, flags: u32) -> Result<usize> {
        if flags & !INIT_VALID_FLAGS != 0 {
            return Err(Error::InvalidArgument);
        }
        for (id, inst) in self.instances.iter_mut().enumerate() {
            if !inst.in_use {
                *inst = InotifyInstance::new(flags);
                inst.in_use = true;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Get a shared reference to an inotify instance by ID.
    ///
    /// Returns `Err(InvalidArgument)` if the ID is out of range,
    /// or `Err(NotFound)` if the slot is not in use.
    pub fn get(&self, id: usize) -> Result<&InotifyInstance> {
        let inst = self.instances.get(id).ok_or(Error::InvalidArgument)?;
        if !inst.in_use {
            return Err(Error::NotFound);
        }
        Ok(inst)
    }

    /// Get a mutable reference to an inotify instance by ID.
    ///
    /// Returns `Err(InvalidArgument)` if the ID is out of range,
    /// or `Err(NotFound)` if the slot is not in use.
    pub fn get_mut(&mut self, id: usize) -> Result<&mut InotifyInstance> {
        let inst = self.instances.get_mut(id).ok_or(Error::InvalidArgument)?;
        if !inst.in_use {
            return Err(Error::NotFound);
        }
        Ok(inst)
    }

    /// Destroy an inotify instance, freeing its slot.
    ///
    /// Returns `Err(InvalidArgument)` if the ID is out of range,
    /// or `Err(NotFound)` if the slot is not in use.
    pub fn close(&mut self, id: usize) -> Result<()> {
        let inst = self.instances.get_mut(id).ok_or(Error::InvalidArgument)?;
        if !inst.in_use {
            return Err(Error::NotFound);
        }
        *inst = InotifyInstance::new(0);
        Ok(())
    }
}
