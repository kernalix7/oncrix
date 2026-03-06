// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Filesystem notification subsystem — inotify/fanotify event routing.
//!
//! Provides the event bus that the VFS uses to dispatch filesystem events
//! to registered watchers. Individual watcher implementations (inotify,
//! fanotify) register callbacks via the `NotifyOps` trait.

use oncrix_lib::{Error, Result};

/// Maximum number of registered notification backends.
pub const MAX_NOTIFY_BACKENDS: usize = 8;

/// Maximum number of pending events per backend.
pub const MAX_PENDING_EVENTS: usize = 512;

/// Filesystem event types (bitmask).
#[derive(Debug, Clone, Copy, Default)]
pub struct FsEvent(pub u32);

impl FsEvent {
    pub const ACCESS: u32 = 1 << 0;
    pub const MODIFY: u32 = 1 << 1;
    pub const ATTRIB: u32 = 1 << 2;
    pub const CLOSE_WRITE: u32 = 1 << 3;
    pub const CLOSE_NOWRITE: u32 = 1 << 4;
    pub const OPEN: u32 = 1 << 5;
    pub const MOVED_FROM: u32 = 1 << 6;
    pub const MOVED_TO: u32 = 1 << 7;
    pub const CREATE: u32 = 1 << 8;
    pub const DELETE: u32 = 1 << 9;
    pub const DELETE_SELF: u32 = 1 << 10;
    pub const MOVE_SELF: u32 = 1 << 11;
    pub const UNMOUNT: u32 = 1 << 12;
    pub const Q_OVERFLOW: u32 = 1 << 13;
    pub const IGNORED: u32 = 1 << 14;
    pub const ISDIR: u32 = 1 << 30;

    /// Test whether an event type is set.
    pub const fn has(self, mask: u32) -> bool {
        (self.0 & mask) != 0
    }

    /// Combine with another event.
    pub const fn or(self, other: FsEvent) -> FsEvent {
        FsEvent(self.0 | other.0)
    }
}

/// A single filesystem event record.
#[derive(Debug, Clone, Copy)]
pub struct FsEventRecord {
    /// Superblock of the affected filesystem.
    pub sb_id: u64,
    /// Inode of the affected file/directory.
    pub ino: u64,
    /// Event type bitmask.
    pub mask: FsEvent,
    /// Cookie for rename pairing (0 = not a rename).
    pub cookie: u32,
    /// Name hash (for directory entry events).
    pub name_hash: u64,
    /// Whether the affected entry is a directory.
    pub is_dir: bool,
}

/// A notification backend (inotify, fanotify, etc.).
pub trait NotifyOps {
    /// Return the backend identifier.
    fn backend_id(&self) -> u32;

    /// Called when an event occurs. The backend should queue the event for
    /// delivery to user space.
    fn handle_event(&mut self, event: &FsEventRecord) -> Result<()>;

    /// Return `true` if this backend is watching the given inode.
    fn watches(&self, sb_id: u64, ino: u64) -> bool;
}

/// Pending event in the dispatcher queue.
#[derive(Clone, Copy)]
struct PendingEvent {
    record: FsEventRecord,
    valid: bool,
}

impl PendingEvent {
    const fn empty() -> Self {
        Self {
            record: FsEventRecord {
                sb_id: 0,
                ino: 0,
                mask: FsEvent(0),
                cookie: 0,
                name_hash: 0,
                is_dir: false,
            },
            valid: false,
        }
    }
}

/// The VFS filesystem notification bus.
pub struct FsNotifyBus {
    pending: [PendingEvent; MAX_PENDING_EVENTS],
    head: usize,
    tail: usize,
    count: usize,
    /// Statistics.
    pub total_dispatched: u64,
    pub total_dropped: u64,
}

impl FsNotifyBus {
    /// Create an empty notification bus.
    pub const fn new() -> Self {
        Self {
            pending: [const { PendingEvent::empty() }; MAX_PENDING_EVENTS],
            head: 0,
            tail: 0,
            count: 0,
            total_dispatched: 0,
            total_dropped: 0,
        }
    }

    /// Enqueue a filesystem event for dispatch.
    pub fn enqueue(&mut self, record: FsEventRecord) -> Result<()> {
        if self.count >= MAX_PENDING_EVENTS {
            self.total_dropped += 1;
            return Err(Error::WouldBlock);
        }
        self.pending[self.tail] = PendingEvent {
            record,
            valid: true,
        };
        self.tail = (self.tail + 1) % MAX_PENDING_EVENTS;
        self.count += 1;
        Ok(())
    }

    /// Dispatch all pending events to registered backends.
    ///
    /// `backends` is a mutable slice of backend references. Each event is
    /// delivered to each backend that watches the affected inode.
    pub fn dispatch<B: NotifyOps>(&mut self, backends: &mut [B]) {
        while self.count > 0 {
            let event = self.pending[self.head];
            if !event.valid {
                break;
            }
            self.pending[self.head] = PendingEvent::empty();
            self.head = (self.head + 1) % MAX_PENDING_EVENTS;
            self.count -= 1;

            for backend in backends.iter_mut() {
                if backend.watches(event.record.sb_id, event.record.ino) {
                    let _ = backend.handle_event(&event.record);
                }
            }
            self.total_dispatched += 1;
        }
    }

    /// Return the number of pending events.
    pub fn pending_count(&self) -> usize {
        self.count
    }

    /// Return `true` if the event queue is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Drain all pending events for a given superblock (on unmount).
    pub fn drain_super(&mut self, sb_id: u64) -> u32 {
        let mut drained = 0u32;
        for slot in self.pending.iter_mut() {
            if slot.valid && slot.record.sb_id == sb_id {
                *slot = PendingEvent::empty();
                self.count = self.count.saturating_sub(1);
                drained += 1;
            }
        }
        drained
    }
}

impl Default for FsNotifyBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience: emit a VFS event to the bus.
pub fn emit_event(bus: &mut FsNotifyBus, sb_id: u64, ino: u64, mask: u32, is_dir: bool) {
    let record = FsEventRecord {
        sb_id,
        ino,
        mask: FsEvent(mask),
        cookie: 0,
        name_hash: 0,
        is_dir,
    };
    let _ = bus.enqueue(record);
}

/// Emit a rename pair (MOVED_FROM / MOVED_TO) with a matching cookie.
pub fn emit_rename(
    bus: &mut FsNotifyBus,
    sb_id: u64,
    src_dir_ino: u64,
    dst_dir_ino: u64,
    name_hash: u64,
    cookie: u32,
) {
    let from = FsEventRecord {
        sb_id,
        ino: src_dir_ino,
        mask: FsEvent(FsEvent::MOVED_FROM),
        cookie,
        name_hash,
        is_dir: false,
    };
    let to = FsEventRecord {
        sb_id,
        ino: dst_dir_ino,
        mask: FsEvent(FsEvent::MOVED_TO),
        cookie,
        name_hash,
        is_dir: false,
    };
    let _ = bus.enqueue(from);
    let _ = bus.enqueue(to);
}
