// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `inotify_init(2)`, `inotify_init1(2)`, `inotify_add_watch(2)`,
//! `inotify_rm_watch(2)` — filesystem event monitoring.
//!
//! inotify is a Linux mechanism for monitoring filesystem events on
//! files and directories.  When events of interest occur (create, delete,
//! modify, etc.), they are delivered as binary records via a file
//! descriptor created by `inotify_init`.
//!
//! # Syscalls
//!
//! | Syscall | Handler | Description |
//! |---------|---------|-------------|
//! | `inotify_init` | [`sys_inotify_init`] | Create an inotify instance |
//! | `inotify_init1` | [`sys_inotify_init1`] | Create with flags |
//! | `inotify_add_watch` | [`sys_inotify_add_watch`] | Add/update a watch |
//! | `inotify_rm_watch` | [`sys_inotify_rm_watch`] | Remove a watch |
//!
//! # Event delivery
//!
//! Events are read as `struct inotify_event` records from the fd.
//! Each record has a fixed header followed by an optional null-terminated
//! name field (for events on directory entries).
//!
//! # Watch descriptor
//!
//! `inotify_add_watch` returns a watch descriptor (WD) — a non-negative
//! integer identifying the watch within the inotify instance.  WDs are
//! unique per inotify instance, not globally.
//!
//! # References
//!
//! - Linux: `fs/notify/inotify/inotify.c`, `fs/notify/inotify/inotify_user.c`
//! - man: `inotify(7)`, `inotify_init(2)`, `inotify_add_watch(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// inotify event flags (IN_*)
// ---------------------------------------------------------------------------

/// File was accessed (read).
pub const IN_ACCESS: u32 = 0x0000_0001;

/// Metadata changed (permissions, timestamps, etc.).
pub const IN_ATTRIB: u32 = 0x0000_0004;

/// File opened for writing was closed.
pub const IN_CLOSE_WRITE: u32 = 0x0000_0008;

/// File not opened for writing was closed.
pub const IN_CLOSE_NOWRITE: u32 = 0x0000_0010;

/// File or directory was created in watched directory.
pub const IN_CREATE: u32 = 0x0000_0100;

/// File or directory was deleted from watched directory.
pub const IN_DELETE: u32 = 0x0000_0200;

/// Watched file or directory was deleted.
pub const IN_DELETE_SELF: u32 = 0x0000_0400;

/// File was modified.
pub const IN_MODIFY: u32 = 0x0000_0002;

/// Watched file or directory was moved.
pub const IN_MOVE_SELF: u32 = 0x0000_0800;

/// File was moved out of watched directory.
pub const IN_MOVED_FROM: u32 = 0x0000_0040;

/// File was moved into watched directory.
pub const IN_MOVED_TO: u32 = 0x0000_0080;

/// File was opened.
pub const IN_OPEN: u32 = 0x0000_0020;

/// Convenience: all file close events.
pub const IN_CLOSE: u32 = IN_CLOSE_WRITE | IN_CLOSE_NOWRITE;

/// Convenience: all file move events.
pub const IN_MOVE: u32 = IN_MOVED_FROM | IN_MOVED_TO;

/// Convenience: all standard events.
pub const IN_ALL_EVENTS: u32 = IN_ACCESS
    | IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_CLOSE_NOWRITE
    | IN_CREATE
    | IN_DELETE
    | IN_DELETE_SELF
    | IN_MODIFY
    | IN_MOVE_SELF
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_OPEN;

// ---------------------------------------------------------------------------
// inotify watch flags (add_watch-specific)
// ---------------------------------------------------------------------------

/// Don't follow symbolic links.
pub const IN_DONT_FOLLOW: u32 = 0x0200_0000;

/// Only watch events for the caller's filesystem namespace.
pub const IN_EXCL_UNLINK: u32 = 0x0400_0000;

/// Add to an existing watch mask instead of replacing it.
pub const IN_MASK_ADD: u32 = 0x2000_0000;

/// Watch is one-shot — removed after first event.
pub const IN_ONESHOT: u32 = 0x8000_0000;

/// Watch is on a directory (set by kernel in events, not user).
pub const IN_ISDIR: u32 = 0x4000_0000;

/// Set for events where the watch was removed or the filesystem was unmounted.
pub const IN_IGNORED: u32 = 0x0000_8000;

/// Q overflow — some events were lost.
pub const IN_Q_OVERFLOW: u32 = 0x0000_4000;

/// Filesystem containing watched object was unmounted.
pub const IN_UNMOUNT: u32 = 0x0000_2000;

/// Mask of valid user-supplied `add_watch` flags.
const IN_ADD_WATCH_VALID: u32 =
    IN_ALL_EVENTS | IN_DONT_FOLLOW | IN_EXCL_UNLINK | IN_MASK_ADD | IN_ONESHOT | IN_ISDIR;

// ---------------------------------------------------------------------------
// inotify_init1 flags
// ---------------------------------------------------------------------------

/// Set close-on-exec on the inotify fd.
pub const IN_CLOEXEC: u32 = 0x80000;

/// Set non-blocking mode on the inotify fd.
pub const IN_NONBLOCK: u32 = 0x800;

/// Valid `inotify_init1` flag bits.
const IN_INIT1_VALID: u32 = IN_CLOEXEC | IN_NONBLOCK;

// ---------------------------------------------------------------------------
// inotify event structure
// ---------------------------------------------------------------------------

/// Maximum length of the optional name field in an inotify event.
pub const INOTIFY_NAME_LEN_MAX: usize = 256;

/// An inotify event record.
///
/// Corresponds to `struct inotify_event` in the Linux UAPI.
/// The `name` field is only present when `len > 0`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InotifyEvent {
    /// Watch descriptor that triggered the event.
    pub wd: i32,
    /// Bitmask of event types.
    pub mask: u32,
    /// Cookie for linking `IN_MOVED_FROM`/`IN_MOVED_TO` pairs.
    pub cookie: u32,
    /// Length of the `name` field (0 if not present).
    pub len: u32,
}

impl InotifyEvent {
    /// Create an event without a name.
    pub const fn new(wd: i32, mask: u32, cookie: u32) -> Self {
        Self {
            wd,
            mask,
            cookie,
            len: 0,
        }
    }

    /// Create an overflow notification.
    pub const fn overflow() -> Self {
        Self::new(-1, IN_Q_OVERFLOW, 0)
    }

    /// Create an unmount notification.
    pub const fn unmount(wd: i32) -> Self {
        Self::new(wd, IN_UNMOUNT, 0)
    }

    /// Returns `true` if this event has an associated name.
    pub const fn has_name(&self) -> bool {
        self.len > 0
    }
}

// ---------------------------------------------------------------------------
// Watch entry
// ---------------------------------------------------------------------------

/// Identifier for an inode within the watch table (simplified).
pub type InoId = u64;

/// Watch descriptor — a positive integer unique within an inotify instance.
pub type WatchDesc = i32;

/// A single watch within an inotify instance.
#[derive(Debug, Clone, Copy)]
pub struct WatchEntry {
    /// Watch descriptor (identifier).
    pub wd: WatchDesc,
    /// Watched inode ID.
    pub ino_id: InoId,
    /// Event mask — which events trigger notifications.
    pub mask: u32,
    /// Whether the watch is one-shot (auto-removed on first event).
    pub oneshot: bool,
    /// Whether symlinks should not be followed.
    pub no_follow: bool,
    /// Total events delivered for this watch.
    pub events_delivered: u64,
}

impl WatchEntry {
    /// Create a new watch entry.
    pub const fn new(wd: WatchDesc, ino_id: InoId, mask: u32) -> Self {
        Self {
            wd,
            ino_id,
            mask,
            oneshot: (mask & IN_ONESHOT) != 0,
            no_follow: (mask & IN_DONT_FOLLOW) != 0,
            events_delivered: 0,
        }
    }

    /// Update the mask for this watch (`IN_MASK_ADD` semantics).
    pub fn update_mask(&mut self, new_mask: u32, add_mode: bool) {
        let base = new_mask & !IN_MASK_ADD;
        if add_mode {
            self.mask |= base;
        } else {
            self.mask = base;
        }
        self.oneshot = (self.mask & IN_ONESHOT) != 0;
        self.no_follow = (self.mask & IN_DONT_FOLLOW) != 0;
    }

    /// Returns `true` if `event_mask` matches this watch's mask.
    pub const fn matches(&self, event_mask: u32) -> bool {
        (self.mask & event_mask) != 0
    }
}

// ---------------------------------------------------------------------------
// Event queue
// ---------------------------------------------------------------------------

/// Maximum number of queued inotify events per instance.
const INOTIFY_QUEUE_DEPTH: usize = 16_384;

/// Maximum number of watches per inotify instance.
const MAX_WATCHES: usize = 8_192;

/// Simple ring-buffer event queue.
///
/// In a real kernel this would be a linked list of `inotify_event` records
/// in a per-fd buffer.  Here we use a fixed-size ring buffer of event
/// structs for correctness without dynamic allocation.
pub struct EventQueue {
    /// Ring buffer of events.
    buf: [InotifyEvent; INOTIFY_QUEUE_DEPTH],
    /// Write position.
    head: usize,
    /// Read position.
    tail: usize,
    /// Number of enqueued events.
    count: usize,
    /// Whether the overflow sentinel has been enqueued.
    overflowed: bool,
}

impl EventQueue {
    /// Create an empty event queue.
    pub const fn new() -> Self {
        Self {
            buf: [InotifyEvent {
                wd: 0,
                mask: 0,
                cookie: 0,
                len: 0,
            }; INOTIFY_QUEUE_DEPTH],
            head: 0,
            tail: 0,
            count: 0,
            overflowed: false,
        }
    }

    /// Enqueue an event.
    ///
    /// If the queue is full, marks it as overflowed.  The overflow
    /// sentinel is delivered as a separate `IN_Q_OVERFLOW` event.
    pub fn enqueue(&mut self, event: InotifyEvent) {
        if self.count >= INOTIFY_QUEUE_DEPTH {
            if !self.overflowed {
                self.overflowed = true;
            }
            return;
        }
        self.buf[self.head] = event;
        self.head = (self.head + 1) % INOTIFY_QUEUE_DEPTH;
        self.count += 1;
    }

    /// Dequeue the next event, or return the overflow sentinel.
    pub fn dequeue(&mut self) -> Option<InotifyEvent> {
        if self.count == 0 {
            if self.overflowed {
                self.overflowed = false;
                return Some(InotifyEvent::overflow());
            }
            return None;
        }
        let ev = self.buf[self.tail];
        self.tail = (self.tail + 1) % INOTIFY_QUEUE_DEPTH;
        self.count -= 1;
        Some(ev)
    }

    /// Number of pending events.
    pub const fn pending(&self) -> usize {
        self.count
    }

    /// Returns `true` if there are events ready to read.
    pub fn has_events(&self) -> bool {
        self.count > 0 || self.overflowed
    }
}

impl Default for EventQueue {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// inotify instance
// ---------------------------------------------------------------------------

/// An inotify file descriptor instance.
pub struct InotifyInstance {
    /// inotify file descriptor number.
    pub fd: i32,
    /// Flags from `inotify_init1`.
    pub flags: u32,
    /// Next watch descriptor to allocate.
    next_wd: WatchDesc,
    /// Watch table.
    watches: [Option<WatchEntry>; MAX_WATCHES],
    /// Number of active watches.
    watch_count: usize,
    /// Pending event queue.
    pub queue: EventQueue,
}

impl InotifyInstance {
    /// Create a new inotify instance.
    pub const fn new(fd: i32, flags: u32) -> Self {
        Self {
            fd,
            flags,
            next_wd: 1,
            watches: [const { None }; MAX_WATCHES],
            watch_count: 0,
            queue: EventQueue::new(),
        }
    }

    fn find_by_wd(&self, wd: WatchDesc) -> Option<usize> {
        self.watches
            .iter()
            .position(|w| w.map_or(false, |w| w.wd == wd))
    }

    fn find_by_ino(&self, ino_id: InoId) -> Option<usize> {
        self.watches
            .iter()
            .position(|w| w.map_or(false, |w| w.ino_id == ino_id))
    }

    fn free_slot(&self) -> Option<usize> {
        self.watches.iter().position(|w| w.is_none())
    }

    /// Add or update a watch for `ino_id` with `mask`.
    ///
    /// Returns the watch descriptor on success.
    pub fn add_watch(&mut self, ino_id: InoId, mask: u32) -> Result<WatchDesc> {
        if let Some(idx) = self.find_by_ino(ino_id) {
            // Update existing watch.
            let add_mode = (mask & IN_MASK_ADD) != 0;
            let entry = self.watches[idx].as_mut().unwrap();
            entry.update_mask(mask, add_mode);
            return Ok(entry.wd);
        }
        if self.watch_count >= MAX_WATCHES {
            return Err(Error::OutOfMemory);
        }
        let slot = self.free_slot().ok_or(Error::OutOfMemory)?;
        let wd = self.next_wd;
        self.next_wd = self.next_wd.wrapping_add(1).max(1);
        self.watches[slot] = Some(WatchEntry::new(wd, ino_id, mask));
        self.watch_count += 1;
        Ok(wd)
    }

    /// Remove the watch with descriptor `wd`.
    ///
    /// Returns [`Error::NotFound`] if no such watch exists.
    pub fn rm_watch(&mut self, wd: WatchDesc) -> Result<()> {
        let idx = self.find_by_wd(wd).ok_or(Error::NotFound)?;
        self.watches[idx] = None;
        self.watch_count = self.watch_count.saturating_sub(1);
        Ok(())
    }

    /// Deliver an event for `ino_id` with `event_mask`.
    ///
    /// If a matching watch exists, the event is enqueued.  One-shot
    /// watches are removed after delivery.
    pub fn deliver_event(&mut self, ino_id: InoId, event_mask: u32, cookie: u32) {
        let idx = match self.find_by_ino(ino_id) {
            Some(i) => i,
            None => return,
        };
        let (wd, oneshot, matches) = {
            let entry = self.watches[idx].as_mut().unwrap();
            let m = entry.matches(event_mask);
            if m {
                entry.events_delivered = entry.events_delivered.saturating_add(1);
            }
            (entry.wd, entry.oneshot, m)
        };
        if matches {
            self.queue
                .enqueue(InotifyEvent::new(wd, event_mask, cookie));
            if oneshot {
                self.watches[idx] = None;
                self.watch_count = self.watch_count.saturating_sub(1);
            }
        }
    }

    /// Number of active watches.
    pub const fn watch_count(&self) -> usize {
        self.watch_count
    }

    /// Returns `true` if close-on-exec is set.
    pub const fn cloexec(&self) -> bool {
        (self.flags & IN_CLOEXEC) != 0
    }

    /// Returns `true` if non-blocking mode is set.
    pub const fn nonblocking(&self) -> bool {
        (self.flags & IN_NONBLOCK) != 0
    }
}

// ---------------------------------------------------------------------------
// inotify instance registry
// ---------------------------------------------------------------------------

/// Maximum number of inotify instances in the system.
const MAX_INOTIFY_INSTANCES: usize = 128;

/// System-wide inotify instance registry.
pub struct InotifyRegistry {
    instances: [Option<InotifyInstance>; MAX_INOTIFY_INSTANCES],
    next_fd: i32,
    count: usize,
}

impl InotifyRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            instances: [const { None }; MAX_INOTIFY_INSTANCES],
            next_fd: 1,
            count: 0,
        }
    }

    fn free_slot(&self) -> Option<usize> {
        self.instances.iter().position(|i| i.is_none())
    }

    fn find_by_fd(&self, fd: i32) -> Option<usize> {
        self.instances
            .iter()
            .position(|i| i.as_ref().map_or(false, |i| i.fd == fd))
    }

    /// Allocate a new inotify instance, returning its fd.
    pub fn create(&mut self, flags: u32) -> Result<i32> {
        if self.count >= MAX_INOTIFY_INSTANCES {
            return Err(Error::OutOfMemory);
        }
        let slot = self.free_slot().ok_or(Error::OutOfMemory)?;
        let fd = self.next_fd;
        self.next_fd = self.next_fd.wrapping_add(1).max(1);
        self.instances[slot] = Some(InotifyInstance::new(fd, flags));
        self.count += 1;
        Ok(fd)
    }

    /// Get a reference to an instance by fd.
    pub fn get(&self, fd: i32) -> Option<&InotifyInstance> {
        self.instances.iter().flatten().find(|i| i.fd == fd)
    }

    /// Get a mutable reference to an instance by fd.
    pub fn get_mut(&mut self, fd: i32) -> Option<&mut InotifyInstance> {
        self.instances.iter_mut().flatten().find(|i| i.fd == fd)
    }

    /// Close an inotify instance by fd.
    pub fn close(&mut self, fd: i32) -> Result<()> {
        let idx = self.find_by_fd(fd).ok_or(Error::NotFound)?;
        self.instances[idx] = None;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }
}

impl Default for InotifyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Syscall handlers
// ---------------------------------------------------------------------------

/// `inotify_init(2)` — create an inotify instance with no flags.
///
/// # Errors
///
/// - [`Error::OutOfMemory`] — Registry is full.
pub fn sys_inotify_init(registry: &mut InotifyRegistry) -> Result<i32> {
    registry.create(0)
}

/// `inotify_init1(2)` — create an inotify instance with flags.
///
/// # Arguments
///
/// - `registry` — Mutable inotify registry.
/// - `flags` — Combination of `IN_CLOEXEC` and/or `IN_NONBLOCK`.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — Unrecognised flag bits.
/// - [`Error::OutOfMemory`] — Registry is full.
pub fn sys_inotify_init1(registry: &mut InotifyRegistry, flags: u32) -> Result<i32> {
    if flags & !IN_INIT1_VALID != 0 {
        return Err(Error::InvalidArgument);
    }
    registry.create(flags)
}

/// `inotify_add_watch(2)` — add or modify a watch on `ino_id`.
///
/// # Arguments
///
/// - `registry` — Mutable inotify registry.
/// - `fd` — inotify instance fd.
/// - `ino_id` — Inode to watch.
/// - `mask` — Event mask (`IN_*` flags).
///
/// # Errors
///
/// - [`Error::NotFound`] — `fd` does not refer to an inotify instance.
/// - [`Error::InvalidArgument`] — `mask` has no valid event bits.
/// - [`Error::OutOfMemory`] — Watch table is full.
pub fn sys_inotify_add_watch(
    registry: &mut InotifyRegistry,
    fd: i32,
    ino_id: InoId,
    mask: u32,
) -> Result<WatchDesc> {
    if mask & IN_ADD_WATCH_VALID == 0 {
        return Err(Error::InvalidArgument);
    }
    let instance = registry.get_mut(fd).ok_or(Error::NotFound)?;
    instance.add_watch(ino_id, mask)
}

/// `inotify_rm_watch(2)` — remove a watch by its watch descriptor.
///
/// # Arguments
///
/// - `registry` — Mutable inotify registry.
/// - `fd` — inotify instance fd.
/// - `wd` — Watch descriptor to remove.
///
/// # Errors
///
/// - [`Error::NotFound`] — `fd` or `wd` not found.
pub fn sys_inotify_rm_watch(registry: &mut InotifyRegistry, fd: i32, wd: WatchDesc) -> Result<()> {
    let instance = registry.get_mut(fd).ok_or(Error::NotFound)?;
    instance.rm_watch(wd)
}

/// Read the next pending inotify event from an instance.
///
/// Returns `None` if there are no pending events and the instance is
/// non-blocking, or blocks semantically for blocking instances.
///
/// # Arguments
///
/// - `registry` — Mutable inotify registry.
/// - `fd` — inotify instance fd.
///
/// # Errors
///
/// - [`Error::NotFound`] — `fd` not found.
/// - [`Error::WouldBlock`] — Non-blocking fd with no pending events.
pub fn sys_inotify_read(registry: &mut InotifyRegistry, fd: i32) -> Result<InotifyEvent> {
    let instance = registry.get_mut(fd).ok_or(Error::NotFound)?;
    if let Some(ev) = instance.queue.dequeue() {
        return Ok(ev);
    }
    if instance.nonblocking() {
        Err(Error::WouldBlock)
    } else {
        Err(Error::WouldBlock) // simplified: would block in real impl
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_and_close() {
        let mut reg = InotifyRegistry::new();
        let fd = sys_inotify_init(&mut reg).unwrap();
        assert!(fd > 0);
        assert_eq!(reg.count, 1);
        reg.close(fd).unwrap();
        assert_eq!(reg.count, 0);
    }

    #[test]
    fn test_init1_invalid_flags() {
        let mut reg = InotifyRegistry::new();
        let result = sys_inotify_init1(&mut reg, 0xFF00_0000);
        assert!(result.is_err());
    }

    #[test]
    fn test_add_and_rm_watch() {
        let mut reg = InotifyRegistry::new();
        let fd = sys_inotify_init(&mut reg).unwrap();
        let wd = sys_inotify_add_watch(&mut reg, fd, 42, IN_CREATE | IN_DELETE).unwrap();
        assert!(wd > 0);
        sys_inotify_rm_watch(&mut reg, fd, wd).unwrap();
    }

    #[test]
    fn test_event_delivery() {
        let mut reg = InotifyRegistry::new();
        let fd = sys_inotify_init(&mut reg).unwrap();
        sys_inotify_add_watch(&mut reg, fd, 42, IN_CREATE).unwrap();
        let inst = reg.get_mut(fd).unwrap();
        inst.deliver_event(42, IN_CREATE, 0);
        assert!(inst.queue.has_events());
        let ev = inst.queue.dequeue().unwrap();
        assert_eq!(ev.mask, IN_CREATE);
    }

    #[test]
    fn test_event_not_delivered_for_unmatched_mask() {
        let mut reg = InotifyRegistry::new();
        let fd = sys_inotify_init(&mut reg).unwrap();
        sys_inotify_add_watch(&mut reg, fd, 42, IN_CREATE).unwrap();
        let inst = reg.get_mut(fd).unwrap();
        inst.deliver_event(42, IN_DELETE, 0); // not in watch mask
        assert!(!inst.queue.has_events());
    }

    #[test]
    fn test_oneshot_watch_removed_after_event() {
        let mut reg = InotifyRegistry::new();
        let fd = sys_inotify_init(&mut reg).unwrap();
        sys_inotify_add_watch(&mut reg, fd, 42, IN_CREATE | IN_ONESHOT).unwrap();
        let inst = reg.get_mut(fd).unwrap();
        inst.deliver_event(42, IN_CREATE, 0);
        assert_eq!(inst.watch_count(), 0); // removed after delivery
    }

    #[test]
    fn test_nonblocking_returns_wouldblock() {
        let mut reg = InotifyRegistry::new();
        let fd = sys_inotify_init1(&mut reg, IN_NONBLOCK).unwrap();
        let result = sys_inotify_read(&mut reg, fd);
        assert!(matches!(result, Err(Error::WouldBlock)));
    }
}
