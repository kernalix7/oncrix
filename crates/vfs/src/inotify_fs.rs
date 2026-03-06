// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Inotify filesystem event system — VFS integration layer.
//!
//! This module provides the VFS-level hook layer that connects filesystem
//! operations to the inotify notification machinery. While [`crate::inotify`]
//! implements the instance/watch data structures, this module handles:
//!
//! - Per-inode watch lists that survive inode recycle.
//! - Event generation at filesystem operation boundaries (create, delete,
//!   rename, chmod, truncate, …).
//! - Cookie allocation for paired `IN_MOVED_FROM` / `IN_MOVED_TO` events.
//! - A global [`InotifyFsRegistry`] that the VFS calls into at each op.
//!
//! # Design
//!
//! ```text
//! VFS operation (e.g., vfs_create)
//!   → inotify_fs::notify_event(inode_id, IN_CREATE, name)
//!     → InotifyFsRegistry::dispatch()
//!       → for each watch on this inode:
//!           InotifyFsInstance::queue_event()
//! ```
//!
//! # References
//!
//! - Linux `fs/notify/inotify/inotify_fsnotify.c`
//! - Linux `fs/notify/inotify/inotify_user.c`
//! - `inotify(7)` manual page

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────

/// Maximum inotify instances tracked by the registry.
const MAX_FS_INSTANCES: usize = 64;

/// Maximum watches per inotify-fs instance.
const MAX_FS_WATCHES: usize = 128;

/// Maximum queued events per inotify-fs instance.
const MAX_FS_EVENTS: usize = 256;

/// Maximum name length for an event subject (filename component).
const MAX_EVENT_NAME: usize = 256;

/// Maximum number of inodes tracked globally for watch hints.
const MAX_WATCHED_INODES: usize = 512;

// ── Event mask constants (re-exported for users of this module) ─

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
/// Subdirectory was created.
pub const IN_CREATE: u32 = 0x0000_0100;
/// File/directory was deleted.
pub const IN_DELETE: u32 = 0x0000_0200;
/// Watched file/directory itself was deleted.
pub const IN_DELETE_SELF: u32 = 0x0000_0400;
/// Watched file/directory itself was moved.
pub const IN_MOVE_SELF: u32 = 0x0000_0800;
/// Filesystem containing watched object was unmounted.
pub const IN_UNMOUNT: u32 = 0x0000_2000;
/// Event queue overflowed.
pub const IN_Q_OVERFLOW: u32 = 0x0000_4000;
/// Watch was removed.
pub const IN_IGNORED: u32 = 0x0000_8000;
/// Subject of this event is a directory.
pub const IN_ISDIR: u32 = 0x4000_0000;
/// Only monitor for a single event, then remove the watch.
pub const IN_ONESHOT: u32 = 0x8000_0000;

/// All standard event bits combined.
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

// ── FsEventName ─────────────────────────────────────────────────

/// Fixed-size filename associated with an inotify filesystem event.
#[derive(Clone, Copy)]
pub struct FsEventName {
    buf: [u8; MAX_EVENT_NAME],
    len: usize,
}

impl FsEventName {
    /// Creates an empty event name.
    pub const fn empty() -> Self {
        Self {
            buf: [0u8; MAX_EVENT_NAME],
            len: 0,
        }
    }

    /// Creates an event name from a byte slice, truncating if necessary.
    pub fn from_bytes(name: &[u8]) -> Self {
        let mut this = Self::empty();
        let copy_len = name.len().min(MAX_EVENT_NAME);
        this.buf[..copy_len].copy_from_slice(&name[..copy_len]);
        this.len = copy_len;
        this
    }

    /// Returns the name as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Returns `true` if the name is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl core::fmt::Debug for FsEventName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "FsEventName({:?})",
            core::str::from_utf8(self.as_bytes()).unwrap_or("<non-utf8>")
        )
    }
}

// ── InotifyFsEvent ───────────────────────────────────────────────

/// A pending inotify event in the per-instance queue.
#[derive(Clone, Copy, Debug)]
pub struct InotifyFsEvent {
    /// Watch descriptor that generated this event.
    pub watch_descriptor: i32,
    /// Event mask bits.
    pub mask: u32,
    /// Cookie for rename pairing (`IN_MOVED_FROM` / `IN_MOVED_TO`).
    pub cookie: u32,
    /// Inode identifier the event is about.
    pub inode_id: u64,
    /// Optional filename component (e.g., name of created child).
    pub name: FsEventName,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl InotifyFsEvent {
    /// Creates an empty/unoccupied event slot.
    pub const fn empty() -> Self {
        Self {
            watch_descriptor: 0,
            mask: 0,
            cookie: 0,
            inode_id: 0,
            name: FsEventName::empty(),
            occupied: false,
        }
    }
}

// ── InotifyFsWatch ───────────────────────────────────────────────

/// A single watch entry within an inotify-fs instance.
#[derive(Clone, Copy, Debug)]
pub struct InotifyFsWatch {
    /// Unique watch descriptor (> 0 when active).
    pub descriptor: i32,
    /// Inode being watched.
    pub inode_id: u64,
    /// Event mask this watch is interested in.
    pub mask: u32,
    /// Whether this watch slot is active.
    active: bool,
}

impl InotifyFsWatch {
    /// Creates an inactive watch slot.
    pub const fn empty() -> Self {
        Self {
            descriptor: 0,
            inode_id: 0,
            mask: 0,
            active: false,
        }
    }
}

// ── InotifyFsInstance ────────────────────────────────────────────

/// Per-process inotify-fs instance holding watches and the event queue.
pub struct InotifyFsInstance {
    /// Unique instance identifier.
    pub id: u32,
    /// Active watches.
    watches: [InotifyFsWatch; MAX_FS_WATCHES],
    /// Number of active watches.
    watch_count: usize,
    /// Next watch descriptor to assign.
    next_wd: i32,
    /// Pending event ring buffer.
    events: [InotifyFsEvent; MAX_FS_EVENTS],
    /// Write head of the ring buffer.
    head: usize,
    /// Read tail of the ring buffer.
    tail: usize,
    /// Whether the queue overflowed since last read.
    overflow: bool,
    /// Whether this instance slot is active.
    active: bool,
}

impl InotifyFsInstance {
    /// Creates an inactive instance slot.
    pub const fn empty() -> Self {
        Self {
            id: 0,
            watches: [const { InotifyFsWatch::empty() }; MAX_FS_WATCHES],
            watch_count: 0,
            next_wd: 1,
            events: [const { InotifyFsEvent::empty() }; MAX_FS_EVENTS],
            head: 0,
            tail: 0,
            overflow: false,
            active: false,
        }
    }

    /// Adds a watch for `inode_id` with the given `mask`.
    ///
    /// If a watch for `inode_id` already exists, its mask is replaced.
    /// Returns the watch descriptor on success.
    pub fn add_watch(&mut self, inode_id: u64, mask: u32) -> Result<i32> {
        // Update existing watch if present.
        for i in 0..MAX_FS_WATCHES {
            if self.watches[i].active && self.watches[i].inode_id == inode_id {
                self.watches[i].mask = mask;
                return Ok(self.watches[i].descriptor);
            }
        }
        // Find empty slot.
        for i in 0..MAX_FS_WATCHES {
            if !self.watches[i].active {
                let wd = self.next_wd;
                self.next_wd = self.next_wd.saturating_add(1);
                self.watches[i] = InotifyFsWatch {
                    descriptor: wd,
                    inode_id,
                    mask,
                    active: true,
                };
                self.watch_count += 1;
                return Ok(wd);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Removes the watch identified by `wd`.
    ///
    /// Queues an `IN_IGNORED` event so the caller knows the watch is gone.
    pub fn remove_watch(&mut self, wd: i32) -> Result<()> {
        for i in 0..MAX_FS_WATCHES {
            if self.watches[i].active && self.watches[i].descriptor == wd {
                let inode_id = self.watches[i].inode_id;
                self.watches[i].active = false;
                self.watch_count -= 1;
                self.push_event(InotifyFsEvent {
                    watch_descriptor: wd,
                    mask: IN_IGNORED,
                    cookie: 0,
                    inode_id,
                    name: FsEventName::empty(),
                    occupied: true,
                });
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Queues `event` into the ring buffer.
    ///
    /// If the buffer is full the overflow flag is set; a later
    /// `IN_Q_OVERFLOW` event will be generated when the caller reads.
    fn push_event(&mut self, mut event: InotifyFsEvent) {
        let next = (self.head + 1) % MAX_FS_EVENTS;
        if next == self.tail {
            self.overflow = true;
            return;
        }
        event.occupied = true;
        self.events[self.head] = event;
        self.head = next;
    }

    /// Reads the next event from the queue.
    ///
    /// Returns `None` when no events are pending.
    pub fn read_event(&mut self) -> Option<InotifyFsEvent> {
        if self.overflow {
            self.overflow = false;
            return Some(InotifyFsEvent {
                watch_descriptor: -1,
                mask: IN_Q_OVERFLOW,
                cookie: 0,
                inode_id: 0,
                name: FsEventName::empty(),
                occupied: true,
            });
        }
        if self.head == self.tail {
            return None;
        }
        let ev = self.events[self.tail];
        self.tail = (self.tail + 1) % MAX_FS_EVENTS;
        Some(ev)
    }

    /// Returns the number of pending events (approximate, without overflow).
    pub fn pending_count(&self) -> usize {
        (self.head + MAX_FS_EVENTS - self.tail) % MAX_FS_EVENTS
    }

    /// Dispatches a raw filesystem event to this instance.
    ///
    /// Checks every watch on this instance; if the inode matches and
    /// the mask overlaps, queues the event.
    pub fn dispatch(&mut self, inode_id: u64, mask: u32, cookie: u32, name: FsEventName) {
        for i in 0..MAX_FS_WATCHES {
            if !self.watches[i].active {
                continue;
            }
            if self.watches[i].inode_id != inode_id {
                continue;
            }
            if self.watches[i].mask & mask == 0 {
                continue;
            }
            let wd = self.watches[i].descriptor;
            let effective_mask = self.watches[i].mask & mask;
            self.push_event(InotifyFsEvent {
                watch_descriptor: wd,
                mask: effective_mask,
                cookie,
                inode_id,
                name,
                occupied: true,
            });
            // Remove watch on IN_ONESHOT.
            if self.watches[i].mask & IN_ONESHOT != 0 {
                self.watches[i].active = false;
                self.watch_count -= 1;
            }
        }
    }
}

// ── InotifyInodeHint ─────────────────────────────────────────────

/// Lightweight record that notes which inodes have at least one watch.
///
/// The registry uses this to skip dispatch when no instance is watching
/// a given inode — avoiding O(n) scan of all instances for unmonitored inodes.
#[derive(Clone, Copy, Debug)]
struct InotifyInodeHint {
    inode_id: u64,
    ref_count: u32,
}

impl InotifyInodeHint {
    const fn empty() -> Self {
        Self {
            inode_id: 0,
            ref_count: 0,
        }
    }
}

// ── InotifyFsRegistry ────────────────────────────────────────────

/// Global registry of all inotify-fs instances.
///
/// This is the central coordination point called by the VFS at each
/// filesystem operation.  It maintains a set of active instances and
/// dispatches events to those instances whose watches match the
/// affected inode.
pub struct InotifyFsRegistry {
    /// All inotify-fs instances.
    instances: [InotifyFsInstance; MAX_FS_INSTANCES],
    /// Number of active instances.
    instance_count: usize,
    /// Next instance identifier.
    next_id: u32,
    /// Hint table of inodes that have at least one active watch.
    inode_hints: [InotifyInodeHint; MAX_WATCHED_INODES],
    /// Number of occupied hint entries.
    hint_count: usize,
    /// Monotonic rename cookie counter.
    next_cookie: u32,
}

impl InotifyFsRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            instances: [const { InotifyFsInstance::empty() }; MAX_FS_INSTANCES],
            instance_count: 0,
            next_id: 1,
            inode_hints: [const { InotifyInodeHint::empty() }; MAX_WATCHED_INODES],
            hint_count: 0,
            next_cookie: 1,
        }
    }

    /// Creates a new inotify-fs instance.
    ///
    /// Returns the instance identifier on success.
    pub fn create_instance(&mut self) -> Result<u32> {
        for i in 0..MAX_FS_INSTANCES {
            if !self.instances[i].active {
                let id = self.next_id;
                self.next_id = self.next_id.saturating_add(1);
                self.instances[i].active = true;
                self.instances[i].id = id;
                self.instances[i].watch_count = 0;
                self.instances[i].head = 0;
                self.instances[i].tail = 0;
                self.instances[i].next_wd = 1;
                self.instances[i].overflow = false;
                self.instance_count += 1;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Destroys an inotify-fs instance identified by `id`.
    pub fn destroy_instance(&mut self, id: u32) -> Result<()> {
        for i in 0..MAX_FS_INSTANCES {
            if self.instances[i].active && self.instances[i].id == id {
                // Remove all watches from the hint table.
                for j in 0..MAX_FS_WATCHES {
                    if self.instances[i].watches[j].active {
                        let inode_id = self.instances[i].watches[j].inode_id;
                        self.decrement_hint(inode_id);
                    }
                }
                self.instances[i].active = false;
                self.instance_count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Adds a watch for `inode_id` to instance `id`.
    pub fn add_watch(&mut self, instance_id: u32, inode_id: u64, mask: u32) -> Result<i32> {
        for i in 0..MAX_FS_INSTANCES {
            if self.instances[i].active && self.instances[i].id == instance_id {
                // Track hint before add (add_watch updates existing or creates new).
                let had_watch = self.instances[i]
                    .watches
                    .iter()
                    .any(|w| w.active && w.inode_id == inode_id);
                let wd = self.instances[i].add_watch(inode_id, mask)?;
                if !had_watch {
                    self.increment_hint(inode_id)?;
                }
                return Ok(wd);
            }
        }
        Err(Error::NotFound)
    }

    /// Removes a watch by descriptor from instance `id`.
    pub fn remove_watch(&mut self, instance_id: u32, wd: i32) -> Result<()> {
        for i in 0..MAX_FS_INSTANCES {
            if self.instances[i].active && self.instances[i].id == instance_id {
                // Find the inode_id before removal.
                let inode_id = self.instances[i]
                    .watches
                    .iter()
                    .find(|w| w.active && w.descriptor == wd)
                    .map(|w| w.inode_id)
                    .ok_or(Error::NotFound)?;
                self.instances[i].remove_watch(wd)?;
                self.decrement_hint(inode_id);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Reads the next pending event from instance `id`.
    pub fn read_event(&mut self, instance_id: u32) -> Result<Option<InotifyFsEvent>> {
        for i in 0..MAX_FS_INSTANCES {
            if self.instances[i].active && self.instances[i].id == instance_id {
                return Ok(self.instances[i].read_event());
            }
        }
        Err(Error::NotFound)
    }

    /// Dispatches an event to all instances watching `inode_id`.
    ///
    /// This is the main entry point for the VFS hook layer.
    pub fn notify_event(&mut self, inode_id: u64, mask: u32, name: &[u8]) {
        if !self.inode_is_watched(inode_id) {
            return;
        }
        let name = FsEventName::from_bytes(name);
        for i in 0..MAX_FS_INSTANCES {
            if self.instances[i].active {
                self.instances[i].dispatch(inode_id, mask, 0, name);
            }
        }
    }

    /// Dispatches a rename event pair (allocates a shared cookie).
    ///
    /// Sends `IN_MOVED_FROM` for `src_inode` and `IN_MOVED_TO` for
    /// `dst_inode` with the same cookie value.
    pub fn notify_rename(
        &mut self,
        src_inode: u64,
        src_name: &[u8],
        dst_inode: u64,
        dst_name: &[u8],
    ) {
        let cookie = self.next_cookie;
        self.next_cookie = self.next_cookie.wrapping_add(1);

        let src = FsEventName::from_bytes(src_name);
        let dst = FsEventName::from_bytes(dst_name);

        for i in 0..MAX_FS_INSTANCES {
            if self.instances[i].active {
                if self.inode_is_watched(src_inode) {
                    self.instances[i].dispatch(src_inode, IN_MOVED_FROM, cookie, src);
                }
                if self.inode_is_watched(dst_inode) {
                    self.instances[i].dispatch(dst_inode, IN_MOVED_TO, cookie, dst);
                }
            }
        }
    }

    /// Returns `true` if any active watch targets `inode_id`.
    fn inode_is_watched(&self, inode_id: u64) -> bool {
        for i in 0..self.hint_count {
            if self.inode_hints[i].inode_id == inode_id && self.inode_hints[i].ref_count > 0 {
                return true;
            }
        }
        false
    }

    /// Increments the reference count for `inode_id` in the hint table.
    fn increment_hint(&mut self, inode_id: u64) -> Result<()> {
        for i in 0..self.hint_count {
            if self.inode_hints[i].inode_id == inode_id {
                self.inode_hints[i].ref_count += 1;
                return Ok(());
            }
        }
        if self.hint_count >= MAX_WATCHED_INODES {
            return Err(Error::OutOfMemory);
        }
        self.inode_hints[self.hint_count] = InotifyInodeHint {
            inode_id,
            ref_count: 1,
        };
        self.hint_count += 1;
        Ok(())
    }

    /// Decrements the reference count for `inode_id` in the hint table.
    fn decrement_hint(&mut self, inode_id: u64) {
        for i in 0..self.hint_count {
            if self.inode_hints[i].inode_id == inode_id {
                if self.inode_hints[i].ref_count > 0 {
                    self.inode_hints[i].ref_count -= 1;
                }
                return;
            }
        }
    }

    /// Returns the number of active instances.
    pub fn instance_count(&self) -> usize {
        self.instance_count
    }
}

// ── Public hook functions ─────────────────────────────────────────

/// Convenience hook: notify a file access event on `inode_id`.
pub fn fs_notify_access(registry: &mut InotifyFsRegistry, inode_id: u64) {
    registry.notify_event(inode_id, IN_ACCESS, b"");
}

/// Convenience hook: notify a file modification event on `inode_id`.
pub fn fs_notify_modify(registry: &mut InotifyFsRegistry, inode_id: u64) {
    registry.notify_event(inode_id, IN_MODIFY, b"");
}

/// Convenience hook: notify an attribute change on `inode_id`.
pub fn fs_notify_attrib(registry: &mut InotifyFsRegistry, inode_id: u64) {
    registry.notify_event(inode_id, IN_ATTRIB, b"");
}

/// Convenience hook: notify a file-create event in directory `dir_inode`.
pub fn fs_notify_create(registry: &mut InotifyFsRegistry, dir_inode: u64, name: &[u8]) {
    registry.notify_event(dir_inode, IN_CREATE, name);
}

/// Convenience hook: notify a file-delete event in directory `dir_inode`.
pub fn fs_notify_delete(registry: &mut InotifyFsRegistry, dir_inode: u64, name: &[u8]) {
    registry.notify_event(dir_inode, IN_DELETE, name);
}

/// Convenience hook: notify that `inode_id` itself was deleted.
pub fn fs_notify_delete_self(registry: &mut InotifyFsRegistry, inode_id: u64) {
    registry.notify_event(inode_id, IN_DELETE_SELF, b"");
}

/// Convenience hook: notify open event on `inode_id`.
pub fn fs_notify_open(registry: &mut InotifyFsRegistry, inode_id: u64) {
    registry.notify_event(inode_id, IN_OPEN, b"");
}

/// Convenience hook: notify close-write event on `inode_id`.
pub fn fs_notify_close_write(registry: &mut InotifyFsRegistry, inode_id: u64) {
    registry.notify_event(inode_id, IN_CLOSE_WRITE, b"");
}

/// Convenience hook: notify rename across two inodes.
pub fn fs_notify_rename(
    registry: &mut InotifyFsRegistry,
    src_inode: u64,
    src_name: &[u8],
    dst_inode: u64,
    dst_name: &[u8],
) {
    registry.notify_rename(src_inode, src_name, dst_inode, dst_name);
}

/// Convenience hook: notify unmount of `inode_id`.
pub fn fs_notify_unmount(registry: &mut InotifyFsRegistry, inode_id: u64) {
    registry.notify_event(inode_id, IN_UNMOUNT, b"");
}

// ── Unit tests ───────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_destroy_instance() {
        let mut reg = InotifyFsRegistry::new();
        let id = reg.create_instance().unwrap();
        assert!(id > 0);
        assert_eq!(reg.instance_count(), 1);
        reg.destroy_instance(id).unwrap();
        assert_eq!(reg.instance_count(), 0);
    }

    #[test]
    fn test_add_remove_watch() {
        let mut reg = InotifyFsRegistry::new();
        let id = reg.create_instance().unwrap();
        let wd = reg.add_watch(id, 42, IN_CREATE | IN_DELETE).unwrap();
        assert!(wd > 0);
        reg.remove_watch(id, wd).unwrap();
        reg.destroy_instance(id).unwrap();
    }

    #[test]
    fn test_event_dispatch() {
        let mut reg = InotifyFsRegistry::new();
        let id = reg.create_instance().unwrap();
        reg.add_watch(id, 99, IN_CREATE).unwrap();
        reg.notify_event(99, IN_CREATE, b"hello.txt");
        let ev = reg.read_event(id).unwrap().unwrap();
        assert_eq!(ev.mask & IN_CREATE, IN_CREATE);
        assert_eq!(ev.name.as_bytes(), b"hello.txt");
        reg.destroy_instance(id).unwrap();
    }

    #[test]
    fn test_rename_cookie_pairing() {
        let mut reg = InotifyFsRegistry::new();
        let id = reg.create_instance().unwrap();
        reg.add_watch(id, 10, IN_MOVED_FROM).unwrap();
        reg.add_watch(id, 20, IN_MOVED_TO).unwrap();
        reg.notify_rename(10, b"src", 20, b"dst");
        let ev_from = reg.read_event(id).unwrap().unwrap();
        let ev_to = reg.read_event(id).unwrap().unwrap();
        assert_eq!(ev_from.cookie, ev_to.cookie);
        assert!(ev_from.mask & IN_MOVED_FROM != 0);
        assert!(ev_to.mask & IN_MOVED_TO != 0);
        reg.destroy_instance(id).unwrap();
    }

    #[test]
    fn test_oneshot_removes_watch() {
        let mut reg = InotifyFsRegistry::new();
        let id = reg.create_instance().unwrap();
        reg.add_watch(id, 55, IN_MODIFY | IN_ONESHOT).unwrap();
        reg.notify_event(55, IN_MODIFY, b"");
        // Event delivered.
        let ev = reg.read_event(id).unwrap().unwrap();
        assert!(ev.mask & IN_MODIFY != 0);
        // Second event should not be delivered (watch removed).
        reg.notify_event(55, IN_MODIFY, b"");
        assert!(reg.read_event(id).unwrap().is_none());
        reg.destroy_instance(id).unwrap();
    }

    #[test]
    fn test_no_dispatch_when_not_watched() {
        let mut reg = InotifyFsRegistry::new();
        let id = reg.create_instance().unwrap();
        // Watch inode 1, dispatch on inode 2 — no event.
        reg.add_watch(id, 1, IN_ALL_EVENTS).unwrap();
        reg.notify_event(2, IN_CREATE, b"file");
        assert!(reg.read_event(id).unwrap().is_none());
        reg.destroy_instance(id).unwrap();
    }

    #[test]
    fn test_event_name_truncation() {
        let long_name = [b'x'; MAX_EVENT_NAME + 10];
        let name = FsEventName::from_bytes(&long_name);
        assert_eq!(name.as_bytes().len(), MAX_EVENT_NAME);
    }
}
