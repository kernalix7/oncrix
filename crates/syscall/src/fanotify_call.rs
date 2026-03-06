// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `fanotify_init(2)`, `fanotify_mark(2)` — file access notification.
//!
//! fanotify is a Linux subsystem for filesystem event monitoring with
//! optional permission decisions.  Unlike inotify, fanotify can intercept
//! filesystem operations and grant or deny access, making it suitable for
//! antivirus scanners, hierarchical storage management, and audit daemons.
//!
//! # Key differences from inotify
//!
//! - fanotify can monitor entire mount points or filesystem trees, not just
//!   individual files and directories.
//! - Events include a file descriptor to the affected file.
//! - Permission events (`FAN_OPEN_PERM`, `FAN_ACCESS_PERM`) allow the
//!   listener to allow or deny the operation.
//! - Requires `CAP_SYS_ADMIN` (or `CAP_DAC_READ_SEARCH` for some modes).
//!
//! # Syscalls
//!
//! | Syscall | Handler | Description |
//! |---------|---------|-------------|
//! | `fanotify_init` | [`sys_fanotify_init`] | Create a fanotify group |
//! | `fanotify_mark` | [`sys_fanotify_mark`] | Add/remove/flush marks |
//!
//! # POSIX
//!
//! fanotify is a Linux-specific interface; no POSIX equivalent.
//!
//! # References
//!
//! - Linux: `fs/notify/fanotify/fanotify.c`, `fanotify_user.c`
//! - man: `fanotify(7)`, `fanotify_init(2)`, `fanotify_mark(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// fanotify event types (FAN_*)
// ---------------------------------------------------------------------------

/// File was accessed (read).
pub const FAN_ACCESS: u64 = 0x0000_0001;

/// File was modified.
pub const FAN_MODIFY: u64 = 0x0000_0002;

/// Metadata changed.
pub const FAN_ATTRIB: u64 = 0x0000_0004;

/// Writable file closed.
pub const FAN_CLOSE_WRITE: u64 = 0x0000_0008;

/// Read-only file closed.
pub const FAN_CLOSE_NOWRITE: u64 = 0x0000_0010;

/// File opened.
pub const FAN_OPEN: u64 = 0x0000_0020;

/// File moved from location.
pub const FAN_MOVED_FROM: u64 = 0x0000_0040;

/// File moved to location.
pub const FAN_MOVED_TO: u64 = 0x0000_0080;

/// Directory entry created.
pub const FAN_CREATE: u64 = 0x0000_0100;

/// Directory entry deleted.
pub const FAN_DELETE: u64 = 0x0000_0200;

/// Watched file deleted.
pub const FAN_DELETE_SELF: u64 = 0x0000_0400;

/// Watched file moved.
pub const FAN_MOVE_SELF: u64 = 0x0000_0800;

/// File opened for execution.
pub const FAN_OPEN_EXEC: u64 = 0x0000_1000;

/// Permission check on file access.
pub const FAN_ACCESS_PERM: u64 = 0x0002_0000;

/// Permission check on file open.
pub const FAN_OPEN_PERM: u64 = 0x0001_0000;

/// Permission check on file open for execution.
pub const FAN_OPEN_EXEC_PERM: u64 = 0x0004_0000;

/// Event was generated on a directory.
pub const FAN_ONDIR: u64 = 0x4000_0000;

/// Event queue is full.
pub const FAN_Q_OVERFLOW: u64 = 0x0000_4000;

/// Filesystem error event.
pub const FAN_FS_ERROR: u64 = 0x0000_8000;

/// Convenience: all close events.
pub const FAN_CLOSE: u64 = FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE;

/// Convenience: all move events.
pub const FAN_MOVE: u64 = FAN_MOVED_FROM | FAN_MOVED_TO;

/// All standard events (non-permission).
pub const FAN_ALL_EVENTS: u64 = FAN_ACCESS
    | FAN_MODIFY
    | FAN_ATTRIB
    | FAN_CLOSE_WRITE
    | FAN_CLOSE_NOWRITE
    | FAN_OPEN
    | FAN_MOVED_FROM
    | FAN_MOVED_TO
    | FAN_CREATE
    | FAN_DELETE
    | FAN_DELETE_SELF
    | FAN_MOVE_SELF
    | FAN_OPEN_EXEC;

/// Permission events.
pub const FAN_ALL_PERM_EVENTS: u64 = FAN_ACCESS_PERM | FAN_OPEN_PERM | FAN_OPEN_EXEC_PERM;

/// All valid event bits.
pub const FAN_ALL_VALID: u64 = FAN_ALL_EVENTS | FAN_ALL_PERM_EVENTS | FAN_ONDIR;

// ---------------------------------------------------------------------------
// fanotify_init flags
// ---------------------------------------------------------------------------

/// Report only events for the calling process's filesystem namespace.
pub const FAN_CLASS_NOTIF: u32 = 0x0000_0000;

/// Receive both notification and permission events (requires higher priv).
pub const FAN_CLASS_CONTENT: u32 = 0x0000_0004;

/// Receive pre-content access events.
pub const FAN_CLASS_PRE_CONTENT: u32 = 0x0000_0008;

/// Close-on-exec flag for the fanotify fd.
pub const FAN_CLOEXEC: u32 = 0x0000_0001;

/// Non-blocking mode for the fanotify fd.
pub const FAN_NONBLOCK: u32 = 0x0000_0002;

/// Generate events with file FDs (required for most uses).
pub const FAN_REPORT_FID: u32 = 0x0000_0200;

/// Include directory FID in events.
pub const FAN_REPORT_DIR_FID: u32 = 0x0000_0400;

/// Include entry name in events.
pub const FAN_REPORT_NAME: u32 = 0x0000_0800;

/// Include target entry name in events.
pub const FAN_REPORT_TARGET_FID: u32 = 0x0000_1000;

/// Unlimited event queue size.
pub const FAN_UNLIMITED_QUEUE: u32 = 0x0001_0000;

/// Unlimited marks.
pub const FAN_UNLIMITED_MARKS: u32 = 0x0002_0000;

/// Valid `fanotify_init` flag bits.
const FAN_INIT_VALID: u32 = FAN_CLASS_CONTENT
    | FAN_CLASS_PRE_CONTENT
    | FAN_CLOEXEC
    | FAN_NONBLOCK
    | FAN_REPORT_FID
    | FAN_REPORT_DIR_FID
    | FAN_REPORT_NAME
    | FAN_REPORT_TARGET_FID
    | FAN_UNLIMITED_QUEUE
    | FAN_UNLIMITED_MARKS;

// ---------------------------------------------------------------------------
// fanotify_mark flags
// ---------------------------------------------------------------------------

/// Add a mark.
pub const FAN_MARK_ADD: u32 = 0x0000_0001;

/// Remove a mark.
pub const FAN_MARK_REMOVE: u32 = 0x0000_0002;

/// Mark an entire mount point.
pub const FAN_MARK_MOUNT: u32 = 0x0000_0010;

/// Mark a filesystem (all mounts).
pub const FAN_MARK_FILESYSTEM: u32 = 0x0000_0100;

/// Flush all inode marks.
pub const FAN_MARK_FLUSH: u32 = 0x0000_0080;

/// Do not follow symbolic links.
pub const FAN_MARK_DONT_FOLLOW: u32 = 0x0000_0004;

/// Mark the directory, not the contents.
pub const FAN_MARK_ONLYDIR: u32 = 0x0000_0008;

/// Ignore events matching `mask`.
pub const FAN_MARK_IGNORED_MASK: u32 = 0x0000_0020;

/// Persist the ignored mask.
pub const FAN_MARK_IGNORED_SURV_MODIFY: u32 = 0x0000_0040;

/// Valid mark flag bits (excluding mutually exclusive action bits).
const FAN_MARK_ACTION_MASK: u32 = FAN_MARK_ADD | FAN_MARK_REMOVE | FAN_MARK_FLUSH;

// ---------------------------------------------------------------------------
// Permission response
// ---------------------------------------------------------------------------

/// Permission response codes for `fanotify_response`.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FanotifyResponse {
    /// Allow the filesystem operation to proceed.
    Allow = 0x01,
    /// Deny the filesystem operation (returns `EPERM` to caller).
    Deny = 0x02,
}

// ---------------------------------------------------------------------------
// fanotify event metadata
// ---------------------------------------------------------------------------

/// Standard fanotify event metadata header.
///
/// Corresponds to `struct fanotify_event_metadata` in the Linux UAPI.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FanotifyEventMetadata {
    /// Total length of this event record (bytes).
    pub event_len: u32,
    /// Version of the event structure (always `FANOTIFY_METADATA_VERSION`).
    pub vers: u8,
    /// Reserved (must be 0).
    pub reserved: u8,
    /// Metadata length (size of this struct without extra info).
    pub metadata_len: u16,
    /// Event type mask.
    pub mask: u64,
    /// File descriptor of the affected file (-1 if not applicable).
    pub fd: i32,
    /// PID of the process that generated the event.
    pub pid: i32,
}

/// fanotify metadata structure version.
pub const FANOTIFY_METADATA_VERSION: u8 = 3;

impl FanotifyEventMetadata {
    /// Create a new event metadata record.
    pub const fn new(mask: u64, fd: i32, pid: i32) -> Self {
        Self {
            event_len: core::mem::size_of::<Self>() as u32,
            vers: FANOTIFY_METADATA_VERSION,
            reserved: 0,
            metadata_len: core::mem::size_of::<Self>() as u16,
            mask,
            fd,
            pid,
        }
    }

    /// Returns `true` if this is a permission event.
    pub const fn is_perm(&self) -> bool {
        self.mask & FAN_ALL_PERM_EVENTS != 0
    }

    /// Returns `true` if this event is for a directory.
    pub const fn is_dir(&self) -> bool {
        self.mask & FAN_ONDIR != 0
    }
}

// ---------------------------------------------------------------------------
// Mark entry
// ---------------------------------------------------------------------------

/// Object type for a fanotify mark.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkType {
    /// Mark is on a specific inode.
    Inode = 0,
    /// Mark is on a mount point.
    Mount = 1,
    /// Mark is on an entire filesystem.
    Filesystem = 2,
}

/// Unique identifier for a marked object.
///
/// Encodes both the type and ID (inode number, mount ID, or FS ID).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MarkTarget {
    /// Type of the marked object.
    pub kind: MarkType,
    /// Object identifier (inode number, mount ID, or filesystem ID).
    pub id: u64,
}

impl MarkTarget {
    /// Create an inode mark target.
    pub const fn inode(ino: u64) -> Self {
        Self {
            kind: MarkType::Inode,
            id: ino,
        }
    }

    /// Create a mount mark target.
    pub const fn mount(mount_id: u64) -> Self {
        Self {
            kind: MarkType::Mount,
            id: mount_id,
        }
    }

    /// Create a filesystem mark target.
    pub const fn filesystem(fsid: u64) -> Self {
        Self {
            kind: MarkType::Filesystem,
            id: fsid,
        }
    }
}

/// A single fanotify mark.
#[derive(Debug, Clone, Copy)]
pub struct MarkEntry {
    /// The marked object.
    pub target: MarkTarget,
    /// Events to notify on.
    pub mask: u64,
    /// Events to ignore.
    pub ignored_mask: u64,
    /// Whether the ignored mask persists across modifications.
    pub ignored_surv_modify: bool,
    /// Do not follow symlinks when resolving this mark.
    pub dont_follow: bool,
    /// Only trigger for directory events.
    pub onlydir: bool,
    /// Total events delivered for this mark.
    pub events_delivered: u64,
}

impl MarkEntry {
    /// Create a new mark entry.
    pub const fn new(target: MarkTarget, mask: u64, flags: u32) -> Self {
        Self {
            target,
            mask,
            ignored_mask: 0,
            ignored_surv_modify: (flags & FAN_MARK_IGNORED_SURV_MODIFY) != 0,
            dont_follow: (flags & FAN_MARK_DONT_FOLLOW) != 0,
            onlydir: (flags & FAN_MARK_ONLYDIR) != 0,
            events_delivered: 0,
        }
    }

    /// Returns `true` if `event_mask` should be reported.
    pub fn should_notify(&self, event_mask: u64) -> bool {
        let active = self.mask & !self.ignored_mask;
        active & event_mask != 0
    }
}

// ---------------------------------------------------------------------------
// fanotify group (instance)
// ---------------------------------------------------------------------------

/// Maximum marks per fanotify group.
const MAX_MARKS: usize = 8_192;

/// Maximum pending events per fanotify group.
const FAN_QUEUE_DEPTH: usize = 16_384;

/// Event queue for a fanotify group.
pub struct FanEventQueue {
    buf: [FanotifyEventMetadata; FAN_QUEUE_DEPTH],
    head: usize,
    tail: usize,
    count: usize,
    overflowed: bool,
}

impl FanEventQueue {
    /// Create an empty queue.
    pub const fn new() -> Self {
        Self {
            buf: [FanotifyEventMetadata {
                event_len: 0,
                vers: 0,
                reserved: 0,
                metadata_len: 0,
                mask: 0,
                fd: -1,
                pid: 0,
            }; FAN_QUEUE_DEPTH],
            head: 0,
            tail: 0,
            count: 0,
            overflowed: false,
        }
    }

    /// Enqueue an event.
    pub fn enqueue(&mut self, event: FanotifyEventMetadata) {
        if self.count >= FAN_QUEUE_DEPTH {
            self.overflowed = true;
            return;
        }
        self.buf[self.head] = event;
        self.head = (self.head + 1) % FAN_QUEUE_DEPTH;
        self.count += 1;
    }

    /// Dequeue the next event.
    pub fn dequeue(&mut self) -> Option<FanotifyEventMetadata> {
        if self.count == 0 {
            if self.overflowed {
                self.overflowed = false;
                return Some(FanotifyEventMetadata::new(FAN_Q_OVERFLOW, -1, 0));
            }
            return None;
        }
        let ev = self.buf[self.tail];
        self.tail = (self.tail + 1) % FAN_QUEUE_DEPTH;
        self.count -= 1;
        Some(ev)
    }

    /// Number of pending events.
    pub const fn pending(&self) -> usize {
        self.count
    }

    /// Returns `true` if there are events ready.
    pub fn has_events(&self) -> bool {
        self.count > 0 || self.overflowed
    }
}

impl Default for FanEventQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// A fanotify group (instance created by `fanotify_init`).
pub struct FanotifyGroup {
    /// File descriptor for this group.
    pub fd: i32,
    /// Flags from `fanotify_init`.
    pub flags: u32,
    /// Notification class (FAN_CLASS_*).
    pub class: u32,
    /// Active marks.
    marks: [Option<MarkEntry>; MAX_MARKS],
    /// Number of active marks.
    mark_count: usize,
    /// Pending event queue.
    pub queue: FanEventQueue,
}

impl FanotifyGroup {
    /// Create a new fanotify group.
    pub const fn new(fd: i32, flags: u32) -> Self {
        let class = flags & (FAN_CLASS_CONTENT | FAN_CLASS_PRE_CONTENT);
        Self {
            fd,
            flags,
            class,
            marks: [const { None }; MAX_MARKS],
            mark_count: 0,
            queue: FanEventQueue::new(),
        }
    }

    fn find_mark(&self, target: &MarkTarget) -> Option<usize> {
        self.marks
            .iter()
            .position(|m| m.map_or(false, |m| m.target == *target))
    }

    fn free_slot(&self) -> Option<usize> {
        self.marks.iter().position(|m| m.is_none())
    }

    /// Add or update a mark.
    pub fn add_mark(&mut self, target: MarkTarget, mask: u64, flags: u32) -> Result<()> {
        if let Some(idx) = self.find_mark(&target) {
            let entry = self.marks[idx].as_mut().unwrap();
            if (flags & FAN_MARK_IGNORED_MASK) != 0 {
                entry.ignored_mask |= mask;
            } else {
                entry.mask |= mask;
            }
            return Ok(());
        }
        if self.mark_count >= MAX_MARKS {
            return Err(Error::OutOfMemory);
        }
        let slot = self.free_slot().ok_or(Error::OutOfMemory)?;
        self.marks[slot] = Some(MarkEntry::new(target, mask, flags));
        self.mark_count += 1;
        Ok(())
    }

    /// Remove a mark matching `target` and `mask`.
    pub fn remove_mark(&mut self, target: &MarkTarget, mask: u64) -> Result<()> {
        let idx = self.find_mark(target).ok_or(Error::NotFound)?;
        let entry = self.marks[idx].as_mut().unwrap();
        entry.mask &= !mask;
        if entry.mask == 0 {
            self.marks[idx] = None;
            self.mark_count = self.mark_count.saturating_sub(1);
        }
        Ok(())
    }

    /// Flush all marks of the given type.
    pub fn flush_marks(&mut self, mark_type: Option<MarkType>) {
        for slot in &mut self.marks {
            if let Some(entry) = slot {
                let remove = match mark_type {
                    None => true,
                    Some(t) => entry.target.kind == t,
                };
                if remove {
                    *slot = None;
                    self.mark_count = self.mark_count.saturating_sub(1);
                }
            }
        }
    }

    /// Deliver an event if any mark matches.
    pub fn deliver_event(&mut self, target: &MarkTarget, event_mask: u64, pid: i32) {
        let idx = match self.find_mark(target) {
            Some(i) => i,
            None => return,
        };
        let should = {
            let entry = self.marks[idx].as_mut().unwrap();
            let s = entry.should_notify(event_mask);
            if s {
                entry.events_delivered = entry.events_delivered.saturating_add(1);
            }
            s
        };
        if should {
            self.queue
                .enqueue(FanotifyEventMetadata::new(event_mask, -1, pid));
        }
    }

    /// Returns `true` if close-on-exec is set.
    pub const fn cloexec(&self) -> bool {
        (self.flags & FAN_CLOEXEC) != 0
    }

    /// Returns `true` if non-blocking mode is set.
    pub const fn nonblocking(&self) -> bool {
        (self.flags & FAN_NONBLOCK) != 0
    }

    /// Returns `true` if this group can issue permission decisions.
    pub const fn can_perm(&self) -> bool {
        self.class == FAN_CLASS_CONTENT || self.class == FAN_CLASS_PRE_CONTENT
    }

    /// Number of active marks.
    pub const fn mark_count(&self) -> usize {
        self.mark_count
    }
}

// ---------------------------------------------------------------------------
// fanotify group registry
// ---------------------------------------------------------------------------

/// Maximum number of fanotify groups in the system.
const MAX_FAN_GROUPS: usize = 128;

/// System-wide fanotify group registry.
pub struct FanotifyRegistry {
    groups: [Option<FanotifyGroup>; MAX_FAN_GROUPS],
    next_fd: i32,
    count: usize,
}

impl FanotifyRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            groups: [const { None }; MAX_FAN_GROUPS],
            next_fd: 1,
            count: 0,
        }
    }

    fn free_slot(&self) -> Option<usize> {
        self.groups.iter().position(|g| g.is_none())
    }

    fn find_by_fd(&self, fd: i32) -> Option<usize> {
        self.groups
            .iter()
            .position(|g| g.as_ref().map_or(false, |g| g.fd == fd))
    }

    /// Create a new fanotify group.
    pub fn create(&mut self, flags: u32) -> Result<i32> {
        if self.count >= MAX_FAN_GROUPS {
            return Err(Error::OutOfMemory);
        }
        let slot = self.free_slot().ok_or(Error::OutOfMemory)?;
        let fd = self.next_fd;
        self.next_fd = self.next_fd.wrapping_add(1).max(1);
        self.groups[slot] = Some(FanotifyGroup::new(fd, flags));
        self.count += 1;
        Ok(fd)
    }

    /// Get a reference to a group by fd.
    pub fn get(&self, fd: i32) -> Option<&FanotifyGroup> {
        self.groups.iter().flatten().find(|g| g.fd == fd)
    }

    /// Get a mutable reference to a group by fd.
    pub fn get_mut(&mut self, fd: i32) -> Option<&mut FanotifyGroup> {
        self.groups.iter_mut().flatten().find(|g| g.fd == fd)
    }

    /// Close and remove a group.
    pub fn close(&mut self, fd: i32) -> Result<()> {
        let idx = self.find_by_fd(fd).ok_or(Error::NotFound)?;
        self.groups[idx] = None;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }
}

impl Default for FanotifyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Syscall handlers
// ---------------------------------------------------------------------------

/// `fanotify_init(2)` — create a fanotify group.
///
/// # Arguments
///
/// - `registry` — Mutable fanotify registry.
/// - `flags` — `FAN_CLOEXEC`, `FAN_NONBLOCK`, class flags, report flags.
/// - `event_f_flags` — Flags for file descriptors returned in events
///   (e.g. `O_RDONLY | O_LARGEFILE`).  Validated but not stored in stub.
/// - `cap_sys_admin` — Caller holds `CAP_SYS_ADMIN`.
///
/// # Errors
///
/// - [`Error::PermissionDenied`] — Requires `CAP_SYS_ADMIN`.
/// - [`Error::InvalidArgument`] — Invalid flag bits.
/// - [`Error::OutOfMemory`] — Registry full.
pub fn sys_fanotify_init(
    registry: &mut FanotifyRegistry,
    flags: u32,
    event_f_flags: u32,
    cap_sys_admin: bool,
) -> Result<i32> {
    if !cap_sys_admin {
        return Err(Error::PermissionDenied);
    }
    if flags & !FAN_INIT_VALID != 0 {
        return Err(Error::InvalidArgument);
    }
    // event_f_flags must be O_RDONLY (0) or O_RDWR; reject write-only.
    if event_f_flags & 0x1 != 0 && event_f_flags & 0x2 == 0 {
        return Err(Error::InvalidArgument);
    }
    registry.create(flags)
}

/// `fanotify_mark(2)` — add, remove, or flush marks on a fanotify group.
///
/// # Arguments
///
/// - `registry` — Mutable fanotify registry.
/// - `fd` — fanotify group fd.
/// - `flags` — `FAN_MARK_ADD`, `FAN_MARK_REMOVE`, `FAN_MARK_FLUSH`, etc.
/// - `mask` — Event types to mark.
/// - `target` — Object to mark (inode, mount, or filesystem).
///
/// # Errors
///
/// - [`Error::NotFound`] — `fd` not found, or removing a non-existent mark.
/// - [`Error::InvalidArgument`] — Invalid flags or mask.
/// - [`Error::OutOfMemory`] — Mark table full.
pub fn sys_fanotify_mark(
    registry: &mut FanotifyRegistry,
    fd: i32,
    flags: u32,
    mask: u64,
    target: MarkTarget,
) -> Result<()> {
    let action = flags & FAN_MARK_ACTION_MASK;
    // Exactly one action must be specified.
    if action.count_ones() != 1 {
        return Err(Error::InvalidArgument);
    }
    if mask & !FAN_ALL_VALID != 0 && action != FAN_MARK_FLUSH {
        return Err(Error::InvalidArgument);
    }

    let group = registry.get_mut(fd).ok_or(Error::NotFound)?;

    match action {
        FAN_MARK_ADD => group.add_mark(target, mask, flags),
        FAN_MARK_REMOVE => group.remove_mark(&target, mask),
        FAN_MARK_FLUSH => {
            let mark_type = if (flags & FAN_MARK_MOUNT) != 0 {
                Some(MarkType::Mount)
            } else if (flags & FAN_MARK_FILESYSTEM) != 0 {
                Some(MarkType::Filesystem)
            } else {
                None
            };
            group.flush_marks(mark_type);
            Ok(())
        }
        _ => Err(Error::InvalidArgument),
    }
}

/// Read the next pending fanotify event.
///
/// # Arguments
///
/// - `registry` — Mutable fanotify registry.
/// - `fd` — fanotify group fd.
///
/// # Errors
///
/// - [`Error::NotFound`] — `fd` not found.
/// - [`Error::WouldBlock`] — Non-blocking fd with no events.
pub fn sys_fanotify_read(
    registry: &mut FanotifyRegistry,
    fd: i32,
) -> Result<FanotifyEventMetadata> {
    let group = registry.get_mut(fd).ok_or(Error::NotFound)?;
    if let Some(ev) = group.queue.dequeue() {
        return Ok(ev);
    }
    if group.nonblocking() {
        Err(Error::WouldBlock)
    } else {
        Err(Error::WouldBlock)
    }
}

/// Write a permission response for a pending permission event.
///
/// # Arguments
///
/// - `registry` — Mutable fanotify registry.
/// - `fd` — fanotify group fd.
/// - `response_fd` — File descriptor from the permission event.
/// - `response` — [`FanotifyResponse::Allow`] or [`FanotifyResponse::Deny`].
///
/// # Errors
///
/// - [`Error::NotFound`] — `fd` not found.
/// - [`Error::PermissionDenied`] — Group is not a permission class.
pub fn sys_fanotify_write_response(
    registry: &mut FanotifyRegistry,
    fd: i32,
    _response_fd: i32,
    _response: FanotifyResponse,
) -> Result<()> {
    let group = registry.get(fd).ok_or(Error::NotFound)?;
    if !group.can_perm() {
        return Err(Error::PermissionDenied);
    }
    // In a real implementation this would unblock the waiting process.
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_requires_cap() {
        let mut reg = FanotifyRegistry::new();
        let result = sys_fanotify_init(&mut reg, FAN_CLOEXEC, 0, false);
        assert!(matches!(result, Err(Error::PermissionDenied)));
    }

    #[test]
    fn test_init_ok() {
        let mut reg = FanotifyRegistry::new();
        let fd = sys_fanotify_init(&mut reg, FAN_CLOEXEC | FAN_NONBLOCK, 0, true).unwrap();
        assert!(fd > 0);
        assert_eq!(reg.count, 1);
    }

    #[test]
    fn test_init_invalid_flags() {
        let mut reg = FanotifyRegistry::new();
        let result = sys_fanotify_init(&mut reg, 0xFFFF_FFFF, 0, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_mark_add_inode() {
        let mut reg = FanotifyRegistry::new();
        let fd = sys_fanotify_init(&mut reg, 0, 0, true).unwrap();
        let target = MarkTarget::inode(42);
        sys_fanotify_mark(&mut reg, fd, FAN_MARK_ADD, FAN_CREATE | FAN_DELETE, target).unwrap();
        let group = reg.get(fd).unwrap();
        assert_eq!(group.mark_count(), 1);
    }

    #[test]
    fn test_mark_remove() {
        let mut reg = FanotifyRegistry::new();
        let fd = sys_fanotify_init(&mut reg, 0, 0, true).unwrap();
        let target = MarkTarget::inode(42);
        sys_fanotify_mark(&mut reg, fd, FAN_MARK_ADD, FAN_CREATE | FAN_DELETE, target).unwrap();
        sys_fanotify_mark(
            &mut reg,
            fd,
            FAN_MARK_REMOVE,
            FAN_CREATE | FAN_DELETE,
            target,
        )
        .unwrap();
        let group = reg.get(fd).unwrap();
        assert_eq!(group.mark_count(), 0);
    }

    #[test]
    fn test_event_delivery() {
        let mut reg = FanotifyRegistry::new();
        let fd = sys_fanotify_init(&mut reg, 0, 0, true).unwrap();
        let target = MarkTarget::inode(42);
        sys_fanotify_mark(&mut reg, fd, FAN_MARK_ADD, FAN_CREATE, target).unwrap();
        let group = reg.get_mut(fd).unwrap();
        group.deliver_event(&target, FAN_CREATE, 1000);
        assert!(group.queue.has_events());
        let ev = group.queue.dequeue().unwrap();
        assert_eq!(ev.mask, FAN_CREATE);
        assert_eq!(ev.pid, 1000);
    }

    #[test]
    fn test_flush_marks() {
        let mut reg = FanotifyRegistry::new();
        let fd = sys_fanotify_init(&mut reg, 0, 0, true).unwrap();
        for i in 0..5u64 {
            let target = MarkTarget::inode(i);
            sys_fanotify_mark(&mut reg, fd, FAN_MARK_ADD, FAN_CREATE, target).unwrap();
        }
        assert_eq!(reg.get(fd).unwrap().mark_count(), 5);
        sys_fanotify_mark(&mut reg, fd, FAN_MARK_FLUSH, 0, MarkTarget::inode(0)).unwrap();
        assert_eq!(reg.get(fd).unwrap().mark_count(), 0);
    }

    #[test]
    fn test_mark_mount() {
        let mut reg = FanotifyRegistry::new();
        let fd = sys_fanotify_init(&mut reg, 0, 0, true).unwrap();
        let target = MarkTarget::mount(1);
        sys_fanotify_mark(
            &mut reg,
            fd,
            FAN_MARK_ADD | FAN_MARK_MOUNT,
            FAN_ACCESS,
            target,
        )
        .unwrap();
        assert_eq!(reg.get(fd).unwrap().mark_count(), 1);
    }

    #[test]
    fn test_nonblocking_wouldblock() {
        let mut reg = FanotifyRegistry::new();
        let fd = sys_fanotify_init(&mut reg, FAN_NONBLOCK, 0, true).unwrap();
        let result = sys_fanotify_read(&mut reg, fd);
        assert!(matches!(result, Err(Error::WouldBlock)));
    }
}
