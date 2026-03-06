// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `inotify_init(2)`, `inotify_init1(2)`, `inotify_add_watch(2)`, and
//! `inotify_rm_watch(2)` syscall handlers.
//!
//! Filesystem event monitoring.
//!
//! # Key behaviours
//!
//! - An inotify instance monitors filesystem paths for events.
//! - `inotify_add_watch` returns a watch descriptor (wd >= 1).
//! - Multiple watches on the same path consolidate to the same wd.
//! - Events are queued; `read(2)` returns `InotifyEvent` records.
//! - `IN_IGNORED` is generated when a watch is removed.
//! - Maximum watches per instance: `INOTIFY_MAX_WATCHES`.
//!
//! # References
//!
//! - Linux man pages: `inotify_init(2)`, `inotify_add_watch(2)`,
//!   `inotify_rm_watch(2)`, `inotify(7)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Non-blocking I/O.
pub const IN_NONBLOCK: u32 = 0x0000_0800;
/// Close-on-exec.
pub const IN_CLOEXEC: u32 = 0x0002_0000;

// ---------------------------------------------------------------------------
// Event mask constants
// ---------------------------------------------------------------------------

/// File accessed.
pub const IN_ACCESS: u32 = 0x0000_0001;
/// File modified.
pub const IN_MODIFY: u32 = 0x0000_0002;
/// Metadata changed.
pub const IN_ATTRIB: u32 = 0x0000_0004;
/// Written to and closed.
pub const IN_CLOSE_WRITE: u32 = 0x0000_0008;
/// Not written and closed.
pub const IN_CLOSE_NOWRITE: u32 = 0x0000_0010;
/// File opened.
pub const IN_OPEN: u32 = 0x0000_0020;
/// File moved from watched dir.
pub const IN_MOVED_FROM: u32 = 0x0000_0040;
/// File moved to watched dir.
pub const IN_MOVED_TO: u32 = 0x0000_0080;
/// File created in watched dir.
pub const IN_CREATE: u32 = 0x0000_0100;
/// File deleted from watched dir.
pub const IN_DELETE: u32 = 0x0000_0200;
/// Watched file deleted.
pub const IN_DELETE_SELF: u32 = 0x0000_0400;
/// Watched file moved.
pub const IN_MOVE_SELF: u32 = 0x0000_0800;

/// Watch removed (kernel-generated).
pub const IN_IGNORED: u32 = 0x0000_8000;
/// Subject is a directory.
pub const IN_ISDIR: u32 = 0x0100_0000;
/// Event queue overflowed.
pub const IN_Q_OVERFLOW: u32 = 0x0000_4000;

/// Watch only once (remove after first event).
pub const IN_ONESHOT: u32 = 0x8000_0000;
/// Watch does not follow symlinks.
pub const IN_DONT_FOLLOW: u32 = 0x0200_0000;

/// All standard event bits.
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

/// Maximum watches per inotify instance.
pub const INOTIFY_MAX_WATCHES: usize = 256;
/// Maximum queued events per instance.
pub const INOTIFY_MAX_QUEUE: usize = 512;

// ---------------------------------------------------------------------------
// Path storage (fixed-size, no alloc)
// ---------------------------------------------------------------------------

/// Maximum path length stored per watch.
const WATCH_PATH_MAX: usize = 128;

/// Fixed-size path buffer.
#[derive(Clone, Copy)]
struct PathBuf {
    data: [u8; WATCH_PATH_MAX],
    len: usize,
}

impl PathBuf {
    fn from_bytes(b: &[u8]) -> Self {
        let len = b.len().min(WATCH_PATH_MAX);
        let mut data = [0u8; WATCH_PATH_MAX];
        data[..len].copy_from_slice(&b[..len]);
        Self { data, len }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

impl PartialEq for PathBuf {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

// ---------------------------------------------------------------------------
// Watch entry
// ---------------------------------------------------------------------------

struct WatchEntry {
    wd: i32,
    path: PathBuf,
    mask: u32,
    /// `IN_ONESHOT`: remove after first delivery.
    oneshot: bool,
}

// ---------------------------------------------------------------------------
// InotifyEvent
// ---------------------------------------------------------------------------

/// Variable-length inotify event as read from the fd.
///
/// The `name` field (not included here) follows in the actual read buffer;
/// `name_len` indicates its length including the NUL terminator.
#[derive(Debug, Clone, Copy, Default)]
pub struct InotifyEvent {
    /// Watch descriptor.
    pub wd: i32,
    /// Event mask.
    pub mask: u32,
    /// Cookie (links IN_MOVED_FROM and IN_MOVED_TO).
    pub cookie: u32,
    /// Length of name field (0 if absent).
    pub name_len: u32,
}

// ---------------------------------------------------------------------------
// Inotify instance
// ---------------------------------------------------------------------------

/// Kernel-side inotify instance.
pub struct InotifyInstance {
    /// Watch list.
    watches: [Option<WatchEntry>; INOTIFY_MAX_WATCHES],
    /// Watch count.
    watch_count: usize,
    /// Next watch descriptor to assign.
    next_wd: i32,
    /// Event queue.
    queue: [Option<InotifyEvent>; INOTIFY_MAX_QUEUE],
    /// Write pointer.
    q_head: usize,
    /// Read pointer.
    q_tail: usize,
    /// Number of queued events.
    q_len: usize,
    /// Non-blocking flag.
    pub nonblock: bool,
}

impl InotifyInstance {
    /// Create a new inotify instance.
    pub fn new(flags: u32) -> Self {
        Self {
            watches: [const { None }; INOTIFY_MAX_WATCHES],
            watch_count: 0,
            next_wd: 1,
            queue: [const { None }; INOTIFY_MAX_QUEUE],
            q_head: 0,
            q_tail: 0,
            q_len: 0,
            nonblock: flags & IN_NONBLOCK != 0,
        }
    }

    fn find_by_path(&self, path: &[u8]) -> Option<usize> {
        let pb = PathBuf::from_bytes(path);
        self.watches[..self.watch_count]
            .iter()
            .position(|e| e.as_ref().map_or(false, |w| w.path == pb))
    }

    fn find_by_wd(&self, wd: i32) -> Option<usize> {
        self.watches[..self.watch_count]
            .iter()
            .position(|e| e.as_ref().map_or(false, |w| w.wd == wd))
    }

    fn enqueue(&mut self, event: InotifyEvent) {
        if self.q_len >= INOTIFY_MAX_QUEUE {
            // Overflow: enqueue IN_Q_OVERFLOW at tail position if possible.
            return;
        }
        self.queue[self.q_head] = Some(event);
        self.q_head = (self.q_head + 1) % INOTIFY_MAX_QUEUE;
        self.q_len += 1;
    }

    fn dequeue(&mut self) -> Option<InotifyEvent> {
        if self.q_len == 0 {
            return None;
        }
        let ev = self.queue[self.q_tail].take();
        self.q_tail = (self.q_tail + 1) % INOTIFY_MAX_QUEUE;
        self.q_len -= 1;
        ev
    }
}

// ---------------------------------------------------------------------------
// Core handlers
// ---------------------------------------------------------------------------

/// Handler for `inotify_init(2)` / `inotify_init1(2)`.
///
/// # Errors
///
/// | `Error`           | Condition              |
/// |-------------------|------------------------|
/// | `InvalidArgument` | Unknown flags          |
pub fn do_inotify_init(flags: u32) -> Result<InotifyInstance> {
    let known = IN_NONBLOCK | IN_CLOEXEC;
    if flags & !known != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(InotifyInstance::new(flags))
}

/// Handler for `inotify_add_watch(2)`.
///
/// Adds or updates a watch for `path`.  Returns the watch descriptor.
///
/// # Errors
///
/// | `Error`           | Condition                                   |
/// |-------------------|---------------------------------------------|
/// | `InvalidArgument` | Empty path or zero/invalid mask             |
/// | `OutOfMemory`     | Watch limit reached                         |
pub fn do_inotify_add_watch(inotify: &mut InotifyInstance, path: &[u8], mask: u32) -> Result<i32> {
    if path.is_empty() || mask & IN_ALL_EVENTS == 0 {
        return Err(Error::InvalidArgument);
    }
    // If path already watched, update mask and return existing wd.
    if let Some(idx) = inotify.find_by_path(path) {
        if let Some(ref mut entry) = inotify.watches[idx] {
            entry.mask = mask;
            return Ok(entry.wd);
        }
    }
    if inotify.watch_count >= INOTIFY_MAX_WATCHES {
        return Err(Error::OutOfMemory);
    }
    let wd = inotify.next_wd;
    inotify.next_wd += 1;
    let slot = inotify.watch_count;
    inotify.watches[slot] = Some(WatchEntry {
        wd,
        path: PathBuf::from_bytes(path),
        mask,
        oneshot: mask & IN_ONESHOT != 0,
    });
    inotify.watch_count += 1;
    Ok(wd)
}

/// Handler for `inotify_rm_watch(2)`.
///
/// Removes a watch; generates an `IN_IGNORED` event.
///
/// # Errors
///
/// | `Error`           | Condition                  |
/// |-------------------|----------------------------|
/// | `InvalidArgument` | `wd` not found             |
pub fn do_inotify_rm_watch(inotify: &mut InotifyInstance, wd: i32) -> Result<()> {
    let idx = inotify.find_by_wd(wd).ok_or(Error::InvalidArgument)?;
    inotify.watches[idx] = None;
    // Compact: swap with last.
    let last = inotify.watch_count - 1;
    inotify.watches.swap(idx, last);
    inotify.watch_count -= 1;
    // Generate IN_IGNORED event.
    inotify.enqueue(InotifyEvent {
        wd,
        mask: IN_IGNORED,
        cookie: 0,
        name_len: 0,
    });
    Ok(())
}

/// Simulate a filesystem event on `path` with `event_mask`.
///
/// Delivers the event to all matching watches.
pub fn inotify_deliver_event(
    inotify: &mut InotifyInstance,
    path: &[u8],
    event_mask: u32,
    cookie: u32,
    name_len: u32,
) {
    // Collect matching watches before any mutation.
    let mut matches: [Option<(i32, bool)>; INOTIFY_MAX_WATCHES] =
        [const { None }; INOTIFY_MAX_WATCHES];
    let mut n_matches = 0usize;

    for i in 0..inotify.watch_count {
        if let Some(ref entry) = inotify.watches[i] {
            if entry.path.as_bytes() == path && entry.mask & event_mask != 0 {
                if n_matches < INOTIFY_MAX_WATCHES {
                    matches[n_matches] = Some((entry.wd, entry.oneshot));
                    n_matches += 1;
                }
            }
        }
    }

    let mut oneshot_wds: [Option<i32>; 8] = [None; 8];
    let mut n_oneshot = 0usize;

    for m in matches[..n_matches].iter() {
        if let Some((wd, oneshot)) = *m {
            let ev = InotifyEvent {
                wd,
                mask: event_mask,
                cookie,
                name_len,
            };
            inotify.enqueue(ev);
            if oneshot && n_oneshot < 8 {
                oneshot_wds[n_oneshot] = Some(wd);
                n_oneshot += 1;
            }
        }
    }

    // Remove oneshot watches.
    for wd_opt in oneshot_wds[..n_oneshot].iter() {
        if let Some(wd) = wd_opt {
            let _ = do_inotify_rm_watch(inotify, *wd);
        }
    }
}

/// Handler for inotify `read(2)`.
///
/// Reads up to `out.len()` pending events.
///
/// # Errors
///
/// | `Error`      | Condition                                     |
/// |--------------|-----------------------------------------------|
/// | `WouldBlock` | No events pending                             |
/// | `InvalidArgument` | `out` is empty                           |
pub fn do_inotify_read(inotify: &mut InotifyInstance, out: &mut [InotifyEvent]) -> Result<usize> {
    if out.is_empty() {
        return Err(Error::InvalidArgument);
    }
    if inotify.q_len == 0 {
        return Err(Error::WouldBlock);
    }
    let mut n = 0;
    while n < out.len() {
        match inotify.dequeue() {
            Some(ev) => {
                out[n] = ev;
                n += 1;
            }
            None => break,
        }
    }
    Ok(n)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_ok() {
        let inotify = do_inotify_init(0).unwrap();
        assert_eq!(inotify.watch_count, 0);
        assert!(!inotify.nonblock);
    }

    #[test]
    fn init_unknown_flags_fails() {
        assert_eq!(do_inotify_init(0xF000_0000), Err(Error::InvalidArgument));
    }

    #[test]
    fn add_watch_ok() {
        let mut inotify = do_inotify_init(0).unwrap();
        let wd = do_inotify_add_watch(&mut inotify, b"/tmp", IN_CREATE | IN_DELETE).unwrap();
        assert_eq!(wd, 1);
        assert_eq!(inotify.watch_count, 1);
    }

    #[test]
    fn add_watch_same_path_updates() {
        let mut inotify = do_inotify_init(0).unwrap();
        let wd1 = do_inotify_add_watch(&mut inotify, b"/tmp", IN_CREATE).unwrap();
        let wd2 = do_inotify_add_watch(&mut inotify, b"/tmp", IN_MODIFY).unwrap();
        assert_eq!(wd1, wd2);
        assert_eq!(inotify.watch_count, 1);
    }

    #[test]
    fn rm_watch_generates_ignored() {
        let mut inotify = do_inotify_init(0).unwrap();
        let wd = do_inotify_add_watch(&mut inotify, b"/tmp", IN_CREATE).unwrap();
        do_inotify_rm_watch(&mut inotify, wd).unwrap();
        let mut out = [InotifyEvent::default(); 4];
        let n = do_inotify_read(&mut inotify, &mut out).unwrap();
        assert_eq!(n, 1);
        assert_eq!(out[0].mask, IN_IGNORED);
    }

    #[test]
    fn deliver_event_and_read() {
        let mut inotify = do_inotify_init(0).unwrap();
        do_inotify_add_watch(&mut inotify, b"/home", IN_CREATE).unwrap();
        inotify_deliver_event(&mut inotify, b"/home", IN_CREATE, 0, 0);
        let mut out = [InotifyEvent::default(); 4];
        let n = do_inotify_read(&mut inotify, &mut out).unwrap();
        assert_eq!(n, 1);
        assert_eq!(out[0].mask, IN_CREATE);
    }

    #[test]
    fn read_no_events_wouldblock() {
        let mut inotify = do_inotify_init(IN_NONBLOCK).unwrap();
        let mut out = [InotifyEvent::default(); 4];
        assert_eq!(
            do_inotify_read(&mut inotify, &mut out),
            Err(Error::WouldBlock)
        );
    }
}
