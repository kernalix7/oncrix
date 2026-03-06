// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! dnotify — directory change notification.
//!
//! Implements the legacy dnotify(7) interface:
//! - [`DnotifyMark`] — per-directory notification registration
//!   (dn_mask, fd, owner_pid)
//! - [`dir_notify`] — register via `fcntl(fd, F_NOTIFY, ...)`
//! - [`dnotify_flush`] — remove all notifications for a file descriptor
//! - [`dnotify_signal`] — generate `SIGIO` or `SIGRT*` to the owner
//! - Event mask flags: `DN_ACCESS`, `DN_MODIFY`, `DN_CREATE`, `DN_DELETE`,
//!   `DN_RENAME`, `DN_ATTRIB`
//! - `DN_MULTISHOT` flag: keep monitoring after first event (persistent)
//!
//! # Limitations
//!
//! dnotify is a legacy interface superseded by inotify. It only monitors
//! directories (not individual files) and delivers coarse-grained signals.
//!
//! # References
//! - Linux `fs/notify/dnotify/dnotify.c`
//! - Linux `fcntl(2)` man page — F_NOTIFY

extern crate alloc;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// DN event mask flags
// ---------------------------------------------------------------------------

/// Notify on file access (read) within the directory.
pub const DN_ACCESS: u32 = 0x00000001;
/// Notify on file modification (write) within the directory.
pub const DN_MODIFY: u32 = 0x00000002;
/// Notify on file creation within the directory.
pub const DN_CREATE: u32 = 0x00000004;
/// Notify on file deletion within the directory.
pub const DN_DELETE: u32 = 0x00000008;
/// Notify on file rename within the directory.
pub const DN_RENAME: u32 = 0x00000010;
/// Notify on attribute change (chmod/chown) within the directory.
pub const DN_ATTRIB: u32 = 0x00000020;
/// Keep notification active after first delivery (persistent).
pub const DN_MULTISHOT: u32 = 0x80000000;
/// All events (convenience mask).
pub const DN_ALL: u32 = DN_ACCESS | DN_MODIFY | DN_CREATE | DN_DELETE | DN_RENAME | DN_ATTRIB;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum dnotify marks (one per watched directory per process).
const MAX_DNOTIFY_MARKS: usize = 256;

/// SIGIO signal number.
pub const SIGIO: u32 = 29;
/// Minimum real-time signal.
pub const SIGRTMIN: u32 = 34;
/// Maximum real-time signal.
pub const SIGRTMAX: u32 = 64;

// ---------------------------------------------------------------------------
// DnotifyMark
// ---------------------------------------------------------------------------

/// A dnotify registration for one directory.
#[derive(Debug, Clone)]
pub struct DnotifyMark {
    /// Directory inode number being watched.
    pub dir_ino: u64,
    /// Event mask (`DN_*` flags, possibly OR'd with `DN_MULTISHOT`).
    pub dn_mask: u32,
    /// File descriptor used to register (the directory fd).
    pub fd: i32,
    /// PID of the registering process (receives the signal).
    pub owner_pid: u32,
    /// Signal to deliver (SIGIO or SIGRT*). Defaults to SIGIO.
    pub signo: u32,
    /// True if this mark is still active.
    pub active: bool,
}

impl DnotifyMark {
    /// Create a new dnotify mark.
    pub fn new(dir_ino: u64, dn_mask: u32, fd: i32, owner_pid: u32) -> Self {
        Self {
            dir_ino,
            dn_mask,
            fd,
            owner_pid,
            signo: SIGIO,
            active: true,
        }
    }

    /// Return true if this mark uses multishot (persistent) mode.
    pub fn is_multishot(&self) -> bool {
        self.dn_mask & DN_MULTISHOT != 0
    }

    /// Return the effective event mask (without the multishot bit).
    pub fn event_mask(&self) -> u32 {
        self.dn_mask & !DN_MULTISHOT
    }
}

// ---------------------------------------------------------------------------
// DnotifyEvent — a pending event to deliver
// ---------------------------------------------------------------------------

/// A pending dnotify event to be delivered to a process.
#[derive(Debug, Clone, Copy)]
pub struct DnotifyEvent {
    /// Which event occurred.
    pub event: u32,
    /// Directory inode.
    pub dir_ino: u64,
    /// Signal to send.
    pub signo: u32,
    /// Target PID.
    pub pid: u32,
}

// ---------------------------------------------------------------------------
// DnotifyRegistry
// ---------------------------------------------------------------------------

/// Registry of all active dnotify marks.
pub struct DnotifyRegistry {
    marks: [Option<DnotifyMark>; MAX_DNOTIFY_MARKS],
    count: usize,
    /// Pending events queued for signal delivery.
    pending: [Option<DnotifyEvent>; 64],
    pending_count: usize,
}

impl DnotifyRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            marks: core::array::from_fn(|_| None),
            count: 0,
            pending: core::array::from_fn(|_| None),
            pending_count: 0,
        }
    }

    fn find_mark(&self, fd: i32, dir_ino: u64) -> Option<usize> {
        for (i, slot) in self.marks[..self.count].iter().enumerate() {
            if let Some(m) = slot {
                if m.fd == fd && m.dir_ino == dir_ino && m.active {
                    return Some(i);
                }
            }
        }
        None
    }
}

impl Default for DnotifyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// dir_notify (fcntl F_NOTIFY)
// ---------------------------------------------------------------------------

/// Register or update a dnotify watch via `fcntl(fd, F_NOTIFY, arg)`.
///
/// `fd` — the directory file descriptor.
/// `dir_ino` — inode number of the directory.
/// `dn_mask` — event mask (DN_* flags). Pass 0 to remove the watch.
/// `owner_pid` — PID to receive signals.
///
/// Returns `Err(OutOfMemory)` if no slots are available.
pub fn dir_notify(
    reg: &mut DnotifyRegistry,
    fd: i32,
    dir_ino: u64,
    dn_mask: u32,
    owner_pid: u32,
) -> Result<()> {
    if dn_mask == 0 {
        // Removing the watch.
        if let Some(idx) = reg.find_mark(fd, dir_ino) {
            if let Some(m) = reg.marks[idx].as_mut() {
                m.active = false;
            }
        }
        return Ok(());
    }

    // Update existing mark.
    if let Some(idx) = reg.find_mark(fd, dir_ino) {
        if let Some(m) = reg.marks[idx].as_mut() {
            m.dn_mask = dn_mask;
            m.owner_pid = owner_pid;
        }
        return Ok(());
    }

    // Add new mark.
    if reg.count >= MAX_DNOTIFY_MARKS {
        return Err(Error::OutOfMemory);
    }
    reg.marks[reg.count] = Some(DnotifyMark::new(dir_ino, dn_mask, fd, owner_pid));
    reg.count += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// dnotify_handle_event
// ---------------------------------------------------------------------------

/// Handle a filesystem event on `dir_ino`, generating pending dnotify signals.
///
/// Called from the VFS layer when an operation occurs within a watched directory.
/// Matches the event against all active marks and queues `DnotifyEvent`s for
/// signal delivery.
pub fn dnotify_handle_event(reg: &mut DnotifyRegistry, dir_ino: u64, event: u32) {
    let mut expired_indices: [usize; 64] = [0usize; 64];
    let mut expired_count = 0usize;

    for (i, slot) in reg.marks[..reg.count].iter().enumerate() {
        if let Some(m) = slot {
            if !m.active || m.dir_ino != dir_ino {
                continue;
            }
            if m.event_mask() & event == 0 {
                continue;
            }
            // Queue signal.
            if reg.pending_count < 64 {
                reg.pending[reg.pending_count] = Some(DnotifyEvent {
                    event,
                    dir_ino,
                    signo: m.signo,
                    pid: m.owner_pid,
                });
                reg.pending_count += 1;
            }
            // One-shot: mark for deactivation.
            if !m.is_multishot() && expired_count < 64 {
                expired_indices[expired_count] = i;
                expired_count += 1;
            }
        }
    }

    for i in 0..expired_count {
        if let Some(m) = reg.marks[expired_indices[i]].as_mut() {
            m.active = false;
        }
    }
}

// ---------------------------------------------------------------------------
// dnotify_flush
// ---------------------------------------------------------------------------

/// Remove all dnotify marks for `fd` (called on file close).
///
/// This ensures no stale notifications are delivered after the file
/// descriptor is closed.
pub fn dnotify_flush(reg: &mut DnotifyRegistry, fd: i32) {
    for slot in reg.marks[..reg.count].iter_mut().flatten() {
        if slot.fd == fd {
            slot.active = false;
        }
    }
}

// ---------------------------------------------------------------------------
// dnotify_signal
// ---------------------------------------------------------------------------

/// Drain and return all pending dnotify events.
///
/// In the kernel this is called by the knotify worker thread (or directly
/// from the VFS path) to deliver SIGIO/SIGRT* to the registered processes.
pub fn dnotify_signal(reg: &mut DnotifyRegistry) -> Vec<DnotifyEvent> {
    let mut events = Vec::new();
    for i in 0..reg.pending_count {
        if let Some(ev) = reg.pending[i].take() {
            events.push(ev);
        }
    }
    reg.pending_count = 0;
    events
}

// ---------------------------------------------------------------------------
// dir_notify_set_signal
// ---------------------------------------------------------------------------

/// Override the signal sent for a dnotify mark.
///
/// `signo` must be `SIGIO` or a real-time signal in `[SIGRTMIN, SIGRTMAX]`.
pub fn dir_notify_set_signal(
    reg: &mut DnotifyRegistry,
    fd: i32,
    dir_ino: u64,
    signo: u32,
) -> Result<()> {
    if signo != SIGIO && !(SIGRTMIN..=SIGRTMAX).contains(&signo) {
        return Err(Error::InvalidArgument);
    }
    let idx = reg.find_mark(fd, dir_ino).ok_or(Error::NotFound)?;
    if let Some(m) = reg.marks[idx].as_mut() {
        m.signo = signo;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Query helpers
// ---------------------------------------------------------------------------

/// List all active dnotify marks for `dir_ino`.
pub fn list_marks_for_dir(reg: &DnotifyRegistry, dir_ino: u64) -> Vec<DnotifyMark> {
    reg.marks[..reg.count]
        .iter()
        .flatten()
        .filter(|m| m.active && m.dir_ino == dir_ino)
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_event() {
        let mut reg = DnotifyRegistry::new();
        dir_notify(&mut reg, 3, 100, DN_CREATE | DN_DELETE | DN_MULTISHOT, 1234).unwrap();

        // Event that matches.
        dnotify_handle_event(&mut reg, 100, DN_CREATE);
        let events = dnotify_signal(&mut reg);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, DN_CREATE);
        assert_eq!(events[0].pid, 1234);
        assert_eq!(events[0].signo, SIGIO);

        // Second event should still fire (multishot).
        dnotify_handle_event(&mut reg, 100, DN_DELETE);
        let events2 = dnotify_signal(&mut reg);
        assert_eq!(events2.len(), 1);
    }

    #[test]
    fn test_oneshot_deactivates() {
        let mut reg = DnotifyRegistry::new();
        // No DN_MULTISHOT → one-shot.
        dir_notify(&mut reg, 4, 200, DN_MODIFY, 999).unwrap();
        dnotify_handle_event(&mut reg, 200, DN_MODIFY);
        dnotify_signal(&mut reg);
        // Second event should produce nothing.
        dnotify_handle_event(&mut reg, 200, DN_MODIFY);
        let events = dnotify_signal(&mut reg);
        assert!(events.is_empty());
    }

    #[test]
    fn test_flush_removes_marks() {
        let mut reg = DnotifyRegistry::new();
        dir_notify(&mut reg, 5, 300, DN_ALL | DN_MULTISHOT, 42).unwrap();
        dnotify_flush(&mut reg, 5);
        dnotify_handle_event(&mut reg, 300, DN_CREATE);
        let events = dnotify_signal(&mut reg);
        assert!(events.is_empty());
    }

    #[test]
    fn test_unmatched_event_ignored() {
        let mut reg = DnotifyRegistry::new();
        dir_notify(&mut reg, 6, 400, DN_CREATE | DN_MULTISHOT, 10).unwrap();
        dnotify_handle_event(&mut reg, 400, DN_DELETE); // not in mask
        let events = dnotify_signal(&mut reg);
        assert!(events.is_empty());
    }
}
