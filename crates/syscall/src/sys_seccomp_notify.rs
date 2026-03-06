// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! seccomp user notification handler (`seccomp_unotify(2)`).
//!
//! The seccomp user-notification mechanism allows a supervisor process to
//! intercept and respond to syscalls made by a sandboxed process.  When a
//! thread hits a BPF filter that returns `SECCOMP_RET_USER_NOTIF`, the kernel:
//!
//! 1. Suspends the sandboxed thread.
//! 2. Delivers a `seccomp_notif` to the supervisor via a notification fd.
//! 3. Waits for the supervisor to send a `seccomp_notif_resp`.
//! 4. Resumes the sandboxed thread with the result from the supervisor.
//!
//! # Key structures
//!
//! | Structure              | Direction          | Purpose                             |
//! |------------------------|--------------------|-------------------------------------|
//! | [`SeccompNotif`]       | kernel → supervisor | Describes the intercepted syscall   |
//! | [`SeccompNotifResp`]   | supervisor → kernel | Supervisor's response (allow/errno) |
//! | [`SeccompData`]        | embedded in notif   | Syscall number and arguments        |
//!
//! # Operations
//!
//! | Ioctl                         | Constant                   | Purpose                        |
//! |-------------------------------|----------------------------|--------------------------------|
//! | Receive notification          | `SECCOMP_IOCTL_NOTIF_RECV` | Block until next notification  |
//! | Send response                 | `SECCOMP_IOCTL_NOTIF_SEND` | Reply to a notification        |
//! | Validate notification ID      | `SECCOMP_IOCTL_NOTIF_ID_VALID` | Check cookie still valid   |
//! | Add file descriptor           | `SECCOMP_IOCTL_NOTIF_ADDFD` | Inject fd into target         |
//!
//! # Cookie validation
//!
//! Each notification has a 64-bit `id` (cookie) that ties the recv and send
//! operations together.  The `ID_VALID` ioctl confirms that the sandboxed
//! thread is still waiting on this specific notification ID.
//!
//! # References
//!
//! - Linux: `kernel/seccomp.c`
//! - man: `seccomp_unotify(2)`, `seccomp(2)`

use oncrix_lib::{Error, Result};

// Re-export constants from the existing seccomp_calls module.
pub use crate::seccomp_calls::{
    SECCOMP_FILTER_FLAG_NEW_LISTENER, SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
    SECCOMP_RET_USER_NOTIF,
};

// ---------------------------------------------------------------------------
// Ioctl codes for the notification fd
// ---------------------------------------------------------------------------

/// Receive the next pending notification.  Blocks if none is queued.
pub const SECCOMP_IOCTL_NOTIF_RECV: u32 = 0xC050_FF00;
/// Send a response to a pending notification.
pub const SECCOMP_IOCTL_NOTIF_SEND: u32 = 0xC018_FF01;
/// Validate that a notification ID is still active.
pub const SECCOMP_IOCTL_NOTIF_ID_VALID: u32 = 0x4008_FF02;
/// Inject an fd into the tracee's file descriptor table.
pub const SECCOMP_IOCTL_NOTIF_ADDFD: u32 = 0x4020_FF03;

// ---------------------------------------------------------------------------
// SeccompData — embedded syscall context
// ---------------------------------------------------------------------------

/// Syscall arguments passed to a seccomp BPF program.
///
/// Matches `struct seccomp_data` from `include/uapi/linux/seccomp.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SeccompData {
    /// Syscall number.
    pub nr: i32,
    /// Architecture (AUDIT_ARCH_* constant).
    pub arch: u32,
    /// Value of the instruction pointer at the time of the syscall.
    pub instruction_pointer: u64,
    /// Syscall arguments (up to 6).
    pub args: [u64; 6],
}

// ---------------------------------------------------------------------------
// SeccompNotif — notification delivered to supervisor
// ---------------------------------------------------------------------------

/// Notification sent from the kernel to the supervisor.
///
/// Matches `struct seccomp_notif` from `include/uapi/linux/seccomp.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct SeccompNotif {
    /// Notification cookie — must match in the corresponding response.
    pub id: u64,
    /// PID of the sandboxed thread.
    pub pid: u32,
    /// Reserved flags (must be 0).
    pub flags: u32,
    /// Syscall context.
    pub data: SeccompData,
}

// ---------------------------------------------------------------------------
// SeccompNotifResp — supervisor's response
// ---------------------------------------------------------------------------

/// Response flags: the supervisor's response was an error return.
pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1 << 0;

/// Response sent from the supervisor back to the kernel.
///
/// Matches `struct seccomp_notif_resp` from `include/uapi/linux/seccomp.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SeccompNotifResp {
    /// Cookie from the corresponding [`SeccompNotif`].
    pub id: u64,
    /// Syscall return value (used when `error == 0` and CONTINUE not set).
    pub val: i64,
    /// Error code to return to the tracee (negative errno).  0 = use `val`.
    pub error: i32,
    /// Response flags: `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.
    pub flags: u32,
}

// ---------------------------------------------------------------------------
// Notification queue
// ---------------------------------------------------------------------------

/// Maximum pending notifications in the queue.
pub const NOTIF_QUEUE_SIZE: usize = 32;

/// State of a pending notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifState {
    /// Notification is pending; supervisor has not yet received it.
    Pending,
    /// Supervisor has received the notification; waiting for response.
    AwaitingResponse,
    /// Response received; sandboxed thread is being resumed.
    Responded,
}

/// A single pending notification entry.
#[derive(Debug, Clone, Copy)]
pub struct NotifEntry {
    /// Whether this slot is occupied.
    pub in_use: bool,
    /// Current state of this notification.
    pub state: NotifState,
    /// The notification data.
    pub notif: SeccompNotif,
    /// The response (valid once state reaches `Responded`).
    pub resp: SeccompNotifResp,
}

impl NotifEntry {
    const fn empty() -> Self {
        Self {
            in_use: false,
            state: NotifState::Pending,
            notif: SeccompNotif {
                id: 0,
                pid: 0,
                flags: 0,
                data: SeccompData {
                    nr: 0,
                    arch: 0,
                    instruction_pointer: 0,
                    args: [0; 6],
                },
            },
            resp: SeccompNotifResp {
                id: 0,
                val: 0,
                error: 0,
                flags: 0,
            },
        }
    }
}

/// Notification queue for a single seccomp notification fd.
pub struct NotifQueue {
    entries: [NotifEntry; NOTIF_QUEUE_SIZE],
    count: usize,
    /// Monotonically increasing cookie generator.
    next_id: u64,
}

impl NotifQueue {
    /// Create an empty notification queue.
    pub const fn new() -> Self {
        Self {
            entries: [const { NotifEntry::empty() }; NOTIF_QUEUE_SIZE],
            count: 0,
            next_id: 1,
        }
    }

    /// Allocate a new cookie ID.
    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// Enqueue a new notification for the sandboxed thread `pid`.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] — Queue is full.
    pub fn enqueue(&mut self, pid: u32, data: SeccompData) -> Result<u64> {
        let id = self.alloc_id();
        let slot = self
            .entries
            .iter_mut()
            .find(|e| !e.in_use)
            .ok_or(Error::OutOfMemory)?;
        slot.in_use = true;
        slot.state = NotifState::Pending;
        slot.notif = SeccompNotif {
            id,
            pid,
            flags: 0,
            data,
        };
        slot.resp = SeccompNotifResp::default();
        self.count += 1;
        Ok(id)
    }

    /// Dequeue the oldest pending notification (FIFO order).
    ///
    /// Returns `None` if no notification is in the `Pending` state.
    pub fn recv(&mut self) -> Option<SeccompNotif> {
        let idx = self
            .entries
            .iter()
            .position(|e| e.in_use && e.state == NotifState::Pending)?;
        self.entries[idx].state = NotifState::AwaitingResponse;
        Some(self.entries[idx].notif)
    }

    /// Submit a response for notification `id`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`]        — No notification with that `id` in
    ///                                `AwaitingResponse` state.
    /// - [`Error::InvalidArgument`] — Cookie mismatch or unexpected flags.
    pub fn send(&mut self, resp: SeccompNotifResp) -> Result<()> {
        // Validate flags.
        if resp.flags & !SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
            return Err(Error::InvalidArgument);
        }

        let idx = self
            .entries
            .iter()
            .position(|e| {
                e.in_use && e.state == NotifState::AwaitingResponse && e.notif.id == resp.id
            })
            .ok_or(Error::NotFound)?;

        self.entries[idx].resp = resp;
        self.entries[idx].state = NotifState::Responded;
        Ok(())
    }

    /// Check whether a notification ID is still active (not yet responded).
    ///
    /// Returns `true` when the notification exists and the sandboxed thread
    /// is still waiting.  Returns `false` (i.e., `ENOENT` semantics) once
    /// the response has been submitted or the thread has been killed.
    pub fn id_valid(&self, id: u64) -> bool {
        self.entries.iter().any(|e| {
            e.in_use
                && e.notif.id == id
                && matches!(e.state, NotifState::Pending | NotifState::AwaitingResponse)
        })
    }

    /// Retrieve the response for notification `id` and free the slot.
    ///
    /// Called by the kernel to get the supervisor's answer after `send` has
    /// been called.  The slot is reclaimed.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] — No responded notification with that `id`.
    pub fn take_response(&mut self, id: u64) -> Result<SeccompNotifResp> {
        let idx = self
            .entries
            .iter()
            .position(|e| e.in_use && e.state == NotifState::Responded && e.notif.id == id)
            .ok_or(Error::NotFound)?;
        let resp = self.entries[idx].resp;
        self.entries[idx].in_use = false;
        self.count -= 1;
        Ok(resp)
    }

    /// Cancel all pending notifications for sandboxed thread `pid`.
    ///
    /// Called when the tracee thread exits or is killed.
    pub fn cancel_for_pid(&mut self, pid: u32) {
        for entry in self.entries.iter_mut() {
            if entry.in_use && entry.notif.pid == pid {
                entry.in_use = false;
                self.count = self.count.saturating_sub(1);
            }
        }
    }

    /// Return the number of active notification entries.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return the number of notifications in the `Pending` state.
    pub fn pending_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.in_use && e.state == NotifState::Pending)
            .count()
    }
}

// ---------------------------------------------------------------------------
// AddFd request — inject fd into tracee
// ---------------------------------------------------------------------------

/// Flags for `SECCOMP_IOCTL_NOTIF_ADDFD`.
pub const SECCOMP_ADDFD_FLAG_SETFD: u32 = 1 << 0;
/// Create the new fd with `O_CLOEXEC` set.
pub const SECCOMP_ADDFD_FLAG_SEND: u32 = 1 << 1;

/// Parameters for the `ADDFD` ioctl.
///
/// Matches `struct seccomp_notif_addfd` from `include/uapi/linux/seccomp.h`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SeccompNotifAddfd {
    /// Notification cookie.
    pub id: u64,
    /// Flags (`SECCOMP_ADDFD_FLAG_*`).
    pub flags: u32,
    /// File descriptor in the supervisor to duplicate into the tracee.
    pub srcfd: u32,
    /// Destination fd in the tracee (ignored unless `SETFD`).
    pub newfd: u32,
    /// Flags to set on the new fd (e.g. `O_CLOEXEC`).
    pub newfd_flags: u32,
}

/// Validate a `SeccompNotifAddfd` request.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — Unknown flags or `srcfd` is invalid.
pub fn validate_addfd(req: &SeccompNotifAddfd) -> Result<()> {
    let valid_flags = SECCOMP_ADDFD_FLAG_SETFD | SECCOMP_ADDFD_FLAG_SEND;
    if req.flags & !valid_flags != 0 {
        return Err(Error::InvalidArgument);
    }
    if req.srcfd > i32::MAX as u32 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_data(nr: i32) -> SeccompData {
        SeccompData {
            nr,
            arch: 0xC000_003E, // AUDIT_ARCH_X86_64
            instruction_pointer: 0x7FFF_0000,
            args: [1, 2, 3, 4, 5, 6],
        }
    }

    #[test]
    fn enqueue_and_recv() {
        let mut q = NotifQueue::new();
        let id = q.enqueue(1000, make_data(1)).unwrap();
        assert_eq!(q.pending_count(), 1);
        let notif = q.recv().unwrap();
        assert_eq!(notif.id, id);
        assert_eq!(notif.pid, 1000);
        assert_eq!(notif.data.nr, 1);
        assert_eq!(q.pending_count(), 0);
    }

    #[test]
    fn recv_empty_returns_none() {
        let mut q = NotifQueue::new();
        assert!(q.recv().is_none());
    }

    #[test]
    fn id_valid_before_response() {
        let mut q = NotifQueue::new();
        let id = q.enqueue(2000, make_data(2)).unwrap();
        assert!(q.id_valid(id));
        q.recv().unwrap();
        assert!(q.id_valid(id)); // still waiting for response
    }

    #[test]
    fn id_invalid_after_response() {
        let mut q = NotifQueue::new();
        let id = q.enqueue(2000, make_data(2)).unwrap();
        q.recv().unwrap();
        let resp = SeccompNotifResp {
            id,
            val: 0,
            error: 0,
            flags: 0,
        };
        q.send(resp).unwrap();
        assert!(!q.id_valid(id));
    }

    #[test]
    fn send_and_take_response() {
        let mut q = NotifQueue::new();
        let id = q.enqueue(3000, make_data(3)).unwrap();
        q.recv().unwrap();
        let resp = SeccompNotifResp {
            id,
            val: 42,
            error: 0,
            flags: 0,
        };
        q.send(resp).unwrap();
        let taken = q.take_response(id).unwrap();
        assert_eq!(taken.val, 42);
        assert_eq!(q.count(), 0);
    }

    #[test]
    fn send_wrong_id_returns_not_found() {
        let mut q = NotifQueue::new();
        let id = q.enqueue(4000, make_data(4)).unwrap();
        q.recv().unwrap();
        let resp = SeccompNotifResp {
            id: id + 999,
            val: 0,
            error: 0,
            flags: 0,
        };
        assert_eq!(q.send(resp), Err(Error::NotFound));
    }

    #[test]
    fn send_before_recv_returns_not_found() {
        let mut q = NotifQueue::new();
        let id = q.enqueue(5000, make_data(5)).unwrap();
        let resp = SeccompNotifResp {
            id,
            val: 0,
            error: 0,
            flags: 0,
        };
        // Notification is still in Pending state — send should fail.
        assert_eq!(q.send(resp), Err(Error::NotFound));
    }

    #[test]
    fn send_unknown_flags_rejected() {
        let mut q = NotifQueue::new();
        let id = q.enqueue(6000, make_data(6)).unwrap();
        q.recv().unwrap();
        let resp = SeccompNotifResp {
            id,
            val: 0,
            error: 0,
            flags: 0xFF00,
        };
        assert_eq!(q.send(resp), Err(Error::InvalidArgument));
    }

    #[test]
    fn cancel_for_pid_clears_entries() {
        let mut q = NotifQueue::new();
        q.enqueue(7000, make_data(1)).unwrap();
        q.enqueue(7000, make_data(2)).unwrap();
        q.enqueue(8000, make_data(3)).unwrap();
        assert_eq!(q.count(), 3);
        q.cancel_for_pid(7000);
        assert_eq!(q.count(), 1);
    }

    #[test]
    fn queue_full_returns_oom() {
        let mut q = NotifQueue::new();
        for i in 0..NOTIF_QUEUE_SIZE {
            q.enqueue(i as u32, make_data(i as i32)).unwrap();
        }
        assert_eq!(q.enqueue(9999, make_data(0)), Err(Error::OutOfMemory));
    }

    #[test]
    fn continue_flag_accepted() {
        let mut q = NotifQueue::new();
        let id = q.enqueue(1000, make_data(1)).unwrap();
        q.recv().unwrap();
        let resp = SeccompNotifResp {
            id,
            val: 0,
            error: 0,
            flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
        };
        assert_eq!(q.send(resp), Ok(()));
    }

    #[test]
    fn validate_addfd_ok() {
        let req = SeccompNotifAddfd {
            id: 1,
            flags: SECCOMP_ADDFD_FLAG_SETFD,
            srcfd: 5,
            newfd: 10,
            newfd_flags: 0,
        };
        assert_eq!(validate_addfd(&req), Ok(()));
    }

    #[test]
    fn validate_addfd_bad_flags_rejected() {
        let req = SeccompNotifAddfd {
            id: 1,
            flags: 0xDEAD,
            srcfd: 5,
            newfd: 10,
            newfd_flags: 0,
        };
        assert_eq!(validate_addfd(&req), Err(Error::InvalidArgument));
    }
}
