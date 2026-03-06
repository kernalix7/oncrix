// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Seccomp user-space notification subsystem.
//!
//! Extends the seccomp filter engine with `SECCOMP_RET_USER_NOTIF`
//! support, allowing a supervisor process to intercept and decide
//! on filtered syscalls via a notification file descriptor.
//!
//! # Architecture
//!
//! ```text
//!  target process              supervisor process
//!  ──────────────              ──────────────────
//!  syscall()                   recv_notif()
//!    │                           │
//!    ▼                           ▼
//!  seccomp filter              inspect request
//!    │ RET_USER_NOTIF            │
//!    ▼                           ▼
//!  enqueue request ─────────► notification queue
//!  (blocks target)              │
//!    ▲                           ▼
//!    │                         decide (allow/deny)
//!    │                           │
//!    └──────────────────────── send_resp()
//!                              (unblocks target)
//! ```
//!
//! # Cookie-Based Tracking
//!
//! Each notification request is assigned a unique 64-bit cookie
//! (`id`). The supervisor must present this cookie when responding,
//! and can use [`check_id_valid`](NotifListener::check_id_valid)
//! to verify the request is still active (the target process has
//! not exited or been killed).
//!
//! # SECCOMP_IOCTL_NOTIF_ADDFD
//!
//! The supervisor can inject file descriptors into the target
//! process via the [`AddFdRequest`] mechanism, enabling the
//! supervisor to open resources on behalf of the target.
//!
//! Reference: Linux `kernel/seccomp.c`
//! (`SECCOMP_FILTER_FLAG_NEW_LISTENER`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of pending notification requests per listener.
const MAX_PENDING: usize = 64;

/// Maximum number of active notification listeners.
const MAX_LISTENERS: usize = 16;

/// Maximum number of pending ADDFD requests per listener.
const MAX_ADDFD_PENDING: usize = 16;

// -------------------------------------------------------------------
// SeccompNotifReq
// -------------------------------------------------------------------

/// A seccomp user-notification request.
///
/// Sent from the kernel to a supervisor process when a target
/// process's seccomp filter returns `SECCOMP_RET_USER_NOTIF`.
/// The supervisor inspects the syscall details and responds with
/// a [`SeccompNotifResp`].
#[derive(Debug, Clone, Copy)]
pub struct SeccompNotifReq {
    /// Unique request cookie (monotonically increasing).
    pub id: u64,
    /// PID of the target process that triggered the notification.
    pub pid: u64,
    /// System call number.
    pub syscall_nr: u32,
    /// Syscall arguments (up to 6).
    pub args: [u64; 6],
    /// Opaque data from the seccomp filter (lower 16 bits of the
    /// BPF return value).
    pub data: u16,
}

impl SeccompNotifReq {
    /// Create an empty notification request.
    const fn empty() -> Self {
        Self {
            id: 0,
            pid: 0,
            syscall_nr: 0,
            args: [0u64; 6],
            data: 0,
        }
    }
}

// -------------------------------------------------------------------
// SeccompNotifResp
// -------------------------------------------------------------------

/// A seccomp user-notification response.
///
/// Sent from the supervisor to the kernel, deciding the outcome
/// of the intercepted syscall.
#[derive(Debug, Clone, Copy)]
pub struct SeccompNotifResp {
    /// Request cookie (must match the corresponding request).
    pub id: u64,
    /// Return value for the syscall (on success).
    pub val: i64,
    /// Error value (negated errno; 0 = no error).
    pub error: i32,
    /// Response flags.
    pub flags: u32,
}

/// Response flag: allow the syscall to continue (kernel evaluates
/// the syscall normally instead of returning `val`/`error`).
pub const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1 << 0;

// -------------------------------------------------------------------
// NotifState
// -------------------------------------------------------------------

/// Internal state of a notification request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotifState {
    /// Request is pending — waiting for supervisor response.
    Pending,
    /// Supervisor has responded.
    Responded,
    /// Request was cancelled (target exited or was killed).
    Cancelled,
}

// -------------------------------------------------------------------
// NotifEntry (internal)
// -------------------------------------------------------------------

/// Internal notification entry combining request, response, and
/// state tracking.
#[derive(Debug, Clone, Copy)]
struct NotifEntry {
    /// The notification request.
    request: SeccompNotifReq,
    /// The supervisor's response (valid when state == Responded).
    response: SeccompNotifResp,
    /// Current state of this notification.
    state: NotifState,
    /// Whether this slot is in use.
    active: bool,
}

impl NotifEntry {
    /// Create an empty, inactive entry.
    const fn empty() -> Self {
        Self {
            request: SeccompNotifReq::empty(),
            response: SeccompNotifResp {
                id: 0,
                val: 0,
                error: 0,
                flags: 0,
            },
            state: NotifState::Pending,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// AddFdRequest
// -------------------------------------------------------------------

/// Request to inject a file descriptor into the target process.
///
/// Corresponds to `SECCOMP_IOCTL_NOTIF_ADDFD` in Linux. The
/// supervisor uses this to install a file descriptor (opened by
/// the supervisor) into the target process's fd table.
#[derive(Debug, Clone, Copy)]
pub struct AddFdRequest {
    /// Notification cookie identifying the target request.
    pub id: u64,
    /// File descriptor number in the supervisor's fd table.
    pub src_fd: u32,
    /// Desired fd number in the target process (-1 for next free).
    pub new_fd: i32,
    /// Flags controlling the fd injection.
    pub flags: u32,
}

/// ADDFD flag: set the O_CLOEXEC flag on the injected fd.
pub const SECCOMP_ADDFD_FLAG_SETFD: u32 = 1 << 0;

/// ADDFD flag: send the new fd as the syscall return value.
pub const SECCOMP_ADDFD_FLAG_SEND: u32 = 1 << 1;

// -------------------------------------------------------------------
// AddFdEntry (internal)
// -------------------------------------------------------------------

/// Internal entry tracking a pending ADDFD request.
#[derive(Debug, Clone, Copy)]
struct AddFdEntry {
    /// The ADDFD request.
    request: AddFdRequest,
    /// Whether this slot is in use.
    active: bool,
}

impl AddFdEntry {
    /// Create an empty, inactive entry.
    const fn empty() -> Self {
        Self {
            request: AddFdRequest {
                id: 0,
                src_fd: 0,
                new_fd: 0,
                flags: 0,
            },
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// ListenerId
// -------------------------------------------------------------------

/// Opaque identifier for a notification listener.
///
/// Each listener is identified by an index into the global
/// listener registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenerId(usize);

impl ListenerId {
    /// Return the raw index.
    pub fn index(self) -> usize {
        self.0
    }
}

// -------------------------------------------------------------------
// NotifListener
// -------------------------------------------------------------------

/// A seccomp notification listener.
///
/// Manages a queue of pending notification requests from target
/// processes and allows a supervisor to receive and respond to
/// them. Each listener also supports ADDFD requests.
pub struct NotifListener {
    /// Pending notification entries.
    entries: [NotifEntry; MAX_PENDING],
    /// Number of active entries (pending + responded).
    entry_count: usize,
    /// Next cookie value to assign.
    next_id: u64,
    /// Whether this listener is active.
    active: bool,
    /// Pending ADDFD requests.
    addfd_entries: [AddFdEntry; MAX_ADDFD_PENDING],
    /// Number of active ADDFD entries.
    addfd_count: usize,
}

impl NotifListener {
    /// Create an empty, inactive listener.
    const fn empty() -> Self {
        Self {
            entries: [NotifEntry::empty(); MAX_PENDING],
            entry_count: 0,
            next_id: 1,
            active: false,
            addfd_entries: [AddFdEntry::empty(); MAX_ADDFD_PENDING],
            addfd_count: 0,
        }
    }

    /// Enqueue a notification request from a target process.
    ///
    /// Called by the kernel when a seccomp filter returns
    /// `SECCOMP_RET_USER_NOTIF`. The target process is blocked
    /// until the supervisor responds.
    ///
    /// Returns the assigned cookie (`id`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the notification queue
    /// is full.
    pub fn enqueue(
        &mut self,
        pid: u64,
        syscall_nr: u32,
        args: &[u64; 6],
        data: u16,
    ) -> Result<u64> {
        if self.entry_count >= MAX_PENDING {
            return Err(Error::OutOfMemory);
        }

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        // Find a free slot.
        let mut i = 0;
        while i < MAX_PENDING {
            if !self.entries[i].active {
                self.entries[i] = NotifEntry {
                    request: SeccompNotifReq {
                        id,
                        pid,
                        syscall_nr,
                        args: *args,
                        data,
                    },
                    response: SeccompNotifResp {
                        id: 0,
                        val: 0,
                        error: 0,
                        flags: 0,
                    },
                    state: NotifState::Pending,
                    active: true,
                };
                self.entry_count += 1;
                return Ok(id);
            }
            i += 1;
        }

        Err(Error::OutOfMemory)
    }

    /// Receive the next pending notification request.
    ///
    /// Returns the oldest pending request, or `None` if no
    /// requests are waiting.
    pub fn recv_notif(&self) -> Option<SeccompNotifReq> {
        let mut i = 0;
        while i < MAX_PENDING {
            if self.entries[i].active && self.entries[i].state == NotifState::Pending {
                return Some(self.entries[i].request);
            }
            i += 1;
        }
        None
    }

    /// Send a response to a pending notification.
    ///
    /// The `resp.id` must match a pending request. After response,
    /// the entry is marked as responded and the slot is freed.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no pending request with the given
    ///   id exists.
    /// - [`Error::InvalidArgument`] if the request is not in the
    ///   Pending state.
    pub fn send_resp(&mut self, resp: SeccompNotifResp) -> Result<()> {
        let mut i = 0;
        while i < MAX_PENDING {
            if self.entries[i].active && self.entries[i].request.id == resp.id {
                if self.entries[i].state != NotifState::Pending {
                    return Err(Error::InvalidArgument);
                }
                self.entries[i].response = resp;
                self.entries[i].state = NotifState::Responded;
                return Ok(());
            }
            i += 1;
        }
        Err(Error::NotFound)
    }

    /// Retrieve the response for a completed notification.
    ///
    /// Called by the kernel to unblock a target process. If the
    /// notification has been responded to, returns the response
    /// and frees the slot. Returns `None` if still pending or
    /// cancelled.
    pub fn take_response(&mut self, id: u64) -> Option<SeccompNotifResp> {
        let mut i = 0;
        while i < MAX_PENDING {
            if self.entries[i].active && self.entries[i].request.id == id {
                if self.entries[i].state == NotifState::Responded {
                    let resp = self.entries[i].response;
                    self.entries[i] = NotifEntry::empty();
                    self.entry_count = self.entry_count.saturating_sub(1);
                    return Some(resp);
                }
                return None;
            }
            i += 1;
        }
        None
    }

    /// Check whether a notification request is still valid.
    ///
    /// Returns `true` if the request with the given `id` is still
    /// pending (the target process has not exited). The supervisor
    /// should call this before performing expensive operations on
    /// behalf of the target.
    pub fn check_id_valid(&self, id: u64) -> bool {
        let mut i = 0;
        while i < MAX_PENDING {
            if self.entries[i].active && self.entries[i].request.id == id {
                return self.entries[i].state == NotifState::Pending;
            }
            i += 1;
        }
        false
    }

    /// Cancel a notification (e.g., when the target process exits).
    ///
    /// Marks the notification as cancelled and frees the slot.
    pub fn cancel(&mut self, id: u64) {
        let mut i = 0;
        while i < MAX_PENDING {
            if self.entries[i].active && self.entries[i].request.id == id {
                self.entries[i].state = NotifState::Cancelled;
                self.entries[i].active = false;
                self.entry_count = self.entry_count.saturating_sub(1);
                return;
            }
            i += 1;
        }
    }

    /// Cancel all notifications for a given PID.
    ///
    /// Called when a process exits to clean up all pending
    /// notifications from that process.
    pub fn cancel_all_for_pid(&mut self, pid: u64) {
        let mut i = 0;
        while i < MAX_PENDING {
            if self.entries[i].active && self.entries[i].request.pid == pid {
                self.entries[i].state = NotifState::Cancelled;
                self.entries[i].active = false;
                self.entry_count = self.entry_count.saturating_sub(1);
            }
            i += 1;
        }
    }

    /// Submit an ADDFD request to inject a file descriptor into
    /// the target process.
    ///
    /// The `req.id` must reference a valid pending notification.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the notification id is not valid.
    /// - [`Error::OutOfMemory`] if the ADDFD queue is full.
    pub fn submit_addfd(&mut self, req: AddFdRequest) -> Result<()> {
        if !self.check_id_valid(req.id) {
            return Err(Error::NotFound);
        }
        if self.addfd_count >= MAX_ADDFD_PENDING {
            return Err(Error::OutOfMemory);
        }
        let mut i = 0;
        while i < MAX_ADDFD_PENDING {
            if !self.addfd_entries[i].active {
                self.addfd_entries[i] = AddFdEntry {
                    request: req,
                    active: true,
                };
                self.addfd_count += 1;
                return Ok(());
            }
            i += 1;
        }
        Err(Error::OutOfMemory)
    }

    /// Retrieve the next pending ADDFD request.
    ///
    /// Returns and dequeues the oldest ADDFD request, or `None`
    /// if the queue is empty.
    pub fn take_addfd(&mut self) -> Option<AddFdRequest> {
        let mut i = 0;
        while i < MAX_ADDFD_PENDING {
            if self.addfd_entries[i].active {
                let req = self.addfd_entries[i].request;
                self.addfd_entries[i] = AddFdEntry::empty();
                self.addfd_count = self.addfd_count.saturating_sub(1);
                return Some(req);
            }
            i += 1;
        }
        None
    }

    /// Return the number of pending notifications.
    pub fn pending_count(&self) -> usize {
        let mut count = 0;
        let mut i = 0;
        while i < MAX_PENDING {
            if self.entries[i].active && self.entries[i].state == NotifState::Pending {
                count += 1;
            }
            i += 1;
        }
        count
    }

    /// Return the total number of active entries.
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }
}

impl core::fmt::Debug for NotifListener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NotifListener")
            .field("entry_count", &self.entry_count)
            .field("next_id", &self.next_id)
            .field("active", &self.active)
            .field("addfd_count", &self.addfd_count)
            .finish()
    }
}

// -------------------------------------------------------------------
// SeccompNotifRegistry
// -------------------------------------------------------------------

/// Global registry of seccomp notification listeners.
///
/// Provides up to [`MAX_LISTENERS`] listener slots. Each listener
/// is associated with a seccomp filter installation and receives
/// notifications for `SECCOMP_RET_USER_NOTIF` verdicts.
pub struct SeccompNotifRegistry {
    /// Listener slots.
    listeners: [NotifListener; MAX_LISTENERS],
    /// Number of active listeners.
    count: usize,
}

impl Default for SeccompNotifRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SeccompNotifRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            listeners: [const { NotifListener::empty() }; MAX_LISTENERS],
            count: 0,
        }
    }

    /// Create a new notification listener.
    ///
    /// Returns the listener's id, which is used to receive
    /// notifications and send responses.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all listener slots are
    /// occupied.
    pub fn create_listener(&mut self) -> Result<ListenerId> {
        if self.count >= MAX_LISTENERS {
            return Err(Error::OutOfMemory);
        }
        let mut i = 0;
        while i < MAX_LISTENERS {
            if !self.listeners[i].active {
                self.listeners[i] = NotifListener::empty();
                self.listeners[i].active = true;
                self.count += 1;
                return Ok(ListenerId(i));
            }
            i += 1;
        }
        Err(Error::OutOfMemory)
    }

    /// Destroy a notification listener and cancel all pending
    /// notifications.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the listener id is
    /// invalid.
    pub fn destroy_listener(&mut self, id: ListenerId) -> Result<()> {
        let idx = id.index();
        if idx >= MAX_LISTENERS || !self.listeners[idx].active {
            return Err(Error::InvalidArgument);
        }
        self.listeners[idx] = NotifListener::empty();
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Get a reference to a listener.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the listener id is
    /// invalid.
    pub fn get_listener(&self, id: ListenerId) -> Result<&NotifListener> {
        let idx = id.index();
        if idx >= MAX_LISTENERS || !self.listeners[idx].active {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.listeners[idx])
    }

    /// Get a mutable reference to a listener.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the listener id is
    /// invalid.
    pub fn get_listener_mut(&mut self, id: ListenerId) -> Result<&mut NotifListener> {
        let idx = id.index();
        if idx >= MAX_LISTENERS || !self.listeners[idx].active {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.listeners[idx])
    }

    /// Enqueue a notification on a specific listener.
    ///
    /// Convenience wrapper that combines listener lookup and
    /// [`NotifListener::enqueue`].
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the listener id is invalid.
    /// - [`Error::OutOfMemory`] if the notification queue is full.
    pub fn enqueue_notif(
        &mut self,
        listener_id: ListenerId,
        pid: u64,
        syscall_nr: u32,
        args: &[u64; 6],
        data: u16,
    ) -> Result<u64> {
        let listener = self.get_listener_mut(listener_id)?;
        listener.enqueue(pid, syscall_nr, args, data)
    }

    /// Receive the next notification from a listener.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the listener id is
    /// invalid.
    pub fn recv_notif(&self, listener_id: ListenerId) -> Result<Option<SeccompNotifReq>> {
        let listener = self.get_listener(listener_id)?;
        Ok(listener.recv_notif())
    }

    /// Send a response through a listener.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the listener id is invalid.
    /// - [`Error::NotFound`] if no matching pending request exists.
    pub fn send_resp(&mut self, listener_id: ListenerId, resp: SeccompNotifResp) -> Result<()> {
        let listener = self.get_listener_mut(listener_id)?;
        listener.send_resp(resp)
    }

    /// Check whether a notification id is still valid on a listener.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the listener id is
    /// invalid.
    pub fn check_id_valid(&self, listener_id: ListenerId, notif_id: u64) -> Result<bool> {
        let listener = self.get_listener(listener_id)?;
        Ok(listener.check_id_valid(notif_id))
    }

    /// Return the number of active listeners.
    pub fn listener_count(&self) -> usize {
        self.count
    }
}

impl core::fmt::Debug for SeccompNotifRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SeccompNotifRegistry")
            .field("listeners", &self.count)
            .field("capacity", &MAX_LISTENERS)
            .finish()
    }
}
