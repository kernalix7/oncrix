// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX message queue notification (`mq_notify`).
//!
//! Implements the POSIX.1-2024 `mq_notify()` interface for registering
//! asynchronous notification of message arrival on a POSIX message queue.
//! When a message arrives on a previously empty queue and a notification
//! is registered, the notification is delivered and the registration is
//! automatically removed.
//!
//! # Design
//!
//! Each message queue may have at most one registered notification at
//! any time.  Notifications can be delivered via:
//! - Signal delivery (`SIGEV_SIGNAL`)
//! - Thread creation (`SIGEV_THREAD`) — represented as a callback index
//! - No delivery (`SIGEV_NONE`) — registration only for blocking purposes
//!
//! # Operations
//!
//! | Function                | Purpose                                    |
//! |-------------------------|--------------------------------------------|
//! | [`register_notify`]     | Register for message arrival notification  |
//! | [`unregister_notify`]   | Remove an existing notification            |
//! | [`deliver_notification`]| Trigger notification on message arrival     |
//! | [`check_pending`]       | Check for pending (undelivered) notifications |
//!
//! # POSIX conformance
//!
//! - POSIX.1-2024: `mq_notify()`
//! - EBUSY when another process is already registered
//! - Registration removed after notification delivery
//! - Notification suppressed when a thread is blocked in `mq_receive`
//!
//! # References
//!
//! - POSIX.1-2024: `mq_notify()`
//! - Linux: `ipc/mqueue.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of notification registrations system-wide.
const MAX_NOTIFY_ENTRIES: usize = 64;

/// Maximum number of queues that can have pending notifications.
const MAX_PENDING: usize = 32;

// ---------------------------------------------------------------------------
// NotifyType — notification delivery mechanism
// ---------------------------------------------------------------------------

/// Notification delivery mechanism (mirrors `sigev_notify` values).
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyType {
    /// No notification delivery (registration for tracking only).
    None = 0,
    /// Deliver notification via signal.
    Signal = 1,
    /// Deliver notification by creating a thread.
    Thread = 2,
}

impl NotifyType {
    /// Convert from a raw `i32` value.
    ///
    /// Returns `Err(Error::InvalidArgument)` for unrecognised values.
    pub fn from_i32(val: i32) -> Result<Self> {
        match val {
            0 => Ok(Self::None),
            1 => Ok(Self::Signal),
            2 => Ok(Self::Thread),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// SignalInfo — signal notification parameters
// ---------------------------------------------------------------------------

/// Signal information for signal-based notification.
///
/// When `NotifyType::Signal` is used, these parameters specify which
/// signal to deliver and what value to carry in `si_value`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SignalInfo {
    /// Signal number to deliver (e.g., `SIGUSR1`).
    pub signo: i32,
    /// Value to deliver with the signal (`si_value`).
    pub value: i64,
}

impl SignalInfo {
    /// Create a new signal notification descriptor.
    pub const fn new(signo: i32, value: i64) -> Self {
        Self { signo, value }
    }
}

// ---------------------------------------------------------------------------
// NotifyState — lifecycle state of a notification registration
// ---------------------------------------------------------------------------

/// Lifecycle state of a notification registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotifyState {
    /// Notification is registered and waiting for a message to arrive.
    Active,
    /// A message has arrived; notification is pending delivery.
    Pending,
    /// Notification has been delivered and consumed.
    Delivered,
    /// Registration was explicitly cancelled.
    Cancelled,
}

// ---------------------------------------------------------------------------
// MqNotifyEntry — a single notification registration
// ---------------------------------------------------------------------------

/// A single notification registration for a message queue.
///
/// Associates a process (by PID) with a message queue (by descriptor
/// index) and specifies how the notification should be delivered.
#[derive(Debug, Clone, Copy)]
pub struct MqNotifyEntry {
    /// Message queue descriptor index.
    pub mq_index: usize,
    /// Generation counter of the queue descriptor (for staleness detection).
    pub mq_generation: u32,
    /// PID of the registering process.
    pub pid: u32,
    /// Type of notification delivery.
    pub notify_type: NotifyType,
    /// Signal info (valid only when `notify_type == Signal`).
    pub signal: SignalInfo,
    /// Current state of this registration.
    pub state: NotifyState,
    /// Whether this entry is in use.
    in_use: bool,
}

impl MqNotifyEntry {
    /// Create an inactive entry.
    const fn new() -> Self {
        Self {
            mq_index: 0,
            mq_generation: 0,
            pid: 0,
            notify_type: NotifyType::None,
            signal: SignalInfo { signo: 0, value: 0 },
            state: NotifyState::Cancelled,
            in_use: false,
        }
    }
}

// ---------------------------------------------------------------------------
// NotifyRegistry — system-wide notification table
// ---------------------------------------------------------------------------

/// System-wide notification registration table.
///
/// Tracks all active `mq_notify` registrations.  Per POSIX, at most one
/// process may be registered for notification on any given queue.
pub struct NotifyRegistry {
    entries: [MqNotifyEntry; MAX_NOTIFY_ENTRIES],
    count: usize,
    /// Pending notification queue indices awaiting delivery.
    pending: [usize; MAX_PENDING],
    /// Number of pending notifications.
    pending_count: usize,
}

impl NotifyRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            entries: [const { MqNotifyEntry::new() }; MAX_NOTIFY_ENTRIES],
            count: 0,
            pending: [0usize; MAX_PENDING],
            pending_count: 0,
        }
    }

    /// Return the number of active registrations.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return `true` if there are no active registrations.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return the number of pending notifications.
    pub const fn pending_count(&self) -> usize {
        self.pending_count
    }

    /// Find an active registration for a given queue.
    fn find_by_queue(&self, mq_index: usize, mq_generation: u32) -> Option<usize> {
        self.entries.iter().position(|e| {
            e.in_use
                && e.mq_index == mq_index
                && e.mq_generation == mq_generation
                && e.state == NotifyState::Active
        })
    }

    /// Find any registration (active or pending) for a queue by a process.
    fn find_by_queue_and_pid(
        &self,
        mq_index: usize,
        mq_generation: u32,
        pid: u32,
    ) -> Option<usize> {
        self.entries.iter().position(|e| {
            e.in_use
                && e.mq_index == mq_index
                && e.mq_generation == mq_generation
                && e.pid == pid
                && matches!(e.state, NotifyState::Active | NotifyState::Pending)
        })
    }

    /// Find a free slot.
    fn find_free(&self) -> Option<usize> {
        self.entries.iter().position(|e| !e.in_use)
    }

    /// Add a notification index to the pending queue.
    fn enqueue_pending(&mut self, entry_idx: usize) {
        if self.pending_count < MAX_PENDING {
            self.pending[self.pending_count] = entry_idx;
            self.pending_count += 1;
        }
    }

    /// Remove and return the oldest pending notification index.
    fn dequeue_pending(&mut self) -> Option<usize> {
        if self.pending_count == 0 {
            return None;
        }
        let idx = self.pending[0];
        let remaining = self.pending_count - 1;
        for i in 0..remaining {
            self.pending[i] = self.pending[i + 1];
        }
        self.pending[remaining] = 0;
        self.pending_count -= 1;
        Some(idx)
    }
}

impl Default for NotifyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// register_notify — mq_notify(mqdes, &notification)
// ---------------------------------------------------------------------------

/// Register for notification of message arrival on a message queue.
///
/// Per POSIX, at most one process may be registered for notification
/// on any given queue.  Attempting to register when another process
/// already has a registration returns `Error::Busy` (EBUSY).
///
/// # Arguments
///
/// * `registry`      — The system-wide notification registry.
/// * `mq_index`      — Message queue descriptor index.
/// * `mq_generation` — Generation counter for staleness detection.
/// * `pid`           — PID of the registering process.
/// * `notify_type`   — Notification delivery mechanism.
/// * `signal`        — Signal info (used only when `notify_type == Signal`).
///
/// # Errors
///
/// * [`Error::Busy`]           — another process is already registered.
/// * [`Error::OutOfMemory`]    — registry full.
/// * [`Error::InvalidArgument`] — invalid signal number for signal notification.
pub fn register_notify(
    registry: &mut NotifyRegistry,
    mq_index: usize,
    mq_generation: u32,
    pid: u32,
    notify_type: NotifyType,
    signal: SignalInfo,
) -> Result<()> {
    // Validate signal number for signal-based notifications.
    if notify_type == NotifyType::Signal && signal.signo <= 0 {
        return Err(Error::InvalidArgument);
    }

    // Check if another process is already registered for this queue.
    if let Some(existing_idx) = registry.find_by_queue(mq_index, mq_generation) {
        let existing = &registry.entries[existing_idx];
        if existing.pid != pid {
            return Err(Error::Busy);
        }
        // Same process re-registering: update the existing entry.
        let entry = &mut registry.entries[existing_idx];
        entry.notify_type = notify_type;
        entry.signal = signal;
        entry.state = NotifyState::Active;
        return Ok(());
    }

    // Allocate a new entry.
    let free_idx = registry.find_free().ok_or(Error::OutOfMemory)?;
    let entry = &mut registry.entries[free_idx];
    entry.mq_index = mq_index;
    entry.mq_generation = mq_generation;
    entry.pid = pid;
    entry.notify_type = notify_type;
    entry.signal = signal;
    entry.state = NotifyState::Active;
    entry.in_use = true;
    registry.count += 1;

    Ok(())
}

// ---------------------------------------------------------------------------
// unregister_notify — mq_notify(mqdes, NULL)
// ---------------------------------------------------------------------------

/// Unregister an existing notification for a message queue.
///
/// Per POSIX, passing `NULL` as the notification argument removes the
/// calling process's registration for the specified queue.
///
/// # Arguments
///
/// * `registry`      — The system-wide notification registry.
/// * `mq_index`      — Message queue descriptor index.
/// * `mq_generation` — Generation counter.
/// * `pid`           — PID of the calling process.
///
/// # Errors
///
/// * [`Error::NotFound`] — no registration found for this process/queue.
pub fn unregister_notify(
    registry: &mut NotifyRegistry,
    mq_index: usize,
    mq_generation: u32,
    pid: u32,
) -> Result<()> {
    let idx = registry
        .find_by_queue_and_pid(mq_index, mq_generation, pid)
        .ok_or(Error::NotFound)?;

    let entry = &mut registry.entries[idx];
    entry.state = NotifyState::Cancelled;
    entry.in_use = false;
    registry.count = registry.count.saturating_sub(1);
    Ok(())
}

// ---------------------------------------------------------------------------
// deliver_notification — called when a message arrives on an empty queue
// ---------------------------------------------------------------------------

/// Trigger notification delivery when a message arrives on an empty queue.
///
/// Per POSIX, the notification is delivered only when the queue transitions
/// from empty to non-empty.  After delivery, the registration is removed.
///
/// If a thread is blocked in `mq_receive` on the same queue, the arriving
/// message satisfies the receive and no notification is sent (the
/// `receiver_blocked` flag controls this).
///
/// # Arguments
///
/// * `registry`         — The system-wide notification registry.
/// * `mq_index`         — Queue that received the message.
/// * `mq_generation`    — Generation counter.
/// * `receiver_blocked` — `true` if a thread is blocked in `mq_receive`.
///
/// # Returns
///
/// `Some(entry_copy)` if a notification was triggered, `None` otherwise.
pub fn deliver_notification(
    registry: &mut NotifyRegistry,
    mq_index: usize,
    mq_generation: u32,
    receiver_blocked: bool,
) -> Option<MqNotifyEntry> {
    // Per POSIX: if a receiver is blocked, the message satisfies the
    // receive and no notification is sent.
    if receiver_blocked {
        return None;
    }

    let idx = registry.find_by_queue(mq_index, mq_generation)?;

    let entry = &mut registry.entries[idx];

    // Copy the entry data before modifying state.
    let result = *entry;

    match entry.notify_type {
        NotifyType::None => {
            // SIGEV_NONE: no actual delivery, but registration is consumed.
            entry.state = NotifyState::Delivered;
            entry.in_use = false;
            registry.count = registry.count.saturating_sub(1);
        }
        NotifyType::Signal | NotifyType::Thread => {
            // Mark as pending delivery.
            entry.state = NotifyState::Pending;
            registry.enqueue_pending(idx);
        }
    }

    Some(result)
}

// ---------------------------------------------------------------------------
// check_pending — process pending notifications
// ---------------------------------------------------------------------------

/// Check for and dequeue the next pending notification.
///
/// Returns a copy of the next pending notification entry, or `None` if
/// no notifications are pending.  The returned entry's registration is
/// removed from the registry.
///
/// In a real kernel, this would be called by the signal delivery path
/// or the thread creation path to actually deliver the notification.
pub fn check_pending(registry: &mut NotifyRegistry) -> Option<MqNotifyEntry> {
    let entry_idx = registry.dequeue_pending()?;

    if !registry.entries[entry_idx].in_use {
        return None;
    }

    let entry = &mut registry.entries[entry_idx];
    if entry.state != NotifyState::Pending {
        return None;
    }

    let result = *entry;

    // After delivery, remove the registration.
    entry.state = NotifyState::Delivered;
    entry.in_use = false;
    registry.count = registry.count.saturating_sub(1);

    Some(result)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- NotifyType ---

    #[test]
    fn notify_type_valid() {
        assert_eq!(NotifyType::from_i32(0).unwrap(), NotifyType::None);
        assert_eq!(NotifyType::from_i32(1).unwrap(), NotifyType::Signal);
        assert_eq!(NotifyType::from_i32(2).unwrap(), NotifyType::Thread);
    }

    #[test]
    fn notify_type_invalid() {
        assert_eq!(NotifyType::from_i32(3), Err(Error::InvalidArgument));
    }

    // --- register_notify ---

    #[test]
    fn register_signal_notification() {
        let mut reg = NotifyRegistry::new();
        register_notify(
            &mut reg,
            0,
            1,
            100,
            NotifyType::Signal,
            SignalInfo::new(10, 42),
        )
        .unwrap();
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn register_none_notification() {
        let mut reg = NotifyRegistry::new();
        register_notify(&mut reg, 0, 1, 100, NotifyType::None, SignalInfo::default()).unwrap();
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn register_signal_bad_signo() {
        let mut reg = NotifyRegistry::new();
        assert_eq!(
            register_notify(
                &mut reg,
                0,
                1,
                100,
                NotifyType::Signal,
                SignalInfo::new(0, 0),
            ),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn register_duplicate_different_pid_ebusy() {
        let mut reg = NotifyRegistry::new();
        register_notify(&mut reg, 0, 1, 100, NotifyType::None, SignalInfo::default()).unwrap();
        assert_eq!(
            register_notify(&mut reg, 0, 1, 200, NotifyType::None, SignalInfo::default(),),
            Err(Error::Busy)
        );
    }

    #[test]
    fn register_same_pid_updates() {
        let mut reg = NotifyRegistry::new();
        register_notify(&mut reg, 0, 1, 100, NotifyType::None, SignalInfo::default()).unwrap();
        register_notify(
            &mut reg,
            0,
            1,
            100,
            NotifyType::Signal,
            SignalInfo::new(10, 0),
        )
        .unwrap();
        assert_eq!(reg.count(), 1);
    }

    // --- unregister_notify ---

    #[test]
    fn unregister_existing() {
        let mut reg = NotifyRegistry::new();
        register_notify(&mut reg, 0, 1, 100, NotifyType::None, SignalInfo::default()).unwrap();
        unregister_notify(&mut reg, 0, 1, 100).unwrap();
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn unregister_nonexistent() {
        let mut reg = NotifyRegistry::new();
        assert_eq!(unregister_notify(&mut reg, 0, 1, 100), Err(Error::NotFound));
    }

    #[test]
    fn unregister_wrong_pid() {
        let mut reg = NotifyRegistry::new();
        register_notify(&mut reg, 0, 1, 100, NotifyType::None, SignalInfo::default()).unwrap();
        assert_eq!(unregister_notify(&mut reg, 0, 1, 200), Err(Error::NotFound));
    }

    // --- deliver_notification ---

    #[test]
    fn deliver_signal_notification() {
        let mut reg = NotifyRegistry::new();
        register_notify(
            &mut reg,
            5,
            2,
            100,
            NotifyType::Signal,
            SignalInfo::new(10, 42),
        )
        .unwrap();
        let entry = deliver_notification(&mut reg, 5, 2, false).unwrap();
        assert_eq!(entry.pid, 100);
        assert_eq!(entry.notify_type, NotifyType::Signal);
        assert_eq!(entry.signal.signo, 10);
        assert_eq!(reg.pending_count(), 1);
    }

    #[test]
    fn deliver_none_notification_removes_registration() {
        let mut reg = NotifyRegistry::new();
        register_notify(&mut reg, 5, 2, 100, NotifyType::None, SignalInfo::default()).unwrap();
        let entry = deliver_notification(&mut reg, 5, 2, false).unwrap();
        assert_eq!(entry.notify_type, NotifyType::None);
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn deliver_suppressed_when_receiver_blocked() {
        let mut reg = NotifyRegistry::new();
        register_notify(
            &mut reg,
            5,
            2,
            100,
            NotifyType::Signal,
            SignalInfo::new(10, 0),
        )
        .unwrap();
        let result = deliver_notification(&mut reg, 5, 2, true);
        assert!(result.is_none());
        // Registration should still be active.
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn deliver_no_registration() {
        let mut reg = NotifyRegistry::new();
        assert!(deliver_notification(&mut reg, 5, 2, false).is_none());
    }

    #[test]
    fn deliver_wrong_generation() {
        let mut reg = NotifyRegistry::new();
        register_notify(
            &mut reg,
            5,
            1,
            100,
            NotifyType::Signal,
            SignalInfo::new(10, 0),
        )
        .unwrap();
        assert!(deliver_notification(&mut reg, 5, 2, false).is_none());
    }

    // --- check_pending ---

    #[test]
    fn check_pending_after_deliver() {
        let mut reg = NotifyRegistry::new();
        register_notify(
            &mut reg,
            5,
            2,
            100,
            NotifyType::Signal,
            SignalInfo::new(10, 42),
        )
        .unwrap();
        deliver_notification(&mut reg, 5, 2, false);
        let entry = check_pending(&mut reg).unwrap();
        assert_eq!(entry.pid, 100);
        assert_eq!(entry.signal.value, 42);
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn check_pending_empty() {
        let mut reg = NotifyRegistry::new();
        assert!(check_pending(&mut reg).is_none());
    }

    #[test]
    fn check_pending_multiple() {
        let mut reg = NotifyRegistry::new();
        register_notify(
            &mut reg,
            1,
            1,
            100,
            NotifyType::Signal,
            SignalInfo::new(10, 1),
        )
        .unwrap();
        register_notify(
            &mut reg,
            2,
            1,
            200,
            NotifyType::Signal,
            SignalInfo::new(11, 2),
        )
        .unwrap();
        deliver_notification(&mut reg, 1, 1, false);
        deliver_notification(&mut reg, 2, 1, false);

        let first = check_pending(&mut reg).unwrap();
        assert_eq!(first.signal.value, 1);
        let second = check_pending(&mut reg).unwrap();
        assert_eq!(second.signal.value, 2);
        assert!(check_pending(&mut reg).is_none());
    }

    // --- Registration after delivery allows re-registration ---

    #[test]
    fn re_register_after_delivery() {
        let mut reg = NotifyRegistry::new();
        register_notify(&mut reg, 5, 2, 100, NotifyType::None, SignalInfo::default()).unwrap();
        deliver_notification(&mut reg, 5, 2, false);
        // After delivery, another process can register.
        register_notify(&mut reg, 5, 2, 200, NotifyType::None, SignalInfo::default()).unwrap();
        assert_eq!(reg.count(), 1);
    }
}
