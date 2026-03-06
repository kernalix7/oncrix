// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Quota netlink notifications.
//!
//! Implements a netlink-style quota event notification subsystem that
//! broadcasts quota warnings and violations to registered listeners.
//! When a process exceeds its soft or hard limit, a [`QuotaEvent`] is
//! generated and delivered to all subscribed notification sinks.
//!
//! # Architecture
//!
//! ```text
//! QuotaNotifier (global)
//!   → event queue (ring buffer, MAX_EVENTS slots)
//!     → QuotaListener table (MAX_LISTENERS subscriptions)
//!       → per-listener pending queue
//!         → poll / read interface
//! ```
//!
//! # Structures
//!
//! - [`QuotaEventType`]   — event kind (warning, exceeded, grace expiry, …)
//! - [`QuotaEvent`]       — a single quota notification message
//! - [`ListenerFilter`]   — subscription filter (fs, quota type, uid/gid)
//! - [`QuotaListener`]    — a registered notification consumer
//! - [`QuotaNotifier`]    — global event dispatcher with ring buffer
//! - [`NetlinkQuotaSocket`] — socket-like interface for user-space delivery
//!
//! # References
//!
//! - Linux `fs/quota/netlink.c`, `include/linux/quota.h`
//! - `QUOTA_NL_*` netlink quota commands

use oncrix_lib::{Error, Result};

// ── Constants ───────────────────────────────────────────────────────────────

/// Maximum events held in the global ring buffer before oldest are dropped.
pub const MAX_EVENTS: usize = 256;

/// Maximum number of concurrent quota listeners.
pub const MAX_LISTENERS: usize = 32;

/// Maximum events queued per listener before the oldest is dropped.
pub const MAX_LISTENER_QUEUE: usize = 64;

/// Maximum filesystem path length for filtering.
pub const MAX_FS_PATH: usize = 128;

/// Netlink quota multicast group number (mirrors Linux QUOTA_NL_GRP).
pub const QUOTA_NL_GRP: u32 = 1;

// ── QuotaEventType ──────────────────────────────────────────────────────────

/// Classification of a quota notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum QuotaEventType {
    /// Usage is approaching the soft limit (warning threshold).
    #[default]
    SoftWarn = 0,
    /// Usage has crossed the soft limit; grace period started.
    SoftExceeded = 1,
    /// Grace period for the soft limit has expired.
    GraceExpired = 2,
    /// Usage has reached the hard block limit.
    HardBlockExceeded = 3,
    /// Usage has reached the hard inode limit.
    HardInodeExceeded = 4,
    /// Quota was reset or limits were changed by the administrator.
    LimitsChanged = 5,
    /// Quota accounting was enabled on a filesystem.
    QuotaEnabled = 6,
    /// Quota accounting was disabled on a filesystem.
    QuotaDisabled = 7,
}

// ── QuotaType ───────────────────────────────────────────────────────────────

/// Identifies whose quota triggered the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum QuotaTypeNl {
    /// Per-user quota.
    #[default]
    User = 0,
    /// Per-group quota.
    Group = 1,
    /// Per-project quota.
    Project = 2,
}

// ── QuotaEvent ──────────────────────────────────────────────────────────────

/// A single quota notification message.
#[derive(Debug, Clone, Copy)]
pub struct QuotaEvent {
    /// Sequential event identifier (monotonically increasing).
    pub seq: u64,
    /// Timestamp (nanoseconds since boot).
    pub timestamp_ns: u64,
    /// Kind of event.
    pub event_type: QuotaEventType,
    /// Quota type (user / group / project).
    pub quota_type: QuotaTypeNl,
    /// ID of the affected entity (uid, gid, or project ID).
    pub id: u32,
    /// Filesystem device number (major << 20 | minor).
    pub dev: u32,
    /// Current block usage in 1 KiB units.
    pub block_usage: u64,
    /// Soft block limit in 1 KiB units.
    pub block_softlimit: u64,
    /// Hard block limit in 1 KiB units.
    pub block_hardlimit: u64,
    /// Current inode usage.
    pub inode_usage: u64,
    /// Soft inode limit.
    pub inode_softlimit: u64,
    /// Hard inode limit.
    pub inode_hardlimit: u64,
    /// Grace deadline (0 = not running).
    pub grace_deadline: u64,
}

impl Default for QuotaEvent {
    fn default() -> Self {
        Self {
            seq: 0,
            timestamp_ns: 0,
            event_type: QuotaEventType::SoftWarn,
            quota_type: QuotaTypeNl::User,
            id: 0,
            dev: 0,
            block_usage: 0,
            block_softlimit: 0,
            block_hardlimit: 0,
            inode_usage: 0,
            inode_softlimit: 0,
            inode_hardlimit: 0,
            grace_deadline: 0,
        }
    }
}

// ── ListenerFilter ──────────────────────────────────────────────────────────

/// Subscription filter that selects which events a listener receives.
#[derive(Debug, Clone, Copy)]
pub struct ListenerFilter {
    /// Match only events for a specific filesystem device (0 = any).
    pub dev: u32,
    /// Match only this quota type (None = all types).
    pub quota_type: Option<QuotaTypeNl>,
    /// Match only this entity ID (0 = all).
    pub id: u32,
    /// Minimum severity: events with type index < this are skipped.
    pub min_event_type: u32,
}

impl Default for ListenerFilter {
    fn default() -> Self {
        Self {
            dev: 0,
            quota_type: None,
            id: 0,
            min_event_type: 0,
        }
    }
}

impl ListenerFilter {
    /// Returns `true` if the given event passes this filter.
    pub fn matches(&self, event: &QuotaEvent) -> bool {
        if self.dev != 0 && self.dev != event.dev {
            return false;
        }
        if let Some(qt) = self.quota_type {
            if qt != event.quota_type {
                return false;
            }
        }
        if self.id != 0 && self.id != event.id {
            return false;
        }
        if (event.event_type as u32) < self.min_event_type {
            return false;
        }
        true
    }
}

// ── QuotaListener ───────────────────────────────────────────────────────────

/// A registered consumer of quota events.
#[derive(Debug)]
pub struct QuotaListener {
    /// Unique listener ID.
    pub id: u32,
    /// Whether this listener is active.
    active: bool,
    /// Subscription filter.
    pub filter: ListenerFilter,
    /// Ring buffer of pending events for this listener.
    queue: [Option<QuotaEvent>; MAX_LISTENER_QUEUE],
    /// Write index into the ring buffer.
    write_idx: usize,
    /// Read index into the ring buffer.
    read_idx: usize,
    /// Number of events currently in the queue.
    queued: usize,
    /// Number of events dropped due to queue overflow.
    pub dropped: u64,
}

impl Default for QuotaListener {
    fn default() -> Self {
        Self {
            id: 0,
            active: false,
            filter: ListenerFilter::default(),
            queue: [const { None }; MAX_LISTENER_QUEUE],
            write_idx: 0,
            read_idx: 0,
            queued: 0,
            dropped: 0,
        }
    }
}

impl QuotaListener {
    /// Push an event into this listener's queue, dropping the oldest if full.
    fn push(&mut self, event: QuotaEvent) {
        if self.queued == MAX_LISTENER_QUEUE {
            // Drop oldest.
            self.read_idx = (self.read_idx + 1) % MAX_LISTENER_QUEUE;
            self.queued -= 1;
            self.dropped += 1;
        }
        self.queue[self.write_idx] = Some(event);
        self.write_idx = (self.write_idx + 1) % MAX_LISTENER_QUEUE;
        self.queued += 1;
    }

    /// Pop the oldest event from this listener's queue.
    pub fn pop(&mut self) -> Option<QuotaEvent> {
        if self.queued == 0 {
            return None;
        }
        let event = self.queue[self.read_idx].take();
        self.read_idx = (self.read_idx + 1) % MAX_LISTENER_QUEUE;
        self.queued -= 1;
        event
    }

    /// Returns the number of events pending in this listener's queue.
    pub fn pending(&self) -> usize {
        self.queued
    }
}

// ── GlobalRingBuffer ────────────────────────────────────────────────────────

/// Global event ring buffer shared across all listeners.
struct GlobalRingBuffer {
    events: [Option<QuotaEvent>; MAX_EVENTS],
    write_idx: usize,
    count: u64,
}

impl Default for GlobalRingBuffer {
    fn default() -> Self {
        Self {
            events: [const { None }; MAX_EVENTS],
            write_idx: 0,
            count: 0,
        }
    }
}

impl GlobalRingBuffer {
    /// Append an event, overwriting the oldest slot when full.
    fn push(&mut self, event: QuotaEvent) -> usize {
        let slot = self.write_idx % MAX_EVENTS;
        self.events[slot] = Some(event);
        self.write_idx = (slot + 1) % MAX_EVENTS;
        self.count += 1;
        slot
    }
}

// ── QuotaNotifier ───────────────────────────────────────────────────────────

/// Global quota event dispatcher.
pub struct QuotaNotifier {
    /// Global event ring buffer.
    ring: GlobalRingBuffer,
    /// Registered listeners.
    listeners: [Option<QuotaListener>; MAX_LISTENERS],
    /// Next listener ID to assign.
    next_id: u32,
    /// Global event sequence counter.
    next_seq: u64,
    /// Timestamp source (nanoseconds since boot, caller-supplied).
    now_ns: u64,
    /// Total events dispatched since creation.
    pub total_dispatched: u64,
}

impl Default for QuotaNotifier {
    fn default() -> Self {
        Self::new()
    }
}

impl QuotaNotifier {
    /// Create a new, empty notifier.
    pub fn new() -> Self {
        Self {
            ring: GlobalRingBuffer::default(),
            listeners: [const { None }; MAX_LISTENERS],
            next_id: 1,
            next_seq: 0,
            now_ns: 0,
            total_dispatched: 0,
        }
    }

    /// Update the internal clock (nanoseconds since boot).
    pub fn set_clock(&mut self, now_ns: u64) {
        self.now_ns = now_ns;
    }

    /// Register a new listener with the given filter.
    ///
    /// Returns the listener ID on success, or [`Error::OutOfMemory`] when the
    /// listener table is full.
    pub fn subscribe(&mut self, filter: ListenerFilter) -> Result<u32> {
        let slot = self
            .listeners
            .iter()
            .position(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id += 1;

        let mut listener = QuotaListener::default();
        listener.id = id;
        listener.active = true;
        listener.filter = filter;
        self.listeners[slot] = Some(listener);
        Ok(id)
    }

    /// Unsubscribe a listener by ID.
    ///
    /// Returns [`Error::NotFound`] if no matching listener exists.
    pub fn unsubscribe(&mut self, id: u32) -> Result<()> {
        let slot = self
            .listeners
            .iter()
            .position(|s| s.as_ref().is_some_and(|l| l.id == id))
            .ok_or(Error::NotFound)?;
        self.listeners[slot] = None;
        Ok(())
    }

    /// Dispatch a quota event to all matching listeners and the global ring.
    ///
    /// Fills in the sequence number and timestamp automatically.
    pub fn dispatch(&mut self, mut event: QuotaEvent) {
        event.seq = self.next_seq;
        event.timestamp_ns = self.now_ns;
        self.next_seq += 1;
        self.ring.push(event);
        self.total_dispatched += 1;

        for slot in self.listeners.iter_mut().flatten() {
            if slot.active && slot.filter.matches(&event) {
                slot.push(event);
            }
        }
    }

    /// Read the next pending event for the given listener.
    ///
    /// Returns [`Error::WouldBlock`] if no events are pending.
    pub fn read_event(&mut self, listener_id: u32) -> Result<QuotaEvent> {
        let slot = self
            .listeners
            .iter_mut()
            .find(|s| s.as_ref().is_some_and(|l| l.id == listener_id))
            .ok_or(Error::NotFound)?;

        let listener = slot.as_mut().ok_or(Error::NotFound)?;
        listener.pop().ok_or(Error::WouldBlock)
    }

    /// Returns the number of pending events for a listener.
    ///
    /// Returns [`Error::NotFound`] if the listener does not exist.
    pub fn pending_count(&self, listener_id: u32) -> Result<usize> {
        self.listeners
            .iter()
            .find(|s| s.as_ref().is_some_and(|l| l.id == listener_id))
            .ok_or(Error::NotFound)?
            .as_ref()
            .map(|l| l.pending())
            .ok_or(Error::NotFound)
    }

    /// Returns the total number of events stored in the global ring.
    pub fn ring_count(&self) -> u64 {
        self.ring.count
    }
}

// ── NetlinkQuotaSocket ──────────────────────────────────────────────────────

/// Socket-like handle for receiving quota notifications.
///
/// Wraps a listener ID and provides `read` / `poll` semantics matching
/// a datagram socket.
#[derive(Debug)]
pub struct NetlinkQuotaSocket {
    /// Listener ID inside the global notifier.
    pub listener_id: u32,
    /// Whether the socket is still open.
    open: bool,
}

impl NetlinkQuotaSocket {
    /// Open a new quota netlink socket with the given filter.
    pub fn open(notifier: &mut QuotaNotifier, filter: ListenerFilter) -> Result<Self> {
        let listener_id = notifier.subscribe(filter)?;
        Ok(Self {
            listener_id,
            open: true,
        })
    }

    /// Close the socket, deregistering from the notifier.
    pub fn close(&mut self, notifier: &mut QuotaNotifier) -> Result<()> {
        if !self.open {
            return Err(Error::InvalidArgument);
        }
        notifier.unsubscribe(self.listener_id)?;
        self.open = false;
        Ok(())
    }

    /// Read the next event from this socket.
    ///
    /// Returns [`Error::WouldBlock`] if no event is pending.
    /// Returns [`Error::InvalidArgument`] if the socket is closed.
    pub fn read(&self, notifier: &mut QuotaNotifier) -> Result<QuotaEvent> {
        if !self.open {
            return Err(Error::InvalidArgument);
        }
        notifier.read_event(self.listener_id)
    }

    /// Returns the number of events pending on this socket.
    pub fn poll(&self, notifier: &QuotaNotifier) -> Result<usize> {
        if !self.open {
            return Err(Error::InvalidArgument);
        }
        notifier.pending_count(self.listener_id)
    }
}

// ── Helper ──────────────────────────────────────────────────────────────────

/// Build a [`QuotaEvent`] for a block hard-limit violation.
///
/// Convenience constructor for the most common case (hard block exceeded).
pub fn block_hard_exceeded(
    dev: u32,
    quota_type: QuotaTypeNl,
    id: u32,
    block_usage: u64,
    block_softlimit: u64,
    block_hardlimit: u64,
) -> QuotaEvent {
    QuotaEvent {
        event_type: QuotaEventType::HardBlockExceeded,
        quota_type,
        id,
        dev,
        block_usage,
        block_softlimit,
        block_hardlimit,
        ..QuotaEvent::default()
    }
}

/// Build a [`QuotaEvent`] for a grace-period expiry.
pub fn grace_expired(dev: u32, quota_type: QuotaTypeNl, id: u32, deadline: u64) -> QuotaEvent {
    QuotaEvent {
        event_type: QuotaEventType::GraceExpired,
        quota_type,
        id,
        dev,
        grace_deadline: deadline,
        ..QuotaEvent::default()
    }
}

// ── Statistics ───────────────────────────────────────────────────────────────

/// Aggregated statistics reported by [`QuotaNotifier`].
#[derive(Debug, Clone, Copy, Default)]
pub struct NotifierStats {
    /// Total events dispatched since creation.
    pub total_dispatched: u64,
    /// Total events stored in the global ring buffer.
    pub ring_count: u64,
    /// Number of active listeners.
    pub active_listeners: usize,
}

impl QuotaNotifier {
    /// Snapshot current statistics.
    pub fn stats(&self) -> NotifierStats {
        let active_listeners = self.listeners.iter().filter(|s| s.is_some()).count();
        NotifierStats {
            total_dispatched: self.total_dispatched,
            ring_count: self.ring.count,
            active_listeners,
        }
    }
}
