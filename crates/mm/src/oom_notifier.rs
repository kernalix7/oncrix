// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! OOM notification chain.
//!
//! Provides a notification mechanism for out-of-memory events. Kernel
//! subsystems and user-space (via eventfd/cgroup) can register
//! callbacks that fire when memory pressure reaches critical levels.
//! Listeners can respond by releasing caches, killing low-priority
//! tasks, or logging diagnostics.
//!
//! # Design
//!
//! ```text
//!  OOM condition detected
//!       │
//!       ▼
//!  ┌──────────────────┐
//!  │  OomNotifier      │
//!  │  notify_all()     │
//!  └──────┬───────────┘
//!         │
//!   ┌─────┼─────────────┐
//!   ▼     ▼             ▼
//! listener0  listener1  listener2
//! (cache)    (log)      (kill)
//! ```
//!
//! # Key Types
//!
//! - [`OomLevel`] — severity of the OOM event
//! - [`OomListener`] — a registered notification listener
//! - [`OomNotifier`] — the notification chain manager
//! - [`OomEvent`] — an OOM event delivered to listeners
//!
//! Reference: Linux `mm/oom_kill.c`, `include/linux/oom.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum registered listeners.
const MAX_LISTENERS: usize = 64;

/// Maximum events in the event log.
const MAX_EVENT_LOG: usize = 128;

// -------------------------------------------------------------------
// OomLevel
// -------------------------------------------------------------------

/// Severity level of an OOM event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OomLevel {
    /// Low pressure — caches should be trimmed.
    Low,
    /// Medium pressure — aggressive reclaim needed.
    Medium,
    /// Critical — OOM killer will be invoked.
    Critical,
}

impl Default for OomLevel {
    fn default() -> Self {
        Self::Low
    }
}

// -------------------------------------------------------------------
// OomAction
// -------------------------------------------------------------------

/// Suggested action for a listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OomAction {
    /// No action taken.
    None,
    /// Freed some memory (report amount).
    Freed(u64),
    /// Deferred to a later handler.
    Deferred,
    /// Vetoed the OOM kill (e.g., cgroup is being deleted).
    Vetoed,
}

impl Default for OomAction {
    fn default() -> Self {
        Self::None
    }
}

// -------------------------------------------------------------------
// OomEvent
// -------------------------------------------------------------------

/// An OOM event delivered to listeners.
#[derive(Debug, Clone, Copy)]
pub struct OomEvent {
    /// Sequence number.
    pub sequence: u64,
    /// Severity level.
    pub level: OomLevel,
    /// Affected cgroup ID (0 = global).
    pub cgroup_id: u64,
    /// Free pages at the time of the event.
    pub free_pages: u64,
    /// Total pages.
    pub total_pages: u64,
}

impl OomEvent {
    /// Creates a new event.
    pub const fn new(
        sequence: u64,
        level: OomLevel,
        cgroup_id: u64,
        free_pages: u64,
        total_pages: u64,
    ) -> Self {
        Self {
            sequence,
            level,
            cgroup_id,
            free_pages,
            total_pages,
        }
    }

    /// Returns the memory pressure ratio (0..100).
    pub const fn pressure_percent(&self) -> u64 {
        if self.total_pages == 0 {
            return 100;
        }
        (self.total_pages - self.free_pages) * 100 / self.total_pages
    }
}

impl Default for OomEvent {
    fn default() -> Self {
        Self::new(0, OomLevel::Low, 0, 0, 0)
    }
}

// -------------------------------------------------------------------
// OomListener
// -------------------------------------------------------------------

/// A registered OOM notification listener.
#[derive(Debug, Clone, Copy)]
pub struct OomListener {
    /// Listener identifier.
    id: u64,
    /// Minimum level to trigger notification.
    min_level: OomLevel,
    /// Cgroup filter (0 = all cgroups).
    cgroup_filter: u64,
    /// Priority (higher = called first).
    priority: i32,
    /// Total notifications received.
    notifications: u64,
    /// Whether this listener is active.
    active: bool,
}

impl OomListener {
    /// Creates a new listener.
    pub const fn new(id: u64, min_level: OomLevel, priority: i32) -> Self {
        Self {
            id,
            min_level,
            cgroup_filter: 0,
            priority,
            notifications: 0,
            active: true,
        }
    }

    /// Creates an empty listener.
    pub const fn empty() -> Self {
        Self {
            id: 0,
            min_level: OomLevel::Low,
            cgroup_filter: 0,
            priority: 0,
            notifications: 0,
            active: false,
        }
    }

    /// Returns the listener ID.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Returns the minimum level.
    pub const fn min_level(&self) -> OomLevel {
        self.min_level
    }

    /// Returns the priority.
    pub const fn priority(&self) -> i32 {
        self.priority
    }

    /// Returns total notifications received.
    pub const fn notifications(&self) -> u64 {
        self.notifications
    }

    /// Returns `true` if this listener should be notified for the event.
    pub fn should_notify(&self, event: &OomEvent) -> bool {
        if !self.active {
            return false;
        }
        if (event.level as u8) < (self.min_level as u8) {
            return false;
        }
        if self.cgroup_filter != 0 && self.cgroup_filter != event.cgroup_id {
            return false;
        }
        true
    }
}

impl Default for OomListener {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// OomNotifier
// -------------------------------------------------------------------

/// The OOM notification chain manager.
pub struct OomNotifier {
    /// Registered listeners.
    listeners: [OomListener; MAX_LISTENERS],
    /// Number of active listeners.
    count: usize,
    /// Event log.
    events: [OomEvent; MAX_EVENT_LOG],
    /// Number of logged events.
    event_count: usize,
    /// Next event sequence number.
    next_seq: u64,
}

impl OomNotifier {
    /// Creates a new notifier.
    pub const fn new() -> Self {
        Self {
            listeners: [const { OomListener::empty() }; MAX_LISTENERS],
            count: 0,
            events: [const { OomEvent::new(0, OomLevel::Low, 0, 0, 0) }; MAX_EVENT_LOG],
            event_count: 0,
            next_seq: 1,
        }
    }

    /// Returns the number of active listeners.
    pub const fn listener_count(&self) -> usize {
        self.count
    }

    /// Returns the number of logged events.
    pub const fn event_count(&self) -> usize {
        self.event_count
    }

    /// Registers a new listener.
    pub fn register(&mut self, listener: OomListener) -> Result<()> {
        // Check duplicate.
        for i in 0..self.count {
            if self.listeners[i].active && self.listeners[i].id == listener.id {
                return Err(Error::AlreadyExists);
            }
        }
        if self.count >= MAX_LISTENERS {
            return Err(Error::OutOfMemory);
        }
        self.listeners[self.count] = listener;
        self.count += 1;

        // Sort by priority (descending).
        for i in 1..self.count {
            let mut j = i;
            while j > 0 && self.listeners[j].priority > self.listeners[j - 1].priority {
                self.listeners.swap(j, j - 1);
                j -= 1;
            }
        }

        Ok(())
    }

    /// Unregisters a listener by ID.
    pub fn unregister(&mut self, id: u64) -> Result<()> {
        for i in 0..self.count {
            if self.listeners[i].active && self.listeners[i].id == id {
                self.listeners[i].active = false;
                // Compact.
                let mut j = i;
                while j + 1 < self.count {
                    self.listeners[j] = self.listeners[j + 1];
                    j += 1;
                }
                self.count -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Fires an OOM notification to all matching listeners.
    ///
    /// Returns the number of listeners notified.
    pub fn notify(
        &mut self,
        level: OomLevel,
        cgroup_id: u64,
        free_pages: u64,
        total_pages: u64,
    ) -> usize {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let event = OomEvent::new(seq, level, cgroup_id, free_pages, total_pages);

        // Log the event.
        if self.event_count < MAX_EVENT_LOG {
            self.events[self.event_count] = event;
            self.event_count += 1;
        }

        // Notify listeners.
        let mut notified = 0;
        for i in 0..self.count {
            if self.listeners[i].should_notify(&event) {
                self.listeners[i].notifications = self.listeners[i].notifications.saturating_add(1);
                notified += 1;
            }
        }
        notified
    }

    /// Returns recent events.
    pub fn recent_events(&self) -> &[OomEvent] {
        &self.events[..self.event_count]
    }
}

impl Default for OomNotifier {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Creates a new OOM notifier.
pub fn create_notifier() -> OomNotifier {
    OomNotifier::new()
}

/// Fires an OOM notification, returning the count of listeners notified.
pub fn notify_oom(
    notifier: &mut OomNotifier,
    level: OomLevel,
    cgroup_id: u64,
    free_pages: u64,
    total_pages: u64,
) -> usize {
    notifier.notify(level, cgroup_id, free_pages, total_pages)
}

/// Registers an OOM listener.
pub fn register_listener(notifier: &mut OomNotifier, listener: OomListener) -> Result<()> {
    notifier.register(listener)
}
