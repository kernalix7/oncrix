// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! General notification / watch queue mechanism.
//!
//! Provides a generic event notification system where kernel subsystems
//! can post typed events to user-space watchers via a pipe-backed ring
//! buffer. Watchers can filter events by type using bitmask filters.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                      WatchQueueSubsystem                         │
//! │                                                                  │
//! │  Producers (kernel subsystems):                                  │
//! │    post_notification(queue_id, &notification)                    │
//! │                        │                                         │
//! │                        ▼                                         │
//! │  ┌─────────────────────────────────┐                             │
//! │  │         WatchQueue              │                             │
//! │  │  ring: [WatchNotification; CAP] │ ← ring buffer              │
//! │  │  head / tail / count            │                             │
//! │  │  filter: WatchFilter            │ ← bitmask by event type    │
//! │  │  overflow_count                 │                             │
//! │  └─────────────────────────────────┘                             │
//! │                        │                                         │
//! │                        ▼                                         │
//! │  Consumers (user-space watchers):                                │
//! │    dequeue_notification(queue_id) → WatchNotification            │
//! │                                                                  │
//! │  Fan-out: WatchGroup holds multiple queues for same event source │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Event Types
//!
//! Events are classified by `WatchEventType` (key change, mount change,
//! etc.) and carry a subtype plus an opaque 64-bit info field.
//!
//! # Reference
//!
//! Linux `kernel/watch_queue.c`, `include/linux/watch_queue.h`.

use oncrix_lib::{Error, Result};

extern crate alloc;
use alloc::vec::Vec;

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of watch queues in the system.
const MAX_QUEUES: usize = 256;

/// Maximum capacity of a single watch queue ring buffer.
const MAX_RING_CAPACITY: usize = 1024;

/// Default ring buffer capacity.
const DEFAULT_RING_CAPACITY: usize = 64;

/// Maximum number of watch groups (fan-out sets).
const MAX_GROUPS: usize = 64;

/// Maximum number of watchers per group.
const MAX_WATCHERS_PER_GROUP: usize = 16;

/// Number of event type bits in the filter bitmask.
const FILTER_BITS: usize = 64;

/// Maximum length of a queue name.
const MAX_NAME_LEN: usize = 32;

// ── Event Types ─────────────────────────────────────────────────────────────

/// Classification of watch events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WatchEventType {
    /// Key/keyring change notification.
    KeyChange = 0,
    /// Mount topology change.
    MountChange = 1,
    /// Superblock/filesystem event.
    SuperblockChange = 2,
    /// Device state change (add/remove/change).
    DeviceChange = 3,
    /// Process state change (exit, exec, etc.).
    ProcessChange = 4,
    /// Network interface change.
    NetChange = 5,
    /// Cgroup change.
    CgroupChange = 6,
    /// Timer expiration.
    TimerExpire = 7,
    /// Security/audit event.
    SecurityEvent = 8,
    /// Power management event.
    PowerEvent = 9,
    /// Memory pressure event.
    MemoryPressure = 10,
    /// Custom/user-defined event.
    Custom = 63,
}

impl WatchEventType {
    /// Convert from raw u8 value.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::KeyChange),
            1 => Some(Self::MountChange),
            2 => Some(Self::SuperblockChange),
            3 => Some(Self::DeviceChange),
            4 => Some(Self::ProcessChange),
            5 => Some(Self::NetChange),
            6 => Some(Self::CgroupChange),
            7 => Some(Self::TimerExpire),
            8 => Some(Self::SecurityEvent),
            9 => Some(Self::PowerEvent),
            10 => Some(Self::MemoryPressure),
            63 => Some(Self::Custom),
            _ => None,
        }
    }

    /// Get the bit index for filter matching.
    pub fn bit_index(self) -> usize {
        self as usize
    }
}

/// Event subtypes for more specific classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WatchEventSubtype {
    /// Generic / unspecified subtype.
    Generic = 0,
    /// Object was created.
    Created = 1,
    /// Object was modified.
    Modified = 2,
    /// Object was removed/destroyed.
    Removed = 3,
    /// Object was moved/renamed.
    Moved = 4,
    /// Access/permission change.
    AccessChange = 5,
    /// State transition (online/offline, up/down).
    StateChange = 6,
    /// Error or fault condition.
    Fault = 7,
}

impl WatchEventSubtype {
    /// Convert from raw u8 value.
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Generic),
            1 => Some(Self::Created),
            2 => Some(Self::Modified),
            3 => Some(Self::Removed),
            4 => Some(Self::Moved),
            5 => Some(Self::AccessChange),
            6 => Some(Self::StateChange),
            7 => Some(Self::Fault),
            _ => None,
        }
    }
}

// ── Notification ────────────────────────────────────────────────────────────

/// A single watch notification event.
///
/// This is the unit of data that flows through the watch queue.
/// Events are typed, carry a subtype for finer classification,
/// and include a 64-bit info field plus an optional object ID.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WatchNotification {
    /// Event type.
    pub event_type: u8,
    /// Event subtype.
    pub subtype: u8,
    /// Flags (reserved for future use).
    pub flags: u16,
    /// Sequence number (set by the queue on enqueue).
    pub sequence: u32,
    /// Primary information payload.
    pub info: u64,
    /// Object ID (key serial, mount ID, PID, etc.).
    pub object_id: u64,
    /// Timestamp (nanoseconds since boot or epoch).
    pub timestamp_ns: u64,
}

impl WatchNotification {
    /// Create a new notification.
    pub const fn new(
        event_type: WatchEventType,
        subtype: WatchEventSubtype,
        info: u64,
        object_id: u64,
    ) -> Self {
        Self {
            event_type: event_type as u8,
            subtype: subtype as u8,
            flags: 0,
            sequence: 0,
            info,
            object_id,
            timestamp_ns: 0,
        }
    }

    /// Create a new notification with timestamp.
    pub const fn with_timestamp(
        event_type: WatchEventType,
        subtype: WatchEventSubtype,
        info: u64,
        object_id: u64,
        timestamp_ns: u64,
    ) -> Self {
        Self {
            event_type: event_type as u8,
            subtype: subtype as u8,
            flags: 0,
            sequence: 0,
            info,
            object_id,
            timestamp_ns,
        }
    }

    /// Get the event type enum.
    pub fn get_event_type(&self) -> Option<WatchEventType> {
        WatchEventType::from_u8(self.event_type)
    }

    /// Get the subtype enum.
    pub fn get_subtype(&self) -> Option<WatchEventSubtype> {
        WatchEventSubtype::from_u8(self.subtype)
    }
}

// ── Watch Filter ────────────────────────────────────────────────────────────

/// Bitmask filter for event types.
///
/// Each bit position corresponds to a `WatchEventType` value.
/// Only events whose type bit is set in the filter will be enqueued.
#[derive(Debug, Clone, Copy)]
pub struct WatchFilter {
    /// Bitmask of accepted event types.
    type_mask: u64,
    /// Whether to also filter by subtype (per event type).
    subtype_filters: [u8; FILTER_BITS],
    /// Whether subtype filtering is enabled for each type.
    subtype_filter_active: u64,
}

impl WatchFilter {
    /// Create a filter that accepts all events.
    pub const fn accept_all() -> Self {
        Self {
            type_mask: u64::MAX,
            subtype_filters: [0xff; FILTER_BITS],
            subtype_filter_active: 0,
        }
    }

    /// Create a filter that accepts no events.
    pub const fn accept_none() -> Self {
        Self {
            type_mask: 0,
            subtype_filters: [0u8; FILTER_BITS],
            subtype_filter_active: 0,
        }
    }

    /// Enable a specific event type in the filter.
    pub fn enable_type(&mut self, event_type: WatchEventType) {
        let bit = event_type.bit_index();
        if bit < FILTER_BITS {
            self.type_mask |= 1u64 << bit;
        }
    }

    /// Disable a specific event type in the filter.
    pub fn disable_type(&mut self, event_type: WatchEventType) {
        let bit = event_type.bit_index();
        if bit < FILTER_BITS {
            self.type_mask &= !(1u64 << bit);
        }
    }

    /// Enable subtype filtering for an event type.
    pub fn set_subtype_filter(&mut self, event_type: WatchEventType, subtype_mask: u8) {
        let bit = event_type.bit_index();
        if bit < FILTER_BITS {
            self.subtype_filters[bit] = subtype_mask;
            self.subtype_filter_active |= 1u64 << bit;
        }
    }

    /// Check if a notification passes this filter.
    pub fn matches(&self, notif: &WatchNotification) -> bool {
        let type_bit = notif.event_type as usize;
        if type_bit >= FILTER_BITS {
            return false;
        }
        // Check type mask
        if self.type_mask & (1u64 << type_bit) == 0 {
            return false;
        }
        // Check subtype filter if active
        if self.subtype_filter_active & (1u64 << type_bit) != 0 {
            let subtype_bit = notif.subtype;
            if subtype_bit >= 8 {
                return false;
            }
            if self.subtype_filters[type_bit] & (1u8 << subtype_bit) == 0 {
                return false;
            }
        }
        true
    }

    /// Get the current type mask.
    pub fn type_mask(&self) -> u64 {
        self.type_mask
    }
}

// ── Watch Queue ─────────────────────────────────────────────────────────────

/// State of a watch queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueState {
    /// Queue is active and accepting events.
    Active,
    /// Queue is paused (events are dropped silently).
    Paused,
    /// Queue is closed and will be freed.
    Closed,
}

/// A single pipe-backed watch queue (ring buffer).
pub struct WatchQueue {
    /// Whether this queue slot is in use.
    active: bool,
    /// Queue ID.
    queue_id: u32,
    /// Queue name for debugging.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Ring buffer of notifications.
    ring: Vec<WatchNotification>,
    /// Ring buffer capacity.
    capacity: usize,
    /// Read position (consumer).
    head: usize,
    /// Write position (producer).
    tail: usize,
    /// Number of events currently in the ring.
    count: usize,
    /// Next sequence number to assign.
    next_sequence: u32,
    /// Event filter.
    filter: WatchFilter,
    /// Queue state.
    state: QueueState,
    /// Pipe file descriptor (for user-space notification).
    pipe_fd: i32,
    /// Overflow counter (events dropped because ring was full).
    overflow_count: u64,
    /// Total events enqueued.
    total_enqueued: u64,
    /// Total events dequeued.
    total_dequeued: u64,
    /// Total events filtered out.
    total_filtered: u64,
}

impl WatchQueue {
    /// Create a new watch queue with default capacity.
    pub fn new(queue_id: u32, pipe_fd: i32) -> Self {
        let capacity = DEFAULT_RING_CAPACITY;
        let mut ring = Vec::new();
        ring.resize(
            capacity,
            WatchNotification::new(WatchEventType::KeyChange, WatchEventSubtype::Generic, 0, 0),
        );
        Self {
            active: true,
            queue_id,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            ring,
            capacity,
            head: 0,
            tail: 0,
            count: 0,
            next_sequence: 0,
            filter: WatchFilter::accept_all(),
            state: QueueState::Active,
            pipe_fd,
            overflow_count: 0,
            total_enqueued: 0,
            total_dequeued: 0,
            total_filtered: 0,
        }
    }

    /// Create a new watch queue with specified capacity.
    pub fn with_capacity(queue_id: u32, pipe_fd: i32, capacity: usize) -> Result<Self> {
        if capacity == 0 || capacity > MAX_RING_CAPACITY {
            return Err(Error::InvalidArgument);
        }
        // Round up to power of 2 for efficient modulo
        let cap = capacity.next_power_of_two();
        let mut ring = Vec::new();
        ring.resize(
            cap,
            WatchNotification::new(WatchEventType::KeyChange, WatchEventSubtype::Generic, 0, 0),
        );
        Ok(Self {
            active: true,
            queue_id,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            ring,
            capacity: cap,
            head: 0,
            tail: 0,
            count: 0,
            next_sequence: 0,
            filter: WatchFilter::accept_all(),
            state: QueueState::Active,
            pipe_fd,
            overflow_count: 0,
            total_enqueued: 0,
            total_dequeued: 0,
            total_filtered: 0,
        })
    }

    /// Set the queue name for debugging.
    pub fn set_name(&mut self, name: &[u8]) -> Result<()> {
        if name.len() >= MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        self.name[..name.len()].copy_from_slice(name);
        self.name_len = name.len();
        Ok(())
    }

    /// Get the queue ID.
    pub fn queue_id(&self) -> u32 {
        self.queue_id
    }

    /// Get the pipe file descriptor.
    pub fn pipe_fd(&self) -> i32 {
        self.pipe_fd
    }

    /// Get the current queue state.
    pub fn state(&self) -> QueueState {
        self.state
    }

    /// Set the event filter.
    pub fn set_filter(&mut self, filter: WatchFilter) {
        self.filter = filter;
    }

    /// Get the current filter.
    pub fn filter(&self) -> &WatchFilter {
        &self.filter
    }

    /// Check if the ring buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check if the ring buffer is full.
    pub fn is_full(&self) -> bool {
        self.count >= self.capacity
    }

    /// Get the number of events in the queue.
    pub fn pending_count(&self) -> usize {
        self.count
    }

    /// Get the ring buffer capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Pause the queue (events will be silently dropped).
    pub fn pause(&mut self) {
        self.state = QueueState::Paused;
    }

    /// Resume the queue.
    pub fn resume(&mut self) {
        if self.state == QueueState::Paused {
            self.state = QueueState::Active;
        }
    }

    /// Close the queue permanently.
    pub fn close(&mut self) {
        self.state = QueueState::Closed;
    }

    /// Post a notification to this queue.
    ///
    /// The notification is filtered, assigned a sequence number,
    /// and enqueued. Returns `Ok(true)` if enqueued, `Ok(false)` if
    /// filtered out, or `Err` on overflow.
    pub fn post(&mut self, notif: &WatchNotification) -> Result<bool> {
        if self.state != QueueState::Active {
            return Err(Error::WouldBlock);
        }
        // Apply filter
        if !self.filter.matches(notif) {
            self.total_filtered += 1;
            return Ok(false);
        }
        // Check for overflow
        if self.is_full() {
            self.overflow_count += 1;
            return Err(Error::WouldBlock);
        }
        // Enqueue with sequence number
        let mut event = *notif;
        event.sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        self.ring[self.tail] = event;
        self.tail = (self.tail + 1) % self.capacity;
        self.count += 1;
        self.total_enqueued += 1;
        Ok(true)
    }

    /// Dequeue the next notification from the queue.
    pub fn dequeue(&mut self) -> Option<WatchNotification> {
        if self.count == 0 {
            return None;
        }
        let notif = self.ring[self.head];
        self.head = (self.head + 1) % self.capacity;
        self.count -= 1;
        self.total_dequeued += 1;
        Some(notif)
    }

    /// Peek at the next notification without removing it.
    pub fn peek(&self) -> Option<&WatchNotification> {
        if self.count == 0 {
            return None;
        }
        Some(&self.ring[self.head])
    }

    /// Drain up to `max` notifications into the provided buffer.
    ///
    /// Returns the number of notifications drained.
    pub fn drain(&mut self, buf: &mut [WatchNotification], max: usize) -> usize {
        let to_drain = self.count.min(max).min(buf.len());
        for item in buf.iter_mut().take(to_drain) {
            if let Some(notif) = self.dequeue() {
                *item = notif;
            }
        }
        to_drain
    }

    /// Flush all pending notifications.
    pub fn flush(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }

    /// Get overflow statistics.
    pub fn overflow_count(&self) -> u64 {
        self.overflow_count
    }

    /// Get total events enqueued.
    pub fn total_enqueued(&self) -> u64 {
        self.total_enqueued
    }

    /// Get total events dequeued.
    pub fn total_dequeued(&self) -> u64 {
        self.total_dequeued
    }

    /// Get total events filtered out.
    pub fn total_filtered(&self) -> u64 {
        self.total_filtered
    }
}

// ── Watch Group (Fan-out) ───────────────────────────────────────────────────

/// A watcher entry in a group.
#[derive(Debug, Clone, Copy)]
pub struct GroupWatcher {
    /// Whether this watcher slot is in use.
    pub active: bool,
    /// Queue ID that this watcher is connected to.
    pub queue_id: u32,
}

impl GroupWatcher {
    /// Create an empty watcher slot.
    pub const fn new() -> Self {
        Self {
            active: false,
            queue_id: 0,
        }
    }
}

/// A watch group enables fan-out: one event source can notify
/// multiple queues simultaneously.
pub struct WatchGroup {
    /// Whether this group is in use.
    active: bool,
    /// Group ID.
    group_id: u32,
    /// Watchers (queue IDs) in this group.
    watchers: [GroupWatcher; MAX_WATCHERS_PER_GROUP],
    /// Number of active watchers.
    watcher_count: usize,
    /// Total notifications posted to this group.
    total_posted: u64,
}

impl WatchGroup {
    /// Create a new watch group.
    pub const fn new(group_id: u32) -> Self {
        Self {
            active: true,
            group_id,
            watchers: [const { GroupWatcher::new() }; MAX_WATCHERS_PER_GROUP],
            watcher_count: 0,
            total_posted: 0,
        }
    }

    /// Get the group ID.
    pub fn group_id(&self) -> u32 {
        self.group_id
    }

    /// Whether this group is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get the number of watchers.
    pub fn watcher_count(&self) -> usize {
        self.watcher_count
    }

    /// Add a watcher (queue) to this group.
    pub fn add_watcher(&mut self, queue_id: u32) -> Result<()> {
        // Check for duplicates
        for i in 0..MAX_WATCHERS_PER_GROUP {
            if self.watchers[i].active && self.watchers[i].queue_id == queue_id {
                return Err(Error::AlreadyExists);
            }
        }
        let slot = (0..MAX_WATCHERS_PER_GROUP)
            .find(|&i| !self.watchers[i].active)
            .ok_or(Error::OutOfMemory)?;
        self.watchers[slot].active = true;
        self.watchers[slot].queue_id = queue_id;
        self.watcher_count += 1;
        Ok(())
    }

    /// Remove a watcher from this group.
    pub fn remove_watcher(&mut self, queue_id: u32) -> Result<()> {
        let slot = (0..MAX_WATCHERS_PER_GROUP)
            .find(|&i| self.watchers[i].active && self.watchers[i].queue_id == queue_id)
            .ok_or(Error::NotFound)?;
        self.watchers[slot].active = false;
        self.watcher_count = self.watcher_count.saturating_sub(1);
        Ok(())
    }

    /// Get the list of active queue IDs in this group.
    pub fn queue_ids(&self) -> [Option<u32>; MAX_WATCHERS_PER_GROUP] {
        let mut result = [None; MAX_WATCHERS_PER_GROUP];
        for (i, watcher) in self.watchers.iter().enumerate() {
            if watcher.active {
                result[i] = Some(watcher.queue_id);
            }
        }
        result
    }

    /// Record that a notification was posted.
    pub fn record_post(&mut self) {
        self.total_posted += 1;
    }

    /// Get total notifications posted.
    pub fn total_posted(&self) -> u64 {
        self.total_posted
    }

    /// Close the group.
    pub fn close(&mut self) {
        self.active = false;
        for watcher in &mut self.watchers {
            watcher.active = false;
        }
        self.watcher_count = 0;
    }
}

// ── Watch Queue Subsystem ───────────────────────────────────────────────────

/// Global watch queue subsystem statistics.
#[derive(Debug, Clone, Copy)]
pub struct WatchQueueStats {
    /// Number of active queues.
    pub active_queues: u32,
    /// Number of active groups.
    pub active_groups: u32,
    /// Total events posted across all queues.
    pub total_events_posted: u64,
    /// Total events delivered (not filtered, not overflowed).
    pub total_events_delivered: u64,
    /// Total overflow events (dropped).
    pub total_overflow: u64,
    /// Total filtered events.
    pub total_filtered: u64,
}

/// The global watch queue subsystem.
///
/// Manages all watch queues and groups, providing the interface for
/// kernel subsystems to post events and user-space to consume them.
pub struct WatchQueueSubsystem {
    /// All watch queues.
    queues: Vec<WatchQueue>,
    /// Watch groups for fan-out.
    groups: [WatchGroup; MAX_GROUPS],
    /// Number of active groups.
    group_count: usize,
    /// Next queue ID to assign.
    next_queue_id: u32,
    /// Next group ID to assign.
    next_group_id: u32,
}

impl WatchQueueSubsystem {
    /// Create a new watch queue subsystem.
    pub fn new() -> Self {
        Self {
            queues: Vec::new(),
            groups: [const { WatchGroup::new(0) }; MAX_GROUPS],
            group_count: 0,
            next_queue_id: 1,
            next_group_id: 1,
        }
    }

    /// Allocate a new watch queue.
    ///
    /// Returns the queue ID.
    pub fn create_queue(&mut self, pipe_fd: i32) -> Result<u32> {
        if self.queues.len() >= MAX_QUEUES {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_queue_id;
        self.next_queue_id += 1;
        let queue = WatchQueue::new(id, pipe_fd);
        self.queues.push(queue);
        Ok(id)
    }

    /// Allocate a new watch queue with specified capacity.
    pub fn create_queue_with_capacity(&mut self, pipe_fd: i32, capacity: usize) -> Result<u32> {
        if self.queues.len() >= MAX_QUEUES {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_queue_id;
        self.next_queue_id += 1;
        let queue = WatchQueue::with_capacity(id, pipe_fd, capacity)?;
        self.queues.push(queue);
        Ok(id)
    }

    /// Destroy a watch queue.
    pub fn destroy_queue(&mut self, queue_id: u32) -> Result<()> {
        let idx = self.find_queue_index(queue_id)?;
        self.queues[idx].close();
        self.queues.remove(idx);
        // Remove from all groups
        for i in 0..MAX_GROUPS {
            if self.groups[i].is_active() {
                let _ = self.groups[i].remove_watcher(queue_id);
            }
        }
        Ok(())
    }

    /// Set the filter on a watch queue.
    pub fn set_queue_filter(&mut self, queue_id: u32, filter: WatchFilter) -> Result<()> {
        let idx = self.find_queue_index(queue_id)?;
        self.queues[idx].set_filter(filter);
        Ok(())
    }

    /// Post a notification to a specific queue.
    pub fn post_to_queue(&mut self, queue_id: u32, notif: &WatchNotification) -> Result<bool> {
        let idx = self.find_queue_index(queue_id)?;
        self.queues[idx].post(notif)
    }

    /// Dequeue a notification from a specific queue.
    pub fn dequeue_from_queue(&mut self, queue_id: u32) -> Result<Option<WatchNotification>> {
        let idx = self.find_queue_index(queue_id)?;
        Ok(self.queues[idx].dequeue())
    }

    /// Create a new watch group.
    pub fn create_group(&mut self) -> Result<u32> {
        if self.group_count >= MAX_GROUPS {
            return Err(Error::OutOfMemory);
        }
        let slot = (0..MAX_GROUPS)
            .find(|&i| !self.groups[i].is_active())
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_group_id;
        self.next_group_id += 1;
        self.groups[slot] = WatchGroup::new(id);
        self.group_count += 1;
        Ok(id)
    }

    /// Add a queue to a group.
    pub fn add_to_group(&mut self, group_id: u32, queue_id: u32) -> Result<()> {
        // Verify queue exists
        let _queue_idx = self.find_queue_index(queue_id)?;
        let group_idx = self.find_group_index(group_id)?;
        self.groups[group_idx].add_watcher(queue_id)
    }

    /// Remove a queue from a group.
    pub fn remove_from_group(&mut self, group_id: u32, queue_id: u32) -> Result<()> {
        let group_idx = self.find_group_index(group_id)?;
        self.groups[group_idx].remove_watcher(queue_id)
    }

    /// Post a notification to all queues in a group (fan-out).
    ///
    /// Returns the number of queues that accepted the notification.
    pub fn post_to_group(&mut self, group_id: u32, notif: &WatchNotification) -> Result<usize> {
        let group_idx = self.find_group_index(group_id)?;
        let queue_ids = self.groups[group_idx].queue_ids();
        self.groups[group_idx].record_post();
        let mut delivered = 0usize;
        for opt_qid in &queue_ids {
            if let Some(qid) = opt_qid {
                if let Ok(idx) = self.find_queue_index(*qid) {
                    if self.queues[idx].post(notif).unwrap_or(false) {
                        delivered += 1;
                    }
                }
            }
        }
        Ok(delivered)
    }

    /// Destroy a group.
    pub fn destroy_group(&mut self, group_id: u32) -> Result<()> {
        let group_idx = self.find_group_index(group_id)?;
        self.groups[group_idx].close();
        self.group_count = self.group_count.saturating_sub(1);
        Ok(())
    }

    /// Get statistics for the subsystem.
    pub fn stats(&self) -> WatchQueueStats {
        let mut stats = WatchQueueStats {
            active_queues: self.queues.len() as u32,
            active_groups: self.group_count as u32,
            total_events_posted: 0,
            total_events_delivered: 0,
            total_overflow: 0,
            total_filtered: 0,
        };
        for q in &self.queues {
            stats.total_events_posted +=
                q.total_enqueued() + q.overflow_count() + q.total_filtered();
            stats.total_events_delivered += q.total_dequeued();
            stats.total_overflow += q.overflow_count();
            stats.total_filtered += q.total_filtered();
        }
        stats
    }

    /// Find the index of a queue by its ID.
    fn find_queue_index(&self, queue_id: u32) -> Result<usize> {
        self.queues
            .iter()
            .position(|q| q.active && q.queue_id == queue_id)
            .ok_or(Error::NotFound)
    }

    /// Find the index of a group by its ID.
    fn find_group_index(&self, group_id: u32) -> Result<usize> {
        (0..MAX_GROUPS)
            .find(|&i| self.groups[i].is_active() && self.groups[i].group_id() == group_id)
            .ok_or(Error::NotFound)
    }
}
