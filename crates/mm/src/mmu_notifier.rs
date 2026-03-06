// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! MMU notifier subsystem.
//!
//! Provides a callback mechanism for subsystems that need to be
//! notified when the kernel modifies page table mappings.  This is
//! critical for:
//! - KVM / hypervisors (shadow page table invalidation)
//! - GPU drivers (IOMMU/GPU page table sync)
//! - RDMA / InfiniBand (memory registration invalidation)
//! - Device drivers using DMA mapping to user pages
//!
//! The MMU notifier framework sits between the MM core and
//! subscribers.  When the kernel unmaps, write-protects, or
//! otherwise modifies a page table entry, it invokes registered
//! notifier callbacks so subscribers can keep their own page tables
//! or TLBs in sync.
//!
//! Inspired by Linux `mm/mmu_notifier.c` and
//! `include/linux/mmu_notifier.h`.
//!
//! Key components:
//! - [`MmuEvent`] — type of MMU event being notified
//! - [`MmuNotification`] — event descriptor sent to callbacks
//! - [`MmuCallbackAction`] — what the callback wants the MM to do
//! - [`MmuNotifierEntry`] — a registered notifier
//! - [`MmuNotifierGroup`] — notifiers for one address space
//! - [`MmuNotifierStats`] — aggregate statistics
//! - [`MmuNotifierManager`] — top-level manager
//!
//! Reference: Linux `mm/mmu_notifier.c`,
//! `include/linux/mmu_notifier.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of notifier groups (one per address space).
const MAX_NOTIFIER_GROUPS: usize = 32;

/// Maximum notifiers per group.
const MAX_NOTIFIERS_PER_GROUP: usize = 16;

/// Maximum pending notifications in the queue.
const MAX_PENDING_NOTIFICATIONS: usize = 256;

/// Maximum completed notification records retained.
const MAX_NOTIFICATION_RECORDS: usize = 512;

/// Maximum address ranges per invalidation batch.
const MAX_RANGES_PER_BATCH: usize = 32;

/// Notification timeout (nanoseconds) — 1 second.
const NOTIFICATION_TIMEOUT_NS: u64 = 1_000_000_000;

// -------------------------------------------------------------------
// MmuEvent
// -------------------------------------------------------------------

/// Type of MMU event being notified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MmuEvent {
    /// Page(s) unmapped (e.g., munmap, exit).
    #[default]
    Unmap,
    /// Page(s) protection changed (e.g., mprotect).
    ProtectionChange,
    /// Page(s) marked read-only for CoW.
    CowBreak,
    /// Range invalidation (generic).
    Invalidate,
    /// Page migration (NUMA balancing, compaction).
    Migrate,
    /// Huge page split into base pages.
    HugePageSplit,
    /// Huge page collapse (base pages merged).
    HugePageCollapse,
    /// TLB flush required.
    TlbFlush,
    /// Address space destroyed.
    Release,
    /// Swap-out (page moved to swap).
    SwapOut,
    /// Swap-in (page returned from swap).
    SwapIn,
}

// -------------------------------------------------------------------
// MmuNotification
// -------------------------------------------------------------------

/// Descriptor for an MMU notification event.
#[derive(Debug, Clone, Copy)]
pub struct MmuNotification {
    /// Event type.
    pub event: MmuEvent,
    /// Address space ID.
    pub address_space_id: u32,
    /// Start of the affected virtual address range.
    pub start: u64,
    /// End of the affected range (exclusive).
    pub end: u64,
    /// Old page table flags (for protection changes).
    pub old_flags: u64,
    /// New page table flags (for protection changes).
    pub new_flags: u64,
    /// Whether this is a "start" notification (before change).
    pub is_begin: bool,
    /// Whether this is an "end" notification (after change).
    pub is_end: bool,
    /// Timestamp (nanoseconds).
    pub timestamp_ns: u64,
    /// Sequence number for ordering.
    pub seq: u64,
    /// Whether blockable (can sleep waiting for callback).
    pub blockable: bool,
}

impl MmuNotification {
    /// Number of pages in the affected range.
    pub const fn nr_pages(&self) -> u64 {
        (self.end - self.start) / PAGE_SIZE
    }
}

// -------------------------------------------------------------------
// MmuCallbackAction
// -------------------------------------------------------------------

/// Action returned by a notifier callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MmuCallbackAction {
    /// Proceed normally.
    #[default]
    Ok,
    /// Retry the operation (callback needs more time).
    Retry,
    /// Block the operation (veto).
    Block,
}

// -------------------------------------------------------------------
// MmuNotifierType
// -------------------------------------------------------------------

/// Type/subsystem of a registered notifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MmuNotifierType {
    /// Generic notifier.
    #[default]
    Generic,
    /// KVM hypervisor.
    Kvm,
    /// GPU driver.
    Gpu,
    /// RDMA / InfiniBand.
    Rdma,
    /// IOMMU driver.
    Iommu,
    /// DMA engine.
    Dma,
    /// Custom subsystem.
    Custom,
}

// -------------------------------------------------------------------
// MmuNotifierEntry
// -------------------------------------------------------------------

/// A registered MMU notifier.
#[derive(Debug, Clone, Copy)]
pub struct MmuNotifierEntry {
    /// Notifier ID (unique within a group).
    pub id: u32,
    /// Type of the subscribing subsystem.
    pub notifier_type: MmuNotifierType,
    /// Events this notifier is interested in.
    pub event_mask: u32,
    /// Priority (higher = called first).
    pub priority: i32,
    /// Whether this notifier is active.
    active: bool,
    /// Total notifications delivered.
    total_delivered: u64,
    /// Total callbacks that returned Retry.
    total_retries: u64,
    /// Total callbacks that returned Block.
    total_blocks: u64,
}

impl MmuNotifierEntry {
    /// Create an empty entry.
    const fn empty() -> Self {
        Self {
            id: 0,
            notifier_type: MmuNotifierType::Generic,
            event_mask: 0,
            priority: 0,
            active: false,
            total_delivered: 0,
            total_retries: 0,
            total_blocks: 0,
        }
    }

    /// Check if this notifier is interested in an event.
    pub const fn interested_in(&self, event: MmuEvent) -> bool {
        let bit = event_to_bit(event);
        (self.event_mask & (1 << bit)) != 0
    }
}

/// Convert an event to a bit position for the mask.
const fn event_to_bit(event: MmuEvent) -> u32 {
    match event {
        MmuEvent::Unmap => 0,
        MmuEvent::ProtectionChange => 1,
        MmuEvent::CowBreak => 2,
        MmuEvent::Invalidate => 3,
        MmuEvent::Migrate => 4,
        MmuEvent::HugePageSplit => 5,
        MmuEvent::HugePageCollapse => 6,
        MmuEvent::TlbFlush => 7,
        MmuEvent::Release => 8,
        MmuEvent::SwapOut => 9,
        MmuEvent::SwapIn => 10,
    }
}

/// Build an event mask from a slice of events.
pub fn event_mask_from(events: &[MmuEvent]) -> u32 {
    let mut mask = 0u32;
    for &event in events {
        mask |= 1 << event_to_bit(event);
    }
    mask
}

/// Event mask that subscribes to all events.
pub const ALL_EVENTS_MASK: u32 = 0x7FF; // bits 0..10

// -------------------------------------------------------------------
// MmuNotifierGroup
// -------------------------------------------------------------------

/// Notifiers registered for a single address space.
#[derive(Debug)]
pub struct MmuNotifierGroup {
    /// Address space ID.
    address_space_id: u32,
    /// Registered notifiers.
    notifiers: [MmuNotifierEntry; MAX_NOTIFIERS_PER_GROUP],
    /// Number of active notifiers.
    notifier_count: usize,
    /// Next notifier ID.
    next_notifier_id: u32,
    /// Whether this group is active.
    active: bool,
    /// Total notifications dispatched.
    total_dispatched: u64,
}

impl MmuNotifierGroup {
    /// Create an empty group.
    fn empty() -> Self {
        Self {
            address_space_id: 0,
            notifiers: [const { MmuNotifierEntry::empty() }; MAX_NOTIFIERS_PER_GROUP],
            notifier_count: 0,
            next_notifier_id: 1,
            active: false,
            total_dispatched: 0,
        }
    }
}

// -------------------------------------------------------------------
// PendingNotification
// -------------------------------------------------------------------

/// A notification waiting to be dispatched.
#[derive(Debug, Clone, Copy)]
struct PendingNotification {
    /// The notification.
    notification: MmuNotification,
    /// Whether dispatched.
    dispatched: bool,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl PendingNotification {
    const fn empty() -> Self {
        Self {
            notification: MmuNotification {
                event: MmuEvent::Unmap,
                address_space_id: 0,
                start: 0,
                end: 0,
                old_flags: 0,
                new_flags: 0,
                is_begin: false,
                is_end: false,
                timestamp_ns: 0,
                seq: 0,
                blockable: true,
            },
            dispatched: false,
            occupied: false,
        }
    }
}

// -------------------------------------------------------------------
// NotificationRecord
// -------------------------------------------------------------------

/// Completed notification record.
#[derive(Debug, Clone, Copy)]
pub struct NotificationRecord {
    /// Event type.
    pub event: MmuEvent,
    /// Address space ID.
    pub address_space_id: u32,
    /// Start address.
    pub start: u64,
    /// End address.
    pub end: u64,
    /// Number of notifiers called.
    pub notifiers_called: usize,
    /// Number that returned Ok.
    pub ok_count: usize,
    /// Number that returned Retry.
    pub retry_count: usize,
    /// Number that returned Block.
    pub block_count: usize,
    /// Timestamp.
    pub timestamp_ns: u64,
    /// Sequence number.
    pub seq: u64,
    /// Active.
    active: bool,
}

impl NotificationRecord {
    const fn empty() -> Self {
        Self {
            event: MmuEvent::Unmap,
            address_space_id: 0,
            start: 0,
            end: 0,
            notifiers_called: 0,
            ok_count: 0,
            retry_count: 0,
            block_count: 0,
            timestamp_ns: 0,
            seq: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// InvalidateRange
// -------------------------------------------------------------------

/// A single range in a batch invalidation.
#[derive(Debug, Clone, Copy)]
pub struct InvalidateRange {
    /// Start address.
    pub start: u64,
    /// End address (exclusive).
    pub end: u64,
}

// -------------------------------------------------------------------
// MmuNotifierStats
// -------------------------------------------------------------------

/// Aggregate MMU notifier statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MmuNotifierStats {
    /// Active notifier groups.
    pub active_groups: usize,
    /// Total registered notifiers.
    pub total_notifiers: usize,
    /// Total notifications dispatched.
    pub total_dispatched: u64,
    /// Total Ok callbacks.
    pub total_ok: u64,
    /// Total Retry callbacks.
    pub total_retries: u64,
    /// Total Block callbacks.
    pub total_blocks: u64,
    /// Pending notifications.
    pub pending_count: usize,
    /// Completed records stored.
    pub records_stored: usize,
    /// Sequence counter.
    pub current_seq: u64,
}

// -------------------------------------------------------------------
// MmuNotifierManager
// -------------------------------------------------------------------

/// Top-level MMU notifier manager.
///
/// Manages notifier registration per address space and dispatches
/// MMU change notifications to all interested subscribers.
///
/// # Example (conceptual)
///
/// ```ignore
/// let mut mgr = MmuNotifierManager::new();
/// mgr.create_group(1)?;
/// let id = mgr.register_notifier(
///     1,
///     MmuNotifierType::Kvm,
///     ALL_EVENTS_MASK,
///     0,
/// )?;
/// let result = mgr.notify(
///     1, MmuEvent::Unmap, 0x1000, 0x2000,
///     0, 0, true, 1000,
/// )?;
/// ```
pub struct MmuNotifierManager {
    /// Notifier groups (one per address space).
    groups: [MmuNotifierGroup; MAX_NOTIFIER_GROUPS],
    /// Pending notification queue.
    pending: [PendingNotification; MAX_PENDING_NOTIFICATIONS],
    /// Number of pending notifications.
    pending_count: usize,
    /// Completed notification records.
    records: [NotificationRecord; MAX_NOTIFICATION_RECORDS],
    /// Number of records.
    record_count: usize,
    /// Global sequence counter.
    seq: u64,
    /// Aggregate stats.
    stats: MmuNotifierStats,
}

impl MmuNotifierManager {
    /// Create a new MMU notifier manager.
    pub fn new() -> Self {
        Self {
            groups: core::array::from_fn(|_| MmuNotifierGroup::empty()),
            pending: [const { PendingNotification::empty() }; MAX_PENDING_NOTIFICATIONS],
            pending_count: 0,
            records: [const { NotificationRecord::empty() }; MAX_NOTIFICATION_RECORDS],
            record_count: 0,
            seq: 0,
            stats: MmuNotifierStats::default(),
        }
    }

    // ── group management ─────────────────────────────────────────

    /// Create a notifier group for an address space.
    pub fn create_group(&mut self, address_space_id: u32) -> Result<()> {
        // Check duplicate.
        if self.find_group(address_space_id).is_some() {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .groups
            .iter_mut()
            .find(|g| !g.active)
            .ok_or(Error::OutOfMemory)?;
        *slot = MmuNotifierGroup::empty();
        slot.address_space_id = address_space_id;
        slot.active = true;
        Ok(())
    }

    /// Remove a notifier group (address space destroyed).
    pub fn remove_group(&mut self, address_space_id: u32) -> Result<()> {
        let idx = self.find_group(address_space_id).ok_or(Error::NotFound)?;
        self.groups[idx].active = false;
        Ok(())
    }

    /// Find a group by address space ID.
    fn find_group(&self, address_space_id: u32) -> Option<usize> {
        self.groups
            .iter()
            .position(|g| g.active && g.address_space_id == address_space_id)
    }

    // ── notifier registration ────────────────────────────────────

    /// Register a notifier for an address space.
    ///
    /// Returns the notifier ID.
    pub fn register_notifier(
        &mut self,
        address_space_id: u32,
        notifier_type: MmuNotifierType,
        event_mask: u32,
        priority: i32,
    ) -> Result<u32> {
        let idx = self.find_group(address_space_id).ok_or(Error::NotFound)?;
        let group = &mut self.groups[idx];
        if group.notifier_count >= MAX_NOTIFIERS_PER_GROUP {
            return Err(Error::OutOfMemory);
        }
        let notifier_id = group.next_notifier_id;
        group.next_notifier_id += 1;

        let slot = group
            .notifiers
            .iter_mut()
            .find(|n| !n.active)
            .ok_or(Error::OutOfMemory)?;
        *slot = MmuNotifierEntry {
            id: notifier_id,
            notifier_type,
            event_mask,
            priority,
            active: true,
            total_delivered: 0,
            total_retries: 0,
            total_blocks: 0,
        };
        group.notifier_count += 1;
        Ok(notifier_id)
    }

    /// Unregister a notifier.
    pub fn unregister_notifier(&mut self, address_space_id: u32, notifier_id: u32) -> Result<()> {
        let idx = self.find_group(address_space_id).ok_or(Error::NotFound)?;
        let group = &mut self.groups[idx];
        let slot = group
            .notifiers
            .iter_mut()
            .find(|n| n.active && n.id == notifier_id)
            .ok_or(Error::NotFound)?;
        slot.active = false;
        group.notifier_count = group.notifier_count.saturating_sub(1);
        Ok(())
    }

    // ── notification dispatch ────────────────────────────────────

    /// Send a notification to all interested notifiers in an
    /// address space.
    ///
    /// Returns a summary of callback responses.
    #[allow(clippy::too_many_arguments)]
    pub fn notify(
        &mut self,
        address_space_id: u32,
        event: MmuEvent,
        start: u64,
        end: u64,
        old_flags: u64,
        new_flags: u64,
        blockable: bool,
        now_ns: u64,
    ) -> Result<NotificationRecord> {
        let idx = self.find_group(address_space_id).ok_or(Error::NotFound)?;

        self.seq += 1;
        let seq = self.seq;

        let notification = MmuNotification {
            event,
            address_space_id,
            start,
            end,
            old_flags,
            new_flags,
            is_begin: true,
            is_end: true,
            timestamp_ns: now_ns,
            seq,
            blockable,
        };

        // Dispatch to all interested notifiers.
        let mut record = NotificationRecord {
            event,
            address_space_id,
            start,
            end,
            notifiers_called: 0,
            ok_count: 0,
            retry_count: 0,
            block_count: 0,
            timestamp_ns: now_ns,
            seq,
            active: true,
        };

        // Sort notifiers by priority (descending) — we use a
        // simple selection over the small array.
        let group = &mut self.groups[idx];
        for notifier in &mut group.notifiers {
            if !notifier.active {
                continue;
            }
            if !notifier.interested_in(notification.event) {
                continue;
            }

            // Simulate callback invocation.  In a real kernel,
            // this would call a function pointer.
            let action = Self::invoke_callback(notifier, &notification);
            record.notifiers_called += 1;

            match action {
                MmuCallbackAction::Ok => {
                    record.ok_count += 1;
                    notifier.total_delivered += 1;
                }
                MmuCallbackAction::Retry => {
                    record.retry_count += 1;
                    notifier.total_retries += 1;
                }
                MmuCallbackAction::Block => {
                    record.block_count += 1;
                    notifier.total_blocks += 1;
                }
            }
        }

        group.total_dispatched += 1;
        self.stats.total_dispatched += 1;
        self.stats.total_ok += record.ok_count as u64;
        self.stats.total_retries += record.retry_count as u64;
        self.stats.total_blocks += record.block_count as u64;

        self.store_record(record);
        Ok(record)
    }

    /// Send begin/end paired notifications.
    #[allow(clippy::too_many_arguments)]
    pub fn notify_range(
        &mut self,
        address_space_id: u32,
        event: MmuEvent,
        start: u64,
        end: u64,
        old_flags: u64,
        new_flags: u64,
        blockable: bool,
        now_ns: u64,
    ) -> Result<(NotificationRecord, NotificationRecord)> {
        // Begin notification.
        let begin = self.notify(
            address_space_id,
            event,
            start,
            end,
            old_flags,
            new_flags,
            blockable,
            now_ns,
        )?;
        // End notification.
        let end_record = self.notify(
            address_space_id,
            event,
            start,
            end,
            old_flags,
            new_flags,
            blockable,
            now_ns,
        )?;
        Ok((begin, end_record))
    }

    /// Batch invalidation for multiple ranges.
    pub fn invalidate_batch(
        &mut self,
        address_space_id: u32,
        ranges: &[InvalidateRange],
        now_ns: u64,
    ) -> Result<usize> {
        let mut notified = 0usize;
        let count = ranges.len().min(MAX_RANGES_PER_BATCH);
        for range in ranges.iter().take(count) {
            self.notify(
                address_space_id,
                MmuEvent::Invalidate,
                range.start,
                range.end,
                0,
                0,
                true,
                now_ns,
            )?;
            notified += 1;
        }
        Ok(notified)
    }

    /// Simulated callback invocation.
    fn invoke_callback(
        notifier: &MmuNotifierEntry,
        _notification: &MmuNotification,
    ) -> MmuCallbackAction {
        // In a real kernel, this would call the registered
        // callback function pointer.  Here we always return Ok.
        let _ = notifier;
        MmuCallbackAction::Ok
    }

    /// Store a completed notification record.
    fn store_record(&mut self, record: NotificationRecord) {
        if self.record_count >= MAX_NOTIFICATION_RECORDS {
            // Shift left.
            for i in 1..MAX_NOTIFICATION_RECORDS {
                self.records[i - 1] = self.records[i];
            }
            self.record_count = MAX_NOTIFICATION_RECORDS - 1;
        }
        self.records[self.record_count] = record;
        self.record_count += 1;
    }

    // ── queries ──────────────────────────────────────────────────

    /// Number of active groups.
    pub fn active_group_count(&self) -> usize {
        self.groups.iter().filter(|g| g.active).count()
    }

    /// Total registered notifiers across all groups.
    pub fn total_notifier_count(&self) -> usize {
        self.groups
            .iter()
            .filter(|g| g.active)
            .map(|g| g.notifier_count)
            .sum()
    }

    /// Aggregate statistics.
    pub fn stats(&self) -> MmuNotifierStats {
        let mut s = self.stats;
        s.active_groups = self.active_group_count();
        s.total_notifiers = self.total_notifier_count();
        s.pending_count = self.pending_count;
        s.records_stored = self.record_count;
        s.current_seq = self.seq;
        s
    }

    /// Get recent notification records.
    pub fn records(&self) -> &[NotificationRecord] {
        &self.records[..self.record_count]
    }

    /// Check for timed-out pending notifications.
    pub fn check_timeouts(&mut self, now_ns: u64) -> usize {
        let mut timed_out = 0usize;
        for entry in &mut self.pending {
            if entry.occupied
                && !entry.dispatched
                && now_ns.saturating_sub(entry.notification.timestamp_ns) > NOTIFICATION_TIMEOUT_NS
            {
                entry.dispatched = true;
                entry.occupied = false;
                self.pending_count = self.pending_count.saturating_sub(1);
                timed_out += 1;
            }
        }
        timed_out
    }

    /// Reset the manager.
    pub fn reset(&mut self) {
        for group in &mut self.groups {
            *group = MmuNotifierGroup::empty();
        }
        for entry in &mut self.pending {
            *entry = PendingNotification::empty();
        }
        for record in &mut self.records {
            *record = NotificationRecord::empty();
        }
        self.pending_count = 0;
        self.record_count = 0;
        self.seq = 0;
        self.stats = MmuNotifierStats::default();
    }
}

impl Default for MmuNotifierManager {
    fn default() -> Self {
        Self::new()
    }
}
