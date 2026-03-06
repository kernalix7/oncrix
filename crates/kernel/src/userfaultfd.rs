// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Userfaultfd subsystem for user-space page fault handling.
//!
//! Provides a mechanism for user-space processes to intercept and
//! resolve page faults. A monitor process creates a userfaultfd,
//! registers memory ranges, and receives fault events via a ring
//! buffer. Faults are resolved by copying data, mapping zero pages,
//! or waking faulting threads.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────┐
//! │              UffdRegistry                    │
//! │  (up to MAX_UFFD userfaultfd instances)      │
//! │  ┌────────┐ ┌────────┐       ┌────────┐     │
//! │  │ uffd 0 │ │ uffd 1 │  ...  │ uffd N │     │
//! │  │ ranges │ │ ranges │       │ ranges │     │
//! │  │ events │ │ events │       │ events │     │
//! │  └────────┘ └────────┘       └────────┘     │
//! └──────────────────────────────────────────────┘
//! ```
//!
//! # Fault Flow
//!
//! 1. A thread faults on a registered address range.
//! 2. The kernel calls [`UffdRegistry::on_fault`] to push an
//!    event into the owning userfaultfd's ring buffer.
//! 3. The monitor reads the event via [`UffdRegistry::read_event`].
//! 4. The monitor resolves the fault with [`copy_page`], [`zero_page`],
//!    or [`wake`].

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────

/// Maximum number of concurrent userfaultfd instances.
const _MAX_UFFD: usize = 32;

/// Maximum number of registered ranges per userfaultfd.
const _MAX_UFFD_RANGES: usize = 64;

/// Page fault event type.
pub const UFFD_EVENT_PAGEFAULT: u8 = 0x12;

/// Fork event type.
pub const UFFD_EVENT_FORK: u8 = 0x13;

/// Remap (mremap) event type.
pub const UFFD_EVENT_REMAP: u8 = 0x14;

/// Remove (madvise DONTNEED) event type.
pub const UFFD_EVENT_REMOVE: u8 = 0x15;

/// Unmap event type.
pub const UFFD_EVENT_UNMAP: u8 = 0x16;

/// Flag indicating the fault was a write access.
pub const UFFD_PAGEFAULT_FLAG_WRITE: u64 = 1;

/// Flag indicating the fault was a write-protect violation.
pub const UFFD_PAGEFAULT_FLAG_WP: u64 = 2;

/// Feature: handle missing pages in shared memory.
pub const UFFD_FEATURE_MISSING_SHMEM: u64 = 0x10;

/// Feature: handle missing pages in hugetlbfs.
pub const UFFD_FEATURE_MISSING_HUGETLBFS: u64 = 0x20;

/// Event ring buffer capacity per userfaultfd.
const EVENT_RING_CAP: usize = 64;

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

// ── UffdMode ─────────────────────────────────────────────────

/// Mode of fault handling for a registered range.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum UffdMode {
    /// Handle missing page faults (default).
    #[default]
    Missing,
    /// Handle write-protect faults.
    Wp,
    /// Handle minor faults (e.g. soft-dirty).
    Minor,
}

// ── UffdEvent ────────────────────────────────────────────────

/// An event delivered to a userfaultfd monitor.
#[derive(Debug, Clone, Copy)]
pub struct UffdEvent {
    /// Event type (one of `UFFD_EVENT_*` constants).
    pub event_type: u8,
    /// Event-specific flags (e.g. `UFFD_PAGEFAULT_FLAG_*`).
    pub flags: u64,
    /// Faulting or affected virtual address.
    pub address: u64,
    /// PID of the faulting process.
    pub pid: u64,
    /// Timestamp in nanoseconds (monotonic).
    pub timestamp_ns: u64,
}

// ── UffdRange ────────────────────────────────────────────────

/// A registered address range within a userfaultfd.
#[derive(Debug, Clone, Copy)]
pub struct UffdRange {
    /// Start address (inclusive, page-aligned).
    pub start: u64,
    /// End address (exclusive, page-aligned).
    pub end: u64,
    /// Fault handling mode for this range.
    pub mode: UffdMode,
    /// Whether this range slot is active.
    pub active: bool,
}

impl UffdRange {
    /// Create an inactive (empty) range slot.
    const fn empty() -> Self {
        Self {
            start: 0,
            end: 0,
            mode: UffdMode::Missing,
            active: false,
        }
    }
}

// ── Userfaultfd ──────────────────────────────────────────────

/// A single userfaultfd instance.
///
/// Holds registered memory ranges and a ring buffer of fault
/// events. The owning monitor process reads events and resolves
/// faults by providing page data or waking faulting threads.
pub struct Userfaultfd {
    /// Unique identifier for this userfaultfd.
    id: u32,
    /// PID of the owning monitor process.
    owner_pid: u64,
    /// Registered address ranges.
    ranges: [UffdRange; 64],
    /// Number of active ranges.
    range_count: usize,
    /// Event ring buffer.
    events: [UffdEvent; EVENT_RING_CAP],
    /// Ring buffer head (read position).
    head: usize,
    /// Ring buffer tail (write position).
    tail: usize,
    /// Number of pending events.
    count: usize,
    /// Enabled feature flags.
    features: u64,
    /// Whether this userfaultfd is active.
    active: bool,
    /// Whether reads are non-blocking.
    nonblock: bool,
}

/// Placeholder event used to fill the ring buffer at init.
const EMPTY_EVENT: UffdEvent = UffdEvent {
    event_type: 0,
    flags: 0,
    address: 0,
    pid: 0,
    timestamp_ns: 0,
};

impl Userfaultfd {
    /// Create a new userfaultfd for the given owner PID.
    const fn new(id: u32, owner_pid: u64, nonblock: bool) -> Self {
        Self {
            id,
            owner_pid,
            ranges: [UffdRange::empty(); 64],
            range_count: 0,
            events: [EMPTY_EVENT; EVENT_RING_CAP],
            head: 0,
            tail: 0,
            count: 0,
            features: 0,
            active: true,
            nonblock,
        }
    }

    /// Return the userfaultfd identifier.
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Return the owner process PID.
    pub const fn owner_pid(&self) -> u64 {
        self.owner_pid
    }

    /// Return the enabled feature flags.
    pub const fn features(&self) -> u64 {
        self.features
    }

    /// Return whether this userfaultfd is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Return whether non-blocking mode is enabled.
    pub const fn is_nonblock(&self) -> bool {
        self.nonblock
    }

    /// Register a memory range for fault handling.
    ///
    /// The range `[start, start + len)` will be monitored with
    /// the given [`UffdMode`]. Both `start` and `len` must be
    /// page-aligned and non-zero.
    pub fn register_range(&mut self, start: u64, len: u64, mode: UffdMode) -> Result<()> {
        if len == 0 || start % PAGE_SIZE != 0 || len % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        let end = start.checked_add(len).ok_or(Error::InvalidArgument)?;

        if self.range_count >= self.ranges.len() {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .ranges
            .iter_mut()
            .find(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = UffdRange {
            start,
            end,
            mode,
            active: true,
        };
        self.range_count += 1;
        Ok(())
    }

    /// Unregister a previously registered memory range.
    ///
    /// The `start` and `len` must exactly match a registered range.
    pub fn unregister_range(&mut self, start: u64, len: u64) -> Result<()> {
        if len == 0 {
            return Err(Error::InvalidArgument);
        }
        let end = start.checked_add(len).ok_or(Error::InvalidArgument)?;

        let slot = self
            .ranges
            .iter_mut()
            .find(|r| r.active && r.start == start && r.end == end)
            .ok_or(Error::NotFound)?;

        *slot = UffdRange::empty();
        self.range_count = self.range_count.saturating_sub(1);
        Ok(())
    }

    /// Push an event into the ring buffer.
    ///
    /// If the ring is full the oldest event is silently dropped.
    pub fn push_event(&mut self, event: UffdEvent) {
        self.events[self.tail] = event;
        self.tail = (self.tail + 1) % EVENT_RING_CAP;
        if self.count == EVENT_RING_CAP {
            // Ring full — advance head to drop oldest.
            self.head = (self.head + 1) % EVENT_RING_CAP;
        } else {
            self.count += 1;
        }
    }

    /// Pop the oldest event from the ring buffer.
    ///
    /// Returns `None` if the ring is empty.
    pub fn pop_event(&mut self) -> Option<UffdEvent> {
        if self.count == 0 {
            return None;
        }
        let event = self.events[self.head];
        self.head = (self.head + 1) % EVENT_RING_CAP;
        self.count -= 1;
        Some(event)
    }

    /// Check whether this userfaultfd handles the given address.
    pub fn handles_address(&self, addr: u64) -> bool {
        self.ranges
            .iter()
            .any(|r| r.active && addr >= r.start && addr < r.end)
    }

    /// Return the number of pending (unread) events.
    pub const fn pending_events(&self) -> usize {
        self.count
    }
}

// ── UffdRegistry ─────────────────────────────────────────────

/// Global registry managing all userfaultfd instances.
///
/// Provides creation, lookup, and fault-dispatch operations for
/// up to [`_MAX_UFFD`] concurrent userfaultfd instances.
pub struct UffdRegistry {
    /// Fixed array of userfaultfd slots.
    fds: [Option<Userfaultfd>; 32],
    /// Next unique identifier to assign.
    next_id: u32,
    /// Number of active userfaultfd instances.
    count: usize,
}

impl Default for UffdRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl UffdRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            fds: [const { None }; 32],
            next_id: 0,
            count: 0,
        }
    }

    /// Create a new userfaultfd for the given PID.
    ///
    /// Returns the userfaultfd ID on success.
    pub fn create(&mut self, pid: u64, nonblock: bool) -> Result<u32> {
        let slot = self
            .fds
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        *slot = Some(Userfaultfd::new(id, pid, nonblock));
        self.count += 1;
        Ok(id)
    }

    /// Close and destroy a userfaultfd by ID.
    pub fn close(&mut self, id: u32) -> Result<()> {
        let slot = self.find_slot_mut(id)?;
        *slot = None;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Register a memory range on a userfaultfd.
    pub fn register(&mut self, id: u32, start: u64, len: u64, mode: UffdMode) -> Result<()> {
        let uffd = self.get_mut(id)?;
        uffd.register_range(start, len, mode)
    }

    /// Unregister a memory range from a userfaultfd.
    pub fn unregister(&mut self, id: u32, start: u64, len: u64) -> Result<()> {
        let uffd = self.get_mut(id)?;
        uffd.unregister_range(start, len)
    }

    /// Resolve a page fault by copying user-provided data.
    ///
    /// Validates that the destination address is within a
    /// registered range and that the data length is page-aligned.
    /// Actual memory mapping is deferred to the memory subsystem.
    pub fn copy_page(&mut self, id: u32, dst: u64, src_data: &[u8]) -> Result<()> {
        let uffd = self.get_mut(id)?;

        if dst % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if src_data.len() as u64 % PAGE_SIZE != 0 || src_data.is_empty() {
            return Err(Error::InvalidArgument);
        }
        if !uffd.handles_address(dst) {
            return Err(Error::InvalidArgument);
        }

        // Stub: actual page installation is handled by the MM
        // subsystem once integrated.
        Ok(())
    }

    /// Resolve a page fault by mapping zero-filled pages.
    ///
    /// Both `addr` and `len` must be page-aligned and within a
    /// registered range.
    pub fn zero_page(&mut self, id: u32, addr: u64, len: u64) -> Result<()> {
        let uffd = self.get_mut(id)?;

        if addr % PAGE_SIZE != 0 || len % PAGE_SIZE != 0 || len == 0 {
            return Err(Error::InvalidArgument);
        }
        if !uffd.handles_address(addr) {
            return Err(Error::InvalidArgument);
        }

        // Stub: actual zero-page installation is handled by the
        // MM subsystem.
        Ok(())
    }

    /// Wake threads waiting on a resolved fault.
    ///
    /// After resolving a fault with [`copy_page`] or [`zero_page`],
    /// the monitor calls `wake` to resume the faulting thread.
    pub fn wake(&mut self, id: u32, addr: u64, len: u64) -> Result<()> {
        let uffd = self.get_mut(id)?;

        if addr % PAGE_SIZE != 0 || len % PAGE_SIZE != 0 || len == 0 {
            return Err(Error::InvalidArgument);
        }
        if !uffd.handles_address(addr) {
            return Err(Error::InvalidArgument);
        }

        // Stub: actual thread wake-up is handled by the scheduler
        // once integrated.
        Ok(())
    }

    /// Handle a page fault at the given address.
    ///
    /// Searches all active userfaultfd instances for one that
    /// covers `addr`. If found, pushes a pagefault event and
    /// returns the userfaultfd ID.
    pub fn on_fault(&mut self, addr: u64, write: bool, pid: u64, now_ns: u64) -> Option<u32> {
        let mut found_idx = None;
        for (i, slot) in self.fds.iter().enumerate() {
            if let Some(uffd) = slot {
                if uffd.active && uffd.handles_address(addr) {
                    found_idx = Some(i);
                    break;
                }
            }
        }

        let idx = found_idx?;
        let flags = if write { UFFD_PAGEFAULT_FLAG_WRITE } else { 0 };

        let event = UffdEvent {
            event_type: UFFD_EVENT_PAGEFAULT,
            flags,
            address: addr,
            pid,
            timestamp_ns: now_ns,
        };

        let uffd = self.fds[idx].as_mut()?;
        let id = uffd.id();
        uffd.push_event(event);
        Some(id)
    }

    /// Read the next event from a userfaultfd.
    ///
    /// Returns `Ok(None)` if no events are pending.
    pub fn read_event(&mut self, id: u32) -> Result<Option<UffdEvent>> {
        let uffd = self.get_mut(id)?;
        Ok(uffd.pop_event())
    }

    /// Return the number of active userfaultfd instances.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Return whether the registry has no active instances.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Find a mutable reference to the slot containing the given ID.
    fn find_slot_mut(&mut self, id: u32) -> Result<&mut Option<Userfaultfd>> {
        self.fds
            .iter_mut()
            .find(|s| s.as_ref().is_some_and(|u| u.id == id))
            .ok_or(Error::NotFound)
    }

    /// Get a mutable reference to a userfaultfd by ID.
    fn get_mut(&mut self, id: u32) -> Result<&mut Userfaultfd> {
        self.find_slot_mut(id)?.as_mut().ok_or(Error::NotFound)
    }
}
