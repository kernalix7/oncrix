// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Userfaultfd kernel support for the ONCRIX memory management subsystem.
//!
//! Implements the kernel-side of the userfaultfd mechanism, which allows
//! a user-space process to handle page faults for specific memory
//! regions. When a fault occurs in a registered range, the faulting
//! thread is paused and the monitor process is notified, enabling
//! user-space page fault handling (e.g., for live migration, garbage
//! collection, or checkpoint/restore).
//!
//! - [`UserfaultfdCtx`] — context for a userfaultfd instance
//! - [`UffdMode`] — fault modes (MISSING, WP, MINOR)
//! - [`UffdEvent`] — events delivered to the monitor
//! - [`UserfaultfdManager`] — manages multiple userfaultfd instances
//!
//! Reference: `.kernelORG/` — `fs/userfaultfd.c`, `mm/userfaultfd.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of userfaultfd contexts.
const MAX_UFFD_CONTEXTS: usize = 32;

/// Maximum number of registered ranges per context.
const MAX_RANGES: usize = 64;

/// Maximum number of pending fault events.
const MAX_PENDING_EVENTS: usize = 128;

/// Maximum number of waiters (faulting threads) per context.
const MAX_WAITERS: usize = 64;

// -------------------------------------------------------------------
// UffdMode
// -------------------------------------------------------------------

/// Fault handling modes for userfaultfd.
pub struct UffdMode;

impl UffdMode {
    /// Handle missing page faults (page not present).
    pub const MISSING: u32 = 1 << 0;
    /// Handle write-protect faults.
    pub const WP: u32 = 1 << 1;
    /// Handle minor faults (page present but needs update).
    pub const MINOR: u32 = 1 << 2;
}

// -------------------------------------------------------------------
// UffdFeatures
// -------------------------------------------------------------------

/// Feature flags for userfaultfd.
pub struct UffdFeatures;

impl UffdFeatures {
    /// Support for fork event notification.
    pub const EVENT_FORK: u32 = 1 << 0;
    /// Support for remap event notification.
    pub const EVENT_REMAP: u32 = 1 << 1;
    /// Support for remove event notification.
    pub const EVENT_REMOVE: u32 = 1 << 2;
    /// Support for unmap event notification.
    pub const EVENT_UNMAP: u32 = 1 << 3;
    /// Support for pagefault flag write-protect.
    pub const PAGEFAULT_FLAG_WP: u32 = 1 << 4;
    /// Support for thread ID in fault messages.
    pub const THREAD_ID: u32 = 1 << 5;
    /// Support for minor faults.
    pub const MINOR_HUGETLBFS: u32 = 1 << 6;
    /// Support for minor shmem faults.
    pub const MINOR_SHMEM: u32 = 1 << 7;
}

// -------------------------------------------------------------------
// UffdEventType
// -------------------------------------------------------------------

/// Types of events delivered to the userfaultfd monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UffdEventType {
    /// A page fault occurred.
    #[default]
    Pagefault,
    /// The tracked process forked.
    Fork,
    /// A mapping was remapped (mremap).
    Remap,
    /// A mapping was removed (munmap).
    Remove,
    /// A mapping was unmapped.
    Unmap,
}

// -------------------------------------------------------------------
// UffdEvent
// -------------------------------------------------------------------

/// An event delivered to the userfaultfd monitor.
#[derive(Debug, Clone, Copy)]
pub struct UffdEvent {
    /// Event type.
    pub event_type: UffdEventType,
    /// Faulting address (for pagefault events).
    pub address: u64,
    /// Fault flags (write, wp, etc.).
    pub flags: u32,
    /// Thread ID of the faulting thread.
    pub thread_id: u32,
    /// Sequence number for ordering.
    pub sequence: u64,
    /// Whether this event is pending (not yet consumed).
    pub pending: bool,
}

impl UffdEvent {
    /// Create an empty event.
    pub const fn empty() -> Self {
        Self {
            event_type: UffdEventType::Pagefault,
            address: 0,
            flags: 0,
            thread_id: 0,
            sequence: 0,
            pending: false,
        }
    }
}

// -------------------------------------------------------------------
// UffdRange
// -------------------------------------------------------------------

/// A registered userfaultfd range.
#[derive(Debug, Clone, Copy)]
pub struct UffdRange {
    /// Start address (page-aligned).
    pub start: u64,
    /// End address (page-aligned, exclusive).
    pub end: u64,
    /// Fault handling mode.
    pub mode: u32,
    /// Whether this range is active.
    pub active: bool,
}

impl UffdRange {
    /// Create an empty range.
    pub const fn empty() -> Self {
        Self {
            start: 0,
            end: 0,
            mode: 0,
            active: false,
        }
    }

    /// Check if the range contains the address.
    pub fn contains(&self, addr: u64) -> bool {
        self.active && addr >= self.start && addr < self.end
    }

    /// Size of the range in bytes.
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Number of pages in the range.
    pub fn page_count(&self) -> u64 {
        self.size() / PAGE_SIZE
    }
}

// -------------------------------------------------------------------
// Waiter
// -------------------------------------------------------------------

/// A faulting thread waiting for resolution.
#[derive(Debug, Clone, Copy)]
pub struct Waiter {
    /// Thread ID.
    pub thread_id: u32,
    /// Faulting address.
    pub address: u64,
    /// Whether this waiter is active.
    pub active: bool,
    /// Whether the fault has been resolved.
    pub resolved: bool,
}

impl Waiter {
    /// Create an empty waiter.
    pub const fn empty() -> Self {
        Self {
            thread_id: 0,
            address: 0,
            active: false,
            resolved: false,
        }
    }
}

// -------------------------------------------------------------------
// UserfaultfdCtx
// -------------------------------------------------------------------

/// Context for a single userfaultfd instance.
///
/// Manages registered ranges, pending fault events, and waiting
/// threads for one userfaultfd file descriptor.
pub struct UserfaultfdCtx {
    /// Context identifier.
    pub id: u32,
    /// Enabled fault modes.
    pub mode: u32,
    /// Enabled features.
    pub features: u32,
    /// Registered ranges.
    ranges: [UffdRange; MAX_RANGES],
    /// Number of registered ranges.
    range_count: usize,
    /// Pending events.
    events: [UffdEvent; MAX_PENDING_EVENTS],
    /// Number of pending events.
    event_count: usize,
    /// Waiting (faulting) threads.
    waiters: [Waiter; MAX_WAITERS],
    /// Number of waiters.
    waiter_count: usize,
    /// Next event sequence number.
    next_sequence: u64,
    /// Whether the context is active.
    pub active: bool,
    /// Total events generated.
    pub total_events: u64,
    /// Total faults handled.
    pub total_resolved: u64,
}

impl UserfaultfdCtx {
    /// Create a new userfaultfd context.
    pub fn new(id: u32, mode: u32, features: u32) -> Self {
        Self {
            id,
            mode,
            features,
            ranges: [UffdRange::empty(); MAX_RANGES],
            range_count: 0,
            events: [UffdEvent::empty(); MAX_PENDING_EVENTS],
            event_count: 0,
            waiters: [Waiter::empty(); MAX_WAITERS],
            waiter_count: 0,
            next_sequence: 0,
            active: true,
            total_events: 0,
            total_resolved: 0,
        }
    }

    /// Register a virtual address range for userfaultfd handling.
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if the range table is full, or
    /// `InvalidArgument` if the range is invalid.
    pub fn register_range(&mut self, start: u64, end: u64, mode: u32) -> Result<usize> {
        if start >= end || start % PAGE_SIZE != 0 || end % PAGE_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.range_count >= MAX_RANGES {
            return Err(Error::OutOfMemory);
        }

        // Check for overlaps.
        for i in 0..self.range_count {
            let r = &self.ranges[i];
            if r.active && start < r.end && end > r.start {
                return Err(Error::AlreadyExists);
            }
        }

        let idx = self.range_count;
        self.ranges[idx] = UffdRange {
            start,
            end,
            mode,
            active: true,
        };
        self.range_count += 1;
        Ok(idx)
    }

    /// Unregister a range by index.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the index is out of bounds.
    pub fn unregister_range(&mut self, idx: usize) -> Result<()> {
        if idx >= self.range_count || !self.ranges[idx].active {
            return Err(Error::InvalidArgument);
        }
        self.ranges[idx].active = false;
        Ok(())
    }

    /// Handle a page fault in a registered range.
    ///
    /// Queues a fault event and registers the faulting thread as a
    /// waiter. Returns `true` if the fault was handled (the thread
    /// should be paused).
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if the event or waiter tables are full.
    pub fn handle_userfault(&mut self, address: u64, flags: u32, thread_id: u32) -> Result<bool> {
        let page_addr = address & !(PAGE_SIZE - 1);

        // Check if the address is in a registered range.
        let mut in_range = false;
        let mut range_mode = 0u32;
        for i in 0..self.range_count {
            if self.ranges[i].contains(page_addr) {
                in_range = true;
                range_mode = self.ranges[i].mode;
                break;
            }
        }

        if !in_range {
            return Ok(false);
        }

        // Check if the fault mode matches.
        let is_missing = flags & UffdMode::MISSING != 0;
        let is_wp = flags & UffdMode::WP != 0;

        if is_missing && (range_mode & UffdMode::MISSING == 0) {
            return Ok(false);
        }
        if is_wp && (range_mode & UffdMode::WP == 0) {
            return Ok(false);
        }

        // Queue the event.
        if self.event_count >= MAX_PENDING_EVENTS {
            return Err(Error::OutOfMemory);
        }

        let seq = self.next_sequence;
        self.next_sequence += 1;

        self.events[self.event_count] = UffdEvent {
            event_type: UffdEventType::Pagefault,
            address: page_addr,
            flags,
            thread_id,
            sequence: seq,
            pending: true,
        };
        self.event_count += 1;
        self.total_events += 1;

        // Register the waiter.
        if self.waiter_count < MAX_WAITERS {
            self.waiters[self.waiter_count] = Waiter {
                thread_id,
                address: page_addr,
                active: true,
                resolved: false,
            };
            self.waiter_count += 1;
        }

        Ok(true)
    }

    /// Read pending events (consume them).
    ///
    /// Returns the number of events consumed.
    pub fn read_events(&mut self, out: &mut [UffdEvent]) -> usize {
        let mut consumed = 0;

        for i in 0..self.event_count {
            if !self.events[i].pending {
                continue;
            }
            if consumed >= out.len() {
                break;
            }
            out[consumed] = self.events[i];
            self.events[i].pending = false;
            consumed += 1;
        }

        // Compact events.
        let mut write_idx = 0;
        for read_idx in 0..self.event_count {
            if self.events[read_idx].pending {
                self.events[write_idx] = self.events[read_idx];
                write_idx += 1;
            }
        }
        self.event_count = write_idx;

        consumed
    }

    /// Resolve a fault by copying data to the faulting page.
    ///
    /// The monitor calls this after handling the fault. Wakes the
    /// waiting thread.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if no waiter exists for the address.
    pub fn userfaultfd_copy(&mut self, dst_addr: u64, _src_data: &[u8]) -> Result<u64> {
        let page_addr = dst_addr & !(PAGE_SIZE - 1);

        // Find and wake the waiter.
        let mut found = false;
        for i in 0..self.waiter_count {
            if self.waiters[i].active
                && self.waiters[i].address == page_addr
                && !self.waiters[i].resolved
            {
                self.waiters[i].resolved = true;
                found = true;
                break;
            }
        }

        if !found {
            return Err(Error::NotFound);
        }

        self.total_resolved += 1;

        // Clean up resolved waiters.
        let mut write_idx = 0;
        for read_idx in 0..self.waiter_count {
            if self.waiters[read_idx].active && !self.waiters[read_idx].resolved {
                self.waiters[write_idx] = self.waiters[read_idx];
                write_idx += 1;
            }
        }
        self.waiter_count = write_idx;

        Ok(PAGE_SIZE)
    }

    /// Resolve a fault by mapping a zero page.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if no waiter exists for the address.
    pub fn userfaultfd_zeropage(&mut self, addr: u64) -> Result<u64> {
        self.userfaultfd_copy(addr, &[])
    }

    /// Change write-protection on a range.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if the range is invalid.
    pub fn userfaultfd_writeprotect(
        &mut self,
        start: u64,
        len: u64,
        enable_wp: bool,
    ) -> Result<()> {
        if start % PAGE_SIZE != 0 || len == 0 {
            return Err(Error::InvalidArgument);
        }

        let end = start + len;

        // Verify the range is registered.
        let mut found = false;
        for i in 0..self.range_count {
            let r = &self.ranges[i];
            if r.active && start >= r.start && end <= r.end {
                found = true;
                break;
            }
        }

        if !found {
            return Err(Error::InvalidArgument);
        }

        // In a real implementation, this would modify page table entries.
        let _ = enable_wp;
        Ok(())
    }

    /// Get the number of pending events.
    pub fn pending_event_count(&self) -> usize {
        self.events
            .iter()
            .take(self.event_count)
            .filter(|e| e.pending)
            .count()
    }

    /// Get the number of active waiters.
    pub fn waiter_count(&self) -> usize {
        self.waiters
            .iter()
            .take(self.waiter_count)
            .filter(|w| w.active && !w.resolved)
            .count()
    }

    /// Get the number of registered ranges.
    pub fn range_count(&self) -> usize {
        self.ranges
            .iter()
            .take(self.range_count)
            .filter(|r| r.active)
            .count()
    }
}

// -------------------------------------------------------------------
// UserfaultfdManager
// -------------------------------------------------------------------

/// Manages multiple userfaultfd contexts.
pub struct UserfaultfdManager {
    /// Registered contexts.
    contexts: [Option<UserfaultfdCtx>; MAX_UFFD_CONTEXTS],
    /// Next context ID.
    next_id: u32,
    /// Number of active contexts.
    active_count: usize,
}

impl UserfaultfdManager {
    /// Create a new userfaultfd manager.
    pub fn new() -> Self {
        Self {
            contexts: [const { None }; MAX_UFFD_CONTEXTS],
            next_id: 0,
            active_count: 0,
        }
    }

    /// Create a new userfaultfd context.
    ///
    /// # Errors
    ///
    /// Returns `OutOfMemory` if the maximum number of contexts is reached.
    pub fn create_context(&mut self, mode: u32, features: u32) -> Result<u32> {
        if self.active_count >= MAX_UFFD_CONTEXTS {
            return Err(Error::OutOfMemory);
        }

        // Find a free slot.
        let slot = self
            .contexts
            .iter()
            .position(|c| c.is_none())
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id += 1;

        self.contexts[slot] = Some(UserfaultfdCtx::new(id, mode, features));
        self.active_count += 1;

        Ok(id)
    }

    /// Get a reference to a context by ID.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the context doesn't exist.
    pub fn get_context(&self, id: u32) -> Result<&UserfaultfdCtx> {
        for ctx in self.contexts.iter().flatten() {
            if ctx.id == id && ctx.active {
                return Ok(ctx);
            }
        }
        Err(Error::NotFound)
    }

    /// Get a mutable reference to a context by ID.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the context doesn't exist.
    pub fn get_context_mut(&mut self, id: u32) -> Result<&mut UserfaultfdCtx> {
        for ctx in self.contexts.iter_mut().flatten() {
            if ctx.id == id && ctx.active {
                return Ok(ctx);
            }
        }
        Err(Error::NotFound)
    }

    /// Destroy a userfaultfd context.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the context doesn't exist.
    pub fn destroy_context(&mut self, id: u32) -> Result<()> {
        for slot in self.contexts.iter_mut() {
            if let Some(ctx) = slot {
                if ctx.id == id {
                    *slot = None;
                    self.active_count = self.active_count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Get the number of active contexts.
    pub fn context_count(&self) -> usize {
        self.active_count
    }
}
