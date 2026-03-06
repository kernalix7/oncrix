// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Userfaultfd write-protect mode.
//!
//! Extends userfaultfd with write-protect (WP) tracking. When WP mode
//! is enabled on a range, any write to a WP-registered page triggers a
//! userfault event instead of a normal CoW fault. This enables
//! user-space dirty tracking for live migration and checkpointing.
//!
//! # Design
//!
//! ```text
//!  uffdio_writeprotect(range, UFFDIO_WRITEPROTECT_MODE_WP)
//!     │
//!     ├─ mark PTEs read-only in range
//!     ├─ flush TLB
//!     └─ future writes → userfault WP event → user-space handler
//!
//!  uffdio_writeprotect(range, 0)  (clear WP)
//!     │
//!     ├─ restore writable PTEs
//!     └─ flush TLB
//! ```
//!
//! # Key Types
//!
//! - [`WpRange`] — a write-protected range
//! - [`WpEvent`] — a write-protect fault event
//! - [`UserfaultfdWp`] — WP mode manager
//! - [`WpStats`] — write-protect statistics
//!
//! Reference: Linux `mm/userfaultfd.c`, `include/linux/userfaultfd_k.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum write-protected ranges.
const MAX_WP_RANGES: usize = 512;

/// Maximum queued WP events.
const MAX_WP_EVENTS: usize = 4096;

/// Page size.
const PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// WpRange
// -------------------------------------------------------------------

/// A write-protected range.
#[derive(Debug, Clone, Copy)]
pub struct WpRange {
    /// Start address (page-aligned).
    start_addr: u64,
    /// End address (page-aligned, exclusive).
    end_addr: u64,
    /// Whether WP is currently active.
    active: bool,
    /// Associated userfaultfd descriptor.
    uffd: u64,
    /// Number of faults in this range.
    fault_count: u64,
    /// Timestamp when WP was enabled.
    enabled_at: u64,
}

impl WpRange {
    /// Create a new WP range.
    pub const fn new(start_addr: u64, end_addr: u64, uffd: u64, timestamp: u64) -> Self {
        Self {
            start_addr,
            end_addr,
            active: true,
            uffd,
            fault_count: 0,
            enabled_at: timestamp,
        }
    }

    /// Return the start address.
    pub const fn start_addr(&self) -> u64 {
        self.start_addr
    }

    /// Return the end address.
    pub const fn end_addr(&self) -> u64 {
        self.end_addr
    }

    /// Check whether WP is active.
    pub const fn active(&self) -> bool {
        self.active
    }

    /// Return the uffd descriptor.
    pub const fn uffd(&self) -> u64 {
        self.uffd
    }

    /// Return the fault count.
    pub const fn fault_count(&self) -> u64 {
        self.fault_count
    }

    /// Return the page count.
    pub const fn page_count(&self) -> u64 {
        (self.end_addr - self.start_addr) / PAGE_SIZE
    }

    /// Deactivate WP.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Record a fault.
    pub fn record_fault(&mut self) {
        self.fault_count = self.fault_count.saturating_add(1);
    }

    /// Check whether an address falls in this range.
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start_addr && addr < self.end_addr
    }
}

impl Default for WpRange {
    fn default() -> Self {
        Self {
            start_addr: 0,
            end_addr: 0,
            active: false,
            uffd: 0,
            fault_count: 0,
            enabled_at: 0,
        }
    }
}

// -------------------------------------------------------------------
// WpEvent
// -------------------------------------------------------------------

/// A write-protect fault event.
#[derive(Debug, Clone, Copy)]
pub struct WpEvent {
    /// Faulting address.
    addr: u64,
    /// Associated uffd descriptor.
    uffd: u64,
    /// Faulting thread ID.
    thread_id: u64,
    /// Timestamp of the fault.
    timestamp: u64,
    /// Whether the event has been consumed by user space.
    consumed: bool,
}

impl WpEvent {
    /// Create a new WP event.
    pub const fn new(addr: u64, uffd: u64, thread_id: u64, timestamp: u64) -> Self {
        Self {
            addr,
            uffd,
            thread_id,
            timestamp,
            consumed: false,
        }
    }

    /// Return the faulting address.
    pub const fn addr(&self) -> u64 {
        self.addr
    }

    /// Return the uffd.
    pub const fn uffd(&self) -> u64 {
        self.uffd
    }

    /// Return the thread ID.
    pub const fn thread_id(&self) -> u64 {
        self.thread_id
    }

    /// Return the timestamp.
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Check whether the event is consumed.
    pub const fn consumed(&self) -> bool {
        self.consumed
    }

    /// Mark the event as consumed.
    pub fn consume(&mut self) {
        self.consumed = true;
    }
}

impl Default for WpEvent {
    fn default() -> Self {
        Self {
            addr: 0,
            uffd: 0,
            thread_id: 0,
            timestamp: 0,
            consumed: false,
        }
    }
}

// -------------------------------------------------------------------
// WpStats
// -------------------------------------------------------------------

/// Write-protect statistics.
#[derive(Debug, Clone, Copy)]
pub struct WpStats {
    /// Total WP ranges registered.
    pub ranges_registered: u64,
    /// Total WP ranges deactivated.
    pub ranges_deactivated: u64,
    /// Total WP faults.
    pub total_faults: u64,
    /// Events consumed by user space.
    pub events_consumed: u64,
    /// Events dropped (queue full).
    pub events_dropped: u64,
}

impl WpStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            ranges_registered: 0,
            ranges_deactivated: 0,
            total_faults: 0,
            events_consumed: 0,
            events_dropped: 0,
        }
    }

    /// Event consumption rate as percent.
    pub const fn consumption_pct(&self) -> u64 {
        if self.total_faults == 0 {
            return 0;
        }
        self.events_consumed * 100 / self.total_faults
    }
}

impl Default for WpStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// UserfaultfdWp
// -------------------------------------------------------------------

/// WP mode manager for userfaultfd.
pub struct UserfaultfdWp {
    /// WP ranges.
    ranges: [WpRange; MAX_WP_RANGES],
    /// Number of ranges.
    range_count: usize,
    /// Event queue.
    events: [WpEvent; MAX_WP_EVENTS],
    /// Number of events in queue.
    event_count: usize,
    /// Statistics.
    stats: WpStats,
}

impl UserfaultfdWp {
    /// Create a new WP manager.
    pub const fn new() -> Self {
        Self {
            ranges: [const {
                WpRange {
                    start_addr: 0,
                    end_addr: 0,
                    active: false,
                    uffd: 0,
                    fault_count: 0,
                    enabled_at: 0,
                }
            }; MAX_WP_RANGES],
            range_count: 0,
            events: [const {
                WpEvent {
                    addr: 0,
                    uffd: 0,
                    thread_id: 0,
                    timestamp: 0,
                    consumed: false,
                }
            }; MAX_WP_EVENTS],
            event_count: 0,
            stats: WpStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &WpStats {
        &self.stats
    }

    /// Return the number of WP ranges.
    pub const fn range_count(&self) -> usize {
        self.range_count
    }

    /// Return the number of queued events.
    pub const fn event_count(&self) -> usize {
        self.event_count
    }

    /// Register a WP range.
    pub fn register_range(
        &mut self,
        start_addr: u64,
        end_addr: u64,
        uffd: u64,
        timestamp: u64,
    ) -> Result<()> {
        if (start_addr % PAGE_SIZE) != 0 || (end_addr % PAGE_SIZE) != 0 {
            return Err(Error::InvalidArgument);
        }
        if start_addr >= end_addr {
            return Err(Error::InvalidArgument);
        }
        if self.range_count >= MAX_WP_RANGES {
            return Err(Error::OutOfMemory);
        }
        self.ranges[self.range_count] = WpRange::new(start_addr, end_addr, uffd, timestamp);
        self.range_count += 1;
        self.stats.ranges_registered += 1;
        Ok(())
    }

    /// Handle a WP fault.
    pub fn handle_fault(&mut self, addr: u64, thread_id: u64, timestamp: u64) -> Result<()> {
        // Find matching range.
        let mut found_uffd = 0u64;
        let mut found = false;
        for idx in 0..self.range_count {
            if self.ranges[idx].active() && self.ranges[idx].contains(addr) {
                self.ranges[idx].record_fault();
                found_uffd = self.ranges[idx].uffd();
                found = true;
                break;
            }
        }
        if !found {
            return Err(Error::NotFound);
        }

        self.stats.total_faults += 1;

        // Queue event.
        if self.event_count >= MAX_WP_EVENTS {
            self.stats.events_dropped += 1;
            return Err(Error::OutOfMemory);
        }
        self.events[self.event_count] = WpEvent::new(addr, found_uffd, thread_id, timestamp);
        self.event_count += 1;
        Ok(())
    }

    /// Consume the next event.
    pub fn consume_event(&mut self) -> Option<WpEvent> {
        for idx in 0..self.event_count {
            if !self.events[idx].consumed() {
                self.events[idx].consume();
                self.stats.events_consumed += 1;
                return Some(self.events[idx]);
            }
        }
        None
    }

    /// Deactivate a WP range by start address.
    pub fn deactivate_range(&mut self, start_addr: u64) -> Result<()> {
        for idx in 0..self.range_count {
            if self.ranges[idx].start_addr() == start_addr && self.ranges[idx].active() {
                self.ranges[idx].deactivate();
                self.stats.ranges_deactivated += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }
}

impl Default for UserfaultfdWp {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum WP ranges.
pub const fn max_wp_ranges() -> usize {
    MAX_WP_RANGES
}

/// Return the maximum WP events.
pub const fn max_wp_events() -> usize {
    MAX_WP_EVENTS
}
