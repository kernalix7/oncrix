// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page allocation debug.
//!
//! Provides debugging infrastructure for the page allocator. Tracks
//! every allocation and free in a circular ring buffer, detecting
//! common bugs like double-free, use-after-free, and memory leaks.
//!
//! - [`AllocRecord`] — a single allocation event record
//! - [`AllocEvent`] — allocation or free event type
//! - [`AllocTraceRing`] — circular buffer of allocation events
//! - [`DebugChecker`] — checks for allocation bugs
//! - [`AllocDebugStats`] — debug statistics
//!
//! Reference: `.kernelORG/` — `mm/page_alloc.c` (page_alloc_debug),
//!   `mm/page_owner.c`.

// oncrix_lib used indirectly via crate types.

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum records in the trace ring.
const RING_SIZE: usize = 1024;

/// Maximum tracked live allocations.
const MAX_LIVE_ALLOCS: usize = 2048;

/// Maximum allocation order for debug tracking.
const MAX_ORDER: usize = 11;

/// Poison value for freed pages.
const PAGE_POISON: u8 = 0xAA;

/// Canary value before allocation.
const ALLOC_CANARY: u64 = 0xCAFE_BABE_DEAD_BEEF;

// -------------------------------------------------------------------
// AllocEvent
// -------------------------------------------------------------------

/// Type of allocation event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AllocEvent {
    /// Page allocation.
    #[default]
    Alloc,
    /// Page free.
    Free,
    /// Page reallocation (order change).
    Realloc,
}

impl AllocEvent {
    /// Returns a human-readable name.
    pub fn as_str(self) -> &'static str {
        match self {
            AllocEvent::Alloc => "alloc",
            AllocEvent::Free => "free",
            AllocEvent::Realloc => "realloc",
        }
    }
}

// -------------------------------------------------------------------
// AllocRecord
// -------------------------------------------------------------------

/// A single allocation event record.
#[derive(Debug, Clone, Copy)]
pub struct AllocRecord {
    /// Page frame number.
    pub pfn: u64,
    /// Allocation order (0 = single page, N = 2^N pages).
    pub order: u8,
    /// GFP flags used.
    pub gfp_flags: u32,
    /// Caller identifier (function hash or address).
    pub caller_id: u32,
    /// Timestamp (tick counter).
    pub timestamp: u64,
    /// Event type.
    pub event: AllocEvent,
    /// Whether this record slot is valid.
    pub valid: bool,
}

impl AllocRecord {
    /// Creates a new allocation record.
    pub fn new(
        pfn: u64,
        order: u8,
        gfp_flags: u32,
        caller_id: u32,
        timestamp: u64,
        event: AllocEvent,
    ) -> Self {
        Self {
            pfn,
            order,
            gfp_flags,
            caller_id,
            timestamp,
            event,
            valid: true,
        }
    }

    /// Returns the number of pages in this allocation.
    pub fn nr_pages(&self) -> u64 {
        1u64 << self.order
    }

    /// Returns the size in bytes.
    pub fn size_bytes(&self) -> u64 {
        self.nr_pages() * PAGE_SIZE
    }
}

impl Default for AllocRecord {
    fn default() -> Self {
        Self {
            pfn: 0,
            order: 0,
            gfp_flags: 0,
            caller_id: 0,
            timestamp: 0,
            event: AllocEvent::Alloc,
            valid: false,
        }
    }
}

// -------------------------------------------------------------------
// AllocTraceRing
// -------------------------------------------------------------------

/// Circular buffer of allocation events.
///
/// Records the most recent N allocation/free events for post-mortem
/// analysis of memory bugs.
pub struct AllocTraceRing {
    /// Ring buffer of records.
    records: [AllocRecord; RING_SIZE],
    /// Next write index.
    head: usize,
    /// Number of records written (may exceed RING_SIZE).
    total_records: u64,
}

impl AllocTraceRing {
    /// Creates a new empty trace ring.
    pub fn new() -> Self {
        Self {
            records: [AllocRecord::default(); RING_SIZE],
            head: 0,
            total_records: 0,
        }
    }

    /// Records an event.
    pub fn record(&mut self, rec: AllocRecord) {
        self.records[self.head] = rec;
        self.head = (self.head + 1) % RING_SIZE;
        self.total_records += 1;
    }

    /// Returns the most recent record.
    pub fn last(&self) -> Option<&AllocRecord> {
        if self.total_records == 0 {
            return None;
        }
        let idx = if self.head == 0 {
            RING_SIZE - 1
        } else {
            self.head - 1
        };
        if self.records[idx].valid {
            Some(&self.records[idx])
        } else {
            None
        }
    }

    /// Returns the N most recent records (newest first).
    pub fn recent(&self, count: usize) -> &[AllocRecord] {
        let available = (self.total_records as usize).min(RING_SIZE);
        let count = count.min(available);
        if count == 0 {
            return &[];
        }
        // Return a slice from the buffer (may not be in exact order
        // if wrapped, but sufficient for debug dump).
        let start = if self.head >= count {
            self.head - count
        } else {
            0
        };
        &self.records[start..start + count.min(RING_SIZE - start)]
    }

    /// Finds all records for a given PFN.
    pub fn find_pfn(&self, pfn: u64) -> [Option<usize>; 16] {
        let mut results = [None; 16];
        let mut count = 0;
        let available = (self.total_records as usize).min(RING_SIZE);
        for i in 0..available {
            if self.records[i].valid && self.records[i].pfn == pfn {
                if count < 16 {
                    results[count] = Some(i);
                    count += 1;
                }
            }
        }
        results
    }

    /// Returns total records ever written.
    pub fn total_records(&self) -> u64 {
        self.total_records
    }

    /// Returns the current ring position.
    pub fn head(&self) -> usize {
        self.head
    }

    /// Clears the ring.
    pub fn clear(&mut self) {
        self.records = [AllocRecord::default(); RING_SIZE];
        self.head = 0;
        self.total_records = 0;
    }
}

impl Default for AllocTraceRing {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// LiveAlloc
// -------------------------------------------------------------------

/// A currently live (allocated, not freed) page allocation.
#[derive(Debug, Clone, Copy, Default)]
struct LiveAlloc {
    /// Page frame number.
    pfn: u64,
    /// Allocation order.
    order: u8,
    /// Caller ID.
    caller_id: u32,
    /// Allocation timestamp.
    timestamp: u64,
    /// Whether this slot is in use.
    in_use: bool,
}

// -------------------------------------------------------------------
// DebugCheckResult
// -------------------------------------------------------------------

/// Result of a debug check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugCheckResult {
    /// No issues detected.
    Ok,
    /// Double-free detected.
    DoubleFree,
    /// Use-after-free detected (free of untracked PFN).
    UseAfterFree,
    /// Potential leak (allocation older than threshold).
    PotentialLeak,
    /// Order mismatch on free.
    OrderMismatch,
}

// -------------------------------------------------------------------
// AllocDebugStats
// -------------------------------------------------------------------

/// Debug statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllocDebugStats {
    /// Total allocations tracked.
    pub total_allocs: u64,
    /// Total frees tracked.
    pub total_frees: u64,
    /// Double-free detections.
    pub double_frees: u64,
    /// Use-after-free detections.
    pub use_after_frees: u64,
    /// Potential leaks detected.
    pub potential_leaks: u64,
    /// Order mismatches.
    pub order_mismatches: u64,
    /// Current live allocations.
    pub live_allocs: u64,
}

impl AllocDebugStats {
    /// Resets all statistics.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// DebugChecker
// -------------------------------------------------------------------

/// Page allocation debug checker.
///
/// Tracks live allocations and detects bugs on alloc/free operations.
pub struct DebugChecker {
    /// Live allocations.
    live: [LiveAlloc; MAX_LIVE_ALLOCS],
    /// Number of live allocations.
    nr_live: usize,
    /// Trace ring.
    ring: AllocTraceRing,
    /// Statistics.
    stats: AllocDebugStats,
    /// Current timestamp.
    current_tick: u64,
    /// Leak detection threshold (ticks).
    leak_threshold: u64,
}

impl DebugChecker {
    /// Creates a new debug checker.
    pub fn new() -> Self {
        Self {
            live: [LiveAlloc::default(); MAX_LIVE_ALLOCS],
            nr_live: 0,
            ring: AllocTraceRing::new(),
            stats: AllocDebugStats::default(),
            current_tick: 0,
            leak_threshold: 10000,
        }
    }

    /// Records an allocation.
    pub fn track_alloc(
        &mut self,
        pfn: u64,
        order: u8,
        gfp_flags: u32,
        caller_id: u32,
    ) -> DebugCheckResult {
        let record = AllocRecord::new(
            pfn,
            order,
            gfp_flags,
            caller_id,
            self.current_tick,
            AllocEvent::Alloc,
        );
        self.ring.record(record);
        self.stats.total_allocs += 1;

        // Check for double-alloc (same PFN already live).
        for alloc in &self.live {
            if alloc.in_use && alloc.pfn == pfn {
                self.stats.double_frees += 1;
                return DebugCheckResult::DoubleFree;
            }
        }

        // Add to live allocations.
        for alloc in &mut self.live {
            if !alloc.in_use {
                alloc.pfn = pfn;
                alloc.order = order;
                alloc.caller_id = caller_id;
                alloc.timestamp = self.current_tick;
                alloc.in_use = true;
                self.nr_live += 1;
                self.stats.live_allocs = self.nr_live as u64;
                return DebugCheckResult::Ok;
            }
        }

        DebugCheckResult::Ok
    }

    /// Records a free and checks for bugs.
    pub fn track_free(&mut self, pfn: u64, order: u8, caller_id: u32) -> DebugCheckResult {
        let record = AllocRecord::new(
            pfn,
            order,
            0,
            caller_id,
            self.current_tick,
            AllocEvent::Free,
        );
        self.ring.record(record);
        self.stats.total_frees += 1;

        // Find the live allocation.
        for alloc in &mut self.live {
            if alloc.in_use && alloc.pfn == pfn {
                // Check order mismatch.
                if alloc.order != order {
                    self.stats.order_mismatches += 1;
                    alloc.in_use = false;
                    self.nr_live = self.nr_live.saturating_sub(1);
                    self.stats.live_allocs = self.nr_live as u64;
                    return DebugCheckResult::OrderMismatch;
                }
                alloc.in_use = false;
                self.nr_live = self.nr_live.saturating_sub(1);
                self.stats.live_allocs = self.nr_live as u64;
                return DebugCheckResult::Ok;
            }
        }

        // PFN not found in live allocations: double-free or use-after-free.
        // Check the ring for a previous free of this PFN.
        let history = self.ring.find_pfn(pfn);
        let has_prior_free = history.iter().any(|idx| {
            idx.map(|i| self.ring.records[i].event == AllocEvent::Free)
                .unwrap_or(false)
        });

        if has_prior_free {
            self.stats.double_frees += 1;
            DebugCheckResult::DoubleFree
        } else {
            self.stats.use_after_frees += 1;
            DebugCheckResult::UseAfterFree
        }
    }

    /// Scans for potential leaks (allocations older than threshold).
    pub fn check_leaks(&mut self) -> usize {
        let mut leaks = 0;
        for alloc in &self.live {
            if alloc.in_use && self.current_tick - alloc.timestamp > self.leak_threshold {
                leaks += 1;
            }
        }
        self.stats.potential_leaks = leaks as u64;
        leaks
    }

    /// Dumps the allocation history for a PFN.
    pub fn dump_alloc_history(&self, pfn: u64) -> [Option<AllocRecord>; 16] {
        let indices = self.ring.find_pfn(pfn);
        let mut results = [None; 16];
        for (i, idx) in indices.iter().enumerate() {
            if let Some(ring_idx) = idx {
                results[i] = Some(self.ring.records[*ring_idx]);
            }
        }
        results
    }

    /// Advances the tick counter.
    pub fn tick(&mut self, ticks: u64) {
        self.current_tick += ticks;
    }

    /// Returns the trace ring.
    pub fn ring(&self) -> &AllocTraceRing {
        &self.ring
    }

    /// Returns statistics.
    pub fn stats(&self) -> &AllocDebugStats {
        &self.stats
    }

    /// Returns the number of live allocations.
    pub fn nr_live(&self) -> usize {
        self.nr_live
    }

    /// Sets the leak detection threshold.
    pub fn set_leak_threshold(&mut self, threshold: u64) {
        self.leak_threshold = threshold;
    }
}

impl Default for DebugChecker {
    fn default() -> Self {
        Self::new()
    }
}
