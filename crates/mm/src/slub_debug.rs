// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SLUB allocator debugging support.
//!
//! Provides debugging and validation facilities for the SLUB slab
//! allocator, including red-zone checking, free-pointer validation,
//! allocation/free tracking, and poison patterns.
//!
//! - [`SlubDebugFlag`] — debug feature flags
//! - [`SlubDebugConfig`] — debug configuration per cache
//! - [`SlubTraceEntry`] — allocation/free trace record
//! - [`SlubDebugStats`] — error/validation statistics
//! - [`SlubDebugger`] — the debugging engine
//!
//! Reference: Linux `mm/slub.c` (debug sections).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Red-zone fill pattern.
const REDZONE_PATTERN: u8 = 0xBB;

/// Poison fill pattern for freed objects.
const POISON_FREE: u8 = 0x6B;

/// Poison fill pattern for allocated objects.
const POISON_ALLOC: u8 = 0x5A;

/// Maximum trace entries.
const MAX_TRACE_ENTRIES: usize = 512;

/// Maximum caches tracked.
const MAX_CACHES: usize = 64;

/// Red-zone size in bytes.
const REDZONE_SIZE: usize = 8;

// -------------------------------------------------------------------
// SlubDebugFlag
// -------------------------------------------------------------------

/// Debug feature flags for SLUB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SlubDebugFlag {
    /// Raw flag bits.
    bits: u32,
}

impl SlubDebugFlag {
    /// Enable red-zone checking.
    pub const REDZONE: u32 = 1 << 0;
    /// Enable poison pattern on free.
    pub const POISON: u32 = 1 << 1;
    /// Enable allocation/free tracking.
    pub const TRACK: u32 = 1 << 2;
    /// Enable free-pointer consistency check.
    pub const CONSISTENCY: u32 = 1 << 3;
    /// Enable sanity checks on alloc.
    pub const SANITY: u32 = 1 << 4;

    /// All debug flags enabled.
    pub fn all() -> Self {
        Self {
            bits: Self::REDZONE | Self::POISON | Self::TRACK | Self::CONSISTENCY | Self::SANITY,
        }
    }

    /// Creates empty flags.
    pub fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Tests a flag.
    pub fn contains(self, flag: u32) -> bool {
        self.bits & flag == flag
    }

    /// Sets a flag.
    pub fn set(self, flag: u32) -> Self {
        Self {
            bits: self.bits | flag,
        }
    }
}

// -------------------------------------------------------------------
// SlubDebugConfig
// -------------------------------------------------------------------

/// Debug configuration for a slab cache.
#[derive(Debug, Clone, Copy, Default)]
pub struct SlubDebugConfig {
    /// Cache name hash (for identification).
    pub cache_id: u64,
    /// Object size in bytes.
    pub object_size: usize,
    /// Debug flags enabled.
    pub flags: SlubDebugFlag,
    /// Whether this config is active.
    pub active: bool,
}

impl SlubDebugConfig {
    /// Creates a new debug config.
    pub fn new(cache_id: u64, object_size: usize, flags: SlubDebugFlag) -> Self {
        Self {
            cache_id,
            object_size,
            flags,
            active: true,
        }
    }

    /// Returns the total object size including red-zones.
    pub fn total_size(&self) -> usize {
        if self.flags.contains(SlubDebugFlag::REDZONE) {
            self.object_size + 2 * REDZONE_SIZE
        } else {
            self.object_size
        }
    }
}

// -------------------------------------------------------------------
// SlubTraceEntry
// -------------------------------------------------------------------

/// An allocation or free trace record.
#[derive(Debug, Clone, Copy, Default)]
pub struct SlubTraceEntry {
    /// Cache ID.
    pub cache_id: u64,
    /// Object address (simulated).
    pub object_addr: u64,
    /// Whether this is an allocation (true) or free (false).
    pub is_alloc: bool,
    /// Timestamp (nanoseconds).
    pub timestamp_ns: u64,
    /// Caller address (simulated).
    pub caller: u64,
    /// Whether this entry is active.
    pub active: bool,
}

// -------------------------------------------------------------------
// SlubDebugStats
// -------------------------------------------------------------------

/// SLUB debug statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct SlubDebugStats {
    /// Total allocations tracked.
    pub allocs_tracked: u64,
    /// Total frees tracked.
    pub frees_tracked: u64,
    /// Red-zone violations detected.
    pub redzone_errors: u64,
    /// Poison pattern violations detected.
    pub poison_errors: u64,
    /// Double-free detections.
    pub double_frees: u64,
    /// Consistency check failures.
    pub consistency_errors: u64,
    /// Total validations performed.
    pub validations: u64,
}

impl SlubDebugStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// SlubDebugger
// -------------------------------------------------------------------

/// The SLUB debugging engine.
pub struct SlubDebugger {
    /// Cache configurations.
    caches: [SlubDebugConfig; MAX_CACHES],
    /// Number of tracked caches.
    cache_count: usize,
    /// Trace log.
    traces: [SlubTraceEntry; MAX_TRACE_ENTRIES],
    /// Number of trace entries.
    trace_count: usize,
    /// Statistics.
    stats: SlubDebugStats,
}

impl Default for SlubDebugger {
    fn default() -> Self {
        Self {
            caches: [SlubDebugConfig::default(); MAX_CACHES],
            cache_count: 0,
            traces: [SlubTraceEntry::default(); MAX_TRACE_ENTRIES],
            trace_count: 0,
            stats: SlubDebugStats::default(),
        }
    }
}

impl SlubDebugger {
    /// Creates a new SLUB debugger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a cache for debugging.
    pub fn register_cache(
        &mut self,
        cache_id: u64,
        object_size: usize,
        flags: SlubDebugFlag,
    ) -> Result<usize> {
        if self.cache_count >= MAX_CACHES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.cache_count;
        self.caches[idx] = SlubDebugConfig::new(cache_id, object_size, flags);
        self.cache_count += 1;
        Ok(idx)
    }

    /// Records an allocation event.
    pub fn track_alloc(&mut self, cache_id: u64, object_addr: u64, timestamp_ns: u64, caller: u64) {
        if self.trace_count < MAX_TRACE_ENTRIES {
            self.traces[self.trace_count] = SlubTraceEntry {
                cache_id,
                object_addr,
                is_alloc: true,
                timestamp_ns,
                caller,
                active: true,
            };
            self.trace_count += 1;
        }
        self.stats.allocs_tracked += 1;
    }

    /// Records a free event and checks for double-free.
    pub fn track_free(
        &mut self,
        cache_id: u64,
        object_addr: u64,
        timestamp_ns: u64,
        caller: u64,
    ) -> Result<()> {
        // Check for double-free: last trace for this object must be alloc.
        let mut last_is_alloc = false;
        let mut found = false;
        for i in (0..self.trace_count).rev() {
            if self.traces[i].active
                && self.traces[i].cache_id == cache_id
                && self.traces[i].object_addr == object_addr
            {
                last_is_alloc = self.traces[i].is_alloc;
                found = true;
                break;
            }
        }

        if found && !last_is_alloc {
            self.stats.double_frees += 1;
            return Err(Error::InvalidArgument);
        }

        if self.trace_count < MAX_TRACE_ENTRIES {
            self.traces[self.trace_count] = SlubTraceEntry {
                cache_id,
                object_addr,
                is_alloc: false,
                timestamp_ns,
                caller,
                active: true,
            };
            self.trace_count += 1;
        }
        self.stats.frees_tracked += 1;
        Ok(())
    }

    /// Validates a red-zone pattern (simulated).
    pub fn check_redzone(&mut self, pattern: &[u8]) -> bool {
        self.stats.validations += 1;
        for byte in pattern {
            if *byte != REDZONE_PATTERN {
                self.stats.redzone_errors += 1;
                return false;
            }
        }
        true
    }

    /// Validates a poison pattern (simulated).
    pub fn check_poison(&mut self, data: &[u8], is_free: bool) -> bool {
        self.stats.validations += 1;
        let expected = if is_free { POISON_FREE } else { POISON_ALLOC };
        for byte in data {
            if *byte != expected {
                self.stats.poison_errors += 1;
                return false;
            }
        }
        true
    }

    /// Returns the number of tracked caches.
    pub fn cache_count(&self) -> usize {
        self.cache_count
    }

    /// Returns the number of trace entries.
    pub fn trace_count(&self) -> usize {
        self.trace_count
    }

    /// Returns statistics.
    pub fn stats(&self) -> &SlubDebugStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
