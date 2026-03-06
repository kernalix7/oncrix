// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Slab debugging subsystem.
//!
//! Provides runtime checks for slab allocator correctness: red-zone
//! padding detection, poison patterns for freed objects, allocation/
//! free caller tracking, and consistency checks. These are
//! compile-time-optional (enabled via flags) and intended for
//! development and debugging.
//!
//! - [`SlabDebugFlags`] — per-cache debug feature flags
//! - [`RedZone`] — red-zone canary and check logic
//! - [`PoisonPattern`] — poison byte patterns for free/alloc
//! - [`FreeTrack`] — allocation/free site tracker
//! - [`SlabDebugReport`] — structured bug report
//! - [`SlabDebugger`] — the main slab debugging engine
//!
//! Reference: `.kernelORG/` — `mm/slub.c` (debug paths),
//! `include/linux/slub_def.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Red-zone canary value (magic bytes at object boundaries).
const RED_ZONE_MAGIC: u64 = 0xBB44_1133_AABB_5566;

/// Red-zone size in bytes (placed before and after each object).
const RED_ZONE_SIZE: usize = 8;

/// Poison byte for freed objects (0x6b = 'k' for "killed").
const POISON_FREE: u8 = 0x6b;

/// Poison byte for newly allocated objects (0x5a = 'Z' for "zapped").
const POISON_ALLOC: u8 = 0x5a;

/// Poison byte for the end-of-object marker.
const POISON_END: u8 = 0xa5;

/// Maximum number of tracked caches.
const MAX_TRACKED_CACHES: usize = 32;

/// Maximum number of free-track entries per cache.
const MAX_FREE_TRACK: usize = 64;

/// Maximum number of bug reports.
const MAX_BUG_REPORTS: usize = 32;

/// Maximum object size for poisoning (larger objects are skipped).
const MAX_POISON_SIZE: usize = 4096;

// -------------------------------------------------------------------
// SlabDebugFlags
// -------------------------------------------------------------------

/// Per-cache debug feature flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SlabDebugFlags {
    /// Raw flag bits.
    bits: u32,
}

impl SlabDebugFlags {
    /// Enable red-zone checks.
    pub const POISON: u32 = 1 << 0;
    /// Enable poison pattern on free/alloc.
    pub const RED_ZONE: u32 = 1 << 1;
    /// Track allocation/free call sites.
    pub const STORE_USER: u32 = 1 << 2;
    /// Enable allocation/free tracing.
    pub const TRACE: u32 = 1 << 3;
    /// Enable consistency checks.
    pub const CONSISTENCY_CHECKS: u32 = 1 << 4;

    /// Creates an empty flag set.
    pub fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Creates with all debug features enabled.
    pub fn all() -> Self {
        Self {
            bits: Self::POISON
                | Self::RED_ZONE
                | Self::STORE_USER
                | Self::TRACE
                | Self::CONSISTENCY_CHECKS,
        }
    }

    /// Creates from raw bits.
    pub fn from_bits(bits: u32) -> Self {
        Self { bits }
    }

    /// Returns raw bits.
    pub fn bits(self) -> u32 {
        self.bits
    }

    /// Tests if a flag is set.
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
// RedZone
// -------------------------------------------------------------------

/// Red-zone state for a single object.
#[derive(Debug, Clone, Copy, Default)]
pub struct RedZone {
    /// Canary before the object.
    pub head_canary: u64,
    /// Canary after the object.
    pub tail_canary: u64,
    /// Object size (excluding red zones).
    pub object_size: usize,
}

impl RedZone {
    /// Creates red-zone canaries for an object.
    pub fn new(object_size: usize) -> Self {
        Self {
            head_canary: RED_ZONE_MAGIC,
            tail_canary: RED_ZONE_MAGIC,
            object_size,
        }
    }

    /// Checks whether both canaries are intact.
    pub fn check(&self) -> bool {
        self.head_canary == RED_ZONE_MAGIC && self.tail_canary == RED_ZONE_MAGIC
    }

    /// Returns which canary (if any) is corrupt.
    pub fn corrupted_side(&self) -> Option<&'static str> {
        if self.head_canary != RED_ZONE_MAGIC {
            Some("head")
        } else if self.tail_canary != RED_ZONE_MAGIC {
            Some("tail")
        } else {
            None
        }
    }

    /// Resets canaries to the magic value.
    pub fn reset(&mut self) {
        self.head_canary = RED_ZONE_MAGIC;
        self.tail_canary = RED_ZONE_MAGIC;
    }
}

// -------------------------------------------------------------------
// PoisonPattern
// -------------------------------------------------------------------

/// Poison byte pattern checker.
#[derive(Debug, Clone, Copy, Default)]
pub struct PoisonPattern {
    /// Expected pattern byte.
    pub pattern: u8,
    /// Size to check.
    pub size: usize,
}

impl PoisonPattern {
    /// Creates a pattern for freed objects.
    pub fn free_pattern(size: usize) -> Self {
        Self {
            pattern: POISON_FREE,
            size: size.min(MAX_POISON_SIZE),
        }
    }

    /// Creates a pattern for newly allocated objects.
    pub fn alloc_pattern(size: usize) -> Self {
        Self {
            pattern: POISON_ALLOC,
            size: size.min(MAX_POISON_SIZE),
        }
    }

    /// Checks a byte buffer against the expected pattern.
    ///
    /// Returns the offset of the first mismatch, or `None` if all
    /// bytes match.
    pub fn check(&self, data: &[u8]) -> Option<usize> {
        let check_len = self.size.min(data.len());
        for i in 0..check_len {
            if data[i] != self.pattern {
                return Some(i);
            }
        }
        None
    }

    /// Fills a buffer with the poison pattern.
    pub fn fill(&self, data: &mut [u8]) {
        let fill_len = self.size.min(data.len());
        for byte in data[..fill_len].iter_mut() {
            *byte = self.pattern;
        }
        // Place end marker.
        if fill_len < data.len() {
            data[fill_len] = POISON_END;
        }
    }
}

// -------------------------------------------------------------------
// FreeTrackEntry
// -------------------------------------------------------------------

/// A single allocation/free tracking record.
#[derive(Debug, Clone, Copy, Default)]
pub struct FreeTrackEntry {
    /// Caller address (alloc site).
    pub alloc_caller: u64,
    /// Caller address (free site, 0 if not freed).
    pub free_caller: u64,
    /// Object index within the slab.
    pub object_index: usize,
    /// Whether the object is currently allocated.
    pub allocated: bool,
    /// Allocation timestamp (monotonic ns).
    pub alloc_ts: u64,
    /// Free timestamp (0 if not freed).
    pub free_ts: u64,
}

// -------------------------------------------------------------------
// FreeTrack
// -------------------------------------------------------------------

/// Allocation/free site tracker for a cache.
pub struct FreeTrack {
    /// Tracking entries.
    entries: [FreeTrackEntry; MAX_FREE_TRACK],
    /// Number of entries.
    count: usize,
    /// Cache name identifier.
    cache_id: u64,
}

impl Default for FreeTrack {
    fn default() -> Self {
        Self {
            entries: [FreeTrackEntry::default(); MAX_FREE_TRACK],
            count: 0,
            cache_id: 0,
        }
    }
}

impl FreeTrack {
    /// Creates a new tracker for the given cache.
    pub fn new(cache_id: u64) -> Self {
        Self {
            cache_id,
            ..Self::default()
        }
    }

    /// Records an allocation event.
    pub fn record_alloc(&mut self, object_index: usize, caller: u64, timestamp: u64) -> Result<()> {
        // Try to find existing entry for this object.
        for i in 0..self.count {
            if self.entries[i].object_index == object_index {
                self.entries[i].alloc_caller = caller;
                self.entries[i].alloc_ts = timestamp;
                self.entries[i].allocated = true;
                self.entries[i].free_caller = 0;
                self.entries[i].free_ts = 0;
                return Ok(());
            }
        }
        // New entry.
        if self.count >= MAX_FREE_TRACK {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = FreeTrackEntry {
            alloc_caller: caller,
            free_caller: 0,
            object_index,
            allocated: true,
            alloc_ts: timestamp,
            free_ts: 0,
        };
        self.count += 1;
        Ok(())
    }

    /// Records a free event.
    pub fn record_free(
        &mut self,
        object_index: usize,
        caller: u64,
        timestamp: u64,
    ) -> Result<bool> {
        for i in 0..self.count {
            if self.entries[i].object_index == object_index {
                if !self.entries[i].allocated {
                    // Double free detected!
                    return Ok(false);
                }
                self.entries[i].free_caller = caller;
                self.entries[i].free_ts = timestamp;
                self.entries[i].allocated = false;
                return Ok(true);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of tracked entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the cache ID.
    pub fn cache_id(&self) -> u64 {
        self.cache_id
    }

    /// Returns the entry at the given index.
    pub fn get(&self, index: usize) -> Option<&FreeTrackEntry> {
        if index < self.count {
            Some(&self.entries[index])
        } else {
            None
        }
    }

    /// Counts currently allocated objects.
    pub fn allocated_count(&self) -> usize {
        self.entries[..self.count]
            .iter()
            .filter(|e| e.allocated)
            .count()
    }
}

// -------------------------------------------------------------------
// SlabBugType
// -------------------------------------------------------------------

/// Category of slab bug detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SlabBugType {
    /// Red-zone corruption detected.
    #[default]
    RedZoneCorruption,
    /// Poison pattern mismatch on free check.
    PoisonMismatch,
    /// Double free detected.
    DoubleFree,
    /// Use-after-free detected (write to freed object).
    UseAfterFree,
    /// Object out-of-bounds access.
    OutOfBounds,
}

// -------------------------------------------------------------------
// SlabDebugReport
// -------------------------------------------------------------------

/// A structured slab bug report.
#[derive(Debug, Clone, Copy, Default)]
pub struct SlabDebugReport {
    /// Type of bug.
    pub bug_type: SlabBugType,
    /// Cache ID where the bug was found.
    pub cache_id: u64,
    /// Object index within the slab.
    pub object_index: usize,
    /// Byte offset of the corruption (if applicable).
    pub offset: usize,
    /// Expected value at the corruption site.
    pub expected: u64,
    /// Actual value found.
    pub actual: u64,
    /// Timestamp of detection.
    pub timestamp: u64,
}

// -------------------------------------------------------------------
// SlabDebugger
// -------------------------------------------------------------------

/// The main slab debugging engine.
///
/// Manages per-cache debug state including red zones, poison patterns,
/// and free tracking.
pub struct SlabDebugger {
    /// Per-cache debug flags.
    cache_flags: [SlabDebugFlags; MAX_TRACKED_CACHES],
    /// Per-cache red zones (head canary per object slot).
    red_zones: [[RedZone; MAX_FREE_TRACK]; MAX_TRACKED_CACHES],
    /// Per-cache free trackers.
    trackers: [FreeTrack; MAX_TRACKED_CACHES],
    /// Bug reports.
    reports: [SlabDebugReport; MAX_BUG_REPORTS],
    /// Number of bug reports.
    report_count: usize,
    /// Number of tracked caches.
    cache_count: usize,
}

impl Default for SlabDebugger {
    fn default() -> Self {
        Self {
            cache_flags: [SlabDebugFlags::empty(); MAX_TRACKED_CACHES],
            red_zones: [[const {
                RedZone {
                    head_canary: 0,
                    tail_canary: 0,
                    object_size: 0,
                }
            }; MAX_FREE_TRACK]; MAX_TRACKED_CACHES],
            trackers: [const {
                FreeTrack {
                    entries: [FreeTrackEntry {
                        alloc_caller: 0,
                        free_caller: 0,
                        object_index: 0,
                        allocated: false,
                        alloc_ts: 0,
                        free_ts: 0,
                    }; MAX_FREE_TRACK],
                    count: 0,
                    cache_id: 0,
                }
            }; MAX_TRACKED_CACHES],
            reports: [SlabDebugReport::default(); MAX_BUG_REPORTS],
            report_count: 0,
            cache_count: 0,
        }
    }
}

impl SlabDebugger {
    /// Creates a new slab debugger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a cache for debugging.
    pub fn register_cache(&mut self, cache_id: u64, flags: SlabDebugFlags) -> Result<usize> {
        if self.cache_count >= MAX_TRACKED_CACHES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.cache_count;
        self.cache_flags[idx] = flags;
        self.trackers[idx] = FreeTrack::new(cache_id);
        self.cache_count += 1;
        Ok(idx)
    }

    /// Performs a red-zone check on the given cache/object.
    pub fn red_zone_check(&mut self, cache_idx: usize, object_idx: usize, timestamp: u64) -> bool {
        if cache_idx >= self.cache_count || object_idx >= MAX_FREE_TRACK {
            return false;
        }
        if !self.cache_flags[cache_idx].contains(SlabDebugFlags::RED_ZONE) {
            return true;
        }
        let rz = &self.red_zones[cache_idx][object_idx];
        if rz.check() {
            return true;
        }
        // Report corruption.
        self.add_report(SlabDebugReport {
            bug_type: SlabBugType::RedZoneCorruption,
            cache_id: self.trackers[cache_idx].cache_id(),
            object_index: object_idx,
            offset: 0,
            expected: RED_ZONE_MAGIC,
            actual: rz.head_canary,
            timestamp,
        });
        false
    }

    /// Performs a poison check on the given data.
    pub fn poison_check(
        &mut self,
        cache_idx: usize,
        object_idx: usize,
        data: &[u8],
        is_free_check: bool,
        timestamp: u64,
    ) -> bool {
        if cache_idx >= self.cache_count {
            return false;
        }
        if !self.cache_flags[cache_idx].contains(SlabDebugFlags::POISON) {
            return true;
        }
        let pattern = if is_free_check {
            PoisonPattern::free_pattern(data.len())
        } else {
            PoisonPattern::alloc_pattern(data.len())
        };
        match pattern.check(data) {
            None => true,
            Some(offset) => {
                self.add_report(SlabDebugReport {
                    bug_type: if is_free_check {
                        SlabBugType::UseAfterFree
                    } else {
                        SlabBugType::PoisonMismatch
                    },
                    cache_id: self.trackers[cache_idx].cache_id(),
                    object_index: object_idx,
                    offset,
                    expected: pattern.pattern as u64,
                    actual: data[offset] as u64,
                    timestamp,
                });
                false
            }
        }
    }

    /// Records an allocation in the tracker.
    pub fn track_alloc(
        &mut self,
        cache_idx: usize,
        object_idx: usize,
        caller: u64,
        object_size: usize,
        timestamp: u64,
    ) -> Result<()> {
        if cache_idx >= self.cache_count {
            return Err(Error::InvalidArgument);
        }
        // Set up red zone.
        if self.cache_flags[cache_idx].contains(SlabDebugFlags::RED_ZONE)
            && object_idx < MAX_FREE_TRACK
        {
            self.red_zones[cache_idx][object_idx] = RedZone::new(object_size);
        }
        // Track caller.
        if self.cache_flags[cache_idx].contains(SlabDebugFlags::STORE_USER) {
            self.trackers[cache_idx].record_alloc(object_idx, caller, timestamp)?;
        }
        Ok(())
    }

    /// Records a free in the tracker.
    pub fn track_free(
        &mut self,
        cache_idx: usize,
        object_idx: usize,
        caller: u64,
        timestamp: u64,
    ) -> Result<bool> {
        if cache_idx >= self.cache_count {
            return Err(Error::InvalidArgument);
        }
        if self.cache_flags[cache_idx].contains(SlabDebugFlags::STORE_USER) {
            let ok = self.trackers[cache_idx].record_free(object_idx, caller, timestamp)?;
            if !ok {
                self.add_report(SlabDebugReport {
                    bug_type: SlabBugType::DoubleFree,
                    cache_id: self.trackers[cache_idx].cache_id(),
                    object_index: object_idx,
                    offset: 0,
                    expected: 0,
                    actual: 0,
                    timestamp,
                });
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Returns the number of bug reports.
    pub fn report_count(&self) -> usize {
        self.report_count
    }

    /// Returns a report by index.
    pub fn get_report(&self, index: usize) -> Option<&SlabDebugReport> {
        if index < self.report_count {
            Some(&self.reports[index])
        } else {
            None
        }
    }

    /// Returns the number of tracked caches.
    pub fn cache_count(&self) -> usize {
        self.cache_count
    }

    /// Adds a bug report.
    fn add_report(&mut self, report: SlabDebugReport) {
        if self.report_count < MAX_BUG_REPORTS {
            self.reports[self.report_count] = report;
            self.report_count += 1;
        }
    }
}
