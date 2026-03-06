// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! vmalloc fallback allocator.
//!
//! When the primary vmalloc allocator cannot satisfy a request (e.g.,
//! due to virtual address space fragmentation or temporary exhaustion),
//! this fallback module provides alternative strategies: emergency
//! reserve pools, compaction-assisted retry, and degraded-mode
//! allocation from a pre-reserved region.
//!
//! # Design
//!
//! ```text
//!  vmalloc(size) → primary fails
//!       │
//!       ▼
//!  ┌──────────────────────────┐
//!  │  VmallocFallback          │
//!  │  1. try emergency pool   │
//!  │  2. compact VA space     │
//!  │  3. try degraded alloc   │
//!  │  4. fail with ENOMEM     │
//!  └──────────────────────────┘
//! ```
//!
//! # Key Types
//!
//! - [`FallbackStrategy`] — which fallback to attempt
//! - [`EmergencyPool`] — pre-reserved emergency allocations
//! - [`VmallocFallback`] — the fallback allocator
//! - [`FallbackStats`] — fallback usage statistics
//!
//! Reference: Linux `mm/vmalloc.c` (fallback paths).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size.
const PAGE_SIZE: usize = 4096;

/// Maximum emergency pool entries.
const MAX_EMERGENCY_ENTRIES: usize = 64;

/// Maximum size of an emergency allocation (256 KiB).
const MAX_EMERGENCY_SIZE: usize = 256 * 1024;

/// Emergency pool total capacity (1 MiB).
const EMERGENCY_POOL_SIZE: usize = 1024 * 1024;

// -------------------------------------------------------------------
// FallbackStrategy
// -------------------------------------------------------------------

/// Which fallback strategy was used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackStrategy {
    /// Used the emergency pool.
    EmergencyPool,
    /// Compacted the VA space and retried.
    Compaction,
    /// Used the degraded region.
    DegradedAlloc,
    /// All strategies failed.
    Failed,
}

impl Default for FallbackStrategy {
    fn default() -> Self {
        Self::Failed
    }
}

// -------------------------------------------------------------------
// EmergencyEntry
// -------------------------------------------------------------------

/// An entry in the emergency pool.
#[derive(Debug, Clone, Copy)]
struct EmergencyEntry {
    /// Virtual address of the reserved region.
    vaddr: u64,
    /// Size in bytes.
    size: usize,
    /// Whether this entry is allocated (in-use).
    allocated: bool,
    /// Whether this slot has a reservation.
    reserved: bool,
}

impl EmergencyEntry {
    const fn new() -> Self {
        Self {
            vaddr: 0,
            size: 0,
            allocated: false,
            reserved: false,
        }
    }
}

// -------------------------------------------------------------------
// EmergencyPool
// -------------------------------------------------------------------

/// Pre-reserved pool for emergency vmalloc allocations.
pub struct EmergencyPool {
    /// Pool entries.
    entries: [EmergencyEntry; MAX_EMERGENCY_ENTRIES],
    /// Number of reserved entries.
    reserved: usize,
    /// Number of allocated entries.
    allocated: usize,
    /// Total reserved bytes.
    total_bytes: usize,
}

impl EmergencyPool {
    /// Creates an empty emergency pool.
    pub const fn new() -> Self {
        Self {
            entries: [const { EmergencyEntry::new() }; MAX_EMERGENCY_ENTRIES],
            reserved: 0,
            allocated: 0,
            total_bytes: 0,
        }
    }

    /// Returns the number of available (reserved but not allocated) entries.
    pub const fn available(&self) -> usize {
        self.reserved - self.allocated
    }

    /// Returns total reserved bytes.
    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Reserves an entry in the pool.
    pub fn reserve(&mut self, vaddr: u64, size: usize) -> Result<()> {
        if size > MAX_EMERGENCY_SIZE {
            return Err(Error::InvalidArgument);
        }
        if self.total_bytes + size > EMERGENCY_POOL_SIZE {
            return Err(Error::OutOfMemory);
        }
        for i in 0..MAX_EMERGENCY_ENTRIES {
            if !self.entries[i].reserved {
                self.entries[i] = EmergencyEntry {
                    vaddr,
                    size,
                    allocated: false,
                    reserved: true,
                };
                self.reserved += 1;
                self.total_bytes += size;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Allocates from the pool for the given size.
    pub fn alloc(&mut self, size: usize) -> Result<u64> {
        for i in 0..MAX_EMERGENCY_ENTRIES {
            if self.entries[i].reserved
                && !self.entries[i].allocated
                && self.entries[i].size >= size
            {
                self.entries[i].allocated = true;
                self.allocated += 1;
                return Ok(self.entries[i].vaddr);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Frees an allocation back to the pool.
    pub fn free(&mut self, vaddr: u64) -> Result<()> {
        for i in 0..MAX_EMERGENCY_ENTRIES {
            if self.entries[i].reserved
                && self.entries[i].allocated
                && self.entries[i].vaddr == vaddr
            {
                self.entries[i].allocated = false;
                self.allocated -= 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }
}

impl Default for EmergencyPool {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// FallbackStats
// -------------------------------------------------------------------

/// Fallback allocator usage statistics.
#[derive(Debug, Clone, Copy)]
pub struct FallbackStats {
    /// Total fallback attempts.
    pub attempts: u64,
    /// Successful emergency pool allocations.
    pub emergency_hits: u64,
    /// Successful compaction retries.
    pub compaction_hits: u64,
    /// Successful degraded allocations.
    pub degraded_hits: u64,
    /// Total failures (all strategies exhausted).
    pub failures: u64,
}

impl FallbackStats {
    /// Creates empty stats.
    pub const fn new() -> Self {
        Self {
            attempts: 0,
            emergency_hits: 0,
            compaction_hits: 0,
            degraded_hits: 0,
            failures: 0,
        }
    }

    /// Returns the fallback success rate (0..100).
    pub const fn success_rate(&self) -> u64 {
        if self.attempts == 0 {
            return 100;
        }
        (self.attempts - self.failures) * 100 / self.attempts
    }
}

impl Default for FallbackStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// VmallocFallback
// -------------------------------------------------------------------

/// Fallback allocator for vmalloc failures.
pub struct VmallocFallback {
    /// Emergency pool.
    pool: EmergencyPool,
    /// Statistics.
    stats: FallbackStats,
    /// Whether compaction is enabled.
    compaction_enabled: bool,
    /// Whether degraded mode is enabled.
    degraded_enabled: bool,
    /// Degraded region base address.
    degraded_base: u64,
    /// Degraded region current offset.
    degraded_offset: usize,
    /// Degraded region total size.
    degraded_size: usize,
}

impl VmallocFallback {
    /// Creates a new fallback allocator.
    pub const fn new() -> Self {
        Self {
            pool: EmergencyPool::new(),
            stats: FallbackStats::new(),
            compaction_enabled: true,
            degraded_enabled: false,
            degraded_base: 0,
            degraded_offset: 0,
            degraded_size: 0,
        }
    }

    /// Returns the statistics.
    pub const fn stats(&self) -> &FallbackStats {
        &self.stats
    }

    /// Returns the emergency pool.
    pub const fn emergency_pool(&self) -> &EmergencyPool {
        &self.pool
    }

    /// Configures the degraded allocation region.
    pub fn set_degraded_region(&mut self, base: u64, size: usize) {
        self.degraded_base = base;
        self.degraded_size = size;
        self.degraded_offset = 0;
        self.degraded_enabled = true;
    }

    /// Adds a reservation to the emergency pool.
    pub fn add_emergency_reserve(&mut self, vaddr: u64, size: usize) -> Result<()> {
        self.pool.reserve(vaddr, size)
    }

    /// Attempts a fallback allocation.
    ///
    /// Tries strategies in order: emergency pool → compaction → degraded.
    pub fn alloc(&mut self, size: usize) -> Result<(u64, FallbackStrategy)> {
        self.stats.attempts = self.stats.attempts.saturating_add(1);
        let aligned_size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        // Strategy 1: emergency pool.
        if let Ok(vaddr) = self.pool.alloc(aligned_size) {
            self.stats.emergency_hits = self.stats.emergency_hits.saturating_add(1);
            return Ok((vaddr, FallbackStrategy::EmergencyPool));
        }

        // Strategy 2: compaction (simulated).
        if self.compaction_enabled {
            // In a real system this would trigger VA space compaction
            // and retry the primary allocator. Simulate failure.
        }

        // Strategy 3: degraded allocation.
        if self.degraded_enabled && self.degraded_offset + aligned_size <= self.degraded_size {
            let vaddr = self.degraded_base + self.degraded_offset as u64;
            self.degraded_offset += aligned_size;
            self.stats.degraded_hits = self.stats.degraded_hits.saturating_add(1);
            return Ok((vaddr, FallbackStrategy::DegradedAlloc));
        }

        self.stats.failures = self.stats.failures.saturating_add(1);
        Err(Error::OutOfMemory)
    }

    /// Frees a fallback allocation.
    pub fn free(&mut self, vaddr: u64) -> Result<()> {
        // Try emergency pool first.
        if self.pool.free(vaddr).is_ok() {
            return Ok(());
        }
        // Degraded allocations are bump-allocated; no individual free.
        Ok(())
    }
}

impl Default for VmallocFallback {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Creates a new vmalloc fallback allocator.
pub fn create_fallback() -> VmallocFallback {
    VmallocFallback::new()
}

/// Attempts a fallback allocation, returning the address and strategy used.
pub fn fallback_alloc(fb: &mut VmallocFallback, size: usize) -> Result<(u64, FallbackStrategy)> {
    fb.alloc(size)
}

/// Returns the fallback success rate (0..100).
pub fn fallback_success_rate(fb: &VmallocFallback) -> u64 {
    fb.stats().success_rate()
}
