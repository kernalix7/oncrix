// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Slab cache reclaim and shrink operations.
//!
//! When memory pressure rises, the kernel needs to reclaim memory from
//! slab caches. This module implements the shrinker framework: each slab
//! cache registers a shrinker that reports how many objects can be freed
//! and performs the actual freeing when asked.
//!
//! # Design
//!
//! ```text
//!  Memory pressure
//!       │
//!       ▼
//!  SlabShrinkerRegistry::shrink_all(nr_to_scan)
//!       │
//!       ├─ for each shrinker:
//!       │     ├─ count_objects() → freeable count
//!       │     └─ scan_objects(nr) → freed count
//!       │
//!       └─ return total freed
//! ```
//!
//! # Key Types
//!
//! - [`SlabShrinker`] — a single slab cache shrinker
//! - [`SlabShrinkerRegistry`] — global registry of shrinkers
//! - [`ShrinkResult`] — outcome of a shrink pass
//!
//! Reference: Linux `mm/shrinker.c`, `include/linux/shrinker.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum registered shrinkers.
const MAX_SHRINKERS: usize = 128;

/// Default scan batch size.
const DEFAULT_SCAN_BATCH: u64 = 128;

/// Minimum objects a cache should keep (safety floor).
const MIN_OBJECTS_KEEP: u64 = 16;

// -------------------------------------------------------------------
// SlabShrinker
// -------------------------------------------------------------------

/// Priority for shrinking (lower = shrink first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ShrinkPriority {
    /// Low priority — shrink last.
    Low = 0,
    /// Normal priority.
    Normal = 1,
    /// High priority — shrink first.
    High = 2,
}

impl Default for ShrinkPriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// A slab cache shrinker descriptor.
#[derive(Debug, Clone, Copy)]
pub struct SlabShrinker {
    /// Shrinker identifier.
    shrinker_id: u32,
    /// Name (index into a name table, simplified).
    name_id: u32,
    /// Total objects in the cache.
    total_objects: u64,
    /// Objects currently in use (pinned).
    active_objects: u64,
    /// Minimum objects to retain.
    min_objects: u64,
    /// Priority.
    priority: ShrinkPriority,
    /// Whether this shrinker is active.
    active: bool,
    /// Total objects freed by this shrinker.
    lifetime_freed: u64,
}

impl SlabShrinker {
    /// Create a new shrinker.
    pub const fn new(shrinker_id: u32, total_objects: u64, active_objects: u64) -> Self {
        Self {
            shrinker_id,
            name_id: 0,
            total_objects,
            active_objects,
            min_objects: MIN_OBJECTS_KEEP,
            priority: ShrinkPriority::Normal,
            active: true,
            lifetime_freed: 0,
        }
    }

    /// Return the shrinker ID.
    pub const fn shrinker_id(&self) -> u32 {
        self.shrinker_id
    }

    /// Return total objects.
    pub const fn total_objects(&self) -> u64 {
        self.total_objects
    }

    /// Return active (pinned) objects.
    pub const fn active_objects(&self) -> u64 {
        self.active_objects
    }

    /// Return the number of freeable objects.
    pub fn freeable_count(&self) -> u64 {
        if !self.active {
            return 0;
        }
        let floor = self.active_objects.max(self.min_objects);
        self.total_objects.saturating_sub(floor)
    }

    /// Scan and free up to `nr_to_scan` objects.
    pub fn scan_objects(&mut self, nr_to_scan: u64) -> u64 {
        if !self.active {
            return 0;
        }
        let freeable = self.freeable_count();
        let to_free = nr_to_scan.min(freeable);
        self.total_objects -= to_free;
        self.lifetime_freed += to_free;
        to_free
    }

    /// Update the object counts (e.g., after allocation/free).
    pub fn update_counts(&mut self, total: u64, active: u64) {
        self.total_objects = total;
        self.active_objects = active;
    }

    /// Set the priority.
    pub fn set_priority(&mut self, priority: ShrinkPriority) {
        self.priority = priority;
    }

    /// Return the priority.
    pub const fn priority(&self) -> ShrinkPriority {
        self.priority
    }

    /// Deactivate this shrinker.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Return lifetime freed count.
    pub const fn lifetime_freed(&self) -> u64 {
        self.lifetime_freed
    }
}

impl Default for SlabShrinker {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

// -------------------------------------------------------------------
// ShrinkResult
// -------------------------------------------------------------------

/// Outcome of a shrink pass.
#[derive(Debug, Clone, Copy)]
pub struct ShrinkResult {
    /// Total objects freed.
    pub freed: u64,
    /// Number of shrinkers scanned.
    pub shrinkers_scanned: usize,
    /// Number of shrinkers that contributed.
    pub shrinkers_contributed: usize,
}

impl ShrinkResult {
    /// Create a new result.
    pub const fn new(freed: u64, scanned: usize, contributed: usize) -> Self {
        Self {
            freed,
            shrinkers_scanned: scanned,
            shrinkers_contributed: contributed,
        }
    }
}

// -------------------------------------------------------------------
// SlabShrinkerRegistry
// -------------------------------------------------------------------

/// Global registry of slab shrinkers.
pub struct SlabShrinkerRegistry {
    /// Registered shrinkers.
    shrinkers: [SlabShrinker; MAX_SHRINKERS],
    /// Number of registered shrinkers.
    count: usize,
    /// Total objects freed across all passes.
    total_freed: u64,
}

impl SlabShrinkerRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            shrinkers: [const { SlabShrinker::new(0, 0, 0) }; MAX_SHRINKERS],
            count: 0,
            total_freed: 0,
        }
    }

    /// Register a shrinker.
    pub fn register(&mut self, shrinker: SlabShrinker) -> Result<()> {
        if self.count >= MAX_SHRINKERS {
            return Err(Error::OutOfMemory);
        }
        self.shrinkers[self.count] = shrinker;
        self.count += 1;
        Ok(())
    }

    /// Unregister a shrinker by ID.
    pub fn unregister(&mut self, shrinker_id: u32) -> Result<()> {
        for idx in 0..self.count {
            if self.shrinkers[idx].shrinker_id() == shrinker_id {
                self.shrinkers[idx].deactivate();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Return the number of registered shrinkers.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Count total freeable objects across all shrinkers.
    pub fn count_freeable(&self) -> u64 {
        let mut total = 0u64;
        for idx in 0..self.count {
            total += self.shrinkers[idx].freeable_count();
        }
        total
    }

    /// Run a shrink pass, scanning up to `nr_to_scan` objects per shrinker.
    pub fn shrink_all(&mut self, nr_to_scan: u64) -> ShrinkResult {
        let scan = if nr_to_scan == 0 {
            DEFAULT_SCAN_BATCH
        } else {
            nr_to_scan
        };

        let mut total_freed = 0u64;
        let mut scanned = 0usize;
        let mut contributed = 0usize;

        for idx in 0..self.count {
            let freed = self.shrinkers[idx].scan_objects(scan);
            scanned += 1;
            if freed > 0 {
                total_freed += freed;
                contributed += 1;
            }
        }

        self.total_freed += total_freed;
        ShrinkResult::new(total_freed, scanned, contributed)
    }

    /// Return total lifetime freed objects.
    pub const fn total_freed(&self) -> u64 {
        self.total_freed
    }
}

impl Default for SlabShrinkerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Create and register a shrinker for a slab cache.
pub fn register_slab_shrinker(
    registry: &mut SlabShrinkerRegistry,
    shrinker_id: u32,
    total_objects: u64,
    active_objects: u64,
) -> Result<()> {
    let shrinker = SlabShrinker::new(shrinker_id, total_objects, active_objects);
    registry.register(shrinker)
}

/// Perform an emergency shrink across all caches.
pub fn emergency_shrink(registry: &mut SlabShrinkerRegistry) -> u64 {
    let freeable = registry.count_freeable();
    let result = registry.shrink_all(freeable);
    result.freed
}

/// Return a summary of shrinker state.
pub fn shrinker_summary(registry: &SlabShrinkerRegistry) -> &'static str {
    let freeable = registry.count_freeable();
    if freeable == 0 {
        "slab shrinkers: nothing freeable"
    } else if freeable > 10000 {
        "slab shrinkers: significant reclaimable objects"
    } else {
        "slab shrinkers: some reclaimable objects"
    }
}
