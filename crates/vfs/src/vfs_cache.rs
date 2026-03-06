// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VFS unified cache — coordinates inode cache, dentry cache, and page cache
//! reclaim under memory pressure.
//!
//! Provides the `VfsCache` controller which tracks all caches registered by
//! mounted filesystems and drives LRU-based shrinking when memory is low.

use oncrix_lib::{Error, Result};

/// Maximum number of registered cache shrinkers.
pub const MAX_SHRINKERS: usize = 32;

/// Cache category for statistics and priority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheKind {
    /// Inode cache (icache).
    Inode,
    /// Dentry cache (dcache).
    Dentry,
    /// Page cache.
    Page,
    /// Filesystem-specific internal cache.
    FsPrivate,
}

/// A registered cache shrinker entry.
#[derive(Clone, Copy)]
pub struct ShrinkerEntry {
    /// Human-readable name for diagnostics.
    pub name: &'static str,
    /// Cache category.
    pub kind: CacheKind,
    /// Current number of objects in this cache.
    pub current_objects: u64,
    /// Maximum target objects (0 = unlimited).
    pub max_objects: u64,
    /// Priority: higher value = shrunk first under pressure.
    pub priority: u8,
    /// Unique shrinker identifier.
    pub id: u32,
}

impl ShrinkerEntry {
    /// Create a new shrinker entry.
    pub const fn new(
        name: &'static str,
        kind: CacheKind,
        max_objects: u64,
        priority: u8,
        id: u32,
    ) -> Self {
        Self {
            name,
            kind,
            current_objects: 0,
            max_objects,
            priority,
            id,
        }
    }

    /// Return how many objects exceed the configured maximum.
    pub fn excess(&self) -> u64 {
        if self.max_objects == 0 || self.current_objects <= self.max_objects {
            0
        } else {
            self.current_objects - self.max_objects
        }
    }
}

/// Aggregate VFS cache statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct VfsCacheStats {
    /// Total registered shrinkers.
    pub shrinker_count: u32,
    /// Total objects across all caches.
    pub total_objects: u64,
    /// Total objects freed in last shrink pass.
    pub last_freed: u64,
    /// Number of shrink passes performed.
    pub shrink_passes: u64,
    /// Number of times pressure was applied.
    pub pressure_events: u64,
}

/// The VFS unified cache controller.
pub struct VfsCache {
    shrinkers: [Option<ShrinkerEntry>; MAX_SHRINKERS],
    count: usize,
    next_id: u32,
    pub stats: VfsCacheStats,
}

impl VfsCache {
    /// Create an empty VFS cache controller.
    pub const fn new() -> Self {
        Self {
            shrinkers: [const { None }; MAX_SHRINKERS],
            count: 0,
            next_id: 1,
            stats: VfsCacheStats {
                shrinker_count: 0,
                total_objects: 0,
                last_freed: 0,
                shrink_passes: 0,
                pressure_events: 0,
            },
        }
    }

    /// Register a new cache shrinker.
    ///
    /// Returns the assigned shrinker ID.
    pub fn register_shrinker(
        &mut self,
        name: &'static str,
        kind: CacheKind,
        max_objects: u64,
        priority: u8,
    ) -> Result<u32> {
        if self.count >= MAX_SHRINKERS {
            return Err(Error::OutOfMemory);
        }
        let id = self.next_id;
        self.next_id += 1;
        let entry = ShrinkerEntry::new(name, kind, max_objects, priority, id);
        for slot in self.shrinkers.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                self.count += 1;
                self.stats.shrinker_count += 1;
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister a shrinker by ID.
    pub fn unregister_shrinker(&mut self, id: u32) -> Result<()> {
        for slot in self.shrinkers.iter_mut() {
            if let Some(e) = slot {
                if e.id == id {
                    *slot = None;
                    self.count -= 1;
                    self.stats.shrinker_count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Update the object count for a shrinker.
    pub fn update_count(&mut self, id: u32, current: u64) -> Result<()> {
        for slot in self.shrinkers.iter_mut() {
            if let Some(e) = slot {
                if e.id == id {
                    e.current_objects = current;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Drive a shrink pass: call `shrink_fn` for each shrinker with excess
    /// objects, in descending priority order.
    ///
    /// `shrink_fn(shrinker_id, target_to_free) -> objects_freed`
    pub fn shrink<F>(&mut self, target: u64, mut shrink_fn: F) -> u64
    where
        F: FnMut(u32, u64) -> u64,
    {
        self.stats.shrink_passes += 1;
        let mut freed = 0u64;
        let mut remaining = target;

        // Simple priority-order pass (selection sort on priority).
        let mut visited = [false; MAX_SHRINKERS];
        while remaining > 0 {
            // Find highest-priority unvisited shrinker with excess.
            let mut best_idx: Option<usize> = None;
            let mut best_pri = 0u8;
            for (i, slot) in self.shrinkers.iter().enumerate() {
                if visited[i] {
                    continue;
                }
                if let Some(e) = slot {
                    if e.excess() > 0 && e.priority >= best_pri {
                        best_pri = e.priority;
                        best_idx = Some(i);
                    }
                }
            }
            let idx = match best_idx {
                None => break,
                Some(i) => i,
            };
            visited[idx] = true;

            let entry = match &self.shrinkers[idx] {
                Some(e) => *e,
                None => continue,
            };

            let to_free = remaining.min(entry.excess());
            let f = shrink_fn(entry.id, to_free);
            freed += f;
            remaining = remaining.saturating_sub(f);

            // Update the object count.
            if let Some(e) = &mut self.shrinkers[idx] {
                e.current_objects = e.current_objects.saturating_sub(f);
            }
        }

        self.stats.last_freed = freed;
        self.stats.total_objects = self.compute_total();
        freed
    }

    /// Signal memory pressure — triggers an emergency shrink pass.
    pub fn memory_pressure<F>(&mut self, shrink_fn: F) -> u64
    where
        F: FnMut(u32, u64) -> u64,
    {
        self.stats.pressure_events += 1;
        let total = self.compute_total();
        // Try to free at least 25% of total cached objects.
        let target = total / 4;
        self.shrink(target, shrink_fn)
    }

    fn compute_total(&self) -> u64 {
        self.shrinkers
            .iter()
            .filter_map(|s| s.as_ref())
            .map(|e| e.current_objects)
            .sum()
    }

    /// Return a snapshot of a shrinker by ID.
    pub fn get_shrinker(&self, id: u32) -> Option<ShrinkerEntry> {
        for slot in &self.shrinkers {
            if let Some(e) = slot {
                if e.id == id {
                    return Some(*e);
                }
            }
        }
        None
    }

    /// Return the total object count across all caches.
    pub fn total_objects(&self) -> u64 {
        self.compute_total()
    }

    /// Return number of registered shrinkers.
    pub fn shrinker_count(&self) -> usize {
        self.count
    }
}

impl Default for VfsCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Determine whether the VFS cache is under pressure.
///
/// Returns `true` if any registered shrinker exceeds its maximum by more
/// than `threshold_pct` percent.
pub fn is_under_pressure(cache: &VfsCache, threshold_pct: u64) -> bool {
    for slot in &cache.shrinkers {
        if let Some(e) = slot {
            if e.max_objects > 0 {
                let usage_pct = e.current_objects.saturating_mul(100) / e.max_objects;
                if usage_pct > threshold_pct {
                    return true;
                }
            }
        }
    }
    false
}
