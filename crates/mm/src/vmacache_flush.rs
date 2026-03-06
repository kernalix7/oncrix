// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! VMA cache flushing operations.
//!
//! The VMA cache (vmacache) is a per-task, small array of recently
//! accessed VMA pointers to speed up `find_vma()`. When the VMA tree
//! changes (munmap, mprotect, mremap), the cache must be invalidated
//! to avoid stale pointers. This module handles cache invalidation
//! strategies: full flush, range flush, and sequence-number based
//! lazy invalidation.
//!
//! # Design
//!
//! ```text
//!  find_vma(mm, addr)
//!     │
//!     ├─ check vmacache[hash(addr)] → cache hit? return VMA
//!     ├─ miss → walk maple tree → update cache
//!     └─ if mm->vmacache_seqnum != task->vmacache_seqnum → flush
//!
//!  munmap(addr, len)
//!     │
//!     └─ mm->vmacache_seqnum++ → all tasks see stale cache
//! ```
//!
//! # Key Types
//!
//! - [`CacheEntry`] — a single cache entry
//! - [`VmaCacheFlush`] — per-task VMA cache with flush support
//! - [`VmaCacheFlushStats`] — cache flush statistics
//!
//! Reference: Linux `mm/vmacache.c`, `include/linux/vmacache.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Number of cache entries per task.
const CACHE_SIZE: usize = 4;

/// Maximum tracked tasks.
const MAX_TASKS: usize = 1024;

// -------------------------------------------------------------------
// CacheEntry
// -------------------------------------------------------------------

/// A single VMA cache entry.
#[derive(Debug, Clone, Copy)]
pub struct CacheEntry {
    /// VMA start address (0 if empty).
    vma_start: u64,
    /// VMA end address.
    vma_end: u64,
    /// VMA flags snapshot.
    vma_flags: u64,
    /// Whether this entry is valid.
    valid: bool,
}

impl CacheEntry {
    /// Create an empty entry.
    pub const fn empty() -> Self {
        Self {
            vma_start: 0,
            vma_end: 0,
            vma_flags: 0,
            valid: false,
        }
    }

    /// Create a populated entry.
    pub const fn new(vma_start: u64, vma_end: u64, vma_flags: u64) -> Self {
        Self {
            vma_start,
            vma_end,
            vma_flags,
            valid: true,
        }
    }

    /// Check whether this entry is valid.
    pub const fn valid(&self) -> bool {
        self.valid
    }

    /// Return the VMA start.
    pub const fn vma_start(&self) -> u64 {
        self.vma_start
    }

    /// Return the VMA end.
    pub const fn vma_end(&self) -> u64 {
        self.vma_end
    }

    /// Return the VMA flags.
    pub const fn vma_flags(&self) -> u64 {
        self.vma_flags
    }

    /// Check whether an address is in this entry.
    pub const fn contains(&self, addr: u64) -> bool {
        self.valid && addr >= self.vma_start && addr < self.vma_end
    }

    /// Invalidate this entry.
    pub fn invalidate(&mut self) {
        self.valid = false;
        self.vma_start = 0;
        self.vma_end = 0;
        self.vma_flags = 0;
    }
}

impl Default for CacheEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// VmaCacheFlushStats
// -------------------------------------------------------------------

/// Cache flush statistics.
#[derive(Debug, Clone, Copy)]
pub struct VmaCacheFlushStats {
    /// Total cache lookups.
    pub lookups: u64,
    /// Cache hits.
    pub hits: u64,
    /// Cache misses.
    pub misses: u64,
    /// Full cache flushes.
    pub full_flushes: u64,
    /// Range flushes.
    pub range_flushes: u64,
    /// Sequence-based invalidations.
    pub seqnum_invalidations: u64,
    /// Cache updates.
    pub updates: u64,
}

impl VmaCacheFlushStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            lookups: 0,
            hits: 0,
            misses: 0,
            full_flushes: 0,
            range_flushes: 0,
            seqnum_invalidations: 0,
            updates: 0,
        }
    }

    /// Hit rate as percent.
    pub const fn hit_rate_pct(&self) -> u64 {
        if self.lookups == 0 {
            return 0;
        }
        self.hits * 100 / self.lookups
    }
}

impl Default for VmaCacheFlushStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// VmaCacheFlush
// -------------------------------------------------------------------

/// Per-task VMA cache with flush support.
pub struct VmaCacheFlush {
    /// Per-task caches: (task_id, seqnum, entries).
    tasks: [(u64, u64, [CacheEntry; CACHE_SIZE]); MAX_TASKS],
    /// Number of registered tasks.
    task_count: usize,
    /// Global sequence number.
    global_seqnum: u64,
    /// Statistics.
    stats: VmaCacheFlushStats,
}

impl VmaCacheFlush {
    /// Create a new cache manager.
    pub const fn new() -> Self {
        Self {
            tasks: [const {
                (
                    0u64,
                    0u64,
                    [CacheEntry {
                        vma_start: 0,
                        vma_end: 0,
                        vma_flags: 0,
                        valid: false,
                    }; CACHE_SIZE],
                )
            }; MAX_TASKS],
            task_count: 0,
            global_seqnum: 1,
            stats: VmaCacheFlushStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &VmaCacheFlushStats {
        &self.stats
    }

    /// Return the global sequence number.
    pub const fn global_seqnum(&self) -> u64 {
        self.global_seqnum
    }

    /// Register a task.
    pub fn register_task(&mut self, task_id: u64) -> Result<()> {
        if self.task_count >= MAX_TASKS {
            return Err(Error::OutOfMemory);
        }
        self.tasks[self.task_count] = (
            task_id,
            self.global_seqnum,
            [CacheEntry::empty(); CACHE_SIZE],
        );
        self.task_count += 1;
        Ok(())
    }

    /// Look up an address in a task's cache.
    pub fn lookup(&mut self, task_id: u64, addr: u64) -> Option<CacheEntry> {
        self.stats.lookups += 1;
        for idx in 0..self.task_count {
            if self.tasks[idx].0 == task_id {
                // Seqnum check.
                if self.tasks[idx].1 != self.global_seqnum {
                    // Cache is stale, flush.
                    self.flush_task(idx);
                    self.tasks[idx].1 = self.global_seqnum;
                    self.stats.seqnum_invalidations += 1;
                    self.stats.misses += 1;
                    return None;
                }
                let slot = (addr as usize >> 12) % CACHE_SIZE;
                let entry = self.tasks[idx].2[slot];
                if entry.contains(addr) {
                    self.stats.hits += 1;
                    return Some(entry);
                }
                self.stats.misses += 1;
                return None;
            }
        }
        self.stats.misses += 1;
        None
    }

    /// Update a task's cache with a VMA.
    pub fn update(
        &mut self,
        task_id: u64,
        addr: u64,
        vma_start: u64,
        vma_end: u64,
        vma_flags: u64,
    ) -> Result<()> {
        for idx in 0..self.task_count {
            if self.tasks[idx].0 == task_id {
                let slot = (addr as usize >> 12) % CACHE_SIZE;
                self.tasks[idx].2[slot] = CacheEntry::new(vma_start, vma_end, vma_flags);
                self.stats.updates += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Bump the global sequence number (invalidates all caches).
    pub fn invalidate_all(&mut self) {
        self.global_seqnum = self.global_seqnum.wrapping_add(1);
        self.stats.full_flushes += 1;
    }

    /// Flush a range from all task caches.
    pub fn flush_range(&mut self, start: u64, end: u64) {
        for tidx in 0..self.task_count {
            for sidx in 0..CACHE_SIZE {
                let entry = &self.tasks[tidx].2[sidx];
                if entry.valid() && entry.vma_start() < end && start < entry.vma_end() {
                    self.tasks[tidx].2[sidx].invalidate();
                }
            }
        }
        self.stats.range_flushes += 1;
    }

    /// Flush a single task's cache.
    fn flush_task(&mut self, task_idx: usize) {
        for sidx in 0..CACHE_SIZE {
            self.tasks[task_idx].2[sidx].invalidate();
        }
    }

    /// Return the task count.
    pub const fn task_count(&self) -> usize {
        self.task_count
    }
}

impl Default for VmaCacheFlush {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the cache size per task.
pub const fn cache_size() -> usize {
    CACHE_SIZE
}

/// Return the maximum tasks.
pub const fn max_tasks() -> usize {
    MAX_TASKS
}
