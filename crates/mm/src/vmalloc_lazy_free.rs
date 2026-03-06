// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Lazy vmalloc freeing.
//!
//! Defers `vfree` operations to an RCU-like callback mechanism,
//! batching TLB flushes across multiple `vunmap` operations for
//! efficiency. Freed vmalloc areas are placed on per-CPU deferred
//! queues and purged in batches when a threshold is reached.
//!
//! # Architecture
//!
//! - [`DeferredVfreeEntry`] — a single deferred free request
//! - [`DeferredQueue`] — per-CPU queue of pending vfree requests
//! - [`LazyPurgeList`] — global list of areas awaiting TLB flush
//! - [`VmallocLazyFreeManager`] — coordinates deferred free,
//!   threshold-based flush, and purge
//!
//! ## Lifecycle
//!
//! 1. `vfree` is called — entry goes to per-CPU deferred queue
//! 2. When queue depth exceeds threshold, a batch flush is
//!    triggered
//! 3. Batch flush moves entries to the purge list, issues a
//!    single global TLB flush
//! 4. Purge list entries are recycled (backing pages freed)
//!
//! Reference: Linux `mm/vmalloc.c` (`vfree_deferred`).

use oncrix_lib::{Error, Result};

// -- Constants

/// Maximum number of per-CPU deferred queues.
const MAX_CPUS: usize = 16;

/// Maximum entries per deferred queue.
const MAX_DEFERRED_PER_CPU: usize = 64;

/// Maximum entries on the global purge list.
const MAX_PURGE_ENTRIES: usize = 256;

/// Default threshold: flush when queue reaches this depth.
const DEFAULT_FLUSH_THRESHOLD: usize = 32;

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

// -- DeferredVfreeEntry

/// A single deferred vfree request.
#[derive(Debug, Clone, Copy)]
pub struct DeferredVfreeEntry {
    /// Virtual base address of the vmalloc area.
    pub base: u64,
    /// Size in bytes of the area (including guard).
    pub size: u64,
    /// Number of backing pages.
    pub nr_pages: u32,
    /// Unique vmalloc area ID.
    pub area_id: u32,
    /// CPU that queued this entry.
    pub cpu_id: u8,
    /// Whether this entry is occupied.
    pub active: bool,
}

impl DeferredVfreeEntry {
    const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            nr_pages: 0,
            area_id: 0,
            cpu_id: 0,
            active: false,
        }
    }
}

impl Default for DeferredVfreeEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// -- DeferredQueue

/// Per-CPU queue of pending vfree requests.
#[derive(Debug, Clone, Copy)]
pub struct DeferredQueue {
    /// Entries in this queue.
    pub entries: [DeferredVfreeEntry; MAX_DEFERRED_PER_CPU],
    /// Number of active entries.
    pub count: usize,
    /// CPU identifier for this queue.
    pub cpu_id: u8,
    /// Whether this queue is active (CPU is online).
    pub active: bool,
}

impl DeferredQueue {
    const fn empty() -> Self {
        Self {
            entries: [const { DeferredVfreeEntry::empty() }; MAX_DEFERRED_PER_CPU],
            count: 0,
            cpu_id: 0,
            active: false,
        }
    }

    /// Enqueue a deferred vfree entry.
    fn enqueue(&mut self, entry: DeferredVfreeEntry) -> Result<()> {
        if self.count >= MAX_DEFERRED_PER_CPU {
            return Err(Error::OutOfMemory);
        }
        let idx = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;
        self.entries[idx] = entry;
        self.entries[idx].active = true;
        self.count += 1;
        Ok(())
    }

    /// Drain all entries, returning the count drained.
    fn drain(&mut self) -> usize {
        let drained = self.count;
        for e in &mut self.entries {
            e.active = false;
        }
        self.count = 0;
        drained
    }
}

impl Default for DeferredQueue {
    fn default() -> Self {
        Self::empty()
    }
}

// -- PurgeEntry

/// An entry on the global purge list awaiting final reclamation.
#[derive(Debug, Clone, Copy)]
pub struct PurgeEntry {
    /// Virtual base address.
    pub base: u64,
    /// Size in bytes.
    pub size: u64,
    /// Number of pages to free.
    pub nr_pages: u32,
    /// Whether this entry is occupied.
    pub active: bool,
}

impl PurgeEntry {
    const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            nr_pages: 0,
            active: false,
        }
    }
}

impl Default for PurgeEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// -- VmallocLazyFreeStats

/// Statistics for the lazy vmalloc free subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct VmallocLazyFreeStats {
    /// Total vfree_deferred calls.
    pub deferred_calls: u64,
    /// Total batch flush triggers.
    pub batch_flushes: u64,
    /// Total TLB flushes performed.
    pub tlb_flushes: u64,
    /// Total entries purged.
    pub entries_purged: u64,
    /// Total pages freed.
    pub pages_freed: u64,
    /// Total threshold-triggered flushes.
    pub threshold_triggers: u64,
}

// -- VmallocLazyFreeManager

/// Manages lazy vmalloc freeing with per-CPU deferred queues
/// and threshold-based batch TLB flushing.
pub struct VmallocLazyFreeManager {
    /// Per-CPU deferred queues.
    queues: [DeferredQueue; MAX_CPUS],
    /// Number of online CPUs.
    online_cpus: usize,
    /// Global purge list.
    purge_list: [PurgeEntry; MAX_PURGE_ENTRIES],
    /// Number of active purge entries.
    purge_count: usize,
    /// Flush threshold (entries per queue).
    flush_threshold: usize,
    /// Statistics.
    stats: VmallocLazyFreeStats,
}

impl VmallocLazyFreeManager {
    /// Create a new manager with the given number of CPUs.
    pub fn new(online_cpus: usize) -> Self {
        let cpu_count = if online_cpus > MAX_CPUS {
            MAX_CPUS
        } else if online_cpus == 0 {
            1
        } else {
            online_cpus
        };
        let mut mgr = Self {
            queues: [const { DeferredQueue::empty() }; MAX_CPUS],
            online_cpus: cpu_count,
            purge_list: [const { PurgeEntry::empty() }; MAX_PURGE_ENTRIES],
            purge_count: 0,
            flush_threshold: DEFAULT_FLUSH_THRESHOLD,
            stats: VmallocLazyFreeStats {
                deferred_calls: 0,
                batch_flushes: 0,
                tlb_flushes: 0,
                entries_purged: 0,
                pages_freed: 0,
                threshold_triggers: 0,
            },
        };
        for i in 0..cpu_count {
            mgr.queues[i].cpu_id = i as u8;
            mgr.queues[i].active = true;
        }
        mgr
    }

    /// Defer a vfree to the specified CPU's queue.
    ///
    /// If the queue exceeds the flush threshold, a batch flush
    /// is triggered automatically.
    pub fn vfree_deferred(
        &mut self,
        cpu: usize,
        base: u64,
        size: u64,
        nr_pages: u32,
        area_id: u32,
    ) -> Result<()> {
        if cpu >= self.online_cpus {
            return Err(Error::InvalidArgument);
        }
        self.stats.deferred_calls += 1;
        let entry = DeferredVfreeEntry {
            base,
            size,
            nr_pages,
            area_id,
            cpu_id: cpu as u8,
            active: true,
        };
        self.queues[cpu].enqueue(entry)?;
        // Check threshold.
        if self.queues[cpu].count >= self.flush_threshold {
            self.stats.threshold_triggers += 1;
            self.flush_queue(cpu)?;
        }
        Ok(())
    }

    /// Flush a specific CPU's deferred queue to the purge list.
    pub fn flush_queue(&mut self, cpu: usize) -> Result<()> {
        if cpu >= self.online_cpus {
            return Err(Error::InvalidArgument);
        }
        self.stats.batch_flushes += 1;
        // Move entries to purge list.
        for e in &self.queues[cpu].entries {
            if !e.active {
                continue;
            }
            let purge_idx = self.purge_list.iter().position(|p| !p.active);
            if let Some(pi) = purge_idx {
                self.purge_list[pi] = PurgeEntry {
                    base: e.base,
                    size: e.size,
                    nr_pages: e.nr_pages,
                    active: true,
                };
                self.purge_count += 1;
            }
        }
        self.queues[cpu].drain();
        // Issue a single TLB flush for the batch.
        self.stats.tlb_flushes += 1;
        Ok(())
    }

    /// Flush all CPU queues.
    pub fn flush_all(&mut self) -> Result<()> {
        for cpu in 0..self.online_cpus {
            if self.queues[cpu].count > 0 {
                self.flush_queue(cpu)?;
            }
        }
        Ok(())
    }

    /// Purge all entries on the purge list, freeing backing
    /// pages. Returns the number of pages freed.
    pub fn purge(&mut self) -> u64 {
        let mut freed = 0u64;
        for pe in &mut self.purge_list {
            if !pe.active {
                continue;
            }
            freed += pe.nr_pages as u64;
            pe.active = false;
            self.stats.entries_purged += 1;
        }
        self.purge_count = 0;
        self.stats.pages_freed += freed;
        freed
    }

    /// Set the flush threshold.
    pub fn set_threshold(&mut self, threshold: usize) -> Result<()> {
        if threshold == 0 || threshold > MAX_DEFERRED_PER_CPU {
            return Err(Error::InvalidArgument);
        }
        self.flush_threshold = threshold;
        Ok(())
    }

    /// Return the total bytes awaiting purge.
    pub fn pending_bytes(&self) -> u64 {
        let mut total = 0u64;
        for pe in &self.purge_list {
            if pe.active {
                total += pe.nr_pages as u64 * PAGE_SIZE;
            }
        }
        total
    }

    /// Number of entries in a CPU's deferred queue.
    pub fn queue_depth(&self, cpu: usize) -> usize {
        if cpu >= MAX_CPUS {
            return 0;
        }
        self.queues[cpu].count
    }

    /// Number of entries on the purge list.
    pub fn purge_count(&self) -> usize {
        self.purge_count
    }

    /// Return statistics.
    pub fn stats(&self) -> &VmallocLazyFreeStats {
        &self.stats
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.stats = VmallocLazyFreeStats::default();
    }
}

impl Default for VmallocLazyFreeManager {
    fn default() -> Self {
        Self::new(4)
    }
}
