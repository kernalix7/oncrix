// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Slab allocator free-path (kfree) implementation.
//!
//! Handles the kfree path for slab-allocated objects, including
//! size-class lookup, per-CPU free-list return, and deferred free
//! via RCU. Supports both regular kfree and kfree_rcu for objects
//! that need grace-period protection.
//!
//! - [`FreeMode`] — free operation mode
//! - [`FreeEntry`] — a pending free entry
//! - [`DeferredFreeList`] — RCU deferred free list
//! - [`KfreeStats`] — free-path statistics
//! - [`SlabKfree`] — the kfree engine
//!
//! Reference: Linux `mm/slub.c` (kfree, kfree_rcu paths).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum pending deferred frees.
const MAX_DEFERRED: usize = 256;

/// Maximum tracked size classes.
const MAX_SIZE_CLASSES: usize = 32;

/// Maximum free operations per batch.
const MAX_BATCH: usize = 64;

// -------------------------------------------------------------------
// FreeMode
// -------------------------------------------------------------------

/// Free operation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FreeMode {
    /// Immediate free.
    #[default]
    Immediate,
    /// Deferred free (RCU).
    DeferredRcu,
    /// Bulk free.
    Bulk,
}

// -------------------------------------------------------------------
// FreeEntry
// -------------------------------------------------------------------

/// A pending free entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct FreeEntry {
    /// Object address (simulated).
    pub addr: u64,
    /// Size class index.
    pub class_idx: usize,
    /// Free mode.
    pub mode: FreeMode,
    /// Grace period sequence number (for RCU).
    pub gp_seq: u64,
    /// Whether this entry is active.
    pub active: bool,
}

// -------------------------------------------------------------------
// DeferredFreeList
// -------------------------------------------------------------------

/// RCU deferred free list.
pub struct DeferredFreeList {
    /// Pending entries.
    entries: [FreeEntry; MAX_DEFERRED],
    /// Number of entries.
    count: usize,
    /// Current grace period sequence.
    current_gp: u64,
}

impl Default for DeferredFreeList {
    fn default() -> Self {
        Self {
            entries: [FreeEntry::default(); MAX_DEFERRED],
            count: 0,
            current_gp: 0,
        }
    }
}

impl DeferredFreeList {
    /// Adds an entry to the deferred list.
    pub fn add(&mut self, addr: u64, class_idx: usize) -> Result<()> {
        if self.count >= MAX_DEFERRED {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = FreeEntry {
            addr,
            class_idx,
            mode: FreeMode::DeferredRcu,
            gp_seq: self.current_gp,
            active: true,
        };
        self.count += 1;
        Ok(())
    }

    /// Drains entries that have passed the grace period.
    pub fn drain(&mut self, completed_gp: u64) -> usize {
        let mut drained = 0;
        for i in 0..self.count {
            if self.entries[i].active && self.entries[i].gp_seq <= completed_gp {
                self.entries[i].active = false;
                drained += 1;
            }
        }
        drained
    }

    /// Advances the grace period counter.
    pub fn advance_gp(&mut self) {
        self.current_gp += 1;
    }

    /// Returns the number of pending entries.
    pub fn pending_count(&self) -> usize {
        self.entries[..self.count]
            .iter()
            .filter(|e| e.active)
            .count()
    }
}

// -------------------------------------------------------------------
// KfreeStats
// -------------------------------------------------------------------

/// Free-path statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct KfreeStats {
    /// Total immediate frees.
    pub immediate_frees: u64,
    /// Total deferred frees queued.
    pub deferred_queued: u64,
    /// Total deferred frees completed.
    pub deferred_completed: u64,
    /// Total bulk frees.
    pub bulk_frees: u64,
    /// Free operations with invalid address.
    pub invalid_frees: u64,
    /// Total objects freed.
    pub total_freed: u64,
}

impl KfreeStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// SlabKfree
// -------------------------------------------------------------------

/// The kfree engine for slab-allocated objects.
pub struct SlabKfree {
    /// Size class base sizes.
    class_sizes: [usize; MAX_SIZE_CLASSES],
    /// Number of active size classes.
    nr_classes: usize,
    /// Deferred free list.
    deferred: DeferredFreeList,
    /// Statistics.
    stats: KfreeStats,
}

impl Default for SlabKfree {
    fn default() -> Self {
        let mut class_sizes = [0usize; MAX_SIZE_CLASSES];
        // Initialize geometric size classes: 8, 16, 32, ..., 8192.
        for i in 0..MAX_SIZE_CLASSES {
            class_sizes[i] = 8 << i.min(13);
        }
        Self {
            class_sizes,
            nr_classes: MAX_SIZE_CLASSES,
            deferred: DeferredFreeList::default(),
            stats: KfreeStats::default(),
        }
    }
}

impl SlabKfree {
    /// Creates a new kfree engine.
    pub fn new() -> Self {
        Self::default()
    }

    /// Finds the size class for a given object size.
    fn find_class(&self, size: usize) -> Option<usize> {
        for i in 0..self.nr_classes {
            if self.class_sizes[i] >= size {
                return Some(i);
            }
        }
        None
    }

    /// Frees an object immediately.
    pub fn kfree(&mut self, addr: u64, size: usize) -> Result<()> {
        if addr == 0 {
            return Ok(()); // NULL free is valid no-op.
        }
        let _class = self.find_class(size).ok_or(Error::InvalidArgument)?;
        self.stats.immediate_frees += 1;
        self.stats.total_freed += 1;
        Ok(())
    }

    /// Queues an object for deferred (RCU) free.
    pub fn kfree_rcu(&mut self, addr: u64, size: usize) -> Result<()> {
        if addr == 0 {
            return Ok(());
        }
        let class = self.find_class(size).ok_or(Error::InvalidArgument)?;
        self.deferred.add(addr, class)?;
        self.stats.deferred_queued += 1;
        Ok(())
    }

    /// Processes deferred frees for a completed grace period.
    pub fn process_deferred(&mut self, completed_gp: u64) -> usize {
        let drained = self.deferred.drain(completed_gp);
        self.stats.deferred_completed += drained as u64;
        self.stats.total_freed += drained as u64;
        drained
    }

    /// Advances the grace period.
    pub fn advance_gp(&mut self) {
        self.deferred.advance_gp();
    }

    /// Performs a bulk free of objects at the given addresses.
    pub fn kfree_bulk(&mut self, addrs: &[u64], size: usize) -> Result<usize> {
        let _class = self.find_class(size).ok_or(Error::InvalidArgument)?;
        let mut freed = 0;
        for addr in addrs.iter().take(MAX_BATCH) {
            if *addr != 0 {
                freed += 1;
            }
        }
        self.stats.bulk_frees += 1;
        self.stats.total_freed += freed as u64;
        Ok(freed)
    }

    /// Returns the number of pending deferred frees.
    pub fn pending_deferred(&self) -> usize {
        self.deferred.pending_count()
    }

    /// Returns statistics.
    pub fn stats(&self) -> &KfreeStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
