// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! OOM notification chain.
//!
//! Provides a notifier chain that fires when the system enters an
//! out-of-memory condition. Subsystems register callbacks (notifiers)
//! that are invoked in priority order before and after the OOM killer
//! selects a victim. This allows subsystems to:
//!
//! - Release caches or temporary buffers to avoid OOM entirely.
//! - Log diagnostic information for post-mortem analysis.
//! - Protect critical processes from being killed.
//! - Perform cleanup after a process is OOM-killed.
//!
//! # Priority Ordering
//!
//! Notifiers with lower priority numbers are invoked first.
//! Convention:
//!
//! | Range   | Purpose |
//! |---------|---------|
//! | 0..99   | Emergency: drop caches, free slabs |
//! | 100..199| Normal: log diagnostics, adjust limits |
//! | 200..255| Late: post-OOM cleanup, statistics |
//!
//! # Callback Return Values
//!
//! Each notifier returns an [`OomAction`]:
//! - `Continue`: proceed to the next notifier.
//! - `Stop`: abort the chain (the notifier handled the OOM itself).
//! - `FreedMemory(pages)`: memory was freed; re-check before killing.
//!
//! # Reference
//!
//! Linux `include/linux/oom.h`, `mm/oom_kill.c`
//! (`register_oom_notifier`).

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum number of notifiers in the chain.
const MAX_NOTIFIERS: usize = 64;

/// Maximum name length for a notifier entry.
const MAX_NAME_LEN: usize = 64;

// ======================================================================
// OomPriority — invocation priority
// ======================================================================

/// Invocation priority for an OOM notifier.
///
/// Lower values are invoked first. Priorities are grouped into
/// bands for convention (see module-level docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OomPriority(pub u8);

impl OomPriority {
    /// Emergency priority (first to run).
    pub const EMERGENCY: Self = Self(0);
    /// Normal priority.
    pub const NORMAL: Self = Self(100);
    /// Late priority (last to run).
    pub const LATE: Self = Self(200);

    /// Create a custom priority.
    pub const fn new(val: u8) -> Self {
        Self(val)
    }

    /// Get the raw priority value.
    pub fn value(self) -> u8 {
        self.0
    }
}

// ======================================================================
// OomAction — notifier return value
// ======================================================================

/// Action returned by an OOM notifier callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OomAction {
    /// Continue processing the next notifier in the chain.
    Continue,
    /// Stop the chain — the notifier handled the OOM condition.
    Stop,
    /// Memory was freed; the specified number of pages are now
    /// available. The OOM killer should re-check before killing.
    FreedMemory(u64),
}

// ======================================================================
// OomEvent — describes the OOM condition
// ======================================================================

/// Describes the out-of-memory event that triggered the chain.
#[derive(Debug, Clone, Copy)]
pub struct OomEvent {
    /// Number of pages requested that triggered OOM.
    pub order: u32,
    /// GFP-style allocation flags (kernel-internal).
    pub gfp_flags: u32,
    /// NUMA node where allocation was attempted (u32::MAX = any).
    pub node: u32,
    /// Total pages free in the system at OOM time.
    pub free_pages: u64,
    /// Total pages in the system.
    pub total_pages: u64,
    /// Number of reclaimable slab pages.
    pub reclaimable_slab: u64,
    /// Task ID of the process that triggered OOM (0 = system).
    pub triggering_tid: u64,
    /// Monotonic tick when OOM was detected.
    pub timestamp: u64,
    /// Memory cgroup ID (0 = global OOM).
    pub memcg_id: u64,
    /// Whether this is a memcg-local OOM (vs. global).
    pub is_memcg_oom: bool,
}

impl OomEvent {
    /// Create an empty OOM event.
    pub const fn new() -> Self {
        Self {
            order: 0,
            gfp_flags: 0,
            node: u32::MAX,
            free_pages: 0,
            total_pages: 0,
            reclaimable_slab: 0,
            triggering_tid: 0,
            timestamp: 0,
            memcg_id: 0,
            is_memcg_oom: false,
        }
    }

    /// Memory pressure as a percentage (0..100).
    pub fn pressure_pct(&self) -> u64 {
        if self.total_pages == 0 {
            return 100;
        }
        let used = self.total_pages.saturating_sub(self.free_pages);
        used * 100 / self.total_pages
    }
}

// ======================================================================
// OomNotifyEntry — a single registered notifier
// ======================================================================

/// A registered OOM notifier entry.
#[derive(Debug, Clone, Copy)]
pub struct OomNotifyEntry {
    /// Unique notifier ID.
    pub id: u64,
    /// Human-readable name.
    pub name: [u8; MAX_NAME_LEN],
    /// Name length in bytes.
    pub name_len: usize,
    /// Callback identifier (dispatched to actual function).
    pub func_id: u64,
    /// Invocation priority.
    pub priority: OomPriority,
    /// Whether this entry is active.
    pub active: bool,
    /// Number of times this notifier has been invoked.
    pub invoke_count: u64,
    /// Last timestamp when this notifier was invoked.
    pub last_invoke_tick: u64,
    /// Total pages freed by this notifier (if applicable).
    pub total_freed: u64,
}

impl OomNotifyEntry {
    /// Create an empty (inactive) notifier entry.
    const fn empty() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            func_id: 0,
            priority: OomPriority::NORMAL,
            active: false,
            invoke_count: 0,
            last_invoke_tick: 0,
            total_freed: 0,
        }
    }
}

// ======================================================================
// OomChainStats — aggregate statistics
// ======================================================================

/// Aggregate statistics for the OOM notifier chain.
#[derive(Debug, Clone, Copy)]
pub struct OomChainStats {
    /// Total OOM events processed.
    pub total_events: u64,
    /// Number of times a notifier stopped the chain.
    pub stopped_count: u64,
    /// Total pages freed by all notifiers across all events.
    pub total_freed_pages: u64,
    /// Number of events that proceeded to OOM kill.
    pub kill_proceeded: u64,
    /// Number of events resolved without killing.
    pub resolved_without_kill: u64,
    /// Number of active notifiers in the chain.
    pub active_notifiers: u32,
}

impl OomChainStats {
    /// Create zeroed statistics.
    const fn new() -> Self {
        Self {
            total_events: 0,
            stopped_count: 0,
            total_freed_pages: 0,
            kill_proceeded: 0,
            resolved_without_kill: 0,
            active_notifiers: 0,
        }
    }
}

// ======================================================================
// NotifyResult — result of processing the notifier chain
// ======================================================================

/// Result of processing the entire OOM notifier chain.
#[derive(Debug, Clone, Copy)]
pub struct NotifyResult {
    /// Number of notifiers that were invoked.
    pub invoked: u32,
    /// Total pages freed by all notifiers in this pass.
    pub freed_pages: u64,
    /// Whether the chain was stopped by a notifier.
    pub stopped: bool,
    /// Whether the OOM condition was resolved without killing.
    pub resolved: bool,
}

// ======================================================================
// OomNotifierChain — the notifier chain
// ======================================================================

/// OOM notifier chain managing registered callbacks.
///
/// Notifiers are maintained in priority-sorted order and invoked
/// sequentially when an OOM event occurs.
pub struct OomNotifierChain {
    /// Registered notifier entries.
    entries: [OomNotifyEntry; MAX_NOTIFIERS],
    /// Number of active entries.
    num_entries: usize,
    /// Next unique notifier ID.
    next_id: u64,
    /// Aggregate statistics.
    stats: OomChainStats,
    /// Current monotonic tick.
    current_tick: u64,
    /// Sorted index array (indices into `entries`, sorted by priority).
    sorted: [usize; MAX_NOTIFIERS],
    /// Whether the sorted index needs rebuilding.
    sort_dirty: bool,
}

impl OomNotifierChain {
    /// Create a new empty notifier chain.
    pub const fn new() -> Self {
        Self {
            entries: [const { OomNotifyEntry::empty() }; MAX_NOTIFIERS],
            num_entries: 0,
            next_id: 1,
            stats: OomChainStats::new(),
            current_tick: 0,
            sorted: [0usize; MAX_NOTIFIERS],
            sort_dirty: true,
        }
    }

    /// Register a new OOM notifier.
    ///
    /// Returns the unique notifier ID on success.
    pub fn register(&mut self, name: &[u8], func_id: u64, priority: OomPriority) -> Result<u64> {
        if self.num_entries >= MAX_NOTIFIERS {
            return Err(Error::OutOfMemory);
        }

        let slot_idx = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id += 1;

        let entry = &mut self.entries[slot_idx];
        entry.id = id;
        let len = name.len().min(MAX_NAME_LEN);
        entry.name[..len].copy_from_slice(&name[..len]);
        entry.name_len = len;
        entry.func_id = func_id;
        entry.priority = priority;
        entry.active = true;
        entry.invoke_count = 0;
        entry.last_invoke_tick = 0;
        entry.total_freed = 0;

        self.num_entries += 1;
        self.stats.active_notifiers += 1;
        self.sort_dirty = true;

        Ok(id)
    }

    /// Unregister an OOM notifier by ID.
    pub fn unregister(&mut self, id: u64) -> Result<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.id == id)
            .ok_or(Error::NotFound)?;

        entry.active = false;
        if self.num_entries > 0 {
            self.num_entries -= 1;
        }
        if self.stats.active_notifiers > 0 {
            self.stats.active_notifiers -= 1;
        }
        self.sort_dirty = true;

        Ok(())
    }

    /// Rebuild the priority-sorted index.
    fn rebuild_sorted(&mut self) {
        // Collect active entry indices.
        let mut count = 0usize;
        for (i, entry) in self.entries.iter().enumerate() {
            if entry.active {
                self.sorted[count] = i;
                count += 1;
            }
        }

        // Insertion sort by priority (small N, no alloc needed).
        for i in 1..count {
            let key = self.sorted[i];
            let key_prio = self.entries[key].priority;
            let mut j = i;
            while j > 0 && self.entries[self.sorted[j - 1]].priority > key_prio {
                self.sorted[j] = self.sorted[j - 1];
                j -= 1;
            }
            self.sorted[j] = key;
        }

        // Zero out remaining slots.
        for slot in self.sorted.iter_mut().skip(count) {
            *slot = 0;
        }

        self.sort_dirty = false;
    }

    /// Notify all registered callbacks about an OOM event.
    ///
    /// Invokes notifiers in priority order. If any notifier returns
    /// `OomAction::Stop`, the chain is aborted. Pages freed by
    /// `OomAction::FreedMemory` are accumulated.
    ///
    /// Since we cannot call function pointers directly (no_std
    /// static dispatch), the caller must provide a dispatch closure.
    /// In this implementation we simulate the dispatch internally
    /// and return the chain result.
    pub fn notify_all(&mut self, event: &OomEvent) -> NotifyResult {
        if self.sort_dirty {
            self.rebuild_sorted();
        }

        self.stats.total_events += 1;

        let mut result = NotifyResult {
            invoked: 0,
            freed_pages: 0,
            stopped: false,
            resolved: false,
        };

        for i in 0..self.num_entries {
            let entry_idx = self.sorted[i];
            let entry = &mut self.entries[entry_idx];
            if !entry.active {
                continue;
            }

            // In a real kernel, we would dispatch to the actual
            // callback via `entry.func_id`. Here we simulate that
            // every callback returns `Continue`.
            let action = OomAction::Continue;

            entry.invoke_count += 1;
            entry.last_invoke_tick = self.current_tick;
            result.invoked += 1;

            match action {
                OomAction::Continue => {}
                OomAction::Stop => {
                    result.stopped = true;
                    self.stats.stopped_count += 1;
                    break;
                }
                OomAction::FreedMemory(pages) => {
                    result.freed_pages += pages;
                    entry.total_freed += pages;
                    self.stats.total_freed_pages += pages;

                    // If enough memory was freed, consider resolved.
                    let needed = 1u64 << event.order;
                    if result.freed_pages >= needed {
                        result.resolved = true;
                        self.stats.resolved_without_kill += 1;
                        break;
                    }
                }
            }
        }

        if !result.resolved && !result.stopped {
            self.stats.kill_proceeded += 1;
        }

        result
    }

    /// Change the priority of an existing notifier.
    pub fn set_priority(&mut self, id: u64, priority: OomPriority) -> Result<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.id == id)
            .ok_or(Error::NotFound)?;

        entry.priority = priority;
        self.sort_dirty = true;
        Ok(())
    }

    /// Get the number of active notifiers in the chain.
    pub fn get_chain_length(&self) -> usize {
        self.num_entries
    }

    /// Get a reference to a notifier entry by ID.
    pub fn get_entry(&self, id: u64) -> Result<&OomNotifyEntry> {
        self.entries
            .iter()
            .find(|e| e.active && e.id == id)
            .ok_or(Error::NotFound)
    }

    /// Get a reference to the chain statistics.
    pub fn chain_stats(&self) -> &OomChainStats {
        &self.stats
    }

    /// Set the current monotonic tick.
    pub fn set_tick(&mut self, tick: u64) {
        self.current_tick = tick;
    }

    /// Iterate over active notifier entries in priority order.
    ///
    /// Returns an array of IDs in priority order and the count.
    pub fn sorted_ids(&mut self) -> ([u64; MAX_NOTIFIERS], usize) {
        if self.sort_dirty {
            self.rebuild_sorted();
        }
        let mut ids = [0u64; MAX_NOTIFIERS];
        for i in 0..self.num_entries {
            ids[i] = self.entries[self.sorted[i]].id;
        }
        (ids, self.num_entries)
    }

    /// Check whether a notifier with the given name already exists.
    pub fn has_notifier(&self, name: &[u8]) -> bool {
        let len = name.len().min(MAX_NAME_LEN);
        self.entries
            .iter()
            .any(|e| e.active && e.name_len == len && e.name[..len] == name[..len])
    }
}
