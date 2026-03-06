// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-cgroup memory reclaim subsystem.
//!
//! Implements the `memory.reclaim` interface and `memory.high` soft
//! throttle for cgroup v2, allowing targeted memory reclaim within
//! individual cgroups without impacting the rest of the system.
//!
//! This complements the global kswapd reclaim (`crate::kswapd`) and
//! memcg accounting (`crate::memcg`) by enabling:
//!
//! - **Proactive reclaim**: user-space memory managers can write to
//!   `memory.reclaim` to reclaim a specific number of pages from a
//!   cgroup before the system hits pressure.
//! - **Soft throttle**: when a cgroup's usage exceeds `memory.high`,
//!   allocating tasks are throttled (delayed) rather than killed,
//!   creating back-pressure that encourages the cgroup to self-limit.
//!
//! # Architecture
//!
//! - [`ReclaimTarget`] — what type of pages to reclaim
//! - [`ThrottleState`] — per-cgroup throttle tracking
//! - [`CgroupReclaimConfig`] — per-cgroup reclaim tuning
//! - [`CgroupReclaimContext`] — active reclaim operation state
//! - [`CgroupReclaimStats`] — per-cgroup reclaim statistics
//! - [`CgroupReclaimEntry`] — per-cgroup reclaim entry
//! - [`CgroupReclaimManager`] — central manager for all cgroups
//!
//! Reference: Linux `mm/memcontrol.c` (`memory.reclaim`,
//! `memory.high`), `mm/vmscan.c` (cgroup-aware reclaim).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of cgroups that can have reclaim state.
const MAX_CGROUPS: usize = 64;

/// Maximum active reclaim contexts (concurrent reclaim operations).
const MAX_ACTIVE_RECLAIMS: usize = 16;

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Sentinel value meaning "no limit".
const NO_LIMIT: u64 = u64::MAX;

/// Default throttle delay in microseconds when over memory.high.
const DEFAULT_THROTTLE_DELAY_US: u64 = 2000;

/// Maximum throttle delay in microseconds.
const MAX_THROTTLE_DELAY_US: u64 = 100_000;

/// Default scan batch size for per-cgroup reclaim.
const DEFAULT_SCAN_BATCH: usize = 32;

/// Maximum number of scan passes per reclaim invocation.
const MAX_SCAN_PASSES: u32 = 16;

// -------------------------------------------------------------------
// ReclaimTarget
// -------------------------------------------------------------------

/// Types of pages targeted for reclaim within a cgroup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ReclaimTarget {
    /// Reclaim any reclaimable pages (anonymous + file-backed).
    #[default]
    Any,
    /// Reclaim only anonymous pages (requires swap).
    Anonymous,
    /// Reclaim only file-backed (page cache) pages.
    File,
    /// Reclaim slab objects associated with this cgroup.
    Slab,
}

// -------------------------------------------------------------------
// ThrottleState
// -------------------------------------------------------------------

/// Per-cgroup throttle tracking for the `memory.high` soft limit.
///
/// When a cgroup's memory usage exceeds `memory.high`, allocating
/// tasks accumulate throttle delay. The delay increases
/// proportionally to the overage.
#[derive(Debug, Clone, Copy)]
pub struct ThrottleState {
    /// Whether throttling is currently active for this cgroup.
    pub active: bool,
    /// Current throttle delay in microseconds.
    pub delay_us: u64,
    /// Number of times a task has been throttled.
    pub throttle_count: u64,
    /// Total accumulated delay in microseconds.
    pub total_delay_us: u64,
    /// Timestamp (tick count) when throttling last triggered.
    pub last_throttle_tick: u64,
}

impl ThrottleState {
    /// Creates a new inactive throttle state.
    const fn inactive() -> Self {
        Self {
            active: false,
            delay_us: 0,
            throttle_count: 0,
            total_delay_us: 0,
            last_throttle_tick: 0,
        }
    }
}

// -------------------------------------------------------------------
// CgroupReclaimConfig
// -------------------------------------------------------------------

/// Per-cgroup reclaim configuration.
#[derive(Debug, Clone, Copy)]
pub struct CgroupReclaimConfig {
    /// The `memory.high` soft limit in bytes (NO_LIMIT = disabled).
    pub memory_high: u64,
    /// Base throttle delay in microseconds when over memory.high.
    pub throttle_delay_us: u64,
    /// Scan batch size (pages per scan cycle).
    pub scan_batch: usize,
    /// Whether to prefer reclaiming file-backed pages over
    /// anonymous.
    pub prefer_file: bool,
}

impl Default for CgroupReclaimConfig {
    fn default() -> Self {
        Self {
            memory_high: NO_LIMIT,
            throttle_delay_us: DEFAULT_THROTTLE_DELAY_US,
            scan_batch: DEFAULT_SCAN_BATCH,
            prefer_file: true,
        }
    }
}

// -------------------------------------------------------------------
// CgroupReclaimContext
// -------------------------------------------------------------------

/// State of an active per-cgroup reclaim operation.
///
/// Created when user-space writes to `memory.reclaim` or when the
/// system detects that a cgroup is over its `memory.high`.
#[derive(Debug, Clone, Copy)]
pub struct CgroupReclaimContext {
    /// Cgroup identifier this reclaim targets.
    pub cgroup_id: u32,
    /// Number of pages requested for reclaim.
    pub nr_to_reclaim: u64,
    /// Number of pages reclaimed so far.
    pub nr_reclaimed: u64,
    /// Number of pages scanned so far.
    pub nr_scanned: u64,
    /// Number of scan passes completed.
    pub scan_passes: u32,
    /// Target page type to reclaim.
    pub target: ReclaimTarget,
    /// Whether this context is active.
    pub active: bool,
    /// Whether reclaim was initiated by user-space (memory.reclaim)
    /// vs. automatic (memory.high).
    pub user_initiated: bool,
}

impl CgroupReclaimContext {
    /// Creates an empty, inactive context.
    const fn empty() -> Self {
        Self {
            cgroup_id: 0,
            nr_to_reclaim: 0,
            nr_reclaimed: 0,
            nr_scanned: 0,
            scan_passes: 0,
            target: ReclaimTarget::Any,
            active: false,
            user_initiated: false,
        }
    }

    /// Returns `true` if the reclaim target has been met.
    pub const fn target_met(&self) -> bool {
        self.nr_reclaimed >= self.nr_to_reclaim
    }

    /// Returns `true` if the maximum number of scan passes has been
    /// reached.
    pub const fn exhausted(&self) -> bool {
        self.scan_passes >= MAX_SCAN_PASSES
    }

    /// Returns `true` if this reclaim operation should stop.
    pub const fn should_stop(&self) -> bool {
        self.target_met() || self.exhausted()
    }

    /// Returns the number of pages still needed.
    pub const fn remaining(&self) -> u64 {
        self.nr_to_reclaim.saturating_sub(self.nr_reclaimed)
    }
}

// -------------------------------------------------------------------
// CgroupReclaimStats
// -------------------------------------------------------------------

/// Per-cgroup reclaim statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct CgroupReclaimStats {
    /// Total pages scanned.
    pub pages_scanned: u64,
    /// Total pages reclaimed.
    pub pages_reclaimed: u64,
    /// Total pages skipped (pinned, dirty, wrong type).
    pub pages_skipped: u64,
    /// Number of reclaim invocations from user-space.
    pub user_reclaim_calls: u64,
    /// Number of automatic reclaim invocations (memory.high).
    pub auto_reclaim_calls: u64,
    /// Total throttle events.
    pub throttle_events: u64,
    /// Total accumulated throttle delay in microseconds.
    pub total_throttle_delay_us: u64,
    /// Number of scan passes.
    pub scan_passes: u64,
}

// -------------------------------------------------------------------
// CgroupReclaimEntry
// -------------------------------------------------------------------

/// Per-cgroup reclaim state and configuration.
#[derive(Debug, Clone, Copy)]
pub struct CgroupReclaimEntry {
    /// Cgroup identifier.
    pub cgroup_id: u32,
    /// Current memory usage in bytes (mirrored from memcg).
    pub usage: u64,
    /// Hard memory limit in bytes (mirrored from memcg).
    pub limit: u64,
    /// Reclaim configuration.
    pub config: CgroupReclaimConfig,
    /// Throttle state.
    pub throttle: ThrottleState,
    /// Reclaim statistics.
    pub stats: CgroupReclaimStats,
    /// Whether this slot is in use.
    pub active: bool,
}

impl CgroupReclaimEntry {
    /// Creates an empty, inactive entry.
    const fn empty() -> Self {
        Self {
            cgroup_id: 0,
            usage: 0,
            limit: NO_LIMIT,
            config: CgroupReclaimConfig {
                memory_high: NO_LIMIT,
                throttle_delay_us: DEFAULT_THROTTLE_DELAY_US,
                scan_batch: DEFAULT_SCAN_BATCH,
                prefer_file: true,
            },
            throttle: ThrottleState::inactive(),
            stats: CgroupReclaimStats {
                pages_scanned: 0,
                pages_reclaimed: 0,
                pages_skipped: 0,
                user_reclaim_calls: 0,
                auto_reclaim_calls: 0,
                throttle_events: 0,
                total_throttle_delay_us: 0,
                scan_passes: 0,
            },
            active: false,
        }
    }

    /// Returns `true` if usage exceeds the `memory.high` soft limit.
    pub const fn over_high(&self) -> bool {
        self.config.memory_high != NO_LIMIT && self.usage > self.config.memory_high
    }

    /// Returns the amount by which usage exceeds `memory.high`
    /// (in bytes), or 0 if under the limit.
    pub const fn overage(&self) -> u64 {
        if self.over_high() {
            self.usage.saturating_sub(self.config.memory_high)
        } else {
            0
        }
    }

    /// Computes the throttle delay proportional to the overage.
    ///
    /// Delay scales linearly: at 1x over, use base delay. At 2x,
    /// double the base. Capped at [`MAX_THROTTLE_DELAY_US`].
    pub fn compute_throttle_delay(&self) -> u64 {
        if !self.over_high() || self.config.memory_high == 0 {
            return 0;
        }

        let overage = self.overage();
        let high = self.config.memory_high;
        // Scale factor: overage / high * base_delay.
        let scaled = overage.saturating_mul(self.config.throttle_delay_us) / high;

        let delay = self.config.throttle_delay_us.saturating_add(scaled);
        if delay > MAX_THROTTLE_DELAY_US {
            MAX_THROTTLE_DELAY_US
        } else {
            delay
        }
    }
}

// -------------------------------------------------------------------
// CgroupReclaimManager
// -------------------------------------------------------------------

/// Central manager for per-cgroup memory reclaim.
///
/// Tracks cgroup reclaim state, processes `memory.reclaim` requests,
/// and enforces `memory.high` throttling. Maintains active reclaim
/// contexts for concurrent operations.
pub struct CgroupReclaimManager {
    /// Per-cgroup entries.
    entries: [CgroupReclaimEntry; MAX_CGROUPS],
    /// Number of active entries.
    entry_count: usize,
    /// Active reclaim contexts.
    contexts: [CgroupReclaimContext; MAX_ACTIVE_RECLAIMS],
    /// Number of active contexts.
    context_count: usize,
}

impl Default for CgroupReclaimManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CgroupReclaimManager {
    /// Creates a new, empty reclaim manager.
    pub const fn new() -> Self {
        Self {
            entries: [CgroupReclaimEntry::empty(); MAX_CGROUPS],
            entry_count: 0,
            contexts: [CgroupReclaimContext::empty(); MAX_ACTIVE_RECLAIMS],
            context_count: 0,
        }
    }

    // ---------------------------------------------------------------
    // Cgroup registration
    // ---------------------------------------------------------------

    /// Registers a cgroup for reclaim tracking.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all slots are full.
    /// Returns [`Error::AlreadyExists`] if the cgroup is already
    /// registered.
    pub fn register_cgroup(&mut self, cgroup_id: u32) -> Result<()> {
        if self.find_entry_index(cgroup_id).is_some() {
            return Err(Error::AlreadyExists);
        }
        if self.entry_count >= MAX_CGROUPS {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .entries
            .iter_mut()
            .find(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = CgroupReclaimEntry::empty();
        slot.cgroup_id = cgroup_id;
        slot.active = true;

        self.entry_count += 1;
        Ok(())
    }

    /// Unregisters a cgroup from reclaim tracking.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the cgroup is not registered.
    /// Returns [`Error::Busy`] if there is an active reclaim context
    /// for this cgroup.
    pub fn unregister_cgroup(&mut self, cgroup_id: u32) -> Result<()> {
        // Check for active reclaim contexts.
        for ctx in &self.contexts {
            if ctx.active && ctx.cgroup_id == cgroup_id {
                return Err(Error::Busy);
            }
        }

        let idx = self.find_entry_index(cgroup_id).ok_or(Error::NotFound)?;
        self.entries[idx].active = false;
        self.entry_count = self.entry_count.saturating_sub(1);
        Ok(())
    }

    // ---------------------------------------------------------------
    // Configuration
    // ---------------------------------------------------------------

    /// Sets the `memory.high` soft limit for a cgroup (in bytes).
    ///
    /// Pass `u64::MAX` to disable the soft limit.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the cgroup is not registered.
    pub fn set_memory_high(&mut self, cgroup_id: u32, high: u64) -> Result<()> {
        let idx = self.find_entry_index(cgroup_id).ok_or(Error::NotFound)?;
        self.entries[idx].config.memory_high = high;
        Ok(())
    }

    /// Sets the hard memory limit for a cgroup (in bytes).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the cgroup is not registered.
    pub fn set_memory_limit(&mut self, cgroup_id: u32, limit: u64) -> Result<()> {
        let idx = self.find_entry_index(cgroup_id).ok_or(Error::NotFound)?;
        self.entries[idx].limit = limit;
        Ok(())
    }

    /// Sets the throttle delay for a cgroup.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the cgroup is not registered.
    /// Returns [`Error::InvalidArgument`] if `delay_us` exceeds
    /// [`MAX_THROTTLE_DELAY_US`].
    pub fn set_throttle_delay(&mut self, cgroup_id: u32, delay_us: u64) -> Result<()> {
        if delay_us > MAX_THROTTLE_DELAY_US {
            return Err(Error::InvalidArgument);
        }
        let idx = self.find_entry_index(cgroup_id).ok_or(Error::NotFound)?;
        self.entries[idx].config.throttle_delay_us = delay_us;
        Ok(())
    }

    /// Updates the current memory usage for a cgroup.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the cgroup is not registered.
    pub fn update_usage(&mut self, cgroup_id: u32, usage: u64) -> Result<()> {
        let idx = self.find_entry_index(cgroup_id).ok_or(Error::NotFound)?;
        self.entries[idx].usage = usage;
        Ok(())
    }

    // ---------------------------------------------------------------
    // memory.reclaim interface
    // ---------------------------------------------------------------

    /// Initiates a user-space reclaim request (`memory.reclaim`).
    ///
    /// Requests reclaim of `nr_pages` pages from the specified
    /// cgroup. The reclaim is processed by calling
    /// [`process_reclaim`](Self::process_reclaim).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the cgroup is not registered.
    /// Returns [`Error::InvalidArgument`] if `nr_pages` is zero.
    /// Returns [`Error::OutOfMemory`] if no reclaim context slot is
    /// available.
    pub fn reclaim_from_cgroup(
        &mut self,
        cgroup_id: u32,
        nr_pages: u64,
        target: ReclaimTarget,
    ) -> Result<()> {
        if nr_pages == 0 {
            return Err(Error::InvalidArgument);
        }
        let idx = self.find_entry_index(cgroup_id).ok_or(Error::NotFound)?;

        self.entries[idx].stats.user_reclaim_calls += 1;

        self.create_context(cgroup_id, nr_pages, target, true)
    }

    /// Processes a single pass of an active reclaim context.
    ///
    /// Simulates scanning and reclaiming pages from the cgroup.
    /// Each pass scans up to `scan_batch` pages and reclaims those
    /// that are eligible.
    ///
    /// Returns the number of pages reclaimed in this pass, or
    /// an error if the context is not found.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the cgroup has no active
    /// context.
    pub fn process_reclaim(&mut self, cgroup_id: u32) -> Result<u64> {
        let ctx_idx = self.find_context_index(cgroup_id).ok_or(Error::NotFound)?;

        if self.contexts[ctx_idx].should_stop() {
            return Ok(0);
        }

        let entry_idx = self.find_entry_index(cgroup_id);
        let batch = entry_idx
            .map(|i| self.entries[i].config.scan_batch)
            .unwrap_or(DEFAULT_SCAN_BATCH);

        // Simulate scanning: reclaim half the batch as a heuristic.
        let scanned = batch as u64;
        let remaining = self.contexts[ctx_idx].remaining();
        let reclaimed = if remaining < scanned / 2 {
            remaining
        } else {
            scanned / 2
        };

        self.contexts[ctx_idx].nr_scanned =
            self.contexts[ctx_idx].nr_scanned.saturating_add(scanned);
        self.contexts[ctx_idx].nr_reclaimed = self.contexts[ctx_idx]
            .nr_reclaimed
            .saturating_add(reclaimed);
        self.contexts[ctx_idx].scan_passes += 1;

        // Update entry stats.
        if let Some(eidx) = entry_idx {
            self.entries[eidx].stats.pages_scanned = self.entries[eidx]
                .stats
                .pages_scanned
                .saturating_add(scanned);
            self.entries[eidx].stats.pages_reclaimed = self.entries[eidx]
                .stats
                .pages_reclaimed
                .saturating_add(reclaimed);
            self.entries[eidx].stats.scan_passes += 1;

            // Reduce usage by reclaimed pages.
            let bytes = reclaimed.saturating_mul(PAGE_SIZE);
            self.entries[eidx].usage = self.entries[eidx].usage.saturating_sub(bytes);
        }

        // Auto-complete if target met or exhausted.
        if self.contexts[ctx_idx].should_stop() {
            self.contexts[ctx_idx].active = false;
            self.context_count = self.context_count.saturating_sub(1);
        }

        Ok(reclaimed)
    }

    // ---------------------------------------------------------------
    // memory.high throttle enforcement
    // ---------------------------------------------------------------

    /// Checks whether a cgroup requires throttling and returns the
    /// delay in microseconds.
    ///
    /// If usage is over `memory.high`, computes a proportional delay
    /// and updates throttle counters. Returns 0 if no throttle is
    /// needed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the cgroup is not registered.
    pub fn check_throttle(&mut self, cgroup_id: u32) -> Result<u64> {
        let idx = self.find_entry_index(cgroup_id).ok_or(Error::NotFound)?;

        if !self.entries[idx].over_high() {
            // Reset throttle if we dropped back below high.
            self.entries[idx].throttle.active = false;
            self.entries[idx].throttle.delay_us = 0;
            return Ok(0);
        }

        let delay = self.entries[idx].compute_throttle_delay();

        self.entries[idx].throttle.active = true;
        self.entries[idx].throttle.delay_us = delay;
        self.entries[idx].throttle.throttle_count += 1;
        self.entries[idx].throttle.total_delay_us = self.entries[idx]
            .throttle
            .total_delay_us
            .saturating_add(delay);

        self.entries[idx].stats.throttle_events += 1;
        self.entries[idx].stats.total_throttle_delay_us = self.entries[idx]
            .stats
            .total_throttle_delay_us
            .saturating_add(delay);

        Ok(delay)
    }

    /// Triggers automatic reclaim for a cgroup that is over
    /// `memory.high`.
    ///
    /// Computes how many pages need to be reclaimed to bring usage
    /// back down to `memory.high` and starts a reclaim context.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the cgroup is not registered.
    /// Returns [`Error::InvalidArgument`] if the cgroup is not over
    /// `memory.high`.
    pub fn trigger_high_reclaim(&mut self, cgroup_id: u32) -> Result<u64> {
        let idx = self.find_entry_index(cgroup_id).ok_or(Error::NotFound)?;

        if !self.entries[idx].over_high() {
            return Err(Error::InvalidArgument);
        }

        let overage = self.entries[idx].overage();
        let nr_pages = overage.saturating_add(PAGE_SIZE - 1) / PAGE_SIZE;

        self.entries[idx].stats.auto_reclaim_calls += 1;

        let target = if self.entries[idx].config.prefer_file {
            ReclaimTarget::File
        } else {
            ReclaimTarget::Any
        };

        self.create_context(cgroup_id, nr_pages, target, false)?;
        Ok(nr_pages)
    }

    // ---------------------------------------------------------------
    // Accessors
    // ---------------------------------------------------------------

    /// Returns the number of registered cgroups.
    pub const fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Returns `true` if no cgroups are registered.
    pub const fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    /// Returns the number of active reclaim contexts.
    pub const fn active_reclaims(&self) -> usize {
        self.context_count
    }

    /// Returns the reclaim statistics for a cgroup.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the cgroup is not registered.
    pub fn get_stats(&self, cgroup_id: u32) -> Result<&CgroupReclaimStats> {
        let idx = self.find_entry_index(cgroup_id).ok_or(Error::NotFound)?;
        Ok(&self.entries[idx].stats)
    }

    /// Returns the throttle state for a cgroup.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the cgroup is not registered.
    pub fn get_throttle(&self, cgroup_id: u32) -> Result<&ThrottleState> {
        let idx = self.find_entry_index(cgroup_id).ok_or(Error::NotFound)?;
        Ok(&self.entries[idx].throttle)
    }

    /// Returns the reclaim configuration for a cgroup.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the cgroup is not registered.
    pub fn get_config(&self, cgroup_id: u32) -> Result<&CgroupReclaimConfig> {
        let idx = self.find_entry_index(cgroup_id).ok_or(Error::NotFound)?;
        Ok(&self.entries[idx].config)
    }

    /// Returns the current usage for a cgroup.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the cgroup is not registered.
    pub fn get_usage(&self, cgroup_id: u32) -> Result<u64> {
        let idx = self.find_entry_index(cgroup_id).ok_or(Error::NotFound)?;
        Ok(self.entries[idx].usage)
    }

    /// Returns `true` if the cgroup is over its `memory.high` limit.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the cgroup is not registered.
    pub fn is_over_high(&self, cgroup_id: u32) -> Result<bool> {
        let idx = self.find_entry_index(cgroup_id).ok_or(Error::NotFound)?;
        Ok(self.entries[idx].over_high())
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Finds the array index of a cgroup entry by ID.
    fn find_entry_index(&self, cgroup_id: u32) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.active && e.cgroup_id == cgroup_id)
    }

    /// Finds the array index of an active reclaim context for a
    /// cgroup.
    fn find_context_index(&self, cgroup_id: u32) -> Option<usize> {
        self.contexts
            .iter()
            .position(|c| c.active && c.cgroup_id == cgroup_id)
    }

    /// Creates a new reclaim context.
    fn create_context(
        &mut self,
        cgroup_id: u32,
        nr_pages: u64,
        target: ReclaimTarget,
        user_initiated: bool,
    ) -> Result<()> {
        // If there is already an active context for this cgroup,
        // update it instead of creating a new one.
        if let Some(idx) = self.find_context_index(cgroup_id) {
            self.contexts[idx].nr_to_reclaim =
                self.contexts[idx].nr_to_reclaim.saturating_add(nr_pages);
            return Ok(());
        }

        if self.context_count >= MAX_ACTIVE_RECLAIMS {
            return Err(Error::OutOfMemory);
        }

        let slot = self
            .contexts
            .iter_mut()
            .find(|c| !c.active)
            .ok_or(Error::OutOfMemory)?;

        *slot = CgroupReclaimContext {
            cgroup_id,
            nr_to_reclaim: nr_pages,
            nr_reclaimed: 0,
            nr_scanned: 0,
            scan_passes: 0,
            target,
            active: true,
            user_initiated,
        };

        self.context_count += 1;
        Ok(())
    }
}
