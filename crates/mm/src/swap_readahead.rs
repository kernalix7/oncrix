// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Swap readahead policy.
//!
//! Implements speculative prefetching of swap entries to reduce
//! the latency of page faults on swapped-out pages. Two strategies
//! are supported:
//!
//! 1. **Cluster-based** — reads adjacent swap slots around the
//!    faulting entry.
//! 2. **VMA-based** — follows the page fault pattern within a
//!    virtual memory area to predict which pages will be needed.
//!
//! An adaptive window sizes the readahead: window grows on hits
//! and shrinks on misses.
//!
//! # Key Types
//!
//! - [`SwapRaPolicy`] — readahead policy selector
//! - [`SwapRaInfo`] — per-VMA readahead tracking (hits, misses, win)
//! - [`SwapRaConfig`] — global readahead configuration
//! - [`SwapReadaheadEntry`] — a prefetched swap slot
//! - [`SwapReadaheadManager`] — central readahead manager
//! - [`SwapRaStats`] — readahead statistics
//!
//! Reference: Linux `mm/swap_state.c` (`swapin_readahead`),
//! `mm/swap.c`, `include/linux/swap.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Default readahead window (pages).
const DEFAULT_RA_WIN: u32 = 8;

/// Minimum readahead window.
const MIN_RA_WIN: u32 = 1;

/// Maximum readahead window.
const MAX_RA_WIN: u32 = 64;

/// Maximum pages to readahead in a single operation.
const MAX_RA_PAGES: usize = 64;

/// Maximum number of tracked VMAs for readahead.
const MAX_VMA_TRACKING: usize = 128;

/// Maximum number of prefetched entries in the cache.
const MAX_PREFETCH_ENTRIES: usize = 512;

/// Number of logical CPUs for per-CPU state.
const NR_CPUS: usize = 8;

/// Window growth factor on hit (additive, pages).
const WIN_GROW_STEP: u32 = 2;

/// Window shrink factor on miss (multiplicative, /2).
const WIN_SHRINK_SHIFT: u32 = 1;

/// Hit/miss history depth for adaptive decisions.
const HISTORY_DEPTH: usize = 16;

// -------------------------------------------------------------------
// SwapRaPolicy
// -------------------------------------------------------------------

/// Readahead policy selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SwapRaPolicy {
    /// Cluster-based: read adjacent swap slots.
    #[default]
    Cluster,
    /// VMA-based: follow fault pattern.
    Vma,
    /// Disabled: no readahead.
    Disabled,
}

// -------------------------------------------------------------------
// SwapRaConfig
// -------------------------------------------------------------------

/// Global swap readahead configuration.
#[derive(Debug, Clone, Copy)]
pub struct SwapRaConfig {
    /// Default readahead window (pages).
    pub default_win: u32,
    /// Maximum readahead window (pages).
    pub max_win: u32,
    /// Minimum readahead window (pages).
    pub min_win: u32,
    /// Maximum pages per readahead operation.
    pub max_pages: usize,
    /// Active policy.
    pub policy: SwapRaPolicy,
}

impl SwapRaConfig {
    /// Create a config with defaults.
    pub const fn new() -> Self {
        Self {
            default_win: DEFAULT_RA_WIN,
            max_win: MAX_RA_WIN,
            min_win: MIN_RA_WIN,
            max_pages: MAX_RA_PAGES,
            policy: SwapRaPolicy::Cluster,
        }
    }
}

impl Default for SwapRaConfig {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// SwapRaInfo
// -------------------------------------------------------------------

/// Per-VMA readahead tracking.
///
/// Records hit/miss history and the current adaptive window size
/// for a given virtual memory area.
#[derive(Clone)]
pub struct SwapRaInfo {
    /// VMA identifier.
    vma_id: u32,
    /// Total readahead hits (prefetched page was actually faulted).
    hits: u32,
    /// Total readahead misses (prefetched page was never used).
    misses: u32,
    /// Current readahead window size.
    win: u32,
    /// Last faulted swap offset (for pattern detection).
    last_offset: u64,
    /// Direction of sequential access (positive = forward).
    direction: i64,
    /// Recent hit/miss history (true = hit, false = miss).
    history: [bool; HISTORY_DEPTH],
    /// Number of valid history entries.
    history_count: usize,
    /// Next history write index.
    history_next: usize,
    /// Whether this entry is active.
    active: bool,
}

impl SwapRaInfo {
    /// Create an empty tracking entry.
    const fn empty() -> Self {
        Self {
            vma_id: 0,
            hits: 0,
            misses: 0,
            win: DEFAULT_RA_WIN,
            last_offset: 0,
            direction: 1,
            history: [false; HISTORY_DEPTH],
            history_count: 0,
            history_next: 0,
            active: false,
        }
    }

    /// Return the current window size.
    pub const fn window(&self) -> u32 {
        self.win
    }

    /// Return the hit count.
    pub const fn hits(&self) -> u32 {
        self.hits
    }

    /// Return the miss count.
    pub const fn misses(&self) -> u32 {
        self.misses
    }

    /// Return the hit rate as a percentage (0..100).
    pub fn hit_rate(&self) -> u32 {
        let total = self.hits + self.misses;
        if total == 0 {
            return 0;
        }
        (self.hits as u64 * 100 / total as u64) as u32
    }

    /// Record a hit and grow the window.
    fn record_hit(&mut self, max_win: u32) {
        self.hits += 1;
        self.add_history(true);
        // Grow window additively.
        self.win = (self.win + WIN_GROW_STEP).min(max_win);
    }

    /// Record a miss and shrink the window.
    fn record_miss(&mut self, min_win: u32) {
        self.misses += 1;
        self.add_history(false);
        // Shrink window by halving.
        self.win = (self.win >> WIN_SHRINK_SHIFT).max(min_win);
    }

    /// Add an entry to the history ring.
    fn add_history(&mut self, hit: bool) {
        self.history[self.history_next] = hit;
        self.history_next = (self.history_next + 1) % HISTORY_DEPTH;
        if self.history_count < HISTORY_DEPTH {
            self.history_count += 1;
        }
    }

    /// Detect the access direction from sequential faults.
    fn update_direction(&mut self, new_offset: u64) {
        if new_offset > self.last_offset {
            self.direction = 1; // forward
        } else if new_offset < self.last_offset {
            self.direction = -1; // backward
        }
        self.last_offset = new_offset;
    }
}

// -------------------------------------------------------------------
// SwapReadaheadEntry
// -------------------------------------------------------------------

/// A prefetched swap entry in the readahead cache.
#[derive(Clone, Copy)]
pub struct SwapReadaheadEntry {
    /// Swap device ID.
    pub device_id: u8,
    /// Swap slot offset.
    pub slot_offset: u64,
    /// VMA that triggered the readahead.
    pub vma_id: u32,
    /// Whether this entry has been consumed (fault on it occurred).
    pub consumed: bool,
    /// Whether this entry is valid.
    pub valid: bool,
    /// Readahead generation (to detect stale entries).
    pub generation: u64,
}

impl SwapReadaheadEntry {
    /// Create an empty entry.
    const fn empty() -> Self {
        Self {
            device_id: 0,
            slot_offset: 0,
            vma_id: 0,
            consumed: false,
            valid: false,
            generation: 0,
        }
    }
}

// -------------------------------------------------------------------
// PerCpuRaState
// -------------------------------------------------------------------

/// Per-CPU readahead state.
#[derive(Clone, Copy)]
struct PerCpuRaState {
    /// Last readahead device.
    last_device: u8,
    /// Last readahead offset.
    last_offset: u64,
    /// Number of pending readahead pages.
    pending_pages: u32,
    /// Current generation.
    generation: u64,
}

impl PerCpuRaState {
    /// Create an empty state.
    const fn empty() -> Self {
        Self {
            last_device: 0,
            last_offset: 0,
            pending_pages: 0,
            generation: 0,
        }
    }
}

// -------------------------------------------------------------------
// SwapRaStats
// -------------------------------------------------------------------

/// Swap readahead statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct SwapRaStats {
    /// Total readahead operations initiated.
    pub total_readaheads: u64,
    /// Total pages prefetched.
    pub total_prefetched: u64,
    /// Total hits (prefetched page was used).
    pub total_hits: u64,
    /// Total misses (prefetched page was not used).
    pub total_misses: u64,
    /// Total pages freed from readahead cache.
    pub total_freed: u64,
    /// Current entries in the prefetch cache.
    pub cache_entries: u32,
    /// Cluster readahead invocations.
    pub cluster_count: u64,
    /// VMA readahead invocations.
    pub vma_count: u64,
}

// -------------------------------------------------------------------
// SwapReadaheadManager
// -------------------------------------------------------------------

/// Central swap readahead manager.
///
/// Coordinates readahead policy, per-VMA tracking, the prefetch
/// cache, and per-CPU state.
pub struct SwapReadaheadManager {
    /// Global configuration.
    config: SwapRaConfig,
    /// Per-VMA readahead tracking.
    vma_info: [SwapRaInfo; MAX_VMA_TRACKING],
    /// Prefetch entry cache.
    cache: [SwapReadaheadEntry; MAX_PREFETCH_ENTRIES],
    /// Number of valid cache entries.
    cache_count: usize,
    /// Per-CPU state.
    percpu: [PerCpuRaState; NR_CPUS],
    /// Global generation counter.
    generation: u64,
    /// Statistics.
    stats: SwapRaStats,
}

impl SwapReadaheadManager {
    /// Create a new readahead manager with default config.
    pub const fn new() -> Self {
        Self {
            config: SwapRaConfig::new(),
            vma_info: [const { SwapRaInfo::empty() }; MAX_VMA_TRACKING],
            cache: [const { SwapReadaheadEntry::empty() }; MAX_PREFETCH_ENTRIES],
            cache_count: 0,
            percpu: [const { PerCpuRaState::empty() }; NR_CPUS],
            generation: 1,
            stats: SwapRaStats {
                total_readaheads: 0,
                total_prefetched: 0,
                total_hits: 0,
                total_misses: 0,
                total_freed: 0,
                cache_entries: 0,
                cluster_count: 0,
                vma_count: 0,
            },
        }
    }

    /// Set the readahead configuration.
    pub fn set_config(&mut self, config: SwapRaConfig) {
        self.config = config;
    }

    /// Return the current configuration.
    pub const fn config(&self) -> &SwapRaConfig {
        &self.config
    }

    /// Register a VMA for readahead tracking.
    ///
    /// # Errors
    /// - `OutOfMemory` — no free VMA tracking slots.
    /// - `AlreadyExists` — VMA already tracked.
    pub fn register_vma(&mut self, vma_id: u32) -> Result<usize> {
        // Check duplicate.
        if self.find_vma(vma_id).is_ok() {
            return Err(Error::AlreadyExists);
        }
        for i in 0..MAX_VMA_TRACKING {
            if !self.vma_info[i].active {
                self.vma_info[i] = SwapRaInfo::empty();
                self.vma_info[i].vma_id = vma_id;
                self.vma_info[i].win = self.config.default_win;
                self.vma_info[i].active = true;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister a VMA.
    ///
    /// # Errors
    /// - `NotFound` — VMA not tracked.
    pub fn unregister_vma(&mut self, vma_id: u32) -> Result<()> {
        let idx = self.find_vma(vma_id)?;
        self.vma_info[idx] = SwapRaInfo::empty();
        Ok(())
    }

    /// Find VMA tracking index.
    fn find_vma(&self, vma_id: u32) -> Result<usize> {
        for i in 0..MAX_VMA_TRACKING {
            if self.vma_info[i].active && self.vma_info[i].vma_id == vma_id {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Main entry point: initiate swap readahead.
    ///
    /// Called on a page fault for a swap entry. Returns the number
    /// of pages queued for prefetch.
    ///
    /// # Arguments
    /// - `device_id` — swap device.
    /// - `slot_offset` — the faulting swap slot.
    /// - `vma_id` — VMA containing the fault.
    /// - `cpu` — CPU performing the fault.
    ///
    /// # Errors
    /// - `NotFound` — VMA not tracked (auto-registers).
    pub fn swapin_readahead(
        &mut self,
        device_id: u8,
        slot_offset: u64,
        vma_id: u32,
        cpu: usize,
    ) -> Result<usize> {
        if self.config.policy == SwapRaPolicy::Disabled {
            return Ok(0);
        }

        // Auto-register VMA if needed.
        let vma_idx = match self.find_vma(vma_id) {
            Ok(idx) => idx,
            Err(_) => self.register_vma(vma_id)?,
        };

        // Check if this fault was a readahead hit.
        self.check_hit(device_id, slot_offset, vma_id);

        // Update access direction.
        self.vma_info[vma_idx].update_direction(slot_offset);

        // Update per-CPU state.
        let cpu_idx = cpu % NR_CPUS;
        self.percpu[cpu_idx].last_device = device_id;
        self.percpu[cpu_idx].last_offset = slot_offset;
        self.percpu[cpu_idx].generation = self.generation;

        let win = self.vma_info[vma_idx].win as usize;
        let max_pages = win.min(self.config.max_pages);

        let prefetched = match self.config.policy {
            SwapRaPolicy::Cluster => {
                self.stats.cluster_count += 1;
                self.cluster_readahead(device_id, slot_offset, vma_id, max_pages)
            }
            SwapRaPolicy::Vma => {
                self.stats.vma_count += 1;
                let dir = self.vma_info[vma_idx].direction;
                self.vma_readahead(device_id, slot_offset, vma_id, dir, max_pages)
            }
            SwapRaPolicy::Disabled => 0,
        };

        self.generation += 1;
        self.stats.total_readaheads += 1;
        self.stats.total_prefetched += prefetched as u64;
        self.percpu[cpu_idx].pending_pages += prefetched as u32;

        Ok(prefetched)
    }

    /// Cluster-based readahead: read slots adjacent to the fault.
    fn cluster_readahead(
        &mut self,
        device_id: u8,
        slot_offset: u64,
        vma_id: u32,
        max_pages: usize,
    ) -> usize {
        let mut count = 0;
        let half = max_pages / 2;

        // Read slots before the fault.
        let start = slot_offset.saturating_sub(half as u64);
        for off in start..slot_offset {
            if count >= max_pages {
                break;
            }
            if self.add_prefetch(device_id, off, vma_id) {
                count += 1;
            }
        }

        // Read slots after the fault (excluding the fault itself).
        for off in (slot_offset + 1)..=(slot_offset + max_pages as u64) {
            if count >= max_pages {
                break;
            }
            if self.add_prefetch(device_id, off, vma_id) {
                count += 1;
            }
        }

        count
    }

    /// VMA-based readahead: follow the fault direction.
    fn vma_readahead(
        &mut self,
        device_id: u8,
        slot_offset: u64,
        vma_id: u32,
        direction: i64,
        max_pages: usize,
    ) -> usize {
        let mut count = 0;
        let mut off = slot_offset;

        for _ in 0..max_pages {
            if direction >= 0 {
                off = off.saturating_add(1);
            } else {
                if off == 0 {
                    break;
                }
                off -= 1;
            }
            if self.add_prefetch(device_id, off, vma_id) {
                count += 1;
            }
        }

        count
    }

    /// Add a prefetch entry to the cache.
    ///
    /// Returns `true` if added, `false` if cache full or duplicate.
    fn add_prefetch(&mut self, device_id: u8, slot_offset: u64, vma_id: u32) -> bool {
        // Check for duplicate.
        for i in 0..self.cache_count {
            if self.cache[i].valid
                && self.cache[i].device_id == device_id
                && self.cache[i].slot_offset == slot_offset
            {
                return false;
            }
        }

        if self.cache_count >= MAX_PREFETCH_ENTRIES {
            // Evict oldest non-consumed entry.
            if !self.evict_one() {
                return false;
            }
        }

        // Find a free slot.
        for i in 0..MAX_PREFETCH_ENTRIES {
            if !self.cache[i].valid {
                self.cache[i] = SwapReadaheadEntry {
                    device_id,
                    slot_offset,
                    vma_id,
                    consumed: false,
                    valid: true,
                    generation: self.generation,
                };
                self.cache_count += 1;
                self.stats.cache_entries = self.cache_count as u32;
                return true;
            }
        }
        false
    }

    /// Evict one stale/consumed entry from the cache.
    fn evict_one(&mut self) -> bool {
        // First try consumed entries.
        for i in 0..MAX_PREFETCH_ENTRIES {
            if self.cache[i].valid && self.cache[i].consumed {
                self.cache[i] = SwapReadaheadEntry::empty();
                self.cache_count = self.cache_count.saturating_sub(1);
                self.stats.total_freed += 1;
                self.stats.cache_entries = self.cache_count as u32;
                return true;
            }
        }
        // Then oldest by generation.
        let mut oldest_idx = None;
        let mut oldest_gen = u64::MAX;
        for i in 0..MAX_PREFETCH_ENTRIES {
            if self.cache[i].valid && self.cache[i].generation < oldest_gen {
                oldest_gen = self.cache[i].generation;
                oldest_idx = Some(i);
            }
        }
        if let Some(idx) = oldest_idx {
            self.cache[idx] = SwapReadaheadEntry::empty();
            self.cache_count = self.cache_count.saturating_sub(1);
            self.stats.total_freed += 1;
            self.stats.total_misses += 1;
            self.stats.cache_entries = self.cache_count as u32;
            return true;
        }
        false
    }

    /// Check if a page fault is a readahead hit.
    fn check_hit(&mut self, device_id: u8, slot_offset: u64, vma_id: u32) {
        for i in 0..MAX_PREFETCH_ENTRIES {
            if self.cache[i].valid
                && !self.cache[i].consumed
                && self.cache[i].device_id == device_id
                && self.cache[i].slot_offset == slot_offset
            {
                self.cache[i].consumed = true;
                self.stats.total_hits += 1;

                // Record hit on VMA tracker.
                if let Ok(vma_idx) = self.find_vma(vma_id) {
                    let max_win = self.config.max_win;
                    self.vma_info[vma_idx].record_hit(max_win);
                }
                return;
            }
        }

        // Not a hit — this is a cold miss, record it.
        if let Ok(vma_idx) = self.find_vma(vma_id) {
            let min_win = self.config.min_win;
            self.vma_info[vma_idx].record_miss(min_win);
        }
    }

    /// Free all readahead entries for a given swap slot.
    ///
    /// Called when a swap slot is freed, so that stale prefetch
    /// entries are removed.
    pub fn free_readahead_for_slot(&mut self, device_id: u8, slot_offset: u64) {
        for i in 0..MAX_PREFETCH_ENTRIES {
            if self.cache[i].valid
                && self.cache[i].device_id == device_id
                && self.cache[i].slot_offset == slot_offset
            {
                self.cache[i] = SwapReadaheadEntry::empty();
                self.cache_count = self.cache_count.saturating_sub(1);
                self.stats.total_freed += 1;
                self.stats.cache_entries = self.cache_count as u32;
            }
        }
    }

    /// Get the readahead info for a VMA.
    ///
    /// # Errors
    /// - `NotFound` — VMA not tracked.
    pub fn get_vma_info(&self, vma_id: u32) -> Result<&SwapRaInfo> {
        let idx = self.find_vma(vma_id)?;
        Ok(&self.vma_info[idx])
    }

    /// Return current statistics.
    pub const fn stats(&self) -> &SwapRaStats {
        &self.stats
    }

    /// Return the number of cached prefetch entries.
    pub const fn cache_count(&self) -> usize {
        self.cache_count
    }
}
