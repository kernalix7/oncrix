// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Working set detection and refault distance measurement.
//!
//! Detects memory thrashing by tracking evicted pages as "shadow
//! entries" in the page cache radix tree. When an evicted page is
//! faulted back in (refault), the refault distance — the number of
//! evictions between the original eviction and the refault — is
//! compared against the active list size to decide whether the page
//! should be activated immediately.
//!
//! # Key concepts
//!
//! - **Shadow entry**: metadata stored in the slot of an evicted page
//!   recording the eviction tick and zone/node information.
//! - **Refault distance**: `current_tick - eviction_tick`. If this is
//!   less than the active list size, the page was part of the working
//!   set and is immediately activated.
//! - **Adaptive threshold**: the refault distance threshold tracks the
//!   active list size so the working set estimate adapts to load.
//!
//! # Subsystems
//!
//! - [`ShadowEntry`] — eviction metadata for a single page
//! - [`ShadowNodePool`] — pool of shadow entries
//! - [`WorkingSetState`] — per-zone working-set counters
//! - [`WorkingSetSubsystem`] — main subsystem coordinating detection
//! - [`WorkingSetStats`] — aggregate statistics
//!
//! Reference: Linux `mm/workingset.c`, `include/linux/swap.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of shadow entries.
const MAX_SHADOW_ENTRIES: usize = 1024;

/// Maximum number of memory zones.
const MAX_ZONES: usize = 4;

/// Invalid shadow entry index sentinel.
const INVALID_SHADOW: u32 = u32::MAX;

/// Default refault distance threshold (in eviction ticks).
const DEFAULT_THRESHOLD: u64 = 256;

/// Minimum threshold to prevent over-activation.
const MIN_THRESHOLD: u64 = 16;

// -------------------------------------------------------------------
// ShadowEntry
// -------------------------------------------------------------------

/// Shadow entry stored in an evicted page's radix-tree slot.
///
/// Records enough information to compute the refault distance and
/// decide whether the page should be activated on re-fault.
#[derive(Debug, Clone, Copy)]
pub struct ShadowEntry {
    /// Global eviction tick at the time this page was evicted.
    eviction_tick: u64,
    /// Memory zone the page belonged to.
    zone_id: u8,
    /// NUMA node the page belonged to.
    node_id: u8,
    /// Whether the page was on the active list when evicted.
    was_active: bool,
    /// Virtual address (or page-cache index) for identification.
    key: u64,
    /// Whether this slot is occupied.
    active: bool,
}

impl ShadowEntry {
    /// Create an empty (unused) shadow entry.
    const fn empty() -> Self {
        Self {
            eviction_tick: 0,
            zone_id: 0,
            node_id: 0,
            was_active: false,
            key: 0,
            active: false,
        }
    }

    /// Eviction tick.
    pub const fn eviction_tick(&self) -> u64 {
        self.eviction_tick
    }

    /// Memory zone ID.
    pub const fn zone_id(&self) -> u8 {
        self.zone_id
    }

    /// NUMA node ID.
    pub const fn node_id(&self) -> u8 {
        self.node_id
    }

    /// Whether the page was active at eviction time.
    pub const fn was_active(&self) -> bool {
        self.was_active
    }

    /// Key (virtual address or page-cache index).
    pub const fn key(&self) -> u64 {
        self.key
    }

    /// Whether this entry is occupied.
    pub const fn is_active(&self) -> bool {
        self.active
    }
}

impl Default for ShadowEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// ShadowNodePool
// -------------------------------------------------------------------

/// Pool of shadow entries for evicted pages.
///
/// Stores up to [`MAX_SHADOW_ENTRIES`] entries. Entries are reused in
/// FIFO order when the pool is full.
pub struct ShadowNodePool {
    /// Shadow entry storage.
    entries: [ShadowEntry; MAX_SHADOW_ENTRIES],
    /// Number of active entries.
    count: u32,
    /// Next index to overwrite when full (circular).
    next_overwrite: u32,
}

impl ShadowNodePool {
    /// Create an empty pool.
    const fn new() -> Self {
        Self {
            entries: [const { ShadowEntry::empty() }; MAX_SHADOW_ENTRIES],
            count: 0,
            next_overwrite: 0,
        }
    }

    /// Number of active entries.
    pub const fn count(&self) -> u32 {
        self.count
    }

    /// Insert a new shadow entry, returning its index.
    ///
    /// If the pool is full, the oldest entry is overwritten.
    fn insert(&mut self, entry: ShadowEntry) -> u32 {
        // Try to find a free slot first.
        let idx = self.find_free_slot();
        let slot = match idx {
            Some(i) => {
                self.count += 1;
                i
            }
            None => {
                // Overwrite the oldest entry (FIFO).
                let i = self.next_overwrite as usize;
                self.next_overwrite =
                    ((self.next_overwrite + 1) as usize % MAX_SHADOW_ENTRIES) as u32;
                i
            }
        };
        self.entries[slot] = entry;
        slot as u32
    }

    /// Look up a shadow entry by key.
    ///
    /// Returns the entry and its index if found.
    fn lookup(&self, key: u64) -> Option<(usize, &ShadowEntry)> {
        self.entries
            .iter()
            .enumerate()
            .find(|(_, e)| e.active && e.key == key)
    }

    /// Remove a shadow entry by index.
    fn remove(&mut self, idx: usize) {
        if idx < MAX_SHADOW_ENTRIES && self.entries[idx].active {
            self.entries[idx].active = false;
            self.count = self.count.saturating_sub(1);
        }
    }

    /// Find a free slot in the pool.
    fn find_free_slot(&self) -> Option<usize> {
        self.entries.iter().position(|e| !e.active)
    }
}

impl Default for ShadowNodePool {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// WorkingSetState
// -------------------------------------------------------------------

/// Per-zone working-set state counters.
#[derive(Debug, Clone, Copy)]
pub struct WorkingSetState {
    /// Current refault distance threshold.
    /// Pages with refault distance below this are activated.
    refault_distance_threshold: u64,
    /// Number of pages on the active list.
    nr_active: u64,
    /// Number of pages on the inactive list.
    nr_inactive: u64,
    /// Total number of evictions in this zone.
    nr_evictions: u64,
}

impl WorkingSetState {
    /// Create a new state with default values.
    const fn new() -> Self {
        Self {
            refault_distance_threshold: DEFAULT_THRESHOLD,
            nr_active: 0,
            nr_inactive: 0,
            nr_evictions: 0,
        }
    }

    /// Refault distance threshold.
    pub const fn threshold(&self) -> u64 {
        self.refault_distance_threshold
    }

    /// Number of active pages.
    pub const fn nr_active(&self) -> u64 {
        self.nr_active
    }

    /// Number of inactive pages.
    pub const fn nr_inactive(&self) -> u64 {
        self.nr_inactive
    }

    /// Number of evictions.
    pub const fn nr_evictions(&self) -> u64 {
        self.nr_evictions
    }

    /// Update the threshold to track the active list size.
    fn update_threshold(&mut self) {
        // The threshold is the active list size, clamped to a minimum.
        let new_thresh = if self.nr_active > MIN_THRESHOLD {
            self.nr_active
        } else {
            MIN_THRESHOLD
        };
        self.refault_distance_threshold = new_thresh;
    }
}

impl Default for WorkingSetState {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// WorkingSetStats
// -------------------------------------------------------------------

/// Aggregate working-set detection statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct WorkingSetStats {
    /// Total refault events (page re-faulted after eviction).
    pub total_refaults: u64,
    /// Total activations (refault distance < threshold).
    pub total_activations: u64,
    /// Total thrashing detections (repeated quick evict-refault).
    pub thrashing_count: u64,
    /// Total shadow entries created.
    pub total_shadows_created: u64,
    /// Total shadow entries consumed (looked up on refault).
    pub total_shadows_consumed: u64,
}

// -------------------------------------------------------------------
// RefaultDecision
// -------------------------------------------------------------------

/// Result of evaluating a refault event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefaultDecision {
    /// Page should be immediately activated (working-set member).
    Activate,
    /// Page goes to inactive list (not working-set).
    Inactive,
}

// -------------------------------------------------------------------
// WorkingSetSubsystem
// -------------------------------------------------------------------

/// Main working-set detection subsystem.
///
/// Coordinates shadow entry management, refault distance computation,
/// and adaptive threshold updates across all zones.
pub struct WorkingSetSubsystem {
    /// Per-zone state.
    zones: [WorkingSetState; MAX_ZONES],
    /// Shadow entry pool.
    shadow_pool: ShadowNodePool,
    /// Global monotonic eviction counter (tick).
    global_tick: u64,
    /// Statistics.
    stats: WorkingSetStats,
}

impl WorkingSetSubsystem {
    /// Create a new working-set subsystem.
    pub const fn new() -> Self {
        Self {
            zones: [const { WorkingSetState::new() }; MAX_ZONES],
            shadow_pool: ShadowNodePool::new(),
            global_tick: 0,
            stats: WorkingSetStats {
                total_refaults: 0,
                total_activations: 0,
                thrashing_count: 0,
                total_shadows_created: 0,
                total_shadows_consumed: 0,
            },
        }
    }

    /// Return current statistics.
    pub const fn stats(&self) -> &WorkingSetStats {
        &self.stats
    }

    /// Get per-zone state.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — zone_id out of range
    pub fn zone_state(&self, zone_id: u8) -> Result<&WorkingSetState> {
        if zone_id as usize >= MAX_ZONES {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.zones[zone_id as usize])
    }

    /// Record a page eviction.
    ///
    /// Creates a shadow entry for the evicted page so that a future
    /// refault can measure the refault distance.
    ///
    /// # Arguments
    ///
    /// * `key` — page identifier (vaddr or page-cache index)
    /// * `zone_id` — memory zone the page belongs to
    /// * `node_id` — NUMA node
    /// * `was_active` — whether the page was on the active list
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — zone_id out of range
    pub fn workingset_eviction(
        &mut self,
        key: u64,
        zone_id: u8,
        node_id: u8,
        was_active: bool,
    ) -> Result<u32> {
        if zone_id as usize >= MAX_ZONES {
            return Err(Error::InvalidArgument);
        }

        // Increment global eviction tick.
        self.global_tick += 1;
        let tick = self.global_tick;

        // Update zone counters.
        self.zones[zone_id as usize].nr_evictions += 1;
        if was_active {
            self.zones[zone_id as usize].nr_active =
                self.zones[zone_id as usize].nr_active.saturating_sub(1);
        } else {
            self.zones[zone_id as usize].nr_inactive =
                self.zones[zone_id as usize].nr_inactive.saturating_sub(1);
        }

        // Create shadow entry.
        let shadow = ShadowEntry {
            eviction_tick: tick,
            zone_id,
            node_id,
            was_active,
            key,
            active: true,
        };

        let idx = self.shadow_pool.insert(shadow);
        self.stats.total_shadows_created += 1;

        // Update adaptive threshold.
        self.zones[zone_id as usize].update_threshold();

        Ok(idx)
    }

    /// Evaluate a refault event.
    ///
    /// Looks up the shadow entry for the re-faulted page and computes
    /// the refault distance. If the distance is below the zone
    /// threshold, returns [`RefaultDecision::Activate`].
    ///
    /// # Arguments
    ///
    /// * `key` — page identifier matching the eviction call
    ///
    /// # Returns
    ///
    /// The refault decision and the zone_id of the original eviction.
    ///
    /// # Errors
    ///
    /// * `NotFound` — no shadow entry for this key
    pub fn workingset_refault(&mut self, key: u64) -> Result<(RefaultDecision, u8)> {
        // Look up the shadow entry.
        let (shadow_idx, eviction_tick, zone_id, was_active) = {
            let (idx, entry) = self.shadow_pool.lookup(key).ok_or(Error::NotFound)?;
            (idx, entry.eviction_tick, entry.zone_id, entry.was_active)
        };

        // Remove the shadow entry (consumed).
        self.shadow_pool.remove(shadow_idx);
        self.stats.total_shadows_consumed += 1;
        self.stats.total_refaults += 1;

        // Compute refault distance.
        let refault_distance = self.global_tick.saturating_sub(eviction_tick);
        let zone = zone_id as usize;
        let threshold = if zone < MAX_ZONES {
            self.zones[zone].refault_distance_threshold
        } else {
            DEFAULT_THRESHOLD
        };

        // Decide whether to activate.
        let decision = if refault_distance <= threshold {
            self.stats.total_activations += 1;

            // If the page was already active before eviction and
            // is being refaulted quickly, count as thrashing.
            if was_active {
                self.stats.thrashing_count += 1;
            }

            RefaultDecision::Activate
        } else {
            RefaultDecision::Inactive
        };

        Ok((decision, zone_id))
    }

    /// Notify that a page has been activated (moved to active list).
    ///
    /// Updates the per-zone active/inactive counters.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — zone_id out of range
    pub fn workingset_activation(&mut self, zone_id: u8) -> Result<()> {
        if zone_id as usize >= MAX_ZONES {
            return Err(Error::InvalidArgument);
        }
        let z = &mut self.zones[zone_id as usize];
        z.nr_active += 1;
        z.update_threshold();
        Ok(())
    }

    /// Notify that a page has been deactivated (moved to inactive).
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — zone_id out of range
    pub fn workingset_deactivation(&mut self, zone_id: u8) -> Result<()> {
        if zone_id as usize >= MAX_ZONES {
            return Err(Error::InvalidArgument);
        }
        let z = &mut self.zones[zone_id as usize];
        z.nr_active = z.nr_active.saturating_sub(1);
        z.nr_inactive += 1;
        z.update_threshold();
        Ok(())
    }

    /// Notify that a page has been added to the inactive list (new).
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — zone_id out of range
    pub fn workingset_page_added(&mut self, zone_id: u8) -> Result<()> {
        if zone_id as usize >= MAX_ZONES {
            return Err(Error::InvalidArgument);
        }
        self.zones[zone_id as usize].nr_inactive += 1;
        Ok(())
    }

    /// Current global eviction tick.
    pub const fn global_tick(&self) -> u64 {
        self.global_tick
    }

    /// Number of shadow entries currently stored.
    pub fn shadow_count(&self) -> u32 {
        self.shadow_pool.count()
    }

    /// Set the refault distance threshold for a zone manually.
    ///
    /// This overrides the adaptive computation until the next
    /// automatic update.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — zone_id out of range or threshold is zero
    pub fn set_threshold(&mut self, zone_id: u8, threshold: u64) -> Result<()> {
        if zone_id as usize >= MAX_ZONES {
            return Err(Error::InvalidArgument);
        }
        if threshold == 0 {
            return Err(Error::InvalidArgument);
        }
        self.zones[zone_id as usize].refault_distance_threshold = threshold;
        Ok(())
    }

    /// Check whether a zone is experiencing thrashing.
    ///
    /// A zone is considered thrashing if refaults exceed 50% of
    /// evictions in that zone.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — zone_id out of range
    pub fn is_thrashing(&self, zone_id: u8) -> Result<bool> {
        if zone_id as usize >= MAX_ZONES {
            return Err(Error::InvalidArgument);
        }
        let evictions = self.zones[zone_id as usize].nr_evictions;
        if evictions == 0 {
            return Ok(false);
        }
        // Use total refaults as a proxy (per-zone tracking could be
        // added for higher fidelity).
        Ok(self.stats.total_refaults > evictions / 2)
    }
}

impl Default for WorkingSetSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Free-standing helpers
// -------------------------------------------------------------------

/// Compute the refault distance between an eviction tick and the
/// current tick.
pub const fn refault_distance(eviction_tick: u64, current_tick: u64) -> u64 {
    current_tick.saturating_sub(eviction_tick)
}

/// Determine whether a refault distance indicates working-set
/// membership.
pub const fn is_working_set(distance: u64, threshold: u64) -> bool {
    distance <= threshold
}
