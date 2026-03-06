// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Generic shrinker framework for kernel memory reclaim.
//!
//! When memory pressure rises the kernel asks registered shrinkers to
//! release reclaimable objects.  Unlike the slab-specific shrinkers in
//! [`super::slab_reclaim`] and the scan-level mechanics in
//! [`super::slab_shrink_scan`], this module provides the **generic
//! shrinker infrastructure**: registration lifecycle, NUMA-aware
//! invocation, memcg-scoped shrinking, deferred-work accounting,
//! and superblock shrinker support.
//!
//! # Architecture
//!
//! ```text
//!  Memory pressure event
//!       │
//!       ▼
//!  ShrinkerRegistry::shrink_all(sc)
//!       │
//!       ├─ for each registered shrinker (ordered by priority):
//!       │    ├─ count_objects(sc)  → nr_freeable
//!       │    ├─ compute scan ratio (nr_to_scan / total_scan)
//!       │    ├─ scan_objects(sc)   → nr_freed
//!       │    ├─ account nr_deferred for incomplete scans
//!       │    └─ update statistics
//!       │
//!       └─ return ShrinkerResult { total_freed, ... }
//! ```
//!
//! # Key types
//!
//! - [`ShrinkerFlags`] — bitfield controlling shrinker behaviour
//! - [`ShrinkControl`] — parameters passed to each invocation
//! - [`ShrinkerInfo`] — descriptor for a registered shrinker
//! - [`ShrinkerResult`] — outcome of a shrink pass
//! - [`ShrinkerStats`] — aggregate statistics
//! - [`ShrinkerRegistry`] — global registry and dispatch engine
//!
//! Reference: Linux `mm/shrinker.c`, `include/linux/shrinker.h`,
//! `mm/vmscan.c` (`do_shrink_slab`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of registered shrinkers system-wide.
const MAX_SHRINKERS: usize = 256;

/// Maximum NUMA nodes for per-node invocation.
const MAX_NUMA_NODES: usize = 8;

/// Default seek cost (higher means costlier to scan, so scan less).
const DEFAULT_SEEKS: u32 = 2;

/// Minimum scan batch size.
const MIN_SCAN_BATCH: u64 = 16;

/// Maximum deferred work before forced drain.
const MAX_DEFERRED: u64 = 65536;

/// Invalid shrinker ID sentinel.
const INVALID_ID: u32 = u32::MAX;

/// Flag: shrinker is NUMA-aware (reports per-node counts).
const FLAG_NUMA_AWARE: u32 = 1 << 0;

/// Flag: shrinker is memcg-aware (honours cgroup scope).
const FLAG_MEMCG_AWARE: u32 = 1 << 1;

/// Flag: shrinker should not be called during direct reclaim.
const FLAG_NO_DIRECT_RECLAIM: u32 = 1 << 2;

/// Flag: shrinker is for a filesystem superblock.
const FLAG_SUPERBLOCK: u32 = 1 << 3;

// -------------------------------------------------------------------
// ShrinkerFlags
// -------------------------------------------------------------------

/// Bitfield flags controlling shrinker behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ShrinkerFlags(u32);

impl ShrinkerFlags {
    /// Empty flags.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Create flags from a raw u32.
    pub const fn from_raw(bits: u32) -> Self {
        Self(bits)
    }

    /// Return the raw bits.
    pub const fn bits(&self) -> u32 {
        self.0
    }

    /// Whether this shrinker is NUMA-aware.
    pub const fn is_numa_aware(&self) -> bool {
        self.0 & FLAG_NUMA_AWARE != 0
    }

    /// Whether this shrinker is memcg-aware.
    pub const fn is_memcg_aware(&self) -> bool {
        self.0 & FLAG_MEMCG_AWARE != 0
    }

    /// Whether direct-reclaim invocation is suppressed.
    pub const fn no_direct_reclaim(&self) -> bool {
        self.0 & FLAG_NO_DIRECT_RECLAIM != 0
    }

    /// Whether this shrinker belongs to a filesystem superblock.
    pub const fn is_superblock(&self) -> bool {
        self.0 & FLAG_SUPERBLOCK != 0
    }

    /// Set NUMA-aware flag.
    pub const fn with_numa_aware(self) -> Self {
        Self(self.0 | FLAG_NUMA_AWARE)
    }

    /// Set memcg-aware flag.
    pub const fn with_memcg_aware(self) -> Self {
        Self(self.0 | FLAG_MEMCG_AWARE)
    }

    /// Set no-direct-reclaim flag.
    pub const fn with_no_direct_reclaim(self) -> Self {
        Self(self.0 | FLAG_NO_DIRECT_RECLAIM)
    }

    /// Set superblock flag.
    pub const fn with_superblock(self) -> Self {
        Self(self.0 | FLAG_SUPERBLOCK)
    }
}

// -------------------------------------------------------------------
// GfpMask (simplified)
// -------------------------------------------------------------------

/// Simplified GFP (Get Free Pages) allocation mask.
///
/// Determines which memory zones and reclaim strategies are allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GfpMask(u32);

impl GfpMask {
    /// Kernel allocation (may sleep, may reclaim).
    pub const GFP_KERNEL: Self = Self(0x01);

    /// Atomic allocation (no sleep, no reclaim).
    pub const GFP_ATOMIC: Self = Self(0x02);

    /// User allocation (may sleep, OOM-killable).
    pub const GFP_USER: Self = Self(0x04);

    /// High-memory allocation.
    pub const GFP_HIGHMEM: Self = Self(0x08);

    /// Direct reclaim is allowed.
    pub const fn allows_direct_reclaim(&self) -> bool {
        self.0 & 0x02 == 0 // not atomic
    }

    /// Whether the caller may sleep.
    pub const fn may_sleep(&self) -> bool {
        self.0 & 0x02 == 0
    }

    /// Return the raw bits.
    pub const fn bits(&self) -> u32 {
        self.0
    }
}

// -------------------------------------------------------------------
// ShrinkControl
// -------------------------------------------------------------------

/// Parameters passed to a shrinker on each invocation.
///
/// Modeled after Linux `struct shrink_control`.
#[derive(Debug, Clone, Copy)]
pub struct ShrinkControl {
    /// Allocation context (determines reclaim aggressiveness).
    pub gfp_mask: GfpMask,
    /// Number of objects the shrinker should attempt to free.
    pub nr_to_scan: u64,
    /// Number of objects that were reported as freeable.
    pub nr_scanned: u64,
    /// NUMA node hint (-1 for all nodes).
    pub nid: i32,
    /// Memory cgroup ID (0 for root / no cgroup).
    pub memcg_id: u32,
}

impl ShrinkControl {
    /// Create a new shrink control with the given scan target.
    pub const fn new(nr_to_scan: u64, gfp_mask: GfpMask) -> Self {
        Self {
            gfp_mask,
            nr_to_scan,
            nr_scanned: 0,
            nid: -1,
            memcg_id: 0,
        }
    }

    /// Set the NUMA node hint.
    pub const fn with_node(mut self, nid: i32) -> Self {
        self.nid = nid;
        self
    }

    /// Set the memcg scope.
    pub const fn with_memcg(mut self, memcg_id: u32) -> Self {
        self.memcg_id = memcg_id;
        self
    }
}

// -------------------------------------------------------------------
// ReclamPriority
// -------------------------------------------------------------------

/// Reclaim priority passed to the shrinker dispatch loop.
///
/// Lower numeric value means higher urgency (more aggressive).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum ReclaimPriority {
    /// Background kswapd reclaim.
    #[default]
    Background = 0,
    /// Moderate memory pressure.
    Moderate = 1,
    /// High pressure — direct reclaim path.
    High = 2,
    /// Critical — last resort before OOM.
    Critical = 3,
}

impl ReclaimPriority {
    /// Multiplier applied to scan batch sizes at this priority.
    pub const fn scan_multiplier(&self) -> u64 {
        match self {
            Self::Background => 1,
            Self::Moderate => 2,
            Self::High => 4,
            Self::Critical => 8,
        }
    }
}

// -------------------------------------------------------------------
// ShrinkerInfo
// -------------------------------------------------------------------

/// Descriptor for a registered shrinker.
#[derive(Debug, Clone, Copy)]
pub struct ShrinkerInfo {
    /// Unique shrinker ID (assigned at registration).
    id: u32,
    /// Human-readable name token (index into a name table).
    name_token: u32,
    /// Shrinker flags.
    flags: ShrinkerFlags,
    /// Seek cost — higher means costlier objects to recreate.
    seeks: u32,
    /// Number of objects currently reclaimable (last count).
    nr_freeable: u64,
    /// Deferred work from previous incomplete scans.
    nr_deferred: u64,
    /// Per-NUMA-node freeable counts (valid if NUMA-aware).
    per_node_freeable: [u64; MAX_NUMA_NODES],
    /// Total objects freed lifetime.
    lifetime_freed: u64,
    /// Total scan invocations.
    scan_count: u64,
    /// Total count invocations.
    count_count: u64,
    /// Whether this slot is occupied.
    active: bool,
    /// Batch size for scanning.
    batch_size: u64,
}

impl ShrinkerInfo {
    /// Create a new shrinker descriptor.
    pub const fn new(id: u32, flags: ShrinkerFlags, seeks: u32) -> Self {
        Self {
            id,
            name_token: 0,
            flags,
            seeks,
            nr_freeable: 0,
            nr_deferred: 0,
            per_node_freeable: [0; MAX_NUMA_NODES],
            lifetime_freed: 0,
            scan_count: 0,
            count_count: 0,
            active: true,
            batch_size: MIN_SCAN_BATCH,
        }
    }

    /// Return the shrinker ID.
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Return the name token.
    pub const fn name_token(&self) -> u32 {
        self.name_token
    }

    /// Return the flags.
    pub const fn flags(&self) -> ShrinkerFlags {
        self.flags
    }

    /// Return the seek cost.
    pub const fn seeks(&self) -> u32 {
        self.seeks
    }

    /// Return the last reported freeable count.
    pub const fn nr_freeable(&self) -> u64 {
        self.nr_freeable
    }

    /// Return the deferred work count.
    pub const fn nr_deferred(&self) -> u64 {
        self.nr_deferred
    }

    /// Return lifetime freed count.
    pub const fn lifetime_freed(&self) -> u64 {
        self.lifetime_freed
    }

    /// Return total scan invocations.
    pub const fn scan_count(&self) -> u64 {
        self.scan_count
    }

    /// Return total count invocations.
    pub const fn count_count(&self) -> u64 {
        self.count_count
    }

    /// Whether this shrinker is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Return the per-node freeable count for a node.
    pub fn node_freeable(&self, nid: usize) -> u64 {
        if nid < MAX_NUMA_NODES {
            self.per_node_freeable[nid]
        } else {
            0
        }
    }

    /// Set the name token.
    pub fn set_name_token(&mut self, token: u32) {
        self.name_token = token;
    }

    /// Set the batch size.
    pub fn set_batch_size(&mut self, batch: u64) {
        self.batch_size = batch.max(MIN_SCAN_BATCH);
    }

    /// Deactivate this shrinker (unregister).
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Add deferred work.
    pub fn add_deferred(&mut self, amount: u64) {
        self.nr_deferred = self.nr_deferred.saturating_add(amount);
        if self.nr_deferred > MAX_DEFERRED {
            self.nr_deferred = MAX_DEFERRED;
        }
    }

    /// Drain (consume) deferred work, returning the amount drained.
    pub fn drain_deferred(&mut self) -> u64 {
        let d = self.nr_deferred;
        self.nr_deferred = 0;
        d
    }

    /// Simulate a count_objects callback. Updates `nr_freeable`.
    ///
    /// In a real kernel this would invoke the shrinker's registered
    /// callback. Here we model it as a setter for the count.
    pub fn do_count(&mut self, freeable: u64) {
        self.nr_freeable = freeable;
        self.count_count += 1;
    }

    /// Simulate a count_objects callback with per-node data.
    pub fn do_count_node(&mut self, nid: usize, freeable: u64) {
        if nid < MAX_NUMA_NODES {
            self.per_node_freeable[nid] = freeable;
        }
        // Sum nodes for total.
        let mut total = 0u64;
        for n in &self.per_node_freeable {
            total = total.saturating_add(*n);
        }
        self.nr_freeable = total;
        self.count_count += 1;
    }

    /// Simulate a scan_objects callback. Returns number freed.
    ///
    /// `nr_to_scan` is how many objects the reclaim path wants freed.
    pub fn do_scan(&mut self, nr_to_scan: u64) -> u64 {
        self.scan_count += 1;

        if self.nr_freeable == 0 {
            return 0;
        }

        let effective = nr_to_scan.min(self.nr_freeable);
        self.nr_freeable -= effective;
        self.lifetime_freed += effective;
        effective
    }
}

// -------------------------------------------------------------------
// ShrinkerResult
// -------------------------------------------------------------------

/// Outcome of a global shrink pass across all shrinkers.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShrinkerResult {
    /// Total objects freed across all shrinkers.
    pub total_freed: u64,
    /// Number of shrinkers invoked.
    pub shrinkers_invoked: u32,
    /// Number of shrinkers that freed at least one object.
    pub shrinkers_active: u32,
    /// Total deferred work remaining.
    pub total_deferred: u64,
    /// Whether any shrinker was skipped (e.g., no-direct-reclaim).
    pub any_skipped: bool,
}

// -------------------------------------------------------------------
// ShrinkerStats
// -------------------------------------------------------------------

/// Aggregate statistics for the shrinker subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShrinkerStats {
    /// Total shrinkers registered (lifetime).
    pub total_registered: u64,
    /// Currently active shrinkers.
    pub active_count: u32,
    /// Total shrink passes executed.
    pub total_passes: u64,
    /// Total objects freed (lifetime).
    pub total_freed: u64,
    /// Total deferred work accumulated (lifetime).
    pub total_deferred_lifetime: u64,
    /// Count passes (count_objects invocations).
    pub total_counts: u64,
    /// Scan passes (scan_objects invocations).
    pub total_scans: u64,
    /// Number of shrinker registrations that failed.
    pub registration_failures: u64,
}

// -------------------------------------------------------------------
// ShrinkerRegistry
// -------------------------------------------------------------------

/// Global shrinker registry and dispatch engine.
///
/// Manages the lifecycle of all registered shrinkers and coordinates
/// the shrink dispatch loop when memory pressure occurs.
pub struct ShrinkerRegistry {
    /// Shrinker slots.
    shrinkers: [ShrinkerInfo; MAX_SHRINKERS],
    /// Number of occupied slots (including deactivated).
    slot_count: usize,
    /// Next ID to assign.
    next_id: u32,
    /// Aggregate statistics.
    stats: ShrinkerStats,
    /// Whether the registry is accepting new registrations.
    accepting: bool,
}

impl ShrinkerRegistry {
    /// Create a new empty registry.
    pub const fn new() -> Self {
        Self {
            shrinkers: [const {
                ShrinkerInfo {
                    id: INVALID_ID,
                    name_token: 0,
                    flags: ShrinkerFlags(0),
                    seeks: DEFAULT_SEEKS,
                    nr_freeable: 0,
                    nr_deferred: 0,
                    per_node_freeable: [0; MAX_NUMA_NODES],
                    lifetime_freed: 0,
                    scan_count: 0,
                    count_count: 0,
                    active: false,
                    batch_size: MIN_SCAN_BATCH,
                }
            }; MAX_SHRINKERS],
            slot_count: 0,
            next_id: 1,
            stats: ShrinkerStats {
                total_registered: 0,
                active_count: 0,
                total_passes: 0,
                total_freed: 0,
                total_deferred_lifetime: 0,
                total_counts: 0,
                total_scans: 0,
                registration_failures: 0,
            },
            accepting: true,
        }
    }

    /// Return a snapshot of the aggregate statistics.
    pub const fn stats(&self) -> &ShrinkerStats {
        &self.stats
    }

    /// Return the number of currently active shrinkers.
    pub fn active_count(&self) -> u32 {
        let mut count = 0u32;
        for i in 0..self.slot_count {
            if self.shrinkers[i].active {
                count += 1;
            }
        }
        count
    }

    /// Return the total slot count (including inactive).
    pub const fn slot_count(&self) -> usize {
        self.slot_count
    }

    /// Stop accepting new registrations (e.g., during shutdown).
    pub fn freeze(&mut self) {
        self.accepting = false;
    }

    /// Resume accepting registrations.
    pub fn thaw(&mut self) {
        self.accepting = true;
    }

    // ---------------------------------------------------------------
    // Registration
    // ---------------------------------------------------------------

    /// Register a new shrinker.
    ///
    /// Returns the assigned shrinker ID on success.
    pub fn register(&mut self, flags: ShrinkerFlags, seeks: u32) -> Result<u32> {
        if !self.accepting {
            return Err(Error::Busy);
        }

        // Try to reuse a deactivated slot first.
        let slot = self.find_free_slot();
        let idx = match slot {
            Some(i) => i,
            None => {
                if self.slot_count >= MAX_SHRINKERS {
                    self.stats.registration_failures += 1;
                    return Err(Error::OutOfMemory);
                }
                let i = self.slot_count;
                self.slot_count += 1;
                i
            }
        };

        let id = self.next_id;
        self.next_id += 1;

        let effective_seeks = if seeks == 0 { DEFAULT_SEEKS } else { seeks };
        self.shrinkers[idx] = ShrinkerInfo::new(id, flags, effective_seeks);
        self.stats.total_registered += 1;
        self.stats.active_count = self.active_count();

        Ok(id)
    }

    /// Unregister (deactivate) a shrinker by ID.
    pub fn unregister(&mut self, id: u32) -> Result<()> {
        let idx = self.find_by_id(id)?;
        self.shrinkers[idx].deactivate();
        self.stats.active_count = self.active_count();
        Ok(())
    }

    /// Look up a shrinker by ID (read-only).
    pub fn get(&self, id: u32) -> Result<&ShrinkerInfo> {
        let idx = self.find_by_id_const(id)?;
        Ok(&self.shrinkers[idx])
    }

    /// Find a slot index by shrinker ID (mutable path).
    fn find_by_id(&self, id: u32) -> Result<usize> {
        for i in 0..self.slot_count {
            if self.shrinkers[i].id == id && self.shrinkers[i].active {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Find a slot index by shrinker ID (const path).
    fn find_by_id_const(&self, id: u32) -> Result<usize> {
        for i in 0..self.slot_count {
            if self.shrinkers[i].id == id && self.shrinkers[i].active {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Find a deactivated slot for reuse.
    fn find_free_slot(&self) -> Option<usize> {
        for i in 0..self.slot_count {
            if !self.shrinkers[i].active {
                return Some(i);
            }
        }
        None
    }

    // ---------------------------------------------------------------
    // Shrink dispatch
    // ---------------------------------------------------------------

    /// Execute a shrink pass across all active shrinkers.
    ///
    /// Each shrinker's count is queried first, then a proportional
    /// scan target is computed, and finally scan is invoked.
    pub fn shrink_all(&mut self, sc: &ShrinkControl, priority: ReclaimPriority) -> ShrinkerResult {
        self.stats.total_passes += 1;
        let multiplier = priority.scan_multiplier();

        let mut result = ShrinkerResult::default();

        // First pass: count freeable objects across all shrinkers.
        let mut total_freeable = 0u64;
        for i in 0..self.slot_count {
            if !self.shrinkers[i].active {
                continue;
            }
            // Skip no-direct-reclaim shrinkers in direct reclaim context.
            if self.shrinkers[i].flags.no_direct_reclaim() && sc.gfp_mask.allows_direct_reclaim() {
                result.any_skipped = true;
                continue;
            }
            total_freeable = total_freeable.saturating_add(self.shrinkers[i].nr_freeable);
        }

        if total_freeable == 0 {
            return result;
        }

        // Second pass: compute per-shrinker scan target and invoke scan.
        for i in 0..self.slot_count {
            if !self.shrinkers[i].active {
                continue;
            }
            if self.shrinkers[i].flags.no_direct_reclaim() && sc.gfp_mask.allows_direct_reclaim() {
                continue;
            }

            let freeable = self.shrinkers[i].nr_freeable;
            if freeable == 0 {
                continue;
            }

            // Proportional scan: this shrinker's share of the total scan.
            let scan_target = if total_freeable > 0 {
                (sc.nr_to_scan * freeable / total_freeable) * multiplier
            } else {
                0
            };

            // Add deferred work from previous passes.
            let deferred = self.shrinkers[i].drain_deferred();
            let effective_scan = scan_target
                .saturating_add(deferred)
                .max(self.shrinkers[i].batch_size);

            // Adjust for seek cost.
            let seeks = self.shrinkers[i].seeks as u64;
            let adjusted = if seeks > 1 {
                effective_scan / seeks
            } else {
                effective_scan
            };
            let adjusted = adjusted.max(MIN_SCAN_BATCH);

            let freed = self.shrinkers[i].do_scan(adjusted);
            self.stats.total_scans += 1;

            // Account deferred work for incomplete scans.
            if freed < adjusted {
                let remaining = adjusted.saturating_sub(freed);
                self.shrinkers[i].add_deferred(remaining);
                self.stats.total_deferred_lifetime += remaining;
            }

            result.total_freed += freed;
            result.shrinkers_invoked += 1;
            if freed > 0 {
                result.shrinkers_active += 1;
            }
        }

        self.stats.total_freed += result.total_freed;

        // Compute total remaining deferred.
        for i in 0..self.slot_count {
            if self.shrinkers[i].active {
                result.total_deferred += self.shrinkers[i].nr_deferred;
            }
        }

        result
    }

    /// Execute a NUMA-aware shrink for a specific node.
    ///
    /// Only invokes shrinkers that have NUMA-aware flag set,
    /// using per-node freeable counts.
    pub fn shrink_node(
        &mut self,
        nid: usize,
        sc: &ShrinkControl,
        priority: ReclaimPriority,
    ) -> ShrinkerResult {
        if nid >= MAX_NUMA_NODES {
            return ShrinkerResult::default();
        }

        self.stats.total_passes += 1;
        let multiplier = priority.scan_multiplier();
        let mut result = ShrinkerResult::default();

        for i in 0..self.slot_count {
            if !self.shrinkers[i].active {
                continue;
            }
            if !self.shrinkers[i].flags.is_numa_aware() {
                continue;
            }

            let node_freeable = self.shrinkers[i].per_node_freeable[nid];
            if node_freeable == 0 {
                continue;
            }

            let scan_target = sc.nr_to_scan.min(node_freeable) * multiplier;
            let freed = self.shrinkers[i].do_scan(scan_target);
            self.stats.total_scans += 1;

            result.total_freed += freed;
            result.shrinkers_invoked += 1;
            if freed > 0 {
                result.shrinkers_active += 1;
            }
        }

        self.stats.total_freed += result.total_freed;
        result
    }

    /// Execute a memcg-scoped shrink.
    ///
    /// Only invokes shrinkers that have memcg-aware flag set.
    pub fn shrink_memcg(
        &mut self,
        memcg_id: u32,
        sc: &ShrinkControl,
        priority: ReclaimPriority,
    ) -> ShrinkerResult {
        if memcg_id == 0 {
            // Root cgroup — shrink all memcg-aware shrinkers.
            return self.shrink_all(sc, priority);
        }

        self.stats.total_passes += 1;
        let multiplier = priority.scan_multiplier();
        let mut result = ShrinkerResult::default();

        for i in 0..self.slot_count {
            if !self.shrinkers[i].active {
                continue;
            }
            if !self.shrinkers[i].flags.is_memcg_aware() {
                continue;
            }

            let freeable = self.shrinkers[i].nr_freeable;
            if freeable == 0 {
                continue;
            }

            // Memcg-scoped scan uses a fraction of the total freeable.
            // Simplified model: allocate 25% of freeable to each cgroup.
            let cgroup_share = freeable / 4;
            let scan_target = sc.nr_to_scan.min(cgroup_share) * multiplier;
            let scan_target = scan_target.max(MIN_SCAN_BATCH);

            let freed = self.shrinkers[i].do_scan(scan_target);
            self.stats.total_scans += 1;

            result.total_freed += freed;
            result.shrinkers_invoked += 1;
            if freed > 0 {
                result.shrinkers_active += 1;
            }
        }

        self.stats.total_freed += result.total_freed;
        result
    }

    // ---------------------------------------------------------------
    // Count
    // ---------------------------------------------------------------

    /// Refresh freeable counts for all active shrinkers.
    ///
    /// `counts` is a slice of `(shrinker_id, freeable_count)` pairs.
    /// Returns the number of shrinkers updated.
    pub fn update_counts(&mut self, counts: &[(u32, u64)]) -> u32 {
        let mut updated = 0u32;
        for &(id, freeable) in counts {
            if let Some(idx) = self.find_idx_by_id(id) {
                self.shrinkers[idx].do_count(freeable);
                self.stats.total_counts += 1;
                updated += 1;
            }
        }
        updated
    }

    /// Refresh per-node freeable counts for a NUMA-aware shrinker.
    pub fn update_node_count(&mut self, id: u32, nid: usize, freeable: u64) -> Result<()> {
        let idx = self.find_by_id(id)?;
        if !self.shrinkers[idx].flags.is_numa_aware() {
            return Err(Error::InvalidArgument);
        }
        self.shrinkers[idx].do_count_node(nid, freeable);
        self.stats.total_counts += 1;
        Ok(())
    }

    /// Helper: find slot index by ID without Result.
    fn find_idx_by_id(&self, id: u32) -> Option<usize> {
        for i in 0..self.slot_count {
            if self.shrinkers[i].id == id && self.shrinkers[i].active {
                return Some(i);
            }
        }
        None
    }

    // ---------------------------------------------------------------
    // Query
    // ---------------------------------------------------------------

    /// Return the total freeable objects across all active shrinkers.
    pub fn total_freeable(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.slot_count {
            if self.shrinkers[i].active {
                total = total.saturating_add(self.shrinkers[i].nr_freeable);
            }
        }
        total
    }

    /// Return the total deferred work across all active shrinkers.
    pub fn total_deferred(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.slot_count {
            if self.shrinkers[i].active {
                total = total.saturating_add(self.shrinkers[i].nr_deferred);
            }
        }
        total
    }

    /// Return the shrinker at a given slot index (for enumeration).
    pub fn shrinker_at(&self, index: usize) -> Result<&ShrinkerInfo> {
        if index >= self.slot_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.shrinkers[index])
    }

    /// Count superblock shrinkers.
    pub fn superblock_count(&self) -> u32 {
        let mut count = 0u32;
        for i in 0..self.slot_count {
            if self.shrinkers[i].active && self.shrinkers[i].flags.is_superblock() {
                count += 1;
            }
        }
        count
    }

    /// Reset aggregate statistics.
    pub fn reset_stats(&mut self) {
        let active = self.active_count();
        self.stats = ShrinkerStats::default();
        self.stats.active_count = active;
    }
}
