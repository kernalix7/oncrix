// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Slab allocator memory cgroup charging.
//!
//! Charges slab allocations to the owning memory cgroup, provides
//! per-object accounting, handles reparenting when a cgroup is
//! destroyed, maintains objcg (object cgroup) reference counting,
//! and implements stock-based charge/uncharge batching to reduce
//! per-allocation overhead.
//!
//! # Key Types
//!
//! - [`ObjCgId`] — object cgroup identifier
//! - [`ObjCgRef`] — reference-counted handle to an object cgroup
//! - [`ObjCgState`] — per-objcg accounting state
//! - [`ChargeStock`] — per-CPU batched charge stock
//! - [`SlabChargeRequest`] — parameters for a slab charge
//! - [`SlabChargeResult`] — outcome of a charge attempt
//! - [`SlabMemcgCharger`] — the charging engine
//! - [`SlabMemcgStats`] — aggregate statistics
//!
//! Reference: Linux `mm/memcontrol.c` (slab charging paths),
//! `mm/slab.h`, `include/linux/memcontrol.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum object cgroups tracked.
const MAX_OBJCGS: usize = 64;

/// Maximum CPUs for per-CPU stock.
const MAX_CPUS: usize = 8;

/// Stock charge batch size (bytes).
const STOCK_BATCH_BYTES: u64 = 32 * 4096;

/// No limit sentinel.
const NO_LIMIT: u64 = u64::MAX;

/// Maximum slab caches tracked for accounting.
const MAX_SLAB_CACHES: usize = 32;

/// Root cgroup ID.
const ROOT_CG: ObjCgId = 0;

// -------------------------------------------------------------------
// ObjCgId
// -------------------------------------------------------------------

/// Object cgroup identifier.
pub type ObjCgId = u32;

// -------------------------------------------------------------------
// ObjCgRef
// -------------------------------------------------------------------

/// Reference-counted handle to an object cgroup.
///
/// When the reference count drops to zero, the objcg is eligible
/// for cleanup.
#[derive(Debug, Clone, Copy)]
pub struct ObjCgRef {
    /// Object cgroup ID.
    pub id: ObjCgId,
    /// Current reference count.
    pub ref_count: u32,
}

impl ObjCgRef {
    /// Creates a new reference with count 1.
    pub fn new(id: ObjCgId) -> Self {
        Self { id, ref_count: 1 }
    }

    /// Increments the reference count.
    pub fn get(&mut self) {
        self.ref_count = self.ref_count.saturating_add(1);
    }

    /// Decrements the reference count. Returns `true` if it
    /// reached zero.
    pub fn put(&mut self) -> bool {
        self.ref_count = self.ref_count.saturating_sub(1);
        self.ref_count == 0
    }

    /// Returns `true` if the reference is still live.
    pub fn is_live(&self) -> bool {
        self.ref_count > 0
    }
}

impl Default for ObjCgRef {
    fn default() -> Self {
        Self {
            id: ROOT_CG,
            ref_count: 0,
        }
    }
}

// -------------------------------------------------------------------
// ObjCgState
// -------------------------------------------------------------------

/// Per-object-cgroup accounting state.
#[derive(Debug, Clone, Copy)]
pub struct ObjCgState {
    /// Object cgroup ID.
    pub id: ObjCgId,
    /// Parent cgroup ID.
    pub parent: ObjCgId,
    /// Memory limit (bytes).
    pub limit: u64,
    /// Current charged bytes.
    pub charged: u64,
    /// Peak charged bytes.
    pub peak_charged: u64,
    /// Number of charged objects.
    pub nr_objects: u64,
    /// Number of charge operations.
    pub nr_charges: u64,
    /// Number of uncharge operations.
    pub nr_uncharges: u64,
    /// Number of charge failures.
    pub nr_failures: u64,
    /// Whether this cgroup is active (not destroyed).
    pub active: bool,
    /// Reference count (number of ObjCgRef handles).
    pub ref_count: u32,
}

impl ObjCgState {
    /// Creates a new objcg state.
    pub fn new(id: ObjCgId, parent: ObjCgId, limit: u64) -> Self {
        Self {
            id,
            parent,
            limit,
            charged: 0,
            peak_charged: 0,
            nr_objects: 0,
            nr_charges: 0,
            nr_uncharges: 0,
            nr_failures: 0,
            active: true,
            ref_count: 1,
        }
    }

    /// Returns available headroom before hitting the limit.
    pub fn headroom(&self) -> u64 {
        self.limit.saturating_sub(self.charged)
    }

    /// Returns `true` if charging `bytes` would exceed the limit.
    pub fn would_exceed(&self, bytes: u64) -> bool {
        self.limit != NO_LIMIT && self.charged + bytes > self.limit
    }

    /// Returns usage as percentage of limit (0-100).
    pub fn usage_pct(&self) -> u64 {
        if self.limit == 0 || self.limit == NO_LIMIT {
            return 0;
        }
        self.charged * 100 / self.limit
    }
}

impl Default for ObjCgState {
    fn default() -> Self {
        Self::new(ROOT_CG, ROOT_CG, NO_LIMIT)
    }
}

// -------------------------------------------------------------------
// ChargeStock
// -------------------------------------------------------------------

/// Per-CPU batched charge stock.
///
/// Maintains a pre-charged buffer of bytes from a specific cgroup.
/// Slab allocations first draw from the stock, avoiding the cost
/// of walking the cgroup hierarchy on every allocation. When the
/// stock is depleted, a batch charge is performed.
#[derive(Debug, Clone, Copy)]
pub struct ChargeStock {
    /// CPU this stock belongs to.
    pub cpu_id: u32,
    /// Object cgroup the stock is charged to.
    pub objcg_id: ObjCgId,
    /// Remaining pre-charged bytes.
    pub remaining: u64,
    /// Total bytes charged via this stock.
    pub total_charged: u64,
    /// Total bytes returned (uncharged) via this stock.
    pub total_returned: u64,
}

impl ChargeStock {
    /// Creates an empty stock for the given CPU.
    const fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            objcg_id: ROOT_CG,
            remaining: 0,
            total_charged: 0,
            total_returned: 0,
        }
    }

    /// Attempts to charge `bytes` from the stock.
    ///
    /// Returns `true` if the stock had enough, `false` otherwise.
    pub fn try_charge(&mut self, objcg_id: ObjCgId, bytes: u64) -> bool {
        if self.objcg_id != objcg_id || self.remaining < bytes {
            return false;
        }
        self.remaining -= bytes;
        self.total_charged += bytes;
        true
    }

    /// Returns `bytes` to the stock.
    pub fn uncharge(&mut self, objcg_id: ObjCgId, bytes: u64) {
        if self.objcg_id == objcg_id {
            self.remaining += bytes;
            self.total_returned += bytes;
        }
    }

    /// Refills the stock with a batch charge.
    pub fn refill(&mut self, objcg_id: ObjCgId, bytes: u64) {
        self.objcg_id = objcg_id;
        self.remaining += bytes;
    }

    /// Drains the stock, returning remaining bytes.
    pub fn drain(&mut self) -> (ObjCgId, u64) {
        let id = self.objcg_id;
        let rem = self.remaining;
        self.remaining = 0;
        (id, rem)
    }

    /// Returns `true` if the stock is empty.
    pub fn is_empty(&self) -> bool {
        self.remaining == 0
    }
}

// -------------------------------------------------------------------
// SlabChargeRequest
// -------------------------------------------------------------------

/// Parameters for a slab allocation charge.
#[derive(Debug, Clone, Copy)]
pub struct SlabChargeRequest {
    /// Object cgroup to charge.
    pub objcg_id: ObjCgId,
    /// Object size in bytes.
    pub obj_size: usize,
    /// Number of objects being allocated.
    pub nr_objects: u32,
    /// Slab cache index (for accounting).
    pub cache_idx: u16,
    /// CPU performing the allocation.
    pub cpu: u32,
}

// -------------------------------------------------------------------
// SlabChargeResult
// -------------------------------------------------------------------

/// Outcome of a slab charge attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlabChargeResult {
    /// Charge succeeded (from stock).
    FromStock,
    /// Charge succeeded (new batch charge).
    NewCharge,
    /// Charge failed: over limit.
    OverLimit,
    /// Charge failed: cgroup not found.
    NotFound,
}

impl SlabChargeResult {
    /// Returns `true` if the charge was accepted.
    pub fn is_success(self) -> bool {
        matches!(self, Self::FromStock | Self::NewCharge)
    }
}

// -------------------------------------------------------------------
// SlabMemcgStats
// -------------------------------------------------------------------

/// Aggregate slab memcg charging statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct SlabMemcgStats {
    /// Total successful charges.
    pub charges: u64,
    /// Total uncharges.
    pub uncharges: u64,
    /// Charges served from stock.
    pub stock_hits: u64,
    /// Charges that required new batch charge.
    pub stock_misses: u64,
    /// Failed charges.
    pub failures: u64,
    /// Reparenting events.
    pub reparent_events: u64,
    /// Total bytes currently charged.
    pub total_charged_bytes: u64,
    /// Active object cgroup count.
    pub active_objcgs: usize,
}

// -------------------------------------------------------------------
// SlabCacheAccounting
// -------------------------------------------------------------------

/// Per-slab-cache accounting entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct SlabCacheAccounting {
    /// Cache index.
    pub cache_idx: u16,
    /// Object size.
    pub obj_size: usize,
    /// Total objects charged across all objcgs.
    pub total_objects: u64,
    /// Total bytes charged.
    pub total_bytes: u64,
    /// Whether this entry is active.
    pub active: bool,
}

// -------------------------------------------------------------------
// SlabMemcgCharger
// -------------------------------------------------------------------

/// Slab allocator memory cgroup charging engine.
///
/// Manages object cgroup references, per-CPU charge stocks, and
/// per-slab-cache accounting. On cgroup destroy, reparents charges
/// to the parent cgroup.
pub struct SlabMemcgCharger {
    /// Object cgroup states.
    objcgs: [Option<ObjCgState>; MAX_OBJCGS],
    /// Number of active objcgs.
    nr_objcgs: usize,
    /// Per-CPU charge stocks.
    stocks: [ChargeStock; MAX_CPUS],
    /// Per-slab-cache accounting.
    caches: [SlabCacheAccounting; MAX_SLAB_CACHES],
    /// Number of active caches.
    nr_caches: usize,
    /// Statistics.
    stats: SlabMemcgStats,
}

impl SlabMemcgCharger {
    /// Creates a new charger with a root objcg.
    pub fn new() -> Self {
        const NONE: Option<ObjCgState> = None;
        let mut objcgs = [NONE; MAX_OBJCGS];
        objcgs[ROOT_CG as usize] = Some(ObjCgState::new(ROOT_CG, ROOT_CG, NO_LIMIT));

        Self {
            objcgs,
            nr_objcgs: 1,
            stocks: [
                ChargeStock::new(0),
                ChargeStock::new(1),
                ChargeStock::new(2),
                ChargeStock::new(3),
                ChargeStock::new(4),
                ChargeStock::new(5),
                ChargeStock::new(6),
                ChargeStock::new(7),
            ],
            caches: [SlabCacheAccounting::default(); MAX_SLAB_CACHES],
            nr_caches: 0,
            stats: SlabMemcgStats::default(),
        }
    }

    /// Creates a new object cgroup.
    pub fn create_objcg(&mut self, id: ObjCgId, parent: ObjCgId, limit: u64) -> Result<()> {
        let idx = id as usize;
        if idx >= MAX_OBJCGS {
            return Err(Error::InvalidArgument);
        }
        if self.objcgs[idx].is_some() {
            return Err(Error::AlreadyExists);
        }
        // Verify parent exists.
        if self
            .objcgs
            .get(parent as usize)
            .and_then(|o| o.as_ref())
            .is_none()
        {
            return Err(Error::NotFound);
        }
        self.objcgs[idx] = Some(ObjCgState::new(id, parent, limit));
        self.nr_objcgs += 1;
        self.stats.active_objcgs = self.nr_objcgs;
        Ok(())
    }

    /// Registers a slab cache for accounting.
    pub fn register_cache(&mut self, cache_idx: u16, obj_size: usize) -> Result<()> {
        if self.nr_caches >= MAX_SLAB_CACHES {
            return Err(Error::OutOfMemory);
        }
        self.caches[self.nr_caches] = SlabCacheAccounting {
            cache_idx,
            obj_size,
            total_objects: 0,
            total_bytes: 0,
            active: true,
        };
        self.nr_caches += 1;
        Ok(())
    }

    /// Charges a slab allocation.
    ///
    /// First attempts the per-CPU stock. If the stock is empty or
    /// belongs to a different cgroup, performs a batch charge and
    /// refills the stock.
    pub fn charge(&mut self, req: &SlabChargeRequest) -> SlabChargeResult {
        let charge_bytes = req.obj_size as u64 * req.nr_objects as u64;
        let cpu = req.cpu as usize;

        // Try per-CPU stock.
        if cpu < MAX_CPUS && self.stocks[cpu].try_charge(req.objcg_id, charge_bytes) {
            self.record_charge(req.objcg_id, charge_bytes, req);
            self.stats.stock_hits += 1;
            self.stats.charges += 1;
            return SlabChargeResult::FromStock;
        }

        // Drain stale stock if it belongs to a different cgroup.
        if cpu < MAX_CPUS && self.stocks[cpu].objcg_id != req.objcg_id {
            let (old_id, remaining) = self.stocks[cpu].drain();
            if remaining > 0 {
                self.unrecord_charge(old_id, remaining);
            }
        }

        // Attempt batch charge to the cgroup hierarchy.
        let batch_bytes = STOCK_BATCH_BYTES.max(charge_bytes);
        if !self.try_hierarchy_charge(req.objcg_id, batch_bytes) {
            self.stats.failures += 1;
            let idx = req.objcg_id as usize;
            if let Some(state) = self.objcgs.get_mut(idx).and_then(|o| o.as_mut()) {
                state.nr_failures += 1;
            }
            return SlabChargeResult::OverLimit;
        }

        // Refill stock with the surplus.
        if cpu < MAX_CPUS {
            let surplus = batch_bytes.saturating_sub(charge_bytes);
            self.stocks[cpu].refill(req.objcg_id, surplus);
        }

        self.record_charge(req.objcg_id, charge_bytes, req);
        self.stats.stock_misses += 1;
        self.stats.charges += 1;
        SlabChargeResult::NewCharge
    }

    /// Uncharges a slab deallocation.
    pub fn uncharge(
        &mut self,
        objcg_id: ObjCgId,
        obj_size: usize,
        nr_objects: u32,
        cpu: u32,
    ) -> Result<()> {
        let bytes = obj_size as u64 * nr_objects as u64;
        let cpu_idx = cpu as usize;

        // Return to per-CPU stock if possible.
        if cpu_idx < MAX_CPUS {
            self.stocks[cpu_idx].uncharge(objcg_id, bytes);
        }

        self.unrecord_charge(objcg_id, bytes);
        self.stats.uncharges += 1;
        Ok(())
    }

    /// Destroys an object cgroup, reparenting charges to its parent.
    pub fn destroy_objcg(&mut self, id: ObjCgId) -> Result<()> {
        let idx = id as usize;
        let (parent, charged) = {
            let state = self
                .objcgs
                .get(idx)
                .and_then(|o| o.as_ref())
                .ok_or(Error::NotFound)?;
            (state.parent, state.charged)
        };

        // Reparent remaining charges.
        if charged > 0 {
            let parent_idx = parent as usize;
            if let Some(p_state) = self.objcgs.get_mut(parent_idx).and_then(|o| o.as_mut()) {
                p_state.charged += charged;
                if p_state.charged > p_state.peak_charged {
                    p_state.peak_charged = p_state.charged;
                }
            }
            self.stats.reparent_events += 1;
        }

        // Drain any per-CPU stocks referencing this cgroup.
        for cpu in 0..MAX_CPUS {
            if self.stocks[cpu].objcg_id == id {
                let (_, remaining) = self.stocks[cpu].drain();
                if remaining > 0 {
                    let parent_idx = parent as usize;
                    if let Some(p_state) = self.objcgs.get_mut(parent_idx).and_then(|o| o.as_mut())
                    {
                        p_state.charged = p_state.charged.saturating_sub(remaining);
                    }
                }
            }
        }

        // Mark destroyed.
        if let Some(state) = self.objcgs.get_mut(idx).and_then(|o| o.as_mut()) {
            state.active = false;
            state.charged = 0;
        }
        self.nr_objcgs = self.nr_objcgs.saturating_sub(1);
        self.stats.active_objcgs = self.nr_objcgs;
        Ok(())
    }

    /// Returns the state of an object cgroup.
    pub fn get_objcg(&self, id: ObjCgId) -> Option<&ObjCgState> {
        self.objcgs.get(id as usize).and_then(|o| o.as_ref())
    }

    /// Returns aggregate statistics.
    pub fn stats(&self) -> SlabMemcgStats {
        let mut s = self.stats;
        let mut total_bytes = 0u64;
        for i in 0..MAX_OBJCGS {
            if let Some(state) = &self.objcgs[i] {
                if state.active {
                    total_bytes += state.charged;
                }
            }
        }
        s.total_charged_bytes = total_bytes;
        s
    }

    /// Returns the number of active object cgroups.
    pub fn nr_objcgs(&self) -> usize {
        self.nr_objcgs
    }

    // -- internal helpers --

    /// Attempts to charge `bytes` up the cgroup hierarchy.
    fn try_hierarchy_charge(&mut self, id: ObjCgId, bytes: u64) -> bool {
        let mut current = id;
        let mut path = [0u32; 8];
        let mut depth = 0usize;

        // Build path to root.
        loop {
            let idx = current as usize;
            let state = match self.objcgs.get(idx).and_then(|o| o.as_ref()) {
                Some(s) => s,
                None => return false,
            };

            if state.would_exceed(bytes) {
                return false;
            }

            if depth < 8 {
                path[depth] = current;
                depth += 1;
            }

            if current == ROOT_CG || current == state.parent {
                break;
            }
            current = state.parent;
        }

        // Apply charges.
        for i in 0..depth {
            let idx = path[i] as usize;
            if let Some(state) = self.objcgs.get_mut(idx).and_then(|o| o.as_mut()) {
                state.charged += bytes;
                if state.charged > state.peak_charged {
                    state.peak_charged = state.charged;
                }
            }
        }

        true
    }

    /// Records a successful charge in per-cache accounting.
    fn record_charge(&mut self, objcg_id: ObjCgId, bytes: u64, req: &SlabChargeRequest) {
        let idx = objcg_id as usize;
        if let Some(state) = self.objcgs.get_mut(idx).and_then(|o| o.as_mut()) {
            state.nr_charges += req.nr_objects as u64;
            state.nr_objects += req.nr_objects as u64;
        }

        // Update slab cache accounting.
        for i in 0..self.nr_caches {
            if self.caches[i].cache_idx == req.cache_idx {
                self.caches[i].total_objects += req.nr_objects as u64;
                self.caches[i].total_bytes += bytes;
                break;
            }
        }
    }

    /// Records an uncharge.
    fn unrecord_charge(&mut self, objcg_id: ObjCgId, bytes: u64) {
        let idx = objcg_id as usize;
        if let Some(state) = self.objcgs.get_mut(idx).and_then(|o| o.as_mut()) {
            state.charged = state.charged.saturating_sub(bytes);
            state.nr_uncharges += 1;
        }
    }
}

impl Default for SlabMemcgCharger {
    fn default() -> Self {
        Self::new()
    }
}
