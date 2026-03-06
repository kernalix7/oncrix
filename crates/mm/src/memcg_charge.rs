// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory cgroup charge/uncharge.
//!
//! Implements the charge accounting for memory cgroups. When a page is
//! allocated, it is "charged" to the owning cgroup (and all ancestors
//! in the hierarchy). When freed, the charge is released. If a cgroup
//! exceeds its memory limit, reclaim is triggered before the charge
//! is allowed to proceed.
//!
//! - [`MemcgId`] — cgroup identifier
//! - [`MemcgLimits`] — memory limits for a cgroup
//! - [`MemcgState`] — per-cgroup charge state
//! - [`ChargeResult`] — outcome of a charge attempt
//! - [`MemcgCharger`] — the charge/uncharge engine
//!
//! Reference: `.kernelORG/` — `mm/memcontrol.c`, `include/linux/memcontrol.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum cgroups in the hierarchy.
const MAX_CGROUPS: usize = 64;

/// Maximum hierarchy depth.
const MAX_HIERARCHY_DEPTH: usize = 8;

/// Charge retry limit.
const CHARGE_RETRY_LIMIT: u32 = 5;

/// No limit sentinel.
const NO_LIMIT: u64 = u64::MAX;

/// Soft reclaim batch size (pages).
const RECLAIM_BATCH: u64 = 32;

// -------------------------------------------------------------------
// MemcgId
// -------------------------------------------------------------------

/// Memory cgroup identifier.
pub type MemcgId = u32;

/// Root cgroup ID.
const ROOT_MEMCG: MemcgId = 0;

// -------------------------------------------------------------------
// MemcgLimits
// -------------------------------------------------------------------

/// Memory limits for a cgroup.
#[derive(Debug, Clone, Copy)]
pub struct MemcgLimits {
    /// Hard memory limit (bytes). Allocation fails above this.
    pub hard_limit: u64,
    /// Soft memory limit (bytes). Reclaim is preferred above this.
    pub soft_limit: u64,
    /// Swap limit (bytes).
    pub swap_limit: u64,
    /// Memory + swap combined limit.
    pub memsw_limit: u64,
    /// High watermark (bytes). Throttle above this.
    pub high: u64,
    /// Low watermark (bytes). Protected from reclaim below this.
    pub low: u64,
    /// Minimum guarantee (bytes).
    pub min: u64,
}

impl MemcgLimits {
    /// Creates limits with no restrictions.
    pub fn unlimited() -> Self {
        Self {
            hard_limit: NO_LIMIT,
            soft_limit: NO_LIMIT,
            swap_limit: NO_LIMIT,
            memsw_limit: NO_LIMIT,
            high: NO_LIMIT,
            low: 0,
            min: 0,
        }
    }

    /// Creates limits with a hard limit.
    pub fn with_hard_limit(limit: u64) -> Self {
        let mut l = Self::unlimited();
        l.hard_limit = limit;
        l.soft_limit = limit * 3 / 4; // 75% of hard limit
        l.high = limit * 7 / 8; // 87.5% of hard limit
        l
    }
}

impl Default for MemcgLimits {
    fn default() -> Self {
        Self::unlimited()
    }
}

// -------------------------------------------------------------------
// MemcgState
// -------------------------------------------------------------------

/// Per-cgroup charge state.
#[derive(Debug, Clone)]
pub struct MemcgState {
    /// Cgroup ID.
    pub id: MemcgId,
    /// Parent cgroup ID (ROOT_MEMCG for root).
    pub parent: MemcgId,
    /// Memory limits.
    pub limits: MemcgLimits,
    /// Current memory usage (bytes).
    pub usage: u64,
    /// Current swap usage (bytes).
    pub swap_usage: u64,
    /// Maximum observed usage (bytes).
    pub max_usage: u64,
    /// Number of page charges.
    pub nr_charges: u64,
    /// Number of page uncharges.
    pub nr_uncharges: u64,
    /// Number of charge failures (OOM).
    pub nr_charge_failures: u64,
    /// Number of reclaim events triggered.
    pub nr_reclaim_events: u64,
    /// Whether this cgroup is active.
    pub active: bool,
    /// Hierarchy depth (0 for root).
    pub depth: u8,
}

impl MemcgState {
    /// Creates a new cgroup state.
    pub fn new(id: MemcgId, parent: MemcgId, depth: u8) -> Self {
        Self {
            id,
            parent,
            limits: MemcgLimits::unlimited(),
            usage: 0,
            swap_usage: 0,
            max_usage: 0,
            nr_charges: 0,
            nr_uncharges: 0,
            nr_charge_failures: 0,
            nr_reclaim_events: 0,
            active: true,
            depth,
        }
    }

    /// Checks if the cgroup is over its hard limit.
    pub fn is_over_limit(&self) -> bool {
        self.usage > self.limits.hard_limit
    }

    /// Checks if the cgroup is over its soft limit.
    pub fn is_over_soft_limit(&self) -> bool {
        self.usage > self.limits.soft_limit
    }

    /// Checks if the cgroup is over its high watermark.
    pub fn is_over_high(&self) -> bool {
        self.usage > self.limits.high
    }

    /// Returns the available headroom (bytes before hard limit).
    pub fn headroom(&self) -> u64 {
        self.limits.hard_limit.saturating_sub(self.usage)
    }

    /// Returns usage as a percentage of the hard limit (0-100).
    pub fn usage_pct(&self) -> u64 {
        if self.limits.hard_limit == NO_LIMIT || self.limits.hard_limit == 0 {
            return 0;
        }
        self.usage * 100 / self.limits.hard_limit
    }
}

impl Default for MemcgState {
    fn default() -> Self {
        Self::new(ROOT_MEMCG, ROOT_MEMCG, 0)
    }
}

// -------------------------------------------------------------------
// ChargeResult
// -------------------------------------------------------------------

/// Outcome of a charge attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChargeResult {
    /// Charge succeeded.
    Success,
    /// Charge succeeded after reclaim.
    SuccessAfterReclaim,
    /// Failed: over limit, OOM.
    OverLimit,
    /// Failed: cgroup not found.
    NotFound,
    /// Cancelled by caller.
    Cancelled,
}

impl ChargeResult {
    /// Returns true if the charge was accepted.
    pub fn is_success(self) -> bool {
        matches!(
            self,
            ChargeResult::Success | ChargeResult::SuccessAfterReclaim
        )
    }
}

// -------------------------------------------------------------------
// MemcgCharger
// -------------------------------------------------------------------

/// Memory cgroup charge/uncharge engine.
///
/// Manages charge accounting across the cgroup hierarchy. When charging,
/// walks from the target cgroup up to the root, checking limits at each
/// level. Uncharging walks the same path in reverse.
pub struct MemcgCharger {
    /// Per-cgroup states.
    cgroups: [Option<MemcgState>; MAX_CGROUPS],
    /// Number of active cgroups.
    nr_cgroups: usize,
}

impl MemcgCharger {
    /// Creates a new charger with a root cgroup.
    pub fn new() -> Self {
        const NONE: Option<MemcgState> = None;
        let mut cgroups = [NONE; MAX_CGROUPS];
        cgroups[ROOT_MEMCG as usize] = Some(MemcgState::new(ROOT_MEMCG, ROOT_MEMCG, 0));
        Self {
            cgroups,
            nr_cgroups: 1,
        }
    }

    /// Creates a new child cgroup.
    pub fn create_cgroup(
        &mut self,
        id: MemcgId,
        parent: MemcgId,
        limits: MemcgLimits,
    ) -> Result<()> {
        let idx = id as usize;
        if idx >= MAX_CGROUPS {
            return Err(Error::InvalidArgument);
        }
        if self.cgroups[idx].is_some() {
            return Err(Error::AlreadyExists);
        }
        let parent_depth = self
            .cgroups
            .get(parent as usize)
            .and_then(|c| c.as_ref())
            .map(|c| c.depth)
            .ok_or(Error::NotFound)?;

        let depth = parent_depth + 1;
        if depth as usize >= MAX_HIERARCHY_DEPTH {
            return Err(Error::InvalidArgument);
        }

        let mut state = MemcgState::new(id, parent, depth);
        state.limits = limits;
        self.cgroups[idx] = Some(state);
        self.nr_cgroups += 1;
        Ok(())
    }

    /// Charges a page to the given cgroup (and its ancestors).
    ///
    /// Walks up the hierarchy from `memcg` to root. At each level,
    /// checks the hard limit. If over limit, triggers reclaim. If
    /// reclaim fails, the charge is refused.
    pub fn memcg_charge_page(&mut self, memcg: MemcgId, nr_pages: u64) -> ChargeResult {
        let charge_bytes = nr_pages * PAGE_SIZE;

        // Build the hierarchy path.
        let path = match self.build_hierarchy_path(memcg) {
            Some(p) => p,
            None => return ChargeResult::NotFound,
        };

        // Check limits along the hierarchy.
        let mut needed_reclaim = false;
        for &cg_id in &path.ids[..path.len] {
            let idx = cg_id as usize;
            if let Some(state) = &self.cgroups[idx] {
                if state.usage + charge_bytes > state.limits.hard_limit
                    && state.limits.hard_limit != NO_LIMIT
                {
                    // Try reclaim.
                    needed_reclaim = true;
                    let reclaimed = self.try_reclaim(cg_id, charge_bytes);
                    if !reclaimed {
                        // Record failure.
                        if let Some(s) = &mut self.cgroups[idx] {
                            s.nr_charge_failures += 1;
                        }
                        // Cancel charges already applied.
                        self.cancel_charge_path(&path, charge_bytes, cg_id);
                        return ChargeResult::OverLimit;
                    }
                }
            }
        }

        // Apply charges.
        for &cg_id in &path.ids[..path.len] {
            let idx = cg_id as usize;
            if let Some(state) = &mut self.cgroups[idx] {
                state.usage += charge_bytes;
                state.nr_charges += nr_pages;
                if state.usage > state.max_usage {
                    state.max_usage = state.usage;
                }
            }
        }

        if needed_reclaim {
            ChargeResult::SuccessAfterReclaim
        } else {
            ChargeResult::Success
        }
    }

    /// Uncharges a page from the given cgroup (and its ancestors).
    pub fn memcg_uncharge_page(&mut self, memcg: MemcgId, nr_pages: u64) -> Result<()> {
        let charge_bytes = nr_pages * PAGE_SIZE;
        let path = self.build_hierarchy_path(memcg).ok_or(Error::NotFound)?;

        for &cg_id in &path.ids[..path.len] {
            let idx = cg_id as usize;
            if let Some(state) = &mut self.cgroups[idx] {
                state.usage = state.usage.saturating_sub(charge_bytes);
                state.nr_uncharges += nr_pages;
            }
        }

        Ok(())
    }

    /// Cancels a charge along a partial hierarchy path.
    fn cancel_charge_path(&mut self, path: &HierarchyPath, charge_bytes: u64, stop_at: MemcgId) {
        for &cg_id in &path.ids[..path.len] {
            if cg_id == stop_at {
                break;
            }
            let idx = cg_id as usize;
            if let Some(state) = &mut self.cgroups[idx] {
                state.usage = state.usage.saturating_sub(charge_bytes);
            }
        }
    }

    /// Attempts reclaim for the given cgroup.
    fn try_reclaim(&mut self, memcg: MemcgId, _needed: u64) -> bool {
        let idx = memcg as usize;
        if let Some(state) = &mut self.cgroups[idx] {
            state.nr_reclaim_events += 1;
            // Stub: model reclaim as always succeeding if over soft limit.
            if state.usage > state.limits.soft_limit {
                let reclaimed = RECLAIM_BATCH * PAGE_SIZE;
                state.usage = state.usage.saturating_sub(reclaimed);
                return true;
            }
        }
        false
    }

    /// Moves charge from one cgroup to another (task migration).
    pub fn move_charge(&mut self, from: MemcgId, to: MemcgId, nr_pages: u64) -> Result<()> {
        let charge_bytes = nr_pages * PAGE_SIZE;

        // Uncharge from source hierarchy.
        self.memcg_uncharge_page(from, nr_pages)?;

        // Charge to target hierarchy.
        let result = self.memcg_charge_page(to, nr_pages);
        if !result.is_success() {
            // Revert: re-charge to source.
            let _ = self.memcg_charge_page(from, nr_pages);
            return Err(Error::OutOfMemory);
        }

        let _ = charge_bytes;
        Ok(())
    }

    /// Returns the state of a cgroup.
    pub fn get_state(&self, id: MemcgId) -> Option<&MemcgState> {
        self.cgroups.get(id as usize).and_then(|c| c.as_ref())
    }

    /// Returns a mutable state of a cgroup.
    pub fn get_state_mut(&mut self, id: MemcgId) -> Option<&mut MemcgState> {
        self.cgroups.get_mut(id as usize).and_then(|c| c.as_mut())
    }

    /// Builds the hierarchy path from a cgroup to root.
    fn build_hierarchy_path(&self, memcg: MemcgId) -> Option<HierarchyPath> {
        let mut path = HierarchyPath::new();
        let mut current = memcg;

        loop {
            let idx = current as usize;
            let state = self.cgroups.get(idx)?.as_ref()?;
            path.push(current);

            if current == ROOT_MEMCG || current == state.parent {
                break;
            }
            current = state.parent;
        }

        Some(path)
    }

    /// Returns the number of active cgroups.
    pub fn nr_cgroups(&self) -> usize {
        self.nr_cgroups
    }
}

impl Default for MemcgCharger {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// HierarchyPath (internal)
// -------------------------------------------------------------------

/// Path from a cgroup to the root.
struct HierarchyPath {
    ids: [MemcgId; MAX_HIERARCHY_DEPTH],
    len: usize,
}

impl HierarchyPath {
    fn new() -> Self {
        Self {
            ids: [0; MAX_HIERARCHY_DEPTH],
            len: 0,
        }
    }

    fn push(&mut self, id: MemcgId) {
        if self.len < MAX_HIERARCHY_DEPTH {
            self.ids[self.len] = id;
            self.len += 1;
        }
    }
}
