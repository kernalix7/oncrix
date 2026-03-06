// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! CFS bandwidth throttling for fair-share CPU scheduling.
//!
//! Implements Completely Fair Scheduler (CFS) bandwidth control,
//! allowing hierarchical CPU bandwidth allocation with:
//!
//! - **Bandwidth pools** ([`BandwidthPool`]): per-group quota/period
//!   budgets with burst accumulation and hierarchical constraints.
//! - **Runtime accounting** ([`RuntimeAccount`]): tracks consumed
//!   and remaining runtime per scheduling entity.
//! - **Throttle state machine** ([`ThrottleState`]): three-state
//!   FSM (Running, Throttled, Expired) with hysteresis.
//! - **Hierarchical enforcement** ([`HierarchyNode`]): tree-based
//!   bandwidth distribution respecting parent constraints.
//! - **Global controller** ([`CfsBandwidthController`]): manages
//!   up to 128 bandwidth groups with periodic replenishment.
//!
//! # Design
//!
//! Each CFS bandwidth group has a quota (maximum CPU time per period)
//! and a period (replenishment interval). When a group exhausts its
//! quota, all tasks in that group are throttled until the next period
//! boundary. Burst accumulation allows unused quota to carry over up
//! to a configurable limit.
//!
//! Reference: Linux `kernel/sched/fair.c` (CFS bandwidth control),
//! `kernel/sched/sched.h`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of bandwidth groups in the system.
const MAX_BANDWIDTH_GROUPS: usize = 128;

/// Maximum hierarchy depth for nested bandwidth groups.
const MAX_HIERARCHY_DEPTH: usize = 16;

/// Maximum children per hierarchy node.
const MAX_CHILDREN: usize = 32;

/// Maximum name length in bytes.
const MAX_NAME_LEN: usize = 64;

/// Default period in microseconds (100 ms).
const DEFAULT_PERIOD_US: u64 = 100_000;

/// Minimum period in microseconds (1 ms).
const MIN_PERIOD_US: u64 = 1_000;

/// Maximum period in microseconds (1 second).
const MAX_PERIOD_US: u64 = 1_000_000;

/// Minimum quota in microseconds (1 ms).
const MIN_QUOTA_US: u64 = 1_000;

/// Quota value meaning unlimited (no bandwidth cap).
const QUOTA_UNLIMITED: i64 = -1;

/// Maximum burst accumulation factor (3x period).
const MAX_BURST_FACTOR: u64 = 3;

/// Slice granularity for runtime distribution (5 ms).
const SLICE_GRANULARITY_US: u64 = 5_000;

/// Maximum number of throttle events to track in history.
const MAX_THROTTLE_HISTORY: usize = 64;

/// Number of periods to average for statistics.
const STAT_WINDOW_PERIODS: u64 = 8;

/// Hysteresis threshold for un-throttling (percentage of quota).
const UNTHROTTLE_HYSTERESIS_PCT: u64 = 5;

// ── ThrottleState ──────────────────────────────────────────────────

/// Throttle state machine states for a bandwidth group.
///
/// Transitions:
/// - `Running` -> `Throttled`: quota exhausted
/// - `Throttled` -> `Expired`: period elapsed while throttled
/// - `Expired` -> `Running`: new period begins with fresh quota
/// - `Running` -> `Running`: quota still available (no transition)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleState {
    /// Group has available quota and tasks may execute.
    Running,
    /// Group exhausted its quota; tasks are suspended.
    Throttled,
    /// Period expired while throttled; awaiting replenishment.
    Expired,
}

impl Default for ThrottleState {
    fn default() -> Self {
        Self::Running
    }
}

// ── RuntimeAccount ─────────────────────────────────────────────────

/// Per-entity runtime accounting.
///
/// Tracks how much CPU time a scheduling entity has consumed
/// within the current period, and how much remains.
#[derive(Debug, Clone, Copy)]
pub struct RuntimeAccount {
    /// Total runtime consumed in current period (microseconds).
    pub consumed_us: u64,
    /// Remaining runtime in current period (microseconds).
    pub remaining_us: u64,
    /// Accumulated burst from previous periods (microseconds).
    pub burst_us: u64,
    /// Total runtime consumed across all periods (microseconds).
    pub total_consumed_us: u64,
    /// Timestamp of last runtime update (microseconds since boot).
    pub last_update_us: u64,
    /// Number of periods since creation.
    pub period_count: u64,
}

impl RuntimeAccount {
    /// Create a new runtime account with the given initial quota.
    pub const fn new(initial_quota_us: u64) -> Self {
        Self {
            consumed_us: 0,
            remaining_us: initial_quota_us,
            burst_us: 0,
            total_consumed_us: 0,
            last_update_us: 0,
            period_count: 0,
        }
    }

    /// Charge runtime to this account.
    ///
    /// Returns `true` if the account still has remaining runtime,
    /// `false` if the quota is exhausted.
    pub fn charge(&mut self, delta_us: u64) -> bool {
        self.consumed_us = self.consumed_us.saturating_add(delta_us);
        self.total_consumed_us = self.total_consumed_us.saturating_add(delta_us);
        if delta_us <= self.remaining_us {
            self.remaining_us -= delta_us;
            true
        } else {
            self.remaining_us = 0;
            false
        }
    }

    /// Replenish the account for a new period.
    ///
    /// Unused runtime is added to burst (up to `max_burst_us`),
    /// then remaining is reset to the full quota.
    pub fn replenish(&mut self, quota_us: u64, max_burst_us: u64, now_us: u64) {
        let unused = self.remaining_us;
        self.burst_us = self.burst_us.saturating_add(unused).min(max_burst_us);
        self.consumed_us = 0;
        self.remaining_us = quota_us.saturating_add(self.burst_us.min(max_burst_us));
        self.last_update_us = now_us;
        self.period_count = self.period_count.wrapping_add(1);
    }

    /// Return the effective available runtime including burst.
    pub fn effective_remaining(&self) -> u64 {
        self.remaining_us.saturating_add(self.burst_us)
    }
}

impl Default for RuntimeAccount {
    fn default() -> Self {
        Self::new(0)
    }
}

// ── BandwidthParams ────────────────────────────────────────────────

/// Configuration parameters for a bandwidth pool.
#[derive(Debug, Clone, Copy)]
pub struct BandwidthParams {
    /// Quota per period in microseconds (`-1` = unlimited).
    pub quota_us: i64,
    /// Period length in microseconds.
    pub period_us: u64,
    /// Maximum burst accumulation in microseconds.
    pub max_burst_us: u64,
    /// Number of CPU shares (weight) for proportional distribution.
    pub shares: u32,
}

impl BandwidthParams {
    /// Validate the parameters.
    pub fn validate(&self) -> Result<()> {
        if self.quota_us != QUOTA_UNLIMITED && self.quota_us < 0 {
            return Err(Error::InvalidArgument);
        }
        if self.quota_us != QUOTA_UNLIMITED && (self.quota_us as u64) < MIN_QUOTA_US {
            return Err(Error::InvalidArgument);
        }
        if self.period_us < MIN_PERIOD_US || self.period_us > MAX_PERIOD_US {
            return Err(Error::InvalidArgument);
        }
        if self.shares == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Return the effective quota, accounting for unlimited.
    pub fn effective_quota_us(&self) -> Option<u64> {
        if self.quota_us == QUOTA_UNLIMITED {
            None
        } else {
            Some(self.quota_us as u64)
        }
    }

    /// Return the maximum burst for this configuration.
    pub fn computed_max_burst(&self) -> u64 {
        if self.max_burst_us > 0 {
            self.max_burst_us
        } else {
            self.period_us.saturating_mul(MAX_BURST_FACTOR)
        }
    }
}

impl Default for BandwidthParams {
    fn default() -> Self {
        Self {
            quota_us: QUOTA_UNLIMITED,
            period_us: DEFAULT_PERIOD_US,
            max_burst_us: 0,
            shares: 1024,
        }
    }
}

// ── ThrottleEvent ──────────────────────────────────────────────────

/// Record of a throttle event for diagnostics.
#[derive(Debug, Clone, Copy)]
pub struct ThrottleEvent {
    /// Timestamp when throttling started (microseconds since boot).
    pub start_us: u64,
    /// Duration of throttle (microseconds), 0 if still throttled.
    pub duration_us: u64,
    /// Runtime consumed before throttle.
    pub consumed_before_us: u64,
    /// Group ID that was throttled.
    pub group_id: u32,
}

impl Default for ThrottleEvent {
    fn default() -> Self {
        Self {
            start_us: 0,
            duration_us: 0,
            consumed_before_us: 0,
            group_id: 0,
        }
    }
}

// ── ThrottleHistory ────────────────────────────────────────────────

/// Ring buffer of recent throttle events for diagnostics.
#[derive(Debug)]
pub struct ThrottleHistory {
    /// Throttle event ring buffer.
    events: [ThrottleEvent; MAX_THROTTLE_HISTORY],
    /// Write index (wraps around).
    head: usize,
    /// Total number of events recorded.
    total_events: u64,
}

impl ThrottleHistory {
    /// Create an empty throttle history.
    pub const fn new() -> Self {
        Self {
            events: [const {
                ThrottleEvent {
                    start_us: 0,
                    duration_us: 0,
                    consumed_before_us: 0,
                    group_id: 0,
                }
            }; MAX_THROTTLE_HISTORY],
            head: 0,
            total_events: 0,
        }
    }

    /// Record a new throttle event.
    pub fn record(&mut self, event: ThrottleEvent) {
        self.events[self.head] = event;
        self.head = (self.head + 1) % MAX_THROTTLE_HISTORY;
        self.total_events = self.total_events.wrapping_add(1);
    }

    /// Return the most recent throttle event, if any.
    pub fn latest(&self) -> Option<&ThrottleEvent> {
        if self.total_events == 0 {
            return None;
        }
        let idx = if self.head == 0 {
            MAX_THROTTLE_HISTORY - 1
        } else {
            self.head - 1
        };
        Some(&self.events[idx])
    }

    /// Return total number of throttle events recorded.
    pub fn total_count(&self) -> u64 {
        self.total_events
    }

    /// Iterate over recorded events (newest first).
    pub fn recent_events(&self, count: usize) -> impl Iterator<Item = &ThrottleEvent> {
        let n = count.min(self.total_events.min(MAX_THROTTLE_HISTORY as u64) as usize);
        let start = if self.head >= n {
            self.head - n
        } else {
            MAX_THROTTLE_HISTORY - (n - self.head)
        };
        (0..n).map(move |i| {
            let idx = (start + i) % MAX_THROTTLE_HISTORY;
            &self.events[idx]
        })
    }
}

impl Default for ThrottleHistory {
    fn default() -> Self {
        Self::new()
    }
}

// ── BandwidthStats ─────────────────────────────────────────────────

/// Cumulative statistics for a bandwidth group.
#[derive(Debug, Clone, Copy)]
pub struct BandwidthStats {
    /// Number of times this group was throttled.
    pub throttle_count: u64,
    /// Total time spent throttled (microseconds).
    pub throttled_time_us: u64,
    /// Total runtime consumed (microseconds).
    pub total_runtime_us: u64,
    /// Number of periods completed.
    pub periods_completed: u64,
    /// Number of periods where quota was exhausted.
    pub periods_exhausted: u64,
    /// Peak burst usage (microseconds).
    pub peak_burst_us: u64,
    /// Average utilization over recent window (0-100 percent).
    pub avg_utilization_pct: u64,
    /// Number of slice distributions performed.
    pub slice_distributions: u64,
}

impl Default for BandwidthStats {
    fn default() -> Self {
        Self {
            throttle_count: 0,
            throttled_time_us: 0,
            total_runtime_us: 0,
            periods_completed: 0,
            periods_exhausted: 0,
            peak_burst_us: 0,
            avg_utilization_pct: 0,
            slice_distributions: 0,
        }
    }
}

// ── BandwidthPool ──────────────────────────────────────────────────

/// A bandwidth pool controlling CPU allocation for a group.
///
/// Each pool has quota/period parameters, runtime accounting,
/// throttle state, and statistics. Pools can be organized
/// hierarchically via [`HierarchyNode`].
#[derive(Debug)]
pub struct BandwidthPool {
    /// Unique pool identifier.
    pub id: u32,
    /// Human-readable name.
    name: [u8; MAX_NAME_LEN],
    /// Length of the name in bytes.
    name_len: usize,
    /// Configuration parameters.
    pub params: BandwidthParams,
    /// Runtime accounting state.
    pub runtime: RuntimeAccount,
    /// Current throttle state.
    pub state: ThrottleState,
    /// Cumulative statistics.
    pub stats: BandwidthStats,
    /// Timestamp of current period start.
    period_start_us: u64,
    /// Timestamp when throttling began (0 if not throttled).
    throttle_start_us: u64,
    /// Whether this pool is active.
    active: bool,
    /// Generation counter for ABA protection.
    generation: u64,
}

impl BandwidthPool {
    /// Create a new bandwidth pool.
    pub const fn new() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            params: BandwidthParams {
                quota_us: QUOTA_UNLIMITED,
                period_us: DEFAULT_PERIOD_US,
                max_burst_us: 0,
                shares: 1024,
            },
            runtime: RuntimeAccount {
                consumed_us: 0,
                remaining_us: 0,
                burst_us: 0,
                total_consumed_us: 0,
                last_update_us: 0,
                period_count: 0,
            },
            state: ThrottleState::Running,
            stats: BandwidthStats {
                throttle_count: 0,
                throttled_time_us: 0,
                total_runtime_us: 0,
                periods_completed: 0,
                periods_exhausted: 0,
                peak_burst_us: 0,
                avg_utilization_pct: 0,
                slice_distributions: 0,
            },
            period_start_us: 0,
            throttle_start_us: 0,
            active: false,
            generation: 0,
        }
    }

    /// Initialize a pool with the given ID, name, and parameters.
    pub fn init(&mut self, id: u32, name: &[u8], params: BandwidthParams) -> Result<()> {
        params.validate()?;
        if name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        self.id = id;
        self.name[..name.len()].copy_from_slice(name);
        self.name_len = name.len();
        self.params = params;
        let initial = params.effective_quota_us().unwrap_or(u64::MAX);
        self.runtime = RuntimeAccount::new(initial);
        self.state = ThrottleState::Running;
        self.stats = BandwidthStats::default();
        self.period_start_us = 0;
        self.throttle_start_us = 0;
        self.active = true;
        self.generation = self.generation.wrapping_add(1);
        Ok(())
    }

    /// Return the pool name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Check whether this pool is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Return the current generation counter.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Charge runtime and potentially trigger throttling.
    ///
    /// Returns the new throttle state after charging.
    pub fn charge_runtime(&mut self, delta_us: u64, now_us: u64) -> ThrottleState {
        if !self.active {
            return self.state;
        }

        // Unlimited quota never throttles
        if self.params.quota_us == QUOTA_UNLIMITED {
            self.runtime.consumed_us = self.runtime.consumed_us.saturating_add(delta_us);
            self.runtime.total_consumed_us =
                self.runtime.total_consumed_us.saturating_add(delta_us);
            self.stats.total_runtime_us = self.stats.total_runtime_us.saturating_add(delta_us);
            return ThrottleState::Running;
        }

        let still_has_runtime = self.runtime.charge(delta_us);
        self.stats.total_runtime_us = self.stats.total_runtime_us.saturating_add(delta_us);
        self.runtime.last_update_us = now_us;

        if !still_has_runtime && self.state == ThrottleState::Running {
            self.state = ThrottleState::Throttled;
            self.throttle_start_us = now_us;
            self.stats.throttle_count += 1;
        }

        self.state
    }

    /// Check if the current period has elapsed and replenish if so.
    ///
    /// Returns `true` if a new period started.
    pub fn tick(&mut self, now_us: u64) -> bool {
        if !self.active {
            return false;
        }

        let elapsed = now_us.saturating_sub(self.period_start_us);
        if elapsed < self.params.period_us {
            return false;
        }

        // Period elapsed — replenish
        self.stats.periods_completed += 1;

        if self.runtime.remaining_us == 0 && self.params.quota_us != QUOTA_UNLIMITED {
            self.stats.periods_exhausted += 1;
        }

        // Update utilization stats
        if let Some(quota) = self.params.effective_quota_us() {
            if quota > 0 {
                let util = (self.runtime.consumed_us * 100) / quota;
                let window = STAT_WINDOW_PERIODS;
                self.stats.avg_utilization_pct =
                    (self.stats.avg_utilization_pct * (window - 1) + util) / window;
            }
        }

        // Track peak burst
        if self.runtime.burst_us > self.stats.peak_burst_us {
            self.stats.peak_burst_us = self.runtime.burst_us;
        }

        let quota = self.params.effective_quota_us().unwrap_or(u64::MAX);
        let max_burst = self.params.computed_max_burst();
        self.runtime.replenish(quota, max_burst, now_us);
        self.period_start_us = now_us;

        // Un-throttle if we were throttled
        if self.state == ThrottleState::Throttled || self.state == ThrottleState::Expired {
            let throttle_duration = now_us.saturating_sub(self.throttle_start_us);
            self.stats.throttled_time_us = self
                .stats
                .throttled_time_us
                .saturating_add(throttle_duration);
            self.state = ThrottleState::Running;
            self.throttle_start_us = 0;
        }

        true
    }

    /// Distribute a runtime slice to a sub-entity.
    ///
    /// Returns the amount of runtime allocated (up to `max_slice_us`).
    pub fn distribute_slice(&mut self, max_slice_us: u64) -> u64 {
        if !self.active || self.state != ThrottleState::Running {
            return 0;
        }

        let available = self.runtime.remaining_us;
        let slice = available.min(max_slice_us).min(SLICE_GRANULARITY_US);
        self.stats.slice_distributions += 1;
        slice
    }

    /// Deactivate this pool.
    pub fn deactivate(&mut self) {
        self.active = false;
        self.state = ThrottleState::Expired;
    }

    /// Update bandwidth parameters on a live pool.
    pub fn update_params(&mut self, params: BandwidthParams) -> Result<()> {
        params.validate()?;
        self.params = params;
        self.generation = self.generation.wrapping_add(1);
        Ok(())
    }

    /// Return the utilization ratio (0-100) for the current period.
    pub fn current_utilization_pct(&self) -> u64 {
        match self.params.effective_quota_us() {
            Some(quota) if quota > 0 => (self.runtime.consumed_us * 100) / quota,
            _ => 0,
        }
    }

    /// Check if the pool should be un-throttled based on hysteresis.
    pub fn should_unthrottle(&self) -> bool {
        if self.state != ThrottleState::Throttled {
            return false;
        }
        match self.params.effective_quota_us() {
            Some(quota) if quota > 0 => {
                let threshold = (quota * UNTHROTTLE_HYSTERESIS_PCT) / 100;
                self.runtime.remaining_us >= threshold
            }
            _ => true,
        }
    }
}

impl Default for BandwidthPool {
    fn default() -> Self {
        Self::new()
    }
}

// ── HierarchyNode ──────────────────────────────────────────────────

/// A node in the bandwidth hierarchy tree.
///
/// Each node references a bandwidth pool and tracks parent/child
/// relationships for hierarchical bandwidth enforcement.
#[derive(Debug)]
pub struct HierarchyNode {
    /// Pool ID associated with this node.
    pub pool_id: u32,
    /// Parent node index (u32::MAX for root).
    pub parent_idx: u32,
    /// Child node indices.
    children: [u32; MAX_CHILDREN],
    /// Number of children.
    child_count: usize,
    /// Depth in the hierarchy (0 = root).
    pub depth: u32,
    /// Whether this node is active.
    active: bool,
    /// Weight relative to siblings.
    pub weight: u32,
    /// Allocated share of parent's bandwidth (microseconds).
    pub allocated_us: u64,
}

impl HierarchyNode {
    /// Create an empty hierarchy node.
    pub const fn new() -> Self {
        Self {
            pool_id: 0,
            parent_idx: u32::MAX,
            children: [0u32; MAX_CHILDREN],
            child_count: 0,
            depth: 0,
            active: false,
            weight: 1024,
            allocated_us: 0,
        }
    }

    /// Initialize a hierarchy node.
    pub fn init(&mut self, pool_id: u32, parent_idx: u32, depth: u32, weight: u32) -> Result<()> {
        if depth as usize >= MAX_HIERARCHY_DEPTH {
            return Err(Error::InvalidArgument);
        }
        if weight == 0 {
            return Err(Error::InvalidArgument);
        }
        self.pool_id = pool_id;
        self.parent_idx = parent_idx;
        self.depth = depth;
        self.weight = weight;
        self.child_count = 0;
        self.active = true;
        self.allocated_us = 0;
        Ok(())
    }

    /// Add a child node index.
    pub fn add_child(&mut self, child_idx: u32) -> Result<()> {
        if self.child_count >= MAX_CHILDREN {
            return Err(Error::OutOfMemory);
        }
        self.children[self.child_count] = child_idx;
        self.child_count += 1;
        Ok(())
    }

    /// Remove a child node index.
    pub fn remove_child(&mut self, child_idx: u32) -> Result<()> {
        let pos = self.children[..self.child_count]
            .iter()
            .position(|&c| c == child_idx)
            .ok_or(Error::NotFound)?;
        self.children[pos] = self.children[self.child_count - 1];
        self.child_count -= 1;
        Ok(())
    }

    /// Return the number of children.
    pub fn child_count(&self) -> usize {
        self.child_count
    }

    /// Return a slice of child indices.
    pub fn children(&self) -> &[u32] {
        &self.children[..self.child_count]
    }

    /// Whether this is a root node.
    pub fn is_root(&self) -> bool {
        self.parent_idx == u32::MAX
    }

    /// Whether this node is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Deactivate this node.
    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

impl Default for HierarchyNode {
    fn default() -> Self {
        Self::new()
    }
}

// ── CfsBandwidthController ─────────────────────────────────────────

/// System-wide CFS bandwidth controller.
///
/// Manages all bandwidth pools and their hierarchy. Provides
/// methods for creating, destroying, and ticking bandwidth groups.
pub struct CfsBandwidthController {
    /// All bandwidth pools.
    pools: [BandwidthPool; MAX_BANDWIDTH_GROUPS],
    /// Hierarchy nodes (one per pool).
    hierarchy: [HierarchyNode; MAX_BANDWIDTH_GROUPS],
    /// Throttle event history.
    history: ThrottleHistory,
    /// Next pool ID to allocate.
    next_id: u32,
    /// Number of active pools.
    active_count: usize,
    /// Global tick counter.
    tick_count: u64,
    /// Whether the controller is initialized.
    initialized: bool,
}

impl CfsBandwidthController {
    /// Create a new uninitialized controller.
    pub const fn new() -> Self {
        Self {
            pools: [const { BandwidthPool::new() }; MAX_BANDWIDTH_GROUPS],
            hierarchy: [const { HierarchyNode::new() }; MAX_BANDWIDTH_GROUPS],
            history: ThrottleHistory::new(),
            next_id: 1,
            active_count: 0,
            tick_count: 0,
            initialized: false,
        }
    }

    /// Initialize the controller.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.initialized = true;
        Ok(())
    }

    /// Create a new bandwidth group.
    ///
    /// Returns the pool ID on success.
    pub fn create_group(
        &mut self,
        name: &[u8],
        params: BandwidthParams,
        parent_id: Option<u32>,
    ) -> Result<u32> {
        if !self.initialized {
            return Err(Error::NotImplemented);
        }
        if self.active_count >= MAX_BANDWIDTH_GROUPS {
            return Err(Error::OutOfMemory);
        }

        let slot_idx = self
            .pools
            .iter()
            .position(|p| !p.is_active())
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        self.pools[slot_idx].init(id, name, params)?;

        // Set up hierarchy
        let (parent_idx, depth) = match parent_id {
            Some(pid) => {
                let pidx = self.find_pool_index(pid)?;
                let d = self.hierarchy[pidx].depth + 1;
                if d as usize >= MAX_HIERARCHY_DEPTH {
                    self.pools[slot_idx].deactivate();
                    return Err(Error::InvalidArgument);
                }
                (pidx as u32, d)
            }
            None => (u32::MAX, 0),
        };

        self.hierarchy[slot_idx].init(id, parent_idx, depth, params.shares)?;

        if parent_idx != u32::MAX {
            let pidx = parent_idx as usize;
            self.hierarchy[pidx].add_child(slot_idx as u32)?;
        }

        self.active_count += 1;
        Ok(id)
    }

    /// Destroy a bandwidth group by ID.
    pub fn destroy_group(&mut self, id: u32) -> Result<()> {
        let idx = self.find_pool_index(id)?;

        if self.hierarchy[idx].child_count() > 0 {
            return Err(Error::Busy);
        }

        // Remove from parent
        let parent_idx = self.hierarchy[idx].parent_idx;
        if parent_idx != u32::MAX {
            let pidx = parent_idx as usize;
            self.hierarchy[pidx].remove_child(idx as u32)?;
        }

        self.pools[idx].deactivate();
        self.hierarchy[idx].deactivate();
        self.active_count = self.active_count.saturating_sub(1);
        Ok(())
    }

    /// Charge runtime to a specific group.
    ///
    /// Propagates the charge up the hierarchy.
    pub fn charge_runtime(&mut self, id: u32, delta_us: u64, now_us: u64) -> Result<ThrottleState> {
        let idx = self.find_pool_index(id)?;
        let state = self.pools[idx].charge_runtime(delta_us, now_us);

        if state == ThrottleState::Throttled {
            self.history.record(ThrottleEvent {
                start_us: now_us,
                duration_us: 0,
                consumed_before_us: self.pools[idx].runtime.consumed_us,
                group_id: id,
            });
        }

        // Propagate charge up hierarchy
        let parent_idx = self.hierarchy[idx].parent_idx;
        if parent_idx != u32::MAX {
            let pidx = parent_idx as usize;
            if self.pools[pidx].is_active() {
                self.pools[pidx].charge_runtime(delta_us, now_us);
            }
        }

        Ok(state)
    }

    /// Perform a periodic tick on all active pools.
    ///
    /// Returns the number of pools that were replenished.
    pub fn tick(&mut self, now_us: u64) -> usize {
        self.tick_count = self.tick_count.wrapping_add(1);
        let mut replenished = 0;

        for pool in &mut self.pools {
            if pool.is_active() && pool.tick(now_us) {
                replenished += 1;
            }
        }

        replenished
    }

    /// Get the throttle state of a specific group.
    pub fn get_state(&self, id: u32) -> Result<ThrottleState> {
        let idx = self.find_pool_index(id)?;
        Ok(self.pools[idx].state)
    }

    /// Get statistics for a specific group.
    pub fn get_stats(&self, id: u32) -> Result<&BandwidthStats> {
        let idx = self.find_pool_index(id)?;
        Ok(&self.pools[idx].stats)
    }

    /// Get the runtime account for a specific group.
    pub fn get_runtime(&self, id: u32) -> Result<&RuntimeAccount> {
        let idx = self.find_pool_index(id)?;
        Ok(&self.pools[idx].runtime)
    }

    /// Update parameters for an existing group.
    pub fn update_params(&mut self, id: u32, params: BandwidthParams) -> Result<()> {
        let idx = self.find_pool_index(id)?;
        self.pools[idx].update_params(params)
    }

    /// Distribute bandwidth from parent to children
    /// proportionally by weight.
    pub fn distribute_hierarchical(&mut self, parent_id: u32, now_us: u64) -> Result<()> {
        let parent_idx = self.find_pool_index(parent_id)?;
        let available = self.pools[parent_idx].runtime.remaining_us;
        let child_indices: [u32; MAX_CHILDREN] = self.hierarchy[parent_idx].children;
        let child_count = self.hierarchy[parent_idx].child_count();

        if child_count == 0 {
            return Ok(());
        }

        // Sum weights of active children
        let total_weight: u64 = child_indices[..child_count]
            .iter()
            .filter(|&&ci| {
                let ci = ci as usize;
                ci < MAX_BANDWIDTH_GROUPS && self.hierarchy[ci].is_active()
            })
            .map(|&ci| self.hierarchy[ci as usize].weight as u64)
            .sum();

        if total_weight == 0 {
            return Ok(());
        }

        // Allocate proportionally
        for &ci in &child_indices[..child_count] {
            let ci = ci as usize;
            if ci < MAX_BANDWIDTH_GROUPS && self.hierarchy[ci].is_active() {
                let w = self.hierarchy[ci].weight as u64;
                let share = (available * w) / total_weight;
                self.hierarchy[ci].allocated_us = share;
                let _ = self.pools[ci].runtime.replenish(share, share, now_us);
            }
        }

        Ok(())
    }

    /// Return the number of active bandwidth groups.
    pub fn active_count(&self) -> usize {
        self.active_count
    }

    /// Return the global tick counter.
    pub fn tick_count(&self) -> u64 {
        self.tick_count
    }

    /// Return a reference to the throttle history.
    pub fn throttle_history(&self) -> &ThrottleHistory {
        &self.history
    }

    /// Find the internal index for a pool by ID.
    fn find_pool_index(&self, id: u32) -> Result<usize> {
        self.pools
            .iter()
            .position(|p| p.is_active() && p.id == id)
            .ok_or(Error::NotFound)
    }
}

impl Default for CfsBandwidthController {
    fn default() -> Self {
        Self::new()
    }
}
