// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Completely Fair Scheduler (CFS) implementation.
//!
//! Implements a proportional-share CPU scheduler modelled on the Linux
//! CFS. Each schedulable entity accumulates *virtual runtime* (vruntime)
//! inversely proportional to its weight, so that higher-weight
//! (lower-nice) tasks run more frequently.
//!
//! # Architecture
//!
//! ```text
//! CfsScheduler
//!  ├── CfsRunqueue[MAX_CPUS]   (per-CPU run queues)
//!  │    ├── entities: [SchedEntity; MAX_ENTITIES]
//!  │    ├── sorted_idx: [u16; MAX_ENTITIES]   (sorted by vruntime)
//!  │    ├── min_vruntime: u64
//!  │    └── nr_running / load_weight
//!  ├── CfsBandwidth (per-CPU throttling)
//!  └── CfsStats (global counters)
//! ```
//!
//! The sorted index array acts as a virtual rb-tree: entities are
//! ordered by vruntime so `pick_next_entity` always selects index 0.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum CPUs supported.
const MAX_CPUS: usize = 64;

/// Maximum schedulable entities per run queue.
const MAX_ENTITIES: usize = 256;

/// Default scheduler latency in microseconds (6 ms).
const SCHED_LATENCY_US: u64 = 6_000;

/// Minimum granularity in microseconds (750 us).
const SCHED_MIN_GRANULARITY_US: u64 = 750;

/// Default weight for nice 0 tasks.
const NICE_0_WEIGHT: u64 = 1024;

/// Weight table indexed by nice value + 20 (nice -20..19 maps to 0..39).
const WEIGHT_TABLE: [u64; 40] = [
    88761, 71755, 56483, 46273, 36291, 29154, 23254, 18705, 14949, 11916, 9548, 7620, 6100, 4904,
    3906, 3121, 2501, 1991, 1586, 1277, 1024, 820, 655, 526, 423, 335, 272, 215, 172, 137, 110, 87,
    70, 56, 45, 36, 29, 23, 18, 15,
];

// ======================================================================
// Types
// ======================================================================

/// Scheduling entity tracked by the CFS run queue.
#[derive(Clone, Copy)]
pub struct SchedEntity {
    /// Task identifier (PID).
    pub pid: u64,
    /// Accumulated virtual runtime in nanoseconds.
    pub vruntime: u64,
    /// Weight derived from nice value.
    pub weight: u64,
    /// Nice value (-20..19).
    pub nice: i8,
    /// Total wall-clock execution time (nanoseconds).
    pub sum_exec_runtime: u64,
    /// Whether this slot is occupied.
    pub active: bool,
    /// Timestamp when entity was last scheduled in (nanoseconds).
    pub exec_start: u64,
    /// Number of involuntary context switches.
    pub nr_involuntary_switches: u64,
}

impl SchedEntity {
    /// Creates an empty (inactive) entity.
    pub const fn new() -> Self {
        Self {
            pid: 0,
            vruntime: 0,
            weight: NICE_0_WEIGHT,
            nice: 0,
            sum_exec_runtime: 0,
            active: false,
            exec_start: 0,
            nr_involuntary_switches: 0,
        }
    }
}

/// Per-CPU CFS run queue.
pub struct CfsRunqueue {
    /// Entity pool.
    entities: [SchedEntity; MAX_ENTITIES],
    /// Indices into `entities` sorted by ascending vruntime.
    sorted_idx: [u16; MAX_ENTITIES],
    /// Number of sorted entries.
    nr_sorted: usize,
    /// Number of runnable entities.
    pub nr_running: u32,
    /// Sum of weights of all runnable entities.
    pub load_weight: u64,
    /// Minimum vruntime ever observed (monotonic).
    pub min_vruntime: u64,
    /// Currently running entity index, or `None`.
    pub current_idx: Option<u16>,
    /// Whether bandwidth throttling is active.
    pub throttled: bool,
}

impl CfsRunqueue {
    /// Creates an empty run queue.
    pub const fn new() -> Self {
        Self {
            entities: [const { SchedEntity::new() }; MAX_ENTITIES],
            sorted_idx: [0u16; MAX_ENTITIES],
            nr_sorted: 0,
            nr_running: 0,
            load_weight: 0,
            min_vruntime: 0,
            current_idx: None,
            throttled: false,
        }
    }

    /// Enqueues a new task. Returns the entity index.
    pub fn enqueue_entity(&mut self, pid: u64, nice: i8) -> Result<u16> {
        let nice_idx = (nice as i32 + 20).clamp(0, 39) as usize;
        let weight = WEIGHT_TABLE[nice_idx];

        // Find a free slot.
        let slot = self
            .entities
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;

        self.entities[slot].pid = pid;
        self.entities[slot].nice = nice;
        self.entities[slot].weight = weight;
        self.entities[slot].vruntime = self.min_vruntime;
        self.entities[slot].active = true;
        self.entities[slot].sum_exec_runtime = 0;
        self.entities[slot].exec_start = 0;
        self.entities[slot].nr_involuntary_switches = 0;

        self.nr_running += 1;
        self.load_weight += weight;

        self.insert_sorted(slot as u16);

        Ok(slot as u16)
    }

    /// Dequeues an entity by index.
    pub fn dequeue_entity(&mut self, idx: u16) -> Result<()> {
        let i = idx as usize;
        if i >= MAX_ENTITIES || !self.entities[i].active {
            return Err(Error::NotFound);
        }

        let weight = self.entities[i].weight;
        self.entities[i].active = false;
        self.nr_running = self.nr_running.saturating_sub(1);
        self.load_weight = self.load_weight.saturating_sub(weight);

        self.remove_sorted(idx);

        if self.current_idx == Some(idx) {
            self.current_idx = None;
        }

        Ok(())
    }

    /// Picks the next entity (lowest vruntime). Returns entity index.
    pub fn pick_next_entity(&self) -> Option<u16> {
        if self.nr_sorted == 0 || self.throttled {
            return None;
        }
        Some(self.sorted_idx[0])
    }

    /// Called when the current entity is being preempted or yielded.
    /// Re-inserts it into the sorted array at the correct position.
    pub fn put_prev_entity(&mut self, idx: u16) -> Result<()> {
        let i = idx as usize;
        if i >= MAX_ENTITIES || !self.entities[i].active {
            return Err(Error::NotFound);
        }
        // Remove and re-insert to maintain sort order.
        self.remove_sorted(idx);
        self.insert_sorted(idx);
        Ok(())
    }

    /// Updates the currently running entity's vruntime.
    ///
    /// `now_ns` is the current monotonic time in nanoseconds.
    pub fn update_curr(&mut self, now_ns: u64) -> Result<()> {
        let idx = match self.current_idx {
            Some(i) => i as usize,
            None => return Ok(()),
        };

        if idx >= MAX_ENTITIES || !self.entities[idx].active {
            return Err(Error::InvalidArgument);
        }

        let exec_start = self.entities[idx].exec_start;
        if now_ns <= exec_start {
            return Ok(());
        }

        let delta_exec = now_ns - exec_start;
        self.entities[idx].sum_exec_runtime += delta_exec;
        self.entities[idx].exec_start = now_ns;

        // vruntime += delta_exec * NICE_0_WEIGHT / weight
        let weight = self.entities[idx].weight.max(1);
        let delta_vruntime = delta_exec
            .saturating_mul(NICE_0_WEIGHT)
            .checked_div(weight)
            .unwrap_or(0);
        self.entities[idx].vruntime += delta_vruntime;

        // Advance min_vruntime monotonically.
        let new_vruntime = self.entities[idx].vruntime;
        if new_vruntime > self.min_vruntime {
            self.min_vruntime = new_vruntime;
        }
        // If there is a leftmost entity, use its vruntime if lower.
        if self.nr_sorted > 0 {
            let left_idx = self.sorted_idx[0] as usize;
            let left_vrt = self.entities[left_idx].vruntime;
            if left_vrt < self.min_vruntime {
                self.min_vruntime = left_vrt;
            }
        }

        Ok(())
    }

    /// Sets the current entity and records the start timestamp.
    pub fn set_current(&mut self, idx: u16, now_ns: u64) -> Result<()> {
        let i = idx as usize;
        if i >= MAX_ENTITIES || !self.entities[i].active {
            return Err(Error::NotFound);
        }
        self.entities[i].exec_start = now_ns;
        self.current_idx = Some(idx);
        self.remove_sorted(idx);
        Ok(())
    }

    /// Computes the ideal timeslice for an entity in nanoseconds.
    pub fn calc_timeslice(&self, idx: u16) -> u64 {
        let i = idx as usize;
        if i >= MAX_ENTITIES || !self.entities[i].active {
            return 0;
        }
        let nr = (self.nr_running as u64).max(1);
        let latency = SCHED_LATENCY_US * 1_000; // to ns
        let slice = latency
            .saturating_mul(self.entities[i].weight)
            .checked_div(self.load_weight.max(1))
            .unwrap_or(0);
        slice.max(SCHED_MIN_GRANULARITY_US * 1_000 / nr)
    }

    /// Returns an immutable reference to an entity.
    pub fn entity(&self, idx: u16) -> Option<&SchedEntity> {
        let i = idx as usize;
        if i < MAX_ENTITIES && self.entities[i].active {
            Some(&self.entities[i])
        } else {
            None
        }
    }

    // ------------------------------------------------------------------
    // Internal sorted-index helpers
    // ------------------------------------------------------------------

    fn insert_sorted(&mut self, idx: u16) {
        if self.nr_sorted >= MAX_ENTITIES {
            return;
        }
        let vrt = self.entities[idx as usize].vruntime;
        // Binary search for insertion point.
        let pos = self.sorted_idx[..self.nr_sorted]
            .iter()
            .position(|&si| self.entities[si as usize].vruntime > vrt)
            .unwrap_or(self.nr_sorted);
        // Shift right.
        let mut j = self.nr_sorted;
        while j > pos {
            self.sorted_idx[j] = self.sorted_idx[j - 1];
            j -= 1;
        }
        self.sorted_idx[pos] = idx;
        self.nr_sorted += 1;
    }

    fn remove_sorted(&mut self, idx: u16) {
        if let Some(pos) = self.sorted_idx[..self.nr_sorted]
            .iter()
            .position(|&si| si == idx)
        {
            let mut j = pos;
            while j + 1 < self.nr_sorted {
                self.sorted_idx[j] = self.sorted_idx[j + 1];
                j += 1;
            }
            self.nr_sorted -= 1;
        }
    }
}

// ======================================================================
// CFS Bandwidth
// ======================================================================

/// Per-CPU bandwidth control for CFS tasks.
pub struct CfsBandwidth {
    /// Allowed CPU time quota per period (microseconds). 0 = unlimited.
    pub quota_us: u64,
    /// Period length in microseconds.
    pub period_us: u64,
    /// Remaining runtime in the current period (microseconds).
    pub runtime_remaining: u64,
    /// Whether the run queue is currently throttled.
    pub throttled: bool,
    /// Number of times throttling occurred.
    pub nr_throttled: u64,
    /// Total throttled time in microseconds.
    pub throttled_time: u64,
}

impl CfsBandwidth {
    /// Creates unlimited bandwidth (no throttling).
    pub const fn new() -> Self {
        Self {
            quota_us: 0,
            period_us: 100_000,
            runtime_remaining: 0,
            throttled: false,
            nr_throttled: 0,
            throttled_time: 0,
        }
    }

    /// Configures bandwidth quota and period.
    pub fn set_bandwidth(&mut self, quota_us: u64, period_us: u64) -> Result<()> {
        if period_us == 0 {
            return Err(Error::InvalidArgument);
        }
        self.quota_us = quota_us;
        self.period_us = period_us;
        self.runtime_remaining = quota_us;
        self.throttled = false;
        Ok(())
    }

    /// Charges `delta_us` microseconds of runtime. Returns `true` if
    /// the budget is exhausted and throttling should begin.
    pub fn charge_runtime(&mut self, delta_us: u64) -> bool {
        if self.quota_us == 0 {
            return false; // unlimited
        }
        if delta_us >= self.runtime_remaining {
            self.runtime_remaining = 0;
            self.throttled = true;
            self.nr_throttled += 1;
            true
        } else {
            self.runtime_remaining -= delta_us;
            false
        }
    }

    /// Replenishes the runtime budget (called at period boundaries).
    pub fn replenish(&mut self) {
        self.runtime_remaining = self.quota_us;
        self.throttled = false;
    }
}

// ======================================================================
// CFS Statistics
// ======================================================================

/// Global CFS scheduling statistics.
pub struct CfsStats {
    /// Total wall-clock runtime across all entities (nanoseconds).
    pub total_runtime: u64,
    /// Number of context switches.
    pub nr_switches: u64,
    /// Number of throttle events.
    pub nr_throttles: u64,
    /// Cumulative scheduling latency (nanoseconds).
    pub latency_sum: u64,
    /// Peak scheduling latency (nanoseconds).
    pub latency_max: u64,
}

impl CfsStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_runtime: 0,
            nr_switches: 0,
            nr_throttles: 0,
            latency_sum: 0,
            latency_max: 0,
        }
    }

    /// Records a context switch with given scheduling latency.
    pub fn record_switch(&mut self, latency_ns: u64) {
        self.nr_switches += 1;
        self.latency_sum += latency_ns;
        if latency_ns > self.latency_max {
            self.latency_max = latency_ns;
        }
    }
}

// ======================================================================
// CfsScheduler — top-level
// ======================================================================

/// Top-level CFS scheduler managing per-CPU run queues.
pub struct CfsScheduler {
    /// Per-CPU run queues.
    rqs: [CfsRunqueue; MAX_CPUS],
    /// Per-CPU bandwidth controllers.
    bw: [CfsBandwidth; MAX_CPUS],
    /// Global statistics.
    pub stats: CfsStats,
    /// Number of active CPUs.
    pub nr_cpus: u32,
}

impl CfsScheduler {
    /// Creates a CFS scheduler with all run queues empty.
    pub const fn new() -> Self {
        Self {
            rqs: [const { CfsRunqueue::new() }; MAX_CPUS],
            bw: [const { CfsBandwidth::new() }; MAX_CPUS],
            stats: CfsStats::new(),
            nr_cpus: 1,
        }
    }

    /// Enqueues a task on the specified CPU's run queue.
    pub fn enqueue_task(&mut self, cpu: u32, pid: u64, nice: i8) -> Result<u16> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.rqs[c].enqueue_entity(pid, nice)
    }

    /// Dequeues a task from the specified CPU's run queue.
    pub fn dequeue_task(&mut self, cpu: u32, idx: u16) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.rqs[c].dequeue_entity(idx)
    }

    /// Picks the next task to run on the given CPU.
    pub fn pick_next_task(&self, cpu: u32) -> Option<u16> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return None;
        }
        self.rqs[c].pick_next_entity()
    }

    /// Updates the currently running task's vruntime on the given CPU.
    pub fn update_curr(&mut self, cpu: u32, now_ns: u64) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.rqs[c].update_curr(now_ns)
    }

    /// Performs a schedule tick: update current, check preemption,
    /// check bandwidth. Returns `true` if a reschedule is needed.
    pub fn scheduler_tick(&mut self, cpu: u32, now_ns: u64) -> Result<bool> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        self.rqs[c].update_curr(now_ns)?;

        let current_idx = match self.rqs[c].current_idx {
            Some(i) => i,
            None => return Ok(false),
        };

        // Check if timeslice expired.
        let timeslice = self.rqs[c].calc_timeslice(current_idx);
        let i = current_idx as usize;
        let delta = now_ns.saturating_sub(self.rqs[c].entities[i].exec_start);
        if delta >= timeslice {
            self.rqs[c].entities[i].nr_involuntary_switches += 1;
            return Ok(true);
        }

        // Check if a new entity has lower vruntime.
        if let Some(next) = self.rqs[c].pick_next_entity() {
            let cur_vrt = self.rqs[c].entities[i].vruntime;
            let next_vrt = self.rqs[c].entities[next as usize].vruntime;
            if next_vrt + SCHED_MIN_GRANULARITY_US * 1_000 < cur_vrt {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Returns immutable access to a per-CPU run queue.
    pub fn runqueue(&self, cpu: u32) -> Option<&CfsRunqueue> {
        let c = cpu as usize;
        if c < MAX_CPUS {
            Some(&self.rqs[c])
        } else {
            None
        }
    }

    /// Returns mutable access to a per-CPU bandwidth controller.
    pub fn bandwidth_mut(&mut self, cpu: u32) -> Option<&mut CfsBandwidth> {
        let c = cpu as usize;
        if c < MAX_CPUS {
            Some(&mut self.bw[c])
        } else {
            None
        }
    }

    /// Attempts load balancing by migrating a task from the busiest
    /// CPU to the idlest CPU. Returns `true` if a migration occurred.
    pub fn load_balance(&mut self) -> bool {
        if self.nr_cpus < 2 {
            return false;
        }
        let cpus = self.nr_cpus as usize;
        let mut busiest = 0usize;
        let mut idlest = 0usize;
        let mut max_load = 0u32;
        let mut min_load = u32::MAX;

        for c in 0..cpus {
            let nr = self.rqs[c].nr_running;
            if nr > max_load {
                max_load = nr;
                busiest = c;
            }
            if nr < min_load {
                min_load = nr;
                idlest = c;
            }
        }

        if busiest == idlest || max_load <= min_load + 1 {
            return false;
        }

        // Find the entity with the highest vruntime on the busiest CPU
        // (least urgent) and migrate it.
        let nr = self.rqs[busiest].nr_sorted;
        if nr == 0 {
            return false;
        }
        let migrate_idx = self.rqs[busiest].sorted_idx[nr - 1];
        let mi = migrate_idx as usize;
        let pid = self.rqs[busiest].entities[mi].pid;
        let nice = self.rqs[busiest].entities[mi].nice;

        if self.rqs[busiest].dequeue_entity(migrate_idx).is_err() {
            return false;
        }
        self.rqs[idlest].enqueue_entity(pid, nice).is_ok()
    }
}
