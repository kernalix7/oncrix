// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Scheduler load tracking and balancing subsystem.
//!
//! Implements per-entity load tracking (PELT-style) for tasks
//! and CPU runqueues. Tracks running, runnable, and utilization
//! signals to enable load-balanced task placement across CPUs.
//! The load balancer periodically rebalances to prevent CPU
//! imbalance and improve throughput.

use oncrix_lib::{Error, Result};

/// Maximum number of CPUs for load tracking.
const MAX_CPUS: usize = 256;

/// Maximum number of load balance domains.
const MAX_DOMAINS: usize = 16;

/// PELT half-life period in milliseconds.
const _PELT_HALF_LIFE_MS: u64 = 32;

/// Load balance interval in milliseconds.
const _BALANCE_INTERVAL_MS: u64 = 4;

/// Imbalance threshold percentage for triggering migration.
const IMBALANCE_THRESHOLD_PCT: u64 = 25;

/// Per-entity load tracking signal.
#[derive(Clone, Copy)]
pub struct LoadSignal {
    /// Running average (time the entity was on-CPU).
    running_avg: u64,
    /// Runnable average (time on runqueue, including running).
    runnable_avg: u64,
    /// Utilization average.
    util_avg: u64,
    /// Load average (weighted by priority).
    load_avg: u64,
    /// Last update timestamp in nanoseconds.
    last_update_ns: u64,
    /// Accumulated running time in the current period.
    running_sum: u64,
    /// Accumulated runnable time in the current period.
    runnable_sum: u64,
    /// Period counter.
    period_count: u64,
}

impl LoadSignal {
    /// Creates a new load signal.
    pub const fn new() -> Self {
        Self {
            running_avg: 0,
            runnable_avg: 0,
            util_avg: 0,
            load_avg: 0,
            last_update_ns: 0,
            running_sum: 0,
            runnable_sum: 0,
            period_count: 0,
        }
    }

    /// Returns the running average.
    pub const fn running_avg(&self) -> u64 {
        self.running_avg
    }

    /// Returns the runnable average.
    pub const fn runnable_avg(&self) -> u64 {
        self.runnable_avg
    }

    /// Returns the utilization average.
    pub const fn util_avg(&self) -> u64 {
        self.util_avg
    }

    /// Returns the load average.
    pub const fn load_avg(&self) -> u64 {
        self.load_avg
    }

    /// Updates the load signal with a new sample.
    pub fn update(&mut self, now_ns: u64, is_running: bool, is_runnable: bool, weight: u64) {
        if now_ns <= self.last_update_ns {
            return;
        }
        let delta_ns = now_ns - self.last_update_ns;
        // Convert to microseconds for calculation
        let delta_us = delta_ns / 1000;

        if is_running {
            self.running_sum += delta_us;
        }
        if is_runnable {
            self.runnable_sum += delta_us;
        }

        // Each period is ~1024us (~1ms)
        let periods = delta_us / 1024;
        if periods > 0 {
            // Decay old values (approximate exponential decay)
            let decay = if periods > 32 { 0 } else { 32 - periods };
            self.running_avg = (self.running_avg * decay + self.running_sum * 32) / 64;
            self.runnable_avg = (self.runnable_avg * decay + self.runnable_sum * 32) / 64;
            self.util_avg = self.running_avg;
            self.load_avg = (self.runnable_avg * weight) / 1024;

            self.running_sum = 0;
            self.runnable_sum = 0;
            self.period_count += periods;
        }

        self.last_update_ns = now_ns;
    }

    /// Resets the load signal to zero.
    pub fn reset(&mut self) {
        self.running_avg = 0;
        self.runnable_avg = 0;
        self.util_avg = 0;
        self.load_avg = 0;
        self.running_sum = 0;
        self.runnable_sum = 0;
    }
}

impl Default for LoadSignal {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-CPU runqueue load statistics.
#[derive(Clone, Copy)]
pub struct CpuLoad {
    /// CPU identifier.
    cpu_id: u32,
    /// Aggregate load from all tasks on this CPU.
    aggregate_load: LoadSignal,
    /// Number of runnable tasks.
    nr_runnable: u32,
    /// Number of running tasks (0 or 1 typically).
    nr_running: u32,
    /// CPU capacity (scaled, 1024 = full capacity).
    capacity: u64,
    /// Available capacity after accounting for load.
    available_capacity: u64,
    /// Whether this CPU is idle.
    is_idle: bool,
}

impl CpuLoad {
    /// Creates a new CPU load entry.
    pub const fn new() -> Self {
        Self {
            cpu_id: 0,
            aggregate_load: LoadSignal::new(),
            nr_runnable: 0,
            nr_running: 0,
            capacity: 1024,
            available_capacity: 1024,
            is_idle: true,
        }
    }

    /// Returns the CPU identifier.
    pub const fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Returns the number of runnable tasks.
    pub const fn nr_runnable(&self) -> u32 {
        self.nr_runnable
    }

    /// Returns the CPU capacity.
    pub const fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Returns available capacity.
    pub const fn available_capacity(&self) -> u64 {
        self.available_capacity
    }

    /// Returns whether this CPU is idle.
    pub const fn is_idle(&self) -> bool {
        self.is_idle
    }

    /// Updates the available capacity based on current load.
    pub fn update_available_capacity(&mut self) {
        let used = self.aggregate_load.util_avg();
        self.available_capacity = if used >= self.capacity {
            0
        } else {
            self.capacity - used
        };
        self.is_idle = self.nr_runnable == 0;
    }

    /// Adds a task to this CPU's runqueue.
    pub fn enqueue_task(&mut self, load: u64) {
        self.nr_runnable += 1;
        self.aggregate_load.load_avg += load;
        self.is_idle = false;
    }

    /// Removes a task from this CPU's runqueue.
    pub fn dequeue_task(&mut self, load: u64) {
        if self.nr_runnable > 0 {
            self.nr_runnable -= 1;
        }
        self.aggregate_load.load_avg = self.aggregate_load.load_avg.saturating_sub(load);
        self.is_idle = self.nr_runnable == 0;
    }
}

impl Default for CpuLoad {
    fn default() -> Self {
        Self::new()
    }
}

/// Load balance domain grouping CPUs for balance decisions.
#[derive(Clone, Copy)]
pub struct BalanceDomain {
    /// Domain identifier.
    id: u32,
    /// First CPU in this domain.
    first_cpu: u32,
    /// Number of CPUs in this domain.
    cpu_count: u32,
    /// Total load across all CPUs in this domain.
    total_load: u64,
    /// Average load per CPU.
    avg_load: u64,
    /// Balance interval in milliseconds.
    balance_interval_ms: u64,
    /// Last balance timestamp.
    last_balance_ns: u64,
}

impl BalanceDomain {
    /// Creates a new balance domain.
    pub const fn new() -> Self {
        Self {
            id: 0,
            first_cpu: 0,
            cpu_count: 0,
            total_load: 0,
            avg_load: 0,
            balance_interval_ms: 4,
            last_balance_ns: 0,
        }
    }

    /// Returns the domain identifier.
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Returns the average load in this domain.
    pub const fn avg_load(&self) -> u64 {
        self.avg_load
    }

    /// Returns the number of CPUs in this domain.
    pub const fn cpu_count(&self) -> u32 {
        self.cpu_count
    }
}

impl Default for BalanceDomain {
    fn default() -> Self {
        Self::new()
    }
}

/// Scheduler load balancer.
pub struct SchedLoadBalancer {
    /// Per-CPU load information.
    cpu_loads: [CpuLoad; MAX_CPUS],
    /// Number of active CPUs.
    cpu_count: usize,
    /// Balance domains.
    domains: [BalanceDomain; MAX_DOMAINS],
    /// Number of active domains.
    domain_count: usize,
    /// Total system load.
    system_load: u64,
    /// Number of load balance operations performed.
    balance_count: u64,
    /// Number of task migrations performed.
    migration_count: u64,
}

impl SchedLoadBalancer {
    /// Creates a new scheduler load balancer.
    pub const fn new() -> Self {
        Self {
            cpu_loads: [const { CpuLoad::new() }; MAX_CPUS],
            cpu_count: 0,
            domains: [const { BalanceDomain::new() }; MAX_DOMAINS],
            domain_count: 0,
            system_load: 0,
            balance_count: 0,
            migration_count: 0,
        }
    }

    /// Registers a CPU for load tracking.
    pub fn register_cpu(&mut self, cpu_id: u32, capacity: u64) -> Result<()> {
        if self.cpu_count >= MAX_CPUS {
            return Err(Error::OutOfMemory);
        }
        self.cpu_loads[self.cpu_count].cpu_id = cpu_id;
        self.cpu_loads[self.cpu_count].capacity = capacity;
        self.cpu_loads[self.cpu_count].available_capacity = capacity;
        self.cpu_count += 1;
        Ok(())
    }

    /// Creates a new load balance domain.
    pub fn create_domain(&mut self, first_cpu: u32, cpu_count: u32) -> Result<u32> {
        if self.domain_count >= MAX_DOMAINS {
            return Err(Error::OutOfMemory);
        }
        let id = self.domain_count as u32;
        self.domains[self.domain_count] = BalanceDomain {
            id,
            first_cpu,
            cpu_count,
            total_load: 0,
            avg_load: 0,
            balance_interval_ms: 4,
            last_balance_ns: 0,
        };
        self.domain_count += 1;
        Ok(id)
    }

    /// Finds the busiest CPU in the system.
    pub fn find_busiest_cpu(&self) -> Result<u32> {
        if self.cpu_count == 0 {
            return Err(Error::NotFound);
        }
        let mut busiest_idx = 0;
        let mut max_load = 0u64;
        for i in 0..self.cpu_count {
            let load = self.cpu_loads[i].aggregate_load.load_avg;
            if load > max_load {
                max_load = load;
                busiest_idx = i;
            }
        }
        Ok(self.cpu_loads[busiest_idx].cpu_id)
    }

    /// Finds the most idle CPU in the system.
    pub fn find_idlest_cpu(&self) -> Result<u32> {
        if self.cpu_count == 0 {
            return Err(Error::NotFound);
        }
        let mut idlest_idx = 0;
        let mut max_avail = 0u64;
        for i in 0..self.cpu_count {
            if self.cpu_loads[i].available_capacity > max_avail {
                max_avail = self.cpu_loads[i].available_capacity;
                idlest_idx = i;
            }
        }
        Ok(self.cpu_loads[idlest_idx].cpu_id)
    }

    /// Checks if load balancing is needed between two CPUs.
    pub fn needs_balance(&self, src_cpu: u32, dst_cpu: u32) -> Result<bool> {
        let src = self.cpu_loads[..self.cpu_count]
            .iter()
            .find(|c| c.cpu_id == src_cpu)
            .ok_or(Error::NotFound)?;
        let dst = self.cpu_loads[..self.cpu_count]
            .iter()
            .find(|c| c.cpu_id == dst_cpu)
            .ok_or(Error::NotFound)?;
        let src_load = src.aggregate_load.load_avg;
        let dst_load = dst.aggregate_load.load_avg;
        if src_load == 0 {
            return Ok(false);
        }
        let imbalance = if src_load > dst_load {
            src_load - dst_load
        } else {
            0
        };
        let threshold = (src_load * IMBALANCE_THRESHOLD_PCT) / 100;
        Ok(imbalance > threshold)
    }

    /// Returns the number of active CPUs.
    pub const fn cpu_count(&self) -> usize {
        self.cpu_count
    }

    /// Returns the total number of migrations performed.
    pub const fn migration_count(&self) -> u64 {
        self.migration_count
    }

    /// Increments the migration counter.
    pub fn record_migration(&mut self) {
        self.migration_count += 1;
    }

    /// Returns the total number of balance operations.
    pub const fn balance_count(&self) -> u64 {
        self.balance_count
    }
}

impl Default for SchedLoadBalancer {
    fn default() -> Self {
        Self::new()
    }
}
