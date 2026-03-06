// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Task migration between CPUs.
//!
//! Implements the pull/push migration logic that the scheduler uses
//! to balance load across CPUs. When one CPU's run queue becomes
//! significantly longer than another's, tasks are migrated to the
//! less loaded CPU.
//!
//! # Migration Triggers
//!
//! - **Periodic rebalance** — the scheduler tick checks load every
//!   few milliseconds.
//! - **Idle balance** — a CPU that runs out of tasks pulls from
//!   busy neighbours.
//! - **Active balance** — a CPU pushes tasks to an idle CPU when
//!   it has more than one runnable task.
//!
//! # Architecture
//!
//! ```text
//! MigrationManager
//!  ├── cpu_loads: [CpuLoad; MAX_CPUS]
//!  ├── pending: [MigrationRequest; MAX_PENDING]
//!  ├── stats: MigrationStats
//!  └── config: MigrationConfig
//! ```

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum CPUs.
const MAX_CPUS: usize = 64;

/// Maximum pending migration requests.
const MAX_PENDING: usize = 128;

/// Default load imbalance threshold (percentage).
const DEFAULT_IMBALANCE_THRESHOLD: u32 = 25;

/// Default migration cost in nanoseconds (cache penalty).
const DEFAULT_MIGRATION_COST_NS: u64 = 500_000;

// ======================================================================
// Types
// ======================================================================

/// Migration trigger reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationReason {
    /// Periodic load balancing.
    PeriodicBalance,
    /// Idle CPU pulling work.
    IdleBalance,
    /// Busy CPU pushing excess work.
    ActiveBalance,
    /// Explicit affinity change.
    AffinityChange,
    /// NUMA placement.
    NumaPlacement,
}

impl Default for MigrationReason {
    fn default() -> Self {
        Self::PeriodicBalance
    }
}

/// Per-CPU load tracking.
#[derive(Debug, Clone, Copy)]
pub struct CpuLoad {
    /// CPU identifier.
    pub cpu_id: u32,
    /// Number of runnable tasks.
    pub nr_running: u32,
    /// Weighted load (sum of task weights).
    pub weighted_load: u64,
    /// Average load over the last period.
    pub avg_load: u64,
    /// Whether this CPU is online.
    pub online: bool,
    /// Whether this CPU is idle (nr_running == 0).
    pub idle: bool,
}

impl CpuLoad {
    /// Creates a default CPU load entry.
    pub const fn new() -> Self {
        Self {
            cpu_id: 0,
            nr_running: 0,
            weighted_load: 0,
            avg_load: 0,
            online: false,
            idle: true,
        }
    }
}

impl Default for CpuLoad {
    fn default() -> Self {
        Self::new()
    }
}

/// A pending migration request.
#[derive(Debug, Clone, Copy)]
pub struct MigrationRequest {
    /// PID of the task to migrate.
    pub pid: u64,
    /// Source CPU.
    pub src_cpu: u32,
    /// Destination CPU.
    pub dst_cpu: u32,
    /// Reason for migration.
    pub reason: MigrationReason,
    /// Whether this request is active.
    pub active: bool,
    /// Whether migration was completed.
    pub completed: bool,
}

impl MigrationRequest {
    /// Creates an empty migration request.
    pub const fn new() -> Self {
        Self {
            pid: 0,
            src_cpu: 0,
            dst_cpu: 0,
            reason: MigrationReason::PeriodicBalance,
            active: false,
            completed: false,
        }
    }
}

impl Default for MigrationRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Migration statistics.
#[derive(Debug, Clone, Copy)]
pub struct MigrationStats {
    /// Total migrations attempted.
    pub total_attempts: u64,
    /// Successful migrations.
    pub total_success: u64,
    /// Migrations blocked by affinity.
    pub affinity_blocked: u64,
    /// Migrations blocked by migration cost.
    pub cost_blocked: u64,
    /// Pull migrations (idle balance).
    pub pull_count: u64,
    /// Push migrations (active balance).
    pub push_count: u64,
}

impl MigrationStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_attempts: 0,
            total_success: 0,
            affinity_blocked: 0,
            cost_blocked: 0,
            pull_count: 0,
            push_count: 0,
        }
    }
}

impl Default for MigrationStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Migration configuration.
#[derive(Debug, Clone, Copy)]
pub struct MigrationConfig {
    /// Load imbalance threshold (percentage, 0-100).
    pub imbalance_threshold: u32,
    /// Migration cost in nanoseconds.
    pub migration_cost_ns: u64,
    /// Whether NUMA-aware migration is enabled.
    pub numa_aware: bool,
}

impl MigrationConfig {
    /// Creates a default migration configuration.
    pub const fn new() -> Self {
        Self {
            imbalance_threshold: DEFAULT_IMBALANCE_THRESHOLD,
            migration_cost_ns: DEFAULT_MIGRATION_COST_NS,
            numa_aware: true,
        }
    }
}

impl Default for MigrationConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Manages task migration decisions.
pub struct MigrationManager {
    /// Per-CPU load data.
    cpu_loads: [CpuLoad; MAX_CPUS],
    /// Number of online CPUs.
    nr_cpus: u32,
    /// Pending migration requests.
    pending: [MigrationRequest; MAX_PENDING],
    /// Number of pending requests.
    nr_pending: usize,
    /// Statistics.
    stats: MigrationStats,
    /// Configuration.
    config: MigrationConfig,
}

impl MigrationManager {
    /// Creates a new migration manager.
    pub const fn new() -> Self {
        Self {
            cpu_loads: [CpuLoad::new(); MAX_CPUS],
            nr_cpus: 1,
            pending: [MigrationRequest::new(); MAX_PENDING],
            nr_pending: 0,
            stats: MigrationStats::new(),
            config: MigrationConfig::new(),
        }
    }

    /// Sets the number of online CPUs and initialises load entries.
    pub fn set_nr_cpus(&mut self, nr: u32) -> Result<()> {
        if nr == 0 || (nr as usize) > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.nr_cpus = nr;
        for i in 0..(nr as usize) {
            self.cpu_loads[i].cpu_id = i as u32;
            self.cpu_loads[i].online = true;
        }
        Ok(())
    }

    /// Updates the load for a specific CPU.
    pub fn update_load(&mut self, cpu_id: u32, nr_running: u32, weighted_load: u64) -> Result<()> {
        if (cpu_id as usize) >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let entry = &mut self.cpu_loads[cpu_id as usize];
        entry.nr_running = nr_running;
        entry.weighted_load = weighted_load;
        entry.idle = nr_running == 0;
        // Exponential moving average.
        entry.avg_load = (entry.avg_load * 3 + weighted_load) / 4;
        Ok(())
    }

    /// Finds the busiest and most idle CPUs.
    pub fn find_imbalance(&self) -> Option<(u32, u32)> {
        let mut busiest_cpu = 0u32;
        let mut busiest_load = 0u64;
        let mut idlest_cpu = 0u32;
        let mut idlest_load = u64::MAX;

        for i in 0..(self.nr_cpus as usize) {
            let load = &self.cpu_loads[i];
            if !load.online {
                continue;
            }
            if load.avg_load > busiest_load {
                busiest_load = load.avg_load;
                busiest_cpu = i as u32;
            }
            if load.avg_load < idlest_load {
                idlest_load = load.avg_load;
                idlest_cpu = i as u32;
            }
        }

        if busiest_load == 0 || busiest_cpu == idlest_cpu {
            return None;
        }

        let diff = busiest_load - idlest_load;
        let threshold = busiest_load * self.config.imbalance_threshold as u64 / 100;
        if diff > threshold {
            Some((busiest_cpu, idlest_cpu))
        } else {
            None
        }
    }

    /// Submits a migration request.
    pub fn submit(
        &mut self,
        pid: u64,
        src_cpu: u32,
        dst_cpu: u32,
        reason: MigrationReason,
    ) -> Result<usize> {
        if src_cpu == dst_cpu {
            return Err(Error::InvalidArgument);
        }
        if self.nr_pending >= MAX_PENDING {
            return Err(Error::OutOfMemory);
        }
        for (i, req) in self.pending.iter_mut().enumerate() {
            if !req.active {
                *req = MigrationRequest {
                    pid,
                    src_cpu,
                    dst_cpu,
                    reason,
                    active: true,
                    completed: false,
                };
                self.nr_pending += 1;
                self.stats.total_attempts += 1;
                match reason {
                    MigrationReason::IdleBalance => {
                        self.stats.pull_count += 1;
                    }
                    MigrationReason::ActiveBalance => {
                        self.stats.push_count += 1;
                    }
                    _ => {}
                }
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Marks a migration request as completed.
    pub fn complete(&mut self, index: usize, success: bool) -> Result<()> {
        if index >= MAX_PENDING {
            return Err(Error::InvalidArgument);
        }
        if !self.pending[index].active {
            return Err(Error::NotFound);
        }
        self.pending[index].completed = true;
        self.pending[index].active = false;
        self.nr_pending = self.nr_pending.saturating_sub(1);
        if success {
            self.stats.total_success += 1;
        }
        Ok(())
    }

    /// Returns migration statistics.
    pub fn stats(&self) -> &MigrationStats {
        &self.stats
    }

    /// Returns the number of pending requests.
    pub fn nr_pending(&self) -> usize {
        self.nr_pending
    }
}

impl Default for MigrationManager {
    fn default() -> Self {
        Self::new()
    }
}
