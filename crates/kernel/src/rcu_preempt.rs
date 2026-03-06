// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Preemptible RCU — RCU variant that allows preemption in read
//! critical sections.
//!
//! Unlike classic RCU, preemptible RCU tracks readers that have been
//! preempted while holding an RCU read lock. Grace periods must wait
//! for all such preempted readers to finish before completing.
//!
//! # Architecture
//!
//! ```text
//! RcuPreemptState
//!  ├── per_cpu[MAX_CPUS]
//!  │    ├── nesting: i32
//!  │    ├── preempted: bool
//!  │    └── blocked_tasks: u32
//!  ├── gp_seq, completed
//!  ├── preempted_readers: u32
//!  └── stats: RcuPreemptStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/rcu/tree_plugin.h` — `CONFIG_PREEMPT_RCU`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum CPUs.
const MAX_CPUS: usize = 64;

// ══════════════════════════════════════════════════════════════
// PerCpuRcuPreempt
// ══════════════════════════════════════════════════════════════

/// Per-CPU preemptible RCU state.
#[derive(Debug, Clone, Copy)]
pub struct PerCpuRcuPreempt {
    /// Read-side nesting depth.
    pub nesting: i32,
    /// Whether a reader on this CPU is currently preempted.
    pub preempted: bool,
    /// Number of tasks blocked in RCU read sections on this CPU.
    pub blocked_tasks: u32,
    /// Quiescent state seen for current grace period.
    pub qs_passed: bool,
    /// Whether this CPU is online.
    pub online: bool,
    /// Total preemptions while in RCU read section.
    pub preempt_count: u64,
}

impl PerCpuRcuPreempt {
    /// Create per-CPU state.
    const fn new() -> Self {
        Self {
            nesting: 0,
            preempted: false,
            blocked_tasks: 0,
            qs_passed: false,
            online: false,
            preempt_count: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// RcuPreemptStats
// ══════════════════════════════════════════════════════════════

/// Preemptible RCU statistics.
#[derive(Debug, Clone, Copy)]
pub struct RcuPreemptStats {
    /// Grace periods completed.
    pub gp_completed: u64,
    /// Grace periods started.
    pub gp_started: u64,
    /// Total preemptions in read sections.
    pub total_preemptions: u64,
    /// Total blocked reader completions.
    pub total_unblocked: u64,
    /// Grace periods delayed by preempted readers.
    pub gp_delayed: u64,
}

impl RcuPreemptStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            gp_completed: 0,
            gp_started: 0,
            total_preemptions: 0,
            total_unblocked: 0,
            gp_delayed: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// RcuPreemptState
// ══════════════════════════════════════════════════════════════

/// Global preemptible RCU state.
pub struct RcuPreemptState {
    /// Per-CPU state.
    cpus: [PerCpuRcuPreempt; MAX_CPUS],
    /// Current grace period sequence.
    pub gp_seq: u64,
    /// Last completed grace period.
    pub completed: u64,
    /// Number of online CPUs.
    pub nr_cpus: u32,
    /// Number of currently preempted readers.
    pub preempted_readers: u32,
    /// Grace period in progress.
    pub gp_in_progress: bool,
    /// Statistics.
    pub stats: RcuPreemptStats,
}

impl RcuPreemptState {
    /// Create global preemptible RCU state.
    pub const fn new() -> Self {
        Self {
            cpus: [const { PerCpuRcuPreempt::new() }; MAX_CPUS],
            gp_seq: 0,
            completed: 0,
            nr_cpus: 1,
            preempted_readers: 0,
            gp_in_progress: false,
            stats: RcuPreemptStats::new(),
        }
    }

    /// Bring a CPU online.
    pub fn cpu_online(&mut self, cpu: u32) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpus[c].online = true;
        if cpu >= self.nr_cpus {
            self.nr_cpus = cpu + 1;
        }
        Ok(())
    }

    /// Enter an RCU read-side critical section.
    pub fn rcu_read_lock(&mut self, cpu: u32) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS || !self.cpus[c].online {
            return Err(Error::InvalidArgument);
        }
        self.cpus[c].nesting += 1;
        Ok(())
    }

    /// Exit an RCU read-side critical section.
    pub fn rcu_read_unlock(&mut self, cpu: u32) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS || !self.cpus[c].online {
            return Err(Error::InvalidArgument);
        }
        if self.cpus[c].nesting <= 0 {
            return Err(Error::InvalidArgument);
        }
        self.cpus[c].nesting -= 1;
        if self.cpus[c].nesting == 0 {
            self.cpus[c].qs_passed = true;
            // If we were preempted, unblock.
            if self.cpus[c].preempted {
                self.cpus[c].preempted = false;
                self.cpus[c].blocked_tasks = self.cpus[c].blocked_tasks.saturating_sub(1);
                self.preempted_readers = self.preempted_readers.saturating_sub(1);
                self.stats.total_unblocked += 1;
            }
        }
        Ok(())
    }

    /// Report that a task was preempted while in an RCU read section.
    pub fn report_preempt(&mut self, cpu: u32) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS || !self.cpus[c].online {
            return Err(Error::InvalidArgument);
        }
        if self.cpus[c].nesting > 0 {
            self.cpus[c].preempted = true;
            self.cpus[c].blocked_tasks += 1;
            self.cpus[c].preempt_count += 1;
            self.preempted_readers += 1;
            self.stats.total_preemptions += 1;
        }
        Ok(())
    }

    /// Start a new grace period.
    pub fn start_grace_period(&mut self) {
        self.gp_seq += 1;
        self.gp_in_progress = true;
        self.stats.gp_started += 1;
        for c in 0..self.nr_cpus as usize {
            if self.cpus[c].online {
                self.cpus[c].qs_passed = false;
            }
        }
    }

    /// Try to complete the current grace period.
    ///
    /// Succeeds only if all CPUs have passed a quiescent state
    /// AND there are no preempted readers from before this GP.
    pub fn try_complete(&mut self) -> bool {
        if !self.gp_in_progress {
            return false;
        }
        // All online CPUs must have passed QS.
        for c in 0..self.nr_cpus as usize {
            if self.cpus[c].online && !self.cpus[c].qs_passed {
                return false;
            }
        }
        // No preempted readers may remain.
        if self.preempted_readers > 0 {
            self.stats.gp_delayed += 1;
            return false;
        }
        self.completed = self.gp_seq;
        self.gp_in_progress = false;
        self.stats.gp_completed += 1;
        true
    }

    /// Report a quiescent state on a CPU (e.g., context switch).
    pub fn report_qs(&mut self, cpu: u32) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS || !self.cpus[c].online {
            return Err(Error::InvalidArgument);
        }
        if self.cpus[c].nesting == 0 {
            self.cpus[c].qs_passed = true;
        }
        Ok(())
    }

    /// Return per-CPU state.
    pub fn per_cpu(&self, cpu: u32) -> Result<&PerCpuRcuPreempt> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.cpus[c])
    }

    /// Return statistics.
    pub fn stats(&self) -> RcuPreemptStats {
        self.stats
    }
}
