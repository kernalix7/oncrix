// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Scheduler CPU accounting.
//!
//! Tracks per-task and per-CPU time accounting for the scheduler.
//! Records user time, system time, idle time, iowait, softirq,
//! and hardirq time. Used for /proc/stat-style reporting and
//! fair scheduling decisions.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum CPUs tracked.
const MAX_CPUS: usize = 64;

/// Maximum tasks tracked.
const MAX_TASKS: usize = 1024;

/// Nanoseconds per jiffy (assuming 250 Hz).
const _NS_PER_JIFFY: u64 = 4_000_000;

// ── Types ────────────────────────────────────────────────────────────

/// CPU time breakdown categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuTimeCategory {
    /// Time in user mode.
    User,
    /// Time in user mode with nice priority.
    Nice,
    /// Time in kernel mode.
    System,
    /// Idle time.
    Idle,
    /// Waiting for I/O.
    IoWait,
    /// Servicing hardware interrupts.
    HardIrq,
    /// Servicing software interrupts.
    SoftIrq,
    /// Stolen time (virtualization).
    Steal,
    /// Guest time.
    Guest,
}

/// Per-CPU time accounting record.
#[derive(Debug, Clone)]
pub struct CpuTimeAccounting {
    /// CPU identifier.
    cpu_id: u32,
    /// User time in nanoseconds.
    user_ns: u64,
    /// Nice user time in nanoseconds.
    nice_ns: u64,
    /// System time in nanoseconds.
    system_ns: u64,
    /// Idle time in nanoseconds.
    idle_ns: u64,
    /// I/O wait time in nanoseconds.
    iowait_ns: u64,
    /// Hardware IRQ time in nanoseconds.
    hardirq_ns: u64,
    /// Software IRQ time in nanoseconds.
    softirq_ns: u64,
    /// Steal time in nanoseconds.
    steal_ns: u64,
    /// Guest time in nanoseconds.
    guest_ns: u64,
    /// Last accounting update timestamp.
    last_update_ns: u64,
}

impl CpuTimeAccounting {
    /// Creates a new per-CPU time accounting record.
    pub const fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            user_ns: 0,
            nice_ns: 0,
            system_ns: 0,
            idle_ns: 0,
            iowait_ns: 0,
            hardirq_ns: 0,
            softirq_ns: 0,
            steal_ns: 0,
            guest_ns: 0,
            last_update_ns: 0,
        }
    }

    /// Returns the total busy time (non-idle).
    pub const fn busy_ns(&self) -> u64 {
        self.user_ns + self.nice_ns + self.system_ns + self.hardirq_ns + self.softirq_ns
    }

    /// Returns the total wall time.
    pub const fn total_ns(&self) -> u64 {
        self.user_ns
            + self.nice_ns
            + self.system_ns
            + self.idle_ns
            + self.iowait_ns
            + self.hardirq_ns
            + self.softirq_ns
            + self.steal_ns
            + self.guest_ns
    }

    /// Returns the CPU identifier.
    pub const fn cpu_id(&self) -> u32 {
        self.cpu_id
    }
}

/// Per-task CPU time accounting.
#[derive(Debug, Clone)]
pub struct TaskTimeAccounting {
    /// Task PID.
    pid: u64,
    /// User CPU time in nanoseconds.
    utime_ns: u64,
    /// System CPU time in nanoseconds.
    stime_ns: u64,
    /// Voluntary context switches.
    voluntary_switches: u64,
    /// Involuntary context switches.
    involuntary_switches: u64,
    /// Time spent runnable but not running (wait time).
    wait_ns: u64,
    /// Last schedule-in timestamp.
    last_sched_in_ns: u64,
    /// Sum of all run periods.
    sum_exec_runtime_ns: u64,
}

impl TaskTimeAccounting {
    /// Creates a new task time accounting record.
    pub const fn new(pid: u64) -> Self {
        Self {
            pid,
            utime_ns: 0,
            stime_ns: 0,
            voluntary_switches: 0,
            involuntary_switches: 0,
            wait_ns: 0,
            last_sched_in_ns: 0,
            sum_exec_runtime_ns: 0,
        }
    }

    /// Returns total CPU time (user + system).
    pub const fn total_cpu_ns(&self) -> u64 {
        self.utime_ns + self.stime_ns
    }

    /// Returns the PID.
    pub const fn pid(&self) -> u64 {
        self.pid
    }

    /// Returns the sum of execution runtime.
    pub const fn sum_exec_runtime_ns(&self) -> u64 {
        self.sum_exec_runtime_ns
    }
}

/// System-wide accounting summary.
#[derive(Debug, Clone)]
pub struct AccountingSummary {
    /// Total user time across all CPUs.
    pub total_user_ns: u64,
    /// Total system time across all CPUs.
    pub total_system_ns: u64,
    /// Total idle time across all CPUs.
    pub total_idle_ns: u64,
    /// Number of CPUs tracked.
    pub cpu_count: u32,
    /// Number of tasks tracked.
    pub task_count: u32,
    /// Total context switches.
    pub total_context_switches: u64,
}

impl Default for AccountingSummary {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountingSummary {
    /// Creates a zeroed summary.
    pub const fn new() -> Self {
        Self {
            total_user_ns: 0,
            total_system_ns: 0,
            total_idle_ns: 0,
            cpu_count: 0,
            task_count: 0,
            total_context_switches: 0,
        }
    }
}

/// Central scheduler accounting manager.
#[derive(Debug)]
pub struct SchedAccountingManager {
    /// Per-CPU accounting records.
    cpu_acct: [Option<CpuTimeAccounting>; MAX_CPUS],
    /// Per-task accounting records.
    task_acct: [Option<TaskTimeAccounting>; MAX_TASKS],
    /// Number of CPUs.
    cpu_count: usize,
    /// Number of tasks.
    task_count: usize,
    /// Total accounting updates.
    total_updates: u64,
}

impl Default for SchedAccountingManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SchedAccountingManager {
    /// Creates a new accounting manager.
    pub const fn new() -> Self {
        Self {
            cpu_acct: [const { None }; MAX_CPUS],
            task_acct: [const { None }; MAX_TASKS],
            cpu_count: 0,
            task_count: 0,
            total_updates: 0,
        }
    }

    /// Registers a CPU for accounting.
    pub fn register_cpu(&mut self, cpu_id: u32) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.cpu_acct[idx].is_some() {
            return Err(Error::AlreadyExists);
        }
        self.cpu_acct[idx] = Some(CpuTimeAccounting::new(cpu_id));
        self.cpu_count += 1;
        Ok(())
    }

    /// Registers a task for accounting.
    pub fn register_task(&mut self, pid: u64) -> Result<()> {
        if self.task_count >= MAX_TASKS {
            return Err(Error::OutOfMemory);
        }
        for slot in self.task_acct.iter().flatten() {
            if slot.pid == pid {
                return Err(Error::AlreadyExists);
            }
        }
        let acct = TaskTimeAccounting::new(pid);
        if let Some(slot) = self.task_acct.iter_mut().find(|s| s.is_none()) {
            *slot = Some(acct);
            self.task_count += 1;
            Ok(())
        } else {
            Err(Error::OutOfMemory)
        }
    }

    /// Accounts CPU time for a CPU.
    pub fn account_cpu_time(
        &mut self,
        cpu_id: u32,
        category: CpuTimeCategory,
        delta_ns: u64,
    ) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let acct = self.cpu_acct[idx].as_mut().ok_or(Error::NotFound)?;
        match category {
            CpuTimeCategory::User => acct.user_ns += delta_ns,
            CpuTimeCategory::Nice => acct.nice_ns += delta_ns,
            CpuTimeCategory::System => acct.system_ns += delta_ns,
            CpuTimeCategory::Idle => acct.idle_ns += delta_ns,
            CpuTimeCategory::IoWait => acct.iowait_ns += delta_ns,
            CpuTimeCategory::HardIrq => acct.hardirq_ns += delta_ns,
            CpuTimeCategory::SoftIrq => acct.softirq_ns += delta_ns,
            CpuTimeCategory::Steal => acct.steal_ns += delta_ns,
            CpuTimeCategory::Guest => acct.guest_ns += delta_ns,
        }
        self.total_updates += 1;
        Ok(())
    }

    /// Accounts task execution time.
    pub fn account_task_time(&mut self, pid: u64, user_ns: u64, system_ns: u64) -> Result<()> {
        let acct = self
            .task_acct
            .iter_mut()
            .flatten()
            .find(|a| a.pid == pid)
            .ok_or(Error::NotFound)?;
        acct.utime_ns += user_ns;
        acct.stime_ns += system_ns;
        acct.sum_exec_runtime_ns += user_ns + system_ns;
        self.total_updates += 1;
        Ok(())
    }

    /// Records a context switch for a task.
    pub fn record_context_switch(&mut self, pid: u64, voluntary: bool) -> Result<()> {
        let acct = self
            .task_acct
            .iter_mut()
            .flatten()
            .find(|a| a.pid == pid)
            .ok_or(Error::NotFound)?;
        if voluntary {
            acct.voluntary_switches += 1;
        } else {
            acct.involuntary_switches += 1;
        }
        Ok(())
    }

    /// Unregisters a task.
    pub fn unregister_task(&mut self, pid: u64) -> Result<()> {
        let slot = self
            .task_acct
            .iter_mut()
            .find(|s| s.as_ref().map_or(false, |a| a.pid == pid))
            .ok_or(Error::NotFound)?;
        *slot = None;
        self.task_count -= 1;
        Ok(())
    }

    /// Returns a system-wide summary.
    pub fn summary(&self) -> AccountingSummary {
        let mut s = AccountingSummary::new();
        s.cpu_count = self.cpu_count as u32;
        s.task_count = self.task_count as u32;
        for acct in self.cpu_acct.iter().flatten() {
            s.total_user_ns += acct.user_ns + acct.nice_ns;
            s.total_system_ns += acct.system_ns;
            s.total_idle_ns += acct.idle_ns;
        }
        for acct in self.task_acct.iter().flatten() {
            s.total_context_switches += acct.voluntary_switches + acct.involuntary_switches;
        }
        s
    }

    /// Returns the number of tracked CPUs.
    pub const fn cpu_count(&self) -> usize {
        self.cpu_count
    }

    /// Returns the number of tracked tasks.
    pub const fn task_count(&self) -> usize {
        self.task_count
    }
}
