// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-CPU and per-task time accounting.
//!
//! Tracks how CPU time is distributed across user mode, system mode,
//! guest mode, IRQ handling, softirq, and steal time. Each CPU
//! maintains running counters that are updated on context switches,
//! timer ticks, and IRQ entry/exit.
//!
//! # Accounting Categories
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │ Total CPU time = user + system + idle + iowait  │
//! │                + irq + softirq + steal + guest   │
//! │                                                  │
//! │  user     — normal user-space execution          │
//! │  nice     — low-priority user-space execution    │
//! │  system   — kernel-mode execution                │
//! │  idle     — idle loop                            │
//! │  iowait   — idle while I/O pending               │
//! │  irq      — hardware interrupt handling          │
//! │  softirq  — software interrupt handling          │
//! │  steal    — time stolen by hypervisor            │
//! │  guest    — running a virtual CPU                │
//! └─────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `kernel/sched/cputime.c`, `include/linux/kernel_stat.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum number of CPUs.
const MAX_CPUS: usize = 64;

/// Maximum number of tasks for per-task accounting.
const MAX_TASKS: usize = 1024;

/// Clock ticks per second (USER_HZ, for /proc/stat).
const _USER_HZ: u64 = 100;

/// Nanoseconds per clock tick.
const NSEC_PER_TICK: u64 = 10_000_000; // 10ms at 100Hz

/// Nanoseconds per second.
const _NSEC_PER_SEC: u64 = 1_000_000_000;

// ======================================================================
// CPU time category
// ======================================================================

/// CPU time accounting categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuTimeCategory {
    /// Normal user-space execution.
    User = 0,
    /// Nice (low-priority) user-space execution.
    Nice = 1,
    /// Kernel-mode execution.
    System = 2,
    /// Idle time.
    Idle = 3,
    /// I/O wait time.
    IoWait = 4,
    /// Hardware interrupt handling.
    Irq = 5,
    /// Software interrupt handling.
    SoftIrq = 6,
    /// Time stolen by hypervisor.
    Steal = 7,
    /// Guest (virtual CPU) time.
    Guest = 8,
    /// Guest nice time.
    GuestNice = 9,
}

/// Number of accounting categories.
const NUM_CATEGORIES: usize = 10;

impl CpuTimeCategory {
    /// Returns the category index.
    pub fn index(self) -> usize {
        self as usize
    }

    /// Creates from an index.
    pub fn from_index(idx: usize) -> Result<Self> {
        match idx {
            0 => Ok(Self::User),
            1 => Ok(Self::Nice),
            2 => Ok(Self::System),
            3 => Ok(Self::Idle),
            4 => Ok(Self::IoWait),
            5 => Ok(Self::Irq),
            6 => Ok(Self::SoftIrq),
            7 => Ok(Self::Steal),
            8 => Ok(Self::Guest),
            9 => Ok(Self::GuestNice),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ======================================================================
// Per-CPU accounting
// ======================================================================

/// CPU time counters for a single CPU (all values in nanoseconds).
#[derive(Debug, Clone, Copy)]
pub struct CpuAccounting {
    /// Time in each category (nanoseconds).
    times: [u64; NUM_CATEGORIES],
    /// CPU index.
    cpu: u32,
    /// Whether this CPU is online.
    online: bool,
    /// Timestamp of last accounting update (ns).
    last_update_ns: u64,
    /// Currently active category.
    current_category: CpuTimeCategory,
    /// Start time of current category accounting (ns).
    category_start_ns: u64,
}

impl CpuAccounting {
    /// Creates zeroed CPU accounting.
    pub const fn new() -> Self {
        Self {
            times: [0; NUM_CATEGORIES],
            cpu: 0,
            online: false,
            last_update_ns: 0,
            current_category: CpuTimeCategory::Idle,
            category_start_ns: 0,
        }
    }

    /// Returns the CPU index.
    pub fn cpu(&self) -> u32 {
        self.cpu
    }

    /// Returns whether this CPU is online.
    pub fn is_online(&self) -> bool {
        self.online
    }

    /// Returns time in a specific category (nanoseconds).
    pub fn time_ns(&self, category: CpuTimeCategory) -> u64 {
        self.times[category.index()]
    }

    /// Returns user time in nanoseconds.
    pub fn utime_ns(&self) -> u64 {
        self.times[CpuTimeCategory::User.index()]
    }

    /// Returns system time in nanoseconds.
    pub fn stime_ns(&self) -> u64 {
        self.times[CpuTimeCategory::System.index()]
    }

    /// Returns guest time in nanoseconds.
    pub fn gtime_ns(&self) -> u64 {
        self.times[CpuTimeCategory::Guest.index()]
    }

    /// Returns steal time in nanoseconds.
    pub fn steal_ns(&self) -> u64 {
        self.times[CpuTimeCategory::Steal.index()]
    }

    /// Returns IRQ time in nanoseconds.
    pub fn irq_ns(&self) -> u64 {
        self.times[CpuTimeCategory::Irq.index()]
    }

    /// Returns softirq time in nanoseconds.
    pub fn softirq_ns(&self) -> u64 {
        self.times[CpuTimeCategory::SoftIrq.index()]
    }

    /// Returns idle time in nanoseconds.
    pub fn idle_ns(&self) -> u64 {
        self.times[CpuTimeCategory::Idle.index()]
    }

    /// Returns total busy time (everything except idle + iowait).
    pub fn busy_ns(&self) -> u64 {
        let total: u64 = self.times.iter().sum();
        total
            .saturating_sub(self.idle_ns())
            .saturating_sub(self.times[CpuTimeCategory::IoWait.index()])
    }

    /// Converts nanoseconds to clock_t (USER_HZ ticks).
    pub fn cputime_to_clock_t(ns: u64) -> u64 {
        ns / NSEC_PER_TICK
    }

    /// Accounts time in a category.
    pub fn account_time(&mut self, category: CpuTimeCategory, delta_ns: u64) {
        self.times[category.index()] = self.times[category.index()].saturating_add(delta_ns);
    }

    /// Switches the currently active category and accounts elapsed
    /// time.
    pub fn switch_category(&mut self, new_category: CpuTimeCategory, now_ns: u64) {
        let elapsed = now_ns.saturating_sub(self.category_start_ns);
        self.account_time(self.current_category, elapsed);
        self.current_category = new_category;
        self.category_start_ns = now_ns;
        self.last_update_ns = now_ns;
    }

    /// Accounts user time for the current tick.
    pub fn account_user_time(&mut self, delta_ns: u64) {
        self.account_time(CpuTimeCategory::User, delta_ns);
    }

    /// Accounts system time for the current tick.
    pub fn account_system_time(&mut self, delta_ns: u64) {
        self.account_time(CpuTimeCategory::System, delta_ns);
    }

    /// Accounts IRQ time.
    pub fn account_irq_time(&mut self, delta_ns: u64) {
        self.account_time(CpuTimeCategory::Irq, delta_ns);
    }

    /// Accounts steal time.
    pub fn account_steal_time(&mut self, delta_ns: u64) {
        self.account_time(CpuTimeCategory::Steal, delta_ns);
    }

    /// Accounts guest time.
    pub fn account_guest_time(&mut self, delta_ns: u64) {
        self.account_time(CpuTimeCategory::Guest, delta_ns);
        // Guest time is also accounted as user time.
        self.account_time(CpuTimeCategory::User, delta_ns);
    }

    /// Accounts idle time.
    pub fn account_idle_time(&mut self, delta_ns: u64) {
        self.account_time(CpuTimeCategory::Idle, delta_ns);
    }

    /// Returns all times as clock_t array.
    pub fn as_clock_t(&self) -> [u64; NUM_CATEGORIES] {
        let mut result = [0u64; NUM_CATEGORIES];
        for i in 0..NUM_CATEGORIES {
            result[i] = Self::cputime_to_clock_t(self.times[i]);
        }
        result
    }
}

// ======================================================================
// Per-task accounting
// ======================================================================

/// Per-task CPU time accounting.
#[derive(Debug, Clone, Copy)]
pub struct TaskCpuAcct {
    /// PID.
    pid: u32,
    /// User time in nanoseconds.
    utime_ns: u64,
    /// System time in nanoseconds.
    stime_ns: u64,
    /// Guest time in nanoseconds.
    gtime_ns: u64,
    /// Voluntary context switches.
    nvcsw: u64,
    /// Involuntary context switches.
    nivcsw: u64,
    /// Start time (nanoseconds since boot).
    start_time_ns: u64,
    /// Whether this slot is occupied.
    active: bool,
    /// CPU this task last ran on.
    last_cpu: u32,
    /// Timestamp of last accounting sample (ns).
    last_sample_ns: u64,
    /// Sum of execution time (for CFS vruntime).
    sum_exec_runtime_ns: u64,
}

impl TaskCpuAcct {
    /// Creates an empty task accounting entry.
    pub const fn new() -> Self {
        Self {
            pid: 0,
            utime_ns: 0,
            stime_ns: 0,
            gtime_ns: 0,
            nvcsw: 0,
            nivcsw: 0,
            start_time_ns: 0,
            active: false,
            last_cpu: 0,
            last_sample_ns: 0,
            sum_exec_runtime_ns: 0,
        }
    }

    /// Returns the PID.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns user time in nanoseconds.
    pub fn utime_ns(&self) -> u64 {
        self.utime_ns
    }

    /// Returns system time in nanoseconds.
    pub fn stime_ns(&self) -> u64 {
        self.stime_ns
    }

    /// Returns guest time in nanoseconds.
    pub fn gtime_ns(&self) -> u64 {
        self.gtime_ns
    }

    /// Returns the total CPU time (user + system).
    pub fn total_time_ns(&self) -> u64 {
        self.utime_ns.saturating_add(self.stime_ns)
    }

    /// Returns voluntary context switches.
    pub fn voluntary_switches(&self) -> u64 {
        self.nvcsw
    }

    /// Returns involuntary context switches.
    pub fn involuntary_switches(&self) -> u64 {
        self.nivcsw
    }

    /// Returns the sum of execution runtime.
    pub fn sum_exec_runtime_ns(&self) -> u64 {
        self.sum_exec_runtime_ns
    }

    /// Accounts user time.
    pub fn account_user(&mut self, delta_ns: u64) {
        self.utime_ns = self.utime_ns.saturating_add(delta_ns);
        self.sum_exec_runtime_ns = self.sum_exec_runtime_ns.saturating_add(delta_ns);
    }

    /// Accounts system time.
    pub fn account_system(&mut self, delta_ns: u64) {
        self.stime_ns = self.stime_ns.saturating_add(delta_ns);
        self.sum_exec_runtime_ns = self.sum_exec_runtime_ns.saturating_add(delta_ns);
    }

    /// Accounts guest time.
    pub fn account_guest(&mut self, delta_ns: u64) {
        self.gtime_ns = self.gtime_ns.saturating_add(delta_ns);
    }

    /// Records a voluntary context switch.
    pub fn record_voluntary_switch(&mut self) {
        self.nvcsw = self.nvcsw.saturating_add(1);
    }

    /// Records an involuntary context switch.
    pub fn record_involuntary_switch(&mut self) {
        self.nivcsw = self.nivcsw.saturating_add(1);
    }
}

// ======================================================================
// CPU accounting manager
// ======================================================================

/// Global CPU accounting manager.
pub struct CpuAccountingManager {
    /// Per-CPU accounting.
    cpus: [CpuAccounting; MAX_CPUS],
    /// Per-task accounting.
    tasks: [TaskCpuAcct; MAX_TASKS],
    /// Number of online CPUs.
    nr_cpus: u32,
    /// Number of active tasks.
    nr_tasks: usize,
    /// Boot time in nanoseconds (monotonic).
    boot_time_ns: u64,
}

impl CpuAccountingManager {
    /// Creates a new CPU accounting manager.
    pub const fn new() -> Self {
        Self {
            cpus: [const { CpuAccounting::new() }; MAX_CPUS],
            tasks: [const { TaskCpuAcct::new() }; MAX_TASKS],
            nr_cpus: 0,
            nr_tasks: 0,
            boot_time_ns: 0,
        }
    }

    /// Initializes the manager.
    pub fn init(&mut self, nr_cpus: u32, boot_time_ns: u64) -> Result<()> {
        if nr_cpus == 0 || nr_cpus as usize > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.nr_cpus = nr_cpus;
        self.boot_time_ns = boot_time_ns;
        for i in 0..nr_cpus as usize {
            self.cpus[i].cpu = i as u32;
            self.cpus[i].online = true;
        }
        Ok(())
    }

    /// Returns the number of online CPUs.
    pub fn nr_cpus(&self) -> u32 {
        self.nr_cpus
    }

    /// Returns per-CPU accounting.
    pub fn cpu(&self, cpu: u32) -> Result<&CpuAccounting> {
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.cpus[cpu as usize])
    }

    /// Returns mutable per-CPU accounting.
    pub fn cpu_mut(&mut self, cpu: u32) -> Result<&mut CpuAccounting> {
        if cpu as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.cpus[cpu as usize])
    }

    /// Registers a new task.
    pub fn register_task(&mut self, pid: u32, start_time_ns: u64) -> Result<usize> {
        let slot = self
            .tasks
            .iter()
            .position(|t| !t.active)
            .ok_or(Error::OutOfMemory)?;
        self.tasks[slot].pid = pid;
        self.tasks[slot].start_time_ns = start_time_ns;
        self.tasks[slot].active = true;
        self.tasks[slot].utime_ns = 0;
        self.tasks[slot].stime_ns = 0;
        self.tasks[slot].gtime_ns = 0;
        self.tasks[slot].nvcsw = 0;
        self.tasks[slot].nivcsw = 0;
        self.tasks[slot].sum_exec_runtime_ns = 0;
        self.nr_tasks += 1;
        Ok(slot)
    }

    /// Unregisters a task.
    pub fn unregister_task(&mut self, pid: u32) -> Result<()> {
        let slot = self.find_task(pid)?;
        self.tasks[slot].active = false;
        self.nr_tasks = self.nr_tasks.saturating_sub(1);
        Ok(())
    }

    /// Returns per-task accounting.
    pub fn task(&self, pid: u32) -> Result<&TaskCpuAcct> {
        let slot = self.find_task(pid)?;
        Ok(&self.tasks[slot])
    }

    /// Accounts user time for a task.
    pub fn account_task_user(&mut self, pid: u32, delta_ns: u64) -> Result<()> {
        let slot = self.find_task(pid)?;
        self.tasks[slot].account_user(delta_ns);
        Ok(())
    }

    /// Accounts system time for a task.
    pub fn account_task_system(&mut self, pid: u32, delta_ns: u64) -> Result<()> {
        let slot = self.find_task(pid)?;
        self.tasks[slot].account_system(delta_ns);
        Ok(())
    }

    /// Finds a task slot by PID.
    fn find_task(&self, pid: u32) -> Result<usize> {
        for i in 0..MAX_TASKS {
            if self.tasks[i].active && self.tasks[i].pid == pid {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the total user time across all CPUs in nanoseconds.
    pub fn total_user_ns(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.nr_cpus as usize {
            total = total.saturating_add(self.cpus[i].utime_ns());
        }
        total
    }

    /// Returns the total system time across all CPUs in nanoseconds.
    pub fn total_system_ns(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.nr_cpus as usize {
            total = total.saturating_add(self.cpus[i].stime_ns());
        }
        total
    }

    /// Returns the total idle time across all CPUs in nanoseconds.
    pub fn total_idle_ns(&self) -> u64 {
        let mut total = 0u64;
        for i in 0..self.nr_cpus as usize {
            total = total.saturating_add(self.cpus[i].idle_ns());
        }
        total
    }
}
