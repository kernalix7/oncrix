// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Core scheduling infrastructure.
//!
//! Provides the per-CPU run queue core, the main `schedule()` entry
//! point, context switch skeleton, reschedule flags, and balance
//! callbacks. This module ties together the CFS, RT, deadline, and
//! idle scheduling classes.
//!
//! # Architecture
//!
//! ```text
//! RunqueueCore[MAX_CPUS]
//!  ├── current_pid / current_prio_class
//!  ├── resched_flags
//!  ├── nr_running (across all classes)
//!  ├── nr_switches
//!  └── ContextSwitchState (saved/restored registers)
//!
//! schedule() → pick_next_task() → context_switch()
//! ```

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum CPUs.
const MAX_CPUS: usize = 64;

/// Maximum tasks the core tracks globally.
const MAX_TASKS: usize = 4096;

/// Scheduler tick period in nanoseconds (4 ms).
const _TICK_PERIOD_NS: u64 = 4_000_000;

// ======================================================================
// Scheduling class priority
// ======================================================================

/// Scheduling class identifier, ordered by priority (highest first).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SchedClass {
    /// Deadline scheduling (highest priority).
    Deadline = 0,
    /// Real-time scheduling.
    Realtime = 1,
    /// Completely Fair Scheduler (normal tasks).
    Fair = 2,
    /// Idle scheduling (lowest priority).
    Idle = 3,
}

impl SchedClass {
    /// Returns the next lower-priority class, if any.
    pub fn lower(self) -> Option<Self> {
        match self {
            SchedClass::Deadline => Some(SchedClass::Realtime),
            SchedClass::Realtime => Some(SchedClass::Fair),
            SchedClass::Fair => Some(SchedClass::Idle),
            SchedClass::Idle => None,
        }
    }
}

// ======================================================================
// Reschedule flags
// ======================================================================

/// Flags indicating why a reschedule is needed.
#[derive(Clone, Copy)]
pub struct ReschedFlags {
    /// A higher-priority task became runnable.
    pub need_resched: bool,
    /// Timer tick exhausted current task's timeslice.
    pub tick_preempt: bool,
    /// Explicit yield requested by current task.
    pub yield_requested: bool,
    /// Signal delivery pending.
    pub signal_pending: bool,
    /// Balance callback requested a migration.
    pub balance_needed: bool,
}

impl ReschedFlags {
    /// Creates cleared flags.
    pub const fn new() -> Self {
        Self {
            need_resched: false,
            tick_preempt: false,
            yield_requested: false,
            signal_pending: false,
            balance_needed: false,
        }
    }

    /// Returns `true` if any flag is set.
    pub fn any(&self) -> bool {
        self.need_resched
            || self.tick_preempt
            || self.yield_requested
            || self.signal_pending
            || self.balance_needed
    }

    /// Clears all flags.
    pub fn clear(&mut self) {
        *self = Self::new();
    }
}

// ======================================================================
// Context switch state
// ======================================================================

/// Saved CPU register state for context switching.
/// In a real kernel these would be architecture-specific registers.
#[derive(Clone, Copy)]
pub struct ContextSwitchState {
    /// Stack pointer.
    pub sp: u64,
    /// Instruction pointer / program counter.
    pub ip: u64,
    /// Flags register.
    pub flags: u64,
    /// General-purpose registers (callee-saved).
    pub regs: [u64; 8],
    /// Floating-point / SIMD state saved flag.
    pub fpu_saved: bool,
    /// FPU state placeholder (in reality much larger).
    pub fpu_state: [u64; 8],
}

impl ContextSwitchState {
    /// Creates a zeroed context.
    pub const fn new() -> Self {
        Self {
            sp: 0,
            ip: 0,
            flags: 0,
            regs: [0u64; 8],
            fpu_saved: false,
            fpu_state: [0u64; 8],
        }
    }

    /// Saves the current context (simulated).
    pub fn save(&mut self, sp: u64, ip: u64, flags: u64) {
        self.sp = sp;
        self.ip = ip;
        self.flags = flags;
    }
}

// ======================================================================
// Task descriptor (core view)
// ======================================================================

/// Task state from the core scheduler's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskRunState {
    /// Runnable, in a scheduling class's queue.
    Runnable,
    /// Currently executing on a CPU.
    Running,
    /// Sleeping / blocked.
    Interruptible,
    /// Sleeping, uninterruptible.
    Uninterruptible,
    /// Stopped (SIGSTOP).
    Stopped,
    /// Zombie (exited, waiting for parent).
    Zombie,
    /// Dead (fully cleaned up).
    Dead,
}

/// Core task descriptor visible to the scheduler core.
#[derive(Clone, Copy)]
pub struct CoreTask {
    /// Task PID.
    pub pid: u64,
    /// Scheduling class.
    pub sched_class: SchedClass,
    /// Run state.
    pub state: TaskRunState,
    /// CPU the task is assigned to.
    pub cpu: u32,
    /// Context switch state.
    pub ctx: ContextSwitchState,
    /// Whether this slot is active.
    pub active: bool,
    /// Number of voluntary context switches.
    pub nr_voluntary_switches: u64,
    /// Number of involuntary context switches.
    pub nr_involuntary_switches: u64,
}

impl CoreTask {
    /// Creates an inactive task slot.
    pub const fn new() -> Self {
        Self {
            pid: 0,
            sched_class: SchedClass::Fair,
            state: TaskRunState::Dead,
            cpu: 0,
            ctx: ContextSwitchState::new(),
            active: false,
            nr_voluntary_switches: 0,
            nr_involuntary_switches: 0,
        }
    }
}

// ======================================================================
// Per-CPU run queue core
// ======================================================================

/// Per-CPU run queue core state.
pub struct RunqueueCore {
    /// CPU id.
    pub cpu_id: u32,
    /// PID of the currently running task (0 = idle).
    pub current_pid: u64,
    /// Scheduling class of the current task.
    pub current_class: SchedClass,
    /// Reschedule flags.
    pub resched: ReschedFlags,
    /// Total number of runnable tasks across all classes.
    pub nr_running: u32,
    /// Per-class runnable counts.
    pub nr_per_class: [u32; 4],
    /// Total context switches on this CPU.
    pub nr_switches: u64,
    /// Clock: last tick timestamp (nanoseconds).
    pub clock_ns: u64,
    /// Whether this CPU is online.
    pub online: bool,
    /// Whether we're currently in the scheduler.
    pub in_schedule: bool,
}

impl RunqueueCore {
    /// Creates an uninitialised run queue core.
    pub const fn new() -> Self {
        Self {
            cpu_id: 0,
            current_pid: 0,
            current_class: SchedClass::Idle,
            resched: ReschedFlags::new(),
            nr_running: 0,
            nr_per_class: [0u32; 4],
            nr_switches: 0,
            clock_ns: 0,
            online: false,
            in_schedule: false,
        }
    }

    /// Records a task enqueue.
    pub fn task_enqueued(&mut self, class: SchedClass) {
        self.nr_running += 1;
        self.nr_per_class[class as usize] += 1;
    }

    /// Records a task dequeue.
    pub fn task_dequeued(&mut self, class: SchedClass) {
        self.nr_running = self.nr_running.saturating_sub(1);
        let idx = class as usize;
        self.nr_per_class[idx] = self.nr_per_class[idx].saturating_sub(1);
    }

    /// Sets the need_resched flag.
    pub fn set_need_resched(&mut self) {
        self.resched.need_resched = true;
    }

    /// Checks if rescheduling is needed and clears the flags.
    pub fn check_resched(&mut self) -> bool {
        let needed = self.resched.any();
        if needed {
            self.resched.clear();
        }
        needed
    }

    /// Picks the highest-priority scheduling class that has
    /// runnable tasks.
    pub fn pick_next_class(&self) -> SchedClass {
        if self.nr_per_class[SchedClass::Deadline as usize] > 0 {
            SchedClass::Deadline
        } else if self.nr_per_class[SchedClass::Realtime as usize] > 0 {
            SchedClass::Realtime
        } else if self.nr_per_class[SchedClass::Fair as usize] > 0 {
            SchedClass::Fair
        } else {
            SchedClass::Idle
        }
    }

    /// Performs a context switch between `prev` and `next`.
    /// Returns `Ok(true)` if a switch actually occurred.
    pub fn context_switch(
        &mut self,
        prev_pid: u64,
        next_pid: u64,
        next_class: SchedClass,
    ) -> Result<bool> {
        if self.in_schedule {
            return Err(Error::Busy);
        }

        if prev_pid == next_pid {
            return Ok(false);
        }

        self.in_schedule = true;
        self.current_pid = next_pid;
        self.current_class = next_class;
        self.nr_switches += 1;
        self.in_schedule = false;

        Ok(true)
    }
}

// ======================================================================
// Balance callback
// ======================================================================

/// Load balance direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalanceAction {
    /// Pull tasks from busiest to this CPU.
    Pull,
    /// Push tasks from this CPU to idlest.
    Push,
    /// No action needed.
    None,
}

/// Result of a balance evaluation.
pub struct BalanceResult {
    /// Recommended action.
    pub action: BalanceAction,
    /// Source CPU (for Pull) or destination CPU (for Push).
    pub target_cpu: u32,
    /// Number of tasks to migrate.
    pub nr_migrate: u32,
}

impl BalanceResult {
    /// Creates a no-op balance result.
    pub const fn none() -> Self {
        Self {
            action: BalanceAction::None,
            target_cpu: 0,
            nr_migrate: 0,
        }
    }
}

/// Evaluates load balance across CPUs.
pub fn evaluate_balance(rqs: &[RunqueueCore], nr_cpus: usize, this_cpu: u32) -> BalanceResult {
    if nr_cpus < 2 {
        return BalanceResult::none();
    }

    let this = this_cpu as usize;
    if this >= nr_cpus {
        return BalanceResult::none();
    }

    let this_load = rqs[this].nr_running;
    let mut max_load = 0u32;
    let mut max_cpu = this;
    let mut min_load = u32::MAX;
    let mut min_cpu = this;

    for c in 0..nr_cpus {
        let load = rqs[c].nr_running;
        if load > max_load {
            max_load = load;
            max_cpu = c;
        }
        if load < min_load {
            min_load = load;
            min_cpu = c;
        }
    }

    // Pull if this CPU is idle and there is an overloaded CPU.
    if this_load == 0 && max_load > 1 {
        return BalanceResult {
            action: BalanceAction::Pull,
            target_cpu: max_cpu as u32,
            nr_migrate: 1,
        };
    }

    // Push if this CPU is overloaded and there is an idle CPU.
    if this_load > 1 && min_load == 0 && min_cpu != this {
        return BalanceResult {
            action: BalanceAction::Push,
            target_cpu: min_cpu as u32,
            nr_migrate: 1,
        };
    }

    BalanceResult::none()
}

// ======================================================================
// CoreScheduler — top-level
// ======================================================================

/// Global core scheduler state.
pub struct CoreScheduler {
    /// Per-CPU run queue cores.
    rqs: [RunqueueCore; MAX_CPUS],
    /// Global task table.
    tasks: [CoreTask; MAX_TASKS],
    /// Number of active tasks.
    pub nr_tasks: u32,
    /// Number of online CPUs.
    pub nr_cpus: u32,
}

impl CoreScheduler {
    /// Creates the core scheduler.
    pub const fn new() -> Self {
        Self {
            rqs: [const { RunqueueCore::new() }; MAX_CPUS],
            tasks: [const { CoreTask::new() }; MAX_TASKS],
            nr_tasks: 0,
            nr_cpus: 1,
        }
    }

    /// Initialises a CPU's run queue.
    pub fn init_cpu(&mut self, cpu: u32) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.rqs[c].cpu_id = cpu;
        self.rqs[c].online = true;
        if cpu >= self.nr_cpus {
            self.nr_cpus = cpu + 1;
        }
        Ok(())
    }

    /// Registers a task in the global task table.
    pub fn register_task(&mut self, pid: u64, cpu: u32, class: SchedClass) -> Result<usize> {
        let slot = self
            .tasks
            .iter()
            .position(|t| !t.active)
            .ok_or(Error::OutOfMemory)?;

        self.tasks[slot].pid = pid;
        self.tasks[slot].cpu = cpu;
        self.tasks[slot].sched_class = class;
        self.tasks[slot].state = TaskRunState::Runnable;
        self.tasks[slot].active = true;

        let c = cpu as usize;
        if c < MAX_CPUS {
            self.rqs[c].task_enqueued(class);
        }

        self.nr_tasks += 1;
        Ok(slot)
    }

    /// Unregisters a task.
    pub fn unregister_task(&mut self, slot: usize) -> Result<()> {
        if slot >= MAX_TASKS || !self.tasks[slot].active {
            return Err(Error::NotFound);
        }
        let cpu = self.tasks[slot].cpu as usize;
        let class = self.tasks[slot].sched_class;
        if cpu < MAX_CPUS {
            self.rqs[cpu].task_dequeued(class);
        }
        self.tasks[slot].active = false;
        self.tasks[slot].state = TaskRunState::Dead;
        self.nr_tasks = self.nr_tasks.saturating_sub(1);
        Ok(())
    }

    /// Main schedule entry point for a CPU.
    /// Returns the PID of the next task to run.
    pub fn schedule(&mut self, cpu: u32) -> Result<u64> {
        let c = cpu as usize;
        if c >= MAX_CPUS || !self.rqs[c].online {
            return Err(Error::InvalidArgument);
        }

        let class = self.rqs[c].pick_next_class();
        // Find the first runnable task of this class on this CPU.
        let mut next_pid = 0u64;
        for task in &self.tasks {
            if task.active
                && task.cpu == cpu
                && task.sched_class == class
                && task.state == TaskRunState::Runnable
            {
                next_pid = task.pid;
                break;
            }
        }

        let prev_pid = self.rqs[c].current_pid;
        self.rqs[c].context_switch(prev_pid, next_pid, class)?;

        Ok(next_pid)
    }

    /// Handles a scheduler tick on the given CPU.
    pub fn scheduler_tick(&mut self, cpu: u32, now_ns: u64) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.rqs[c].clock_ns = now_ns;
        // Balance evaluation.
        let cpus = self.nr_cpus as usize;
        let balance = evaluate_balance(&self.rqs, cpus, cpu);
        if balance.action != BalanceAction::None {
            self.rqs[c].resched.balance_needed = true;
        }
        Ok(())
    }

    /// Returns a reference to a CPU's run queue core.
    pub fn runqueue(&self, cpu: u32) -> Option<&RunqueueCore> {
        let c = cpu as usize;
        if c < MAX_CPUS {
            Some(&self.rqs[c])
        } else {
            None
        }
    }

    /// Returns a task by slot index.
    pub fn task(&self, slot: usize) -> Option<&CoreTask> {
        if slot < MAX_TASKS && self.tasks[slot].active {
            Some(&self.tasks[slot])
        } else {
            None
        }
    }
}
