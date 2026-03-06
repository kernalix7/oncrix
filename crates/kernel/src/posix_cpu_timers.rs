// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX per-process and per-thread CPU timers.
//!
//! Implements `CLOCK_PROCESS_CPUTIME_ID` and `CLOCK_THREAD_CPUTIME_ID`
//! as defined by POSIX.1-2024 (IEEE Std 1003.1-2024). These clocks
//! measure CPU time consumed by a process (sum of all threads) or a
//! single thread, and allow timers (`timer_create`) and alarms
//! (`setitimer`) based on CPU consumption.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                    PosixCpuTimerSubsystem                        │
//! │                                                                  │
//! │  [CpuTimerEntry; MAX_TIMERS]  — all active CPU timers            │
//! │  ┌────────────────────────────────────────────────────────────┐  │
//! │  │  CpuTimerEntry                                             │  │
//! │  │    timer_id, clock_id (Process / Thread)                   │  │
//! │  │    target_pid / target_tid                                 │  │
//! │  │    expires_ns — CPU time at which timer fires              │  │
//! │  │    interval_ns — reload value (0 = one-shot)               │  │
//! │  │    overrun_count — missed expirations                      │  │
//! │  │    CpuTimerState — lifecycle                               │  │
//! │  └────────────────────────────────────────────────────────────┘  │
//! │                                                                  │
//! │  [TaskCpuClock; MAX_TASKS]  — per-task CPU time accumulators     │
//! │  ┌────────────────────────────────────────────────────────────┐  │
//! │  │  TaskCpuClock                                              │  │
//! │  │    pid, tid                                                │  │
//! │  │    utime_ns  — user-mode CPU time                          │  │
//! │  │    stime_ns  — system-mode CPU time                        │  │
//! │  │    sum_exec_ns — utime + stime (total CPU)                 │  │
//! │  └────────────────────────────────────────────────────────────┘  │
//! │                                                                  │
//! │  PosixCpuTimerStats — global counters                            │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Timer Checking
//!
//! On each scheduler tick (or context switch), the kernel calls
//! `check_timers()` for the current task. If the task's accumulated
//! CPU time has reached a timer's `expires_ns`, the timer fires
//! (delivering a signal and reloading for interval timers).
//!
//! # Reference
//!
//! Linux `kernel/time/posix-cpu-timers.c`,
//! `include/linux/posix-timers.h`,
//! POSIX.1-2024 §2.8.4 "Per-Process Timers".

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum CPU timers in the system.
const MAX_TIMERS: usize = 256;

/// Maximum tasks tracked for CPU clocks.
const MAX_TASKS: usize = 512;

/// Maximum process groups tracked (for process-wide timers).
const MAX_PROCESSES: usize = 128;

/// Maximum timers per process.
const MAX_TIMERS_PER_PROCESS: usize = 32;

/// Maximum overrun count before saturation.
const MAX_OVERRUN: u64 = 1_000_000;

/// Clock ID for process CPU time.
pub const CLOCK_PROCESS_CPUTIME_ID: u32 = 2;

/// Clock ID for thread CPU time.
pub const CLOCK_THREAD_CPUTIME_ID: u32 = 3;

/// Minimum timer interval (1 microsecond in ns).
const MIN_INTERVAL_NS: u64 = 1_000;

/// Signal number for CPU timer expiration (SIGPROF-like).
const DEFAULT_SIGNAL: u32 = 27; // SIGPROF

/// ITIMER_PROF value for setitimer compatibility.
const ITIMER_PROF: u32 = 2;

/// ITIMER_VIRTUAL value for setitimer compatibility.
const ITIMER_VIRTUAL: u32 = 1;

// ── CpuClockId ──────────────────────────────────────────────────────────────

/// Identifies which CPU clock a timer is based on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuClockId {
    /// Process CPU time (all threads combined).
    ProcessCpu,
    /// Thread CPU time (single thread).
    ThreadCpu,
    /// Virtual (user-mode only) process time — `ITIMER_VIRTUAL`.
    ProcessVirtual,
    /// Profiling (user + system) process time — `ITIMER_PROF`.
    ProcessProf,
}

impl CpuClockId {
    /// Check whether this clock is per-thread.
    pub fn is_per_thread(self) -> bool {
        matches!(self, Self::ThreadCpu)
    }

    /// Check whether this clock counts only user time.
    pub fn is_user_only(self) -> bool {
        matches!(self, Self::ProcessVirtual)
    }
}

// ── CpuTimerState ───────────────────────────────────────────────────────────

/// Lifecycle state of a CPU timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuTimerState {
    /// Slot is free.
    Free,
    /// Timer is armed and waiting.
    Armed,
    /// Timer has fired and is pending signal delivery.
    Fired,
    /// Timer is disarmed.
    Disarmed,
    /// Timer has been deleted.
    Deleted,
}

impl Default for CpuTimerState {
    fn default() -> Self {
        Self::Free
    }
}

// ── CpuTimerEntry ───────────────────────────────────────────────────────────

/// A single POSIX CPU timer.
#[derive(Debug, Clone, Copy)]
pub struct CpuTimerEntry {
    /// Unique timer ID.
    timer_id: u64,
    /// Which CPU clock this timer uses.
    clock_id: CpuClockId,
    /// Current state.
    state: CpuTimerState,
    /// Target process ID (for process-wide timers).
    target_pid: u64,
    /// Target thread ID (for per-thread timers).
    target_tid: u64,
    /// CPU time at which the timer expires (nanoseconds).
    expires_ns: u64,
    /// Reload interval (0 = one-shot).
    interval_ns: u64,
    /// Number of missed expirations (overruns).
    overrun_count: u64,
    /// Signal to deliver on expiration.
    signal: u32,
    /// Signal value (si_value for siginfo).
    signal_value: u64,
    /// Creation timestamp (wall clock).
    created_ns: u64,
    /// Number of times this timer has fired.
    fire_count: u64,
    /// PID that created this timer.
    creator_pid: u64,
}

impl CpuTimerEntry {
    /// Create an empty timer slot.
    const fn new() -> Self {
        Self {
            timer_id: 0,
            clock_id: CpuClockId::ProcessCpu,
            state: CpuTimerState::Free,
            target_pid: 0,
            target_tid: 0,
            expires_ns: 0,
            interval_ns: 0,
            overrun_count: 0,
            signal: DEFAULT_SIGNAL,
            signal_value: 0,
            created_ns: 0,
            fire_count: 0,
            creator_pid: 0,
        }
    }

    /// Check whether this slot is free.
    fn is_free(&self) -> bool {
        matches!(self.state, CpuTimerState::Free | CpuTimerState::Deleted)
    }

    /// Get the timer ID.
    pub fn timer_id(&self) -> u64 {
        self.timer_id
    }

    /// Get the clock ID.
    pub fn clock_id(&self) -> CpuClockId {
        self.clock_id
    }

    /// Get the expiration time.
    pub fn expires_ns(&self) -> u64 {
        self.expires_ns
    }

    /// Get the interval.
    pub fn interval_ns(&self) -> u64 {
        self.interval_ns
    }

    /// Get the overrun count.
    pub fn overrun_count(&self) -> u64 {
        self.overrun_count
    }

    /// Get the fire count.
    pub fn fire_count(&self) -> u64 {
        self.fire_count
    }

    /// Check whether this is a one-shot timer.
    pub fn is_oneshot(&self) -> bool {
        self.interval_ns == 0
    }
}

// ── TaskCpuClockState ───────────────────────────────────────────────────────

/// State of a task's CPU clock tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskCpuClockState {
    /// Slot is free.
    Free,
    /// Actively tracking.
    Active,
    /// Task has exited.
    Exited,
}

impl Default for TaskCpuClockState {
    fn default() -> Self {
        Self::Free
    }
}

// ── TaskCpuClock ────────────────────────────────────────────────────────────

/// Per-task CPU time accumulator.
#[derive(Debug, Clone, Copy)]
pub struct TaskCpuClock {
    /// Process ID.
    pid: u64,
    /// Thread ID (same as pid for single-threaded).
    tid: u64,
    /// State.
    state: TaskCpuClockState,
    /// User-mode CPU time in nanoseconds.
    utime_ns: u64,
    /// System-mode CPU time in nanoseconds.
    stime_ns: u64,
    /// Total CPU time (utime + stime).
    sum_exec_ns: u64,
    /// Timestamp of last update.
    last_update_ns: u64,
}

impl TaskCpuClock {
    /// Create an empty clock slot.
    const fn new() -> Self {
        Self {
            pid: 0,
            tid: 0,
            state: TaskCpuClockState::Free,
            utime_ns: 0,
            stime_ns: 0,
            sum_exec_ns: 0,
            last_update_ns: 0,
        }
    }

    /// Check whether this slot is free.
    fn is_free(&self) -> bool {
        matches!(self.state, TaskCpuClockState::Free)
    }

    /// Get the user-mode CPU time.
    pub fn utime_ns(&self) -> u64 {
        self.utime_ns
    }

    /// Get the system-mode CPU time.
    pub fn stime_ns(&self) -> u64 {
        self.stime_ns
    }

    /// Get the total CPU time.
    pub fn sum_exec_ns(&self) -> u64 {
        self.sum_exec_ns
    }
}

// ── ProcessCpuInfo ──────────────────────────────────────────────────────────

/// Aggregate CPU time for a process (all threads combined).
#[derive(Debug, Clone, Copy)]
pub struct ProcessCpuInfo {
    /// Process ID.
    pid: u64,
    /// Whether this slot is active.
    active: bool,
    /// Aggregate user-mode time.
    utime_ns: u64,
    /// Aggregate system-mode time.
    stime_ns: u64,
    /// Aggregate total CPU time.
    sum_exec_ns: u64,
    /// Number of threads.
    thread_count: u32,
    /// Timer indices for this process.
    timer_indices: [usize; MAX_TIMERS_PER_PROCESS],
    /// Number of timers.
    timer_count: usize,
}

impl ProcessCpuInfo {
    /// Create an empty process info.
    const fn new() -> Self {
        Self {
            pid: 0,
            active: false,
            utime_ns: 0,
            stime_ns: 0,
            sum_exec_ns: 0,
            thread_count: 0,
            timer_indices: [0usize; MAX_TIMERS_PER_PROCESS],
            timer_count: 0,
        }
    }

    /// Get the aggregate user time.
    pub fn utime_ns(&self) -> u64 {
        self.utime_ns
    }

    /// Get the aggregate system time.
    pub fn stime_ns(&self) -> u64 {
        self.stime_ns
    }

    /// Get the total CPU time.
    pub fn sum_exec_ns(&self) -> u64 {
        self.sum_exec_ns
    }

    /// Get the thread count.
    pub fn thread_count(&self) -> u32 {
        self.thread_count
    }
}

// ── TimerFireResult ─────────────────────────────────────────────────────────

/// Result of checking a timer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerFireResult {
    /// Timer has not expired yet.
    NotExpired,
    /// Timer fired (signal should be delivered).
    Fired,
    /// Timer fired with overruns (missed expirations).
    FiredWithOverruns(u64),
    /// Timer is a one-shot and is now disarmed.
    FiredOneShot,
}

// ── PosixCpuTimerStats ─────────────────────────────────────────────────────

/// Global statistics for the CPU timer subsystem.
#[derive(Debug, Clone, Copy)]
pub struct PosixCpuTimerStats {
    /// Total timers created.
    pub timers_created: u64,
    /// Total timers deleted.
    pub timers_deleted: u64,
    /// Total timer fires.
    pub timer_fires: u64,
    /// Total overruns across all timers.
    pub total_overruns: u64,
    /// Timer checks performed.
    pub checks_performed: u64,
    /// Process-wide timer fires.
    pub process_fires: u64,
    /// Thread-specific timer fires.
    pub thread_fires: u64,
    /// Active timer count.
    pub active_timers: u64,
    /// Tasks tracked.
    pub tasks_tracked: u64,
}

impl PosixCpuTimerStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            timers_created: 0,
            timers_deleted: 0,
            timer_fires: 0,
            total_overruns: 0,
            checks_performed: 0,
            process_fires: 0,
            thread_fires: 0,
            active_timers: 0,
            tasks_tracked: 0,
        }
    }
}

// ── PosixCpuTimerSubsystem ─────────────────────────────────────────────────

/// Top-level POSIX CPU timer subsystem.
///
/// Manages per-process and per-thread CPU timers, tracks CPU time
/// accumulators per task, and fires timers when CPU time thresholds
/// are reached.
pub struct PosixCpuTimerSubsystem {
    /// Timer table.
    timers: [CpuTimerEntry; MAX_TIMERS],
    /// Next timer ID.
    next_timer_id: u64,
    /// Per-task CPU clocks.
    tasks: [TaskCpuClock; MAX_TASKS],
    /// Per-process aggregate info.
    processes: [ProcessCpuInfo; MAX_PROCESSES],
    /// Global statistics.
    stats: PosixCpuTimerStats,
    /// Current wall-clock time.
    now_ns: u64,
}

impl PosixCpuTimerSubsystem {
    /// Create a new CPU timer subsystem.
    pub const fn new() -> Self {
        Self {
            timers: [const { CpuTimerEntry::new() }; MAX_TIMERS],
            next_timer_id: 1,
            tasks: [const { TaskCpuClock::new() }; MAX_TASKS],
            processes: [const { ProcessCpuInfo::new() }; MAX_PROCESSES],
            stats: PosixCpuTimerStats::new(),
            now_ns: 0,
        }
    }

    /// Update the internal time.
    pub fn set_time_ns(&mut self, ns: u64) {
        self.now_ns = ns;
    }

    /// Get global statistics.
    pub fn stats(&self) -> &PosixCpuTimerStats {
        &self.stats
    }

    // ── Task CPU clock management ───────────────────────────────────

    /// Register a task for CPU time tracking.
    pub fn register_task(&mut self, pid: u64, tid: u64) -> Result<usize> {
        if self.find_task(tid).is_some() {
            return Err(Error::AlreadyExists);
        }
        let idx = self
            .tasks
            .iter()
            .position(|t| t.is_free())
            .ok_or(Error::OutOfMemory)?;

        self.tasks[idx] = TaskCpuClock {
            pid,
            tid,
            state: TaskCpuClockState::Active,
            utime_ns: 0,
            stime_ns: 0,
            sum_exec_ns: 0,
            last_update_ns: self.now_ns,
        };
        self.stats.tasks_tracked += 1;

        // Register or update process info.
        self.ensure_process(pid);

        Ok(idx)
    }

    /// Unregister a task (on exit).
    pub fn unregister_task(&mut self, tid: u64) -> Result<()> {
        let idx = self.find_task(tid).ok_or(Error::NotFound)?;
        self.tasks[idx].state = TaskCpuClockState::Exited;
        self.stats.tasks_tracked = self.stats.tasks_tracked.saturating_sub(1);
        Ok(())
    }

    /// Update CPU time for a task.
    ///
    /// Called from the scheduler on context switch or tick.
    pub fn update_cpu_time(
        &mut self,
        tid: u64,
        utime_delta_ns: u64,
        stime_delta_ns: u64,
    ) -> Result<()> {
        let idx = self.find_task(tid).ok_or(Error::NotFound)?;
        let task = &mut self.tasks[idx];
        task.utime_ns += utime_delta_ns;
        task.stime_ns += stime_delta_ns;
        task.sum_exec_ns += utime_delta_ns + stime_delta_ns;
        task.last_update_ns = self.now_ns;

        // Update process aggregate.
        let pid = task.pid;
        self.update_process_aggregate(pid);

        Ok(())
    }

    /// Get the current CPU time for a thread.
    pub fn thread_cpu_time(&self, tid: u64) -> Result<u64> {
        let idx = self.find_task(tid).ok_or(Error::NotFound)?;
        Ok(self.tasks[idx].sum_exec_ns)
    }

    /// Get the current CPU time for a process.
    pub fn process_cpu_time(&self, pid: u64) -> Result<u64> {
        let proc_idx = self.find_process(pid).ok_or(Error::NotFound)?;
        Ok(self.processes[proc_idx].sum_exec_ns)
    }

    /// Get task CPU clock info.
    pub fn task_clock(&self, tid: u64) -> Result<&TaskCpuClock> {
        let idx = self.find_task(tid).ok_or(Error::NotFound)?;
        Ok(&self.tasks[idx])
    }

    /// Get process CPU info.
    pub fn process_info(&self, pid: u64) -> Result<&ProcessCpuInfo> {
        let idx = self.find_process(pid).ok_or(Error::NotFound)?;
        Ok(&self.processes[idx])
    }

    // ── Timer management ────────────────────────────────────────────

    /// Create a new CPU timer (`timer_create` equivalent).
    pub fn create_timer(
        &mut self,
        clock_id: CpuClockId,
        target_pid: u64,
        target_tid: u64,
        signal: u32,
        signal_value: u64,
        creator_pid: u64,
    ) -> Result<u64> {
        // Validate target exists.
        if clock_id.is_per_thread() {
            if self.find_task(target_tid).is_none() {
                return Err(Error::NotFound);
            }
        } else if self.find_process(target_pid).is_none() {
            return Err(Error::NotFound);
        }

        let idx = self
            .timers
            .iter()
            .position(|t| t.is_free())
            .ok_or(Error::OutOfMemory)?;

        let timer_id = self.next_timer_id;
        self.next_timer_id += 1;

        self.timers[idx] = CpuTimerEntry {
            timer_id,
            clock_id,
            state: CpuTimerState::Disarmed,
            target_pid,
            target_tid,
            expires_ns: 0,
            interval_ns: 0,
            overrun_count: 0,
            signal,
            signal_value,
            created_ns: self.now_ns,
            fire_count: 0,
            creator_pid,
        };

        // Link to process timer list.
        if !clock_id.is_per_thread() {
            if let Some(pi) = self.find_process(target_pid) {
                let proc = &mut self.processes[pi];
                if proc.timer_count < MAX_TIMERS_PER_PROCESS {
                    proc.timer_indices[proc.timer_count] = idx;
                    proc.timer_count += 1;
                }
            }
        }

        self.stats.timers_created += 1;
        self.stats.active_timers += 1;
        Ok(timer_id)
    }

    /// Arm a timer (`timer_settime` equivalent).
    pub fn arm_timer(&mut self, timer_id: u64, expires_ns: u64, interval_ns: u64) -> Result<()> {
        let idx = self.find_timer(timer_id).ok_or(Error::NotFound)?;

        if expires_ns == 0 {
            return Err(Error::InvalidArgument);
        }
        if interval_ns > 0 && interval_ns < MIN_INTERVAL_NS {
            return Err(Error::InvalidArgument);
        }

        self.timers[idx].expires_ns = expires_ns;
        self.timers[idx].interval_ns = interval_ns;
        self.timers[idx].overrun_count = 0;
        self.timers[idx].state = CpuTimerState::Armed;
        Ok(())
    }

    /// Disarm a timer.
    pub fn disarm_timer(&mut self, timer_id: u64) -> Result<()> {
        let idx = self.find_timer(timer_id).ok_or(Error::NotFound)?;
        self.timers[idx].state = CpuTimerState::Disarmed;
        Ok(())
    }

    /// Delete a timer (`timer_delete` equivalent).
    pub fn delete_timer(&mut self, timer_id: u64) -> Result<()> {
        let idx = self.find_timer(timer_id).ok_or(Error::NotFound)?;
        self.timers[idx].state = CpuTimerState::Deleted;
        self.stats.timers_deleted += 1;
        self.stats.active_timers = self.stats.active_timers.saturating_sub(1);
        Ok(())
    }

    /// Get timer info.
    pub fn timer_info(&self, timer_id: u64) -> Result<&CpuTimerEntry> {
        let idx = self.find_timer(timer_id).ok_or(Error::NotFound)?;
        Ok(&self.timers[idx])
    }

    /// Get the remaining time until expiration.
    pub fn timer_remaining(&self, timer_id: u64) -> Result<u64> {
        let idx = self.find_timer(timer_id).ok_or(Error::NotFound)?;
        let timer = &self.timers[idx];

        if !matches!(timer.state, CpuTimerState::Armed) {
            return Ok(0);
        }

        let current_cpu = if timer.clock_id.is_per_thread() {
            self.get_thread_cpu(timer.target_tid)
        } else if timer.clock_id.is_user_only() {
            self.get_process_utime(timer.target_pid)
        } else {
            self.get_process_cpu(timer.target_pid)
        };

        Ok(timer.expires_ns.saturating_sub(current_cpu))
    }

    // ── Timer checking ──────────────────────────────────────────────

    /// Check all armed timers for a given thread.
    ///
    /// Called from the scheduler tick. Returns the number of timers
    /// that fired.
    pub fn check_thread_timers(&mut self, tid: u64) -> Result<u32> {
        let task_idx = self.find_task(tid).ok_or(Error::NotFound)?;
        let pid = self.tasks[task_idx].pid;
        let thread_cpu = self.tasks[task_idx].sum_exec_ns;
        let thread_utime = self.tasks[task_idx].utime_ns;

        let mut fired = 0u32;
        self.stats.checks_performed += 1;

        for i in 0..MAX_TIMERS {
            if !matches!(self.timers[i].state, CpuTimerState::Armed) {
                continue;
            }

            let timer = &self.timers[i];
            let current_cpu = match timer.clock_id {
                CpuClockId::ThreadCpu => {
                    if timer.target_tid != tid {
                        continue;
                    }
                    thread_cpu
                }
                CpuClockId::ProcessCpu | CpuClockId::ProcessProf => {
                    if timer.target_pid != pid {
                        continue;
                    }
                    self.get_process_cpu(pid)
                }
                CpuClockId::ProcessVirtual => {
                    if timer.target_pid != pid {
                        continue;
                    }
                    // For virtual, use thread's user time as proxy
                    // (real impl aggregates all threads).
                    thread_utime
                }
            };

            if current_cpu >= timer.expires_ns {
                let result = self.fire_timer(i, current_cpu);
                match result {
                    TimerFireResult::Fired
                    | TimerFireResult::FiredOneShot
                    | TimerFireResult::FiredWithOverruns(_) => {
                        fired += 1;
                    }
                    TimerFireResult::NotExpired => {}
                }
            }
        }

        Ok(fired)
    }

    /// Fire a single timer and handle reloading/overruns.
    fn fire_timer(&mut self, idx: usize, current_cpu: u64) -> TimerFireResult {
        let timer = &mut self.timers[idx];

        timer.fire_count += 1;
        self.stats.timer_fires += 1;

        if timer.clock_id.is_per_thread() {
            self.stats.thread_fires += 1;
        } else {
            self.stats.process_fires += 1;
        }

        if timer.interval_ns == 0 {
            // One-shot: disarm.
            timer.state = CpuTimerState::Fired;
            return TimerFireResult::FiredOneShot;
        }

        // Interval timer: compute overruns and reload.
        let elapsed = current_cpu.saturating_sub(timer.expires_ns);
        let overruns = if timer.interval_ns > 0 {
            elapsed / timer.interval_ns
        } else {
            0
        };

        timer.overrun_count = (timer.overrun_count + overruns).min(MAX_OVERRUN);
        self.stats.total_overruns += overruns;

        // Reload: set next expiration.
        timer.expires_ns = current_cpu + timer.interval_ns;
        timer.state = CpuTimerState::Armed;

        if overruns > 0 {
            TimerFireResult::FiredWithOverruns(overruns)
        } else {
            TimerFireResult::Fired
        }
    }

    // ── setitimer compatibility ─────────────────────────────────────

    /// Set an interval timer (setitimer compatibility).
    ///
    /// Creates or updates a timer for the given process.
    pub fn set_itimer(
        &mut self,
        pid: u64,
        which: u32,
        value_ns: u64,
        interval_ns: u64,
    ) -> Result<u64> {
        let clock_id = match which {
            ITIMER_VIRTUAL => CpuClockId::ProcessVirtual,
            ITIMER_PROF => CpuClockId::ProcessProf,
            _ => return Err(Error::InvalidArgument),
        };

        // Find existing itimer or create new one.
        let existing = self
            .timers
            .iter()
            .position(|t| !t.is_free() && t.target_pid == pid && t.clock_id == clock_id);

        if let Some(idx) = existing {
            if value_ns == 0 {
                // Disarm.
                self.timers[idx].state = CpuTimerState::Disarmed;
                return Ok(self.timers[idx].timer_id);
            }
            let cpu_now = self.get_process_cpu(pid);
            self.timers[idx].expires_ns = cpu_now + value_ns;
            self.timers[idx].interval_ns = interval_ns;
            self.timers[idx].state = CpuTimerState::Armed;
            return Ok(self.timers[idx].timer_id);
        }

        if value_ns == 0 {
            return Err(Error::NotFound);
        }

        let timer_id = self.create_timer(clock_id, pid, 0, DEFAULT_SIGNAL, 0, pid)?;
        let cpu_now = self.get_process_cpu(pid);
        self.arm_timer(timer_id, cpu_now + value_ns, interval_ns)?;
        Ok(timer_id)
    }

    // ── Internal helpers ────────────────────────────────────────────

    /// Find a task by TID.
    fn find_task(&self, tid: u64) -> Option<usize> {
        self.tasks
            .iter()
            .position(|t| matches!(t.state, TaskCpuClockState::Active) && t.tid == tid)
    }

    /// Find a process by PID.
    fn find_process(&self, pid: u64) -> Option<usize> {
        self.processes.iter().position(|p| p.active && p.pid == pid)
    }

    /// Ensure a process entry exists.
    fn ensure_process(&mut self, pid: u64) {
        if self.find_process(pid).is_some() {
            return;
        }
        if let Some(idx) = self.processes.iter().position(|p| !p.active) {
            self.processes[idx] = ProcessCpuInfo {
                pid,
                active: true,
                utime_ns: 0,
                stime_ns: 0,
                sum_exec_ns: 0,
                thread_count: 1,
                timer_indices: [0usize; MAX_TIMERS_PER_PROCESS],
                timer_count: 0,
            };
        }
    }

    /// Update process aggregate CPU times from per-thread data.
    fn update_process_aggregate(&mut self, pid: u64) {
        let proc_idx = match self.find_process(pid) {
            Some(i) => i,
            None => return,
        };

        let mut utime = 0u64;
        let mut stime = 0u64;
        let mut count = 0u32;

        for task in &self.tasks {
            if matches!(task.state, TaskCpuClockState::Active) && task.pid == pid {
                utime += task.utime_ns;
                stime += task.stime_ns;
                count += 1;
            }
        }

        let proc_info = &mut self.processes[proc_idx];
        proc_info.utime_ns = utime;
        proc_info.stime_ns = stime;
        proc_info.sum_exec_ns = utime + stime;
        proc_info.thread_count = count;
    }

    /// Get the total CPU time for a process.
    fn get_process_cpu(&self, pid: u64) -> u64 {
        self.find_process(pid)
            .map(|i| self.processes[i].sum_exec_ns)
            .unwrap_or(0)
    }

    /// Get the user-mode CPU time for a process.
    fn get_process_utime(&self, pid: u64) -> u64 {
        self.find_process(pid)
            .map(|i| self.processes[i].utime_ns)
            .unwrap_or(0)
    }

    /// Get the total CPU time for a thread.
    fn get_thread_cpu(&self, tid: u64) -> u64 {
        self.find_task(tid)
            .map(|i| self.tasks[i].sum_exec_ns)
            .unwrap_or(0)
    }

    /// Find a timer by ID.
    fn find_timer(&self, timer_id: u64) -> Option<usize> {
        self.timers
            .iter()
            .position(|t| !t.is_free() && t.timer_id == timer_id)
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_update() {
        let mut sys = PosixCpuTimerSubsystem::new();
        sys.register_task(1, 1).unwrap();
        sys.update_cpu_time(1, 500, 300).unwrap();
        assert_eq!(sys.thread_cpu_time(1).unwrap(), 800);
        assert_eq!(sys.process_cpu_time(1).unwrap(), 800);
    }

    #[test]
    fn test_create_and_fire_timer() {
        let mut sys = PosixCpuTimerSubsystem::new();
        sys.register_task(1, 1).unwrap();

        let tid = sys
            .create_timer(CpuClockId::ThreadCpu, 1, 1, DEFAULT_SIGNAL, 0, 1)
            .unwrap();
        sys.arm_timer(tid, 1000, 0).unwrap();

        // Accumulate CPU time past the threshold.
        sys.update_cpu_time(1, 600, 500).unwrap();
        let fired = sys.check_thread_timers(1).unwrap();
        assert_eq!(fired, 1);
        assert_eq!(sys.stats().timer_fires, 1);
    }

    #[test]
    fn test_interval_timer_reload() {
        let mut sys = PosixCpuTimerSubsystem::new();
        sys.register_task(1, 1).unwrap();

        let tid = sys
            .create_timer(CpuClockId::ThreadCpu, 1, 1, DEFAULT_SIGNAL, 0, 1)
            .unwrap();
        sys.arm_timer(tid, 500, 500).unwrap();

        sys.update_cpu_time(1, 600, 0).unwrap();
        sys.check_thread_timers(1).unwrap();

        // Timer should have reloaded.
        let info = sys.timer_info(tid).unwrap();
        assert!(matches!(info.state, CpuTimerState::Armed));
        assert!(info.expires_ns() > 500);
    }

    #[test]
    fn test_process_timer() {
        let mut sys = PosixCpuTimerSubsystem::new();
        sys.register_task(1, 1).unwrap();
        sys.register_task(1, 2).unwrap();

        let tid = sys
            .create_timer(CpuClockId::ProcessCpu, 1, 0, DEFAULT_SIGNAL, 0, 1)
            .unwrap();
        sys.arm_timer(tid, 1000, 0).unwrap();

        sys.update_cpu_time(1, 300, 200).unwrap();
        sys.update_cpu_time(2, 300, 200).unwrap();

        // Process total = 1000, should fire.
        let fired = sys.check_thread_timers(1).unwrap();
        assert_eq!(fired, 1);
    }

    #[test]
    fn test_timer_remaining() {
        let mut sys = PosixCpuTimerSubsystem::new();
        sys.register_task(1, 1).unwrap();
        let tid = sys
            .create_timer(CpuClockId::ThreadCpu, 1, 1, DEFAULT_SIGNAL, 0, 1)
            .unwrap();
        sys.arm_timer(tid, 1000, 0).unwrap();
        sys.update_cpu_time(1, 400, 0).unwrap();
        let remaining = sys.timer_remaining(tid).unwrap();
        assert_eq!(remaining, 600);
    }

    #[test]
    fn test_setitimer() {
        let mut sys = PosixCpuTimerSubsystem::new();
        sys.register_task(1, 1).unwrap();
        let tid = sys.set_itimer(1, ITIMER_PROF, 1000, 500).unwrap();
        assert!(tid > 0);
        assert_eq!(sys.stats().timers_created, 1);
    }
}
