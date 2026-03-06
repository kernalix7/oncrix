// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! High-resolution timer tasklet integration.
//!
//! Provides an integration layer between the high-resolution timer
//! (hrtimer) subsystem and the tasklet/softirq deferred execution
//! mechanism. This enables precise timer-driven deferred work:
//!
//! - An hrtimer fires at a precise deadline
//! - Instead of executing a callback directly in IRQ context,
//!   it schedules a tasklet for softirq processing
//! - The tasklet runs the actual work in a safer execution context
//!
//! # Architecture
//!
//! ```text
//!  HrtimerTasklet
//!    ├── hrtimer_id → ties to the timer subsystem
//!    ├── tasklet_id → ties to the softirq/tasklet layer
//!    ├── period_ns  → for periodic timers
//!    └── callback   → executed in tasklet context
//!
//!  Flow:
//!    [Timer IRQ] → hrtimer expires
//!                    → schedule_tasklet(tasklet_id)
//!                      → [Softirq] runs tasklet callback
//!                        → optionally re-arm hrtimer
//! ```
//!
//! # Tasklet Priority
//!
//! | Level | Use Case |
//! |-------|----------|
//! | High | Network RX, latency-critical |
//! | Normal | Periodic housekeeping |
//! | Low | Statistics, deferred cleanup |
//!
//! Reference: Linux `include/linux/hrtimer.h`,
//! `kernel/softirq.c` (tasklet_struct).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of hrtimer-tasklet bindings.
const MAX_HRTIMER_TASKLETS: usize = 64;

/// Maximum number of standalone tasklets.
const MAX_TASKLETS: usize = 128;

/// Maximum tasklet name length.
const MAX_TASKLET_NAME_LEN: usize = 64;

/// Maximum number of hrtimer instances.
const MAX_HRTIMERS: usize = 128;

/// Maximum hrtimer name length.
const MAX_HRTIMER_NAME_LEN: usize = 64;

/// Maximum number of timer groups (for grouping related timers).
const MAX_TIMER_GROUPS: usize = 16;

/// Maximum group name length.
const MAX_GROUP_NAME_LEN: usize = 32;

/// Maximum timers per group.
const MAX_TIMERS_PER_GROUP: usize = 16;

/// Nanoseconds per millisecond.
const NS_PER_MS: u64 = 1_000_000;

/// Nanoseconds per second.
const NS_PER_SEC: u64 = 1_000_000_000;

// -------------------------------------------------------------------
// TaskletPriority
// -------------------------------------------------------------------

/// Priority level for tasklet execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskletPriority {
    /// Runs before normal tasklets — use for latency-critical work.
    High,
    /// Default priority.
    Normal,
    /// Runs after normal tasklets — background work.
    Low,
}

impl TaskletPriority {
    /// Numeric rank (lower = higher priority).
    const fn rank(self) -> u8 {
        match self {
            Self::High => 0,
            Self::Normal => 1,
            Self::Low => 2,
        }
    }
}

// -------------------------------------------------------------------
// TaskletState
// -------------------------------------------------------------------

/// Execution state of a tasklet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskletState {
    /// Idle — not scheduled, not running.
    Idle,
    /// Scheduled — waiting to run in softirq.
    Scheduled,
    /// Running — currently executing.
    Running,
    /// Disabled — scheduling is suppressed.
    Disabled,
}

// -------------------------------------------------------------------
// HrtimerMode
// -------------------------------------------------------------------

/// How the hrtimer expiry time is interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HrtimerMode {
    /// Absolute time (monotonic clock).
    Absolute,
    /// Relative to current time.
    Relative,
    /// Absolute time on the real-time clock.
    AbsoluteRealtime,
    /// Relative, but pinned to the current CPU.
    RelativePinned,
}

// -------------------------------------------------------------------
// HrtimerState
// -------------------------------------------------------------------

/// State of an hrtimer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HrtimerState {
    /// Timer is inactive.
    Inactive,
    /// Timer is enqueued and waiting to fire.
    Enqueued,
    /// Timer callback is being executed.
    CallbackPending,
    /// Timer has been cancelled.
    Cancelled,
}

// -------------------------------------------------------------------
// Tasklet callback
// -------------------------------------------------------------------

/// Callback signature for tasklet execution.
///
/// The `u64` parameter is an opaque context value.
pub type TaskletFn = fn(u64);

// -------------------------------------------------------------------
// Tasklet
// -------------------------------------------------------------------

/// A deferred execution unit (softirq tasklet).
#[derive(Clone, Copy)]
pub struct Tasklet {
    /// Tasklet name.
    name: [u8; MAX_TASKLET_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Unique tasklet ID.
    tasklet_id: u64,
    /// Callback function.
    callback: TaskletFn,
    /// Opaque context value passed to callback.
    context: u64,
    /// Priority level.
    priority: TaskletPriority,
    /// Current state.
    state: TaskletState,
    /// Disable count (tasklet disabled when > 0).
    disable_count: u32,
    /// Whether this slot is active.
    active: bool,
    /// Number of times this tasklet has been executed.
    run_count: u64,
    /// Number of times scheduling was requested.
    schedule_count: u64,
}

/// Default tasklet callback.
fn default_tasklet_fn(_ctx: u64) {}

impl Tasklet {
    /// Create an empty, inactive tasklet.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_TASKLET_NAME_LEN],
            name_len: 0,
            tasklet_id: 0,
            callback: default_tasklet_fn,
            context: 0,
            priority: TaskletPriority::Normal,
            state: TaskletState::Idle,
            disable_count: 0,
            active: false,
            run_count: 0,
            schedule_count: 0,
        }
    }

    /// Return the tasklet name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the tasklet ID.
    pub const fn tasklet_id(&self) -> u64 {
        self.tasklet_id
    }

    /// Return the current state.
    pub const fn state(&self) -> TaskletState {
        self.state
    }

    /// Return the priority.
    pub const fn priority(&self) -> TaskletPriority {
        self.priority
    }

    /// Return whether the tasklet is disabled.
    pub const fn is_disabled(&self) -> bool {
        self.disable_count > 0
    }

    /// Return the run count.
    pub const fn run_count(&self) -> u64 {
        self.run_count
    }

    /// Return the schedule count.
    pub const fn schedule_count(&self) -> u64 {
        self.schedule_count
    }
}

impl core::fmt::Debug for Tasklet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tasklet")
            .field("id", &self.tasklet_id)
            .field("state", &self.state)
            .field("priority", &self.priority)
            .field("run_count", &self.run_count)
            .finish()
    }
}

// -------------------------------------------------------------------
// Hrtimer
// -------------------------------------------------------------------

/// A high-resolution timer instance.
#[derive(Clone, Copy)]
pub struct Hrtimer {
    /// Timer name.
    name: [u8; MAX_HRTIMER_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Unique timer ID.
    timer_id: u64,
    /// Expiry time in nanoseconds (monotonic).
    expires_ns: u64,
    /// Period for repeating timers (0 = one-shot).
    period_ns: u64,
    /// Timer mode.
    mode: HrtimerMode,
    /// Current state.
    state: HrtimerState,
    /// Softirq expiry time (for slack-based grouping).
    softexpires_ns: u64,
    /// Whether this slot is active.
    active: bool,
    /// Number of times this timer has fired.
    fire_count: u64,
    /// Number of times this timer overran.
    overrun_count: u64,
}

impl Hrtimer {
    /// Create an empty, inactive timer.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_HRTIMER_NAME_LEN],
            name_len: 0,
            timer_id: 0,
            expires_ns: 0,
            period_ns: 0,
            mode: HrtimerMode::Relative,
            state: HrtimerState::Inactive,
            softexpires_ns: 0,
            active: false,
            fire_count: 0,
            overrun_count: 0,
        }
    }

    /// Return the timer name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Return the timer ID.
    pub const fn timer_id(&self) -> u64 {
        self.timer_id
    }

    /// Return the expiry time.
    pub const fn expires_ns(&self) -> u64 {
        self.expires_ns
    }

    /// Return the period (0 = one-shot).
    pub const fn period_ns(&self) -> u64 {
        self.period_ns
    }

    /// Return the timer mode.
    pub const fn mode(&self) -> HrtimerMode {
        self.mode
    }

    /// Return the timer state.
    pub const fn state(&self) -> HrtimerState {
        self.state
    }

    /// Return the fire count.
    pub const fn fire_count(&self) -> u64 {
        self.fire_count
    }

    /// Return the overrun count.
    pub const fn overrun_count(&self) -> u64 {
        self.overrun_count
    }

    /// Return whether this is a periodic timer.
    pub const fn is_periodic(&self) -> bool {
        self.period_ns > 0
    }
}

impl core::fmt::Debug for Hrtimer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Hrtimer")
            .field("id", &self.timer_id)
            .field("expires_ns", &self.expires_ns)
            .field("state", &self.state)
            .field("fire_count", &self.fire_count)
            .finish()
    }
}

// -------------------------------------------------------------------
// HrtimerTasklet — the binding
// -------------------------------------------------------------------

/// Binds an hrtimer to a tasklet for deferred execution.
#[derive(Debug, Clone, Copy)]
pub struct HrtimerTasklet {
    /// Associated hrtimer ID.
    hrtimer_id: u64,
    /// Associated tasklet ID.
    tasklet_id: u64,
    /// Whether to automatically re-arm the timer after tasklet runs.
    auto_rearm: bool,
    /// Whether this binding is active.
    active: bool,
    /// Number of times the binding has triggered.
    trigger_count: u64,
}

impl HrtimerTasklet {
    const fn empty() -> Self {
        Self {
            hrtimer_id: 0,
            tasklet_id: 0,
            auto_rearm: false,
            active: false,
            trigger_count: 0,
        }
    }

    /// Return the hrtimer ID.
    pub const fn hrtimer_id(&self) -> u64 {
        self.hrtimer_id
    }

    /// Return the tasklet ID.
    pub const fn tasklet_id(&self) -> u64 {
        self.tasklet_id
    }

    /// Return the trigger count.
    pub const fn trigger_count(&self) -> u64 {
        self.trigger_count
    }

    /// Return whether auto-rearm is enabled.
    pub const fn is_auto_rearm(&self) -> bool {
        self.auto_rearm
    }
}

// -------------------------------------------------------------------
// TimerGroup
// -------------------------------------------------------------------

/// A group of related timers (for batch cancellation, etc.).
#[derive(Clone, Copy)]
struct TimerGroup {
    /// Group name.
    name: [u8; MAX_GROUP_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Group ID.
    group_id: u64,
    /// Timer IDs in this group.
    timer_ids: [u64; MAX_TIMERS_PER_GROUP],
    /// Number of timers.
    timer_count: usize,
    /// Whether this slot is active.
    active: bool,
}

impl TimerGroup {
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_GROUP_NAME_LEN],
            name_len: 0,
            group_id: 0,
            timer_ids: [0u64; MAX_TIMERS_PER_GROUP],
            timer_count: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// HrtimerTaskletStats
// -------------------------------------------------------------------

/// Statistics for the hrtimer-tasklet subsystem.
#[derive(Debug, Clone, Copy)]
pub struct HrtimerTaskletStats {
    /// Total hrtimer expirations.
    pub total_hrtimer_fires: u64,
    /// Total tasklet executions.
    pub total_tasklet_runs: u64,
    /// Total hrtimer-tasklet triggers.
    pub total_binding_triggers: u64,
    /// Tasklets currently scheduled.
    pub tasklets_scheduled: usize,
    /// Hrtimers currently enqueued.
    pub hrtimers_enqueued: usize,
}

impl HrtimerTaskletStats {
    const fn new() -> Self {
        Self {
            total_hrtimer_fires: 0,
            total_tasklet_runs: 0,
            total_binding_triggers: 0,
            tasklets_scheduled: 0,
            hrtimers_enqueued: 0,
        }
    }
}

// -------------------------------------------------------------------
// HrtimerTaskletManager
// -------------------------------------------------------------------

/// Manages hrtimers, tasklets, and their bindings.
pub struct HrtimerTaskletManager {
    /// Tasklet pool.
    tasklets: [Tasklet; MAX_TASKLETS],
    /// Number of active tasklets.
    tasklet_count: usize,
    /// Next tasklet ID.
    next_tasklet_id: u64,
    /// Hrtimer pool.
    hrtimers: [Hrtimer; MAX_HRTIMERS],
    /// Number of active hrtimers.
    hrtimer_count: usize,
    /// Next hrtimer ID.
    next_hrtimer_id: u64,
    /// Hrtimer-tasklet bindings.
    bindings: [HrtimerTasklet; MAX_HRTIMER_TASKLETS],
    /// Number of active bindings.
    binding_count: usize,
    /// Timer groups.
    groups: [TimerGroup; MAX_TIMER_GROUPS],
    /// Number of active groups.
    group_count: usize,
    /// Next group ID.
    next_group_id: u64,
    /// Current monotonic time (nanoseconds).
    now_ns: u64,
    /// Statistics.
    stats: HrtimerTaskletStats,
}

impl Default for HrtimerTaskletManager {
    fn default() -> Self {
        Self::new()
    }
}

impl HrtimerTaskletManager {
    /// Create a new manager.
    pub const fn new() -> Self {
        Self {
            tasklets: [const { Tasklet::empty() }; MAX_TASKLETS],
            tasklet_count: 0,
            next_tasklet_id: 1,
            hrtimers: [const { Hrtimer::empty() }; MAX_HRTIMERS],
            hrtimer_count: 0,
            next_hrtimer_id: 1,
            bindings: [const { HrtimerTasklet::empty() }; MAX_HRTIMER_TASKLETS],
            binding_count: 0,
            groups: [const { TimerGroup::empty() }; MAX_TIMER_GROUPS],
            group_count: 0,
            next_group_id: 1,
            now_ns: 0,
            stats: HrtimerTaskletStats::new(),
        }
    }

    // ── Tasklet management ──────────────────────────────────────

    /// Create a new tasklet.
    pub fn tasklet_init(
        &mut self,
        name: &[u8],
        callback: TaskletFn,
        context: u64,
        priority: TaskletPriority,
    ) -> Result<u64> {
        if name.is_empty() || name.len() > MAX_TASKLET_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let slot = self.find_free_tasklet_slot()?;
        let id = self.next_tasklet_id;
        self.next_tasklet_id += 1;

        self.tasklets[slot].name[..name.len()].copy_from_slice(name);
        self.tasklets[slot].name_len = name.len();
        self.tasklets[slot].tasklet_id = id;
        self.tasklets[slot].callback = callback;
        self.tasklets[slot].context = context;
        self.tasklets[slot].priority = priority;
        self.tasklets[slot].state = TaskletState::Idle;
        self.tasklets[slot].disable_count = 0;
        self.tasklets[slot].active = true;
        self.tasklets[slot].run_count = 0;
        self.tasklets[slot].schedule_count = 0;
        self.tasklet_count += 1;
        Ok(id)
    }

    fn find_free_tasklet_slot(&self) -> Result<usize> {
        for i in 0..MAX_TASKLETS {
            if !self.tasklets[i].active {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    fn find_tasklet_index(&self, tasklet_id: u64) -> Option<usize> {
        (0..MAX_TASKLETS)
            .find(|&i| self.tasklets[i].active && self.tasklets[i].tasklet_id == tasklet_id)
    }

    /// Schedule a tasklet for execution.
    pub fn tasklet_schedule(&mut self, tasklet_id: u64) -> Result<()> {
        let idx = self.find_tasklet_index(tasklet_id).ok_or(Error::NotFound)?;
        if self.tasklets[idx].disable_count > 0 {
            return Err(Error::PermissionDenied);
        }
        if self.tasklets[idx].state == TaskletState::Scheduled
            || self.tasklets[idx].state == TaskletState::Running
        {
            return Ok(()); // Already scheduled or running.
        }
        self.tasklets[idx].state = TaskletState::Scheduled;
        self.tasklets[idx].schedule_count += 1;
        self.stats.tasklets_scheduled += 1;
        Ok(())
    }

    /// Disable a tasklet (increment disable count).
    pub fn tasklet_disable(&mut self, tasklet_id: u64) -> Result<()> {
        let idx = self.find_tasklet_index(tasklet_id).ok_or(Error::NotFound)?;
        self.tasklets[idx].disable_count += 1;
        if self.tasklets[idx].state == TaskletState::Scheduled {
            self.tasklets[idx].state = TaskletState::Disabled;
        }
        Ok(())
    }

    /// Enable a tasklet (decrement disable count).
    pub fn tasklet_enable(&mut self, tasklet_id: u64) -> Result<()> {
        let idx = self.find_tasklet_index(tasklet_id).ok_or(Error::NotFound)?;
        if self.tasklets[idx].disable_count == 0 {
            return Err(Error::InvalidArgument);
        }
        self.tasklets[idx].disable_count -= 1;
        if self.tasklets[idx].disable_count == 0
            && self.tasklets[idx].state == TaskletState::Disabled
        {
            self.tasklets[idx].state = TaskletState::Idle;
        }
        Ok(())
    }

    /// Kill (destroy) a tasklet.
    pub fn tasklet_kill(&mut self, tasklet_id: u64) -> Result<()> {
        let idx = self.find_tasklet_index(tasklet_id).ok_or(Error::NotFound)?;
        if self.tasklets[idx].state == TaskletState::Running {
            return Err(Error::Busy);
        }
        self.tasklets[idx].active = false;
        self.tasklet_count -= 1;
        Ok(())
    }

    /// Run all scheduled tasklets (softirq action).
    ///
    /// Executes tasklets in priority order. Returns the number
    /// of tasklets that ran.
    pub fn run_tasklets(&mut self) -> usize {
        let mut ran = 0;

        // Process in priority order.
        for prio_rank in 0..3u8 {
            for i in 0..MAX_TASKLETS {
                if !self.tasklets[i].active
                    || self.tasklets[i].state != TaskletState::Scheduled
                    || self.tasklets[i].priority.rank() != prio_rank
                    || self.tasklets[i].disable_count > 0
                {
                    continue;
                }

                self.tasklets[i].state = TaskletState::Running;
                let cb = self.tasklets[i].callback;
                let ctx = self.tasklets[i].context;
                cb(ctx);
                self.tasklets[i].run_count += 1;
                self.tasklets[i].state = TaskletState::Idle;
                self.stats.total_tasklet_runs += 1;
                if self.stats.tasklets_scheduled > 0 {
                    self.stats.tasklets_scheduled -= 1;
                }
                ran += 1;
            }
        }
        ran
    }

    /// Get a reference to a tasklet by ID.
    pub fn tasklet(&self, tasklet_id: u64) -> Option<&Tasklet> {
        self.find_tasklet_index(tasklet_id)
            .map(|idx| &self.tasklets[idx])
    }

    // ── Hrtimer management ──────────────────────────────────────

    /// Create a new hrtimer.
    pub fn hrtimer_init(&mut self, name: &[u8], mode: HrtimerMode) -> Result<u64> {
        if name.is_empty() || name.len() > MAX_HRTIMER_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let slot = self.find_free_hrtimer_slot()?;
        let id = self.next_hrtimer_id;
        self.next_hrtimer_id += 1;

        self.hrtimers[slot].name[..name.len()].copy_from_slice(name);
        self.hrtimers[slot].name_len = name.len();
        self.hrtimers[slot].timer_id = id;
        self.hrtimers[slot].mode = mode;
        self.hrtimers[slot].state = HrtimerState::Inactive;
        self.hrtimers[slot].active = true;
        self.hrtimers[slot].fire_count = 0;
        self.hrtimers[slot].overrun_count = 0;
        self.hrtimer_count += 1;
        Ok(id)
    }

    fn find_free_hrtimer_slot(&self) -> Result<usize> {
        for i in 0..MAX_HRTIMERS {
            if !self.hrtimers[i].active {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    fn find_hrtimer_index(&self, timer_id: u64) -> Option<usize> {
        (0..MAX_HRTIMERS)
            .find(|&i| self.hrtimers[i].active && self.hrtimers[i].timer_id == timer_id)
    }

    /// Start (arm) an hrtimer.
    ///
    /// For `Relative` mode, `expires_ns` is added to `now_ns`.
    /// For `Absolute` mode, `expires_ns` is used directly.
    pub fn hrtimer_start(&mut self, timer_id: u64, expires_ns: u64, period_ns: u64) -> Result<()> {
        let idx = self.find_hrtimer_index(timer_id).ok_or(Error::NotFound)?;

        let abs_expires = match self.hrtimers[idx].mode {
            HrtimerMode::Relative | HrtimerMode::RelativePinned => {
                self.now_ns.saturating_add(expires_ns)
            }
            HrtimerMode::Absolute | HrtimerMode::AbsoluteRealtime => expires_ns,
        };

        self.hrtimers[idx].expires_ns = abs_expires;
        self.hrtimers[idx].softexpires_ns = abs_expires;
        self.hrtimers[idx].period_ns = period_ns;
        self.hrtimers[idx].state = HrtimerState::Enqueued;
        self.stats.hrtimers_enqueued += 1;
        Ok(())
    }

    /// Cancel an hrtimer.
    pub fn hrtimer_cancel(&mut self, timer_id: u64) -> Result<bool> {
        let idx = self.find_hrtimer_index(timer_id).ok_or(Error::NotFound)?;
        let was_enqueued = self.hrtimers[idx].state == HrtimerState::Enqueued;
        self.hrtimers[idx].state = HrtimerState::Cancelled;
        if was_enqueued && self.stats.hrtimers_enqueued > 0 {
            self.stats.hrtimers_enqueued -= 1;
        }
        Ok(was_enqueued)
    }

    /// Destroy an hrtimer.
    pub fn hrtimer_destroy(&mut self, timer_id: u64) -> Result<()> {
        let idx = self.find_hrtimer_index(timer_id).ok_or(Error::NotFound)?;
        self.hrtimers[idx].active = false;
        self.hrtimer_count -= 1;
        Ok(())
    }

    /// Get a reference to an hrtimer by ID.
    pub fn hrtimer(&self, timer_id: u64) -> Option<&Hrtimer> {
        self.find_hrtimer_index(timer_id)
            .map(|idx| &self.hrtimers[idx])
    }

    /// Modify the expiry of an active timer.
    pub fn hrtimer_forward(&mut self, timer_id: u64, interval_ns: u64) -> Result<u64> {
        let idx = self.find_hrtimer_index(timer_id).ok_or(Error::NotFound)?;
        let overruns;

        // Calculate how many intervals we need to skip.
        if self.now_ns > self.hrtimers[idx].expires_ns && interval_ns > 0 {
            let diff = self.now_ns - self.hrtimers[idx].expires_ns;
            overruns = diff / interval_ns + 1;
            self.hrtimers[idx].expires_ns += overruns * interval_ns;
            self.hrtimers[idx].overrun_count += overruns;
        } else {
            self.hrtimers[idx].expires_ns += interval_ns;
            overruns = 1;
        }
        Ok(overruns)
    }

    // ── Binding management ──────────────────────────────────────

    /// Create a binding between an hrtimer and a tasklet.
    pub fn bind_hrtimer_tasklet(
        &mut self,
        hrtimer_id: u64,
        tasklet_id: u64,
        auto_rearm: bool,
    ) -> Result<()> {
        // Verify both exist.
        if self.find_hrtimer_index(hrtimer_id).is_none() {
            return Err(Error::NotFound);
        }
        if self.find_tasklet_index(tasklet_id).is_none() {
            return Err(Error::NotFound);
        }
        // Check for duplicate binding.
        for i in 0..self.binding_count {
            if self.bindings[i].active && self.bindings[i].hrtimer_id == hrtimer_id {
                return Err(Error::AlreadyExists);
            }
        }
        if self.binding_count >= MAX_HRTIMER_TASKLETS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.binding_count;
        self.bindings[idx].hrtimer_id = hrtimer_id;
        self.bindings[idx].tasklet_id = tasklet_id;
        self.bindings[idx].auto_rearm = auto_rearm;
        self.bindings[idx].active = true;
        self.bindings[idx].trigger_count = 0;
        self.binding_count += 1;
        Ok(())
    }

    /// Remove a binding.
    pub fn unbind_hrtimer_tasklet(&mut self, hrtimer_id: u64) -> Result<()> {
        for i in 0..self.binding_count {
            if self.bindings[i].active && self.bindings[i].hrtimer_id == hrtimer_id {
                self.bindings[i].active = false;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Get binding info for an hrtimer.
    pub fn binding(&self, hrtimer_id: u64) -> Option<&HrtimerTasklet> {
        (0..self.binding_count)
            .find(|&i| self.bindings[i].active && self.bindings[i].hrtimer_id == hrtimer_id)
            .map(|i| &self.bindings[i])
    }

    // ── Timer group management ──────────────────────────────────

    /// Create a timer group.
    pub fn create_group(&mut self, name: &[u8]) -> Result<u64> {
        if name.is_empty() || name.len() > MAX_GROUP_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        if self.group_count >= MAX_TIMER_GROUPS {
            return Err(Error::OutOfMemory);
        }
        let slot = self.find_free_group_slot()?;
        let id = self.next_group_id;
        self.next_group_id += 1;

        self.groups[slot].name[..name.len()].copy_from_slice(name);
        self.groups[slot].name_len = name.len();
        self.groups[slot].group_id = id;
        self.groups[slot].timer_count = 0;
        self.groups[slot].active = true;
        self.group_count += 1;
        Ok(id)
    }

    fn find_free_group_slot(&self) -> Result<usize> {
        for i in 0..MAX_TIMER_GROUPS {
            if !self.groups[i].active {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    fn find_group_index(&self, group_id: u64) -> Option<usize> {
        (0..MAX_TIMER_GROUPS)
            .find(|&i| self.groups[i].active && self.groups[i].group_id == group_id)
    }

    /// Add a timer to a group.
    pub fn add_timer_to_group(&mut self, group_id: u64, timer_id: u64) -> Result<()> {
        let gidx = self.find_group_index(group_id).ok_or(Error::NotFound)?;
        if self.find_hrtimer_index(timer_id).is_none() {
            return Err(Error::NotFound);
        }
        let tc = self.groups[gidx].timer_count;
        if tc >= MAX_TIMERS_PER_GROUP {
            return Err(Error::OutOfMemory);
        }
        self.groups[gidx].timer_ids[tc] = timer_id;
        self.groups[gidx].timer_count += 1;
        Ok(())
    }

    /// Cancel all timers in a group.
    pub fn cancel_group(&mut self, group_id: u64) -> Result<usize> {
        let gidx = self.find_group_index(group_id).ok_or(Error::NotFound)?;
        let mut cancelled = 0;
        for t in 0..self.groups[gidx].timer_count {
            let tid = self.groups[gidx].timer_ids[t];
            if self.hrtimer_cancel(tid).is_ok() {
                cancelled += 1;
            }
        }
        Ok(cancelled)
    }

    // ── Tick processing ─────────────────────────────────────────

    /// Advance the clock and process expired timers.
    ///
    /// Called from the timer interrupt handler. For each expired
    /// hrtimer that has a tasklet binding, the tasklet is scheduled.
    /// Returns the number of timers that fired.
    pub fn tick(&mut self, now_ns: u64) -> usize {
        self.now_ns = now_ns;
        let mut fired = 0;

        for i in 0..MAX_HRTIMERS {
            if !self.hrtimers[i].active || self.hrtimers[i].state != HrtimerState::Enqueued {
                continue;
            }
            if self.hrtimers[i].expires_ns > now_ns {
                continue;
            }

            // Timer expired.
            self.hrtimers[i].fire_count += 1;
            self.stats.total_hrtimer_fires += 1;
            fired += 1;

            let timer_id = self.hrtimers[i].timer_id;
            let period = self.hrtimers[i].period_ns;

            // Check for binding → schedule tasklet.
            self.trigger_binding(timer_id);

            // Re-arm periodic timers.
            if period > 0 {
                self.hrtimers[i].expires_ns += period;
                self.hrtimers[i].softexpires_ns = self.hrtimers[i].expires_ns;
            } else {
                self.hrtimers[i].state = HrtimerState::Inactive;
                if self.stats.hrtimers_enqueued > 0 {
                    self.stats.hrtimers_enqueued -= 1;
                }
            }
        }
        fired
    }

    /// Trigger a binding (schedule the tasklet for a fired timer).
    fn trigger_binding(&mut self, hrtimer_id: u64) {
        for i in 0..self.binding_count {
            if !self.bindings[i].active || self.bindings[i].hrtimer_id != hrtimer_id {
                continue;
            }
            let tasklet_id = self.bindings[i].tasklet_id;
            self.bindings[i].trigger_count += 1;
            self.stats.total_binding_triggers += 1;
            let _ = self.tasklet_schedule(tasklet_id);
            break;
        }
    }

    /// Return the next expiry time across all enqueued timers.
    pub fn next_expiry_ns(&self) -> Option<u64> {
        let mut earliest: Option<u64> = None;
        for i in 0..MAX_HRTIMERS {
            if !self.hrtimers[i].active || self.hrtimers[i].state != HrtimerState::Enqueued {
                continue;
            }
            match earliest {
                None => earliest = Some(self.hrtimers[i].expires_ns),
                Some(e) if self.hrtimers[i].expires_ns < e => {
                    earliest = Some(self.hrtimers[i].expires_ns);
                }
                _ => {}
            }
        }
        earliest
    }

    /// Convert milliseconds to nanoseconds.
    pub const fn ms_to_ns(ms: u64) -> u64 {
        ms * NS_PER_MS
    }

    /// Convert seconds to nanoseconds.
    pub const fn sec_to_ns(sec: u64) -> u64 {
        sec * NS_PER_SEC
    }

    /// Return the current time.
    pub const fn now_ns(&self) -> u64 {
        self.now_ns
    }

    /// Return statistics.
    pub const fn stats(&self) -> &HrtimerTaskletStats {
        &self.stats
    }

    /// Return the number of active tasklets.
    pub const fn tasklet_count(&self) -> usize {
        self.tasklet_count
    }

    /// Return the number of active hrtimers.
    pub const fn hrtimer_count(&self) -> usize {
        self.hrtimer_count
    }

    /// Return the number of active bindings.
    pub const fn binding_count(&self) -> usize {
        self.binding_count
    }
}
