// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Tick scheduler — nohz (dynamic ticks) subsystem.
//!
//! Manages the per-CPU periodic tick and supports dynamic tick
//! (tickless) modes to reduce power consumption on idle CPUs.
//! When a CPU enters idle with no pending timers, the tick can be
//! stopped entirely until the next event.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                      TickSchedSubsystem                          │
//! │                                                                  │
//! │  per_cpu_state: [TickSchedState; MAX_CPUS]                       │
//! │    ┌───────────────────────────────────────┐                     │
//! │    │  TickSchedState (CPU N)               │                     │
//! │    │    nohz_mode: NohzMode                │                     │
//! │    │    idle_active: bool                  │                     │
//! │    │    last_tick_ns / next_tick_ns         │                     │
//! │    │    idle_entrytime / idle_sleeptime     │                     │
//! │    │    idle_calls / idle_sleeps            │                     │
//! │    │    tick_stopped: bool                  │                     │
//! │    │    do_timer_cpu: bool (jiffies owner)  │                     │
//! │    └───────────────────────────────────────┘                     │
//! │                                                                  │
//! │  Flow:                                                           │
//! │    idle_enter → can_stop_idle_tick? → stop tick                   │
//! │    interrupt  → reprogram or restart tick                        │
//! │    idle_exit  → restart tick                                     │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Nohz Modes
//!
//! | Mode | Description |
//! |------|-------------|
//! | `Lowres` | Periodic tick, no dynamic behavior |
//! | `Highres` | HRT-based tick, can stop on idle |
//! | `Full` | Full nohz: tick stopped even with one runnable task |
//!
//! # Reference
//!
//! Linux `kernel/time/tick-sched.c`, `include/linux/tick.h`,
//! `kernel/time/tick-internal.h`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of CPUs.
const MAX_CPUS: usize = 256;

/// Default tick period in nanoseconds (10ms = 100 Hz).
const TICK_PERIOD_NS: u64 = 10_000_000;

/// Minimum idle duration (ns) before stopping the tick.
const MIN_IDLE_DURATION_NS: u64 = 1_000_000;

/// Maximum number of nanoseconds to skip ahead.
const MAX_SKIP_NS: u64 = 100_000_000_000;

/// Timer slack for idle (1ms).
const IDLE_TIMER_SLACK_NS: u64 = 1_000_000;

/// Idle sleep time threshold for deep idle (5ms).
const DEEP_IDLE_THRESHOLD_NS: u64 = 5_000_000;

/// Maximum number of pending check reasons.
const MAX_CHECK_REASONS: usize = 8;

/// Grace period for RCU callbacks before allowing nohz (1ms).
const RCU_GRACE_PERIOD_NS: u64 = 1_000_000;

/// Jiffies update interval (matches tick period).
const JIFFIES_UPDATE_INTERVAL_NS: u64 = TICK_PERIOD_NS;

// ── Nohz Mode ───────────────────────────────────────────────────────────────

/// Nohz (tickless) operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NohzMode {
    /// Low-resolution mode (periodic tick always active).
    Lowres,
    /// High-resolution mode (tick stops on idle).
    Highres,
    /// Full dynticks (tick stops even with runnable tasks).
    Full,
}

impl NohzMode {
    /// Whether this mode can stop the tick on idle.
    pub fn can_stop_on_idle(self) -> bool {
        matches!(self, Self::Highres | Self::Full)
    }

    /// Whether this mode supports full nohz (no tick with 1 task).
    pub fn is_full(self) -> bool {
        matches!(self, Self::Full)
    }

    /// Human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Lowres => "lowres",
            Self::Highres => "highres",
            Self::Full => "nohz_full",
        }
    }
}

// ── Tick Stop Reasons ───────────────────────────────────────────────────────

/// Reasons that prevent stopping the tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickBusyReason {
    /// Pending timers need servicing.
    PendingTimers,
    /// RCU callbacks need processing.
    RcuCallbacks,
    /// POSIX CPU timers are active.
    PosixCpuTimers,
    /// Scheduler needs periodic ticking.
    SchedBusy,
    /// Perf events need sampling.
    PerfEvents,
    /// Watchdog needs periodic checks.
    Watchdog,
    /// Full dyntick not supported for this CPU.
    NoFullDyntick,
    /// User-space requested periodic tick.
    UserRequest,
}

/// Bitfield of tick-busy reasons.
#[derive(Debug, Clone, Copy)]
pub struct TickBusyReasons(u32);

impl TickBusyReasons {
    /// No reasons — tick can be stopped.
    pub const fn none() -> Self {
        Self(0)
    }

    /// Set a reason.
    pub fn set(&mut self, reason: TickBusyReason) {
        self.0 |= 1u32 << (reason as u32);
    }

    /// Clear a reason.
    pub fn clear(&mut self, reason: TickBusyReason) {
        self.0 &= !(1u32 << (reason as u32));
    }

    /// Check if a reason is set.
    pub fn has(self, reason: TickBusyReason) -> bool {
        self.0 & (1u32 << (reason as u32)) != 0
    }

    /// Whether any reasons are set (tick cannot be stopped).
    pub fn any(self) -> bool {
        self.0 != 0
    }

    /// Whether no reasons are set (tick can be stopped).
    pub fn is_clear(self) -> bool {
        self.0 == 0
    }

    /// Get the raw value.
    pub fn raw(self) -> u32 {
        self.0
    }

    /// Count the number of active reasons.
    pub fn count(self) -> u32 {
        self.0.count_ones()
    }
}

// ── Per-CPU Tick State ──────────────────────────────────────────────────────

/// Idle statistics for one CPU.
#[derive(Debug, Clone, Copy)]
pub struct IdleStats {
    /// Number of times the CPU entered idle.
    pub idle_calls: u64,
    /// Number of times the tick was actually stopped.
    pub idle_sleeps: u64,
    /// Total time spent in idle (nanoseconds).
    pub idle_sleeptime_ns: u64,
    /// Total time in "tickless idle" (tick stopped).
    pub iowait_sleeptime_ns: u64,
    /// Last idle entry time (nanoseconds).
    pub idle_entrytime_ns: u64,
    /// Last idle exit time (nanoseconds).
    pub idle_exittime_ns: u64,
    /// Number of tick stops attempted but blocked.
    pub tick_stop_blocked: u64,
    /// Number of successful tick stops.
    pub tick_stop_success: u64,
    /// Longest idle duration observed (nanoseconds).
    pub max_idle_duration_ns: u64,
}

impl IdleStats {
    /// Create zeroed idle statistics.
    pub const fn new() -> Self {
        Self {
            idle_calls: 0,
            idle_sleeps: 0,
            idle_sleeptime_ns: 0,
            iowait_sleeptime_ns: 0,
            idle_entrytime_ns: 0,
            idle_exittime_ns: 0,
            tick_stop_blocked: 0,
            tick_stop_success: 0,
            max_idle_duration_ns: 0,
        }
    }

    /// Get the average idle duration.
    pub fn avg_idle_duration_ns(&self) -> u64 {
        if self.idle_calls == 0 {
            return 0;
        }
        self.idle_sleeptime_ns / self.idle_calls
    }

    /// Get the tick-stop success rate (percentage).
    pub fn tick_stop_rate(&self) -> u32 {
        let total = self.tick_stop_success + self.tick_stop_blocked;
        if total == 0 {
            return 0;
        }
        ((self.tick_stop_success * 100) / total) as u32
    }
}

/// Per-CPU tick scheduler state.
pub struct TickSchedState {
    /// Whether this CPU slot is initialized.
    initialized: bool,
    /// CPU ID.
    cpu_id: u32,
    /// Nohz operating mode.
    nohz_mode: NohzMode,
    /// Whether the CPU is currently idle.
    idle_active: bool,
    /// Whether the tick is currently stopped.
    tick_stopped: bool,
    /// Whether this CPU owns the jiffies update.
    do_timer_cpu: bool,
    /// Last tick timestamp (nanoseconds).
    last_tick_ns: u64,
    /// Next programmed tick timestamp (nanoseconds).
    next_tick_ns: u64,
    /// Next event time from all sources (nanoseconds).
    next_event_ns: u64,
    /// Tick period (nanoseconds).
    tick_period_ns: u64,
    /// Number of pending timer events.
    pending_timers: u32,
    /// Whether RCU callbacks are pending.
    rcu_pending: bool,
    /// Whether POSIX CPU timers are active.
    posix_timers_active: bool,
    /// Number of runnable tasks on this CPU.
    nr_running: u32,
    /// Busy reasons preventing tick stop.
    busy_reasons: TickBusyReasons,
    /// Idle statistics.
    idle_stats: IdleStats,
    /// Full-dynticks state: tick stopped with tasks running.
    full_dyntick_active: bool,
    /// Timestamp of last tick reprogram.
    last_reprogram_ns: u64,
    /// Number of ticks since boot on this CPU.
    tick_count: u64,
}

impl TickSchedState {
    /// Create a new per-CPU tick state.
    pub const fn new() -> Self {
        Self {
            initialized: false,
            cpu_id: 0,
            nohz_mode: NohzMode::Lowres,
            idle_active: false,
            tick_stopped: false,
            do_timer_cpu: false,
            last_tick_ns: 0,
            next_tick_ns: 0,
            next_event_ns: 0,
            tick_period_ns: TICK_PERIOD_NS,
            pending_timers: 0,
            rcu_pending: false,
            posix_timers_active: false,
            nr_running: 0,
            busy_reasons: TickBusyReasons::none(),
            idle_stats: IdleStats::new(),
            full_dyntick_active: false,
            last_reprogram_ns: 0,
            tick_count: 0,
        }
    }

    /// Initialize the state for a CPU.
    pub fn init(&mut self, cpu_id: u32, mode: NohzMode) {
        self.initialized = true;
        self.cpu_id = cpu_id;
        self.nohz_mode = mode;
        self.tick_period_ns = TICK_PERIOD_NS;
    }

    /// Get the CPU ID.
    pub fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Get the current nohz mode.
    pub fn nohz_mode(&self) -> NohzMode {
        self.nohz_mode
    }

    /// Whether the CPU is idle.
    pub fn is_idle(&self) -> bool {
        self.idle_active
    }

    /// Whether the tick is stopped.
    pub fn is_tick_stopped(&self) -> bool {
        self.tick_stopped
    }

    /// Whether this CPU owns the jiffies update.
    pub fn is_timer_cpu(&self) -> bool {
        self.do_timer_cpu
    }

    /// Get the idle statistics.
    pub fn idle_stats(&self) -> &IdleStats {
        &self.idle_stats
    }

    /// Get the tick count.
    pub fn tick_count(&self) -> u64 {
        self.tick_count
    }

    /// Get busy reasons.
    pub fn busy_reasons(&self) -> TickBusyReasons {
        self.busy_reasons
    }

    /// Set the timer-CPU flag.
    pub fn set_timer_cpu(&mut self, is_timer: bool) {
        self.do_timer_cpu = is_timer;
    }

    /// Update the number of pending timers.
    pub fn set_pending_timers(&mut self, count: u32) {
        self.pending_timers = count;
    }

    /// Update RCU pending state.
    pub fn set_rcu_pending(&mut self, pending: bool) {
        self.rcu_pending = pending;
    }

    /// Update POSIX timer state.
    pub fn set_posix_timers(&mut self, active: bool) {
        self.posix_timers_active = active;
    }

    /// Update runnable task count.
    pub fn set_nr_running(&mut self, count: u32) {
        self.nr_running = count;
    }

    /// Enter idle state.
    ///
    /// Called when the CPU is about to go idle. Evaluates whether
    /// the tick can be stopped and programs the next event.
    pub fn tick_nohz_idle_enter(&mut self, current_ns: u64) -> Result<bool> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        self.idle_active = true;
        self.idle_stats.idle_calls += 1;
        self.idle_stats.idle_entrytime_ns = current_ns;

        // Check if we can stop the tick
        let can_stop = self.can_stop_idle_tick(current_ns);
        if can_stop {
            self.stop_tick(current_ns)?;
            self.idle_stats.idle_sleeps += 1;
            self.idle_stats.tick_stop_success += 1;
        } else {
            self.idle_stats.tick_stop_blocked += 1;
        }
        Ok(can_stop)
    }

    /// Exit idle state.
    ///
    /// Called when the CPU wakes from idle. Restarts the tick if
    /// it was stopped.
    pub fn tick_nohz_idle_exit(&mut self, current_ns: u64) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        if !self.idle_active {
            return Ok(());
        }

        // Update idle time accounting
        let entry_time = self.idle_stats.idle_entrytime_ns;
        if current_ns > entry_time {
            let duration = current_ns - entry_time;
            self.idle_stats.idle_sleeptime_ns += duration;
            if duration > self.idle_stats.max_idle_duration_ns {
                self.idle_stats.max_idle_duration_ns = duration;
            }
        }
        self.idle_stats.idle_exittime_ns = current_ns;
        self.idle_active = false;

        // Restart tick if it was stopped
        if self.tick_stopped {
            self.restart_tick(current_ns)?;
        }
        Ok(())
    }

    /// Check if the idle tick can be stopped.
    ///
    /// Evaluates all conditions that require the periodic tick.
    pub fn can_stop_idle_tick(&mut self, current_ns: u64) -> bool {
        self.busy_reasons = TickBusyReasons::none();

        // Must be in a mode that supports stopping
        if !self.nohz_mode.can_stop_on_idle() {
            return false;
        }

        // Check pending timers
        if self.pending_timers > 0 {
            // Check if nearest timer is beyond the threshold
            if self.next_event_ns > 0 && self.next_event_ns < current_ns + MIN_IDLE_DURATION_NS {
                self.busy_reasons.set(TickBusyReason::PendingTimers);
            }
        }

        // Check RCU
        if self.rcu_pending {
            self.busy_reasons.set(TickBusyReason::RcuCallbacks);
        }

        // Check POSIX CPU timers
        if self.posix_timers_active {
            self.busy_reasons.set(TickBusyReason::PosixCpuTimers);
        }

        // Timer CPU must keep ticking for jiffies
        if self.do_timer_cpu {
            // Only if no other CPU can take over
            self.busy_reasons.set(TickBusyReason::SchedBusy);
        }

        self.busy_reasons.is_clear()
    }

    /// Check if the tick can be stopped in full-dyntick mode.
    ///
    /// In nohz_full mode, the tick can be stopped even when one
    /// task is running (to avoid disturbing latency-sensitive tasks).
    pub fn can_stop_full_tick(&mut self) -> bool {
        if !self.nohz_mode.is_full() {
            return false;
        }
        // Only stop if exactly one task is running
        if self.nr_running != 1 {
            return false;
        }
        // Must still pass all idle-tick checks except sched
        !self.busy_reasons.has(TickBusyReason::PendingTimers)
            && !self.busy_reasons.has(TickBusyReason::RcuCallbacks)
            && !self.busy_reasons.has(TickBusyReason::PosixCpuTimers)
            && !self.busy_reasons.has(TickBusyReason::PerfEvents)
    }

    /// Stop the periodic tick.
    fn stop_tick(&mut self, current_ns: u64) -> Result<()> {
        if self.tick_stopped {
            return Ok(());
        }
        self.tick_stopped = true;
        self.last_tick_ns = current_ns;

        // Compute next event: either an explicit event or max skip
        let next = if self.next_event_ns > current_ns {
            self.next_event_ns
        } else {
            current_ns + MAX_SKIP_NS
        };
        self.next_tick_ns = next;
        Ok(())
    }

    /// Restart the periodic tick.
    fn restart_tick(&mut self, current_ns: u64) -> Result<()> {
        if !self.tick_stopped {
            return Ok(());
        }
        self.tick_stopped = false;

        // Compute how many ticks we missed
        if current_ns > self.last_tick_ns {
            let missed = (current_ns - self.last_tick_ns) / self.tick_period_ns;
            self.tick_count += missed;
        }

        // Reprogram to the next tick boundary
        let next = self.compute_next_tick(current_ns);
        self.next_tick_ns = next;
        self.last_reprogram_ns = current_ns;
        Ok(())
    }

    /// Program the next tick event.
    ///
    /// Sets the clock event device to fire at the specified time.
    pub fn tick_program_event(&mut self, expires_ns: u64, current_ns: u64) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        if expires_ns <= current_ns {
            // Already expired — fire immediately
            self.next_tick_ns = current_ns;
        } else {
            self.next_tick_ns = expires_ns;
        }
        self.last_reprogram_ns = current_ns;
        Ok(())
    }

    /// Handle a tick event (periodic or oneshot).
    ///
    /// Called from the clock event interrupt handler.
    pub fn tick_handler(&mut self, current_ns: u64) -> Result<()> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        self.tick_count += 1;
        self.last_tick_ns = current_ns;

        // If idle, check whether to stop the tick again
        if self.idle_active && self.nohz_mode.can_stop_on_idle() {
            if self.can_stop_idle_tick(current_ns) {
                return self.stop_tick(current_ns);
            }
        }

        // Program next periodic tick
        let next = self.compute_next_tick(current_ns);
        self.next_tick_ns = next;
        Ok(())
    }

    /// Set the next event time (earliest upcoming timer/event).
    pub fn set_next_event(&mut self, next_ns: u64) {
        self.next_event_ns = next_ns;
    }

    /// Get the next tick time.
    pub fn next_tick_ns(&self) -> u64 {
        self.next_tick_ns
    }

    /// Compute the next aligned tick time from `now`.
    fn compute_next_tick(&self, now_ns: u64) -> u64 {
        let period = self.tick_period_ns;
        if period == 0 {
            return now_ns;
        }
        // Align to the next tick boundary
        let elapsed = now_ns.wrapping_sub(self.last_tick_ns);
        let ticks_missed = elapsed / period;
        now_ns
            .wrapping_sub(elapsed % period)
            .wrapping_add((ticks_missed + 1) * period)
    }
}

// ── Tick Scheduler Subsystem ────────────────────────────────────────────────

/// Global tick scheduler statistics.
#[derive(Debug, Clone, Copy)]
pub struct TickSchedStats {
    /// Number of initialized CPUs.
    pub initialized_cpus: u32,
    /// Number of CPUs currently idle.
    pub idle_cpus: u32,
    /// Number of CPUs with tick stopped.
    pub tick_stopped_cpus: u32,
    /// Number of CPUs in full-dyntick mode.
    pub full_dyntick_cpus: u32,
    /// Total tick events processed.
    pub total_ticks: u64,
    /// Total idle entries.
    pub total_idle_entries: u64,
    /// Total idle time (nanoseconds).
    pub total_idle_time_ns: u64,
}

/// Global tick scheduler subsystem.
///
/// Manages the per-CPU tick state and coordinates nohz behavior
/// across all CPUs.
pub struct TickSchedSubsystem {
    /// Per-CPU tick state.
    per_cpu: [TickSchedState; MAX_CPUS],
    /// Number of initialized CPUs.
    cpu_count: u32,
    /// Global nohz mode.
    global_mode: NohzMode,
    /// Which CPU is the current timer (jiffies) CPU.
    timer_cpu: u32,
    /// Current jiffies value.
    jiffies: u64,
    /// Last jiffies update timestamp.
    last_jiffies_update_ns: u64,
    /// Whether the subsystem is active.
    active: bool,
}

impl TickSchedSubsystem {
    /// Create a new tick scheduler subsystem.
    pub const fn new() -> Self {
        Self {
            per_cpu: [const { TickSchedState::new() }; MAX_CPUS],
            cpu_count: 0,
            global_mode: NohzMode::Lowres,
            timer_cpu: 0,
            jiffies: 0,
            last_jiffies_update_ns: 0,
            active: false,
        }
    }

    /// Initialize the subsystem with a global nohz mode.
    pub fn init(&mut self, mode: NohzMode) {
        self.global_mode = mode;
        self.active = true;
    }

    /// Register a CPU.
    pub fn register_cpu(&mut self, cpu_id: u32) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[idx].init(cpu_id, self.global_mode);
        // First CPU becomes the timer CPU
        if self.cpu_count == 0 {
            self.per_cpu[idx].set_timer_cpu(true);
            self.timer_cpu = cpu_id;
        }
        self.cpu_count += 1;
        Ok(())
    }

    /// Get per-CPU state.
    pub fn cpu_state(&self, cpu_id: u32) -> Option<&TickSchedState> {
        let idx = cpu_id as usize;
        if idx < MAX_CPUS && self.per_cpu[idx].initialized {
            Some(&self.per_cpu[idx])
        } else {
            None
        }
    }

    /// Get mutable per-CPU state.
    pub fn cpu_state_mut(&mut self, cpu_id: u32) -> Option<&mut TickSchedState> {
        let idx = cpu_id as usize;
        if idx < MAX_CPUS && self.per_cpu[idx].initialized {
            Some(&mut self.per_cpu[idx])
        } else {
            None
        }
    }

    /// Handle idle entry for a CPU.
    pub fn idle_enter(&mut self, cpu_id: u32, current_ns: u64) -> Result<bool> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS || !self.per_cpu[idx].initialized {
            return Err(Error::InvalidArgument);
        }
        // If this is the timer CPU going idle, try to migrate
        if self.per_cpu[idx].do_timer_cpu {
            self.try_migrate_timer_cpu(cpu_id)?;
        }
        self.per_cpu[idx].tick_nohz_idle_enter(current_ns)
    }

    /// Handle idle exit for a CPU.
    pub fn idle_exit(&mut self, cpu_id: u32, current_ns: u64) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS || !self.per_cpu[idx].initialized {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[idx].tick_nohz_idle_exit(current_ns)?;
        // Update jiffies if we're the timer CPU
        if self.per_cpu[idx].do_timer_cpu {
            self.update_jiffies(current_ns);
        }
        Ok(())
    }

    /// Handle a tick event on a CPU.
    pub fn tick_event(&mut self, cpu_id: u32, current_ns: u64) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS || !self.per_cpu[idx].initialized {
            return Err(Error::InvalidArgument);
        }
        self.per_cpu[idx].tick_handler(current_ns)?;
        // Update jiffies if applicable
        if self.per_cpu[idx].do_timer_cpu {
            self.update_jiffies(current_ns);
        }
        Ok(())
    }

    /// Try to migrate the timer-CPU role to another non-idle CPU.
    fn try_migrate_timer_cpu(&mut self, current_cpu: u32) -> Result<()> {
        // Find a non-idle CPU to take over jiffies duty
        for i in 0..MAX_CPUS {
            let cpu = i as u32;
            if cpu == current_cpu {
                continue;
            }
            if self.per_cpu[i].initialized && !self.per_cpu[i].idle_active {
                // Migrate timer duty
                let old = self.timer_cpu as usize;
                if old < MAX_CPUS {
                    self.per_cpu[old].set_timer_cpu(false);
                }
                self.per_cpu[i].set_timer_cpu(true);
                self.timer_cpu = cpu;
                return Ok(());
            }
        }
        // No other CPU available — keep current
        Ok(())
    }

    /// Update the jiffies counter.
    fn update_jiffies(&mut self, current_ns: u64) {
        if current_ns <= self.last_jiffies_update_ns {
            return;
        }
        let elapsed = current_ns - self.last_jiffies_update_ns;
        let ticks = elapsed / JIFFIES_UPDATE_INTERVAL_NS;
        if ticks > 0 {
            self.jiffies += ticks;
            self.last_jiffies_update_ns += ticks * JIFFIES_UPDATE_INTERVAL_NS;
        }
    }

    /// Get the current jiffies value.
    pub fn jiffies(&self) -> u64 {
        self.jiffies
    }

    /// Get the current timer CPU.
    pub fn timer_cpu(&self) -> u32 {
        self.timer_cpu
    }

    /// Get the global nohz mode.
    pub fn global_mode(&self) -> NohzMode {
        self.global_mode
    }

    /// Set the global nohz mode (affects newly registered CPUs).
    pub fn set_global_mode(&mut self, mode: NohzMode) {
        self.global_mode = mode;
    }

    /// Get subsystem statistics.
    pub fn stats(&self) -> TickSchedStats {
        let mut stats = TickSchedStats {
            initialized_cpus: self.cpu_count,
            idle_cpus: 0,
            tick_stopped_cpus: 0,
            full_dyntick_cpus: 0,
            total_ticks: 0,
            total_idle_entries: 0,
            total_idle_time_ns: 0,
        };
        for cpu in &self.per_cpu {
            if !cpu.initialized {
                continue;
            }
            if cpu.idle_active {
                stats.idle_cpus += 1;
            }
            if cpu.tick_stopped {
                stats.tick_stopped_cpus += 1;
            }
            if cpu.full_dyntick_active {
                stats.full_dyntick_cpus += 1;
            }
            stats.total_ticks += cpu.tick_count;
            stats.total_idle_entries += cpu.idle_stats.idle_calls;
            stats.total_idle_time_ns += cpu.idle_stats.idle_sleeptime_ns;
        }
        stats
    }

    /// Whether the subsystem is active.
    pub fn is_active(&self) -> bool {
        self.active
    }
}
