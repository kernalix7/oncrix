// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Soft and hard lockup detection subsystem.
//!
//! Detects CPUs that are stuck in kernel mode without scheduling
//! (soft lockup) or without processing NMI interrupts (hard lockup),
//! modelled after the Linux kernel's `lockup_detector`.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │                  LockupDetector                          │
//! │                                                          │
//! │  PerCpuWatchdog[0..MAX_CPUS]                             │
//! │  ┌────────────────────────────────────────────────────┐  │
//! │  │  soft_timestamp_ns   — last scheduler activity     │  │
//! │  │  hard_timestamp_ns   — last NMI/timer activity     │  │
//! │  │  touch_ns            — last explicit touch         │  │
//! │  │  soft_lockup_count   — cumulative soft lockups     │  │
//! │  │  hard_lockup_count   — cumulative hard lockups     │  │
//! │  │  state: Healthy | SoftLockup | HardLockup          │  │
//! │  └────────────────────────────────────────────────────┘  │
//! │                                                          │
//! │  Configuration                                           │
//! │  - soft_threshold_ns (default: 20s)                      │
//! │  - hard_threshold_ns (default: 10s)                      │
//! │  - panic_on_soft / panic_on_hard                         │
//! │                                                          │
//! │  GlobalStats                                             │
//! │  - total soft/hard lockups, last lockup info             │
//! └──────────────────────────────────────────────────────────┘
//! ```
//!
//! # Detection Mechanism
//!
//! **Soft lockup**: Each CPU must call `touch_softlockup()` (or
//! implicitly via the scheduler) at least once per soft threshold
//! interval. A soft lockup means the CPU is executing kernel code
//! but not scheduling — the scheduler or timer interrupt is not
//! running.
//!
//! **Hard lockup**: Each CPU must call `touch_hardlockup()` from
//! the NMI or platform timer handler. A hard lockup means the CPU
//! is completely stuck — even the NMI handler is not running,
//! typically caused by disabled interrupts in a tight loop.
//!
//! # Touch / Reset
//!
//! Long-running kernel operations (e.g., memory compaction, large
//! I/O flushes) should call `touch()` periodically to show
//! progress and prevent false positives.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────

/// Maximum number of CPUs supported.
const MAX_CPUS: usize = 64;

/// Default soft lockup threshold in nanoseconds (20 seconds).
const DEFAULT_SOFT_THRESHOLD_NS: u64 = 20_000_000_000;

/// Default hard lockup threshold in nanoseconds (10 seconds).
const DEFAULT_HARD_THRESHOLD_NS: u64 = 10_000_000_000;

/// Minimum threshold in nanoseconds (1 second).
const MIN_THRESHOLD_NS: u64 = 1_000_000_000;

/// Maximum threshold in nanoseconds (5 minutes).
const MAX_THRESHOLD_NS: u64 = 300_000_000_000;

/// Maximum number of lockup events kept in the event log.
const MAX_EVENTS: usize = 128;

/// Sentinel for unused timestamps.
const TIME_NONE: u64 = 0;

/// Default check interval in nanoseconds (1 second).
const DEFAULT_CHECK_INTERVAL_NS: u64 = 1_000_000_000;

// ── WatchdogState ──────────────────────────────────────────────

/// Per-CPU watchdog health state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogState {
    /// CPU is operating normally.
    Healthy,
    /// CPU has not scheduled within the soft threshold.
    SoftLockup,
    /// CPU has not processed NMI within the hard threshold.
    HardLockup,
    /// Watchdog is disabled for this CPU.
    Disabled,
}

impl Default for WatchdogState {
    fn default() -> Self {
        Self::Disabled
    }
}

// ── PerCpuWatchdog ─────────────────────────────────────────────

/// Per-CPU watchdog state.
#[derive(Debug, Clone, Copy)]
pub struct PerCpuWatchdog {
    /// Whether this CPU's watchdog is enabled.
    enabled: bool,
    /// CPU identifier.
    cpu_id: u32,
    /// Current health state.
    state: WatchdogState,
    /// Timestamp of the last scheduler/softirq activity (ns).
    soft_timestamp_ns: u64,
    /// Timestamp of the last NMI/timer activity (ns).
    hard_timestamp_ns: u64,
    /// Timestamp of the last explicit touch (ns).
    touch_ns: u64,
    /// Cumulative soft lockup detections on this CPU.
    soft_lockup_count: u64,
    /// Cumulative hard lockup detections on this CPU.
    hard_lockup_count: u64,
    /// Whether a soft lockup warning has been emitted for the
    /// current lockup episode (suppresses repeated warnings).
    soft_warned: bool,
    /// Whether a hard lockup warning has been emitted for the
    /// current lockup episode.
    hard_warned: bool,
    /// Total time this CPU has spent in soft lockup (ns).
    total_soft_lockup_ns: u64,
    /// Total time this CPU has spent in hard lockup (ns).
    total_hard_lockup_ns: u64,
    /// Timestamp when the current lockup episode started (ns).
    lockup_start_ns: u64,
}

impl Default for PerCpuWatchdog {
    fn default() -> Self {
        Self::empty()
    }
}

impl PerCpuWatchdog {
    /// Create a disabled watchdog for a given CPU.
    pub const fn empty() -> Self {
        Self {
            enabled: false,
            cpu_id: 0,
            state: WatchdogState::Disabled,
            soft_timestamp_ns: TIME_NONE,
            hard_timestamp_ns: TIME_NONE,
            touch_ns: TIME_NONE,
            soft_lockup_count: 0,
            hard_lockup_count: 0,
            soft_warned: false,
            hard_warned: false,
            total_soft_lockup_ns: 0,
            total_hard_lockup_ns: 0,
            lockup_start_ns: TIME_NONE,
        }
    }
}

// ── LockupEvent ────────────────────────────────────────────────

/// Type of lockup event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockupType {
    /// Soft lockup detected.
    Soft,
    /// Hard lockup detected.
    Hard,
    /// Lockup resolved (CPU resumed normal operation).
    Resolved,
}

/// A single lockup event record.
#[derive(Debug, Clone, Copy)]
pub struct LockupEvent {
    /// Type of lockup.
    pub lockup_type: LockupType,
    /// CPU on which the lockup was detected.
    pub cpu_id: u32,
    /// Timestamp when the event was recorded (ns since boot).
    pub timestamp_ns: u64,
    /// Duration of the lockup at detection time (ns).
    pub duration_ns: u64,
    /// Whether this event is valid (used for empty slots).
    valid: bool,
}

impl Default for LockupEvent {
    fn default() -> Self {
        Self::empty()
    }
}

impl LockupEvent {
    /// Create an empty (invalid) event.
    pub const fn empty() -> Self {
        Self {
            lockup_type: LockupType::Soft,
            cpu_id: 0,
            timestamp_ns: TIME_NONE,
            duration_ns: 0,
            valid: false,
        }
    }
}

// ── EventLog ───────────────────────────────────────────────────

/// Ring buffer of lockup events.
struct EventLog {
    /// Event storage.
    events: [LockupEvent; MAX_EVENTS],
    /// Write index.
    write_idx: usize,
    /// Total events written.
    total_written: u64,
}

impl Default for EventLog {
    fn default() -> Self {
        Self::new()
    }
}

impl EventLog {
    /// Create an empty event log.
    const fn new() -> Self {
        Self {
            events: [LockupEvent::empty(); MAX_EVENTS],
            write_idx: 0,
            total_written: 0,
        }
    }

    /// Push a new event.
    fn push(&mut self, event: LockupEvent) {
        self.events[self.write_idx] = event;
        self.write_idx = (self.write_idx + 1) % MAX_EVENTS;
        self.total_written = self.total_written.saturating_add(1);
    }

    /// Return the number of valid events.
    fn count(&self) -> usize {
        if self.total_written >= MAX_EVENTS as u64 {
            MAX_EVENTS
        } else {
            self.total_written as usize
        }
    }

    /// Get an event by logical index (0 = oldest available).
    fn get(&self, index: usize) -> Option<&LockupEvent> {
        let count = self.count();
        if index >= count {
            return None;
        }
        let start = if self.total_written >= MAX_EVENTS as u64 {
            self.write_idx
        } else {
            0
        };
        let actual = (start + index) % MAX_EVENTS;
        let event = &self.events[actual];
        if event.valid { Some(event) } else { None }
    }
}

// ── LockupConfig ───────────────────────────────────────────────

/// Configuration for the lockup detector.
#[derive(Debug, Clone, Copy)]
pub struct LockupConfig {
    /// Soft lockup threshold (ns).
    pub soft_threshold_ns: u64,
    /// Hard lockup threshold (ns).
    pub hard_threshold_ns: u64,
    /// Trigger kernel panic on soft lockup.
    pub panic_on_soft: bool,
    /// Trigger kernel panic on hard lockup.
    pub panic_on_hard: bool,
    /// Whether soft lockup detection is enabled globally.
    pub soft_enabled: bool,
    /// Whether hard lockup detection is enabled globally.
    pub hard_enabled: bool,
    /// Interval between watchdog checks (ns).
    pub check_interval_ns: u64,
}

impl Default for LockupConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl LockupConfig {
    /// Create a configuration with default values.
    pub const fn new() -> Self {
        Self {
            soft_threshold_ns: DEFAULT_SOFT_THRESHOLD_NS,
            hard_threshold_ns: DEFAULT_HARD_THRESHOLD_NS,
            panic_on_soft: false,
            panic_on_hard: true,
            soft_enabled: true,
            hard_enabled: true,
            check_interval_ns: DEFAULT_CHECK_INTERVAL_NS,
        }
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<()> {
        if self.soft_threshold_ns < MIN_THRESHOLD_NS || self.soft_threshold_ns > MAX_THRESHOLD_NS {
            return Err(Error::InvalidArgument);
        }
        if self.hard_threshold_ns < MIN_THRESHOLD_NS || self.hard_threshold_ns > MAX_THRESHOLD_NS {
            return Err(Error::InvalidArgument);
        }
        if self.check_interval_ns == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ── LockupStats ────────────────────────────────────────────────

/// Global lockup detection statistics.
#[derive(Debug, Clone, Copy)]
pub struct LockupStats {
    /// Total soft lockups detected across all CPUs.
    pub total_soft_lockups: u64,
    /// Total hard lockups detected across all CPUs.
    pub total_hard_lockups: u64,
    /// Total panics requested.
    pub panic_requests: u64,
    /// Total checks performed.
    pub checks_performed: u64,
    /// Timestamp of the last check (ns).
    pub last_check_ns: u64,
    /// CPU of the most recent lockup.
    pub last_lockup_cpu: u32,
    /// Type of the most recent lockup.
    pub last_lockup_type: Option<LockupType>,
    /// Number of CPUs currently in lockup state.
    pub cpus_in_lockup: u32,
}

impl Default for LockupStats {
    fn default() -> Self {
        Self::new()
    }
}

impl LockupStats {
    /// Create zero-initialised stats.
    pub const fn new() -> Self {
        Self {
            total_soft_lockups: 0,
            total_hard_lockups: 0,
            panic_requests: 0,
            checks_performed: 0,
            last_check_ns: TIME_NONE,
            last_lockup_cpu: 0,
            last_lockup_type: None,
            cpus_in_lockup: 0,
        }
    }
}

// ── CheckResult ────────────────────────────────────────────────

/// Result of a single watchdog check pass.
#[derive(Debug, Clone, Copy)]
pub struct CheckResult {
    /// Number of CPUs checked.
    pub cpus_checked: u32,
    /// Number of new soft lockups detected.
    pub new_soft_lockups: u32,
    /// Number of new hard lockups detected.
    pub new_hard_lockups: u32,
    /// Number of lockups that resolved.
    pub resolved: u32,
    /// Whether a panic was requested.
    pub panic_requested: bool,
}

// ── PerCpuStats ────────────────────────────────────────────────

/// Read-only statistics snapshot for a single CPU.
#[derive(Debug, Clone, Copy)]
pub struct PerCpuStats {
    /// CPU identifier.
    pub cpu_id: u32,
    /// Current state.
    pub state: WatchdogState,
    /// Cumulative soft lockup count.
    pub soft_lockup_count: u64,
    /// Cumulative hard lockup count.
    pub hard_lockup_count: u64,
    /// Total time in soft lockup (ns).
    pub total_soft_lockup_ns: u64,
    /// Total time in hard lockup (ns).
    pub total_hard_lockup_ns: u64,
    /// Whether the watchdog is enabled.
    pub enabled: bool,
}

// ── LockupDetector ─────────────────────────────────────────────

/// Soft and hard lockup detector.
///
/// Manages per-CPU watchdog state and performs periodic checks to
/// detect CPUs that are stuck in kernel mode.
pub struct LockupDetector {
    /// Per-CPU watchdog state.
    cpus: [PerCpuWatchdog; MAX_CPUS],
    /// Configuration.
    config: LockupConfig,
    /// Global statistics.
    stats: LockupStats,
    /// Event log.
    events: EventLog,
    /// Current monotonic time (ns).
    now_ns: u64,
    /// Timestamp of the last check pass.
    last_check_ns: u64,
    /// Number of online (enabled) CPUs.
    online_count: u32,
}

impl Default for LockupDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl LockupDetector {
    /// Create a new lockup detector.
    pub const fn new() -> Self {
        Self {
            cpus: [PerCpuWatchdog::empty(); MAX_CPUS],
            config: LockupConfig::new(),
            stats: LockupStats::new(),
            events: EventLog::new(),
            now_ns: 0,
            last_check_ns: 0,
            online_count: 0,
        }
    }

    /// Update the detector's notion of current time.
    pub fn update_time(&mut self, now_ns: u64) {
        self.now_ns = now_ns;
    }

    /// Set the configuration.
    pub fn configure(&mut self, config: LockupConfig) -> Result<()> {
        config.validate()?;
        self.config = config;
        Ok(())
    }

    /// Set the soft lockup threshold.
    pub fn set_soft_threshold(&mut self, threshold_ns: u64) -> Result<()> {
        if threshold_ns < MIN_THRESHOLD_NS || threshold_ns > MAX_THRESHOLD_NS {
            return Err(Error::InvalidArgument);
        }
        self.config.soft_threshold_ns = threshold_ns;
        Ok(())
    }

    /// Set the hard lockup threshold.
    pub fn set_hard_threshold(&mut self, threshold_ns: u64) -> Result<()> {
        if threshold_ns < MIN_THRESHOLD_NS || threshold_ns > MAX_THRESHOLD_NS {
            return Err(Error::InvalidArgument);
        }
        self.config.hard_threshold_ns = threshold_ns;
        Ok(())
    }

    /// Enable the watchdog for a specific CPU.
    pub fn enable_cpu(&mut self, cpu_id: u32) -> Result<()> {
        if cpu_id as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let cpu = &mut self.cpus[cpu_id as usize];
        if cpu.enabled {
            return Err(Error::AlreadyExists);
        }
        cpu.enabled = true;
        cpu.cpu_id = cpu_id;
        cpu.state = WatchdogState::Healthy;
        cpu.soft_timestamp_ns = self.now_ns;
        cpu.hard_timestamp_ns = self.now_ns;
        cpu.touch_ns = self.now_ns;
        self.online_count = self.online_count.saturating_add(1);
        Ok(())
    }

    /// Disable the watchdog for a specific CPU.
    pub fn disable_cpu(&mut self, cpu_id: u32) -> Result<()> {
        if cpu_id as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let cpu = &mut self.cpus[cpu_id as usize];
        if !cpu.enabled {
            return Err(Error::NotFound);
        }
        // Account for any ongoing lockup.
        if cpu.state == WatchdogState::SoftLockup || cpu.state == WatchdogState::HardLockup {
            self.stats.cpus_in_lockup = self.stats.cpus_in_lockup.saturating_sub(1);
        }
        cpu.enabled = false;
        cpu.state = WatchdogState::Disabled;
        self.online_count = self.online_count.saturating_sub(1);
        Ok(())
    }

    /// Touch the soft lockup watchdog for a CPU.
    ///
    /// Called from the scheduler or timer interrupt handler to
    /// indicate that the CPU is making progress.
    pub fn touch_softlockup(&mut self, cpu_id: u32) {
        if let Some(cpu) = self.cpus.get_mut(cpu_id as usize) {
            if cpu.enabled {
                cpu.soft_timestamp_ns = self.now_ns;
            }
        }
    }

    /// Touch the hard lockup watchdog for a CPU.
    ///
    /// Called from the NMI handler or platform watchdog timer.
    pub fn touch_hardlockup(&mut self, cpu_id: u32) {
        if let Some(cpu) = self.cpus.get_mut(cpu_id as usize) {
            if cpu.enabled {
                cpu.hard_timestamp_ns = self.now_ns;
            }
        }
    }

    /// Explicit touch to prevent false positives during known
    /// long-running kernel operations.
    ///
    /// Resets both soft and hard timestamps.
    pub fn touch(&mut self, cpu_id: u32) {
        if let Some(cpu) = self.cpus.get_mut(cpu_id as usize) {
            if cpu.enabled {
                cpu.soft_timestamp_ns = self.now_ns;
                cpu.hard_timestamp_ns = self.now_ns;
                cpu.touch_ns = self.now_ns;
            }
        }
    }

    /// Perform a check pass across all enabled CPUs.
    ///
    /// Returns a summary of new lockups and resolutions.
    pub fn check(&mut self) -> CheckResult {
        let mut result = CheckResult {
            cpus_checked: 0,
            new_soft_lockups: 0,
            new_hard_lockups: 0,
            resolved: 0,
            panic_requested: false,
        };

        self.last_check_ns = self.now_ns;
        self.stats.checks_performed = self.stats.checks_performed.saturating_add(1);
        self.stats.last_check_ns = self.now_ns;

        for i in 0..MAX_CPUS {
            let cpu = &self.cpus[i];
            if !cpu.enabled {
                continue;
            }
            result.cpus_checked += 1;

            let old_state = cpu.state;

            // Check hard lockup first (more severe).
            let hard_elapsed = if self.config.hard_enabled {
                self.now_ns.saturating_sub(cpu.hard_timestamp_ns)
            } else {
                0
            };

            let soft_elapsed = if self.config.soft_enabled {
                self.now_ns.saturating_sub(cpu.soft_timestamp_ns)
            } else {
                0
            };

            let new_state = if self.config.hard_enabled
                && hard_elapsed >= self.config.hard_threshold_ns
            {
                WatchdogState::HardLockup
            } else if self.config.soft_enabled && soft_elapsed >= self.config.soft_threshold_ns {
                WatchdogState::SoftLockup
            } else {
                WatchdogState::Healthy
            };

            // Apply state transitions.
            let cpu = &mut self.cpus[i];
            cpu.state = new_state;

            match (old_state, new_state) {
                (WatchdogState::Healthy, WatchdogState::SoftLockup) => {
                    cpu.soft_lockup_count = cpu.soft_lockup_count.saturating_add(1);
                    cpu.soft_warned = true;
                    cpu.lockup_start_ns = self.now_ns;
                    result.new_soft_lockups += 1;
                    self.stats.total_soft_lockups = self.stats.total_soft_lockups.saturating_add(1);
                    self.stats.last_lockup_cpu = cpu.cpu_id;
                    self.stats.last_lockup_type = Some(LockupType::Soft);
                    self.stats.cpus_in_lockup = self.stats.cpus_in_lockup.saturating_add(1);
                    self.events.push(LockupEvent {
                        lockup_type: LockupType::Soft,
                        cpu_id: cpu.cpu_id,
                        timestamp_ns: self.now_ns,
                        duration_ns: soft_elapsed,
                        valid: true,
                    });
                    if self.config.panic_on_soft {
                        result.panic_requested = true;
                        self.stats.panic_requests = self.stats.panic_requests.saturating_add(1);
                    }
                }
                (WatchdogState::Healthy | WatchdogState::SoftLockup, WatchdogState::HardLockup) => {
                    if old_state == WatchdogState::Healthy {
                        cpu.lockup_start_ns = self.now_ns;
                        self.stats.cpus_in_lockup = self.stats.cpus_in_lockup.saturating_add(1);
                    }
                    cpu.hard_lockup_count = cpu.hard_lockup_count.saturating_add(1);
                    cpu.hard_warned = true;
                    result.new_hard_lockups += 1;
                    self.stats.total_hard_lockups = self.stats.total_hard_lockups.saturating_add(1);
                    self.stats.last_lockup_cpu = cpu.cpu_id;
                    self.stats.last_lockup_type = Some(LockupType::Hard);
                    self.events.push(LockupEvent {
                        lockup_type: LockupType::Hard,
                        cpu_id: cpu.cpu_id,
                        timestamp_ns: self.now_ns,
                        duration_ns: hard_elapsed,
                        valid: true,
                    });
                    if self.config.panic_on_hard {
                        result.panic_requested = true;
                        self.stats.panic_requests = self.stats.panic_requests.saturating_add(1);
                    }
                }
                (WatchdogState::SoftLockup | WatchdogState::HardLockup, WatchdogState::Healthy) => {
                    // Lockup resolved.
                    let duration = self.now_ns.saturating_sub(cpu.lockup_start_ns);
                    if old_state == WatchdogState::SoftLockup {
                        cpu.total_soft_lockup_ns =
                            cpu.total_soft_lockup_ns.saturating_add(duration);
                    } else {
                        cpu.total_hard_lockup_ns =
                            cpu.total_hard_lockup_ns.saturating_add(duration);
                    }
                    cpu.soft_warned = false;
                    cpu.hard_warned = false;
                    cpu.lockup_start_ns = TIME_NONE;
                    result.resolved += 1;
                    self.stats.cpus_in_lockup = self.stats.cpus_in_lockup.saturating_sub(1);
                    self.events.push(LockupEvent {
                        lockup_type: LockupType::Resolved,
                        cpu_id: cpu.cpu_id,
                        timestamp_ns: self.now_ns,
                        duration_ns: duration,
                        valid: true,
                    });
                }
                _ => {
                    // No transition — state unchanged.
                }
            }
        }

        result
    }

    /// Check if enough time has elapsed for the next check.
    pub fn should_check(&self) -> bool {
        let elapsed = self.now_ns.saturating_sub(self.last_check_ns);
        elapsed >= self.config.check_interval_ns
    }

    /// Perform a conditional check (only if the interval has
    /// elapsed).
    pub fn tick(&mut self, now_ns: u64) -> Option<CheckResult> {
        self.update_time(now_ns);
        if self.should_check() {
            Some(self.check())
        } else {
            None
        }
    }

    /// Return global statistics.
    pub fn stats(&self) -> &LockupStats {
        &self.stats
    }

    /// Return the current configuration.
    pub fn config(&self) -> &LockupConfig {
        &self.config
    }

    /// Return the number of online (enabled) CPUs.
    pub fn online_count(&self) -> u32 {
        self.online_count
    }

    /// Return per-CPU statistics for a given CPU.
    pub fn cpu_stats(&self, cpu_id: u32) -> Result<PerCpuStats> {
        if cpu_id as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let cpu = &self.cpus[cpu_id as usize];
        if !cpu.enabled {
            return Err(Error::NotFound);
        }
        Ok(PerCpuStats {
            cpu_id: cpu.cpu_id,
            state: cpu.state,
            soft_lockup_count: cpu.soft_lockup_count,
            hard_lockup_count: cpu.hard_lockup_count,
            total_soft_lockup_ns: cpu.total_soft_lockup_ns,
            total_hard_lockup_ns: cpu.total_hard_lockup_ns,
            enabled: cpu.enabled,
        })
    }

    /// Return the watchdog state for a given CPU.
    pub fn cpu_state(&self, cpu_id: u32) -> Result<WatchdogState> {
        if cpu_id as usize >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.cpus[cpu_id as usize].state)
    }

    /// Return the number of events in the event log.
    pub fn event_count(&self) -> usize {
        self.events.count()
    }

    /// Get an event by index (0 = oldest available).
    pub fn get_event(&self, index: usize) -> Option<&LockupEvent> {
        self.events.get(index)
    }

    /// Enable or disable panic-on-soft-lockup.
    pub fn set_panic_on_soft(&mut self, panic: bool) {
        self.config.panic_on_soft = panic;
    }

    /// Enable or disable panic-on-hard-lockup.
    pub fn set_panic_on_hard(&mut self, panic: bool) {
        self.config.panic_on_hard = panic;
    }

    /// Enable or disable soft lockup detection globally.
    pub fn set_soft_enabled(&mut self, enabled: bool) {
        self.config.soft_enabled = enabled;
    }

    /// Enable or disable hard lockup detection globally.
    pub fn set_hard_enabled(&mut self, enabled: bool) {
        self.config.hard_enabled = enabled;
    }
}
