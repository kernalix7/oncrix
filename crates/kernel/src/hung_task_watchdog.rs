// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hung task watchdog extension.
//!
//! Extends the basic hung task detector with configurable watchdog
//! policies, per-task timeout overrides, and integration with the
//! panic notifier chain. Monitors tasks in uninterruptible sleep
//! and generates warnings or panics when thresholds are exceeded.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum number of watched tasks.
const MAX_WATCHED_TASKS: usize = 256;

/// Maximum number of watchdog policies.
const MAX_POLICIES: usize = 16;

/// Default hung timeout in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// Maximum warnings before escalation.
const MAX_WARNINGS: u32 = 3;

/// Check interval in milliseconds.
const _CHECK_INTERVAL_MS: u64 = 10_000;

// ── Types ────────────────────────────────────────────────────────────

/// Action to take when a hung task is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HungTaskAction {
    /// Log a warning.
    Warn,
    /// Send a signal to the task.
    Signal,
    /// Trigger a kernel panic.
    Panic,
    /// Log and continue.
    LogOnly,
}

impl Default for HungTaskAction {
    fn default() -> Self {
        Self::Warn
    }
}

/// State of a watched task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchedTaskState {
    /// Task is running normally.
    Running,
    /// Task is in uninterruptible sleep.
    UninterruptibleSleep,
    /// Task has been flagged as potentially hung.
    Suspected,
    /// Task has been confirmed hung.
    Hung,
    /// Task has recovered.
    Recovered,
}

impl Default for WatchedTaskState {
    fn default() -> Self {
        Self::Running
    }
}

/// A watched task record.
#[derive(Debug, Clone)]
pub struct WatchedTask {
    /// Process identifier.
    pid: u64,
    /// Current state.
    state: WatchedTaskState,
    /// Timeout override (0 = use default).
    timeout_secs: u64,
    /// Time spent in current state (nanoseconds).
    state_duration_ns: u64,
    /// Number of warnings issued.
    warnings_issued: u32,
    /// Last check timestamp (nanoseconds).
    last_check_ns: u64,
    /// Last switch count observed.
    last_switch_count: u64,
    /// Whether this task has a custom policy.
    custom_policy: bool,
}

impl WatchedTask {
    /// Creates a new watched task.
    pub const fn new(pid: u64) -> Self {
        Self {
            pid,
            state: WatchedTaskState::Running,
            timeout_secs: 0,
            state_duration_ns: 0,
            warnings_issued: 0,
            last_check_ns: 0,
            last_switch_count: 0,
            custom_policy: false,
        }
    }

    /// Returns the process identifier.
    pub const fn pid(&self) -> u64 {
        self.pid
    }

    /// Returns the current state.
    pub const fn state(&self) -> WatchedTaskState {
        self.state
    }

    /// Returns the number of warnings issued.
    pub const fn warnings_issued(&self) -> u32 {
        self.warnings_issued
    }
}

/// A watchdog policy definition.
#[derive(Debug, Clone)]
pub struct WatchdogPolicy {
    /// Policy identifier.
    policy_id: u32,
    /// Timeout threshold in seconds.
    timeout_secs: u64,
    /// Action to take on first detection.
    first_action: HungTaskAction,
    /// Action to take on escalation (after MAX_WARNINGS).
    escalation_action: HungTaskAction,
    /// Whether to dump the task stack on detection.
    dump_stack: bool,
    /// Whether this policy is enabled.
    enabled: bool,
}

impl WatchdogPolicy {
    /// Creates a new watchdog policy.
    pub const fn new(policy_id: u32, timeout_secs: u64, first_action: HungTaskAction) -> Self {
        Self {
            policy_id,
            timeout_secs,
            first_action,
            escalation_action: HungTaskAction::Panic,
            dump_stack: true,
            enabled: true,
        }
    }

    /// Returns the timeout in seconds.
    pub const fn timeout_secs(&self) -> u64 {
        self.timeout_secs
    }

    /// Returns whether this policy is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Detection result for a single check cycle.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    /// PID of the detected task.
    pub pid: u64,
    /// Action taken.
    pub action: HungTaskAction,
    /// How long the task has been hung (nanoseconds).
    pub hung_duration_ns: u64,
    /// Whether this is an escalation.
    pub escalated: bool,
}

/// Hung task watchdog statistics.
#[derive(Debug, Clone)]
pub struct HungTaskWatchdogStats {
    /// Total check cycles performed.
    pub total_checks: u64,
    /// Total hung tasks detected.
    pub total_detections: u64,
    /// Total warnings issued.
    pub total_warnings: u64,
    /// Total escalations.
    pub total_escalations: u64,
    /// Total recovered tasks.
    pub total_recoveries: u64,
    /// Currently watched tasks.
    pub watched_count: u32,
}

impl Default for HungTaskWatchdogStats {
    fn default() -> Self {
        Self::new()
    }
}

impl HungTaskWatchdogStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_checks: 0,
            total_detections: 0,
            total_warnings: 0,
            total_escalations: 0,
            total_recoveries: 0,
            watched_count: 0,
        }
    }
}

/// Central hung task watchdog.
#[derive(Debug)]
pub struct HungTaskWatchdog {
    /// Watched tasks.
    tasks: [Option<WatchedTask>; MAX_WATCHED_TASKS],
    /// Policies.
    policies: [Option<WatchdogPolicy>; MAX_POLICIES],
    /// Number of watched tasks.
    task_count: usize,
    /// Number of policies.
    policy_count: usize,
    /// Default timeout in seconds.
    default_timeout_secs: u64,
    /// Default action.
    default_action: HungTaskAction,
    /// Whether the watchdog is running.
    running: bool,
    /// Statistics.
    total_checks: u64,
    total_detections: u64,
    total_warnings: u64,
    total_escalations: u64,
    total_recoveries: u64,
}

impl Default for HungTaskWatchdog {
    fn default() -> Self {
        Self::new()
    }
}

impl HungTaskWatchdog {
    /// Creates a new hung task watchdog.
    pub const fn new() -> Self {
        Self {
            tasks: [const { None }; MAX_WATCHED_TASKS],
            policies: [const { None }; MAX_POLICIES],
            task_count: 0,
            policy_count: 0,
            default_timeout_secs: DEFAULT_TIMEOUT_SECS,
            default_action: HungTaskAction::Warn,
            running: false,
            total_checks: 0,
            total_detections: 0,
            total_warnings: 0,
            total_escalations: 0,
            total_recoveries: 0,
        }
    }

    /// Starts the watchdog.
    pub fn start(&mut self) -> Result<()> {
        if self.running {
            return Err(Error::AlreadyExists);
        }
        self.running = true;
        Ok(())
    }

    /// Stops the watchdog.
    pub fn stop(&mut self) -> Result<()> {
        if !self.running {
            return Err(Error::InvalidArgument);
        }
        self.running = false;
        Ok(())
    }

    /// Adds a task to be watched.
    pub fn watch_task(&mut self, pid: u64) -> Result<()> {
        if self.task_count >= MAX_WATCHED_TASKS {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate.
        for slot in self.tasks.iter().flatten() {
            if slot.pid == pid {
                return Err(Error::AlreadyExists);
            }
        }
        let task = WatchedTask::new(pid);
        if let Some(slot) = self.tasks.iter_mut().find(|s| s.is_none()) {
            *slot = Some(task);
            self.task_count += 1;
            Ok(())
        } else {
            Err(Error::OutOfMemory)
        }
    }

    /// Removes a task from the watch list.
    pub fn unwatch_task(&mut self, pid: u64) -> Result<()> {
        let slot = self
            .tasks
            .iter_mut()
            .find(|s| s.as_ref().map_or(false, |t| t.pid == pid))
            .ok_or(Error::NotFound)?;
        *slot = None;
        self.task_count -= 1;
        Ok(())
    }

    /// Adds a watchdog policy.
    pub fn add_policy(&mut self, timeout_secs: u64, first_action: HungTaskAction) -> Result<u32> {
        if self.policy_count >= MAX_POLICIES {
            return Err(Error::OutOfMemory);
        }
        let id = self.policy_count as u32;
        let policy = WatchdogPolicy::new(id, timeout_secs, first_action);
        if let Some(slot) = self.policies.iter_mut().find(|s| s.is_none()) {
            *slot = Some(policy);
            self.policy_count += 1;
            Ok(id)
        } else {
            Err(Error::OutOfMemory)
        }
    }

    /// Performs a check cycle, updating task states.
    pub fn check_cycle(&mut self, current_ns: u64) -> Result<u32> {
        if !self.running {
            return Err(Error::InvalidArgument);
        }
        self.total_checks += 1;
        let timeout_ns = self.default_timeout_secs * 1_000_000_000;
        let mut detections = 0u32;
        for slot in self.tasks.iter_mut().flatten() {
            let elapsed = current_ns.saturating_sub(slot.last_check_ns);
            slot.state_duration_ns += elapsed;
            slot.last_check_ns = current_ns;
            match slot.state {
                WatchedTaskState::UninterruptibleSleep => {
                    let effective_timeout = if slot.timeout_secs > 0 {
                        slot.timeout_secs * 1_000_000_000
                    } else {
                        timeout_ns
                    };
                    if slot.state_duration_ns > effective_timeout {
                        slot.state = WatchedTaskState::Hung;
                        slot.warnings_issued += 1;
                        self.total_detections += 1;
                        self.total_warnings += 1;
                        detections += 1;
                        if slot.warnings_issued > MAX_WARNINGS {
                            self.total_escalations += 1;
                        }
                    }
                }
                WatchedTaskState::Running => {
                    if slot.state_duration_ns > 0 {
                        slot.state_duration_ns = 0;
                    }
                }
                _ => {}
            }
        }
        Ok(detections)
    }

    /// Updates a task's state.
    pub fn update_task_state(&mut self, pid: u64, new_state: WatchedTaskState) -> Result<()> {
        let task = self
            .tasks
            .iter_mut()
            .flatten()
            .find(|t| t.pid == pid)
            .ok_or(Error::NotFound)?;
        let old_state = task.state;
        task.state = new_state;
        task.state_duration_ns = 0;
        if matches!(old_state, WatchedTaskState::Hung)
            && matches!(new_state, WatchedTaskState::Running)
        {
            self.total_recoveries += 1;
        }
        Ok(())
    }

    /// Returns watchdog statistics.
    pub fn stats(&self) -> HungTaskWatchdogStats {
        HungTaskWatchdogStats {
            total_checks: self.total_checks,
            total_detections: self.total_detections,
            total_warnings: self.total_warnings,
            total_escalations: self.total_escalations,
            total_recoveries: self.total_recoveries,
            watched_count: self.task_count as u32,
        }
    }

    /// Returns the number of watched tasks.
    pub const fn task_count(&self) -> usize {
        self.task_count
    }
}
