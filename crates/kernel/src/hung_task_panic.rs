// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hung task panic handler — triggering panic on unrecoverable hung tasks.
//!
//! When the hung task detector finds a task that has been uninterruptible
//! for an extended period and the system policy dictates a panic, this
//! module handles the panic generation including collecting diagnostic
//! information and notifying subsystems.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                   HungTaskPanic                              │
//! │                                                              │
//! │  PanicRecord[0..MAX_RECORDS]  (hung task panic records)      │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  pid: u64                                              │  │
//! │  │  hung_duration_secs: u64                               │  │
//! │  │  action_taken: PanicAction                             │  │
//! │  │  timestamp: u64                                        │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  HungTaskPanicConfig                                         │
//! │  - timeout_secs, panic_on_hung, max_warnings                 │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `kernel/hung_task.c`, `include/linux/sched/sysctl.h`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum panic records kept.
const MAX_RECORDS: usize = 64;

/// Default hung task timeout in seconds.
const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// Maximum timeout in seconds.
const MAX_TIMEOUT_SECS: u64 = 3600;

/// Default maximum warnings before panic.
const DEFAULT_MAX_WARNINGS: u32 = 10;

// ══════════════════════════════════════════════════════════════
// PanicAction
// ══════════════════════════════════════════════════════════════

/// Action taken when a hung task is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PanicAction {
    /// Log a warning only.
    Warn = 0,
    /// Send SIGKILL to the hung task.
    Kill = 1,
    /// Trigger a kernel panic.
    Panic = 2,
    /// Generate a backtrace and warning.
    BacktraceWarn = 3,
}

impl PanicAction {
    /// Display name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Warn => "warn",
            Self::Kill => "kill",
            Self::Panic => "panic",
            Self::BacktraceWarn => "backtrace_warn",
        }
    }
}

// ══════════════════════════════════════════════════════════════
// TaskState — state of the hung task
// ══════════════════════════════════════════════════════════════

/// State of the task when it was detected as hung.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TaskState {
    /// Task in uninterruptible sleep (D state).
    Uninterruptible = 0,
    /// Task in killable sleep.
    Killable = 1,
    /// Task stuck in I/O wait.
    IoWait = 2,
    /// Unknown state.
    Unknown = 3,
}

// ══════════════════════════════════════════════════════════════
// PanicRecord
// ══════════════════════════════════════════════════════════════

/// Record of a hung task detection event.
#[derive(Debug, Clone, Copy)]
pub struct PanicRecord {
    /// PID of the hung task.
    pub pid: u64,
    /// How long the task was hung (in seconds).
    pub hung_duration_secs: u64,
    /// Task state when detected.
    pub task_state: TaskState,
    /// Action taken.
    pub action_taken: PanicAction,
    /// Timestamp of detection (tick).
    pub timestamp: u64,
    /// Whether this record is active.
    pub active: bool,
    /// CPU the task was last seen on.
    pub last_cpu: u16,
}

impl PanicRecord {
    const fn empty() -> Self {
        Self {
            pid: 0,
            hung_duration_secs: 0,
            task_state: TaskState::Unknown,
            action_taken: PanicAction::Warn,
            timestamp: 0,
            active: false,
            last_cpu: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// HungTaskPanicConfig
// ══════════════════════════════════════════════════════════════

/// Configuration for hung task panic handling.
#[derive(Debug, Clone, Copy)]
pub struct HungTaskPanicConfig {
    /// Timeout before considering a task hung (seconds).
    pub timeout_secs: u64,
    /// Whether to panic on hung task detection.
    pub panic_on_hung: bool,
    /// Maximum warnings before escalating to panic.
    pub max_warnings: u32,
    /// Default action for detected hung tasks.
    pub default_action: PanicAction,
    /// Whether to include backtrace in reports.
    pub include_backtrace: bool,
}

impl HungTaskPanicConfig {
    const fn new() -> Self {
        Self {
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            panic_on_hung: false,
            max_warnings: DEFAULT_MAX_WARNINGS,
            default_action: PanicAction::Warn,
            include_backtrace: true,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// HungTaskPanicStats
// ══════════════════════════════════════════════════════════════

/// Statistics for the hung task panic handler.
#[derive(Debug, Clone, Copy)]
pub struct HungTaskPanicStats {
    /// Total hung tasks detected.
    pub total_detected: u64,
    /// Total warnings issued.
    pub total_warnings: u64,
    /// Total kills issued.
    pub total_kills: u64,
    /// Total panics triggered.
    pub total_panics: u64,
    /// Longest hung duration observed (seconds).
    pub max_hung_secs: u64,
}

impl HungTaskPanicStats {
    const fn new() -> Self {
        Self {
            total_detected: 0,
            total_warnings: 0,
            total_kills: 0,
            total_panics: 0,
            max_hung_secs: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// HungTaskPanic
// ══════════════════════════════════════════════════════════════

/// Top-level hung task panic handler.
pub struct HungTaskPanic {
    /// Panic records.
    records: [PanicRecord; MAX_RECORDS],
    /// Configuration.
    config: HungTaskPanicConfig,
    /// Statistics.
    stats: HungTaskPanicStats,
    /// Current warning count (resets on panic or period).
    warning_count: u32,
    /// Write cursor for records (ring buffer).
    write_cursor: usize,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl Default for HungTaskPanic {
    fn default() -> Self {
        Self::new()
    }
}

impl HungTaskPanic {
    /// Create a new hung task panic handler.
    pub const fn new() -> Self {
        Self {
            records: [const { PanicRecord::empty() }; MAX_RECORDS],
            config: HungTaskPanicConfig::new(),
            stats: HungTaskPanicStats::new(),
            warning_count: 0,
            write_cursor: 0,
            initialised: false,
        }
    }

    /// Initialise the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.initialised = true;
        Ok(())
    }

    // ── Configuration ────────────────────────────────────────

    /// Set the hung task timeout.
    pub fn set_timeout(&mut self, secs: u64) -> Result<()> {
        if secs == 0 || secs > MAX_TIMEOUT_SECS {
            return Err(Error::InvalidArgument);
        }
        self.config.timeout_secs = secs;
        Ok(())
    }

    /// Set whether to panic on hung task.
    pub fn set_panic_on_hung(&mut self, panic_on_hung: bool) {
        self.config.panic_on_hung = panic_on_hung;
    }

    /// Set the default action.
    pub fn set_default_action(&mut self, action: PanicAction) {
        self.config.default_action = action;
    }

    /// Return the configuration.
    pub fn config(&self) -> HungTaskPanicConfig {
        self.config
    }

    // ── Detection ────────────────────────────────────────────

    /// Report a hung task and determine what action to take.
    ///
    /// Returns the action that should be taken.
    pub fn report_hung(
        &mut self,
        pid: u64,
        hung_duration_secs: u64,
        task_state: TaskState,
        last_cpu: u16,
        timestamp: u64,
    ) -> Result<PanicAction> {
        self.stats.total_detected += 1;

        if hung_duration_secs > self.stats.max_hung_secs {
            self.stats.max_hung_secs = hung_duration_secs;
        }

        // Determine action.
        let action = if self.config.panic_on_hung && self.warning_count >= self.config.max_warnings
        {
            PanicAction::Panic
        } else {
            self.config.default_action
        };

        // Record.
        let slot = self.write_cursor;
        self.write_cursor = (self.write_cursor + 1) % MAX_RECORDS;

        self.records[slot] = PanicRecord {
            pid,
            hung_duration_secs,
            task_state,
            action_taken: action,
            timestamp,
            active: true,
            last_cpu,
        };

        // Update stats.
        match action {
            PanicAction::Warn | PanicAction::BacktraceWarn => {
                self.stats.total_warnings += 1;
                self.warning_count += 1;
            }
            PanicAction::Kill => {
                self.stats.total_kills += 1;
            }
            PanicAction::Panic => {
                self.stats.total_panics += 1;
            }
        }

        Ok(action)
    }

    /// Reset the warning counter.
    pub fn reset_warnings(&mut self) {
        self.warning_count = 0;
    }

    // ── Query ────────────────────────────────────────────────

    /// Return statistics.
    pub fn stats(&self) -> HungTaskPanicStats {
        self.stats
    }

    /// Return the current warning count.
    pub fn warning_count(&self) -> u32 {
        self.warning_count
    }

    /// Return the number of active records.
    pub fn record_count(&self) -> usize {
        self.records.iter().filter(|r| r.active).count()
    }

    /// Return the most recent record.
    pub fn most_recent(&self) -> Option<&PanicRecord> {
        self.records
            .iter()
            .filter(|r| r.active)
            .max_by_key(|r| r.timestamp)
    }
}
