// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hung task detection subsystem.
//!
//! Monitors tasks stuck in uninterruptible sleep (D-state) for longer
//! than a configurable timeout, similar to the Linux kernel's
//! `hung_task_timeout_secs` mechanism.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │               HungTaskDetector                      │
//! │                                                     │
//! │  TaskEntry[0..MAX_MONITORED_TASKS]                  │
//! │  ┌───────────────────────────────────────────────┐  │
//! │  │  pid, state, last_switch_ns                   │  │
//! │  │  in_uninterruptible_since_ns                  │  │
//! │  │  whitelisted flag                             │  │
//! │  └───────────────────────────────────────────────┘  │
//! │                                                     │
//! │  Configuration                                      │
//! │  - timeout_ns (default: 120s)                       │
//! │  - check_interval_ns (default: 30s)                 │
//! │  - panic_on_hung (default: false)                   │
//! │                                                     │
//! │  Whitelist[0..MAX_WHITELIST]                        │
//! │  - PIDs of known long D-state tasks                 │
//! │                                                     │
//! │  Backtrace collection buffer                        │
//! │  - Ring buffer of recent hung task reports          │
//! └─────────────────────────────────────────────────────┘
//! ```
//!
//! # Operation
//!
//! The detector runs periodic scans (triggered by a timer or
//! workqueue callback). For each monitored task in D-state, it
//! checks whether the elapsed time since entering D-state exceeds
//! the timeout. If so, it records a hung task report with a
//! backtrace snapshot and optionally triggers a kernel panic.
//!
//! Tasks on the whitelist are exempt from detection — this is
//! useful for known long-running operations such as NFS mounts
//! or hardware reset sequences.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────

/// Maximum number of tasks the detector can monitor.
const MAX_MONITORED_TASKS: usize = 256;

/// Maximum number of whitelisted PIDs.
const MAX_WHITELIST: usize = 32;

/// Maximum number of hung task reports kept in the ring buffer.
const MAX_REPORTS: usize = 64;

/// Maximum backtrace depth (number of return addresses).
const MAX_BACKTRACE_DEPTH: usize = 16;

/// Default hung task timeout in nanoseconds (120 seconds).
const DEFAULT_TIMEOUT_NS: u64 = 120_000_000_000;

/// Default scan interval in nanoseconds (30 seconds).
const DEFAULT_CHECK_INTERVAL_NS: u64 = 30_000_000_000;

/// Minimum allowed timeout in nanoseconds (1 second).
const MIN_TIMEOUT_NS: u64 = 1_000_000_000;

/// Maximum allowed timeout in nanoseconds (1 hour).
const MAX_TIMEOUT_NS: u64 = 3_600_000_000_000;

/// Sentinel value for unused PID slots.
const PID_NONE: u64 = 0;

/// Sentinel value for unused timestamps.
const TIME_NONE: u64 = 0;

// ── TaskState ──────────────────────────────────────────────────

/// Task scheduling states relevant to hung task detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Task is runnable or running.
    Running,
    /// Task is in interruptible sleep (S-state).
    Interruptible,
    /// Task is in uninterruptible sleep (D-state).
    Uninterruptible,
    /// Task has exited.
    Dead,
    /// Task is stopped (e.g., by SIGSTOP).
    Stopped,
}

impl Default for TaskState {
    fn default() -> Self {
        Self::Running
    }
}

// ── TaskEntry ──────────────────────────────────────────────────

/// Per-task monitoring state.
#[derive(Debug, Clone, Copy)]
pub struct TaskEntry {
    /// Process identifier.
    pid: u64,
    /// Current task state.
    state: TaskState,
    /// Timestamp of the last context switch (ns since boot).
    last_switch_ns: u64,
    /// Timestamp when the task entered D-state (0 = not in D-state).
    uninterruptible_since_ns: u64,
    /// Whether this task is whitelisted.
    whitelisted: bool,
    /// Whether this slot is in use.
    active: bool,
    /// Number of times this task has been detected as hung.
    hung_count: u32,
    /// Last time a hung warning was emitted for this task.
    last_warning_ns: u64,
    /// CPU on which the task was last seen.
    last_cpu: u32,
}

impl Default for TaskEntry {
    fn default() -> Self {
        Self::empty()
    }
}

impl TaskEntry {
    /// Create an empty (unused) task entry.
    pub const fn empty() -> Self {
        Self {
            pid: PID_NONE,
            state: TaskState::Running,
            last_switch_ns: TIME_NONE,
            uninterruptible_since_ns: TIME_NONE,
            whitelisted: false,
            active: false,
            hung_count: 0,
            last_warning_ns: TIME_NONE,
            last_cpu: 0,
        }
    }

    /// Whether this slot is unused.
    fn is_free(&self) -> bool {
        !self.active
    }
}

// ── HungTaskReport ─────────────────────────────────────────────

/// A single hung task detection report.
#[derive(Debug, Clone, Copy)]
pub struct HungTaskReport {
    /// PID of the hung task.
    pub pid: u64,
    /// Time the task entered D-state (ns since boot).
    pub entered_dstate_ns: u64,
    /// Time the hung condition was detected (ns since boot).
    pub detected_ns: u64,
    /// Duration the task has been in D-state (ns).
    pub duration_ns: u64,
    /// CPU on which the task was last seen.
    pub cpu: u32,
    /// Number of return addresses in the backtrace.
    pub backtrace_len: usize,
    /// Stack backtrace (return addresses, most recent first).
    pub backtrace: [u64; MAX_BACKTRACE_DEPTH],
}

impl Default for HungTaskReport {
    fn default() -> Self {
        Self::empty()
    }
}

impl HungTaskReport {
    /// Create an empty report.
    pub const fn empty() -> Self {
        Self {
            pid: PID_NONE,
            entered_dstate_ns: TIME_NONE,
            detected_ns: TIME_NONE,
            duration_ns: 0,
            cpu: 0,
            backtrace_len: 0,
            backtrace: [0; MAX_BACKTRACE_DEPTH],
        }
    }
}

// ── ReportRingBuffer ───────────────────────────────────────────

/// Ring buffer of hung task reports.
struct ReportRing {
    /// Storage for reports.
    reports: [HungTaskReport; MAX_REPORTS],
    /// Write index (wraps around).
    write_idx: usize,
    /// Total number of reports written (may exceed capacity).
    total_written: u64,
}

impl Default for ReportRing {
    fn default() -> Self {
        Self::new()
    }
}

impl ReportRing {
    /// Create an empty report ring buffer.
    const fn new() -> Self {
        Self {
            reports: [HungTaskReport::empty(); MAX_REPORTS],
            write_idx: 0,
            total_written: 0,
        }
    }

    /// Push a new report, overwriting the oldest if full.
    fn push(&mut self, report: HungTaskReport) {
        self.reports[self.write_idx] = report;
        self.write_idx = (self.write_idx + 1) % MAX_REPORTS;
        self.total_written = self.total_written.saturating_add(1);
    }

    /// Return the number of valid reports in the buffer.
    fn count(&self) -> usize {
        if self.total_written >= MAX_REPORTS as u64 {
            MAX_REPORTS
        } else {
            self.total_written as usize
        }
    }

    /// Get a report by logical index (0 = oldest available).
    fn get(&self, index: usize) -> Option<&HungTaskReport> {
        let count = self.count();
        if index >= count {
            return None;
        }
        let start = if self.total_written >= MAX_REPORTS as u64 {
            self.write_idx
        } else {
            0
        };
        let actual = (start + index) % MAX_REPORTS;
        Some(&self.reports[actual])
    }
}

// ── HungTaskConfig ─────────────────────────────────────────────

/// Configuration for the hung task detector.
#[derive(Debug, Clone, Copy)]
pub struct HungTaskConfig {
    /// Timeout before a D-state task is considered hung (ns).
    pub timeout_ns: u64,
    /// Interval between scan passes (ns).
    pub check_interval_ns: u64,
    /// Whether to trigger a kernel panic on hung task detection.
    pub panic_on_hung: bool,
    /// Whether the detector is enabled.
    pub enabled: bool,
    /// Maximum number of warnings per task before suppression.
    pub max_warnings_per_task: u32,
    /// Minimum interval between repeated warnings for the same
    /// task (ns). Prevents log flooding.
    pub warning_interval_ns: u64,
}

impl Default for HungTaskConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl HungTaskConfig {
    /// Create a configuration with default values.
    pub const fn new() -> Self {
        Self {
            timeout_ns: DEFAULT_TIMEOUT_NS,
            check_interval_ns: DEFAULT_CHECK_INTERVAL_NS,
            panic_on_hung: false,
            enabled: true,
            max_warnings_per_task: 10,
            warning_interval_ns: DEFAULT_CHECK_INTERVAL_NS,
        }
    }
}

// ── HungTaskStats ──────────────────────────────────────────────

/// Global hung task detection statistics.
#[derive(Debug, Clone, Copy)]
pub struct HungTaskStats {
    /// Total number of scan passes performed.
    pub scans_performed: u64,
    /// Total number of hung tasks detected.
    pub total_detections: u64,
    /// Total number of warnings emitted.
    pub total_warnings: u64,
    /// Total number of panics requested.
    pub panic_requests: u64,
    /// Timestamp of the last scan (ns since boot).
    pub last_scan_ns: u64,
    /// Timestamp of the last detection (ns since boot).
    pub last_detection_ns: u64,
    /// PID of the last detected hung task.
    pub last_hung_pid: u64,
}

impl Default for HungTaskStats {
    fn default() -> Self {
        Self::new()
    }
}

impl HungTaskStats {
    /// Create zero-initialised stats.
    pub const fn new() -> Self {
        Self {
            scans_performed: 0,
            total_detections: 0,
            total_warnings: 0,
            panic_requests: 0,
            last_scan_ns: TIME_NONE,
            last_detection_ns: TIME_NONE,
            last_hung_pid: PID_NONE,
        }
    }
}

// ── ScanResult ─────────────────────────────────────────────────

/// Result of a single scan pass.
#[derive(Debug, Clone, Copy)]
pub struct ScanResult {
    /// Number of tasks scanned.
    pub tasks_scanned: u32,
    /// Number of tasks in D-state.
    pub tasks_in_dstate: u32,
    /// Number of tasks newly detected as hung.
    pub newly_hung: u32,
    /// Whether a panic was requested.
    pub panic_requested: bool,
}

// ── HungTaskDetector ───────────────────────────────────────────

/// Hung task detection subsystem.
///
/// Monitors tasks for prolonged uninterruptible sleep and generates
/// reports with backtrace information when the configured timeout
/// is exceeded.
pub struct HungTaskDetector {
    /// Monitored task entries.
    tasks: [TaskEntry; MAX_MONITORED_TASKS],
    /// Whitelisted PIDs.
    whitelist: [u64; MAX_WHITELIST],
    /// Number of active whitelist entries.
    whitelist_count: usize,
    /// Report ring buffer.
    reports: ReportRing,
    /// Configuration.
    config: HungTaskConfig,
    /// Global statistics.
    stats: HungTaskStats,
    /// Current monotonic time (ns since boot).
    now_ns: u64,
    /// Timestamp of the last scan.
    last_scan_ns: u64,
    /// Number of actively monitored tasks.
    monitored_count: u32,
}

impl Default for HungTaskDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl HungTaskDetector {
    /// Create a new hung task detector with default configuration.
    pub const fn new() -> Self {
        Self {
            tasks: [TaskEntry::empty(); MAX_MONITORED_TASKS],
            whitelist: [PID_NONE; MAX_WHITELIST],
            whitelist_count: 0,
            reports: ReportRing::new(),
            config: HungTaskConfig::new(),
            stats: HungTaskStats::new(),
            now_ns: 0,
            last_scan_ns: 0,
            monitored_count: 0,
        }
    }

    /// Update the detector's notion of current time.
    pub fn update_time(&mut self, now_ns: u64) {
        self.now_ns = now_ns;
    }

    /// Set the configuration.
    pub fn configure(&mut self, config: HungTaskConfig) -> Result<()> {
        if config.timeout_ns < MIN_TIMEOUT_NS || config.timeout_ns > MAX_TIMEOUT_NS {
            return Err(Error::InvalidArgument);
        }
        if config.check_interval_ns == 0 {
            return Err(Error::InvalidArgument);
        }
        self.config = config;
        Ok(())
    }

    /// Set the timeout in nanoseconds.
    pub fn set_timeout(&mut self, timeout_ns: u64) -> Result<()> {
        if timeout_ns < MIN_TIMEOUT_NS || timeout_ns > MAX_TIMEOUT_NS {
            return Err(Error::InvalidArgument);
        }
        self.config.timeout_ns = timeout_ns;
        Ok(())
    }

    /// Enable or disable the detector.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.config.enabled = enabled;
    }

    /// Enable or disable panic-on-hung-task.
    pub fn set_panic_on_hung(&mut self, panic: bool) {
        self.config.panic_on_hung = panic;
    }

    /// Register a task for monitoring.
    pub fn register_task(&mut self, pid: u64, cpu: u32) -> Result<usize> {
        if pid == PID_NONE {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicate.
        for entry in &self.tasks {
            if entry.active && entry.pid == pid {
                return Err(Error::AlreadyExists);
            }
        }
        let idx = self
            .tasks
            .iter()
            .position(|e| e.is_free())
            .ok_or(Error::OutOfMemory)?;

        self.tasks[idx] = TaskEntry {
            pid,
            state: TaskState::Running,
            last_switch_ns: self.now_ns,
            uninterruptible_since_ns: TIME_NONE,
            whitelisted: self.is_whitelisted(pid),
            active: true,
            hung_count: 0,
            last_warning_ns: TIME_NONE,
            last_cpu: cpu,
        };
        self.monitored_count = self.monitored_count.saturating_add(1);
        Ok(idx)
    }

    /// Unregister a task from monitoring.
    pub fn unregister_task(&mut self, pid: u64) -> Result<()> {
        let entry = self
            .tasks
            .iter_mut()
            .find(|e| e.active && e.pid == pid)
            .ok_or(Error::NotFound)?;

        *entry = TaskEntry::empty();
        self.monitored_count = self.monitored_count.saturating_sub(1);
        Ok(())
    }

    /// Update the state of a monitored task.
    ///
    /// Called on context switches to track when a task enters or
    /// leaves D-state.
    pub fn update_task_state(&mut self, pid: u64, new_state: TaskState, cpu: u32) -> Result<()> {
        let entry = self
            .tasks
            .iter_mut()
            .find(|e| e.active && e.pid == pid)
            .ok_or(Error::NotFound)?;

        let old_state = entry.state;
        entry.state = new_state;
        entry.last_switch_ns = self.now_ns;
        entry.last_cpu = cpu;

        // Track D-state entry/exit.
        match (old_state, new_state) {
            (_, TaskState::Uninterruptible) => {
                if entry.uninterruptible_since_ns == TIME_NONE {
                    entry.uninterruptible_since_ns = self.now_ns;
                }
            }
            (TaskState::Uninterruptible, _) => {
                entry.uninterruptible_since_ns = TIME_NONE;
            }
            _ => {}
        }

        Ok(())
    }

    /// Add a PID to the whitelist.
    pub fn whitelist_add(&mut self, pid: u64) -> Result<()> {
        if pid == PID_NONE {
            return Err(Error::InvalidArgument);
        }
        // Check duplicate.
        for i in 0..self.whitelist_count {
            if self.whitelist[i] == pid {
                return Err(Error::AlreadyExists);
            }
        }
        if self.whitelist_count >= MAX_WHITELIST {
            return Err(Error::OutOfMemory);
        }
        self.whitelist[self.whitelist_count] = pid;
        self.whitelist_count += 1;

        // Update existing monitored entry if present.
        for entry in &mut self.tasks {
            if entry.active && entry.pid == pid {
                entry.whitelisted = true;
            }
        }
        Ok(())
    }

    /// Remove a PID from the whitelist.
    pub fn whitelist_remove(&mut self, pid: u64) -> Result<()> {
        let pos = self.whitelist[..self.whitelist_count]
            .iter()
            .position(|&p| p == pid)
            .ok_or(Error::NotFound)?;

        // Shift remaining entries.
        for i in pos..self.whitelist_count.saturating_sub(1) {
            self.whitelist[i] = self.whitelist[i + 1];
        }
        self.whitelist_count -= 1;
        self.whitelist[self.whitelist_count] = PID_NONE;

        // Update existing monitored entry if present.
        for entry in &mut self.tasks {
            if entry.active && entry.pid == pid {
                entry.whitelisted = false;
            }
        }
        Ok(())
    }

    /// Check whether a PID is whitelisted.
    fn is_whitelisted(&self, pid: u64) -> bool {
        self.whitelist[..self.whitelist_count]
            .iter()
            .any(|&p| p == pid)
    }

    /// Perform a scan pass, checking all monitored tasks.
    ///
    /// Returns a summary of the scan. Hung task reports are
    /// generated for newly detected hung tasks.
    pub fn scan(&mut self) -> ScanResult {
        let mut result = ScanResult {
            tasks_scanned: 0,
            tasks_in_dstate: 0,
            newly_hung: 0,
            panic_requested: false,
        };

        if !self.config.enabled {
            return result;
        }

        self.last_scan_ns = self.now_ns;
        self.stats.scans_performed = self.stats.scans_performed.saturating_add(1);
        self.stats.last_scan_ns = self.now_ns;

        for task in &mut self.tasks {
            if !task.active {
                continue;
            }
            result.tasks_scanned += 1;

            if task.state != TaskState::Uninterruptible {
                continue;
            }
            result.tasks_in_dstate += 1;

            // Skip whitelisted tasks.
            if task.whitelisted {
                continue;
            }

            // Check if the D-state duration exceeds the timeout.
            let dstate_start = task.uninterruptible_since_ns;
            if dstate_start == TIME_NONE {
                continue;
            }
            let duration = self.now_ns.saturating_sub(dstate_start);
            if duration < self.config.timeout_ns {
                continue;
            }

            // Suppress repeated warnings for the same task.
            if task.hung_count >= self.config.max_warnings_per_task {
                continue;
            }
            if task.last_warning_ns != TIME_NONE {
                let since_last = self.now_ns.saturating_sub(task.last_warning_ns);
                if since_last < self.config.warning_interval_ns {
                    continue;
                }
            }

            // Record the hung task.
            task.hung_count = task.hung_count.saturating_add(1);
            task.last_warning_ns = self.now_ns;
            result.newly_hung += 1;

            self.stats.total_detections = self.stats.total_detections.saturating_add(1);
            self.stats.total_warnings = self.stats.total_warnings.saturating_add(1);
            self.stats.last_detection_ns = self.now_ns;
            self.stats.last_hung_pid = task.pid;

            // Collect a backtrace placeholder.
            let report = HungTaskReport {
                pid: task.pid,
                entered_dstate_ns: dstate_start,
                detected_ns: self.now_ns,
                duration_ns: duration,
                cpu: task.last_cpu,
                backtrace_len: 0,
                backtrace: [0; MAX_BACKTRACE_DEPTH],
            };
            self.reports.push(report);

            if self.config.panic_on_hung {
                result.panic_requested = true;
                self.stats.panic_requests = self.stats.panic_requests.saturating_add(1);
            }
        }

        result
    }

    /// Check if enough time has elapsed for the next scan.
    pub fn should_scan(&self) -> bool {
        if !self.config.enabled {
            return false;
        }
        let elapsed = self.now_ns.saturating_sub(self.last_scan_ns);
        elapsed >= self.config.check_interval_ns
    }

    /// Perform a conditional scan (only if the interval has elapsed).
    pub fn tick(&mut self, now_ns: u64) -> Option<ScanResult> {
        self.update_time(now_ns);
        if self.should_scan() {
            Some(self.scan())
        } else {
            None
        }
    }

    /// Return global statistics.
    pub fn stats(&self) -> &HungTaskStats {
        &self.stats
    }

    /// Return the current configuration.
    pub fn config(&self) -> &HungTaskConfig {
        &self.config
    }

    /// Return the number of reports in the ring buffer.
    pub fn report_count(&self) -> usize {
        self.reports.count()
    }

    /// Get a hung task report by index (0 = oldest).
    pub fn get_report(&self, index: usize) -> Option<&HungTaskReport> {
        self.reports.get(index)
    }

    /// Return the number of actively monitored tasks.
    pub fn monitored_count(&self) -> u32 {
        self.monitored_count
    }

    /// Return the number of whitelisted PIDs.
    pub fn whitelist_count(&self) -> usize {
        self.whitelist_count
    }

    /// Store backtrace addresses for the most recently pushed report.
    ///
    /// This is called by architecture-specific code that can walk the
    /// stack of a hung task.
    pub fn store_backtrace(&mut self, pid: u64, addresses: &[u64]) -> Result<()> {
        // Find the most recent report for this PID.
        let count = self.reports.count();
        if count == 0 {
            return Err(Error::NotFound);
        }
        // Search backwards for the matching PID.
        for i in (0..count).rev() {
            if let Some(report) = self.reports.get(i) {
                if report.pid == pid {
                    // We need mutable access — compute the actual index.
                    let start = if self.reports.total_written >= MAX_REPORTS as u64 {
                        self.reports.write_idx
                    } else {
                        0
                    };
                    let actual = (start + i) % MAX_REPORTS;
                    let len = addresses.len().min(MAX_BACKTRACE_DEPTH);
                    self.reports.reports[actual].backtrace[..len]
                        .copy_from_slice(&addresses[..len]);
                    self.reports.reports[actual].backtrace_len = len;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }
}
