// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel Concurrency Sanitizer (KCSAN) — runtime data-race detector.
//!
//! KCSAN detects data races by setting *watchpoints* on memory accesses
//! and checking whether conflicting accesses (from other CPUs) occur
//! within a short delay window.  A data race exists when two threads
//! access the same memory location concurrently, at least one access
//! is a write, and the accesses are not properly synchronised.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                     KcsanSubsystem                           │
//! │                                                              │
//! │  KcsanState                                                  │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  watchpoints: [KcsanWatchpoint; MAX_WATCHPOINTS]       │  │
//! │  │  reports: [Option<KcsanReport>; MAX_REPORTS]            │  │
//! │  │  enabled: bool                                         │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  check_access()  — set watchpoint, delay, check conflict    │
//! │  report_race()   — log a detected data race                 │
//! │                                                              │
//! │  KcsanStats                                                  │
//! │  - total_checks, races_detected, watchpoints_set            │
//! │  - reports_suppressed                                        │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Sampling
//!
//! Checking every memory access would be prohibitively expensive.
//! KCSAN samples 1-in-N accesses (configurable via `skip_count`).
//! The skip counter is per-CPU to avoid contention.
//!
//! # Reference
//!
//! Linux `kernel/kcsan/core.c`, `kernel/kcsan/report.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum concurrent watchpoints.
const MAX_WATCHPOINTS: usize = 128;

/// Maximum stored race reports.
const MAX_REPORTS: usize = 256;

/// Maximum CPUs for per-CPU skip counters.
const MAX_CPUS: usize = 64;

/// Default number of accesses to skip between checks.
const DEFAULT_SKIP_COUNT: u64 = 1000;

/// Maximum access size tracked (in bytes).
const MAX_ACCESS_SIZE: u8 = 64;

// ══════════════════════════════════════════════════════════════
// ReportType — classification of detected issues
// ══════════════════════════════════════════════════════════════

/// Type of concurrency issue detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportType {
    /// A data race: two concurrent unsynchronised accesses to
    /// the same location, at least one of which is a write.
    DataRace,
    /// An assertion failure from an explicit KCSAN assert (e.g.,
    /// `ASSERT_EXCLUSIVE_ACCESS`).
    AssertFailure,
}

impl ReportType {
    /// Display name for diagnostics.
    pub const fn name(self) -> &'static str {
        match self {
            Self::DataRace => "data-race",
            Self::AssertFailure => "assert-failure",
        }
    }
}

// ══════════════════════════════════════════════════════════════
// KcsanAccess — recorded memory access
// ══════════════════════════════════════════════════════════════

/// A single recorded memory access for race detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KcsanAccess {
    /// Virtual address accessed.
    pub addr: u64,
    /// Size of the access in bytes (1, 2, 4, 8, 16, ...).
    pub size: u8,
    /// `true` if this was a write access.
    pub is_write: bool,
    /// Instruction pointer (program counter) of the access.
    pub ip: u64,
    /// CPU on which the access occurred.
    pub cpu: u8,
    /// Tick at which the access was observed.
    pub tick: u64,
}

impl KcsanAccess {
    /// Empty access for array initialisation.
    const fn empty() -> Self {
        Self {
            addr: 0,
            size: 0,
            is_write: false,
            ip: 0,
            cpu: 0,
            tick: 0,
        }
    }

    /// Check whether this access overlaps with `other`.
    ///
    /// Two accesses overlap if their address ranges intersect.
    pub const fn overlaps(&self, other: &Self) -> bool {
        let self_end = self.addr + self.size as u64;
        let other_end = other.addr + other.size as u64;
        self.addr < other_end && other.addr < self_end
    }

    /// Check whether this access conflicts with `other`.
    ///
    /// A conflict exists if the accesses overlap and at least one
    /// is a write.
    pub const fn conflicts_with(&self, other: &Self) -> bool {
        if !self.overlaps(other) {
            return false;
        }
        self.is_write || other.is_write
    }
}

// ══════════════════════════════════════════════════════════════
// KcsanWatchpoint — active watchpoint
// ══════════════════════════════════════════════════════════════

/// An active watchpoint monitoring a memory range for conflicting
/// accesses.
#[derive(Debug, Clone, Copy)]
pub struct KcsanWatchpoint {
    /// Start address of the watched range.
    pub addr: u64,
    /// Size of the watched range in bytes.
    pub size: u8,
    /// Whether the original access was a write.
    pub is_write: bool,
    /// CPU that set this watchpoint.
    pub cpu: u8,
    /// Instruction pointer of the original access.
    pub ip: u64,
    /// Tick at which the watchpoint was set.
    pub set_tick: u64,
    /// Whether this watchpoint slot is active.
    pub active: bool,
}

impl KcsanWatchpoint {
    /// Empty (inactive) watchpoint for array initialisation.
    const fn empty() -> Self {
        Self {
            addr: 0,
            size: 0,
            is_write: false,
            cpu: 0,
            ip: 0,
            set_tick: 0,
            active: false,
        }
    }

    /// Returns `true` if this watchpoint is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Check whether the given access hits this watchpoint.
    pub const fn matches(&self, access: &KcsanAccess) -> bool {
        if !self.active {
            return false;
        }
        // Must be from a different CPU.
        if self.cpu == access.cpu {
            return false;
        }
        // Ranges must overlap.
        let wp_end = self.addr + self.size as u64;
        let acc_end = access.addr + access.size as u64;
        if self.addr >= acc_end || access.addr >= wp_end {
            return false;
        }
        // At least one must be a write.
        self.is_write || access.is_write
    }
}

// ══════════════════════════════════════════════════════════════
// KcsanReport — race report
// ══════════════════════════════════════════════════════════════

/// A recorded data-race report.
#[derive(Debug, Clone, Copy)]
pub struct KcsanReport {
    /// The first access (from the watchpoint setter).
    pub access1: KcsanAccess,
    /// The second access (the conflicting access).
    pub access2: KcsanAccess,
    /// Classification of the report.
    pub report_type: ReportType,
    /// Tick at which the report was generated.
    pub report_tick: u64,
    /// Unique report ID.
    pub id: u64,
}

impl KcsanReport {
    /// Create a new report.
    const fn new(
        access1: KcsanAccess,
        access2: KcsanAccess,
        report_type: ReportType,
        report_tick: u64,
        id: u64,
    ) -> Self {
        Self {
            access1,
            access2,
            report_type,
            report_tick,
            id,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// KcsanStats — statistics
// ══════════════════════════════════════════════════════════════

/// KCSAN runtime statistics.
#[derive(Debug, Clone, Copy)]
pub struct KcsanStats {
    /// Total number of `check_access` invocations.
    pub total_checks: u64,
    /// Number of data races detected.
    pub races_detected: u64,
    /// Number of watchpoints set.
    pub watchpoints_set: u64,
    /// Number of reports suppressed (e.g., duplicates).
    pub reports_suppressed: u64,
    /// Number of accesses skipped by sampling.
    pub accesses_skipped: u64,
    /// Number of watchpoint slot overflows.
    pub watchpoint_overflows: u64,
    /// Number of report buffer overflows.
    pub report_overflows: u64,
}

impl KcsanStats {
    /// Zero-initialised stats.
    const fn new() -> Self {
        Self {
            total_checks: 0,
            races_detected: 0,
            watchpoints_set: 0,
            reports_suppressed: 0,
            accesses_skipped: 0,
            watchpoint_overflows: 0,
            report_overflows: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// PerCpuSkip — per-CPU sampling state
// ══════════════════════════════════════════════════════════════

/// Per-CPU sampling counter for access skipping.
#[derive(Debug, Clone, Copy)]
struct PerCpuSkip {
    /// Accesses remaining before the next check.
    remaining: u64,
}

impl PerCpuSkip {
    /// Create with the given skip count.
    const fn new(skip: u64) -> Self {
        Self { remaining: skip }
    }
}

// ══════════════════════════════════════════════════════════════
// KcsanState — internal state
// ══════════════════════════════════════════════════════════════

/// Internal KCSAN state: watchpoints and report buffer.
struct KcsanState {
    /// Active watchpoints.
    watchpoints: [KcsanWatchpoint; MAX_WATCHPOINTS],
    /// Report log (circular).
    reports: [Option<KcsanReport>; MAX_REPORTS],
    /// Next write position in the report log.
    report_head: usize,
    /// Number of reports stored (saturates at MAX_REPORTS).
    report_count: usize,
    /// Next unique report ID.
    next_report_id: u64,
    /// Per-CPU skip counters.
    per_cpu_skip: [PerCpuSkip; MAX_CPUS],
}

impl KcsanState {
    /// Create empty state.
    const fn new(_skip_count: u64) -> Self {
        Self {
            watchpoints: [const { KcsanWatchpoint::empty() }; MAX_WATCHPOINTS],
            reports: [const { None }; MAX_REPORTS],
            report_head: 0,
            report_count: 0,
            next_report_id: 1,
            per_cpu_skip: [const { PerCpuSkip::new(0) }; MAX_CPUS],
        }
    }

    /// Re-initialise all per-CPU skip counters.
    fn reset_skip_counters(&mut self, skip_count: u64) {
        for counter in &mut self.per_cpu_skip {
            counter.remaining = skip_count;
        }
    }
}

// ══════════════════════════════════════════════════════════════
// CheckResult — outcome of check_access
// ══════════════════════════════════════════════════════════════

/// Outcome of a `check_access` invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckResult {
    /// No race detected; a watchpoint was set for this access.
    WatchpointSet,
    /// A data race was detected and reported.
    RaceDetected,
    /// The access was skipped by sampling.
    Skipped,
    /// No free watchpoint slot was available.
    NoFreeSlot,
    /// KCSAN is disabled.
    Disabled,
}

// ══════════════════════════════════════════════════════════════
// KcsanSubsystem — top-level API
// ══════════════════════════════════════════════════════════════

/// Top-level Kernel Concurrency Sanitizer subsystem.
pub struct KcsanSubsystem {
    /// Internal state.
    state: KcsanState,
    /// Statistics.
    stats: KcsanStats,
    /// Whether KCSAN is enabled.
    enabled: bool,
    /// Number of accesses to skip between checks.
    skip_count: u64,
    /// Whether the subsystem has been initialised.
    initialised: bool,
}

impl Default for KcsanSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl KcsanSubsystem {
    /// Create a new KCSAN subsystem with default sampling rate.
    pub const fn new() -> Self {
        Self {
            state: KcsanState::new(DEFAULT_SKIP_COUNT),
            stats: KcsanStats::new(),
            enabled: false,
            skip_count: DEFAULT_SKIP_COUNT,
            initialised: false,
        }
    }

    /// Create with a custom skip count.
    pub const fn with_skip_count(skip_count: u64) -> Self {
        Self {
            state: KcsanState::new(skip_count),
            stats: KcsanStats::new(),
            enabled: false,
            skip_count,
            initialised: false,
        }
    }

    /// Initialise and enable the subsystem.
    pub fn init(&mut self) -> Result<()> {
        if self.initialised {
            return Err(Error::AlreadyExists);
        }
        self.state.reset_skip_counters(self.skip_count);
        self.enabled = true;
        self.initialised = true;
        Ok(())
    }

    // ── Enable / disable ─────────────────────────────────────

    /// Enable KCSAN race detection.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable KCSAN race detection.
    ///
    /// Existing watchpoints are cleared.
    pub fn disable(&mut self) {
        self.enabled = false;
        self.clear_all_watchpoints();
    }

    /// Returns `true` if KCSAN is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    // ── Configuration ────────────────────────────────────────

    /// Set the sampling skip count.
    ///
    /// Higher values reduce overhead but also reduce detection
    /// probability.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `count` is zero.
    pub fn set_skip_count(&mut self, count: u64) -> Result<()> {
        if count == 0 {
            return Err(Error::InvalidArgument);
        }
        self.skip_count = count;
        self.state.reset_skip_counters(count);
        Ok(())
    }

    /// Return the current skip count.
    pub const fn skip_count(&self) -> u64 {
        self.skip_count
    }

    // ── Access checking ──────────────────────────────────────

    /// Check a memory access for potential data races.
    ///
    /// This is the main instrumentation hook.  The compiler (or
    /// explicit annotation) inserts calls to this function at
    /// memory access sites.
    ///
    /// # Arguments
    ///
    /// * `access` — the memory access to check.
    ///
    /// Returns the outcome of the check.
    pub fn check_access(&mut self, access: KcsanAccess) -> CheckResult {
        if !self.enabled {
            return CheckResult::Disabled;
        }

        // Validate access size.
        if access.size == 0 || access.size > MAX_ACCESS_SIZE {
            return CheckResult::Skipped;
        }

        // Sampling: decrement skip counter.
        let cpu = access.cpu as usize;
        if cpu < MAX_CPUS {
            if self.state.per_cpu_skip[cpu].remaining > 0 {
                self.state.per_cpu_skip[cpu].remaining -= 1;
                self.stats.accesses_skipped += 1;
                return CheckResult::Skipped;
            }
            // Reset skip counter for next round.
            self.state.per_cpu_skip[cpu].remaining = self.skip_count;
        }

        self.stats.total_checks += 1;

        // First, check if any existing watchpoint is hit by this
        // access (i.e., another CPU set a watchpoint and we're
        // the conflicting access).
        if let Some(wp_idx) = self.find_matching_watchpoint(&access) {
            let wp = &self.state.watchpoints[wp_idx];
            let access1 = KcsanAccess {
                addr: wp.addr,
                size: wp.size,
                is_write: wp.is_write,
                ip: wp.ip,
                cpu: wp.cpu,
                tick: wp.set_tick,
            };

            self.record_report(access1, access, ReportType::DataRace, access.tick);

            // Clear the triggered watchpoint.
            self.state.watchpoints[wp_idx] = KcsanWatchpoint::empty();

            self.stats.races_detected += 1;
            return CheckResult::RaceDetected;
        }

        // No existing watchpoint was hit.  Try to set a new one
        // for this access so that other CPUs can detect races.
        match self.set_watchpoint(&access) {
            Ok(()) => {
                self.stats.watchpoints_set += 1;
                CheckResult::WatchpointSet
            }
            Err(_) => {
                self.stats.watchpoint_overflows += 1;
                CheckResult::NoFreeSlot
            }
        }
    }

    /// Explicit assert that the given address range is accessed
    /// exclusively by the calling CPU.
    ///
    /// If a conflicting access is found in the watchpoint table,
    /// an `AssertFailure` report is generated.
    pub fn assert_exclusive(
        &mut self,
        addr: u64,
        size: u8,
        cpu: u8,
        ip: u64,
        tick: u64,
    ) -> CheckResult {
        if !self.enabled {
            return CheckResult::Disabled;
        }

        let access = KcsanAccess {
            addr,
            size,
            is_write: true,
            ip,
            cpu,
            tick,
        };

        self.stats.total_checks += 1;

        if let Some(wp_idx) = self.find_matching_watchpoint(&access) {
            let wp = &self.state.watchpoints[wp_idx];
            let access1 = KcsanAccess {
                addr: wp.addr,
                size: wp.size,
                is_write: wp.is_write,
                ip: wp.ip,
                cpu: wp.cpu,
                tick: wp.set_tick,
            };

            self.record_report(access1, access, ReportType::AssertFailure, tick);

            self.state.watchpoints[wp_idx] = KcsanWatchpoint::empty();
            self.stats.races_detected += 1;
            return CheckResult::RaceDetected;
        }

        match self.set_watchpoint(&access) {
            Ok(()) => {
                self.stats.watchpoints_set += 1;
                CheckResult::WatchpointSet
            }
            Err(_) => {
                self.stats.watchpoint_overflows += 1;
                CheckResult::NoFreeSlot
            }
        }
    }

    // ── Report access ────────────────────────────────────────

    /// Return the number of reports stored.
    pub fn report_count(&self) -> usize {
        self.state.report_count
    }

    /// Retrieve a report by index (0 = most recent).
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `index` is out of range.
    pub fn get_report(&self, index: usize) -> Result<&KcsanReport> {
        if index >= self.state.report_count {
            return Err(Error::InvalidArgument);
        }
        let actual = (self.state.report_head + MAX_REPORTS - 1 - index) % MAX_REPORTS;
        self.state.reports[actual].as_ref().ok_or(Error::NotFound)
    }

    /// Clear all stored reports.
    pub fn clear_reports(&mut self) {
        self.state.reports = [const { None }; MAX_REPORTS];
        self.state.report_head = 0;
        self.state.report_count = 0;
    }

    // ── Stats ────────────────────────────────────────────────

    /// Return a snapshot of statistics.
    pub fn stats(&self) -> KcsanStats {
        self.stats
    }

    /// Return the number of active watchpoints.
    pub fn active_watchpoint_count(&self) -> usize {
        self.state
            .watchpoints
            .iter()
            .filter(|wp| wp.is_active())
            .count()
    }

    // ── Watchpoint management ────────────────────────────────

    /// Expire all watchpoints older than `max_age_ticks`.
    pub fn expire_watchpoints(&mut self, current_tick: u64, max_age_ticks: u64) -> usize {
        let mut expired = 0;
        for wp in &mut self.state.watchpoints {
            if wp.active && current_tick.wrapping_sub(wp.set_tick) > max_age_ticks {
                *wp = KcsanWatchpoint::empty();
                expired += 1;
            }
        }
        expired
    }

    /// Clear all active watchpoints.
    pub fn clear_all_watchpoints(&mut self) {
        for wp in &mut self.state.watchpoints {
            *wp = KcsanWatchpoint::empty();
        }
    }

    // ── Internals ────────────────────────────────────────────

    /// Find a watchpoint that conflicts with the given access.
    fn find_matching_watchpoint(&self, access: &KcsanAccess) -> Option<usize> {
        self.state
            .watchpoints
            .iter()
            .position(|wp| wp.matches(access))
    }

    /// Set a new watchpoint for the given access.
    fn set_watchpoint(&mut self, access: &KcsanAccess) -> Result<()> {
        let slot = self
            .state
            .watchpoints
            .iter()
            .position(|wp| !wp.active)
            .ok_or(Error::OutOfMemory)?;

        self.state.watchpoints[slot] = KcsanWatchpoint {
            addr: access.addr,
            size: access.size,
            is_write: access.is_write,
            cpu: access.cpu,
            ip: access.ip,
            set_tick: access.tick,
            active: true,
        };
        Ok(())
    }

    /// Record a race report in the circular buffer.
    fn record_report(
        &mut self,
        access1: KcsanAccess,
        access2: KcsanAccess,
        report_type: ReportType,
        tick: u64,
    ) {
        // Simple duplicate suppression: check if the last N
        // reports have the same (addr, ip1, ip2) tuple.
        if self.is_duplicate_report(&access1, &access2) {
            self.stats.reports_suppressed += 1;
            return;
        }

        let id = self.state.next_report_id;
        self.state.next_report_id += 1;

        let report = KcsanReport::new(access1, access2, report_type, tick, id);

        self.state.reports[self.state.report_head] = Some(report);
        self.state.report_head = (self.state.report_head + 1) % MAX_REPORTS;
        if self.state.report_count < MAX_REPORTS {
            self.state.report_count += 1;
        } else {
            self.stats.report_overflows += 1;
        }
    }

    /// Check whether a report with the same address and IP pair
    /// already exists in the last 16 entries.
    fn is_duplicate_report(&self, access1: &KcsanAccess, access2: &KcsanAccess) -> bool {
        let check_count = if self.state.report_count < 16 {
            self.state.report_count
        } else {
            16
        };

        for i in 0..check_count {
            let idx = (self.state.report_head + MAX_REPORTS - 1 - i) % MAX_REPORTS;
            if let Some(report) = &self.state.reports[idx] {
                if report.access1.addr == access1.addr
                    && report.access1.ip == access1.ip
                    && report.access2.ip == access2.ip
                {
                    return true;
                }
            }
        }
        false
    }
}
