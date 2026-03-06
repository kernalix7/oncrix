// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! KASAN error reporting.
//!
//! Generates human-readable reports when the Kernel Address Sanitizer
//! detects a memory access violation. Reports include access type,
//! shadow memory state, stack trace, and allocation/free history.
//!
//! - [`KasanBugType`] — type of memory violation
//! - [`KasanAccessInfo`] — details about the violating access
//! - [`KasanReport`] — a formatted error report
//! - [`KasanReportStats`] — reporting statistics
//! - [`KasanReporter`] — the report generator
//!
//! Reference: Linux `mm/kasan/report.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum stored reports.
const MAX_REPORTS: usize = 64;

/// Maximum stack trace depth.
const MAX_STACK_DEPTH: usize = 16;

// -------------------------------------------------------------------
// KasanBugType
// -------------------------------------------------------------------

/// Type of memory violation detected by KASAN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KasanBugType {
    /// Out-of-bounds access.
    #[default]
    OutOfBounds,
    /// Use-after-free.
    UseAfterFree,
    /// Use-after-scope.
    UseAfterScope,
    /// Double-free.
    DoubleFree,
    /// Invalid free (never allocated).
    InvalidFree,
    /// Slab out-of-bounds.
    SlabOutOfBounds,
    /// Global buffer overflow.
    GlobalOverflow,
    /// Stack buffer overflow.
    StackOverflow,
}

impl KasanBugType {
    /// Returns the bug type name.
    pub fn name(self) -> &'static str {
        match self {
            Self::OutOfBounds => "out-of-bounds",
            Self::UseAfterFree => "use-after-free",
            Self::UseAfterScope => "use-after-scope",
            Self::DoubleFree => "double-free",
            Self::InvalidFree => "invalid-free",
            Self::SlabOutOfBounds => "slab-out-of-bounds",
            Self::GlobalOverflow => "global-buffer-overflow",
            Self::StackOverflow => "stack-buffer-overflow",
        }
    }
}

// -------------------------------------------------------------------
// KasanAccessInfo
// -------------------------------------------------------------------

/// Details about the violating memory access.
#[derive(Debug, Clone, Copy, Default)]
pub struct KasanAccessInfo {
    /// Address of the access.
    pub addr: u64,
    /// Size of the access in bytes.
    pub size: usize,
    /// Whether the access was a write.
    pub is_write: bool,
    /// Instruction pointer.
    pub ip: u64,
    /// Shadow byte value at the address.
    pub shadow_val: u8,
    /// Task PID that caused the access.
    pub pid: u64,
}

// -------------------------------------------------------------------
// KasanStackEntry
// -------------------------------------------------------------------

/// A stack frame in a KASAN trace.
#[derive(Debug, Clone, Copy, Default)]
pub struct KasanStackEntry {
    /// Return address.
    pub addr: u64,
    /// Whether this entry is valid.
    pub valid: bool,
}

// -------------------------------------------------------------------
// KasanReport
// -------------------------------------------------------------------

/// A KASAN error report.
#[derive(Debug, Clone, Copy)]
pub struct KasanReport {
    /// Bug type.
    pub bug_type: KasanBugType,
    /// Access information.
    pub access: KasanAccessInfo,
    /// Stack trace at time of access.
    pub stack: [KasanStackEntry; MAX_STACK_DEPTH],
    /// Number of valid stack entries.
    pub stack_depth: usize,
    /// Timestamp (nanoseconds).
    pub timestamp_ns: u64,
    /// Whether this report is active.
    pub active: bool,
}

impl Default for KasanReport {
    fn default() -> Self {
        Self {
            bug_type: KasanBugType::OutOfBounds,
            access: KasanAccessInfo::default(),
            stack: [KasanStackEntry::default(); MAX_STACK_DEPTH],
            stack_depth: 0,
            timestamp_ns: 0,
            active: false,
        }
    }
}

impl KasanReport {
    /// Creates a new KASAN report.
    pub fn new(bug_type: KasanBugType, access: KasanAccessInfo, timestamp_ns: u64) -> Self {
        Self {
            bug_type,
            access,
            stack: [KasanStackEntry::default(); MAX_STACK_DEPTH],
            stack_depth: 0,
            timestamp_ns,
            active: true,
        }
    }

    /// Adds a stack frame to the report.
    pub fn add_frame(&mut self, addr: u64) {
        if self.stack_depth < MAX_STACK_DEPTH {
            self.stack[self.stack_depth] = KasanStackEntry { addr, valid: true };
            self.stack_depth += 1;
        }
    }
}

// -------------------------------------------------------------------
// KasanReportStats
// -------------------------------------------------------------------

/// KASAN reporting statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct KasanReportStats {
    /// Total reports generated.
    pub reports_total: u64,
    /// Out-of-bounds reports.
    pub oob_reports: u64,
    /// Use-after-free reports.
    pub uaf_reports: u64,
    /// Double-free reports.
    pub double_free_reports: u64,
    /// Write violations.
    pub write_violations: u64,
    /// Read violations.
    pub read_violations: u64,
}

impl KasanReportStats {
    /// Resets all counters.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// -------------------------------------------------------------------
// KasanReporter
// -------------------------------------------------------------------

/// The KASAN report generator.
pub struct KasanReporter {
    /// Stored reports.
    reports: [KasanReport; MAX_REPORTS],
    /// Number of reports.
    count: usize,
    /// Whether reporting is enabled.
    enabled: bool,
    /// Statistics.
    stats: KasanReportStats,
}

impl Default for KasanReporter {
    fn default() -> Self {
        Self {
            reports: [KasanReport::default(); MAX_REPORTS],
            count: 0,
            enabled: true,
            stats: KasanReportStats::default(),
        }
    }
}

impl KasanReporter {
    /// Creates a new KASAN reporter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Reports a KASAN violation.
    pub fn report(
        &mut self,
        bug_type: KasanBugType,
        access: KasanAccessInfo,
        timestamp_ns: u64,
    ) -> Result<usize> {
        if !self.enabled {
            return Err(Error::PermissionDenied);
        }
        if self.count >= MAX_REPORTS {
            return Err(Error::OutOfMemory);
        }

        let idx = self.count;
        self.reports[idx] = KasanReport::new(bug_type, access, timestamp_ns);
        self.count += 1;

        self.stats.reports_total += 1;
        match bug_type {
            KasanBugType::OutOfBounds
            | KasanBugType::SlabOutOfBounds
            | KasanBugType::GlobalOverflow
            | KasanBugType::StackOverflow => {
                self.stats.oob_reports += 1;
            }
            KasanBugType::UseAfterFree | KasanBugType::UseAfterScope => {
                self.stats.uaf_reports += 1;
            }
            KasanBugType::DoubleFree | KasanBugType::InvalidFree => {
                self.stats.double_free_reports += 1;
            }
        }
        if access.is_write {
            self.stats.write_violations += 1;
        } else {
            self.stats.read_violations += 1;
        }

        Ok(idx)
    }

    /// Returns a reference to a report.
    pub fn get_report(&self, idx: usize) -> Option<&KasanReport> {
        if idx < self.count && self.reports[idx].active {
            Some(&self.reports[idx])
        } else {
            None
        }
    }

    /// Enables or disables reporting.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns the number of reports.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns statistics.
    pub fn stats(&self) -> &KasanReportStats {
        &self.stats
    }

    /// Resets statistics.
    pub fn reset_stats(&mut self) {
        self.stats.reset();
    }
}
