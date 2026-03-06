// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory failure handling subsystem.
//!
//! Handles hardware memory errors (ECC correctable/uncorrectable)
//! detected by the memory controller or machine check architecture.
//! Provides mechanisms to:
//!
//! - Isolate poisoned pages from further allocation
//! - Migrate processes away from failed pages
//! - Track error history per physical frame
//! - Implement soft-offline (correctable error threshold) and
//!   hard-offline (uncorrectable error) policies
//! - Report errors via MCE/GHES to user space
//!
//! # Subsystems
//!
//! - [`HwPoisonPage`] — per-page hardware error metadata
//! - [`MemFailureAction`] — recovery action for each page type
//! - [`MceSeverity`] — machine check exception severity levels
//! - [`ErrorRecord`] — detailed error event record
//! - [`PoisonRecovery`] — recovery engine for poisoned pages
//! - [`SoftOfflineEngine`] — proactive soft-offline handler
//! - [`MemFailureManager`] — top-level failure management
//! - [`MemFailureStats`] — aggregate error statistics
//!
//! Reference: Linux `mm/memory-failure.c`, `mm/hwpoison-inject.c`,
//! `Documentation/vm/hwpoison.rst`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum number of poisoned pages tracked.
const MAX_POISON_PAGES: usize = 512;

/// Maximum number of error records in the log.
const MAX_ERROR_RECORDS: usize = 256;

/// Maximum number of process notifications pending.
const MAX_NOTIFICATIONS: usize = 64;

/// Default correctable error threshold before soft-offline.
const DEFAULT_CE_THRESHOLD: u32 = 10;

/// Maximum pages per soft-offline scan batch.
const SOFT_OFFLINE_BATCH: usize = 32;

/// Maximum DIMM/rank entries for error source tracking.
const MAX_DIMM_ENTRIES: usize = 16;

// -------------------------------------------------------------------
// MceSeverity
// -------------------------------------------------------------------

/// Severity classification for machine check exceptions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum MceSeverity {
    /// Correctable error (CE) — data was corrected by ECC.
    #[default]
    Correctable,
    /// Deferred error — reported but not yet consumed.
    Deferred,
    /// Uncorrectable no action required (UCNA).
    UncorrectableNoAction,
    /// Software recoverable action required (SRAR) — e.g. poison
    /// in user-space data.
    ActionRequired,
    /// Software recoverable action optional (SRAO) — e.g. poison
    /// in page cache.
    ActionOptional,
    /// Fatal — unrecoverable, system must panic.
    Fatal,
}

// -------------------------------------------------------------------
// PagePoisonState
// -------------------------------------------------------------------

/// State of a poisoned page in the recovery lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PagePoisonState {
    /// Page is healthy (not poisoned).
    #[default]
    Healthy,
    /// Page has correctable errors (being monitored).
    CorrectedMonitor,
    /// Page is soft-offlined (migrated, removed from allocator).
    SoftOffline,
    /// Page is hard-offlined (uncorrectable error, permanently removed).
    HardOffline,
    /// Page is being recovered (migration in progress).
    Recovering,
    /// Recovery failed — page remains poisoned.
    RecoveryFailed,
}

/// Type of the poisoned page, affecting recovery strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PoisonedPageType {
    /// Anonymous (user-space) page.
    #[default]
    Anonymous,
    /// Page cache (file-backed) page.
    PageCache,
    /// Kernel slab page.
    KernelSlab,
    /// Kernel stack page.
    KernelStack,
    /// Huge page (2 MiB or 1 GiB).
    HugePage,
    /// Free page (not allocated when error detected).
    FreePage,
    /// Page table page.
    PageTablePage,
    /// Reserved / unmovable page.
    Reserved,
}

// -------------------------------------------------------------------
// HwPoisonPage
// -------------------------------------------------------------------

/// Metadata for a single hardware-poisoned page.
#[derive(Debug, Clone, Copy, Default)]
pub struct HwPoisonPage {
    /// Physical frame number (PFN) of the poisoned page.
    pub pfn: u64,
    /// Current poison lifecycle state.
    pub state: PagePoisonState,
    /// Type of page when error was detected.
    pub page_type: PoisonedPageType,
    /// Most severe error observed on this page.
    pub severity: MceSeverity,
    /// Number of correctable errors observed.
    pub ce_count: u32,
    /// Timestamp (tick) of first error.
    pub first_error_tick: u64,
    /// Timestamp (tick) of most recent error.
    pub last_error_tick: u64,
    /// Process ID that was accessing the page (0 = kernel/free).
    pub affected_pid: u64,
    /// DIMM/rank index where the error originated.
    pub dimm_index: u16,
    /// Bank/row/column address for detailed diagnostics.
    pub bank: u16,
    /// Whether this slot is in use.
    pub in_use: bool,
}

// -------------------------------------------------------------------
// MemFailureAction
// -------------------------------------------------------------------

/// Recovery action to take for a poisoned page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MemFailureAction {
    /// Ignore the error (below threshold).
    #[default]
    Ignore,
    /// Send SIGBUS to the affected process.
    SendSigbus,
    /// Invalidate the page cache entry and drop the page.
    InvalidatePageCache,
    /// Migrate the page to a healthy frame and update mappings.
    MigratePage,
    /// Remove the page from the allocator (soft-offline).
    SoftOfflinePage,
    /// Permanently mark the page as unusable (hard-offline).
    HardOfflinePage,
    /// Kill the affected process (last resort).
    KillProcess,
    /// Panic the system (fatal unrecoverable error).
    SystemPanic,
}

/// Determines the recovery action based on page type and severity.
pub fn determine_action(page_type: PoisonedPageType, severity: MceSeverity) -> MemFailureAction {
    match severity {
        MceSeverity::Fatal => MemFailureAction::SystemPanic,
        MceSeverity::ActionRequired => match page_type {
            PoisonedPageType::Anonymous => MemFailureAction::SendSigbus,
            PoisonedPageType::KernelStack => MemFailureAction::KillProcess,
            PoisonedPageType::PageTablePage => MemFailureAction::KillProcess,
            PoisonedPageType::KernelSlab => MemFailureAction::SystemPanic,
            _ => MemFailureAction::HardOfflinePage,
        },
        MceSeverity::ActionOptional => match page_type {
            PoisonedPageType::PageCache => MemFailureAction::InvalidatePageCache,
            PoisonedPageType::FreePage => MemFailureAction::HardOfflinePage,
            PoisonedPageType::Anonymous => MemFailureAction::MigratePage,
            PoisonedPageType::HugePage => MemFailureAction::MigratePage,
            _ => MemFailureAction::SoftOfflinePage,
        },
        MceSeverity::UncorrectableNoAction => MemFailureAction::SoftOfflinePage,
        MceSeverity::Deferred => MemFailureAction::SoftOfflinePage,
        MceSeverity::Correctable => MemFailureAction::Ignore,
    }
}

// -------------------------------------------------------------------
// ErrorRecord
// -------------------------------------------------------------------

/// Detailed error event record for diagnostics and reporting.
#[derive(Debug, Clone, Copy, Default)]
pub struct ErrorRecord {
    /// Monotonic timestamp (tick).
    pub timestamp: u64,
    /// Physical frame number.
    pub pfn: u64,
    /// Error severity.
    pub severity: MceSeverity,
    /// Page type at time of error.
    pub page_type: PoisonedPageType,
    /// Recovery action taken.
    pub action: MemFailureAction,
    /// Whether recovery succeeded.
    pub recovered: bool,
    /// Affected process ID (0 = kernel/free).
    pub affected_pid: u64,
    /// DIMM index.
    pub dimm_index: u16,
    /// CPU that detected the error.
    pub cpu_id: u16,
    /// Whether this record slot is in use.
    pub in_use: bool,
}

/// Ring-buffer error record log.
#[derive(Debug)]
pub struct ErrorLog {
    /// Log entries.
    records: [ErrorRecord; MAX_ERROR_RECORDS],
    /// Write cursor (wraps around).
    write_pos: usize,
    /// Total records written (including overwritten).
    total_records: u64,
}

impl Default for ErrorLog {
    fn default() -> Self {
        Self::new()
    }
}

impl ErrorLog {
    /// Creates an empty error log.
    pub const fn new() -> Self {
        Self {
            records: [ErrorRecord {
                timestamp: 0,
                pfn: 0,
                severity: MceSeverity::Correctable,
                page_type: PoisonedPageType::Anonymous,
                action: MemFailureAction::Ignore,
                recovered: false,
                affected_pid: 0,
                dimm_index: 0,
                cpu_id: 0,
                in_use: false,
            }; MAX_ERROR_RECORDS],
            write_pos: 0,
            total_records: 0,
        }
    }

    /// Records an error event.
    pub fn record(&mut self, entry: ErrorRecord) {
        self.records[self.write_pos] = entry;
        self.write_pos = (self.write_pos + 1) % MAX_ERROR_RECORDS;
        self.total_records += 1;
    }

    /// Returns the most recent `count` records.
    pub fn recent(&self, count: usize) -> &[ErrorRecord] {
        let available = core::cmp::min(
            count,
            core::cmp::min(self.total_records as usize, MAX_ERROR_RECORDS),
        );
        if available == 0 {
            return &[];
        }
        let start = if self.write_pos >= available {
            self.write_pos - available
        } else {
            0
        };
        let end = core::cmp::min(start + available, MAX_ERROR_RECORDS);
        &self.records[start..end]
    }

    /// Total number of records written.
    pub fn total_records(&self) -> u64 {
        self.total_records
    }
}

// -------------------------------------------------------------------
// ProcessNotification
// -------------------------------------------------------------------

/// A pending notification to a process about a memory error.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessNotification {
    /// Process ID to notify.
    pub pid: u64,
    /// Virtual address of the poisoned mapping.
    pub vaddr: u64,
    /// Signal to send (SIGBUS = 7).
    pub signal: u32,
    /// Error code for si_code.
    pub error_code: u32,
    /// Whether this notification has been delivered.
    pub delivered: bool,
    /// Whether this slot is in use.
    pub in_use: bool,
}

// -------------------------------------------------------------------
// DimmErrorInfo
// -------------------------------------------------------------------

/// Error source tracking per DIMM/rank.
#[derive(Debug, Clone, Copy, Default)]
pub struct DimmErrorInfo {
    /// DIMM index.
    pub dimm_index: u16,
    /// Total correctable errors on this DIMM.
    pub ce_count: u64,
    /// Total uncorrectable errors on this DIMM.
    pub ue_count: u64,
    /// Number of pages offlined from this DIMM.
    pub pages_offlined: u32,
    /// Whether this DIMM is flagged for replacement.
    pub flagged_replace: bool,
    /// DIMM replacement threshold (CE count).
    pub replace_threshold: u64,
    /// Whether this slot is in use.
    pub in_use: bool,
}

// -------------------------------------------------------------------
// PoisonRecovery
// -------------------------------------------------------------------

/// Recovery engine for individual poisoned pages.
///
/// Coordinates the recovery process: identify page type, determine
/// action, execute recovery, and report results.
#[derive(Debug, Default)]
pub struct PoisonRecovery {
    /// Total recovery attempts.
    pub attempts: u64,
    /// Successful recoveries.
    pub successes: u64,
    /// Failed recoveries.
    pub failures: u64,
    /// Pages successfully migrated.
    pub pages_migrated: u64,
    /// Processes killed due to unrecoverable errors.
    pub processes_killed: u64,
    /// SIGBUS signals sent.
    pub sigbus_sent: u64,
}

impl PoisonRecovery {
    /// Creates a new recovery engine.
    pub const fn new() -> Self {
        Self {
            attempts: 0,
            successes: 0,
            failures: 0,
            pages_migrated: 0,
            processes_killed: 0,
            sigbus_sent: 0,
        }
    }

    /// Attempts recovery for a poisoned page.
    ///
    /// Returns the action that was taken.
    pub fn recover(&mut self, page: &mut HwPoisonPage) -> MemFailureAction {
        self.attempts += 1;
        let action = determine_action(page.page_type, page.severity);

        match action {
            MemFailureAction::Ignore => {
                self.successes += 1;
            }
            MemFailureAction::MigratePage => {
                // In a real kernel: call migrate_pages().
                page.state = PagePoisonState::Recovering;
                // Simulate success.
                page.state = PagePoisonState::SoftOffline;
                self.pages_migrated += 1;
                self.successes += 1;
            }
            MemFailureAction::SoftOfflinePage => {
                page.state = PagePoisonState::SoftOffline;
                self.successes += 1;
            }
            MemFailureAction::HardOfflinePage => {
                page.state = PagePoisonState::HardOffline;
                self.successes += 1;
            }
            MemFailureAction::InvalidatePageCache => {
                page.state = PagePoisonState::SoftOffline;
                self.successes += 1;
            }
            MemFailureAction::SendSigbus => {
                self.sigbus_sent += 1;
                page.state = PagePoisonState::HardOffline;
                self.successes += 1;
            }
            MemFailureAction::KillProcess => {
                self.processes_killed += 1;
                page.state = PagePoisonState::HardOffline;
                self.successes += 1;
            }
            MemFailureAction::SystemPanic => {
                // In a real kernel: trigger panic. Here we mark failed.
                page.state = PagePoisonState::RecoveryFailed;
                self.failures += 1;
            }
        }

        action
    }
}

// -------------------------------------------------------------------
// SoftOfflineEngine
// -------------------------------------------------------------------

/// Proactive soft-offline engine.
///
/// Monitors pages with correctable errors and, when the error count
/// exceeds a threshold, proactively migrates and offlines the page
/// before an uncorrectable error occurs.
#[derive(Debug)]
pub struct SoftOfflineEngine {
    /// Correctable error threshold for triggering soft-offline.
    pub ce_threshold: u32,
    /// Whether proactive soft-offline is enabled.
    pub enabled: bool,
    /// Pages that have been soft-offlined.
    pub offlined_count: u64,
    /// Pages checked in the most recent scan.
    pub last_scan_checked: u64,
    /// Pages offlined in the most recent scan.
    pub last_scan_offlined: u64,
}

impl Default for SoftOfflineEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl SoftOfflineEngine {
    /// Creates a new soft-offline engine with default thresholds.
    pub const fn new() -> Self {
        Self {
            ce_threshold: DEFAULT_CE_THRESHOLD,
            enabled: true,
            offlined_count: 0,
            last_scan_checked: 0,
            last_scan_offlined: 0,
        }
    }

    /// Checks if a page should be soft-offlined based on its CE count.
    pub fn should_offline(&self, ce_count: u32) -> bool {
        self.enabled && ce_count >= self.ce_threshold
    }

    /// Sets the correctable error threshold.
    pub fn set_threshold(&mut self, threshold: u32) {
        self.ce_threshold = threshold;
    }
}

// -------------------------------------------------------------------
// MemFailureStats
// -------------------------------------------------------------------

/// Aggregate memory failure statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemFailureStats {
    /// Total correctable errors detected.
    pub total_ce: u64,
    /// Total uncorrectable errors detected.
    pub total_ue: u64,
    /// Pages currently soft-offlined.
    pub soft_offlined: u64,
    /// Pages currently hard-offlined.
    pub hard_offlined: u64,
    /// Total pages poisoned (all states).
    pub total_poisoned: u64,
    /// Successful recovery count.
    pub recoveries: u64,
    /// Failed recovery count.
    pub recovery_failures: u64,
    /// Processes affected by memory errors.
    pub processes_affected: u64,
    /// DIMMs flagged for replacement.
    pub dimms_flagged: u32,
}

// -------------------------------------------------------------------
// MemFailureManager
// -------------------------------------------------------------------

/// Top-level memory failure management subsystem.
///
/// Coordinates error handling across all subsystems: receives MCE
/// events, tracks poisoned pages, orchestrates recovery, manages
/// process notifications, and maintains DIMM-level error tracking.
pub struct MemFailureManager {
    /// Poisoned page tracking table.
    poison_pages: [HwPoisonPage; MAX_POISON_PAGES],
    /// Number of active poison entries.
    poison_count: usize,
    /// Error event log.
    error_log: ErrorLog,
    /// Pending process notifications.
    notifications: [ProcessNotification; MAX_NOTIFICATIONS],
    /// Number of pending notifications.
    notification_count: usize,
    /// DIMM error tracking.
    dimms: [DimmErrorInfo; MAX_DIMM_ENTRIES],
    /// Number of active DIMM entries.
    dimm_count: usize,
    /// Recovery engine.
    recovery: PoisonRecovery,
    /// Soft-offline engine.
    soft_offline: SoftOfflineEngine,
    /// Aggregate statistics.
    stats: MemFailureStats,
    /// Monotonic tick counter.
    tick: u64,
}

impl Default for MemFailureManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MemFailureManager {
    /// Creates a new memory failure manager.
    pub const fn new() -> Self {
        Self {
            poison_pages: [HwPoisonPage {
                pfn: 0,
                state: PagePoisonState::Healthy,
                page_type: PoisonedPageType::Anonymous,
                severity: MceSeverity::Correctable,
                ce_count: 0,
                first_error_tick: 0,
                last_error_tick: 0,
                affected_pid: 0,
                dimm_index: 0,
                bank: 0,
                in_use: false,
            }; MAX_POISON_PAGES],
            poison_count: 0,
            error_log: ErrorLog::new(),
            notifications: [ProcessNotification {
                pid: 0,
                vaddr: 0,
                signal: 0,
                error_code: 0,
                delivered: false,
                in_use: false,
            }; MAX_NOTIFICATIONS],
            notification_count: 0,
            dimms: [DimmErrorInfo {
                dimm_index: 0,
                ce_count: 0,
                ue_count: 0,
                pages_offlined: 0,
                flagged_replace: false,
                replace_threshold: 100,
                in_use: false,
            }; MAX_DIMM_ENTRIES],
            dimm_count: 0,
            recovery: PoisonRecovery::new(),
            soft_offline: SoftOfflineEngine::new(),
            stats: MemFailureStats {
                total_ce: 0,
                total_ue: 0,
                soft_offlined: 0,
                hard_offlined: 0,
                total_poisoned: 0,
                recoveries: 0,
                recovery_failures: 0,
                processes_affected: 0,
                dimms_flagged: 0,
            },
            tick: 0,
        }
    }

    /// Advances the internal tick counter.
    fn advance_tick(&mut self) -> u64 {
        self.tick += 1;
        self.tick
    }

    /// Reports a hardware memory error (MCE/GHES event).
    ///
    /// This is the main entry point for error handling. It:
    /// 1. Finds or creates the poison page entry
    /// 2. Updates error counters
    /// 3. Determines the recovery action
    /// 4. Executes recovery
    /// 5. Queues process notifications if needed
    /// 6. Logs the event
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the poison table is full.
    pub fn report_error(
        &mut self,
        pfn: u64,
        severity: MceSeverity,
        page_type: PoisonedPageType,
        affected_pid: u64,
        dimm_index: u16,
        cpu_id: u16,
    ) -> Result<MemFailureAction> {
        let ts = self.advance_tick();

        // Update DIMM counters.
        self.update_dimm(dimm_index, severity);

        // Find or create poison page entry.
        let pi = self.find_or_create_poison(pfn, ts)?;
        self.poison_pages[pi].page_type = page_type;
        self.poison_pages[pi].affected_pid = affected_pid;
        self.poison_pages[pi].dimm_index = dimm_index;
        self.poison_pages[pi].last_error_tick = ts;

        // Update severity (keep the worst).
        if severity > self.poison_pages[pi].severity {
            self.poison_pages[pi].severity = severity;
        }

        // Update error counters.
        match severity {
            MceSeverity::Correctable => {
                self.poison_pages[pi].ce_count += 1;
                self.stats.total_ce += 1;
            }
            _ => {
                self.stats.total_ue += 1;
            }
        }

        // Check soft-offline threshold for CEs.
        if severity == MceSeverity::Correctable
            && self
                .soft_offline
                .should_offline(self.poison_pages[pi].ce_count)
        {
            self.poison_pages[pi].severity = MceSeverity::UncorrectableNoAction;
        }

        // Execute recovery.
        let action = self.recovery.recover(&mut self.poison_pages[pi]);

        // Update aggregate stats based on new state.
        match self.poison_pages[pi].state {
            PagePoisonState::SoftOffline => {
                self.stats.soft_offlined += 1;
                self.stats.recoveries += 1;
            }
            PagePoisonState::HardOffline => {
                self.stats.hard_offlined += 1;
                self.stats.recoveries += 1;
            }
            PagePoisonState::RecoveryFailed => {
                self.stats.recovery_failures += 1;
            }
            _ => {}
        }

        // Queue notification for affected process.
        if affected_pid != 0
            && (action == MemFailureAction::SendSigbus || action == MemFailureAction::KillProcess)
        {
            let _ = self.queue_notification(
                affected_pid,
                pfn * PAGE_SIZE,
                7, // SIGBUS
                if action == MemFailureAction::KillProcess {
                    2
                } else {
                    1
                },
            );
            self.stats.processes_affected += 1;
        }

        // Log the event.
        self.error_log.record(ErrorRecord {
            timestamp: ts,
            pfn,
            severity,
            page_type,
            action,
            recovered: self.poison_pages[pi].state == PagePoisonState::SoftOffline
                || self.poison_pages[pi].state == PagePoisonState::HardOffline,
            affected_pid,
            dimm_index,
            cpu_id,
            in_use: true,
        });

        Ok(action)
    }

    /// Performs a soft-offline scan over tracked pages.
    ///
    /// Checks all pages with correctable errors against the CE
    /// threshold and initiates soft-offline for pages that exceed it.
    ///
    /// Returns the number of pages offlined in this scan.
    pub fn soft_offline_scan(&mut self) -> usize {
        let mut offlined = 0_usize;
        let mut checked = 0_u64;
        let threshold = self.soft_offline.ce_threshold;

        for i in 0..MAX_POISON_PAGES {
            if offlined >= SOFT_OFFLINE_BATCH {
                break;
            }
            let page = &mut self.poison_pages[i];
            if !page.in_use {
                continue;
            }
            checked += 1;

            if page.state == PagePoisonState::CorrectedMonitor && page.ce_count >= threshold {
                page.state = PagePoisonState::SoftOffline;
                self.stats.soft_offlined += 1;
                self.soft_offline.offlined_count += 1;
                offlined += 1;
            }
        }

        self.soft_offline.last_scan_checked = checked;
        self.soft_offline.last_scan_offlined = offlined as u64;
        offlined
    }

    /// Injects a memory error for testing purposes.
    ///
    /// Creates a fake MCE event on the specified PFN.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the poison table is full.
    pub fn inject_error(
        &mut self,
        pfn: u64,
        severity: MceSeverity,
        page_type: PoisonedPageType,
    ) -> Result<MemFailureAction> {
        self.report_error(pfn, severity, page_type, 0, 0, 0)
    }

    /// Unpoisons a page (clears the error state).
    ///
    /// Only pages in [`PagePoisonState::SoftOffline`] can be
    /// unpoisoned (returned to the allocator).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the PFN is not in the poison
    /// table.
    /// Returns [`Error::PermissionDenied`] if the page is
    /// hard-offlined.
    pub fn unpoison_page(&mut self, pfn: u64) -> Result<()> {
        let page = self
            .poison_pages
            .iter_mut()
            .find(|p| p.in_use && p.pfn == pfn)
            .ok_or(Error::NotFound)?;

        if page.state == PagePoisonState::HardOffline {
            return Err(Error::PermissionDenied);
        }

        page.in_use = false;
        page.state = PagePoisonState::Healthy;
        page.ce_count = 0;
        page.severity = MceSeverity::Correctable;
        self.poison_count = self.poison_count.saturating_sub(1);
        self.stats.total_poisoned = self.stats.total_poisoned.saturating_sub(1);
        self.stats.soft_offlined = self.stats.soft_offlined.saturating_sub(1);

        Ok(())
    }

    /// Checks if a physical frame is poisoned.
    pub fn is_poisoned(&self, pfn: u64) -> bool {
        self.poison_pages.iter().any(|p| p.in_use && p.pfn == pfn)
    }

    /// Returns the poison state for a PFN.
    pub fn get_poison_state(&self, pfn: u64) -> Option<&HwPoisonPage> {
        self.poison_pages.iter().find(|p| p.in_use && p.pfn == pfn)
    }

    /// Delivers all pending process notifications.
    ///
    /// Returns the number of notifications delivered.
    pub fn deliver_notifications(&mut self) -> usize {
        let mut delivered = 0_usize;
        for i in 0..MAX_NOTIFICATIONS {
            if self.notifications[i].in_use && !self.notifications[i].delivered {
                // In a real kernel: send_signal(pid, signal).
                self.notifications[i].delivered = true;
                delivered += 1;
            }
        }
        delivered
    }

    /// Returns a reference to the error log.
    pub fn error_log(&self) -> &ErrorLog {
        &self.error_log
    }

    /// Returns a reference to the soft-offline engine.
    pub fn soft_offline(&self) -> &SoftOfflineEngine {
        &self.soft_offline
    }

    /// Returns a mutable reference to the soft-offline engine.
    pub fn soft_offline_mut(&mut self) -> &mut SoftOfflineEngine {
        &mut self.soft_offline
    }

    /// Returns a reference to the recovery engine.
    pub fn recovery(&self) -> &PoisonRecovery {
        &self.recovery
    }

    /// Returns aggregate statistics.
    pub fn stats(&self) -> &MemFailureStats {
        &self.stats
    }

    /// Number of poisoned pages being tracked.
    pub fn poison_count(&self) -> usize {
        self.poison_count
    }

    /// Returns `true` if no pages are poisoned.
    pub fn is_healthy(&self) -> bool {
        self.poison_count == 0
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Finds an existing poison entry or creates a new one.
    fn find_or_create_poison(&mut self, pfn: u64, tick: u64) -> Result<usize> {
        // Search for existing entry.
        for i in 0..MAX_POISON_PAGES {
            if self.poison_pages[i].in_use && self.poison_pages[i].pfn == pfn {
                return Ok(i);
            }
        }
        // Create new entry.
        if self.poison_count >= MAX_POISON_PAGES {
            return Err(Error::OutOfMemory);
        }
        let idx = self
            .poison_pages
            .iter()
            .position(|p| !p.in_use)
            .ok_or(Error::OutOfMemory)?;

        self.poison_pages[idx] = HwPoisonPage {
            pfn,
            state: PagePoisonState::CorrectedMonitor,
            page_type: PoisonedPageType::Anonymous,
            severity: MceSeverity::Correctable,
            ce_count: 0,
            first_error_tick: tick,
            last_error_tick: tick,
            affected_pid: 0,
            dimm_index: 0,
            bank: 0,
            in_use: true,
        };
        self.poison_count += 1;
        self.stats.total_poisoned += 1;
        Ok(idx)
    }

    /// Queues a notification for a process.
    fn queue_notification(
        &mut self,
        pid: u64,
        vaddr: u64,
        signal: u32,
        error_code: u32,
    ) -> Result<()> {
        if self.notification_count >= MAX_NOTIFICATIONS {
            return Err(Error::OutOfMemory);
        }
        let slot = self
            .notifications
            .iter_mut()
            .find(|n| !n.in_use)
            .ok_or(Error::OutOfMemory)?;
        *slot = ProcessNotification {
            pid,
            vaddr,
            signal,
            error_code,
            delivered: false,
            in_use: true,
        };
        self.notification_count += 1;
        Ok(())
    }

    /// Updates DIMM-level error counters.
    fn update_dimm(&mut self, dimm_index: u16, severity: MceSeverity) {
        // Find existing DIMM entry.
        for i in 0..MAX_DIMM_ENTRIES {
            if self.dimms[i].in_use && self.dimms[i].dimm_index == dimm_index {
                match severity {
                    MceSeverity::Correctable => {
                        self.dimms[i].ce_count += 1;
                        if self.dimms[i].ce_count >= self.dimms[i].replace_threshold
                            && !self.dimms[i].flagged_replace
                        {
                            self.dimms[i].flagged_replace = true;
                            self.stats.dimms_flagged += 1;
                        }
                    }
                    _ => {
                        self.dimms[i].ue_count += 1;
                    }
                }
                return;
            }
        }

        // Create new DIMM entry.
        if self.dimm_count >= MAX_DIMM_ENTRIES {
            return;
        }
        if let Some(slot) = self.dimms.iter_mut().find(|d| !d.in_use) {
            *slot = DimmErrorInfo {
                dimm_index,
                ce_count: if severity == MceSeverity::Correctable {
                    1
                } else {
                    0
                },
                ue_count: if severity != MceSeverity::Correctable {
                    1
                } else {
                    0
                },
                pages_offlined: 0,
                flagged_replace: false,
                replace_threshold: 100,
                in_use: true,
            };
            self.dimm_count += 1;
        }
    }
}
