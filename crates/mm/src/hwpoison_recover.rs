// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hardware memory error recovery subsystem.
//!
//! Complements [`super::hwpoison`] (tracking) and
//! [`super::memory_failure`] (detection) with the recovery pipeline:
//! evaluating whether a poisoned page can be recovered, performing
//! page replacement or data salvage, notifying affected processes,
//! and permanently offlining pages that cannot be recovered.
//!
//! # Recovery pipeline
//!
//! ```text
//!  hwpoison_recover(pfn)
//!     │
//!     ├─ classify page usage  → RecoverableClass
//!     ├─ attempt recovery
//!     │    ├─ Clean file:  drop cache, re-read from disk
//!     │    ├─ Dirty file:  attempt writeback + re-read
//!     │    ├─ Anonymous:   allocate replacement, remap PTEs
//!     │    ├─ Free:        offline immediately
//!     │    └─ Kernel slab: cannot recover → offline + log
//!     ├─ notify affected processes (SIGBUS or remap)
//!     └─ offline page if unrecoverable
//! ```
//!
//! # Key types
//!
//! - [`RecoverableClass`] — classification of recovery feasibility
//! - [`RecoveryAction`] — action taken during recovery
//! - [`RecoveryOutcome`] — final result of a recovery attempt
//! - [`ProcessNotification`] — record of a process that was notified
//! - [`OfflinedPage`] — permanently offlined page descriptor
//! - [`RecoveryStats`] — aggregate recovery statistics
//! - [`HwpoisonRecoveryManager`] — top-level recovery engine
//!
//! Reference: Linux `mm/memory-failure.c` (`me_*` handlers,
//! `memory_failure()`, `soft_offline_page()`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Maximum pages that can be permanently offlined.
const MAX_OFFLINED_PAGES: usize = 4096;

/// Maximum pending recovery attempts tracked simultaneously.
const MAX_PENDING_RECOVERIES: usize = 128;

/// Maximum process notifications queued per recovery event.
const MAX_NOTIFICATIONS_PER_EVENT: usize = 64;

/// Maximum total notification records retained.
const MAX_NOTIFICATION_LOG: usize = 512;

/// Soft-offline retry limit before escalating to hard-offline.
const SOFT_OFFLINE_RETRY_LIMIT: u32 = 5;

/// Maximum number of page replacements attempted per recovery.
const MAX_REPLACEMENT_ATTEMPTS: u32 = 3;

// -------------------------------------------------------------------
// RecoverableClass
// -------------------------------------------------------------------

/// Classification of how recoverable a poisoned page is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecoverableClass {
    /// Clean file-backed page — can be discarded and re-read.
    CleanFile,
    /// Dirty file-backed page — must attempt writeback first.
    DirtyFile,
    /// Anonymous page — need to allocate replacement and remap.
    Anonymous,
    /// Free page — offline immediately, no user data at risk.
    FreePage,
    /// Kernel slab — generally unrecoverable.
    KernelSlab,
    /// Huge page — may be split and partially recovered.
    HugePage,
    /// Page table page — critical, must offline and rebuild.
    PageTable,
    /// Reserved/special page — cannot recover.
    Reserved,
    /// Unknown classification.
    #[default]
    Unknown,
}

impl RecoverableClass {
    /// Whether this class has any recovery path.
    pub const fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::CleanFile | Self::DirtyFile | Self::Anonymous | Self::FreePage | Self::HugePage
        )
    }

    /// Whether this class requires process notification (SIGBUS).
    pub const fn needs_notification(&self) -> bool {
        matches!(
            self,
            Self::DirtyFile | Self::Anonymous | Self::HugePage | Self::KernelSlab | Self::PageTable
        )
    }

    /// Return a human-readable label for this class.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::CleanFile => "clean-file",
            Self::DirtyFile => "dirty-file",
            Self::Anonymous => "anonymous",
            Self::FreePage => "free",
            Self::KernelSlab => "kernel-slab",
            Self::HugePage => "huge-page",
            Self::PageTable => "page-table",
            Self::Reserved => "reserved",
            Self::Unknown => "unknown",
        }
    }

    /// Estimated difficulty of recovery (0 = trivial, 10 = impossible).
    pub const fn difficulty(&self) -> u8 {
        match self {
            Self::FreePage => 0,
            Self::CleanFile => 1,
            Self::DirtyFile => 4,
            Self::Anonymous => 5,
            Self::HugePage => 7,
            Self::PageTable => 9,
            Self::KernelSlab => 9,
            Self::Reserved => 10,
            Self::Unknown => 10,
        }
    }
}

// -------------------------------------------------------------------
// RecoveryAction
// -------------------------------------------------------------------

/// Specific action taken during a recovery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecoveryAction {
    /// Discarded a clean file page (will be re-read on demand).
    DiscardClean,
    /// Attempted writeback of dirty page before discard.
    WritebackAndDiscard,
    /// Allocated a replacement page and remapped PTEs.
    ReplaceAndRemap,
    /// Split a huge page, then recovered sub-pages.
    SplitHugePage,
    /// Offlined the page permanently (no recovery possible).
    OfflinePermanent,
    /// Sent SIGBUS to affected processes.
    SignalProcess,
    /// No action taken (page was already handled or free).
    #[default]
    NoAction,
}

impl RecoveryAction {
    /// Whether this action is destructive (data may be lost).
    pub const fn is_destructive(&self) -> bool {
        matches!(self, Self::OfflinePermanent | Self::SignalProcess)
    }

    /// Return a label for logging.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::DiscardClean => "discard-clean",
            Self::WritebackAndDiscard => "writeback-discard",
            Self::ReplaceAndRemap => "replace-remap",
            Self::SplitHugePage => "split-huge",
            Self::OfflinePermanent => "offline-permanent",
            Self::SignalProcess => "signal-process",
            Self::NoAction => "no-action",
        }
    }
}

// -------------------------------------------------------------------
// RecoveryOutcome
// -------------------------------------------------------------------

/// Final result of a recovery attempt for a single page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecoveryOutcome {
    /// Full recovery: page replaced, no data lost.
    FullRecovery,
    /// Partial recovery: some data may be lost but system continues.
    PartialRecovery,
    /// Page offlined: permanently removed from use.
    Offlined,
    /// Recovery failed: system must kill affected processes.
    Failed,
    /// Recovery was not attempted (page not in use).
    #[default]
    NotAttempted,
}

impl RecoveryOutcome {
    /// Whether the outcome is considered successful (no process kill).
    pub const fn is_success(&self) -> bool {
        matches!(
            self,
            Self::FullRecovery | Self::PartialRecovery | Self::NotAttempted
        )
    }

    /// Whether the page was taken permanently out of service.
    pub const fn is_offlined(&self) -> bool {
        matches!(self, Self::Offlined)
    }
}

// -------------------------------------------------------------------
// ProcessNotification
// -------------------------------------------------------------------

/// Record of a process notification triggered by hwpoison recovery.
#[derive(Debug, Clone, Copy)]
pub struct ProcessNotification {
    /// Process ID of the affected process.
    pid: u32,
    /// Virtual address where the poisoned page was mapped.
    fault_addr: u64,
    /// PFN of the poisoned page.
    pfn: u64,
    /// Signal sent (e.g., SIGBUS = 7).
    signal: u8,
    /// Whether the process was killed as a result.
    process_killed: bool,
    /// Whether a replacement page was provided.
    replacement_provided: bool,
    /// Timestamp of the notification.
    timestamp: u64,
}

impl ProcessNotification {
    /// Create a new notification record.
    pub const fn new(pid: u32, fault_addr: u64, pfn: u64, signal: u8, timestamp: u64) -> Self {
        Self {
            pid,
            fault_addr,
            pfn,
            signal,
            process_killed: false,
            replacement_provided: false,
            timestamp,
        }
    }

    /// Return the process ID.
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Return the fault virtual address.
    pub const fn fault_addr(&self) -> u64 {
        self.fault_addr
    }

    /// Return the poisoned PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Return the signal number sent.
    pub const fn signal(&self) -> u8 {
        self.signal
    }

    /// Whether the process was killed.
    pub const fn process_killed(&self) -> bool {
        self.process_killed
    }

    /// Whether a replacement page was provided to the process.
    pub const fn replacement_provided(&self) -> bool {
        self.replacement_provided
    }

    /// Return the notification timestamp.
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Mark the process as killed.
    pub fn mark_killed(&mut self) {
        self.process_killed = true;
    }

    /// Mark that a replacement page was provided.
    pub fn mark_replacement_provided(&mut self) {
        self.replacement_provided = true;
    }
}

// -------------------------------------------------------------------
// OfflinedPage
// -------------------------------------------------------------------

/// Descriptor for a permanently offlined page.
#[derive(Debug, Clone, Copy)]
pub struct OfflinedPage {
    /// Physical frame number.
    pfn: u64,
    /// Physical address.
    phys_addr: u64,
    /// Class at the time of offlining.
    class: RecoverableClass,
    /// Recovery outcome that led to offlining.
    outcome: RecoveryOutcome,
    /// Number of recovery attempts before offlining.
    recovery_attempts: u32,
    /// Timestamp when the page was offlined.
    offlined_at: u64,
    /// Whether the page was part of a huge page.
    from_huge_page: bool,
    /// NUMA node the page belonged to.
    numa_node: u8,
}

impl OfflinedPage {
    /// Create a new offlined page record.
    pub const fn new(
        pfn: u64,
        class: RecoverableClass,
        outcome: RecoveryOutcome,
        recovery_attempts: u32,
        offlined_at: u64,
    ) -> Self {
        Self {
            pfn,
            phys_addr: pfn * PAGE_SIZE,
            class,
            outcome,
            recovery_attempts,
            offlined_at,
            from_huge_page: false,
            numa_node: 0,
        }
    }

    /// Return the PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Return the physical address.
    pub const fn phys_addr(&self) -> u64 {
        self.phys_addr
    }

    /// Return the classification at offline time.
    pub const fn class(&self) -> RecoverableClass {
        self.class
    }

    /// Return the recovery outcome.
    pub const fn outcome(&self) -> RecoveryOutcome {
        self.outcome
    }

    /// Return how many recovery attempts were made.
    pub const fn recovery_attempts(&self) -> u32 {
        self.recovery_attempts
    }

    /// Return the offline timestamp.
    pub const fn offlined_at(&self) -> u64 {
        self.offlined_at
    }

    /// Whether the page was part of a huge page that was split.
    pub const fn from_huge_page(&self) -> bool {
        self.from_huge_page
    }

    /// Return the NUMA node.
    pub const fn numa_node(&self) -> u8 {
        self.numa_node
    }

    /// Set the NUMA node.
    pub fn set_numa_node(&mut self, node: u8) {
        self.numa_node = node;
    }

    /// Mark as originating from a huge page.
    pub fn set_from_huge_page(&mut self) {
        self.from_huge_page = true;
    }
}

// -------------------------------------------------------------------
// PendingRecovery
// -------------------------------------------------------------------

/// A recovery attempt that is in progress or queued.
#[derive(Debug, Clone, Copy)]
struct PendingRecovery {
    /// Physical frame number of the poisoned page.
    pfn: u64,
    /// Classification of the page.
    class: RecoverableClass,
    /// Actions taken so far (bitmask placeholder).
    actions_taken: u8,
    /// Number of attempts so far.
    attempts: u32,
    /// Replacement PFN (0 if none allocated yet).
    replacement_pfn: u64,
    /// Number of processes notified.
    processes_notified: u32,
    /// Timestamp when recovery started.
    started_at: u64,
    /// Whether recovery is complete.
    complete: bool,
    /// Final outcome (valid only when complete).
    outcome: RecoveryOutcome,
}

impl PendingRecovery {
    /// Create a new pending recovery.
    const fn new(pfn: u64, class: RecoverableClass, started_at: u64) -> Self {
        Self {
            pfn,
            class,
            actions_taken: 0,
            attempts: 0,
            replacement_pfn: 0,
            processes_notified: 0,
            started_at,
            complete: false,
            outcome: RecoveryOutcome::NotAttempted,
        }
    }
}

// -------------------------------------------------------------------
// RecoveryStats
// -------------------------------------------------------------------

/// Aggregate statistics for the hwpoison recovery subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct RecoveryStats {
    /// Total recovery attempts.
    pub total_attempts: u64,
    /// Successful full recoveries.
    pub full_recoveries: u64,
    /// Partial recoveries.
    pub partial_recoveries: u64,
    /// Pages permanently offlined.
    pub pages_offlined: u64,
    /// Failed recoveries (process kill required).
    pub failed_recoveries: u64,
    /// Total process notifications sent.
    pub notifications_sent: u64,
    /// Processes killed due to unrecoverable errors.
    pub processes_killed: u64,
    /// Replacement pages allocated.
    pub replacements_allocated: u64,
    /// Huge pages split for partial recovery.
    pub huge_pages_split: u64,
    /// Soft-offline to hard-offline escalations.
    pub soft_to_hard_escalations: u64,
}

impl RecoveryStats {
    /// Return the overall success rate as a percentage (0-100).
    pub fn success_rate_percent(&self) -> u32 {
        if self.total_attempts == 0 {
            return 100;
        }
        let successes = self.full_recoveries + self.partial_recoveries;
        ((successes * 100) / self.total_attempts) as u32
    }

    /// Return the total number of pages removed from service.
    pub const fn total_removed(&self) -> u64 {
        self.pages_offlined
    }
}

// -------------------------------------------------------------------
// HwpoisonRecoveryManager
// -------------------------------------------------------------------

/// Top-level manager for hardware memory error recovery.
///
/// Coordinates classification, recovery attempts, process notification,
/// and page offlining.  Works alongside [`super::hwpoison::HwPoisonTable`]
/// (tracking) and [`super::memory_failure::MemoryFailureHandler`]
/// (detection).
pub struct HwpoisonRecoveryManager {
    /// Permanently offlined pages.
    offlined: [OfflinedPage; MAX_OFFLINED_PAGES],
    /// Number of offlined pages.
    offlined_count: usize,
    /// Pending (in-progress) recoveries.
    pending: [PendingRecovery; MAX_PENDING_RECOVERIES],
    /// Number of pending recoveries.
    pending_count: usize,
    /// Process notification log.
    notifications: [ProcessNotification; MAX_NOTIFICATION_LOG],
    /// Number of notification records.
    notification_count: usize,
    /// Aggregate statistics.
    stats: RecoveryStats,
    /// Whether the recovery subsystem is enabled.
    enabled: bool,
    /// Next available timestamp counter (monotonic, simplified).
    next_timestamp: u64,
}

impl HwpoisonRecoveryManager {
    /// Create a new recovery manager.
    pub const fn new() -> Self {
        Self {
            offlined: [const {
                OfflinedPage {
                    pfn: 0,
                    phys_addr: 0,
                    class: RecoverableClass::Unknown,
                    outcome: RecoveryOutcome::NotAttempted,
                    recovery_attempts: 0,
                    offlined_at: 0,
                    from_huge_page: false,
                    numa_node: 0,
                }
            }; MAX_OFFLINED_PAGES],
            offlined_count: 0,
            pending: [const {
                PendingRecovery {
                    pfn: 0,
                    class: RecoverableClass::Unknown,
                    actions_taken: 0,
                    attempts: 0,
                    replacement_pfn: 0,
                    processes_notified: 0,
                    started_at: 0,
                    complete: false,
                    outcome: RecoveryOutcome::NotAttempted,
                }
            }; MAX_PENDING_RECOVERIES],
            pending_count: 0,
            notifications: [const {
                ProcessNotification {
                    pid: 0,
                    fault_addr: 0,
                    pfn: 0,
                    signal: 0,
                    process_killed: false,
                    replacement_provided: false,
                    timestamp: 0,
                }
            }; MAX_NOTIFICATION_LOG],
            notification_count: 0,
            stats: RecoveryStats {
                total_attempts: 0,
                full_recoveries: 0,
                partial_recoveries: 0,
                pages_offlined: 0,
                failed_recoveries: 0,
                notifications_sent: 0,
                processes_killed: 0,
                replacements_allocated: 0,
                huge_pages_split: 0,
                soft_to_hard_escalations: 0,
            },
            enabled: true,
            next_timestamp: 1,
        }
    }

    /// Enable the recovery subsystem.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the recovery subsystem.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Whether the subsystem is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Return a snapshot of the current statistics.
    pub const fn stats(&self) -> &RecoveryStats {
        &self.stats
    }

    /// Return the number of permanently offlined pages.
    pub const fn offlined_count(&self) -> usize {
        self.offlined_count
    }

    /// Return the number of pending recoveries.
    pub const fn pending_count(&self) -> usize {
        self.pending_count
    }

    /// Return the number of logged notifications.
    pub const fn notification_count(&self) -> usize {
        self.notification_count
    }

    /// Advance and return the next monotonic timestamp.
    fn tick(&mut self) -> u64 {
        let ts = self.next_timestamp;
        self.next_timestamp += 1;
        ts
    }

    // ---------------------------------------------------------------
    // Classification
    // ---------------------------------------------------------------

    /// Classify a page for recovery based on its usage state.
    ///
    /// `is_free`, `is_file`, `is_dirty`, `is_anon`, `is_huge`,
    /// `is_slab`, `is_pgtable`, `is_reserved` describe the page state.
    pub fn classify_page(
        &self,
        is_free: bool,
        is_file: bool,
        is_dirty: bool,
        is_anon: bool,
        is_huge: bool,
        is_slab: bool,
        is_pgtable: bool,
        is_reserved: bool,
    ) -> RecoverableClass {
        if is_reserved {
            return RecoverableClass::Reserved;
        }
        if is_free {
            return RecoverableClass::FreePage;
        }
        if is_pgtable {
            return RecoverableClass::PageTable;
        }
        if is_slab {
            return RecoverableClass::KernelSlab;
        }
        if is_huge {
            return RecoverableClass::HugePage;
        }
        if is_anon {
            return RecoverableClass::Anonymous;
        }
        if is_file && is_dirty {
            return RecoverableClass::DirtyFile;
        }
        if is_file {
            return RecoverableClass::CleanFile;
        }
        RecoverableClass::Unknown
    }

    // ---------------------------------------------------------------
    // Recovery pipeline
    // ---------------------------------------------------------------

    /// Begin recovery for a poisoned page.
    ///
    /// Returns the recovery outcome. The page is classified,
    /// a recovery strategy is selected and executed, and the page
    /// is offlined if recovery fails.
    pub fn recover_page(&mut self, pfn: u64, class: RecoverableClass) -> Result<RecoveryOutcome> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }

        self.stats.total_attempts += 1;
        let ts = self.tick();

        // Add to pending list.
        let pending_idx = self.add_pending(pfn, class, ts)?;

        let outcome = match class {
            RecoverableClass::FreePage => self.recover_free_page(pending_idx),
            RecoverableClass::CleanFile => self.recover_clean_file(pending_idx),
            RecoverableClass::DirtyFile => self.recover_dirty_file(pending_idx),
            RecoverableClass::Anonymous => self.recover_anonymous(pending_idx),
            RecoverableClass::HugePage => self.recover_huge_page(pending_idx),
            _ => {
                // KernelSlab, PageTable, Reserved, Unknown — unrecoverable.
                self.offline_page_from_pending(pending_idx, ts)
            }
        };

        // Complete the pending entry.
        if pending_idx < self.pending_count {
            self.pending[pending_idx].complete = true;
            self.pending[pending_idx].outcome = outcome;
        }

        // Update stats based on outcome.
        match outcome {
            RecoveryOutcome::FullRecovery => {
                self.stats.full_recoveries += 1;
            }
            RecoveryOutcome::PartialRecovery => {
                self.stats.partial_recoveries += 1;
            }
            RecoveryOutcome::Offlined => {
                // Already counted in offline_page_from_pending.
            }
            RecoveryOutcome::Failed => {
                self.stats.failed_recoveries += 1;
            }
            RecoveryOutcome::NotAttempted => {}
        }

        Ok(outcome)
    }

    /// Add a pending recovery entry.
    fn add_pending(&mut self, pfn: u64, class: RecoverableClass, ts: u64) -> Result<usize> {
        if self.pending_count >= MAX_PENDING_RECOVERIES {
            // Evict oldest completed entry.
            self.evict_completed_pending();
        }
        if self.pending_count >= MAX_PENDING_RECOVERIES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.pending_count;
        self.pending[idx] = PendingRecovery::new(pfn, class, ts);
        self.pending_count += 1;
        Ok(idx)
    }

    /// Evict completed pending entries to make room.
    fn evict_completed_pending(&mut self) {
        let mut write = 0;
        for read in 0..self.pending_count {
            if !self.pending[read].complete {
                self.pending[write] = self.pending[read];
                write += 1;
            }
        }
        self.pending_count = write;
    }

    /// Recover a free page (trivial: just offline it).
    fn recover_free_page(&mut self, idx: usize) -> RecoveryOutcome {
        self.pending[idx].attempts += 1;
        let ts = self.next_timestamp;
        let _ = self.offline_page_from_pending(idx, ts);
        RecoveryOutcome::FullRecovery
    }

    /// Recover a clean file page (discard and let page fault re-read).
    fn recover_clean_file(&mut self, idx: usize) -> RecoveryOutcome {
        self.pending[idx].attempts += 1;
        self.pending[idx].actions_taken |= 0x01; // discard-clean
        RecoveryOutcome::FullRecovery
    }

    /// Recover a dirty file page (attempt writeback, then discard).
    fn recover_dirty_file(&mut self, idx: usize) -> RecoveryOutcome {
        self.pending[idx].attempts += 1;
        self.pending[idx].actions_taken |= 0x02; // writeback-discard

        // In a real kernel, we would invoke the filesystem writeback
        // path here.  For this model, we simulate success if under
        // the retry limit.
        if self.pending[idx].attempts <= MAX_REPLACEMENT_ATTEMPTS {
            RecoveryOutcome::PartialRecovery
        } else {
            let ts = self.next_timestamp;
            self.offline_page_from_pending(idx, ts)
        }
    }

    /// Recover an anonymous page (allocate replacement, remap).
    fn recover_anonymous(&mut self, idx: usize) -> RecoveryOutcome {
        self.pending[idx].attempts += 1;
        self.pending[idx].actions_taken |= 0x04; // replace-remap

        // Simulate replacement allocation.
        let replacement_pfn = self.allocate_replacement_pfn();
        if replacement_pfn == 0 {
            // Cannot allocate replacement — fail.
            self.stats.failed_recoveries += 1;
            return RecoveryOutcome::Failed;
        }

        self.pending[idx].replacement_pfn = replacement_pfn;
        self.stats.replacements_allocated += 1;
        RecoveryOutcome::FullRecovery
    }

    /// Recover a huge page (split into base pages, recover individually).
    fn recover_huge_page(&mut self, idx: usize) -> RecoveryOutcome {
        self.pending[idx].attempts += 1;
        self.pending[idx].actions_taken |= 0x08; // split-huge
        self.stats.huge_pages_split += 1;

        // After splitting, only the poisoned sub-page needs offlining.
        // The rest remain usable. Model as partial recovery.
        RecoveryOutcome::PartialRecovery
    }

    /// Offline a page from a pending recovery entry.
    fn offline_page_from_pending(&mut self, idx: usize, ts: u64) -> RecoveryOutcome {
        if self.offlined_count >= MAX_OFFLINED_PAGES {
            return RecoveryOutcome::Failed;
        }
        let p = &self.pending[idx];
        let entry = OfflinedPage::new(p.pfn, p.class, RecoveryOutcome::Offlined, p.attempts, ts);
        self.offlined[self.offlined_count] = entry;
        self.offlined_count += 1;
        self.stats.pages_offlined += 1;
        RecoveryOutcome::Offlined
    }

    /// Simulate replacement PFN allocation.
    ///
    /// In a real kernel this would call the frame allocator.
    /// Returns 0 on failure.
    fn allocate_replacement_pfn(&self) -> u64 {
        // Simplified: always succeed with a placeholder PFN.
        // A real implementation would call into the bitmap allocator.
        0xDEAD_0000
    }

    // ---------------------------------------------------------------
    // Process notification
    // ---------------------------------------------------------------

    /// Record a process notification for a poisoned page.
    ///
    /// `pid` is the affected process, `fault_addr` is the virtual
    /// address in that process, `pfn` is the physical frame, and
    /// `signal` is the signal number (typically SIGBUS = 7).
    pub fn notify_process(
        &mut self,
        pid: u32,
        fault_addr: u64,
        pfn: u64,
        signal: u8,
    ) -> Result<()> {
        if self.notification_count >= MAX_NOTIFICATION_LOG {
            return Err(Error::OutOfMemory);
        }
        let ts = self.tick();
        let notif = ProcessNotification::new(pid, fault_addr, pfn, signal, ts);
        self.notifications[self.notification_count] = notif;
        self.notification_count += 1;
        self.stats.notifications_sent += 1;

        // Update pending recovery notification count.
        for i in 0..self.pending_count {
            if self.pending[i].pfn == pfn && !self.pending[i].complete {
                self.pending[i].processes_notified += 1;
                break;
            }
        }

        Ok(())
    }

    /// Record that a notified process was killed.
    pub fn record_process_kill(&mut self, pid: u32, pfn: u64) {
        for i in 0..self.notification_count {
            if self.notifications[i].pid == pid
                && self.notifications[i].pfn == pfn
                && !self.notifications[i].process_killed
            {
                self.notifications[i].mark_killed();
                self.stats.processes_killed += 1;
                break;
            }
        }
    }

    // ---------------------------------------------------------------
    // Soft-offline escalation
    // ---------------------------------------------------------------

    /// Attempt a soft-offline for a page. If the retry limit is
    /// exceeded, escalate to hard-offline.
    ///
    /// Returns the recovery outcome.
    pub fn soft_offline(
        &mut self,
        pfn: u64,
        attempt_number: u32,
        class: RecoverableClass,
    ) -> Result<RecoveryOutcome> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }

        if attempt_number >= SOFT_OFFLINE_RETRY_LIMIT {
            self.stats.soft_to_hard_escalations += 1;
            return self.hard_offline(pfn, class);
        }

        // Soft-offline: migrate data away, mark page reserved.
        // For free/clean pages, this is trivially successful.
        match class {
            RecoverableClass::FreePage | RecoverableClass::CleanFile => {
                Ok(RecoveryOutcome::FullRecovery)
            }
            RecoverableClass::Anonymous | RecoverableClass::DirtyFile => {
                // Needs migration — model as partial recovery.
                Ok(RecoveryOutcome::PartialRecovery)
            }
            _ => {
                // Escalate immediately for non-recoverable types.
                self.stats.soft_to_hard_escalations += 1;
                self.hard_offline(pfn, class)
            }
        }
    }

    /// Hard-offline a page: permanently remove it from the allocator.
    pub fn hard_offline(&mut self, pfn: u64, class: RecoverableClass) -> Result<RecoveryOutcome> {
        if self.offlined_count >= MAX_OFFLINED_PAGES {
            return Err(Error::OutOfMemory);
        }

        let ts = self.tick();
        let entry = OfflinedPage::new(pfn, class, RecoveryOutcome::Offlined, 0, ts);
        self.offlined[self.offlined_count] = entry;
        self.offlined_count += 1;
        self.stats.pages_offlined += 1;
        self.stats.total_attempts += 1;

        Ok(RecoveryOutcome::Offlined)
    }

    // ---------------------------------------------------------------
    // Query
    // ---------------------------------------------------------------

    /// Check whether a given PFN has been offlined.
    pub fn is_offlined(&self, pfn: u64) -> bool {
        for i in 0..self.offlined_count {
            if self.offlined[i].pfn == pfn {
                return true;
            }
        }
        false
    }

    /// Look up an offlined page entry by PFN.
    pub fn find_offlined(&self, pfn: u64) -> Option<&OfflinedPage> {
        for i in 0..self.offlined_count {
            if self.offlined[i].pfn == pfn {
                return Some(&self.offlined[i]);
            }
        }
        None
    }

    /// Check whether a PFN has a pending (incomplete) recovery.
    pub fn is_pending(&self, pfn: u64) -> bool {
        for i in 0..self.pending_count {
            if self.pending[i].pfn == pfn && !self.pending[i].complete {
                return true;
            }
        }
        false
    }

    /// Return notifications for a specific process ID.
    pub fn notifications_for_pid(&self, pid: u32) -> u32 {
        let mut count = 0u32;
        for i in 0..self.notification_count {
            if self.notifications[i].pid == pid {
                count += 1;
            }
        }
        count
    }

    /// Compute the total physical memory (in bytes) lost to offlining.
    pub fn offlined_bytes(&self) -> u64 {
        self.offlined_count as u64 * PAGE_SIZE
    }

    /// Return the offlined page at the given index, if valid.
    pub fn offlined_page(&self, index: usize) -> Result<&OfflinedPage> {
        if index >= self.offlined_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.offlined[index])
    }

    /// Return the notification at the given index, if valid.
    pub fn notification(&self, index: usize) -> Result<&ProcessNotification> {
        if index >= self.notification_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.notifications[index])
    }

    // ---------------------------------------------------------------
    // Batch operations
    // ---------------------------------------------------------------

    /// Process a batch of poisoned PFNs through the recovery pipeline.
    ///
    /// `pfns` is a slice of `(pfn, class)` pairs.
    /// Returns the number of pages successfully recovered (full or
    /// partial).
    pub fn recover_batch(&mut self, pfns: &[(u64, RecoverableClass)]) -> Result<u32> {
        if !self.enabled {
            return Err(Error::NotImplemented);
        }

        let mut recovered = 0u32;
        for &(pfn, class) in pfns {
            match self.recover_page(pfn, class) {
                Ok(outcome) if outcome.is_success() => {
                    recovered += 1;
                }
                _ => {}
            }
        }
        Ok(recovered)
    }

    /// Notify multiple processes about a single poisoned PFN.
    ///
    /// `affected` is a slice of `(pid, fault_addr)` pairs.
    /// Returns the number of notifications successfully queued.
    pub fn notify_batch(&mut self, pfn: u64, signal: u8, affected: &[(u32, u64)]) -> u32 {
        let limit = affected.len().min(MAX_NOTIFICATIONS_PER_EVENT);
        let mut sent = 0u32;
        for &(pid, fault_addr) in &affected[..limit] {
            if self.notify_process(pid, fault_addr, pfn, signal).is_ok() {
                sent += 1;
            }
        }
        sent
    }

    // ---------------------------------------------------------------
    // Cleanup
    // ---------------------------------------------------------------

    /// Purge completed pending entries older than `before_ts`.
    pub fn purge_completed(&mut self, before_ts: u64) {
        let mut write = 0;
        for read in 0..self.pending_count {
            let keep = !self.pending[read].complete || self.pending[read].started_at >= before_ts;
            if keep {
                self.pending[write] = self.pending[read];
                write += 1;
            }
        }
        self.pending_count = write;
    }

    /// Reset all statistics counters.
    pub fn reset_stats(&mut self) {
        self.stats = RecoveryStats::default();
    }
}
