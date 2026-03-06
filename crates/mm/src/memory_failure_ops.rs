// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory failure recovery operations.
//!
//! When a hardware memory error is detected, the `memory_failure()`
//! handler must determine the appropriate recovery action based on
//! the page type (anonymous, file-backed, free, slab, etc.). This
//! module implements the per-page-type action table and the recovery
//! logic for each category.
//!
//! # Design
//!
//! ```text
//!  memory_failure(pfn, flags)
//!     │
//!     ├─ identify page type
//!     │   ├─ free → dissolve, skip recovery
//!     │   ├─ anonymous → unmap, SIGBUS to owners
//!     │   ├─ file-backed → invalidate page cache entry
//!     │   ├─ slab → mark slab page poisoned
//!     │   └─ unknown → hard-offline
//!     ├─ apply action from action table
//!     └─ mark page HWPoison
//! ```
//!
//! # Key Types
//!
//! - [`PageType`] — classification of page by usage
//! - [`RecoveryAction`] — action for a given page type
//! - [`FailureRecord`] — a single failure event
//! - [`MemoryFailureOps`] — recovery action executor
//! - [`FailureOpsStats`] — failure statistics
//!
//! Reference: Linux `mm/memory-failure.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum failure records.
const MAX_RECORDS: usize = 2048;

/// Page size.
const PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// PageType
// -------------------------------------------------------------------

/// Classification of page by current usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageType {
    /// Free (in buddy allocator).
    Free,
    /// Anonymous (process private data).
    Anonymous,
    /// File-backed (page cache).
    FileBacked,
    /// Slab-allocated (kmalloc, kmem_cache).
    Slab,
    /// Huge page (THP or hugetlb).
    HugePage,
    /// Page table page.
    PageTable,
    /// Reserved/kernel.
    Reserved,
    /// Unknown.
    Unknown,
}

impl PageType {
    /// Return a label string.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Anonymous => "anonymous",
            Self::FileBacked => "file-backed",
            Self::Slab => "slab",
            Self::HugePage => "huge-page",
            Self::PageTable => "page-table",
            Self::Reserved => "reserved",
            Self::Unknown => "unknown",
        }
    }

    /// Check whether recovery is possible for this type.
    pub const fn recoverable(&self) -> bool {
        matches!(
            self,
            Self::Free | Self::Anonymous | Self::FileBacked | Self::HugePage
        )
    }
}

// -------------------------------------------------------------------
// RecoveryAction
// -------------------------------------------------------------------

/// Action for a given page type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    /// Dissolve free page (remove from buddy).
    Dissolve,
    /// Unmap from all processes and send SIGBUS.
    UnmapAndSignal,
    /// Invalidate page cache entry.
    Invalidate,
    /// Mark slab page as poisoned.
    MarkSlab,
    /// Hard-offline (no recovery possible).
    HardOffline,
    /// Try to migrate huge page.
    MigrateHuge,
    /// Ignore (already handled).
    Ignore,
}

impl RecoveryAction {
    /// Return a label string.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Dissolve => "dissolve",
            Self::UnmapAndSignal => "unmap+SIGBUS",
            Self::Invalidate => "invalidate",
            Self::MarkSlab => "mark-slab",
            Self::HardOffline => "hard-offline",
            Self::MigrateHuge => "migrate-huge",
            Self::Ignore => "ignore",
        }
    }

    /// Determine action for a page type.
    pub const fn for_page_type(page_type: PageType) -> Self {
        match page_type {
            PageType::Free => Self::Dissolve,
            PageType::Anonymous => Self::UnmapAndSignal,
            PageType::FileBacked => Self::Invalidate,
            PageType::Slab => Self::MarkSlab,
            PageType::HugePage => Self::MigrateHuge,
            PageType::PageTable => Self::HardOffline,
            PageType::Reserved => Self::HardOffline,
            PageType::Unknown => Self::HardOffline,
        }
    }
}

// -------------------------------------------------------------------
// FailureRecord
// -------------------------------------------------------------------

/// A single failure event record.
#[derive(Debug, Clone, Copy)]
pub struct FailureRecord {
    /// Physical frame number.
    pfn: u64,
    /// Page type at time of failure.
    page_type: PageType,
    /// Recovery action taken.
    action: RecoveryAction,
    /// Whether recovery succeeded.
    recovered: bool,
    /// Number of processes affected.
    processes_affected: u32,
    /// Timestamp.
    timestamp: u64,
}

impl FailureRecord {
    /// Create a new record.
    pub const fn new(pfn: u64, page_type: PageType, timestamp: u64) -> Self {
        Self {
            pfn,
            page_type,
            action: RecoveryAction::for_page_type(page_type),
            recovered: false,
            processes_affected: 0,
            timestamp,
        }
    }

    /// Return the PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Return the page type.
    pub const fn page_type(&self) -> PageType {
        self.page_type
    }

    /// Return the action.
    pub const fn action(&self) -> RecoveryAction {
        self.action
    }

    /// Check whether recovered.
    pub const fn recovered(&self) -> bool {
        self.recovered
    }

    /// Return processes affected.
    pub const fn processes_affected(&self) -> u32 {
        self.processes_affected
    }

    /// Return the timestamp.
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Mark as recovered.
    pub fn mark_recovered(&mut self) {
        self.recovered = true;
    }

    /// Set affected processes.
    pub fn set_processes_affected(&mut self, count: u32) {
        self.processes_affected = count;
    }
}

impl Default for FailureRecord {
    fn default() -> Self {
        Self {
            pfn: 0,
            page_type: PageType::Unknown,
            action: RecoveryAction::HardOffline,
            recovered: false,
            processes_affected: 0,
            timestamp: 0,
        }
    }
}

// -------------------------------------------------------------------
// FailureOpsStats
// -------------------------------------------------------------------

/// Failure statistics.
#[derive(Debug, Clone, Copy)]
pub struct FailureOpsStats {
    /// Total failures.
    pub total_failures: u64,
    /// Successful recoveries.
    pub recoveries: u64,
    /// Hard offlines (unrecoverable).
    pub hard_offlines: u64,
    /// Pages dissolved.
    pub dissolved: u64,
    /// Processes signaled.
    pub processes_signaled: u64,
}

impl FailureOpsStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            total_failures: 0,
            recoveries: 0,
            hard_offlines: 0,
            dissolved: 0,
            processes_signaled: 0,
        }
    }

    /// Recovery rate as percent.
    pub const fn recovery_rate_pct(&self) -> u64 {
        if self.total_failures == 0 {
            return 0;
        }
        self.recoveries * 100 / self.total_failures
    }
}

impl Default for FailureOpsStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MemoryFailureOps
// -------------------------------------------------------------------

/// Recovery action executor.
pub struct MemoryFailureOps {
    /// Failure records.
    records: [FailureRecord; MAX_RECORDS],
    /// Number of records.
    count: usize,
    /// Statistics.
    stats: FailureOpsStats,
}

impl MemoryFailureOps {
    /// Create a new executor.
    pub const fn new() -> Self {
        Self {
            records: [const {
                FailureRecord {
                    pfn: 0,
                    page_type: PageType::Unknown,
                    action: RecoveryAction::HardOffline,
                    recovered: false,
                    processes_affected: 0,
                    timestamp: 0,
                }
            }; MAX_RECORDS],
            count: 0,
            stats: FailureOpsStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &FailureOpsStats {
        &self.stats
    }

    /// Return the record count.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Handle a memory failure.
    pub fn handle_failure(
        &mut self,
        pfn: u64,
        page_type: PageType,
        timestamp: u64,
    ) -> Result<RecoveryAction> {
        if self.count >= MAX_RECORDS {
            return Err(Error::OutOfMemory);
        }
        let record = FailureRecord::new(pfn, page_type, timestamp);
        let action = record.action();
        self.records[self.count] = record;

        self.stats.total_failures += 1;
        if page_type.recoverable() {
            self.records[self.count].mark_recovered();
            self.stats.recoveries += 1;
        } else {
            self.stats.hard_offlines += 1;
        }
        if matches!(action, RecoveryAction::Dissolve) {
            self.stats.dissolved += 1;
        }
        self.count += 1;
        Ok(action)
    }

    /// Find a record by PFN.
    pub fn find(&self, pfn: u64) -> Option<&FailureRecord> {
        for idx in 0..self.count {
            if self.records[idx].pfn() == pfn {
                return Some(&self.records[idx]);
            }
        }
        None
    }

    /// Memory lost to failures (bytes).
    pub fn memory_lost_bytes(&self) -> u64 {
        self.stats.hard_offlines * PAGE_SIZE
    }
}

impl Default for MemoryFailureOps {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum records.
pub const fn max_records() -> usize {
    MAX_RECORDS
}

/// Determine recovery action for a page type.
pub const fn action_for_type(page_type: PageType) -> RecoveryAction {
    RecoveryAction::for_page_type(page_type)
}
