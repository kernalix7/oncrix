// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Mmap fault handler.
//!
//! When a user accesses an mmap'd region for which no page table entry
//! exists (or the entry has been invalidated), the CPU raises a page
//! fault. This module dispatches mmap page faults to the appropriate
//! handler based on the VMA type: anonymous fault (zero-fill), file
//! fault (read from backing store), CoW fault, or shared fault.
//!
//! # Design
//!
//! ```text
//!  #PF(fault_addr, error_code)
//!       │
//!       ├─ find VMA containing fault_addr
//!       │   └─ not found → SIGSEGV
//!       │
//!       ├─ PTE not present:
//!       │   ├─ anonymous VMA → alloc zero page, map
//!       │   └─ file VMA     → read page from file, map
//!       │
//!       ├─ PTE present, write fault:
//!       │   ├─ CoW page → break CoW, copy, remap writable
//!       │   └─ shared   → mark dirty, allow write
//!       │
//!       └─ PTE present, permission fault → SIGSEGV
//! ```
//!
//! # Key Types
//!
//! - [`FaultType`] — classification of the fault
//! - [`FaultInfo`] — information about a page fault
//! - [`FaultResult`] — outcome of fault handling
//! - [`MmapFaultHandler`] — the fault dispatcher
//!
//! Reference: Linux `mm/memory.c` (handle_mm_fault), `mm/filemap.c`.

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size.
const PAGE_SIZE: u64 = 4096;

/// Error code bit: write access.
const FAULT_WRITE: u32 = 1 << 0;
/// Error code bit: user-mode access.
const FAULT_USER: u32 = 1 << 1;
/// Error code bit: page not present.
const FAULT_NOT_PRESENT: u32 = 1 << 2;
/// Error code bit: instruction fetch.
const FAULT_FETCH: u32 = 1 << 3;

/// Maximum fault log entries.
const MAX_FAULT_LOG: usize = 256;

// -------------------------------------------------------------------
// FaultType
// -------------------------------------------------------------------

/// Classification of the page fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultType {
    /// Anonymous page fault (zero-fill on demand).
    Anonymous,
    /// File-backed page fault (read from file).
    FileBacked,
    /// Copy-on-Write fault.
    CopyOnWrite,
    /// Shared page fault (mark dirty).
    Shared,
    /// Permission violation (signal SIGSEGV).
    PermissionViolation,
    /// Address not in any VMA (signal SIGSEGV).
    InvalidAddress,
}

impl FaultType {
    /// Return a label.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::FileBacked => "file_backed",
            Self::CopyOnWrite => "cow",
            Self::Shared => "shared",
            Self::PermissionViolation => "permission",
            Self::InvalidAddress => "invalid_addr",
        }
    }

    /// Check whether the fault is resolvable (not a signal).
    pub const fn is_resolvable(&self) -> bool {
        matches!(
            self,
            Self::Anonymous | Self::FileBacked | Self::CopyOnWrite | Self::Shared
        )
    }
}

// -------------------------------------------------------------------
// FaultInfo
// -------------------------------------------------------------------

/// Information about a page fault.
#[derive(Debug, Clone, Copy)]
pub struct FaultInfo {
    /// Faulting virtual address.
    fault_addr: u64,
    /// Error code from hardware.
    error_code: u32,
    /// Process ID.
    pid: u64,
    /// Whether this is a write fault.
    is_write: bool,
    /// Whether this is a user-mode fault.
    is_user: bool,
    /// Whether the page was not present.
    not_present: bool,
}

impl FaultInfo {
    /// Create from a fault address and error code.
    pub const fn new(fault_addr: u64, error_code: u32, pid: u64) -> Self {
        Self {
            fault_addr,
            error_code,
            pid,
            is_write: error_code & FAULT_WRITE != 0,
            is_user: error_code & FAULT_USER != 0,
            not_present: error_code & FAULT_NOT_PRESENT != 0,
        }
    }

    /// Return the faulting address.
    pub const fn fault_addr(&self) -> u64 {
        self.fault_addr
    }

    /// Return the page-aligned fault address.
    pub const fn page_addr(&self) -> u64 {
        self.fault_addr & !(PAGE_SIZE - 1)
    }

    /// Return the error code.
    pub const fn error_code(&self) -> u32 {
        self.error_code
    }

    /// Return the PID.
    pub const fn pid(&self) -> u64 {
        self.pid
    }

    /// Check whether this is a write fault.
    pub const fn is_write(&self) -> bool {
        self.is_write
    }

    /// Check whether this is a user-mode fault.
    pub const fn is_user(&self) -> bool {
        self.is_user
    }

    /// Check whether the page was not present.
    pub const fn not_present(&self) -> bool {
        self.not_present
    }

    /// Check whether this is an instruction fetch fault.
    pub const fn is_fetch(&self) -> bool {
        self.error_code & FAULT_FETCH != 0
    }
}

impl Default for FaultInfo {
    fn default() -> Self {
        Self {
            fault_addr: 0,
            error_code: 0,
            pid: 0,
            is_write: false,
            is_user: false,
            not_present: false,
        }
    }
}

// -------------------------------------------------------------------
// FaultResult
// -------------------------------------------------------------------

/// Outcome of fault handling.
#[derive(Debug, Clone, Copy)]
pub struct FaultResult {
    /// The type of fault that was handled.
    fault_type: FaultType,
    /// The PFN that was mapped (0 if signal).
    mapped_pfn: u64,
    /// Whether the fault was resolved.
    resolved: bool,
}

impl FaultResult {
    /// Create a resolved result.
    pub const fn resolved(fault_type: FaultType, pfn: u64) -> Self {
        Self {
            fault_type,
            mapped_pfn: pfn,
            resolved: true,
        }
    }

    /// Create an unresolved result (signal).
    pub const fn signal(fault_type: FaultType) -> Self {
        Self {
            fault_type,
            mapped_pfn: 0,
            resolved: false,
        }
    }

    /// Return the fault type.
    pub const fn fault_type(&self) -> FaultType {
        self.fault_type
    }

    /// Return the mapped PFN.
    pub const fn mapped_pfn(&self) -> u64 {
        self.mapped_pfn
    }

    /// Check whether the fault was resolved.
    pub const fn is_resolved(&self) -> bool {
        self.resolved
    }
}

impl Default for FaultResult {
    fn default() -> Self {
        Self::signal(FaultType::InvalidAddress)
    }
}

// -------------------------------------------------------------------
// FaultStats
// -------------------------------------------------------------------

/// Fault handling statistics.
#[derive(Debug, Clone, Copy)]
pub struct FaultStats {
    /// Total faults handled.
    pub total: u64,
    /// Anonymous faults.
    pub anonymous: u64,
    /// File-backed faults.
    pub file_backed: u64,
    /// CoW faults.
    pub cow: u64,
    /// Shared faults.
    pub shared: u64,
    /// Permission violations.
    pub permission: u64,
    /// Invalid address faults.
    pub invalid: u64,
}

impl FaultStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            total: 0,
            anonymous: 0,
            file_backed: 0,
            cow: 0,
            shared: 0,
            permission: 0,
            invalid: 0,
        }
    }

    /// Record a fault of a given type.
    pub fn record(&mut self, ft: FaultType) {
        self.total += 1;
        match ft {
            FaultType::Anonymous => self.anonymous += 1,
            FaultType::FileBacked => self.file_backed += 1,
            FaultType::CopyOnWrite => self.cow += 1,
            FaultType::Shared => self.shared += 1,
            FaultType::PermissionViolation => self.permission += 1,
            FaultType::InvalidAddress => self.invalid += 1,
        }
    }
}

impl Default for FaultStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MmapFaultHandler
// -------------------------------------------------------------------

/// The mmap page fault dispatcher.
pub struct MmapFaultHandler {
    /// Fault log.
    log: [FaultInfo; MAX_FAULT_LOG],
    /// Log write position.
    log_pos: usize,
    /// Statistics.
    stats: FaultStats,
}

impl MmapFaultHandler {
    /// Create a new fault handler.
    pub const fn new() -> Self {
        Self {
            log: [const {
                FaultInfo {
                    fault_addr: 0,
                    error_code: 0,
                    pid: 0,
                    is_write: false,
                    is_user: false,
                    not_present: false,
                }
            }; MAX_FAULT_LOG],
            log_pos: 0,
            stats: FaultStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &FaultStats {
        &self.stats
    }

    /// Handle a page fault.
    pub fn handle(&mut self, info: FaultInfo) -> FaultResult {
        // Log the fault.
        self.log[self.log_pos % MAX_FAULT_LOG] = info;
        self.log_pos += 1;

        // Classify the fault (simplified dispatch).
        let fault_type = self.classify(&info);
        self.stats.record(fault_type);

        if fault_type.is_resolvable() {
            let pfn = info.page_addr() / PAGE_SIZE;
            FaultResult::resolved(fault_type, pfn)
        } else {
            FaultResult::signal(fault_type)
        }
    }

    /// Classify a fault based on its info.
    fn classify(&self, info: &FaultInfo) -> FaultType {
        if info.fault_addr() == 0 {
            return FaultType::InvalidAddress;
        }
        if info.not_present() {
            return FaultType::Anonymous;
        }
        if info.is_write() {
            return FaultType::CopyOnWrite;
        }
        FaultType::PermissionViolation
    }

    /// Return the number of logged faults.
    pub const fn log_count(&self) -> usize {
        self.log_pos
    }
}

impl Default for MmapFaultHandler {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Create a fault info from raw parameters.
pub const fn make_fault_info(addr: u64, code: u32, pid: u64) -> FaultInfo {
    FaultInfo::new(addr, code, pid)
}

/// Return the write-fault error code flag.
pub const fn fault_write_flag() -> u32 {
    FAULT_WRITE
}

/// Return the user-mode error code flag.
pub const fn fault_user_flag() -> u32 {
    FAULT_USER
}

/// Return the not-present error code flag.
pub const fn fault_not_present_flag() -> u32 {
    FAULT_NOT_PRESENT
}
