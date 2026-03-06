// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Virtual memory fault handling.
//!
//! When a process accesses a virtual address that has no valid page table
//! mapping, the CPU generates a page fault. This module provides the
//! fault classification, handling logic, and statistics tracking for
//! different fault types (minor, major, CoW, segfault).
//!
//! # Design
//!
//! ```text
//!  CPU page fault exception
//!       │
//!       ▼
//!  VmFaultHandler::handle(fault_addr, fault_flags)
//!       │
//!       ├─ address in VMA? → classify fault
//!       │     ├─ minor fault   → allocate page, map, return
//!       │     ├─ major fault   → read from disk, map, return
//!       │     ├─ CoW fault     → copy page, remap, return
//!       │     └─ prot violation→ deliver SIGSEGV
//!       │
//!       └─ not in VMA → segfault
//! ```
//!
//! # Key Types
//!
//! - [`FaultType`] — classification of the fault
//! - [`FaultFlags`] — CPU-provided fault flags
//! - [`VmFault`] — a fault descriptor
//! - [`VmFaultHandler`] — the fault handler
//! - [`FaultStats`] — fault statistics
//!
//! Reference: Linux `mm/memory.c` (`handle_mm_fault`).

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum fault history entries.
const MAX_FAULT_HISTORY: usize = 256;

/// Page size.
const PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// FaultFlags
// -------------------------------------------------------------------

/// CPU-provided fault flags.
#[derive(Debug, Clone, Copy)]
pub struct FaultFlags(u32);

impl FaultFlags {
    /// Fault was caused by a write access.
    pub const WRITE: Self = Self(1 << 0);
    /// Fault occurred in user mode.
    pub const USER: Self = Self(1 << 1);
    /// Fault was caused by an instruction fetch.
    pub const INSTRUCTION: Self = Self(1 << 2);
    /// Fault was caused by a reserved bit violation.
    pub const RESERVED: Self = Self(1 << 3);
    /// Fault was caused by a protection violation (page present).
    pub const PROTECTION: Self = Self(1 << 4);

    /// Empty flags.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Check whether a flag is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Set a flag.
    pub const fn with(self, flag: Self) -> Self {
        Self(self.0 | flag.0)
    }

    /// Return raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl Default for FaultFlags {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// FaultType
// -------------------------------------------------------------------

/// Classification of a page fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultType {
    /// Minor fault — page is in memory but not mapped.
    Minor,
    /// Major fault — page must be read from disk.
    Major,
    /// Copy-on-Write — shared page needs private copy.
    CopyOnWrite,
    /// Protection violation — access type not allowed.
    Protection,
    /// Segmentation fault — address not in any VMA.
    Segfault,
}

impl FaultType {
    /// Return a human-readable name.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Minor => "minor",
            Self::Major => "major",
            Self::CopyOnWrite => "cow",
            Self::Protection => "protection",
            Self::Segfault => "segfault",
        }
    }
}

// -------------------------------------------------------------------
// FaultResolution
// -------------------------------------------------------------------

/// How a fault was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultResolution {
    /// Page was mapped successfully.
    Mapped,
    /// Process should be killed (SIGSEGV).
    Kill,
    /// Fault should be retried (race condition).
    Retry,
    /// OOM — could not allocate a page.
    Oom,
}

// -------------------------------------------------------------------
// VmFault
// -------------------------------------------------------------------

/// A page fault descriptor.
#[derive(Debug, Clone, Copy)]
pub struct VmFault {
    /// Faulting virtual address.
    address: u64,
    /// CPU fault flags.
    flags: FaultFlags,
    /// Classified fault type.
    fault_type: FaultType,
    /// Resolution.
    resolution: FaultResolution,
    /// Process ID that caused the fault.
    pid: u32,
    /// Timestamp.
    timestamp: u64,
}

impl VmFault {
    /// Create a new fault descriptor.
    pub const fn new(address: u64, flags: FaultFlags, pid: u32, timestamp: u64) -> Self {
        Self {
            address,
            flags,
            fault_type: FaultType::Minor,
            resolution: FaultResolution::Mapped,
            pid,
            timestamp,
        }
    }

    /// Return the faulting address.
    pub const fn address(&self) -> u64 {
        self.address
    }

    /// Return the page-aligned address.
    pub const fn page_address(&self) -> u64 {
        self.address & !(PAGE_SIZE - 1)
    }

    /// Return the fault flags.
    pub const fn flags(&self) -> FaultFlags {
        self.flags
    }

    /// Return the fault type.
    pub const fn fault_type(&self) -> FaultType {
        self.fault_type
    }

    /// Set the fault type.
    pub fn set_fault_type(&mut self, ft: FaultType) {
        self.fault_type = ft;
    }

    /// Return the resolution.
    pub const fn resolution(&self) -> FaultResolution {
        self.resolution
    }

    /// Set the resolution.
    pub fn set_resolution(&mut self, res: FaultResolution) {
        self.resolution = res;
    }

    /// Return the PID.
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Check whether this was a write fault.
    pub const fn is_write(&self) -> bool {
        self.flags.contains(FaultFlags::WRITE)
    }

    /// Check whether this was a user-mode fault.
    pub const fn is_user(&self) -> bool {
        self.flags.contains(FaultFlags::USER)
    }
}

impl Default for VmFault {
    fn default() -> Self {
        Self::new(0, FaultFlags::empty(), 0, 0)
    }
}

// -------------------------------------------------------------------
// FaultStats
// -------------------------------------------------------------------

/// Fault statistics.
#[derive(Debug, Clone, Copy)]
pub struct FaultStats {
    /// Total faults.
    pub total: u64,
    /// Minor faults.
    pub minor: u64,
    /// Major faults.
    pub major: u64,
    /// CoW faults.
    pub cow: u64,
    /// Protection violations.
    pub protection: u64,
    /// Segfaults.
    pub segfault: u64,
}

impl FaultStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            total: 0,
            minor: 0,
            major: 0,
            cow: 0,
            protection: 0,
            segfault: 0,
        }
    }

    /// Record a fault.
    pub fn record(&mut self, fault_type: FaultType) {
        self.total += 1;
        match fault_type {
            FaultType::Minor => self.minor += 1,
            FaultType::Major => self.major += 1,
            FaultType::CopyOnWrite => self.cow += 1,
            FaultType::Protection => self.protection += 1,
            FaultType::Segfault => self.segfault += 1,
        }
    }

    /// Return the minor/major ratio.
    pub const fn minor_ratio(&self) -> u64 {
        if self.total == 0 {
            return 0;
        }
        self.minor * 100 / self.total
    }
}

impl Default for FaultStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// VmFaultHandler
// -------------------------------------------------------------------

/// Page fault handler.
pub struct VmFaultHandler {
    /// Fault history.
    history: [VmFault; MAX_FAULT_HISTORY],
    /// Number of recorded faults.
    history_count: usize,
    /// Statistics.
    stats: FaultStats,
    /// Timestamp counter.
    timestamp: u64,
}

impl VmFaultHandler {
    /// Create a new handler.
    pub const fn new() -> Self {
        Self {
            history: [const { VmFault::new(0, FaultFlags::empty(), 0, 0) }; MAX_FAULT_HISTORY],
            history_count: 0,
            stats: FaultStats::new(),
            timestamp: 0,
        }
    }

    /// Return fault statistics.
    pub const fn stats(&self) -> &FaultStats {
        &self.stats
    }

    /// Return history count.
    pub const fn history_count(&self) -> usize {
        self.history_count
    }

    /// Classify a fault based on flags and VMA presence.
    pub fn classify(
        &self,
        flags: FaultFlags,
        in_vma: bool,
        page_present: bool,
        cow_page: bool,
    ) -> FaultType {
        if !in_vma {
            return FaultType::Segfault;
        }
        if flags.contains(FaultFlags::PROTECTION) {
            if cow_page && flags.contains(FaultFlags::WRITE) {
                return FaultType::CopyOnWrite;
            }
            return FaultType::Protection;
        }
        if page_present {
            FaultType::Minor
        } else {
            FaultType::Major
        }
    }

    /// Handle a page fault.
    pub fn handle(
        &mut self,
        address: u64,
        flags: FaultFlags,
        pid: u32,
        in_vma: bool,
        page_present: bool,
        cow_page: bool,
    ) -> VmFault {
        self.timestamp += 1;
        let fault_type = self.classify(flags, in_vma, page_present, cow_page);

        let resolution = match fault_type {
            FaultType::Minor | FaultType::Major | FaultType::CopyOnWrite => FaultResolution::Mapped,
            FaultType::Protection | FaultType::Segfault => FaultResolution::Kill,
        };

        let mut fault = VmFault::new(address, flags, pid, self.timestamp);
        fault.set_fault_type(fault_type);
        fault.set_resolution(resolution);

        self.stats.record(fault_type);

        if self.history_count < MAX_FAULT_HISTORY {
            self.history[self.history_count] = fault;
            self.history_count += 1;
        }

        fault
    }

    /// Get a fault from history.
    pub fn get_history(&self, index: usize) -> Option<&VmFault> {
        if index < self.history_count {
            Some(&self.history[index])
        } else {
            None
        }
    }
}

impl Default for VmFaultHandler {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Handle a simple user-mode read fault.
pub fn handle_user_read_fault(
    handler: &mut VmFaultHandler,
    address: u64,
    pid: u32,
    in_vma: bool,
) -> FaultResolution {
    let flags = FaultFlags::USER;
    let fault = handler.handle(address, flags, pid, in_vma, false, false);
    fault.resolution()
}

/// Handle a user-mode write fault (possible CoW).
pub fn handle_user_write_fault(
    handler: &mut VmFaultHandler,
    address: u64,
    pid: u32,
    in_vma: bool,
    cow: bool,
) -> FaultResolution {
    let flags = FaultFlags::USER.with(FaultFlags::WRITE);
    let prot = if cow {
        FaultFlags::USER
            .with(FaultFlags::WRITE)
            .with(FaultFlags::PROTECTION)
    } else {
        flags
    };
    let fault = handler.handle(address, prot, pid, in_vma, true, cow);
    fault.resolution()
}

/// Return a summary of fault statistics.
pub fn fault_summary(stats: &FaultStats) -> &'static str {
    if stats.total == 0 {
        "vm faults: none"
    } else if stats.segfault > 0 {
        "vm faults: segfaults detected"
    } else if stats.major > stats.minor {
        "vm faults: IO-heavy (major > minor)"
    } else {
        "vm faults: healthy (minor dominant)"
    }
}
