// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page table debugging and inspection.
//!
//! Provides tools for inspecting page table state, dumping page table
//! hierarchies, and detecting inconsistencies. Useful for debugging
//! memory corruption, verifying mapping invariants, and producing
//! human-readable summaries of the page table layout.
//!
//! # Design
//!
//! ```text
//!  PteDumpConfig
//!       │
//!       ▼
//!  PteDumper::walk(root_addr)
//!       │
//!       ├─ PML4 → enumerate entries
//!       ├─ PDPT → enumerate entries
//!       ├─ PD   → enumerate entries (detect huge pages)
//!       └─ PT   → enumerate leaf entries
//!
//!  PteChecker::verify(root_addr)
//!       └─ validate PTE flags, alignment, hierarchy
//! ```
//!
//! # Key Types
//!
//! - [`PteDumpEntry`] — a single entry in a page table dump
//! - [`PteDumper`] — page table hierarchy walker
//! - [`PteChecker`] — page table consistency checker
//! - [`PteCheckResult`] — result of a consistency check
//!
//! Reference: Linux `arch/x86/mm/dump_pagetables.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Number of entries per page table level.
const ENTRIES_PER_TABLE: usize = 512;

/// Maximum dump entries we track.
const MAX_DUMP_ENTRIES: usize = 2048;

/// Maximum check errors reported.
const MAX_CHECK_ERRORS: usize = 64;

/// PTE flag bits.
const PTE_PRESENT: u64 = 1 << 0;
const PTE_WRITABLE: u64 = 1 << 1;
const PTE_USER: u64 = 1 << 2;
const PTE_HUGE: u64 = 1 << 7;
const PTE_NX: u64 = 1 << 63;

// -------------------------------------------------------------------
// PteLevel
// -------------------------------------------------------------------

/// Page table level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PteLevel {
    /// PML4 (level 4).
    Pml4,
    /// Page Directory Pointer Table (level 3).
    Pdpt,
    /// Page Directory (level 2).
    Pd,
    /// Page Table (level 1, leaf for 4K pages).
    Pt,
}

impl PteLevel {
    /// Return the page size at this level if it is a leaf.
    pub const fn page_size(&self) -> u64 {
        match self {
            Self::Pml4 => 0,       // not a leaf
            Self::Pdpt => 1 << 30, // 1 GiB
            Self::Pd => 1 << 21,   // 2 MiB
            Self::Pt => 1 << 12,   // 4 KiB
        }
    }

    /// Return a human-readable name.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pml4 => "PML4",
            Self::Pdpt => "PDPT",
            Self::Pd => "PD",
            Self::Pt => "PT",
        }
    }
}

// -------------------------------------------------------------------
// PteDumpEntry
// -------------------------------------------------------------------

/// A single entry in a page table dump.
#[derive(Debug, Clone, Copy)]
pub struct PteDumpEntry {
    /// Virtual address range start.
    virt_start: u64,
    /// Virtual address range end.
    virt_end: u64,
    /// Physical address mapped to.
    phys_addr: u64,
    /// Raw PTE value.
    raw_pte: u64,
    /// Page table level.
    level: PteLevel,
    /// Whether this is a huge page.
    huge: bool,
}

impl PteDumpEntry {
    /// Create a new dump entry.
    pub const fn new(
        virt_start: u64,
        virt_end: u64,
        phys_addr: u64,
        raw_pte: u64,
        level: PteLevel,
    ) -> Self {
        Self {
            virt_start,
            virt_end,
            phys_addr,
            raw_pte,
            level,
            huge: false,
        }
    }

    /// Return the virtual start.
    pub const fn virt_start(&self) -> u64 {
        self.virt_start
    }

    /// Return the virtual end.
    pub const fn virt_end(&self) -> u64 {
        self.virt_end
    }

    /// Return the physical address.
    pub const fn phys_addr(&self) -> u64 {
        self.phys_addr
    }

    /// Return the raw PTE value.
    pub const fn raw_pte(&self) -> u64 {
        self.raw_pte
    }

    /// Return the level.
    pub const fn level(&self) -> PteLevel {
        self.level
    }

    /// Check whether this is a present mapping.
    pub const fn is_present(&self) -> bool {
        (self.raw_pte & PTE_PRESENT) != 0
    }

    /// Check whether writable.
    pub const fn is_writable(&self) -> bool {
        (self.raw_pte & PTE_WRITABLE) != 0
    }

    /// Check whether user-accessible.
    pub const fn is_user(&self) -> bool {
        (self.raw_pte & PTE_USER) != 0
    }

    /// Check whether no-execute.
    pub const fn is_nx(&self) -> bool {
        (self.raw_pte & PTE_NX) != 0
    }

    /// Check whether this is a huge page.
    pub const fn is_huge(&self) -> bool {
        self.huge
    }

    /// Return the mapping size in bytes.
    pub const fn size(&self) -> u64 {
        self.virt_end - self.virt_start
    }
}

impl Default for PteDumpEntry {
    fn default() -> Self {
        Self::new(0, 0, 0, 0, PteLevel::Pt)
    }
}

// -------------------------------------------------------------------
// PteDumper
// -------------------------------------------------------------------

/// Page table hierarchy dumper.
pub struct PteDumper {
    /// Collected entries.
    entries: [PteDumpEntry; MAX_DUMP_ENTRIES],
    /// Number of entries.
    count: usize,
    /// Total present entries found.
    present_count: usize,
    /// Total huge pages found.
    huge_count: usize,
}

impl PteDumper {
    /// Create a new dumper.
    pub const fn new() -> Self {
        Self {
            entries: [const { PteDumpEntry::new(0, 0, 0, 0, PteLevel::Pt) }; MAX_DUMP_ENTRIES],
            count: 0,
            present_count: 0,
            huge_count: 0,
        }
    }

    /// Return the number of entries collected.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return the number of present entries.
    pub const fn present_count(&self) -> usize {
        self.present_count
    }

    /// Return the number of huge pages.
    pub const fn huge_count(&self) -> usize {
        self.huge_count
    }

    /// Add a dump entry.
    pub fn add_entry(&mut self, entry: PteDumpEntry) -> Result<()> {
        if self.count >= MAX_DUMP_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        if entry.is_present() {
            self.present_count += 1;
        }
        if entry.is_huge() {
            self.huge_count += 1;
        }
        self.entries[self.count] = entry;
        self.count += 1;
        Ok(())
    }

    /// Get an entry by index.
    pub fn get(&self, index: usize) -> Option<&PteDumpEntry> {
        if index < self.count {
            Some(&self.entries[index])
        } else {
            None
        }
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.count = 0;
        self.present_count = 0;
        self.huge_count = 0;
    }
}

impl Default for PteDumper {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// PteCheckError
// -------------------------------------------------------------------

/// A page table consistency error.
#[derive(Debug, Clone, Copy)]
pub struct PteCheckError {
    /// Virtual address where the error was found.
    pub virt_addr: u64,
    /// The problematic PTE value.
    pub pte_value: u64,
    /// Error kind.
    pub kind: PteErrorKind,
}

/// Kind of PTE error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PteErrorKind {
    /// Physical address not aligned to page size.
    MisalignedPhys,
    /// Writable + NX on a code page.
    WritableCode,
    /// User page at a kernel-only address.
    UserInKernel,
    /// Present flag missing but other flags set.
    StaleFlags,
    /// Huge page flag at wrong level.
    InvalidHuge,
}

impl PteErrorKind {
    /// Human-readable description.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::MisalignedPhys => "misaligned physical address",
            Self::WritableCode => "writable code mapping (W+X)",
            Self::UserInKernel => "user-accessible page in kernel space",
            Self::StaleFlags => "stale flags on non-present PTE",
            Self::InvalidHuge => "huge page flag at invalid level",
        }
    }
}

// -------------------------------------------------------------------
// PteChecker
// -------------------------------------------------------------------

/// Page table consistency checker.
pub struct PteChecker {
    /// Errors found.
    errors: [PteCheckError; MAX_CHECK_ERRORS],
    /// Error count.
    error_count: usize,
    /// Total entries checked.
    checked: usize,
}

impl PteChecker {
    /// Create a new checker.
    pub const fn new() -> Self {
        Self {
            errors: [const {
                PteCheckError {
                    virt_addr: 0,
                    pte_value: 0,
                    kind: PteErrorKind::StaleFlags,
                }
            }; MAX_CHECK_ERRORS],
            error_count: 0,
            checked: 0,
        }
    }

    /// Return the number of errors.
    pub const fn error_count(&self) -> usize {
        self.error_count
    }

    /// Return the number of entries checked.
    pub const fn checked(&self) -> usize {
        self.checked
    }

    /// Check a single PTE entry.
    pub fn check_entry(&mut self, virt_addr: u64, pte: u64, level: PteLevel) {
        self.checked += 1;

        let present = (pte & PTE_PRESENT) != 0;
        let writable = (pte & PTE_WRITABLE) != 0;
        let user = (pte & PTE_USER) != 0;
        let nx = (pte & PTE_NX) != 0;
        let huge = (pte & PTE_HUGE) != 0;

        // Stale flags on non-present entries.
        if !present && pte != 0 {
            self.record_error(virt_addr, pte, PteErrorKind::StaleFlags);
        }

        if present {
            // Writable + executable (W^X violation).
            if writable && !nx {
                self.record_error(virt_addr, pte, PteErrorKind::WritableCode);
            }

            // User in kernel space (above 0xFFFF800000000000).
            if user && virt_addr >= 0xFFFF_8000_0000_0000 {
                self.record_error(virt_addr, pte, PteErrorKind::UserInKernel);
            }

            // Huge page at PML4 or PT level.
            if huge && (matches!(level, PteLevel::Pml4) || matches!(level, PteLevel::Pt)) {
                self.record_error(virt_addr, pte, PteErrorKind::InvalidHuge);
            }
        }
    }

    /// Record an error.
    fn record_error(&mut self, virt_addr: u64, pte: u64, kind: PteErrorKind) {
        if self.error_count < MAX_CHECK_ERRORS {
            self.errors[self.error_count] = PteCheckError {
                virt_addr,
                pte_value: pte,
                kind,
            };
            self.error_count += 1;
        }
    }

    /// Get an error by index.
    pub fn get_error(&self, index: usize) -> Option<&PteCheckError> {
        if index < self.error_count {
            Some(&self.errors[index])
        } else {
            None
        }
    }

    /// Check whether no errors were found.
    pub const fn is_clean(&self) -> bool {
        self.error_count == 0
    }
}

impl Default for PteChecker {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// PteCheckResult
// -------------------------------------------------------------------

/// Summary of a consistency check.
#[derive(Debug, Clone, Copy)]
pub struct PteCheckResult {
    /// Number of entries checked.
    pub checked: usize,
    /// Number of errors found.
    pub errors: usize,
    /// Whether the page tables are consistent.
    pub consistent: bool,
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Run a consistency check and return the result summary.
pub fn check_consistency(checker: &PteChecker) -> PteCheckResult {
    PteCheckResult {
        checked: checker.checked(),
        errors: checker.error_count(),
        consistent: checker.is_clean(),
    }
}

/// Format PTE flags as a human-readable string.
pub fn flags_str(pte: u64) -> &'static str {
    let present = (pte & PTE_PRESENT) != 0;
    let writable = (pte & PTE_WRITABLE) != 0;
    let user = (pte & PTE_USER) != 0;

    if !present {
        "---"
    } else if writable && user {
        "RWU"
    } else if writable {
        "RW-"
    } else if user {
        "R-U"
    } else {
        "R--"
    }
}

/// Return a summary of page table state.
pub fn dump_summary(dumper: &PteDumper) -> &'static str {
    if dumper.count() == 0 {
        "page table dump: empty"
    } else if dumper.huge_count() > 0 {
        "page table dump: has huge pages"
    } else {
        "page table dump: 4K pages only"
    }
}
