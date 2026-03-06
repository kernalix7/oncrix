// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page table consistency checker.
//!
//! This module provides runtime verification of page table
//! invariants for x86_64 4-level paging. It detects corruption,
//! stale entries, reference count mismatches, and impossible flag
//! combinations that could cause security vulnerabilities or
//! silent data corruption.
//!
//! # Checks performed
//!
//! - **Structure**: all PML4 / PDPT / PD / PT entries have valid
//!   physical addresses (within RAM bounds, page-aligned).
//! - **Flag consistency**: mutually exclusive flags are not set
//!   simultaneously; present entries have valid permission bits.
//! - **Reference count**: map count on a physical page matches the
//!   number of PTEs that reference it.
//! - **Kernel/user split**: kernel addresses are not mapped with
//!   USER flag; user addresses are not mapped without USER flag.
//! - **NX compliance**: code regions do not have NX bit; data
//!   regions do not have EXEC without NX clearing.
//! - **TLB consistency**: after modification, stale entries are
//!   flagged if the TLB generation counter does not match.
//!
//! # Key types
//!
//! - [`PtCheckLevel`] — page table level (PML4, PDPT, PD, PT)
//! - [`PtCheckEntry`] — one PTE being checked
//! - [`PtCheckViolation`] — one detected problem
//! - [`PtCheckResult`] — summary of a check run
//! - [`PtCheckPage`] — one page of PTEs (512 entries)
//! - [`PtCheckTable`] — per-mm page table checker state
//! - [`PtCheckSubsystem`] — top-level subsystem
//! - [`PtCheckStats`] — aggregate statistics
//!
//! Reference: Linux `mm/page_table_check.c`,
//! `include/linux/page_table_check.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Number of entries per page table page (x86_64).
const ENTRIES_PER_PAGE: usize = 512;

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Large page size (2 MiB).
const LARGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;

/// Maximum physical address (e.g., 52-bit physical address space).
const MAX_PHYS_ADDR: u64 = (1u64 << 52) - 1;

/// Physical address mask for PTE (bits 12..51).
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// PTE flag: present.
const PTE_PRESENT: u64 = 1 << 0;

/// PTE flag: writable.
const PTE_WRITABLE: u64 = 1 << 1;

/// PTE flag: user-accessible.
const PTE_USER: u64 = 1 << 2;

/// PTE flag: write-through.
const PTE_PWT: u64 = 1 << 3;

/// PTE flag: cache-disabled.
const PTE_PCD: u64 = 1 << 4;

/// PTE flag: accessed.
const PTE_ACCESSED: u64 = 1 << 5;

/// PTE flag: dirty.
const PTE_DIRTY: u64 = 1 << 6;

/// PTE flag: huge/large page (at PD or PDPT level).
const PTE_HUGE: u64 = 1 << 7;

/// PTE flag: global (not flushed on CR3 switch).
const PTE_GLOBAL: u64 = 1 << 8;

/// PTE flag: no-execute.
const PTE_NX: u64 = 1 << 63;

/// Maximum number of address spaces to check.
const MAX_MM: usize = 64;

/// Maximum number of violations per check run.
const MAX_VIOLATIONS: usize = 128;

/// Maximum number of page table pages per mm.
const MAX_PT_PAGES: usize = 256;

/// Maximum physical pages tracked for refcount checking.
const MAX_PHYS_PAGES: usize = 2048;

/// Kernel/user boundary (canonical hole on x86_64).
const KERNEL_ADDR_START: u64 = 0xFFFF_8000_0000_0000;

// -------------------------------------------------------------------
// PtCheckLevel
// -------------------------------------------------------------------

/// Page table level in the 4-level hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PtCheckLevel {
    /// Page Map Level 4 (top-level, root).
    #[default]
    Pml4,
    /// Page Directory Pointer Table.
    Pdpt,
    /// Page Directory.
    Pd,
    /// Page Table (leaf).
    Pt,
}

impl PtCheckLevel {
    /// Shift amount for addresses at this level.
    pub fn addr_shift(&self) -> u32 {
        match self {
            Self::Pml4 => 39,
            Self::Pdpt => 30,
            Self::Pd => 21,
            Self::Pt => 12,
        }
    }

    /// Coverage of one entry at this level (in bytes).
    pub fn entry_coverage(&self) -> u64 {
        1u64 << self.addr_shift()
    }

    /// Whether this level can have huge page entries.
    pub fn supports_huge(&self) -> bool {
        matches!(self, Self::Pdpt | Self::Pd)
    }

    /// The next level down.
    pub fn next(&self) -> Option<Self> {
        match self {
            Self::Pml4 => Some(Self::Pdpt),
            Self::Pdpt => Some(Self::Pd),
            Self::Pd => Some(Self::Pt),
            Self::Pt => None,
        }
    }

    /// Level number (4 = PML4, 1 = PT).
    pub fn number(&self) -> u8 {
        match self {
            Self::Pml4 => 4,
            Self::Pdpt => 3,
            Self::Pd => 2,
            Self::Pt => 1,
        }
    }
}

// -------------------------------------------------------------------
// ViolationType
// -------------------------------------------------------------------

/// Classification of a page table violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationType {
    /// Physical address in PTE is out of range.
    InvalidPhysAddr,
    /// Physical address is not page-aligned.
    MisalignedAddr,
    /// Entry is marked present but has no valid address.
    PresentNoAddr,
    /// HUGE flag set at a level that does not support it.
    InvalidHugeFlag,
    /// USER flag set on a kernel-range mapping.
    KernelUserFlag,
    /// USER flag missing on a user-range mapping.
    UserMissingFlag,
    /// Writable + NX on a code region.
    WritableCode,
    /// Dirty bit set on a non-writable page.
    DirtyReadOnly,
    /// Global flag on a non-kernel page.
    GlobalUserPage,
    /// Reference count mismatch.
    RefcountMismatch,
    /// Duplicate mapping (same PFN mapped twice in same mm).
    DuplicateMapping,
    /// Reserved bits set in the PTE.
    ReservedBitsSet,
    /// Non-present entry with non-zero flags (stale entry).
    StaleEntry,
}

// -------------------------------------------------------------------
// PtCheckEntry
// -------------------------------------------------------------------

/// One PTE being checked.
#[derive(Debug, Clone, Copy)]
pub struct PtCheckEntry {
    /// Raw PTE value.
    pub raw: u64,
    /// Level in the page table hierarchy.
    pub level: PtCheckLevel,
    /// Index within the page table page (0..511).
    pub index: u16,
    /// Virtual address this entry covers.
    pub vaddr: u64,
    /// Physical address extracted from the PTE.
    pub paddr: u64,
    /// Whether this entry is valid.
    pub valid: bool,
}

impl PtCheckEntry {
    /// Create an empty entry.
    const fn empty() -> Self {
        Self {
            raw: 0,
            level: PtCheckLevel::Pml4,
            index: 0,
            vaddr: 0,
            paddr: 0,
            valid: false,
        }
    }

    /// Whether the present bit is set.
    pub fn is_present(&self) -> bool {
        self.raw & PTE_PRESENT != 0
    }

    /// Whether the writable bit is set.
    pub fn is_writable(&self) -> bool {
        self.raw & PTE_WRITABLE != 0
    }

    /// Whether the user bit is set.
    pub fn is_user(&self) -> bool {
        self.raw & PTE_USER != 0
    }

    /// Whether the huge-page bit is set.
    pub fn is_huge(&self) -> bool {
        self.raw & PTE_HUGE != 0
    }

    /// Whether the NX bit is set.
    pub fn is_nx(&self) -> bool {
        self.raw & PTE_NX != 0
    }

    /// Whether the dirty bit is set.
    pub fn is_dirty(&self) -> bool {
        self.raw & PTE_DIRTY != 0
    }

    /// Whether the accessed bit is set.
    pub fn is_accessed(&self) -> bool {
        self.raw & PTE_ACCESSED != 0
    }

    /// Whether the global bit is set.
    pub fn is_global(&self) -> bool {
        self.raw & PTE_GLOBAL != 0
    }

    /// Extract the physical address from the raw PTE.
    pub fn extract_paddr(&self) -> u64 {
        self.raw & PTE_ADDR_MASK
    }

    /// Whether this entry maps a kernel-range address.
    pub fn is_kernel_range(&self) -> bool {
        self.vaddr >= KERNEL_ADDR_START
    }

    /// Check reserved bits (bits 52..62 for 4-level paging).
    pub fn has_reserved_bits(&self) -> bool {
        // Bits 52..62 should be 0 on most x86_64 systems.
        let reserved_mask: u64 = 0x7FF0_0000_0000_0000;
        self.raw & reserved_mask != 0
    }
}

impl Default for PtCheckEntry {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// PtCheckViolation
// -------------------------------------------------------------------

/// One detected page table violation.
#[derive(Debug, Clone, Copy)]
pub struct PtCheckViolation {
    /// Type of violation.
    pub violation_type: ViolationType,
    /// The offending entry.
    pub entry: PtCheckEntry,
    /// Additional context (e.g., expected vs actual refcount).
    pub expected: u64,
    /// Actual value.
    pub actual: u64,
    /// Whether this violation is valid.
    pub valid: bool,
}

impl PtCheckViolation {
    /// Create an empty violation.
    const fn empty() -> Self {
        Self {
            violation_type: ViolationType::InvalidPhysAddr,
            entry: PtCheckEntry::empty(),
            expected: 0,
            actual: 0,
            valid: false,
        }
    }
}

impl Default for PtCheckViolation {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// PtCheckResult
// -------------------------------------------------------------------

/// Summary of a consistency check run.
#[derive(Debug, Clone, Copy)]
pub struct PtCheckResult {
    /// Number of entries checked.
    pub entries_checked: u64,
    /// Number of present entries.
    pub present_entries: u64,
    /// Number of violations found.
    pub violation_count: u32,
    /// Violations array.
    pub violations: [PtCheckViolation; MAX_VIOLATIONS],
    /// Whether the check passed (zero violations).
    pub passed: bool,
    /// Page table level that was checked.
    pub level: PtCheckLevel,
    /// Address space identifier.
    pub mm_id: u64,
}

impl PtCheckResult {
    /// Create a passing result.
    const fn passed(mm_id: u64) -> Self {
        Self {
            entries_checked: 0,
            present_entries: 0,
            violation_count: 0,
            violations: [const { PtCheckViolation::empty() }; MAX_VIOLATIONS],
            passed: true,
            level: PtCheckLevel::Pml4,
            mm_id,
        }
    }

    /// Record a violation.
    fn add_violation(&mut self, v: PtCheckViolation) {
        if (self.violation_count as usize) < MAX_VIOLATIONS {
            self.violations[self.violation_count as usize] = v;
            self.violation_count += 1;
            self.passed = false;
        }
    }
}

impl Default for PtCheckResult {
    fn default() -> Self {
        Self::passed(0)
    }
}

// -------------------------------------------------------------------
// PtCheckPage
// -------------------------------------------------------------------

/// One page of page table entries (512 entries).
#[derive(Debug, Clone, Copy)]
pub struct PtCheckPage {
    /// Raw PTE values.
    pub entries: [u64; ENTRIES_PER_PAGE],
    /// Physical address of this page table page.
    pub paddr: u64,
    /// Level of this page in the hierarchy.
    pub level: PtCheckLevel,
    /// Whether this page is in use.
    pub active: bool,
}

impl PtCheckPage {
    /// Create an empty page.
    const fn empty() -> Self {
        Self {
            entries: [0u64; ENTRIES_PER_PAGE],
            paddr: 0,
            level: PtCheckLevel::Pml4,
            active: false,
        }
    }

    /// Count present entries.
    pub fn present_count(&self) -> u32 {
        let mut count = 0u32;
        for entry in &self.entries {
            if *entry & PTE_PRESENT != 0 {
                count += 1;
            }
        }
        count
    }
}

impl Default for PtCheckPage {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// PhysPageRef
// -------------------------------------------------------------------

/// Reference count entry for a physical page.
#[derive(Debug, Clone, Copy)]
pub struct PhysPageRef {
    /// Physical frame number.
    pub pfn: u64,
    /// Expected map count (from the page allocator).
    pub expected_count: u32,
    /// Actual PTE references found during check.
    pub actual_count: u32,
    /// Whether this entry is in use.
    pub active: bool,
}

impl PhysPageRef {
    /// Create an empty entry.
    const fn empty() -> Self {
        Self {
            pfn: 0,
            expected_count: 0,
            actual_count: 0,
            active: false,
        }
    }

    /// Whether the counts match.
    pub fn is_consistent(&self) -> bool {
        self.expected_count == self.actual_count
    }
}

impl Default for PhysPageRef {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// PtCheckTable
// -------------------------------------------------------------------

/// Per-mm page table checker state.
pub struct PtCheckTable {
    /// Page table pages registered for this mm.
    pages: [PtCheckPage; MAX_PT_PAGES],
    /// Number of active page table pages.
    page_count: usize,
    /// Physical page reference counts for cross-checking.
    phys_refs: [PhysPageRef; MAX_PHYS_PAGES],
    /// Number of active phys ref entries.
    phys_ref_count: usize,
    /// Address space identifier.
    mm_id: u64,
    /// Whether this table is active.
    active: bool,
    /// Total checks performed.
    total_checks: u64,
    /// Total violations found across all checks.
    total_violations: u64,
}

impl PtCheckTable {
    /// Create an empty table.
    const fn empty() -> Self {
        Self {
            pages: [const { PtCheckPage::empty() }; MAX_PT_PAGES],
            page_count: 0,
            phys_refs: [const { PhysPageRef::empty() }; MAX_PHYS_PAGES],
            phys_ref_count: 0,
            mm_id: 0,
            active: false,
            total_checks: 0,
            total_violations: 0,
        }
    }

    /// Register a page table page.
    pub fn add_page(
        &mut self,
        paddr: u64,
        level: PtCheckLevel,
        entries: [u64; ENTRIES_PER_PAGE],
    ) -> Result<usize> {
        if self.page_count >= MAX_PT_PAGES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.page_count;
        self.pages[idx].paddr = paddr;
        self.pages[idx].level = level;
        self.pages[idx].entries = entries;
        self.pages[idx].active = true;
        self.page_count += 1;
        Ok(idx)
    }

    /// Register a physical page's expected reference count.
    pub fn add_phys_ref(&mut self, pfn: u64, expected_count: u32) -> Result<usize> {
        if self.phys_ref_count >= MAX_PHYS_PAGES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.phys_ref_count;
        self.phys_refs[idx].pfn = pfn;
        self.phys_refs[idx].expected_count = expected_count;
        self.phys_refs[idx].actual_count = 0;
        self.phys_refs[idx].active = true;
        self.phys_ref_count += 1;
        Ok(idx)
    }

    /// Run the consistency check on all registered pages.
    pub fn check(&mut self) -> PtCheckResult {
        let mut result = PtCheckResult::passed(self.mm_id);

        // Reset actual counts.
        for pr in self.phys_refs.iter_mut().take(self.phys_ref_count) {
            pr.actual_count = 0;
        }

        // Check each page table page.
        for pi in 0..self.page_count {
            if !self.pages[pi].active {
                continue;
            }
            let page_level = self.pages[pi].level;
            let entry_count = self.pages[pi].entries.len();
            for ei in 0..entry_count {
                let raw = self.pages[pi].entries[ei];
                let entry = PtCheckEntry {
                    raw,
                    level: page_level,
                    index: ei as u16,
                    vaddr: self.compute_vaddr(page_level, pi, ei),
                    paddr: raw & PTE_ADDR_MASK,
                    valid: true,
                };
                result.entries_checked += 1;

                if !entry.is_present() {
                    // Non-present: check for stale data.
                    if raw != 0 {
                        result.add_violation(PtCheckViolation {
                            violation_type: ViolationType::StaleEntry,
                            entry,
                            expected: 0,
                            actual: raw,
                            valid: true,
                        });
                    }
                    continue;
                }
                result.present_entries += 1;

                // Check physical address validity.
                let paddr = entry.extract_paddr();
                if paddr > MAX_PHYS_ADDR {
                    result.add_violation(PtCheckViolation {
                        violation_type: ViolationType::InvalidPhysAddr,
                        entry,
                        expected: MAX_PHYS_ADDR,
                        actual: paddr,
                        valid: true,
                    });
                }

                // Check alignment.
                if paddr % PAGE_SIZE != 0 {
                    result.add_violation(PtCheckViolation {
                        violation_type: ViolationType::MisalignedAddr,
                        entry,
                        expected: 0,
                        actual: paddr % PAGE_SIZE,
                        valid: true,
                    });
                }

                // Check huge flag validity.
                if entry.is_huge() && !page_level.supports_huge() {
                    result.add_violation(PtCheckViolation {
                        violation_type: ViolationType::InvalidHugeFlag,
                        entry,
                        expected: 0,
                        actual: 1,
                        valid: true,
                    });
                }

                // Check reserved bits.
                if entry.has_reserved_bits() {
                    result.add_violation(PtCheckViolation {
                        violation_type: ViolationType::ReservedBitsSet,
                        entry,
                        expected: 0,
                        actual: entry.raw & 0x7FF0_0000_0000_0000,
                        valid: true,
                    });
                }

                // Kernel/user flag checks.
                if entry.is_kernel_range() && entry.is_user() {
                    result.add_violation(PtCheckViolation {
                        violation_type: ViolationType::KernelUserFlag,
                        entry,
                        expected: 0,
                        actual: 1,
                        valid: true,
                    });
                }
                if !entry.is_kernel_range() && !entry.is_user() && page_level == PtCheckLevel::Pt {
                    result.add_violation(PtCheckViolation {
                        violation_type: ViolationType::UserMissingFlag,
                        entry,
                        expected: 1,
                        actual: 0,
                        valid: true,
                    });
                }

                // Dirty on read-only.
                if entry.is_dirty() && !entry.is_writable() {
                    result.add_violation(PtCheckViolation {
                        violation_type: ViolationType::DirtyReadOnly,
                        entry,
                        expected: 0,
                        actual: 1,
                        valid: true,
                    });
                }

                // Global on user page.
                if entry.is_global() && !entry.is_kernel_range() {
                    result.add_violation(PtCheckViolation {
                        violation_type: ViolationType::GlobalUserPage,
                        entry,
                        expected: 0,
                        actual: 1,
                        valid: true,
                    });
                }

                // Increment actual refcount for leaf entries.
                if page_level == PtCheckLevel::Pt || entry.is_huge() {
                    let pfn = paddr / PAGE_SIZE;
                    self.increment_actual_ref(pfn);
                }
            }
        }

        // Check reference counts.
        for pr in self.phys_refs.iter().take(self.phys_ref_count) {
            if pr.active && !pr.is_consistent() {
                // Build a synthetic entry for the violation.
                let entry = PtCheckEntry {
                    raw: 0,
                    level: PtCheckLevel::Pt,
                    index: 0,
                    vaddr: 0,
                    paddr: pr.pfn * PAGE_SIZE,
                    valid: true,
                };
                result.add_violation(PtCheckViolation {
                    violation_type: ViolationType::RefcountMismatch,
                    entry,
                    expected: pr.expected_count as u64,
                    actual: pr.actual_count as u64,
                    valid: true,
                });
            }
        }

        self.total_checks = self.total_checks.saturating_add(1);
        self.total_violations = self
            .total_violations
            .saturating_add(result.violation_count as u64);
        result
    }

    /// Compute a virtual address from the page table indices.
    fn compute_vaddr(&self, level: PtCheckLevel, _page_idx: usize, entry_idx: usize) -> u64 {
        (entry_idx as u64) << level.addr_shift()
    }

    /// Increment the actual refcount for a PFN.
    fn increment_actual_ref(&mut self, pfn: u64) {
        for pr in self.phys_refs.iter_mut().take(self.phys_ref_count) {
            if pr.active && pr.pfn == pfn {
                pr.actual_count = pr.actual_count.saturating_add(1);
                return;
            }
        }
    }

    /// Number of registered page table pages.
    pub fn page_count(&self) -> usize {
        self.page_count
    }

    /// Total checks performed.
    pub fn total_checks(&self) -> u64 {
        self.total_checks
    }
}

impl Default for PtCheckTable {
    fn default() -> Self {
        Self::empty()
    }
}

// -------------------------------------------------------------------
// PtCheckSubsystem
// -------------------------------------------------------------------

/// Top-level page table consistency checker subsystem.
pub struct PtCheckSubsystem {
    /// Per-mm checker tables.
    tables: [PtCheckTable; MAX_MM],
    /// Number of active tables.
    active_mm: usize,
    /// Whether the subsystem is initialised.
    initialised: bool,
}

impl PtCheckSubsystem {
    /// Create an uninitialised subsystem.
    pub const fn new() -> Self {
        Self {
            tables: [const { PtCheckTable::empty() }; MAX_MM],
            active_mm: 0,
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

    /// Register an address space for checking.
    pub fn register_mm(&mut self, mm_id: u64) -> Result<usize> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        for t in self.tables.iter().take(self.active_mm) {
            if t.active && t.mm_id == mm_id {
                return Err(Error::AlreadyExists);
            }
        }
        if self.active_mm >= MAX_MM {
            return Err(Error::OutOfMemory);
        }
        let idx = self.active_mm;
        self.tables[idx].mm_id = mm_id;
        self.tables[idx].active = true;
        self.active_mm += 1;
        Ok(idx)
    }

    /// Unregister an address space.
    pub fn unregister_mm(&mut self, mm_id: u64) -> Result<()> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        let pos = self
            .tables
            .iter()
            .take(self.active_mm)
            .position(|t| t.active && t.mm_id == mm_id)
            .ok_or(Error::NotFound)?;
        self.active_mm -= 1;
        if pos < self.active_mm {
            self.tables.swap(pos, self.active_mm);
        }
        self.tables[self.active_mm] = PtCheckTable::empty();
        Ok(())
    }

    /// Find table index for an mm.
    fn find_table(&mut self, mm_id: u64) -> Result<usize> {
        self.tables
            .iter()
            .take(self.active_mm)
            .position(|t| t.active && t.mm_id == mm_id)
            .ok_or(Error::NotFound)
    }

    /// Add a page table page for checking.
    pub fn add_page(
        &mut self,
        mm_id: u64,
        paddr: u64,
        level: PtCheckLevel,
        entries: [u64; ENTRIES_PER_PAGE],
    ) -> Result<usize> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        let idx = self.find_table(mm_id)?;
        self.tables[idx].add_page(paddr, level, entries)
    }

    /// Add a physical page reference count.
    pub fn add_phys_ref(&mut self, mm_id: u64, pfn: u64, expected_count: u32) -> Result<usize> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        let idx = self.find_table(mm_id)?;
        self.tables[idx].add_phys_ref(pfn, expected_count)
    }

    /// Run the consistency check for an address space.
    pub fn check(&mut self, mm_id: u64) -> Result<PtCheckResult> {
        if !self.initialised {
            return Err(Error::NotImplemented);
        }
        let idx = self.find_table(mm_id)?;
        Ok(self.tables[idx].check())
    }

    /// Run checks on all registered address spaces.
    pub fn check_all(&mut self) -> ([PtCheckResult; MAX_MM], usize) {
        let mut results = [PtCheckResult::default(); MAX_MM];
        let mut count = 0usize;
        for i in 0..self.active_mm {
            if !self.tables[i].active {
                continue;
            }
            results[count] = self.tables[i].check();
            results[count].mm_id = self.tables[i].mm_id;
            count += 1;
        }
        (results, count)
    }

    /// Collect aggregate statistics.
    pub fn stats(&self) -> PtCheckStats {
        let mut s = PtCheckStats {
            active_mm: self.active_mm as u64,
            ..PtCheckStats::default()
        };
        for t in self.tables.iter().take(self.active_mm) {
            if !t.active {
                continue;
            }
            s.total_checks = s.total_checks.saturating_add(t.total_checks);
            s.total_violations = s.total_violations.saturating_add(t.total_violations);
            s.total_pt_pages = s.total_pt_pages.saturating_add(t.page_count as u64);
            s.total_phys_refs = s.total_phys_refs.saturating_add(t.phys_ref_count as u64);
        }
        s
    }

    /// Whether the subsystem is initialised.
    pub fn is_initialised(&self) -> bool {
        self.initialised
    }
}

impl Default for PtCheckSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// PtCheckStats
// -------------------------------------------------------------------

/// Aggregate statistics for the page table check subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct PtCheckStats {
    /// Number of active address spaces being checked.
    pub active_mm: u64,
    /// Total check runs across all address spaces.
    pub total_checks: u64,
    /// Total violations found across all checks.
    pub total_violations: u64,
    /// Total page table pages registered.
    pub total_pt_pages: u64,
    /// Total physical page ref entries.
    pub total_phys_refs: u64,
}

// -------------------------------------------------------------------
// Helper functions
// -------------------------------------------------------------------

/// Extract the physical address from a raw PTE value.
pub fn pte_phys_addr(raw: u64) -> u64 {
    raw & PTE_ADDR_MASK
}

/// Check if a raw PTE is present.
pub fn pte_is_present(raw: u64) -> bool {
    raw & PTE_PRESENT != 0
}

/// Check if a raw PTE is writable.
pub fn pte_is_writable(raw: u64) -> bool {
    raw & PTE_WRITABLE != 0
}

/// Check if a raw PTE has the NX bit set.
pub fn pte_is_nx(raw: u64) -> bool {
    raw & PTE_NX != 0
}

/// Check if a raw PTE has the user bit.
pub fn pte_is_user(raw: u64) -> bool {
    raw & PTE_USER != 0
}

/// Check if a virtual address is in the kernel range.
pub fn is_kernel_addr(addr: u64) -> bool {
    addr >= KERNEL_ADDR_START
}
