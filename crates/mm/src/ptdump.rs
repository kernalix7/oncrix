// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page table dumper for debugging and diagnostics.
//!
//! Walks x86_64 4-level page tables (PML4 -> PDPT -> PD -> PT)
//! and produces a structured dump of all valid mappings, including
//! virtual/physical address ranges, permission flags, and page
//! sizes.  Useful for debugging address space issues, verifying
//! page table correctness, and security auditing.
//!
//! Inspired by the Linux `arch/x86/mm/dump_pagetables.c` and
//! the `/sys/kernel/debug/page_tables/` debugfs interface.
//!
//! Key components:
//! - [`PtLevel`] — page table level identifiers
//! - [`PtEntryFlags`] — decoded permission flags
//! - [`PtDumpEntry`] — single mapping in the dump
//! - [`PtDumpRange`] — contiguous range with same flags
//! - [`PtDumpFilter`] — filter criteria for selective dumps
//! - [`PtDumpStats`] — aggregate walk statistics
//! - [`PageTableDumper`] — top-level dumper engine
//!
//! Reference: Linux `arch/x86/mm/dump_pagetables.c`,
//! `mm/ptdump.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Number of entries per page table level.
const ENTRIES_PER_TABLE: usize = 512;

/// Standard page size (4 KiB).
const PAGE_SIZE_4K: u64 = 4096;

/// 2 MiB huge page size.
const PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;

/// 1 GiB huge page size.
const PAGE_SIZE_1G: u64 = 1024 * 1024 * 1024;

/// Maximum entries in a single dump.
const MAX_DUMP_ENTRIES: usize = 512;

/// Maximum coalesced ranges in a dump.
const MAX_DUMP_RANGES: usize = 256;

/// Maximum number of saved dumps.
const MAX_SAVED_DUMPS: usize = 8;

/// PTE flag: entry is present.
const PTE_PRESENT: u64 = 1 << 0;
/// PTE flag: page is writable.
const PTE_WRITABLE: u64 = 1 << 1;
/// PTE flag: user-mode accessible.
const PTE_USER: u64 = 1 << 2;
/// PTE flag: write-through caching.
const PTE_WRITE_THROUGH: u64 = 1 << 3;
/// PTE flag: caching disabled.
const PTE_NO_CACHE: u64 = 1 << 4;
/// PTE flag: page has been accessed.
const PTE_ACCESSED: u64 = 1 << 5;
/// PTE flag: page has been written.
const PTE_DIRTY: u64 = 1 << 6;
/// PTE flag: huge page (2 MiB or 1 GiB).
const PTE_HUGE: u64 = 1 << 7;
/// PTE flag: global page.
const PTE_GLOBAL: u64 = 1 << 8;
/// PTE flag: no-execute.
const PTE_NX: u64 = 1u64 << 63;

/// Mask for physical address extraction (bits 12..51).
const PHYS_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// -------------------------------------------------------------------
// PtLevel
// -------------------------------------------------------------------

/// Page table level identifiers for x86_64 4-level paging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PtLevel {
    /// PML4 (Page Map Level 4) — top level.
    #[default]
    Pml4,
    /// PDPT (Page Directory Pointer Table).
    Pdpt,
    /// PD (Page Directory).
    Pd,
    /// PT (Page Table) — leaf level for 4 KiB pages.
    Pt,
}

impl PtLevel {
    /// Return the virtual address shift for this level.
    pub const fn va_shift(self) -> u32 {
        match self {
            Self::Pml4 => 39,
            Self::Pdpt => 30,
            Self::Pd => 21,
            Self::Pt => 12,
        }
    }

    /// Return the page size mapped at this level (for huge pages).
    pub const fn page_size(self) -> u64 {
        match self {
            Self::Pml4 => 0, // PML4 entries don't map pages.
            Self::Pdpt => PAGE_SIZE_1G,
            Self::Pd => PAGE_SIZE_2M,
            Self::Pt => PAGE_SIZE_4K,
        }
    }

    /// Return the next (child) level.
    pub const fn next(self) -> Option<PtLevel> {
        match self {
            Self::Pml4 => Some(Self::Pdpt),
            Self::Pdpt => Some(Self::Pd),
            Self::Pd => Some(Self::Pt),
            Self::Pt => None,
        }
    }

    /// Depth index (0 = PML4, 3 = PT).
    pub const fn depth(self) -> usize {
        match self {
            Self::Pml4 => 0,
            Self::Pdpt => 1,
            Self::Pd => 2,
            Self::Pt => 3,
        }
    }
}

// -------------------------------------------------------------------
// PtEntryFlags
// -------------------------------------------------------------------

/// Decoded permission and status flags for a page table entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct PtEntryFlags {
    /// Entry is present/valid.
    pub present: bool,
    /// Page is writable.
    pub writable: bool,
    /// User-mode accessible.
    pub user: bool,
    /// Write-through caching.
    pub write_through: bool,
    /// Cache disabled.
    pub no_cache: bool,
    /// Page has been accessed.
    pub accessed: bool,
    /// Page has been written (dirty).
    pub dirty: bool,
    /// Huge page (2 MiB at PD, 1 GiB at PDPT).
    pub huge: bool,
    /// Global page (not flushed on CR3 switch).
    pub global: bool,
    /// No-execute.
    pub no_execute: bool,
    /// Raw flag bits.
    pub raw: u64,
}

impl PtEntryFlags {
    /// Decode flags from a raw PTE value.
    pub const fn from_raw(raw: u64) -> Self {
        Self {
            present: raw & PTE_PRESENT != 0,
            writable: raw & PTE_WRITABLE != 0,
            user: raw & PTE_USER != 0,
            write_through: raw & PTE_WRITE_THROUGH != 0,
            no_cache: raw & PTE_NO_CACHE != 0,
            accessed: raw & PTE_ACCESSED != 0,
            dirty: raw & PTE_DIRTY != 0,
            huge: raw & PTE_HUGE != 0,
            global: raw & PTE_GLOBAL != 0,
            no_execute: raw & PTE_NX != 0,
            raw,
        }
    }

    /// Whether these flags match another set (ignoring accessed
    /// and dirty which are volatile).
    pub const fn permissions_match(&self, other: &Self) -> bool {
        self.writable == other.writable
            && self.user == other.user
            && self.no_execute == other.no_execute
            && self.write_through == other.write_through
            && self.no_cache == other.no_cache
            && self.global == other.global
    }
}

// -------------------------------------------------------------------
// PtDumpEntry
// -------------------------------------------------------------------

/// A single mapping entry in the page table dump.
#[derive(Debug, Clone, Copy)]
pub struct PtDumpEntry {
    /// Virtual address of the mapping.
    pub vaddr: u64,
    /// Physical address the mapping points to.
    pub paddr: u64,
    /// Page size of this mapping.
    pub page_size: u64,
    /// Page table level where this mapping was found.
    pub level: PtLevel,
    /// Decoded flags.
    pub flags: PtEntryFlags,
    /// Index within the page table at this level.
    pub index: u16,
    /// Whether this entry is active (occupied in dump).
    active: bool,
}

impl PtDumpEntry {
    /// Create an empty entry.
    const fn empty() -> Self {
        Self {
            vaddr: 0,
            paddr: 0,
            page_size: 0,
            level: PtLevel::Pt,
            flags: PtEntryFlags {
                present: false,
                writable: false,
                user: false,
                write_through: false,
                no_cache: false,
                accessed: false,
                dirty: false,
                huge: false,
                global: false,
                no_execute: false,
                raw: 0,
            },
            index: 0,
            active: false,
        }
    }
}

// -------------------------------------------------------------------
// PtDumpRange
// -------------------------------------------------------------------

/// A contiguous virtual address range with the same permissions.
///
/// Multiple adjacent [`PtDumpEntry`] values with matching flags
/// are coalesced into a single range for concise output.
#[derive(Debug, Clone, Copy)]
pub struct PtDumpRange {
    /// Start virtual address.
    pub vaddr_start: u64,
    /// End virtual address (exclusive).
    pub vaddr_end: u64,
    /// Start physical address.
    pub paddr_start: u64,
    /// Page size used in this range.
    pub page_size: u64,
    /// Decoded flags (same for entire range).
    pub flags: PtEntryFlags,
    /// Number of pages in this range.
    pub nr_pages: u32,
    /// Level.
    pub level: PtLevel,
    /// Whether this range is active.
    active: bool,
}

impl PtDumpRange {
    /// Create an empty range.
    const fn empty() -> Self {
        Self {
            vaddr_start: 0,
            vaddr_end: 0,
            paddr_start: 0,
            page_size: 0,
            flags: PtEntryFlags {
                present: false,
                writable: false,
                user: false,
                write_through: false,
                no_cache: false,
                accessed: false,
                dirty: false,
                huge: false,
                global: false,
                no_execute: false,
                raw: 0,
            },
            nr_pages: 0,
            level: PtLevel::Pt,
            active: false,
        }
    }

    /// Size of this range in bytes.
    pub const fn size(&self) -> u64 {
        self.vaddr_end - self.vaddr_start
    }
}

// -------------------------------------------------------------------
// PtDumpFilter
// -------------------------------------------------------------------

/// Filter criteria for selective page table dumps.
#[derive(Debug, Clone, Copy)]
pub struct PtDumpFilter {
    /// Only dump entries within this virtual address range.
    pub vaddr_start: Option<u64>,
    /// End of virtual address range (exclusive).
    pub vaddr_end: Option<u64>,
    /// Only dump entries with these flags set.
    pub require_flags: u64,
    /// Exclude entries with these flags set.
    pub exclude_flags: u64,
    /// Only dump entries at this level.
    pub level: Option<PtLevel>,
    /// Only dump huge page mappings.
    pub huge_only: bool,
    /// Only dump user-accessible mappings.
    pub user_only: bool,
    /// Only dump writable mappings.
    pub writable_only: bool,
    /// Only dump executable mappings (no NX).
    pub executable_only: bool,
}

impl Default for PtDumpFilter {
    fn default() -> Self {
        Self {
            vaddr_start: None,
            vaddr_end: None,
            require_flags: 0,
            exclude_flags: 0,
            level: None,
            huge_only: false,
            user_only: false,
            writable_only: false,
            executable_only: false,
        }
    }
}

impl PtDumpFilter {
    /// Check whether an entry passes this filter.
    pub fn matches(&self, entry: &PtDumpEntry) -> bool {
        // Virtual address range.
        if let Some(start) = self.vaddr_start {
            if entry.vaddr < start {
                return false;
            }
        }
        if let Some(end) = self.vaddr_end {
            if entry.vaddr >= end {
                return false;
            }
        }
        // Required flags.
        if self.require_flags != 0 && (entry.flags.raw & self.require_flags) != self.require_flags {
            return false;
        }
        // Excluded flags.
        if self.exclude_flags != 0 && (entry.flags.raw & self.exclude_flags) != 0 {
            return false;
        }
        // Level.
        if let Some(lvl) = self.level {
            if entry.level != lvl {
                return false;
            }
        }
        // Huge only.
        if self.huge_only && !entry.flags.huge {
            return false;
        }
        // User only.
        if self.user_only && !entry.flags.user {
            return false;
        }
        // Writable only.
        if self.writable_only && !entry.flags.writable {
            return false;
        }
        // Executable only.
        if self.executable_only && entry.flags.no_execute {
            return false;
        }
        true
    }
}

// -------------------------------------------------------------------
// PtDumpStats
// -------------------------------------------------------------------

/// Statistics from a page table walk.
#[derive(Debug, Clone, Copy, Default)]
pub struct PtDumpStats {
    /// Total entries examined.
    pub entries_examined: u64,
    /// Present entries found.
    pub entries_present: u64,
    /// 4 KiB page mappings.
    pub pages_4k: u64,
    /// 2 MiB huge page mappings.
    pub pages_2m: u64,
    /// 1 GiB huge page mappings.
    pub pages_1g: u64,
    /// User-accessible mappings.
    pub user_mappings: u64,
    /// Writable mappings.
    pub writable_mappings: u64,
    /// Executable mappings (no NX).
    pub executable_mappings: u64,
    /// Dirty pages.
    pub dirty_pages: u64,
    /// Accessed pages.
    pub accessed_pages: u64,
    /// Total memory mapped (bytes).
    pub total_mapped_bytes: u64,
    /// Coalesced ranges produced.
    pub coalesced_ranges: usize,
    /// Walk duration (nanoseconds).
    pub walk_duration_ns: u64,
}

// -------------------------------------------------------------------
// SavedDump
// -------------------------------------------------------------------

/// A saved page table dump snapshot.
#[derive(Debug)]
struct SavedDump {
    /// Dump entries.
    entries: [PtDumpEntry; MAX_DUMP_ENTRIES],
    /// Number of valid entries.
    entry_count: usize,
    /// Coalesced ranges.
    ranges: [PtDumpRange; MAX_DUMP_RANGES],
    /// Number of valid ranges.
    range_count: usize,
    /// Statistics from the walk.
    stats: PtDumpStats,
    /// Timestamp of the dump.
    timestamp_ns: u64,
    /// Whether this slot is occupied.
    occupied: bool,
}

impl SavedDump {
    fn empty() -> Self {
        Self {
            entries: [const { PtDumpEntry::empty() }; MAX_DUMP_ENTRIES],
            entry_count: 0,
            ranges: [const { PtDumpRange::empty() }; MAX_DUMP_RANGES],
            range_count: 0,
            stats: PtDumpStats::default(),
            timestamp_ns: 0,
            occupied: false,
        }
    }
}

// -------------------------------------------------------------------
// PageTableDumper
// -------------------------------------------------------------------

/// Page table walk and dump engine.
///
/// Walks a simulated page table structure and produces structured
/// dumps of all present mappings.  Supports filtering, range
/// coalescing, and saving snapshots for comparison.
///
/// # Usage (conceptual)
///
/// ```ignore
/// let mut dumper = PageTableDumper::new();
/// // Load a simulated PML4 table.
/// dumper.set_pml4_entry(0, 0x1000 | PTE_PRESENT | PTE_WRITABLE);
/// let stats = dumper.walk(&PtDumpFilter::default(), 1000)?;
/// for range in dumper.ranges() { /* ... */ }
/// ```
pub struct PageTableDumper {
    /// Simulated PML4 table entries (raw u64 values).
    pml4: [u64; ENTRIES_PER_TABLE],
    /// Simulated PDPT entries (per PML4 entry, flattened).
    pdpt: [[u64; ENTRIES_PER_TABLE]; 4],
    /// Simulated PD entries (per PDPT entry, flattened).
    pd: [[u64; ENTRIES_PER_TABLE]; 4],
    /// Simulated PT entries (per PD entry, flattened).
    pt: [[u64; ENTRIES_PER_TABLE]; 4],
    /// Current dump entries.
    entries: [PtDumpEntry; MAX_DUMP_ENTRIES],
    /// Number of valid dump entries.
    entry_count: usize,
    /// Coalesced ranges.
    ranges: [PtDumpRange; MAX_DUMP_RANGES],
    /// Number of valid ranges.
    range_count: usize,
    /// Saved dump snapshots.
    saved: [SavedDump; MAX_SAVED_DUMPS],
    /// Number of saved dumps.
    saved_count: usize,
    /// Walk statistics.
    stats: PtDumpStats,
}

impl PageTableDumper {
    /// Create a new dumper with empty page tables.
    pub fn new() -> Self {
        Self {
            pml4: [0u64; ENTRIES_PER_TABLE],
            pdpt: [[0u64; ENTRIES_PER_TABLE]; 4],
            pd: [[0u64; ENTRIES_PER_TABLE]; 4],
            pt: [[0u64; ENTRIES_PER_TABLE]; 4],
            entries: [const { PtDumpEntry::empty() }; MAX_DUMP_ENTRIES],
            entry_count: 0,
            ranges: [const { PtDumpRange::empty() }; MAX_DUMP_RANGES],
            range_count: 0,
            saved: core::array::from_fn(|_| SavedDump::empty()),
            saved_count: 0,
            stats: PtDumpStats::default(),
        }
    }

    // ── table setup (for testing/simulation) ─────────────────────

    /// Set a PML4 entry.
    pub fn set_pml4_entry(&mut self, index: usize, raw: u64) {
        if index < ENTRIES_PER_TABLE {
            self.pml4[index] = raw;
        }
    }

    /// Set a PDPT entry.
    pub fn set_pdpt_entry(&mut self, table: usize, index: usize, raw: u64) {
        if table < 4 && index < ENTRIES_PER_TABLE {
            self.pdpt[table][index] = raw;
        }
    }

    /// Set a PD entry.
    pub fn set_pd_entry(&mut self, table: usize, index: usize, raw: u64) {
        if table < 4 && index < ENTRIES_PER_TABLE {
            self.pd[table][index] = raw;
        }
    }

    /// Set a PT entry.
    pub fn set_pt_entry(&mut self, table: usize, index: usize, raw: u64) {
        if table < 4 && index < ENTRIES_PER_TABLE {
            self.pt[table][index] = raw;
        }
    }

    // ── walk ─────────────────────────────────────────────────────

    /// Walk the page table and populate dump entries.
    ///
    /// Applies the given filter to only include matching entries.
    /// Returns walk statistics.
    pub fn walk(&mut self, filter: &PtDumpFilter, now_ns: u64) -> Result<PtDumpStats> {
        self.entry_count = 0;
        self.range_count = 0;
        self.stats = PtDumpStats::default();

        let start_ns = now_ns;

        // Walk PML4.
        for pml4_idx in 0..ENTRIES_PER_TABLE {
            let pml4_entry = self.pml4[pml4_idx];
            self.stats.entries_examined += 1;
            if pml4_entry & PTE_PRESENT == 0 {
                continue;
            }
            self.stats.entries_present += 1;

            let pml4_va = Self::sign_extend(pml4_idx as u64, 39);

            // Walk PDPT (use table index modulo 4).
            let pdpt_table = pml4_idx % 4;
            self.walk_pdpt(pdpt_table, pml4_va, filter);
        }

        self.stats.walk_duration_ns = now_ns.saturating_sub(start_ns);
        self.coalesce_ranges();
        Ok(self.stats)
    }

    /// Walk a PDPT table.
    fn walk_pdpt(&mut self, table: usize, base_va: u64, filter: &PtDumpFilter) {
        for pdpt_idx in 0..ENTRIES_PER_TABLE {
            let entry = self.pdpt[table][pdpt_idx];
            self.stats.entries_examined += 1;
            if entry & PTE_PRESENT == 0 {
                continue;
            }
            self.stats.entries_present += 1;

            let va = base_va | ((pdpt_idx as u64) << PtLevel::Pdpt.va_shift());

            // 1 GiB huge page?
            if entry & PTE_HUGE != 0 {
                self.record_mapping(
                    va,
                    entry & PHYS_ADDR_MASK,
                    PAGE_SIZE_1G,
                    PtLevel::Pdpt,
                    entry,
                    pdpt_idx as u16,
                    filter,
                );
                self.stats.pages_1g += 1;
                self.stats.total_mapped_bytes += PAGE_SIZE_1G;
                continue;
            }

            // Walk PD.
            let pd_table = pdpt_idx % 4;
            self.walk_pd(pd_table, va, filter);
        }
    }

    /// Walk a PD table.
    fn walk_pd(&mut self, table: usize, base_va: u64, filter: &PtDumpFilter) {
        for pd_idx in 0..ENTRIES_PER_TABLE {
            let entry = self.pd[table][pd_idx];
            self.stats.entries_examined += 1;
            if entry & PTE_PRESENT == 0 {
                continue;
            }
            self.stats.entries_present += 1;

            let va = base_va | ((pd_idx as u64) << PtLevel::Pd.va_shift());

            // 2 MiB huge page?
            if entry & PTE_HUGE != 0 {
                self.record_mapping(
                    va,
                    entry & PHYS_ADDR_MASK,
                    PAGE_SIZE_2M,
                    PtLevel::Pd,
                    entry,
                    pd_idx as u16,
                    filter,
                );
                self.stats.pages_2m += 1;
                self.stats.total_mapped_bytes += PAGE_SIZE_2M;
                continue;
            }

            // Walk PT.
            let pt_table = pd_idx % 4;
            self.walk_pt(pt_table, va, filter);
        }
    }

    /// Walk a PT table.
    fn walk_pt(&mut self, table: usize, base_va: u64, filter: &PtDumpFilter) {
        for pt_idx in 0..ENTRIES_PER_TABLE {
            let entry = self.pt[table][pt_idx];
            self.stats.entries_examined += 1;
            if entry & PTE_PRESENT == 0 {
                continue;
            }
            self.stats.entries_present += 1;

            let va = base_va | ((pt_idx as u64) << PtLevel::Pt.va_shift());

            self.record_mapping(
                va,
                entry & PHYS_ADDR_MASK,
                PAGE_SIZE_4K,
                PtLevel::Pt,
                entry,
                pt_idx as u16,
                filter,
            );
            self.stats.pages_4k += 1;
            self.stats.total_mapped_bytes += PAGE_SIZE_4K;
        }
    }

    /// Record a mapping entry if it passes the filter.
    fn record_mapping(
        &mut self,
        vaddr: u64,
        paddr: u64,
        page_size: u64,
        level: PtLevel,
        raw_flags: u64,
        index: u16,
        filter: &PtDumpFilter,
    ) {
        if self.entry_count >= MAX_DUMP_ENTRIES {
            return;
        }
        let flags = PtEntryFlags::from_raw(raw_flags);

        // Update stats.
        if flags.user {
            self.stats.user_mappings += 1;
        }
        if flags.writable {
            self.stats.writable_mappings += 1;
        }
        if !flags.no_execute {
            self.stats.executable_mappings += 1;
        }
        if flags.dirty {
            self.stats.dirty_pages += 1;
        }
        if flags.accessed {
            self.stats.accessed_pages += 1;
        }

        let entry = PtDumpEntry {
            vaddr,
            paddr,
            page_size,
            level,
            flags,
            index,
            active: true,
        };

        if !filter.matches(&entry) {
            return;
        }

        self.entries[self.entry_count] = entry;
        self.entry_count += 1;
    }

    /// Sign-extend a virtual address (x86_64 canonical form).
    fn sign_extend(index: u64, shift: u32) -> u64 {
        let va = index << shift;
        // If bit 47 is set, extend to bits 48..63.
        if va & (1u64 << 47) != 0 {
            va | 0xFFFF_0000_0000_0000
        } else {
            va
        }
    }

    // ── coalescing ───────────────────────────────────────────────

    /// Coalesce adjacent entries with matching permissions into
    /// ranges.
    fn coalesce_ranges(&mut self) {
        self.range_count = 0;
        if self.entry_count == 0 {
            return;
        }

        let first = &self.entries[0];
        let mut current = PtDumpRange {
            vaddr_start: first.vaddr,
            vaddr_end: first.vaddr + first.page_size,
            paddr_start: first.paddr,
            page_size: first.page_size,
            flags: first.flags,
            nr_pages: 1,
            level: first.level,
            active: true,
        };

        for i in 1..self.entry_count {
            let e = &self.entries[i];
            if !e.active {
                continue;
            }

            // Can coalesce?
            let contiguous = e.vaddr == current.vaddr_end
                && e.page_size == current.page_size
                && e.level == current.level
                && current.flags.permissions_match(&e.flags);

            if contiguous {
                current.vaddr_end += e.page_size;
                current.nr_pages += 1;
            } else {
                // Save current range and start new.
                if self.range_count < MAX_DUMP_RANGES {
                    self.ranges[self.range_count] = current;
                    self.range_count += 1;
                }
                current = PtDumpRange {
                    vaddr_start: e.vaddr,
                    vaddr_end: e.vaddr + e.page_size,
                    paddr_start: e.paddr,
                    page_size: e.page_size,
                    flags: e.flags,
                    nr_pages: 1,
                    level: e.level,
                    active: true,
                };
            }
        }
        // Save last range.
        if self.range_count < MAX_DUMP_RANGES {
            self.ranges[self.range_count] = current;
            self.range_count += 1;
        }
        self.stats.coalesced_ranges = self.range_count;
    }

    // ── snapshot management ──────────────────────────────────────

    /// Save the current dump as a snapshot.
    pub fn save_snapshot(&mut self, now_ns: u64) -> Result<usize> {
        if self.saved_count >= MAX_SAVED_DUMPS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.saved_count;
        let dump = &mut self.saved[idx];
        dump.entries = self.entries;
        dump.entry_count = self.entry_count;
        dump.ranges = self.ranges;
        dump.range_count = self.range_count;
        dump.stats = self.stats;
        dump.timestamp_ns = now_ns;
        dump.occupied = true;
        self.saved_count += 1;
        Ok(idx)
    }

    /// Get a saved snapshot's statistics.
    pub fn get_snapshot_stats(&self, index: usize) -> Result<&PtDumpStats> {
        if index >= self.saved_count || !self.saved[index].occupied {
            return Err(Error::NotFound);
        }
        Ok(&self.saved[index].stats)
    }

    /// Compare two snapshots and return differences in stats.
    pub fn compare_snapshots(&self, idx_a: usize, idx_b: usize) -> Result<PtDumpStats> {
        let a = self.get_snapshot_stats(idx_a)?;
        let b = self.get_snapshot_stats(idx_b)?;
        Ok(PtDumpStats {
            entries_examined: b.entries_examined.saturating_sub(a.entries_examined),
            entries_present: b.entries_present.saturating_sub(a.entries_present),
            pages_4k: b.pages_4k.saturating_sub(a.pages_4k),
            pages_2m: b.pages_2m.saturating_sub(a.pages_2m),
            pages_1g: b.pages_1g.saturating_sub(a.pages_1g),
            user_mappings: b.user_mappings.saturating_sub(a.user_mappings),
            writable_mappings: b.writable_mappings.saturating_sub(a.writable_mappings),
            executable_mappings: b.executable_mappings.saturating_sub(a.executable_mappings),
            dirty_pages: b.dirty_pages.saturating_sub(a.dirty_pages),
            accessed_pages: b.accessed_pages.saturating_sub(a.accessed_pages),
            total_mapped_bytes: b.total_mapped_bytes.saturating_sub(a.total_mapped_bytes),
            coalesced_ranges: b.coalesced_ranges.saturating_sub(a.coalesced_ranges),
            walk_duration_ns: 0,
        })
    }

    // ── queries ──────────────────────────────────────────────────

    /// Number of dump entries.
    pub const fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Get dump entries.
    pub fn entries(&self) -> &[PtDumpEntry] {
        &self.entries[..self.entry_count]
    }

    /// Number of coalesced ranges.
    pub const fn range_count(&self) -> usize {
        self.range_count
    }

    /// Get coalesced ranges.
    pub fn ranges(&self) -> &[PtDumpRange] {
        &self.ranges[..self.range_count]
    }

    /// Get walk statistics.
    pub const fn stats(&self) -> &PtDumpStats {
        &self.stats
    }

    /// Clear the current dump.
    pub fn clear(&mut self) {
        self.entry_count = 0;
        self.range_count = 0;
        self.stats = PtDumpStats::default();
    }

    /// Reset the dumper entirely (including saved snapshots).
    pub fn reset(&mut self) {
        self.clear();
        for dump in &mut self.saved {
            dump.occupied = false;
        }
        self.saved_count = 0;
        self.pml4 = [0u64; ENTRIES_PER_TABLE];
        self.pdpt = [[0u64; ENTRIES_PER_TABLE]; 4];
        self.pd = [[0u64; ENTRIES_PER_TABLE]; 4];
        self.pt = [[0u64; ENTRIES_PER_TABLE]; 4];
    }
}

impl Default for PageTableDumper {
    fn default() -> Self {
        Self::new()
    }
}
