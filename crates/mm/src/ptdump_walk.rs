// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page table dump walker.
//!
//! Walks all four levels of x86_64 page tables (PGD/PML4 -> PUD/PDPT
//! -> PMD/PD -> PTE/PT), collecting mappings together with their
//! decoded attributes (RW, NX, User, Global, etc.). Output is
//! formatted for human-readable debugging and can be filtered by
//! virtual address range. Huge pages at PUD (1 GiB) and PMD (2 MiB)
//! levels are detected and reported with their effective page size.
//!
//! # Key Types
//!
//! - [`WalkLevel`] — page table level enumeration
//! - [`WalkFlags`] — decoded permission/status bits
//! - [`WalkMapping`] — single mapping collected during walk
//! - [`WalkFilter`] — address range and attribute filters
//! - [`WalkResult`] — collected mappings from a single walk
//! - [`WalkStats`] — aggregate statistics across walks
//! - [`PageTableWalker`] — top-level walker engine
//!
//! Reference: Linux `arch/x86/mm/dump_pagetables.c`,
//! `mm/ptdump.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Entries per page table (x86_64).
const ENTRIES_PER_TABLE: usize = 512;

/// Standard 4 KiB page.
const PAGE_SIZE_4K: u64 = 4096;

/// 2 MiB huge page.
const PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;

/// 1 GiB huge page.
const PAGE_SIZE_1G: u64 = 1024 * 1024 * 1024;

/// Maximum mappings collected per walk.
const MAX_WALK_MAPPINGS: usize = 512;

/// Maximum number of saved walk results.
const MAX_SAVED_WALKS: usize = 8;

/// PTE: present.
const PTE_PRESENT: u64 = 1 << 0;
/// PTE: writable.
const PTE_WRITABLE: u64 = 1 << 1;
/// PTE: user-accessible.
const PTE_USER: u64 = 1 << 2;
/// PTE: write-through.
const PTE_WRITE_THROUGH: u64 = 1 << 3;
/// PTE: cache disabled.
const PTE_NO_CACHE: u64 = 1 << 4;
/// PTE: accessed.
const PTE_ACCESSED: u64 = 1 << 5;
/// PTE: dirty.
const PTE_DIRTY: u64 = 1 << 6;
/// PTE: huge page.
const PTE_HUGE: u64 = 1 << 7;
/// PTE: global.
const PTE_GLOBAL: u64 = 1 << 8;
/// PTE: no-execute.
const PTE_NX: u64 = 1u64 << 63;

/// Mask for physical address extraction (bits 12..51).
const PHYS_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// -------------------------------------------------------------------
// WalkLevel
// -------------------------------------------------------------------

/// Page table level identifiers for x86_64 4-level paging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WalkLevel {
    /// PGD / PML4 — top level.
    #[default]
    Pgd,
    /// PUD / PDPT — second level (1 GiB huge pages).
    Pud,
    /// PMD / PD — third level (2 MiB huge pages).
    Pmd,
    /// PTE / PT — leaf level (4 KiB pages).
    Pte,
}

impl WalkLevel {
    /// Virtual address shift for this level.
    pub const fn va_shift(self) -> u32 {
        match self {
            Self::Pgd => 39,
            Self::Pud => 30,
            Self::Pmd => 21,
            Self::Pte => 12,
        }
    }

    /// Page size mapped at this level (for leaf/huge entries).
    pub const fn page_size(self) -> u64 {
        match self {
            Self::Pgd => 0,
            Self::Pud => PAGE_SIZE_1G,
            Self::Pmd => PAGE_SIZE_2M,
            Self::Pte => PAGE_SIZE_4K,
        }
    }

    /// Next (child) level, or `None` at leaf.
    pub const fn next(self) -> Option<WalkLevel> {
        match self {
            Self::Pgd => Some(Self::Pud),
            Self::Pud => Some(Self::Pmd),
            Self::Pmd => Some(Self::Pte),
            Self::Pte => None,
        }
    }

    /// Depth index (0 = PGD, 3 = PTE).
    pub const fn depth(self) -> usize {
        match self {
            Self::Pgd => 0,
            Self::Pud => 1,
            Self::Pmd => 2,
            Self::Pte => 3,
        }
    }
}

// -------------------------------------------------------------------
// WalkFlags
// -------------------------------------------------------------------

/// Decoded permission and status flags from a page table entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct WalkFlags {
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
    /// Page is dirty.
    pub dirty: bool,
    /// Huge page (2 MiB at PMD, 1 GiB at PUD).
    pub huge: bool,
    /// Global page.
    pub global: bool,
    /// No-execute bit set.
    pub no_execute: bool,
    /// Raw PTE bits.
    pub raw: u64,
}

impl WalkFlags {
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

    /// Whether the permission-relevant bits match (ignoring
    /// volatile accessed/dirty).
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
// WalkMapping
// -------------------------------------------------------------------

/// A single mapping collected during a page table walk.
#[derive(Debug, Clone, Copy)]
pub struct WalkMapping {
    /// Virtual address of the mapping.
    pub vaddr: u64,
    /// Physical address the mapping points to.
    pub paddr: u64,
    /// Effective page size of this mapping.
    pub page_size: u64,
    /// Page table level where this mapping was found.
    pub level: WalkLevel,
    /// Decoded flags.
    pub flags: WalkFlags,
    /// Index within the page table at this level.
    pub index: u16,
    /// Whether this slot is occupied.
    active: bool,
}

impl WalkMapping {
    /// Create an empty, inactive mapping.
    const fn empty() -> Self {
        Self {
            vaddr: 0,
            paddr: 0,
            page_size: 0,
            level: WalkLevel::Pte,
            flags: WalkFlags {
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

    /// Whether this mapping slot is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Whether this mapping is a huge page.
    pub const fn is_huge(&self) -> bool {
        self.flags.huge
    }
}

// -------------------------------------------------------------------
// WalkFilter
// -------------------------------------------------------------------

/// Filter criteria for selective page table walks.
#[derive(Debug, Clone, Copy)]
pub struct WalkFilter {
    /// Start of the virtual address range (inclusive).
    pub start_vaddr: u64,
    /// End of the virtual address range (exclusive).
    pub end_vaddr: u64,
    /// Only include writable mappings (if true).
    pub writable_only: bool,
    /// Only include user-accessible mappings (if true).
    pub user_only: bool,
    /// Only include huge-page mappings (if true).
    pub huge_only: bool,
    /// Only include no-execute mappings (if true).
    pub nx_only: bool,
    /// Whether this filter is enabled.
    pub enabled: bool,
}

impl WalkFilter {
    /// A disabled (pass-all) filter.
    pub const fn disabled() -> Self {
        Self {
            start_vaddr: 0,
            end_vaddr: u64::MAX,
            writable_only: false,
            user_only: false,
            huge_only: false,
            nx_only: false,
            enabled: false,
        }
    }

    /// Create a filter for a virtual address range.
    pub const fn range(start: u64, end: u64) -> Self {
        Self {
            start_vaddr: start,
            end_vaddr: end,
            writable_only: false,
            user_only: false,
            huge_only: false,
            nx_only: false,
            enabled: true,
        }
    }

    /// Check whether a mapping passes this filter.
    pub const fn matches(&self, mapping: &WalkMapping) -> bool {
        if !self.enabled {
            return true;
        }
        if mapping.vaddr < self.start_vaddr {
            return false;
        }
        if mapping.vaddr >= self.end_vaddr {
            return false;
        }
        if self.writable_only && !mapping.flags.writable {
            return false;
        }
        if self.user_only && !mapping.flags.user {
            return false;
        }
        if self.huge_only && !mapping.flags.huge {
            return false;
        }
        if self.nx_only && !mapping.flags.no_execute {
            return false;
        }
        true
    }
}

impl Default for WalkFilter {
    fn default() -> Self {
        Self::disabled()
    }
}

// -------------------------------------------------------------------
// WalkResult
// -------------------------------------------------------------------

/// Collected mappings from a single page table walk.
pub struct WalkResult {
    /// Walk identifier.
    pub id: u32,
    /// Physical address of the PGD (CR3 value).
    pub pgd_phys: u64,
    /// Collected mappings.
    mappings: [WalkMapping; MAX_WALK_MAPPINGS],
    /// Number of active mappings.
    count: usize,
    /// Filter that was applied.
    pub filter: WalkFilter,
    /// Number of 4 KiB pages found.
    pub pages_4k: u32,
    /// Number of 2 MiB huge pages found.
    pub pages_2m: u32,
    /// Number of 1 GiB huge pages found.
    pub pages_1g: u32,
    /// Whether this result slot is in use.
    active: bool,
}

impl WalkResult {
    /// Create an empty, inactive walk result.
    const fn empty() -> Self {
        Self {
            id: 0,
            pgd_phys: 0,
            mappings: [WalkMapping::empty(); MAX_WALK_MAPPINGS],
            count: 0,
            filter: WalkFilter::disabled(),
            pages_4k: 0,
            pages_2m: 0,
            pages_1g: 0,
            active: false,
        }
    }

    /// Number of collected mappings.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Whether this result is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Read-only access to collected mappings.
    pub fn mappings(&self) -> &[WalkMapping] {
        &self.mappings[..self.count]
    }

    /// Add a mapping to the result set. Returns error if full.
    fn add_mapping(&mut self, mapping: WalkMapping) -> Result<()> {
        if self.count >= MAX_WALK_MAPPINGS {
            return Err(Error::OutOfMemory);
        }
        self.mappings[self.count] = mapping;
        self.count += 1;
        match mapping.page_size {
            PAGE_SIZE_1G => self.pages_1g += 1,
            PAGE_SIZE_2M => self.pages_2m += 1,
            _ => self.pages_4k += 1,
        }
        Ok(())
    }
}

// -------------------------------------------------------------------
// WalkStats
// -------------------------------------------------------------------

/// Aggregate statistics across all page table walks.
#[derive(Debug, Clone, Copy, Default)]
pub struct WalkStats {
    /// Total walks performed.
    pub total_walks: u64,
    /// Total mappings collected across all walks.
    pub total_mappings: u64,
    /// Total 4 KiB pages found.
    pub total_pages_4k: u64,
    /// Total 2 MiB pages found.
    pub total_pages_2m: u64,
    /// Total 1 GiB pages found.
    pub total_pages_1g: u64,
    /// Walks that were truncated due to capacity.
    pub truncated_walks: u64,
    /// Total PGD entries examined.
    pub pgd_entries_scanned: u64,
    /// Total PUD entries examined.
    pub pud_entries_scanned: u64,
    /// Total PMD entries examined.
    pub pmd_entries_scanned: u64,
    /// Total PTE entries examined.
    pub pte_entries_scanned: u64,
}

// -------------------------------------------------------------------
// PageTableWalker
// -------------------------------------------------------------------

/// Top-level page table dump walker engine.
///
/// Performs structured walks over x86_64 4-level page tables,
/// collecting mapping information for debugging and diagnostics.
pub struct PageTableWalker {
    /// Saved walk results.
    results: [WalkResult; MAX_SAVED_WALKS],
    /// Next walk identifier to assign.
    next_id: u32,
    /// Aggregate walk statistics.
    stats: WalkStats,
    /// Default filter for new walks.
    default_filter: WalkFilter,
}

impl Default for PageTableWalker {
    fn default() -> Self {
        Self::new()
    }
}

impl PageTableWalker {
    /// Create a new walker with no saved results.
    pub const fn new() -> Self {
        Self {
            results: [const { WalkResult::empty() }; MAX_SAVED_WALKS],
            next_id: 1,
            stats: WalkStats {
                total_walks: 0,
                total_mappings: 0,
                total_pages_4k: 0,
                total_pages_2m: 0,
                total_pages_1g: 0,
                truncated_walks: 0,
                pgd_entries_scanned: 0,
                pud_entries_scanned: 0,
                pmd_entries_scanned: 0,
                pte_entries_scanned: 0,
            },
            default_filter: WalkFilter::disabled(),
        }
    }

    /// Set the default filter applied to new walks.
    pub fn set_default_filter(&mut self, filter: WalkFilter) {
        self.default_filter = filter;
    }

    /// Current aggregate statistics.
    pub const fn stats(&self) -> &WalkStats {
        &self.stats
    }

    /// Walk a simulated page table described by flat PTE arrays.
    ///
    /// `pgd_phys` is the physical address of the PGD (CR3 value).
    /// `entries` is a flat array of (level, index, raw_pte) tuples
    /// that describe the page table contents to walk.
    pub fn walk_entries(
        &mut self,
        pgd_phys: u64,
        entries: &[(WalkLevel, u16, u64)],
        filter: Option<WalkFilter>,
    ) -> Result<u32> {
        let slot = self
            .results
            .iter()
            .position(|r| !r.active)
            .ok_or(Error::OutOfMemory)?;

        let walk_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let applied_filter = filter.unwrap_or(self.default_filter);

        self.results[slot] = WalkResult::empty();
        self.results[slot].id = walk_id;
        self.results[slot].pgd_phys = pgd_phys;
        self.results[slot].filter = applied_filter;
        self.results[slot].active = true;

        for &(level, index, raw_pte) in entries {
            let flags = WalkFlags::from_raw(raw_pte);
            if !flags.present {
                self.increment_scan_counter(level);
                continue;
            }

            let paddr = raw_pte & PHYS_ADDR_MASK;
            let is_huge = flags.huge && matches!(level, WalkLevel::Pud | WalkLevel::Pmd);

            let page_size = if is_huge {
                level.page_size()
            } else if matches!(level, WalkLevel::Pte) {
                PAGE_SIZE_4K
            } else {
                self.increment_scan_counter(level);
                continue;
            };

            let vaddr = Self::compute_vaddr(level, index, pgd_phys);

            let mapping = WalkMapping {
                vaddr,
                paddr,
                page_size,
                level,
                flags,
                index,
                active: true,
            };

            if applied_filter.matches(&mapping) {
                let _ = self.results[slot].add_mapping(mapping);
            }
            self.increment_scan_counter(level);
        }

        self.stats.total_walks += 1;
        self.stats.total_mappings += self.results[slot].count as u64;
        self.stats.total_pages_4k += self.results[slot].pages_4k as u64;
        self.stats.total_pages_2m += self.results[slot].pages_2m as u64;
        self.stats.total_pages_1g += self.results[slot].pages_1g as u64;
        if self.results[slot].count >= MAX_WALK_MAPPINGS {
            self.stats.truncated_walks += 1;
        }

        Ok(walk_id)
    }

    /// Retrieve a completed walk result by identifier.
    pub fn get_result(&self, walk_id: u32) -> Result<&WalkResult> {
        self.results
            .iter()
            .find(|r| r.active && r.id == walk_id)
            .ok_or(Error::NotFound)
    }

    /// Discard a saved walk result.
    pub fn discard_result(&mut self, walk_id: u32) -> Result<()> {
        let result = self
            .results
            .iter_mut()
            .find(|r| r.active && r.id == walk_id)
            .ok_or(Error::NotFound)?;
        result.active = false;
        result.count = 0;
        Ok(())
    }

    /// Discard all saved walk results.
    pub fn discard_all(&mut self) {
        for r in &mut self.results {
            r.active = false;
            r.count = 0;
        }
    }

    /// Number of active saved walks.
    pub fn active_walks(&self) -> usize {
        self.results.iter().filter(|r| r.active).count()
    }

    /// Compute a virtual address from level, index, and PGD base.
    fn compute_vaddr(level: WalkLevel, index: u16, _pgd_phys: u64) -> u64 {
        let shift = level.va_shift();
        let va = (index as u64) << shift;
        // Sign-extend for canonical x86_64 addresses.
        if va & (1u64 << 47) != 0 {
            va | 0xFFFF_0000_0000_0000
        } else {
            va
        }
    }

    /// Increment the scan counter for the given level.
    fn increment_scan_counter(&mut self, level: WalkLevel) {
        match level {
            WalkLevel::Pgd => self.stats.pgd_entries_scanned += 1,
            WalkLevel::Pud => self.stats.pud_entries_scanned += 1,
            WalkLevel::Pmd => self.stats.pmd_entries_scanned += 1,
            WalkLevel::Pte => self.stats.pte_entries_scanned += 1,
        }
    }
}

// -------------------------------------------------------------------
// Formatting helpers
// -------------------------------------------------------------------

/// Format a single mapping as a human-readable debug line.
///
/// Returns the number of bytes written into `buf`, or an error
/// if the buffer is too small.
pub fn format_mapping(mapping: &WalkMapping, buf: &mut [u8]) -> Result<usize> {
    if buf.len() < 80 {
        return Err(Error::InvalidArgument);
    }
    let f = &mapping.flags;
    let rw = if f.writable { b'W' } else { b'R' };
    let us = if f.user { b'U' } else { b'K' };
    let nx = if f.no_execute { b'X' } else { b'-' };
    let gl = if f.global { b'G' } else { b'-' };
    let hg = if f.huge { b'H' } else { b'-' };

    // "VA:0x{vaddr:016X} PA:0x{paddr:016X} {sz} {flags}"
    let mut pos = 0;
    let prefix = b"VA:0x";
    buf[pos..pos + prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    pos += write_hex16(&mut buf[pos..], mapping.vaddr);

    buf[pos] = b' ';
    pos += 1;
    let pa_prefix = b"PA:0x";
    buf[pos..pos + pa_prefix.len()].copy_from_slice(pa_prefix);
    pos += pa_prefix.len();
    pos += write_hex16(&mut buf[pos..], mapping.paddr);

    buf[pos] = b' ';
    pos += 1;
    let sz_str = match mapping.page_size {
        PAGE_SIZE_1G => b"1G  " as &[u8],
        PAGE_SIZE_2M => b"2M  " as &[u8],
        _ => b"4K  " as &[u8],
    };
    buf[pos..pos + sz_str.len()].copy_from_slice(sz_str);
    pos += sz_str.len();

    buf[pos] = rw;
    pos += 1;
    buf[pos] = us;
    pos += 1;
    buf[pos] = nx;
    pos += 1;
    buf[pos] = gl;
    pos += 1;
    buf[pos] = hg;
    pos += 1;

    Ok(pos)
}

/// Write a 64-bit value as 16 hex digits into `buf`. Returns 16.
fn write_hex16(buf: &mut [u8], val: u64) -> usize {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for i in 0..16 {
        let nibble = ((val >> (60 - i * 4)) & 0xF) as usize;
        buf[i] = HEX[nibble];
    }
    16
}
