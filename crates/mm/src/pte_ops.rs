// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! PTE manipulation helpers for the x86_64 page table entries.
//!
//! Provides a strongly-typed [`PteFlags`] bitfield and a [`Pte`]
//! wrapper around the raw `u64` page table entry, with builder-style
//! mutation helpers (`mkwrite`, `mkclean`, `mkyoung`, …) and
//! predicate queries (`is_present`, `is_dirty`, `is_write`, …).
//!
//! Also provides conversion functions `pfn_pte` and `pte_pfn` for
//! building and extracting page frame numbers from PTEs.
//!
//! - [`PteFlags`] — individual PTE flag constants
//! - [`Pte`] — a single page table entry with accessor/mutator API
//! - [`PteFlagSet`] — aggregated set of PTE flags
//! - [`PteOps`] — bulk PTE operations on arrays of entries
//!
//! Reference: Intel SDM Vol. 3A §4.5 (IA-32e Paging), Linux
//! `arch/x86/include/asm/pgtable_types.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants — PTE flag bit positions
// -------------------------------------------------------------------

/// Page is present in memory.
const FLAG_PRESENT: u64 = 1 << 0;
/// Page is writable.
const FLAG_WRITABLE: u64 = 1 << 1;
/// Page is accessible from user mode.
const FLAG_USER: u64 = 1 << 2;
/// Write-through caching policy.
const FLAG_PWT: u64 = 1 << 3;
/// Cache-disable.
const FLAG_PCD: u64 = 1 << 4;
/// Page has been accessed (read).
const FLAG_ACCESSED: u64 = 1 << 5;
/// Page has been written to (dirty).
const FLAG_DIRTY: u64 = 1 << 6;
/// Huge page (PSE bit at PMD/PUD level).
const FLAG_HUGE: u64 = 1 << 7;
/// Global page (not flushed on CR3 reload).
const FLAG_GLOBAL: u64 = 1 << 8;
/// Software bit: page is special (zero-page, MMIO, etc.).
const FLAG_SPECIAL: u64 = 1 << 9;
/// Software bit: page is a soft-dirty tracked page.
const FLAG_SOFT_DIRTY: u64 = 1 << 10;
/// Software bit: page is protnone (NUMA balancing).
const FLAG_PROTNONE: u64 = 1 << 11;
/// No-execute (XD) bit.
const FLAG_NX: u64 = 1 << 63;

/// Mask for extracting the physical address (bits 12–51).
const ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Page size in bytes.
const PAGE_SIZE: u64 = 4096;

/// Maximum number of PTEs in a bulk operation.
const MAX_BULK_PTES: usize = 512;

// -------------------------------------------------------------------
// PteFlags
// -------------------------------------------------------------------

/// Named constants for individual PTE flag bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PteFlags;

impl PteFlags {
    /// Present bit.
    pub const PRESENT: u64 = FLAG_PRESENT;
    /// Writable bit.
    pub const WRITABLE: u64 = FLAG_WRITABLE;
    /// User bit.
    pub const USER: u64 = FLAG_USER;
    /// Write-through bit.
    pub const PWT: u64 = FLAG_PWT;
    /// Cache-disable bit.
    pub const PCD: u64 = FLAG_PCD;
    /// Accessed bit.
    pub const ACCESSED: u64 = FLAG_ACCESSED;
    /// Dirty bit.
    pub const DIRTY: u64 = FLAG_DIRTY;
    /// Huge page bit.
    pub const HUGE: u64 = FLAG_HUGE;
    /// Global bit.
    pub const GLOBAL: u64 = FLAG_GLOBAL;
    /// Special (software) bit.
    pub const SPECIAL: u64 = FLAG_SPECIAL;
    /// Soft-dirty (software) bit.
    pub const SOFT_DIRTY: u64 = FLAG_SOFT_DIRTY;
    /// Protnone (software) bit.
    pub const PROTNONE: u64 = FLAG_PROTNONE;
    /// No-execute bit.
    pub const NX: u64 = FLAG_NX;
}

// -------------------------------------------------------------------
// PteFlagSet
// -------------------------------------------------------------------

/// An aggregated set of PTE flags that can be combined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PteFlagSet {
    /// Raw combined flags value.
    bits: u64,
}

impl PteFlagSet {
    /// Creates an empty flag set.
    pub fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Creates a flag set from raw bits.
    pub fn from_bits(bits: u64) -> Self {
        Self { bits }
    }

    /// Returns the raw bits.
    pub fn bits(self) -> u64 {
        self.bits
    }

    /// Adds a flag.
    pub fn set(self, flag: u64) -> Self {
        Self {
            bits: self.bits | flag,
        }
    }

    /// Removes a flag.
    pub fn clear(self, flag: u64) -> Self {
        Self {
            bits: self.bits & !flag,
        }
    }

    /// Tests whether a flag is set.
    pub fn contains(self, flag: u64) -> bool {
        self.bits & flag == flag
    }

    /// Merges with another flag set (OR).
    pub fn union(self, other: Self) -> Self {
        Self {
            bits: self.bits | other.bits,
        }
    }

    /// Intersection with another flag set (AND).
    pub fn intersect(self, other: Self) -> Self {
        Self {
            bits: self.bits & other.bits,
        }
    }

    /// Returns a typical user-page flag set:
    /// PRESENT | WRITABLE | USER | ACCESSED.
    pub fn user_default() -> Self {
        Self {
            bits: FLAG_PRESENT | FLAG_WRITABLE | FLAG_USER | FLAG_ACCESSED,
        }
    }

    /// Returns a typical kernel-page flag set:
    /// PRESENT | WRITABLE | GLOBAL | NX.
    pub fn kernel_default() -> Self {
        Self {
            bits: FLAG_PRESENT | FLAG_WRITABLE | FLAG_GLOBAL | FLAG_NX,
        }
    }
}

// -------------------------------------------------------------------
// Pte — single page table entry
// -------------------------------------------------------------------

/// A single x86_64 page table entry (raw u64 wrapper).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Pte {
    /// Raw PTE value.
    raw: u64,
}

impl Pte {
    /// Creates a PTE from a raw u64.
    pub fn from_raw(raw: u64) -> Self {
        Self { raw }
    }

    /// Returns the raw u64 value.
    pub fn raw(self) -> u64 {
        self.raw
    }

    /// Creates a not-present (zero) PTE.
    pub fn none() -> Self {
        Self { raw: 0 }
    }

    // ----- Predicate queries -----

    /// Returns `true` if the PTE is present.
    pub fn is_present(self) -> bool {
        self.raw & FLAG_PRESENT != 0
    }

    /// Returns `true` if the PTE is writable.
    pub fn is_write(self) -> bool {
        self.raw & FLAG_WRITABLE != 0
    }

    /// Returns `true` if the PTE is user-accessible.
    pub fn is_user(self) -> bool {
        self.raw & FLAG_USER != 0
    }

    /// Returns `true` if the PTE has been accessed.
    pub fn is_young(self) -> bool {
        self.raw & FLAG_ACCESSED != 0
    }

    /// Returns `true` if the PTE is dirty.
    pub fn is_dirty(self) -> bool {
        self.raw & FLAG_DIRTY != 0
    }

    /// Returns `true` if the PTE maps a huge page.
    pub fn is_huge(self) -> bool {
        self.raw & FLAG_HUGE != 0
    }

    /// Returns `true` if the PTE is global.
    pub fn is_global(self) -> bool {
        self.raw & FLAG_GLOBAL != 0
    }

    /// Returns `true` if the PTE is special.
    pub fn is_special(self) -> bool {
        self.raw & FLAG_SPECIAL != 0
    }

    /// Returns `true` if the PTE is soft-dirty.
    pub fn is_soft_dirty(self) -> bool {
        self.raw & FLAG_SOFT_DIRTY != 0
    }

    /// Returns `true` if the PTE is protnone.
    pub fn is_protnone(self) -> bool {
        self.raw & FLAG_PROTNONE != 0
    }

    /// Returns `true` if no-execute is set.
    pub fn is_no_exec(self) -> bool {
        self.raw & FLAG_NX != 0
    }

    // ----- Builder-style mutators -----

    /// Sets the writable flag.
    pub fn mkwrite(self) -> Self {
        Self {
            raw: self.raw | FLAG_WRITABLE,
        }
    }

    /// Clears the writable flag (makes read-only).
    pub fn wrprotect(self) -> Self {
        Self {
            raw: self.raw & !FLAG_WRITABLE,
        }
    }

    /// Clears the dirty flag.
    pub fn mkclean(self) -> Self {
        Self {
            raw: self.raw & !FLAG_DIRTY,
        }
    }

    /// Sets the dirty flag.
    pub fn mkdirty(self) -> Self {
        Self {
            raw: self.raw | FLAG_DIRTY,
        }
    }

    /// Clears the accessed flag (marks the page as old).
    pub fn mkold(self) -> Self {
        Self {
            raw: self.raw & !FLAG_ACCESSED,
        }
    }

    /// Sets the accessed flag (marks the page as young).
    pub fn mkyoung(self) -> Self {
        Self {
            raw: self.raw | FLAG_ACCESSED,
        }
    }

    /// Sets the special flag.
    pub fn mkspecial(self) -> Self {
        Self {
            raw: self.raw | FLAG_SPECIAL,
        }
    }

    /// Sets the huge flag.
    pub fn mkhuge(self) -> Self {
        Self {
            raw: self.raw | FLAG_HUGE,
        }
    }

    /// Sets the global flag.
    pub fn mkglobal(self) -> Self {
        Self {
            raw: self.raw | FLAG_GLOBAL,
        }
    }

    /// Sets the no-execute flag.
    pub fn mknoexec(self) -> Self {
        Self {
            raw: self.raw | FLAG_NX,
        }
    }

    /// Clears the no-execute flag (makes executable).
    pub fn mkexec(self) -> Self {
        Self {
            raw: self.raw & !FLAG_NX,
        }
    }

    /// Sets the present flag.
    pub fn mkpresent(self) -> Self {
        Self {
            raw: self.raw | FLAG_PRESENT,
        }
    }

    /// Clears the present flag.
    pub fn mknone(self) -> Self {
        Self {
            raw: self.raw & !FLAG_PRESENT,
        }
    }

    /// Applies a flag set (OR).
    pub fn set_flags(self, flags: PteFlagSet) -> Self {
        Self {
            raw: self.raw | flags.bits(),
        }
    }

    /// Clears the specified flags (AND-NOT).
    pub fn clear_flags(self, flags: PteFlagSet) -> Self {
        Self {
            raw: self.raw & !flags.bits(),
        }
    }

    // ----- Address extraction -----

    /// Extracts the physical frame number (PFN) from the PTE.
    pub fn pfn(self) -> u64 {
        (self.raw & ADDR_MASK) >> 12
    }

    /// Extracts the physical address from the PTE.
    pub fn phys_addr(self) -> u64 {
        self.raw & ADDR_MASK
    }

    /// Returns the PTE flag bits (without the address).
    pub fn flag_bits(self) -> u64 {
        self.raw & !ADDR_MASK
    }
}

// -------------------------------------------------------------------
// Free functions: pfn_pte / pte_pfn
// -------------------------------------------------------------------

/// Constructs a PTE from a page frame number and flag set.
pub fn pfn_pte(pfn: u64, flags: PteFlagSet) -> Pte {
    Pte::from_raw((pfn << 12) | flags.bits())
}

/// Extracts the page frame number from a PTE.
pub fn pte_pfn(pte: Pte) -> u64 {
    pte.pfn()
}

/// Constructs a PTE from a physical address and flag set.
pub fn phys_pte(paddr: u64, flags: PteFlagSet) -> Result<Pte> {
    if paddr % PAGE_SIZE != 0 {
        return Err(Error::InvalidArgument);
    }
    Ok(Pte::from_raw(paddr | flags.bits()))
}

// -------------------------------------------------------------------
// PteOps — bulk operations
// -------------------------------------------------------------------

/// Bulk operations on arrays of PTE entries.
pub struct PteOps {
    /// PTE entry storage.
    entries: [Pte; MAX_BULK_PTES],
    /// Number of valid entries.
    count: usize,
}

impl Default for PteOps {
    fn default() -> Self {
        Self {
            entries: [Pte::none(); MAX_BULK_PTES],
            count: 0,
        }
    }
}

impl PteOps {
    /// Creates a new empty PTE operations buffer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a PTE to the buffer.
    pub fn push(&mut self, pte: Pte) -> Result<()> {
        if self.count >= MAX_BULK_PTES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = pte;
        self.count += 1;
        Ok(())
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Gets the PTE at the given index.
    pub fn get(&self, index: usize) -> Option<Pte> {
        if index < self.count {
            Some(self.entries[index])
        } else {
            None
        }
    }

    /// Sets the PTE at the given index.
    pub fn set(&mut self, index: usize, pte: Pte) -> Result<()> {
        if index >= self.count {
            return Err(Error::InvalidArgument);
        }
        self.entries[index] = pte;
        Ok(())
    }

    /// Applies `mkwrite` to all entries.
    pub fn make_all_writable(&mut self) {
        for i in 0..self.count {
            self.entries[i] = self.entries[i].mkwrite();
        }
    }

    /// Applies `wrprotect` to all entries.
    pub fn write_protect_all(&mut self) {
        for i in 0..self.count {
            self.entries[i] = self.entries[i].wrprotect();
        }
    }

    /// Applies `mkclean` to all entries.
    pub fn clean_all(&mut self) {
        for i in 0..self.count {
            self.entries[i] = self.entries[i].mkclean();
        }
    }

    /// Applies `mkold` to all entries.
    pub fn age_all(&mut self) {
        for i in 0..self.count {
            self.entries[i] = self.entries[i].mkold();
        }
    }

    /// Counts present entries.
    pub fn count_present(&self) -> usize {
        self.entries[..self.count]
            .iter()
            .filter(|pte| pte.is_present())
            .count()
    }

    /// Counts dirty entries.
    pub fn count_dirty(&self) -> usize {
        self.entries[..self.count]
            .iter()
            .filter(|pte| pte.is_dirty())
            .count()
    }

    /// Counts writable entries.
    pub fn count_writable(&self) -> usize {
        self.entries[..self.count]
            .iter()
            .filter(|pte| pte.is_write())
            .count()
    }

    /// Clears all entries.
    pub fn clear(&mut self) {
        self.count = 0;
    }
}
