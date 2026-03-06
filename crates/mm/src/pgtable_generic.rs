// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Generic page table helpers.
//!
//! Architecture-independent page table operations that work across
//! different paging modes. Provides helpers for PTE manipulation,
//! permission bit encoding/decoding, and generic page table walking.
//!
//! - [`PteFlags`] — page table entry permission flags
//! - [`GenericPte`] — architecture-independent PTE representation
//! - [`PteOp`] — batch PTE operations
//! - [`PageTableLevel`] — page table hierarchy levels
//! - [`GenericPageTable`] — generic flat page table for simulation
//!
//! Reference: Linux `include/asm-generic/pgtable.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Page shift (log2 of page size).
const PAGE_SHIFT: u32 = 12;

/// Maximum entries in generic page table.
const MAX_ENTRIES: usize = 512;

/// PFN mask (bits 12..51 on x86_64).
const PFN_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// -------------------------------------------------------------------
// PteFlags
// -------------------------------------------------------------------

/// Page table entry permission flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PteFlags {
    /// Raw flag bits.
    bits: u64,
}

impl PteFlags {
    /// Entry is present.
    pub const PRESENT: u64 = 1 << 0;
    /// Entry is writable.
    pub const WRITABLE: u64 = 1 << 1;
    /// Entry is user-accessible.
    pub const USER: u64 = 1 << 2;
    /// Write-through caching.
    pub const PWT: u64 = 1 << 3;
    /// Cache disabled.
    pub const PCD: u64 = 1 << 4;
    /// Accessed flag.
    pub const ACCESSED: u64 = 1 << 5;
    /// Dirty flag.
    pub const DIRTY: u64 = 1 << 6;
    /// Huge page flag.
    pub const HUGE: u64 = 1 << 7;
    /// Global page flag.
    pub const GLOBAL: u64 = 1 << 8;
    /// No-execute flag.
    pub const NO_EXEC: u64 = 1 << 63;

    /// Creates empty flags.
    pub fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Creates from raw bits.
    pub fn from_bits(bits: u64) -> Self {
        Self { bits }
    }

    /// Returns raw bits.
    pub fn bits(self) -> u64 {
        self.bits
    }

    /// Tests a flag.
    pub fn contains(self, flag: u64) -> bool {
        self.bits & flag == flag
    }

    /// Sets a flag.
    pub fn set(self, flag: u64) -> Self {
        Self {
            bits: self.bits | flag,
        }
    }

    /// Clears a flag.
    pub fn clear(self, flag: u64) -> Self {
        Self {
            bits: self.bits & !flag,
        }
    }
}

// -------------------------------------------------------------------
// GenericPte
// -------------------------------------------------------------------

/// Architecture-independent page table entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct GenericPte {
    /// Raw entry value.
    value: u64,
}

impl GenericPte {
    /// Creates an empty (not present) PTE.
    pub fn empty() -> Self {
        Self { value: 0 }
    }

    /// Creates a PTE mapping the given PFN with flags.
    pub fn new(pfn: u64, flags: PteFlags) -> Self {
        Self {
            value: ((pfn << PAGE_SHIFT) & PFN_MASK) | flags.bits(),
        }
    }

    /// Returns the raw value.
    pub fn value(self) -> u64 {
        self.value
    }

    /// Returns `true` if the entry is present.
    pub fn is_present(self) -> bool {
        self.value & PteFlags::PRESENT != 0
    }

    /// Returns `true` if the entry is writable.
    pub fn is_writable(self) -> bool {
        self.value & PteFlags::WRITABLE != 0
    }

    /// Returns `true` if the entry is user-accessible.
    pub fn is_user(self) -> bool {
        self.value & PteFlags::USER != 0
    }

    /// Returns the PFN.
    pub fn pfn(self) -> u64 {
        (self.value & PFN_MASK) >> PAGE_SHIFT
    }

    /// Returns the flags.
    pub fn flags(self) -> PteFlags {
        PteFlags::from_bits(self.value & !PFN_MASK)
    }

    /// Returns `true` if the dirty bit is set.
    pub fn is_dirty(self) -> bool {
        self.value & PteFlags::DIRTY != 0
    }

    /// Returns `true` if the accessed bit is set.
    pub fn is_accessed(self) -> bool {
        self.value & PteFlags::ACCESSED != 0
    }

    /// Clears the accessed bit. Returns old value.
    pub fn clear_accessed(&mut self) -> bool {
        let was = self.is_accessed();
        self.value &= !PteFlags::ACCESSED;
        was
    }

    /// Clears the dirty bit. Returns old value.
    pub fn clear_dirty(&mut self) -> bool {
        let was = self.is_dirty();
        self.value &= !PteFlags::DIRTY;
        was
    }

    /// Makes the entry read-only.
    pub fn make_readonly(&mut self) {
        self.value &= !PteFlags::WRITABLE;
    }

    /// Makes the entry writable.
    pub fn make_writable(&mut self) {
        self.value |= PteFlags::WRITABLE;
    }
}

// -------------------------------------------------------------------
// PteOp
// -------------------------------------------------------------------

/// Batch PTE operation descriptor.
#[derive(Debug, Clone, Copy)]
pub enum PteOp {
    /// Set a PTE at the given index.
    Set { index: usize, pte: GenericPte },
    /// Clear a PTE at the given index.
    Clear { index: usize },
    /// Clear the accessed bit at the given index.
    ClearAccessed { index: usize },
    /// Clear the dirty bit at the given index.
    ClearDirty { index: usize },
}

// -------------------------------------------------------------------
// PageTableLevel
// -------------------------------------------------------------------

/// Page table hierarchy levels (x86_64 4-level).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageTableLevel {
    /// PML4 (level 4).
    Pml4,
    /// Page Directory Pointer Table (level 3).
    Pdpt,
    /// Page Directory (level 2).
    Pd,
    /// Page Table (level 1).
    Pt,
}

impl PageTableLevel {
    /// Returns the level number (4 for PML4, 1 for PT).
    pub fn level(self) -> u32 {
        match self {
            Self::Pml4 => 4,
            Self::Pdpt => 3,
            Self::Pd => 2,
            Self::Pt => 1,
        }
    }

    /// Returns the page size at this level.
    pub fn page_size(self) -> u64 {
        match self {
            Self::Pml4 => 512 * 1024 * 1024 * 1024, // 512 GiB
            Self::Pdpt => 1024 * 1024 * 1024,       // 1 GiB
            Self::Pd => 2 * 1024 * 1024,            // 2 MiB
            Self::Pt => PAGE_SIZE,                  // 4 KiB
        }
    }
}

// -------------------------------------------------------------------
// GenericPageTable
// -------------------------------------------------------------------

/// A generic flat page table for simulation and testing.
pub struct GenericPageTable {
    /// PTE entries.
    entries: [GenericPte; MAX_ENTRIES],
    /// Level of this table.
    level: PageTableLevel,
}

impl GenericPageTable {
    /// Creates a new empty page table at the given level.
    pub fn new(level: PageTableLevel) -> Self {
        Self {
            entries: [GenericPte::empty(); MAX_ENTRIES],
            level,
        }
    }

    /// Returns the table level.
    pub fn level(&self) -> PageTableLevel {
        self.level
    }

    /// Sets a PTE at the given index.
    pub fn set(&mut self, index: usize, pte: GenericPte) -> Result<()> {
        if index >= MAX_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        self.entries[index] = pte;
        Ok(())
    }

    /// Gets a PTE at the given index.
    pub fn get(&self, index: usize) -> Result<GenericPte> {
        if index >= MAX_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        Ok(self.entries[index])
    }

    /// Clears a PTE at the given index.
    pub fn clear(&mut self, index: usize) -> Result<()> {
        if index >= MAX_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        self.entries[index] = GenericPte::empty();
        Ok(())
    }

    /// Applies a batch of PTE operations.
    pub fn apply_ops(&mut self, ops: &[PteOp]) -> Result<()> {
        for op in ops {
            match *op {
                PteOp::Set { index, pte } => self.set(index, pte)?,
                PteOp::Clear { index } => self.clear(index)?,
                PteOp::ClearAccessed { index } => {
                    if index >= MAX_ENTRIES {
                        return Err(Error::InvalidArgument);
                    }
                    self.entries[index].clear_accessed();
                }
                PteOp::ClearDirty { index } => {
                    if index >= MAX_ENTRIES {
                        return Err(Error::InvalidArgument);
                    }
                    self.entries[index].clear_dirty();
                }
            }
        }
        Ok(())
    }

    /// Returns the number of present entries.
    pub fn present_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_present()).count()
    }

    /// Returns the number of dirty entries.
    pub fn dirty_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.is_present() && e.is_dirty())
            .count()
    }
}
