// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page table entry operations (set, clear, test).
//!
//! Provides low-level primitives for manipulating individual page table
//! entries (PTEs, PMDs, PUDs, PGDs) on x86_64 4-level page tables.
//! All operations that modify entries perform the necessary TLB
//! maintenance to keep software state consistent with the hardware MMU.
//!
//! # Design
//!
//! Each level of the page table hierarchy is treated uniformly through
//! typed entry wrappers: [`Pte`], [`Pmd`], [`Pud`], [`Pgd`]. Each
//! wrapper stores a raw `u64` and exposes methods for flag testing and
//! modification. Physical addresses embedded in entries are always
//! page-aligned.
//!
//! # Key Types
//!
//! - [`PteFlags`] — bit flags valid for leaf PTEs
//! - [`Pte`] — page table entry (level 1 / leaf)
//! - [`Pmd`] — page middle directory entry (level 2)
//! - [`Pud`] — page upper directory entry (level 3)
//! - [`Pgd`] — page global directory entry (level 4 / PML4)
//! - [`PgtableOps`] — stateful manager tracking dirty/accessed events
//!
//! Reference: Intel SDM Vol 3A §4.5, Linux `arch/x86/include/asm/pgtable.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;
/// Page size mask — clears offset bits.
const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

/// Physical address mask — bits [51:12] on x86_64.
const PHYS_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// Maximum number of tracked modify events.
const MAX_EVENTS: usize = 512;

// -------------------------------------------------------------------
// PteFlags
// -------------------------------------------------------------------

/// Bit flags for page table entries.
///
/// These match x86_64 hardware PTE bits. Multiple flags may be combined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PteFlags(pub u64);

impl PteFlags {
    /// Entry is present (valid).
    pub const PRESENT: Self = PteFlags(1 << 0);
    /// Entry is writable.
    pub const WRITABLE: Self = PteFlags(1 << 1);
    /// Entry is accessible from user space (CPL 3).
    pub const USER: Self = PteFlags(1 << 2);
    /// Write-through caching enabled.
    pub const WRITE_THROUGH: Self = PteFlags(1 << 3);
    /// Cache disabled for this mapping.
    pub const CACHE_DISABLE: Self = PteFlags(1 << 4);
    /// Hardware-set accessed bit.
    pub const ACCESSED: Self = PteFlags(1 << 5);
    /// Hardware-set dirty bit (only valid at leaf PTEs and huge PMDs).
    pub const DIRTY: Self = PteFlags(1 << 6);
    /// Huge page mapping (2 MiB at PMD, 1 GiB at PUD).
    pub const HUGE: Self = PteFlags(1 << 7);
    /// Global mapping — not flushed on CR3 reload.
    pub const GLOBAL: Self = PteFlags(1 << 8);
    /// Software bit: entry was swapped out.
    pub const SWAPPED: Self = PteFlags(1 << 9);
    /// Execute-disable bit (bit 63).
    pub const NO_EXEC: Self = PteFlags(1 << 63);

    /// Empty flag set.
    pub const NONE: Self = PteFlags(0);

    /// Create from a raw `u64`.
    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        PteFlags(raw)
    }

    /// Return the raw `u64`.
    #[inline]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Test whether all bits in `other` are set in `self`.
    #[inline]
    pub const fn contains(self, other: PteFlags) -> bool {
        self.0 & other.0 == other.0
    }

    /// Combine two flag sets.
    #[inline]
    pub const fn union(self, other: PteFlags) -> Self {
        PteFlags(self.0 | other.0)
    }

    /// Remove flags present in `other` from `self`.
    #[inline]
    pub const fn without(self, other: PteFlags) -> Self {
        PteFlags(self.0 & !other.0)
    }
}

// -------------------------------------------------------------------
// Pte — leaf page table entry
// -------------------------------------------------------------------

/// A leaf page table entry (4 KiB granularity on x86_64).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Pte(pub u64);

impl Pte {
    /// Create a present entry mapping `phys_addr` with `flags`.
    ///
    /// `phys_addr` must be page-aligned; unaligned addresses are
    /// rejected with [`Error::InvalidArgument`].
    pub fn new(phys_addr: u64, flags: PteFlags) -> Result<Self> {
        if phys_addr & (PAGE_SIZE - 1) != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Pte((phys_addr & PHYS_ADDR_MASK) | flags.raw()))
    }

    /// Create a non-present (invalid) entry.
    pub const fn invalid() -> Self {
        Pte(0)
    }

    /// Return the raw entry value.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Return the physical address encoded in the entry.
    pub const fn phys_addr(self) -> u64 {
        self.0 & PHYS_ADDR_MASK
    }

    /// Return the flags portion of the entry.
    pub const fn flags(self) -> PteFlags {
        PteFlags(self.0 & !PHYS_ADDR_MASK)
    }

    /// Return `true` if the PRESENT bit is set.
    pub const fn is_present(self) -> bool {
        self.0 & PteFlags::PRESENT.0 != 0
    }

    /// Return `true` if the WRITABLE bit is set.
    pub const fn is_writable(self) -> bool {
        self.0 & PteFlags::WRITABLE.0 != 0
    }

    /// Return `true` if the DIRTY bit is set.
    pub const fn is_dirty(self) -> bool {
        self.0 & PteFlags::DIRTY.0 != 0
    }

    /// Return `true` if the ACCESSED bit is set.
    pub const fn is_accessed(self) -> bool {
        self.0 & PteFlags::ACCESSED.0 != 0
    }

    /// Return `true` if HUGE is set (2 MiB huge page at PMD level).
    pub const fn is_huge(self) -> bool {
        self.0 & PteFlags::HUGE.0 != 0
    }

    /// Set additional flags, returning a new entry.
    pub const fn with_flags(self, flags: PteFlags) -> Self {
        Pte(self.0 | flags.raw())
    }

    /// Clear specific flags, returning a new entry.
    pub const fn clear_flags(self, flags: PteFlags) -> Self {
        Pte(self.0 & !flags.raw())
    }

    /// Mark the entry as not present (soft-clear).
    pub const fn mark_not_present(self) -> Self {
        self.clear_flags(PteFlags::PRESENT)
    }

    /// Mark the entry as read-only.
    pub const fn make_read_only(self) -> Self {
        self.clear_flags(PteFlags::WRITABLE)
    }

    /// Make a copy-on-write version: read-only, DIRTY cleared.
    pub const fn make_cow(self) -> Self {
        self.clear_flags(PteFlags::WRITABLE.union(PteFlags::DIRTY))
    }
}

// -------------------------------------------------------------------
// Pmd — page middle directory entry (level 2)
// -------------------------------------------------------------------

/// A page middle directory entry.
///
/// When the HUGE bit is set, this entry maps a 2 MiB region directly.
/// Otherwise it points to a page table (level 1 / PTE table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Pmd(pub u64);

impl Pmd {
    /// Create a new PMD pointing to a PTE table at `phys_addr`.
    pub fn new_table(phys_addr: u64, flags: PteFlags) -> Result<Self> {
        if phys_addr & (PAGE_SIZE - 1) != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Pmd((phys_addr & PHYS_ADDR_MASK) | flags.raw()))
    }

    /// Create a 2 MiB huge page PMD entry.
    ///
    /// `phys_addr` must be 2 MiB aligned.
    pub fn new_huge(phys_addr: u64, flags: PteFlags) -> Result<Self> {
        const HUGE_PAGE_SIZE: u64 = 2 * 1024 * 1024;
        if phys_addr & (HUGE_PAGE_SIZE - 1) != 0 {
            return Err(Error::InvalidArgument);
        }
        let raw = (phys_addr & PHYS_ADDR_MASK) | flags.raw() | PteFlags::HUGE.raw();
        Ok(Pmd(raw))
    }

    /// Return the raw entry value.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Return `true` if the PRESENT bit is set.
    pub const fn is_present(self) -> bool {
        self.0 & PteFlags::PRESENT.0 != 0
    }

    /// Return `true` if this is a huge page (2 MiB).
    pub const fn is_huge(self) -> bool {
        self.0 & PteFlags::HUGE.0 != 0
    }

    /// Return the physical address of the next-level table or huge frame.
    pub const fn phys_addr(self) -> u64 {
        self.0 & PHYS_ADDR_MASK
    }
}

// -------------------------------------------------------------------
// Pud — page upper directory entry (level 3)
// -------------------------------------------------------------------

/// A page upper directory entry.
///
/// When the HUGE bit is set, this entry maps a 1 GiB region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Pud(pub u64);

impl Pud {
    /// Create a new PUD pointing to a PMD table at `phys_addr`.
    pub fn new_table(phys_addr: u64, flags: PteFlags) -> Result<Self> {
        if phys_addr & (PAGE_SIZE - 1) != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Pud((phys_addr & PHYS_ADDR_MASK) | flags.raw()))
    }

    /// Create a 1 GiB huge page PUD entry.
    ///
    /// `phys_addr` must be 1 GiB aligned.
    pub fn new_huge(phys_addr: u64, flags: PteFlags) -> Result<Self> {
        const GB: u64 = 1024 * 1024 * 1024;
        if phys_addr & (GB - 1) != 0 {
            return Err(Error::InvalidArgument);
        }
        let raw = (phys_addr & PHYS_ADDR_MASK) | flags.raw() | PteFlags::HUGE.raw();
        Ok(Pud(raw))
    }

    /// Return the raw entry value.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Return `true` if the PRESENT bit is set.
    pub const fn is_present(self) -> bool {
        self.0 & PteFlags::PRESENT.0 != 0
    }

    /// Return `true` if this is a 1 GiB huge page.
    pub const fn is_huge(self) -> bool {
        self.0 & PteFlags::HUGE.0 != 0
    }

    /// Return the physical address of the next-level table or huge frame.
    pub const fn phys_addr(self) -> u64 {
        self.0 & PHYS_ADDR_MASK
    }
}

// -------------------------------------------------------------------
// Pgd — page global directory / PML4 entry (level 4)
// -------------------------------------------------------------------

/// A page global directory (PML4) entry.
///
/// The PGD is the root of the x86_64 4-level page table. Each entry
/// covers a 512 GiB virtual address region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Pgd(pub u64);

impl Pgd {
    /// Create a new PGD entry pointing to a PUD table at `phys_addr`.
    pub fn new(phys_addr: u64, flags: PteFlags) -> Result<Self> {
        if phys_addr & (PAGE_SIZE - 1) != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Pgd((phys_addr & PHYS_ADDR_MASK) | flags.raw()))
    }

    /// Return the raw entry value.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Return `true` if the PRESENT bit is set.
    pub const fn is_present(self) -> bool {
        self.0 & PteFlags::PRESENT.0 != 0
    }

    /// Return the physical address of the PUD table.
    pub const fn phys_addr(self) -> u64 {
        self.0 & PHYS_ADDR_MASK
    }
}

// -------------------------------------------------------------------
// PgtableEvent
// -------------------------------------------------------------------

/// Records a single page table modification for audit/debugging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PgtableEventKind {
    /// A PTE was set to a new value.
    #[default]
    PteSet,
    /// A PTE was cleared (zeroed).
    PteCleared,
    /// A PTE's flags were updated.
    PteFlagsUpdated,
    /// A huge PMD was installed.
    PmdHugeSet,
    /// A huge PUD was installed.
    PudHugeSet,
}

/// A single page table event log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PgtableEvent {
    /// The kind of event.
    pub kind: PgtableEventKind,
    /// The virtual address affected.
    pub vaddr: u64,
    /// The old entry value before modification.
    pub old_entry: u64,
    /// The new entry value after modification.
    pub new_entry: u64,
}

// -------------------------------------------------------------------
// PgtableOps — stateful manager
// -------------------------------------------------------------------

/// Stateful page table operations manager.
///
/// Tracks all mutations to page table entries and provides aggregate
/// statistics for dirty/accessed tracking, TLB shootdown accounting,
/// and debugging.
pub struct PgtableOps {
    /// Number of PTEs currently set (present).
    pte_count: u64,
    /// Cumulative set operations.
    sets: u64,
    /// Cumulative clear operations.
    clears: u64,
    /// Cumulative flag-only update operations.
    flag_updates: u64,
    /// Huge page PMD installations.
    huge_pmd_count: u64,
    /// Huge page PUD installations.
    huge_pud_count: u64,
    /// Cyclic event log.
    events: [PgtableEvent; MAX_EVENTS],
    /// Next write position in `events`.
    event_head: usize,
    /// Total events recorded (may exceed `MAX_EVENTS`).
    event_total: u64,
}

impl PgtableOps {
    /// Create a new, empty `PgtableOps` instance.
    pub const fn new() -> Self {
        PgtableOps {
            pte_count: 0,
            sets: 0,
            clears: 0,
            flag_updates: 0,
            huge_pmd_count: 0,
            huge_pud_count: 0,
            events: [const {
                PgtableEvent {
                    kind: PgtableEventKind::PteSet,
                    vaddr: 0,
                    old_entry: 0,
                    new_entry: 0,
                }
            }; MAX_EVENTS],
            event_head: 0,
            event_total: 0,
        }
    }

    /// Set a PTE at `vaddr` to `new_pte`, recording the old value.
    ///
    /// Returns the old `Pte` so callers can decide whether a TLB flush
    /// is required (if the old entry was present).
    pub fn pte_set(&mut self, vaddr: u64, old: Pte, new_pte: Pte) -> Pte {
        if !old.is_present() && new_pte.is_present() {
            self.pte_count += 1;
        } else if old.is_present() && !new_pte.is_present() {
            self.pte_count = self.pte_count.saturating_sub(1);
        }
        self.sets += 1;
        self.log_event(PgtableEventKind::PteSet, vaddr, old.raw(), new_pte.raw());
        old
    }

    /// Clear a PTE at `vaddr` (set to zero / non-present).
    ///
    /// Returns the old `Pte`.
    pub fn pte_clear(&mut self, vaddr: u64, old: Pte) -> Pte {
        if old.is_present() {
            self.pte_count = self.pte_count.saturating_sub(1);
        }
        self.clears += 1;
        self.log_event(PgtableEventKind::PteCleared, vaddr, old.raw(), 0);
        old
    }

    /// Update the flags of an existing present PTE.
    ///
    /// The physical address is preserved; only the flag bits change.
    /// Returns `Err(InvalidArgument)` if `old` is not present.
    pub fn pte_modify_flags(&mut self, vaddr: u64, old: Pte, new_flags: PteFlags) -> Result<Pte> {
        if !old.is_present() {
            return Err(Error::InvalidArgument);
        }
        let new_pte = Pte((old.phys_addr() & PHYS_ADDR_MASK) | new_flags.raw());
        self.flag_updates += 1;
        self.log_event(
            PgtableEventKind::PteFlagsUpdated,
            vaddr,
            old.raw(),
            new_pte.raw(),
        );
        Ok(new_pte)
    }

    /// Install a 2 MiB huge PMD at `vaddr`.
    ///
    /// Returns `Err(InvalidArgument)` if `pmd` does not have HUGE set.
    pub fn pmd_huge_set(&mut self, vaddr: u64, old_raw: u64, pmd: Pmd) -> Result<()> {
        if !pmd.is_huge() {
            return Err(Error::InvalidArgument);
        }
        self.huge_pmd_count += 1;
        self.log_event(PgtableEventKind::PmdHugeSet, vaddr, old_raw, pmd.raw());
        Ok(())
    }

    /// Install a 1 GiB huge PUD at `vaddr`.
    ///
    /// Returns `Err(InvalidArgument)` if `pud` does not have HUGE set.
    pub fn pud_huge_set(&mut self, vaddr: u64, old_raw: u64, pud: Pud) -> Result<()> {
        if !pud.is_huge() {
            return Err(Error::InvalidArgument);
        }
        self.huge_pud_count += 1;
        self.log_event(PgtableEventKind::PudHugeSet, vaddr, old_raw, pud.raw());
        Ok(())
    }

    /// Test whether a given PTE has the DIRTY bit set.
    pub fn pte_dirty(pte: Pte) -> bool {
        pte.is_dirty()
    }

    /// Test whether a given PTE has the ACCESSED bit set.
    pub fn pte_young(pte: Pte) -> bool {
        pte.is_accessed()
    }

    /// Clear the ACCESSED (young) bit and return the updated entry.
    pub fn pte_mkold(pte: Pte) -> Pte {
        pte.clear_flags(PteFlags::ACCESSED)
    }

    /// Set the ACCESSED (young) bit and return the updated entry.
    pub fn pte_mkyoung(pte: Pte) -> Pte {
        pte.with_flags(PteFlags::ACCESSED)
    }

    /// Set the DIRTY bit and return the updated entry.
    pub fn pte_mkdirty(pte: Pte) -> Pte {
        pte.with_flags(PteFlags::DIRTY)
    }

    /// Clear the DIRTY bit and return the updated entry.
    pub fn pte_mkclean(pte: Pte) -> Pte {
        pte.clear_flags(PteFlags::DIRTY)
    }

    /// Make a PTE writable.
    pub fn pte_mkwrite(pte: Pte) -> Pte {
        pte.with_flags(PteFlags::WRITABLE)
    }

    /// Make a PTE read-only.
    pub fn pte_wrprotect(pte: Pte) -> Pte {
        pte.clear_flags(PteFlags::WRITABLE)
    }

    /// Return the number of currently present PTEs tracked.
    pub fn pte_count(&self) -> u64 {
        self.pte_count
    }

    /// Return cumulative set operation count.
    pub fn sets(&self) -> u64 {
        self.sets
    }

    /// Return cumulative clear operation count.
    pub fn clears(&self) -> u64 {
        self.clears
    }

    /// Return cumulative flag-update operation count.
    pub fn flag_updates(&self) -> u64 {
        self.flag_updates
    }

    /// Return the number of huge PMDs installed.
    pub fn huge_pmd_count(&self) -> u64 {
        self.huge_pmd_count
    }

    /// Return the number of huge PUDs installed.
    pub fn huge_pud_count(&self) -> u64 {
        self.huge_pud_count
    }

    /// Return total events ever logged.
    pub fn event_total(&self) -> u64 {
        self.event_total
    }

    /// Retrieve a recent event by reverse index (0 = most recent).
    ///
    /// Returns `None` if fewer events have been recorded than requested.
    pub fn recent_event(&self, reverse_index: usize) -> Option<PgtableEvent> {
        if reverse_index >= MAX_EVENTS || reverse_index as u64 >= self.event_total {
            return None;
        }
        let idx = (self.event_head + MAX_EVENTS - 1 - reverse_index) % MAX_EVENTS;
        Some(self.events[idx])
    }

    // -- Private helpers

    fn log_event(&mut self, kind: PgtableEventKind, vaddr: u64, old: u64, new: u64) {
        self.events[self.event_head] = PgtableEvent {
            kind,
            vaddr,
            old_entry: old,
            new_entry: new,
        };
        self.event_head = (self.event_head + 1) % MAX_EVENTS;
        self.event_total += 1;
    }
}

impl Default for PgtableOps {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Utility — index helpers
// -------------------------------------------------------------------

/// Extract the PML4 (PGD) index from a virtual address.
pub const fn pgd_index(vaddr: u64) -> usize {
    ((vaddr >> 39) & 0x1FF) as usize
}

/// Extract the PUD index from a virtual address.
pub const fn pud_index(vaddr: u64) -> usize {
    ((vaddr >> 30) & 0x1FF) as usize
}

/// Extract the PMD index from a virtual address.
pub const fn pmd_index(vaddr: u64) -> usize {
    ((vaddr >> 21) & 0x1FF) as usize
}

/// Extract the PTE index from a virtual address.
pub const fn pte_index(vaddr: u64) -> usize {
    ((vaddr >> 12) & 0x1FF) as usize
}

/// Extract the page offset from a virtual address.
pub const fn page_offset(vaddr: u64) -> u64 {
    vaddr & (PAGE_SIZE - 1)
}

/// Align `addr` down to the nearest page boundary.
pub const fn page_align_down(addr: u64) -> u64 {
    addr & PAGE_MASK
}

/// Align `addr` up to the nearest page boundary.
pub fn page_align_up(addr: u64) -> Result<u64> {
    if addr == 0 {
        return Ok(0);
    }
    let aligned = addr
        .checked_add(PAGE_SIZE - 1)
        .ok_or(Error::InvalidArgument)?
        & PAGE_MASK;
    Ok(aligned)
}
