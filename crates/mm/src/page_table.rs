// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! x86_64 4-level page table structures.
//!
//! Each page table is a 4 KiB aligned array of 512 entries.
//! Virtual address translation walks: PML4 → PDPT → PD → PT.

use crate::addr::{PhysAddr, VirtAddr};
use crate::frame::{Frame, FrameAllocator};

/// Number of entries per page table level.
pub const ENTRIES_PER_TABLE: usize = 512;

/// Page table entry flags (bits 0..11 and bit 63).
pub mod flags {
    /// Entry is present/valid.
    pub const PRESENT: u64 = 1 << 0;
    /// Page is writable.
    pub const WRITABLE: u64 = 1 << 1;
    /// Page is accessible from user mode (Ring 3).
    pub const USER: u64 = 1 << 2;
    /// Write-through caching.
    pub const WRITE_THROUGH: u64 = 1 << 3;
    /// Disable caching for this page.
    pub const NO_CACHE: u64 = 1 << 4;
    /// CPU sets this when the page is accessed.
    pub const ACCESSED: u64 = 1 << 5;
    /// CPU sets this when the page is written (leaf entries only).
    pub const DIRTY: u64 = 1 << 6;
    /// Huge page (2 MiB at PD level, 1 GiB at PDPT level).
    pub const HUGE_PAGE: u64 = 1 << 7;
    /// Global page (not flushed on CR3 switch).
    pub const GLOBAL: u64 = 1 << 8;
    /// No-execute: prevent instruction fetches from this page.
    pub const NO_EXECUTE: u64 = 1 << 63;
}

/// A single page table entry (PTE).
///
/// Contains a physical frame address and permission/status flags.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    /// An empty (not-present) entry.
    pub const EMPTY: Self = Self(0);

    /// Create a new entry with the given physical address and flags.
    ///
    /// The address must be 4 KiB aligned; lower 12 bits are used for flags.
    pub const fn new(addr: PhysAddr, entry_flags: u64) -> Self {
        Self((addr.as_u64() & 0x000F_FFFF_FFFF_F000) | entry_flags)
    }

    /// Check if the entry is present.
    pub const fn is_present(self) -> bool {
        self.0 & flags::PRESENT != 0
    }

    /// Check if the entry maps a huge page.
    pub const fn is_huge(self) -> bool {
        self.0 & flags::HUGE_PAGE != 0
    }

    /// Get the physical address stored in this entry.
    pub const fn addr(self) -> PhysAddr {
        PhysAddr::new(self.0 & 0x000F_FFFF_FFFF_F000)
    }

    /// Get the raw flags (lower 12 bits + bit 63).
    pub const fn entry_flags(self) -> u64 {
        self.0 & (0xFFF | flags::NO_EXECUTE)
    }

    /// Set new flags, preserving the address.
    pub fn set_flags(&mut self, entry_flags: u64) {
        let addr = self.0 & 0x000F_FFFF_FFFF_F000;
        self.0 = addr | entry_flags;
    }

    /// Set the entry to a new address and flags.
    pub fn set(&mut self, addr: PhysAddr, entry_flags: u64) {
        self.0 = (addr.as_u64() & 0x000F_FFFF_FFFF_F000) | entry_flags;
    }

    /// Clear the entry (mark as not-present).
    pub fn clear(&mut self) {
        self.0 = 0;
    }

    /// Get the raw u64 value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl core::fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_present() {
            write!(
                f,
                "PTE({:#x}, flags={:#x})",
                self.addr().as_u64(),
                self.entry_flags()
            )
        } else {
            write!(f, "PTE(empty)")
        }
    }
}

/// A page table: 512 entries, 4 KiB aligned.
///
/// Used for all four levels: PML4, PDPT, PD, PT.
#[repr(C, align(4096))]
pub struct PageTable {
    /// The 512 entries.
    pub entries: [PageTableEntry; ENTRIES_PER_TABLE],
}

impl PageTable {
    /// Create an empty page table (all entries not-present).
    pub const fn new() -> Self {
        Self {
            entries: [PageTableEntry::EMPTY; ENTRIES_PER_TABLE],
        }
    }

    /// Zero out all entries.
    pub fn clear(&mut self) {
        for entry in &mut self.entries {
            entry.clear();
        }
    }
}

impl Default for PageTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Flush a single page from the TLB.
///
/// # Safety
///
/// The caller must ensure this is called from Ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn flush_tlb_page(addr: u64) {
    // SAFETY: `invlpg` invalidates a single TLB entry.
    unsafe {
        core::arch::asm!(
            "invlpg [{}]",
            in(reg) addr,
            options(nostack, preserves_flags),
        );
    }
}

/// Flush the entire TLB by reloading CR3.
///
/// # Safety
///
/// The caller must ensure this is called from Ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn flush_tlb_all() {
    // SAFETY: Reading and writing CR3 flushes the entire TLB.
    unsafe {
        let cr3: u64;
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack));
        core::arch::asm!("mov cr3, {}", in(reg) cr3, options(nostack));
    }
}

// ── Page mapping helpers ────────────────────────────────────────

/// Map a virtual page to a physical frame in the given PML4.
///
/// Walks the 4-level page table, allocating intermediate tables as
/// needed from `allocator`. Sets the given flags on the final PTE.
///
/// # Safety
///
/// - `pml4` must point to a valid, writable PML4 table.
/// - The caller must ensure no conflicting mappings exist.
/// - `allocator` must return zeroed frames.
pub unsafe fn map_page(
    pml4: &mut PageTable,
    virt: VirtAddr,
    phys: PhysAddr,
    entry_flags: u64,
    allocator: &mut dyn FrameAllocator,
) -> Result<(), MapError> {
    let indices = virt.page_table_indices();
    let table_flags = flags::PRESENT | flags::WRITABLE;

    // SAFETY: Caller guarantees pml4 is valid. We walk the table
    // hierarchy, allocating intermediate tables as needed.
    unsafe {
        let pdpt = next_table_or_create(&mut pml4.entries[indices[0]], table_flags, allocator)?;
        let pd = next_table_or_create(&mut pdpt.entries[indices[1]], table_flags, allocator)?;
        let pt = next_table_or_create(&mut pd.entries[indices[2]], table_flags, allocator)?;

        let pte = &mut pt.entries[indices[3]];
        if pte.is_present() {
            return Err(MapError::AlreadyMapped);
        }
        pte.set(phys, entry_flags | flags::PRESENT);
    }
    Ok(())
}

/// Unmap a virtual page from the given PML4.
///
/// Returns the physical frame that was mapped, or `None` if the page
/// was not mapped.
///
/// # Safety
///
/// - `pml4` must point to a valid PML4 table.
/// - The caller must flush the TLB for this address after unmapping.
pub unsafe fn unmap_page(pml4: &mut PageTable, virt: VirtAddr) -> Option<Frame> {
    let indices = virt.page_table_indices();

    // SAFETY: Caller guarantees pml4 is valid.
    unsafe {
        let pdpt = next_table(&pml4.entries[indices[0]])?;
        let pd = next_table(&pdpt.entries[indices[1]])?;
        let pt = next_table(&pd.entries[indices[2]])?;

        let pte = &mut pt.entries[indices[3]];
        if !pte.is_present() {
            return None;
        }
        let frame = Frame::containing(pte.addr());
        pte.clear();
        Some(frame)
    }
}

/// Errors from page mapping operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// The virtual address is already mapped.
    AlreadyMapped,
    /// No physical frames available for page table allocation.
    OutOfFrames,
}

impl core::fmt::Display for MapError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyMapped => write!(f, "virtual address already mapped"),
            Self::OutOfFrames => write!(f, "no physical frames available"),
        }
    }
}

/// Follow a page table entry to the next level, or allocate a new table.
///
/// # Safety
///
/// The returned `&'static mut` has exclusive-by-convention semantics:
/// the caller must ensure page table walks are serialized (single CPU
/// during boot, or protected by a page-table lock during SMP).
unsafe fn next_table_or_create(
    entry: &mut PageTableEntry,
    table_flags: u64,
    allocator: &mut dyn FrameAllocator,
) -> Result<&'static mut PageTable, MapError> {
    if !entry.is_present() {
        let frame = allocator.allocate_frame().ok_or(MapError::OutOfFrames)?;
        entry.set(frame.start_addr(), table_flags);
        // SAFETY: The frame is freshly allocated. We clear it
        // immediately, and no other reference exists yet.
        let table = unsafe { &mut *(frame.start_addr().as_u64() as *mut PageTable) };
        table.clear();
        Ok(table)
    } else {
        // SAFETY: Entry is present and points to a valid page table.
        // Aliasing safety: see function-level doc.
        Ok(unsafe { &mut *(entry.addr().as_u64() as *mut PageTable) })
    }
}

/// Follow a page table entry to the next level.
///
/// # Safety
///
/// The returned `&'static mut` has exclusive-by-convention semantics.
/// The caller must ensure no two mutable references to the same table
/// exist simultaneously. Page table walks must be serialized (single
/// CPU during boot, or protected by a page-table lock during SMP).
unsafe fn next_table(entry: &PageTableEntry) -> Option<&'static mut PageTable> {
    if entry.is_present() && !entry.is_huge() {
        // SAFETY: Entry is present and points to a valid page table
        // frame. Aliasing safety: see function-level doc.
        Some(unsafe { &mut *(entry.addr().as_u64() as *mut PageTable) })
    } else {
        None
    }
}
