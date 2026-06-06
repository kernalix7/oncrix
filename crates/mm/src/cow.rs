// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Copy-on-Write (CoW) page fault handler.
//!
//! After `fork()`, parent and child share physical pages mapped as
//! read-only. When either process writes to a shared page, a page
//! fault occurs. This module handles that fault by:
//!
//! 1. Allocating a new physical frame
//! 2. Copying the contents of the shared page to the new frame
//! 3. Remapping the faulting address to the new frame with write permission
//! 4. Updating the CoW reference count
//!
//! This is the standard lazy copy strategy used by all modern
//! Unix-like operating systems.

use crate::addr::{PAGE_SIZE, VirtAddr};
use crate::frame::FrameAllocator;
use crate::page_ref_count::PageRefTable;
use crate::page_table::{PageTable, PageTableEntry, flags};
use oncrix_lib::{Error, Result};

/// x86_64 page fault error code bits.
pub mod error_code {
    /// Fault caused by a page-level protection violation (vs. not-present).
    pub const PROTECTION: u64 = 1 << 0;
    /// Fault caused by a write access.
    pub const WRITE: u64 = 1 << 1;
    /// Fault occurred in user mode.
    pub const USER: u64 = 1 << 2;
    /// Fault caused by reading a reserved bit.
    pub const RESERVED_WRITE: u64 = 1 << 3;
    /// Fault caused by an instruction fetch.
    pub const INSTRUCTION_FETCH: u64 = 1 << 4;
}

/// Result of handling a page fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageFaultAction {
    /// CoW copy completed — the faulting instruction can be retried.
    Resolved,
    /// Not a CoW fault — the caller should handle it differently
    /// (e.g., deliver SIGSEGV or allocate a demand page).
    NotCow,
    /// The fault address is not mapped at all.
    NotMapped,
}

/// Custom PTE flag: marks a page as copy-on-write.
///
/// We use bit 9 (one of the OS-available bits in x86_64 PTEs) to
/// distinguish CoW pages from genuinely read-only pages.
pub const COW_BIT: u64 = 1 << 9;

/// Check if a page fault is a CoW fault.
///
/// A CoW fault is a write to a present, non-writable page that has
/// the `COW_BIT` set in its PTE.
pub fn is_cow_fault(error_code: u64) -> bool {
    // Must be a protection violation on a write (not a not-present fault).
    error_code & error_code::PROTECTION != 0 && error_code & error_code::WRITE != 0
}

/// Handle a copy-on-write page fault.
///
/// The faulting frame's reference count (tracked in `refs`, keyed by
/// PFN) decides the outcome:
///
/// - **count == 1** — this mapping is the sole owner. No copy is made:
///   the PTE is upgraded in place by setting `WRITABLE` and clearing
///   `COW_BIT`, so subsequent writes no longer fault. This is the
///   "reuse" path Linux takes when `page_mapcount() == 1`.
/// - **count > 1** — the frame is still shared. A new frame is
///   allocated, the contents are copied, and the PTE is repointed at
///   the new frame (writable, no `COW_BIT`). The old frame's reference
///   count is then dropped exactly once via [`PageRefTable::put_page`],
///   and the new frame is registered with an initial count of 1.
///
/// Both paths leave the faulting mapping writable and never expose a
/// still-shared frame as writable, so the contract is self-contained
/// and no separate caller step is required.
///
/// # Arguments
///
/// - `pml4`: the faulting process's root page table
/// - `fault_addr`: the virtual address that caused the fault (CR2)
/// - `error_code`: the x86_64 page fault error code
/// - `allocator`: a frame allocator for the new page
/// - `refs`: per-PFN reference counts for shared frames
///
/// # Returns
///
/// - `Ok(Resolved)` if the CoW fault was handled and the PTE updated
/// - `Ok(NotCow)` if this is not a CoW fault
/// - `Ok(NotMapped)` if the address has no mapping
/// - `Err(OutOfMemory)` if no frames are available
/// - `Err(NotFound)` if the faulting frame is not tracked in `refs`
///
/// # Safety
///
/// - `pml4` must point to a valid PML4 table for the faulting process.
/// - The caller must ensure exclusive access to the page tables
///   (e.g., by holding a page-table lock or running single-threaded).
/// - After this function returns `Resolved`, the caller must flush
///   the TLB entry for `fault_addr`.
pub unsafe fn handle_cow_fault(
    pml4: &mut PageTable,
    fault_addr: u64,
    error_code: u64,
    allocator: &mut dyn FrameAllocator,
    refs: &mut PageRefTable,
) -> Result<PageFaultAction> {
    // Only handle write protection violations.
    if !is_cow_fault(error_code) {
        return Ok(PageFaultAction::NotCow);
    }

    let virt = VirtAddr::new(fault_addr);
    let indices = virt.page_table_indices();

    // Walk the page table to find the PTE.
    //
    // At every non-leaf level we must reject huge entries before
    // descending: a present entry with `HUGE_PAGE` set maps a 1 GiB
    // (PDPT) or 2 MiB (PD) data frame, not a sub-table. Its stored
    // address is the huge frame base, so casting it to `*mut PageTable`
    // and indexing `entries[..]` would interpret attacker-mapped data
    // as PTEs and later write an 8-byte "PTE" into that data frame at a
    // CR2-controlled offset. This mirrors the `!is_huge()` guard used by
    // `next_table()`/`next_table_or_create()` in `page_table.rs`. Huge
    // CoW mappings are not handled here; defer to the generic handler.
    // SAFETY: Caller guarantees pml4 is valid and exclusively accessed.
    let pte = unsafe {
        let pml4e = &pml4.entries[indices[0]];
        if !pml4e.is_present() {
            return Ok(PageFaultAction::NotMapped);
        }
        if pml4e.is_huge() {
            return Ok(PageFaultAction::NotCow);
        }
        let pdpt = &mut *(pml4e.addr().as_u64() as *mut PageTable);

        let pdpte = &pdpt.entries[indices[1]];
        if !pdpte.is_present() {
            return Ok(PageFaultAction::NotMapped);
        }
        if pdpte.is_huge() {
            // 1 GiB huge mapping — not a CoW 4 KiB page.
            return Ok(PageFaultAction::NotCow);
        }
        let pd = &mut *(pdpte.addr().as_u64() as *mut PageTable);

        let pde = &pd.entries[indices[2]];
        if !pde.is_present() {
            return Ok(PageFaultAction::NotMapped);
        }
        if pde.is_huge() {
            // 2 MiB huge mapping — not a CoW 4 KiB page.
            return Ok(PageFaultAction::NotCow);
        }
        let pt = &mut *(pde.addr().as_u64() as *mut PageTable);

        &mut pt.entries[indices[3]]
    };

    if !pte.is_present() {
        return Ok(PageFaultAction::NotMapped);
    }

    // Check if this PTE has the CoW bit set.
    if pte.entry_flags() & COW_BIT == 0 {
        // Present but not CoW — this is a genuine protection fault
        // (e.g., writing to a truly read-only .text page).
        return Ok(PageFaultAction::NotCow);
    }

    // This is a CoW fault. Consult the reference count for the frame
    // this mapping currently points at.
    let old_phys = pte.addr();
    let old_pfn = old_phys.as_u64() / PAGE_SIZE as u64;
    let shared = match refs.lookup(old_pfn) {
        Some(page) => page.count() > 1,
        None => return Err(Error::NotFound),
    };

    if !shared {
        // Sole owner — reuse the frame in place. No new frame, no copy:
        // just grant write access and drop the CoW marker so subsequent
        // writes do not fault. The reference count is already 1, so
        // nothing else maps this frame and it is safe to make writable.
        let old_flags = pte.entry_flags();
        let new_flags = (old_flags | flags::WRITABLE) & !COW_BIT;
        pte.set_flags(new_flags);
        return Ok(PageFaultAction::Resolved);
    }

    // Shared frame — allocate a private copy.
    let new_frame = allocator.allocate_frame().ok_or(Error::OutOfMemory)?;
    let new_pfn = new_frame.start_addr().as_u64() / PAGE_SIZE as u64;

    // Register the new frame's refcount BEFORE mutating the PTE. If the
    // table is full this fails cleanly with the old mapping intact and
    // the freshly allocated frame returned to the allocator.
    if let Err(e) = refs.register(new_pfn) {
        allocator.deallocate_frame(new_frame);
        return Err(e);
    }

    // Copy the old page contents to the new frame.
    // SAFETY: Both old and new frame addresses point to valid 4 KiB
    // physical memory regions. The old page is mapped (PTE is present)
    // and the new frame was just allocated.
    unsafe {
        core::ptr::copy_nonoverlapping(
            old_phys.as_u64() as *const u8,
            new_frame.start_addr().as_u64() as *mut u8,
            PAGE_SIZE,
        );
    }

    // Update the PTE: point to new frame, add WRITABLE, remove COW_BIT.
    let old_flags = pte.entry_flags();
    let new_flags = (old_flags | flags::WRITABLE) & !COW_BIT;
    pte.set(new_frame.start_addr(), new_flags);

    // This mapping no longer references the old frame; drop its count
    // exactly once. The lookup above proved it is present with count > 1,
    // so this put cannot underflow and cannot free a frame still mapped
    // elsewhere. The caller must still flush the TLB for `fault_addr`.
    let _ = refs.put_page(old_pfn);

    Ok(PageFaultAction::Resolved)
}

/// Mark a PTE as copy-on-write.
///
/// Clears the WRITABLE flag and sets the COW_BIT so that writes
/// trigger a page fault handled by [`handle_cow_fault`].
///
/// # Safety
///
/// - `pte` must point to a valid, present page table entry.
/// - The caller must flush the TLB after marking entries as CoW.
pub unsafe fn mark_cow(pte: &mut PageTableEntry) {
    if pte.is_present() {
        let f = pte.entry_flags();
        let new_flags = (f & !flags::WRITABLE) | COW_BIT;
        pte.set_flags(new_flags);
    }
}

/// Mark a range of pages as copy-on-write in a page table.
///
/// Walks the 4-level page table and marks every present, writable
/// leaf PTE in `[start, start + size)` as CoW.
///
/// # Safety
///
/// - `pml4` must point to a valid PML4 table.
/// - The caller must flush the TLB for all modified pages afterward.
pub unsafe fn mark_region_cow(pml4: &mut PageTable, start: u64, size: u64) -> usize {
    let page_start = start & !(PAGE_SIZE as u64 - 1);
    let page_end = (start
        .saturating_add(size)
        .saturating_add(PAGE_SIZE as u64 - 1))
        & !(PAGE_SIZE as u64 - 1);

    // Huge-page strides: a PD entry with HUGE_PAGE maps 2 MiB, a PDPT
    // entry with HUGE_PAGE maps 1 GiB.
    const PAGES_PER_TABLE: u64 = 512;
    const HUGE_2M_STRIDE: u64 = PAGES_PER_TABLE * PAGE_SIZE as u64;
    const HUGE_1G_STRIDE: u64 = PAGES_PER_TABLE * HUGE_2M_STRIDE;

    let mut marked = 0;
    let mut addr = page_start;

    while addr < page_end {
        let virt = VirtAddr::new(addr);
        let indices = virt.page_table_indices();

        // Walk through the page table levels. If any level is
        // not present, skip this page. A huge entry at any non-leaf
        // level maps a 2 MiB/1 GiB data frame, not a sub-table:
        // descending into it would reinterpret that data as 512 PTEs
        // and clobber WRITABLE bits inside the mapped frame. Skip the
        // whole huge region (advance by its stride), mirroring the
        // `!is_huge()` guard in `next_table()`.
        // SAFETY: Caller guarantees pml4 is valid.
        let pte = unsafe {
            let pml4e = &pml4.entries[indices[0]];
            if !pml4e.is_present() || pml4e.is_huge() {
                addr = addr.saturating_add(PAGE_SIZE as u64);
                continue;
            }
            let pdpt = &mut *(pml4e.addr().as_u64() as *mut PageTable);

            let pdpte = &pdpt.entries[indices[1]];
            if !pdpte.is_present() {
                addr = addr.saturating_add(PAGE_SIZE as u64);
                continue;
            }
            if pdpte.is_huge() {
                // 1 GiB huge mapping: advance past it, aligned down to
                // the 1 GiB boundary so the next iteration lands on the
                // following region.
                let next = (addr & !(HUGE_1G_STRIDE - 1)).saturating_add(HUGE_1G_STRIDE);
                addr = next.max(addr.saturating_add(PAGE_SIZE as u64));
                continue;
            }
            let pd = &mut *(pdpte.addr().as_u64() as *mut PageTable);

            let pde = &pd.entries[indices[2]];
            if !pde.is_present() {
                addr = addr.saturating_add(PAGE_SIZE as u64);
                continue;
            }
            if pde.is_huge() {
                // 2 MiB huge mapping: advance past it.
                let next = (addr & !(HUGE_2M_STRIDE - 1)).saturating_add(HUGE_2M_STRIDE);
                addr = next.max(addr.saturating_add(PAGE_SIZE as u64));
                continue;
            }
            let pt = &mut *(pde.addr().as_u64() as *mut PageTable);

            &mut pt.entries[indices[3]]
        };

        if pte.is_present() && pte.entry_flags() & flags::WRITABLE != 0 {
            // SAFETY: PTE is valid and present.
            unsafe {
                mark_cow(pte);
            }
            marked += 1;
        }

        addr = addr.saturating_add(PAGE_SIZE as u64);
    }

    marked
}
