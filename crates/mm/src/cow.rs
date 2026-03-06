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
/// # Arguments
///
/// - `pml4`: the faulting process's root page table
/// - `fault_addr`: the virtual address that caused the fault (CR2)
/// - `error_code`: the x86_64 page fault error code
/// - `allocator`: a frame allocator for the new page
///
/// # Returns
///
/// - `Ok(Resolved)` if the CoW copy was performed and the PTE updated
/// - `Ok(NotCow)` if this is not a CoW fault
/// - `Ok(NotMapped)` if the address has no mapping
/// - `Err(OutOfMemory)` if no frames are available
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
) -> Result<PageFaultAction> {
    // Only handle write protection violations.
    if !is_cow_fault(error_code) {
        return Ok(PageFaultAction::NotCow);
    }

    let virt = VirtAddr::new(fault_addr);
    let indices = virt.page_table_indices();

    // Walk the page table to find the PTE.
    // SAFETY: Caller guarantees pml4 is valid and exclusively accessed.
    let pte = unsafe {
        let pml4e = &pml4.entries[indices[0]];
        if !pml4e.is_present() {
            return Ok(PageFaultAction::NotMapped);
        }
        let pdpt = &mut *(pml4e.addr().as_u64() as *mut PageTable);

        let pdpte = &pdpt.entries[indices[1]];
        if !pdpte.is_present() {
            return Ok(PageFaultAction::NotMapped);
        }
        let pd = &mut *(pdpte.addr().as_u64() as *mut PageTable);

        let pde = &pd.entries[indices[2]];
        if !pde.is_present() {
            return Ok(PageFaultAction::NotMapped);
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

    // This is a CoW fault. Allocate a new frame.
    let new_frame = allocator.allocate_frame().ok_or(Error::OutOfMemory)?;
    let old_phys = pte.addr();

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

    // The caller is responsible for:
    // 1. Flushing the TLB entry for this address
    // 2. Decrementing the CoW reference count for old_phys
    // 3. If the old frame's ref count reaches 1, upgrading the
    //    remaining mapping to writable (removing COW_BIT)

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

    let mut marked = 0;
    let mut addr = page_start;

    while addr < page_end {
        let virt = VirtAddr::new(addr);
        let indices = virt.page_table_indices();

        // Walk through the page table levels. If any level is
        // not present, skip this page.
        // SAFETY: Caller guarantees pml4 is valid.
        let pte = unsafe {
            let pml4e = &pml4.entries[indices[0]];
            if !pml4e.is_present() {
                addr = addr.saturating_add(PAGE_SIZE as u64);
                continue;
            }
            let pdpt = &mut *(pml4e.addr().as_u64() as *mut PageTable);

            let pdpte = &pdpt.entries[indices[1]];
            if !pdpte.is_present() {
                addr = addr.saturating_add(PAGE_SIZE as u64);
                continue;
            }
            let pd = &mut *(pdpte.addr().as_u64() as *mut PageTable);

            let pde = &pd.entries[indices[2]];
            if !pde.is_present() {
                addr = addr.saturating_add(PAGE_SIZE as u64);
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
