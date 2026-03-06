// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Page table hardware: CR3 load and TLB flush operations.
//!
//! This module provides the hardware interface between the memory management
//! subsystem and the CPU's paging hardware:
//!
//! - **CR3 switching** — load a new page table root.
//! - **TLB invalidation** — `invlpg` for single pages, full TLB flush via CR3 reload.
//! - **INVPCID** — process-context-ID-aware TLB invalidation (when available).
//! - **PCID helpers** — construct and strip PCID tags from CR3 values.
//! - **Page fault helpers** — read CR2 after a #PF.
//!
//! Reference: Intel 64 and IA-32 Architectures Software Developer's Manual,
//! Volume 3A, Chapter 4 — Paging; §4.10 — Invalidating TLBs.

// ---------------------------------------------------------------------------
// Page size constants
// ---------------------------------------------------------------------------

/// 4 KiB page size.
pub const PAGE_SIZE_4K: u64 = 4 * 1024;
/// 2 MiB huge page size (PDE with PS bit).
pub const PAGE_SIZE_2M: u64 = 2 * 1024 * 1024;
/// 1 GiB huge page size (PDPTE with PS bit).
pub const PAGE_SIZE_1G: u64 = 1024 * 1024 * 1024;

/// Page alignment mask for 4 KiB pages.
pub const PAGE_MASK_4K: u64 = !(PAGE_SIZE_4K - 1);

// ---------------------------------------------------------------------------
// PCID constants
// ---------------------------------------------------------------------------

/// PCID field mask in CR3 (bits 11:0).
pub const CR3_PCID_MASK: u64 = 0x0FFF;
/// CR3 physical address mask (bits 51:12).
pub const CR3_PHYS_MASK: u64 = 0x000F_FFFF_FFFF_F000;
/// CR3 bit 63: no-flush flag (skip TLB flush when PCIDE=1).
pub const CR3_NOFLUSH: u64 = 1u64 << 63;

// ---------------------------------------------------------------------------
// CR3 helpers
// ---------------------------------------------------------------------------

/// Builds a CR3 value from a physical PML4 address and a PCID.
///
/// # Parameters
/// - `pml4_phys`: Physical address of the PML4 table (must be 4 KiB aligned).
/// - `pcid`: Process-Context ID (12-bit; 0 if PCIDE is disabled).
pub const fn make_cr3(pml4_phys: u64, pcid: u16) -> u64 {
    (pml4_phys & CR3_PHYS_MASK) | (pcid as u64 & CR3_PCID_MASK)
}

/// Extracts the physical address from a CR3 value.
pub const fn cr3_phys(cr3: u64) -> u64 {
    cr3 & CR3_PHYS_MASK
}

/// Extracts the PCID from a CR3 value.
pub const fn cr3_pcid(cr3: u64) -> u16 {
    (cr3 & CR3_PCID_MASK) as u16
}

// ---------------------------------------------------------------------------
// CR3 read/write
// ---------------------------------------------------------------------------

/// Reads the current CR3 (page table base + PCID).
///
/// # Safety
/// Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_cr3() -> u64 {
    let val: u64;
    // SAFETY: Informational ring-0 read.
    unsafe {
        core::arch::asm!(
            "mov {val}, cr3",
            val = out(reg) val,
            options(nomem, nostack, preserves_flags),
        );
    }
    val
}

/// Loads a new page table root into CR3, flushing the TLB (except global entries).
///
/// # Safety
/// - `cr3` must be a valid CR3 value (PML4 address must be mapped and aligned).
/// - Must be called from ring 0.
/// - Writing an invalid CR3 immediately causes a #PF cascade.
#[cfg(target_arch = "x86_64")]
pub unsafe fn write_cr3(cr3: u64) {
    // SAFETY: Caller guarantees cr3 is a valid PML4 base.
    unsafe {
        core::arch::asm!(
            "mov cr3, {val}",
            val = in(reg) cr3,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Switches to a new address space by loading `pml4_phys` into CR3.
///
/// This flushes all non-global TLB entries for the old ASID.
///
/// # Safety
/// See `write_cr3`.
#[cfg(target_arch = "x86_64")]
pub unsafe fn switch_page_table(pml4_phys: u64) {
    // SAFETY: Delegates to write_cr3; caller guarantees pml4_phys is valid.
    unsafe { write_cr3(pml4_phys) }
}

/// Switches to a new address space preserving the current PCID (NOFLUSH hint).
///
/// Only valid when `CR4.PCIDE = 1`. The NOFLUSH bit tells the CPU to skip
/// the TLB flush; software must ensure old translations are not stale.
///
/// # Safety
/// - `CR4.PCIDE` must be enabled.
/// - TLB coherence is the caller's responsibility when using NOFLUSH.
#[cfg(target_arch = "x86_64")]
pub unsafe fn switch_page_table_noflush(cr3: u64) {
    // SAFETY: Caller handles PCIDE and TLB coherence.
    unsafe { write_cr3(cr3 | CR3_NOFLUSH) }
}

/// Returns the physical address of the current PML4.
///
/// # Safety
/// Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn current_pml4_phys() -> u64 {
    // SAFETY: Delegates to read_cr3.
    unsafe { cr3_phys(read_cr3()) }
}

// ---------------------------------------------------------------------------
// TLB Invalidation
// ---------------------------------------------------------------------------

/// Invalidates a single virtual address in the TLB using `invlpg`.
///
/// Only invalidates the TLB entry for `virt_addr` on the current CPU.
/// Other CPUs must be handled via IPI + invlpg (TLB shootdown).
///
/// # Safety
/// - `virt_addr` must be a valid virtual address (need not be mapped).
/// - Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn invlpg(virt_addr: u64) {
    // SAFETY: `invlpg` only reads the address for cache invalidation; no memory access.
    unsafe {
        core::arch::asm!(
            "invlpg [{addr}]",
            addr = in(reg) virt_addr,
            options(nostack, preserves_flags),
        );
    }
}

/// Flushes the entire TLB by reloading CR3 (preserves the current PML4).
///
/// Global entries (PTE/PDE with G=1) are NOT flushed.
///
/// # Safety
/// Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn flush_tlb() {
    // SAFETY: Reading and rewriting the same CR3 is a documented TLB flush technique.
    unsafe {
        let cr3 = read_cr3();
        write_cr3(cr3);
    }
}

/// Flushes the TLB including global entries by toggling `CR4.PGE`.
///
/// Required when remapping kernel global pages (rare; avoid in hot paths).
///
/// # Safety
/// Must be called from ring 0. Briefly clears PGE which may temporarily
/// expose stale TLB entries; caller must ensure no concurrent access issues.
#[cfg(target_arch = "x86_64")]
pub unsafe fn flush_tlb_all() {
    use crate::cr_regs;
    // SAFETY: Toggling PGE is the documented way to flush global TLB entries.
    unsafe {
        let cr4 = cr_regs::read_cr4();
        // Clear PGE to flush global entries, then restore.
        cr_regs::write_cr4(cr4 & !cr_regs::cr4::PGE);
        cr_regs::write_cr4(cr4);
    }
}

/// Invalidates TLB entries for a range of virtual addresses.
///
/// Issues `invlpg` for every 4 KiB-aligned page in `[virt_start, virt_end)`.
///
/// # Safety
/// See `invlpg`. Large ranges can cause significant performance impact.
#[cfg(target_arch = "x86_64")]
pub unsafe fn flush_tlb_range(virt_start: u64, virt_end: u64) {
    let start = virt_start & PAGE_MASK_4K;
    let mut addr = start;
    // SAFETY: Each invlpg call is safe; addr stays within the requested range.
    unsafe {
        while addr < virt_end {
            invlpg(addr);
            addr = addr.saturating_add(PAGE_SIZE_4K);
        }
    }
}

// ---------------------------------------------------------------------------
// INVPCID (when available)
// ---------------------------------------------------------------------------

/// INVPCID type: invalidate individual address for given PCID.
pub const INVPCID_SINGLE_ADDR: u64 = 0;
/// INVPCID type: invalidate all entries for given PCID (not global).
pub const INVPCID_SINGLE_CONTEXT: u64 = 1;
/// INVPCID type: invalidate all non-global entries.
pub const INVPCID_ALL_NON_GLOBAL: u64 = 2;
/// INVPCID type: invalidate all entries including global.
pub const INVPCID_ALL: u64 = 3;

/// INVPCID descriptor (passed in memory to the instruction).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct InvpcidDesc {
    /// PCID to invalidate (bits 11:0; bits 63:12 reserved/zero).
    pub pcid: u64,
    /// Linear address to invalidate (for type 0).
    pub addr: u64,
}

/// Issues INVPCID for fine-grained TLB invalidation.
///
/// # Safety
/// - CPU must support INVPCID (`CPUID.07H:EBX.INVPCID[bit 10]`).
/// - `kind` must be one of the `INVPCID_*` constants.
/// - Must be called from ring 0.
#[cfg(target_arch = "x86_64")]
pub unsafe fn invpcid(kind: u64, desc: &InvpcidDesc) {
    // SAFETY: Caller ensures INVPCID support and correct arguments.
    unsafe {
        core::arch::asm!(
            "invpcid {kind}, [{desc}]",
            kind = in(reg) kind,
            desc = in(reg) desc as *const InvpcidDesc,
            options(nostack, preserves_flags),
        );
    }
}

// ---------------------------------------------------------------------------
// Page Fault Address
// ---------------------------------------------------------------------------

/// Reads CR2 to obtain the faulting virtual address after a #PF.
///
/// # Safety
/// Must be called from ring 0, inside a page-fault handler, before any
/// subsequent page fault (which would overwrite CR2).
#[cfg(target_arch = "x86_64")]
pub unsafe fn read_fault_addr() -> u64 {
    let cr2: u64;
    // SAFETY: `mov %cr2` is a safe informational read in ring 0.
    unsafe {
        core::arch::asm!(
            "mov {cr2}, cr2",
            cr2 = out(reg) cr2,
            options(nomem, nostack, preserves_flags),
        );
    }
    cr2
}
