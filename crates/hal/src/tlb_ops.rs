// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Translation Lookaside Buffer (TLB) management operations.
//!
//! Provides architecture-independent TLB flush and invalidation primitives,
//! supporting full TLB flushes, per-page invalidation, and ASID-scoped flushes.
//!
//! # TLB Coherence
//!
//! After modifying page table entries, the TLB must be flushed to ensure
//! the CPU uses the updated translations. Failure to flush can result in
//! stale mappings being used, leading to security vulnerabilities or corruption.
//!
//! # SMP Considerations
//!
//! On multi-processor systems, TLB shootdowns may be needed on all CPUs.
//! This module provides local-CPU operations; the caller is responsible
//! for issuing IPI-based shootdowns to remote CPUs.

#![allow(dead_code)]

/// TLB flush scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushScope {
    /// Flush all non-global entries.
    All,
    /// Flush a single page.
    Page(usize),
    /// Flush all entries for a specific ASID (ARM) or PCID (x86).
    Asid(u16),
    /// Flush a specific page within an ASID.
    PageAsid { vaddr: usize, asid: u16 },
    /// Flush global entries (affects all address spaces).
    Global,
}

/// Flushes TLB entries according to the given scope.
///
/// On x86_64, ASID operations fall back to full flush if PCID is not enabled.
pub fn flush(scope: FlushScope) {
    match scope {
        FlushScope::All => flush_all_local(),
        FlushScope::Page(vaddr) => flush_page(vaddr),
        FlushScope::Asid(asid) => flush_asid(asid),
        FlushScope::PageAsid { vaddr, asid } => flush_page_asid(vaddr, asid),
        FlushScope::Global => flush_global(),
    }
}

/// Flushes all non-global TLB entries on the current CPU.
pub fn flush_all_local() {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: Reloading CR3 flushes all non-global TLB entries.
        // The current CR3 value is read then written back to trigger the flush.
        unsafe {
            let cr3: u64;
            core::arch::asm!(
                "mov {cr3}, cr3",
                "mov cr3, {cr3}",
                cr3 = out(reg) cr3,
                options(nostack, nomem)
            );
            let _ = cr3;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: TLBI VMALLE1 invalidates all stage-1 EL1 TLB entries (non-global).
        // DSB/ISB ensure the flush completes before subsequent memory accesses.
        unsafe {
            core::arch::asm!(
                "dsb ishst",
                "tlbi vmalle1",
                "dsb ish",
                "isb",
                options(nostack, nomem)
            );
        }
    }
    #[cfg(target_arch = "riscv64")]
    {
        // SAFETY: sfence.vma with no operands flushes all TLB entries.
        unsafe {
            core::arch::asm!("sfence.vma zero, zero", options(nostack));
        }
    }
}

/// Invalidates a single page's TLB entry on the current CPU.
pub fn flush_page(vaddr: usize) {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: INVLPG invalidates the TLB entry for a single linear address.
        // Always safe to call; at worst causes an unnecessary TLB miss.
        unsafe {
            core::arch::asm!("invlpg [{addr}]", addr = in(reg) vaddr, options(nostack));
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        let page = (vaddr as u64) >> 12;
        // SAFETY: TLBI VAE1 invalidates the TLB entry for a specific virtual address in EL1.
        unsafe {
            core::arch::asm!(
                "dsb ishst",
                "tlbi vae1, {addr}",
                "dsb ish",
                "isb",
                addr = in(reg) page,
                options(nostack, nomem)
            );
        }
    }
    #[cfg(target_arch = "riscv64")]
    {
        // SAFETY: sfence.vma with a specific VA flushes TLB for that address only.
        unsafe {
            core::arch::asm!(
                "sfence.vma {va}, zero",
                va = in(reg) vaddr,
                options(nostack)
            );
        }
    }
    let _ = vaddr;
}

/// Flushes all TLB entries for a specific ASID/PCID.
pub fn flush_asid(asid: u16) {
    #[cfg(target_arch = "x86_64")]
    {
        // x86_64 PCID-based flush requires INVPCID instruction.
        // Fallback: full flush.
        let _ = asid;
        flush_all_local();
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: TLBI ASIDE1 invalidates all TLB entries for a specific ASID.
        let asid_val = (asid as u64) << 48;
        unsafe {
            core::arch::asm!(
                "dsb ishst",
                "tlbi aside1, {asid}",
                "dsb ish",
                "isb",
                asid = in(reg) asid_val,
                options(nostack, nomem)
            );
        }
    }
    #[cfg(target_arch = "riscv64")]
    {
        // SAFETY: sfence.vma with ASID in a1 flushes TLB entries for that ASID.
        unsafe {
            core::arch::asm!(
                "sfence.vma zero, {asid}",
                asid = in(reg) asid as usize,
                options(nostack)
            );
        }
    }
    let _ = asid;
}

/// Flushes a specific page within a specific ASID.
pub fn flush_page_asid(vaddr: usize, asid: u16) {
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: TLBI VAE1 with ASID in bits [63:48] flushes the specific VA+ASID combination.
        let val = ((asid as u64) << 48) | ((vaddr as u64) >> 12);
        unsafe {
            core::arch::asm!(
                "dsb ishst",
                "tlbi vae1, {val}",
                "dsb ish",
                "isb",
                val = in(reg) val,
                options(nostack, nomem)
            );
        }
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        // On other architectures, flush the page without ASID specificity.
        let _ = asid;
        flush_page(vaddr);
    }
    let _ = (vaddr, asid);
}

/// Flushes global TLB entries (those marked with the Global bit).
///
/// On x86_64, this is done by toggling CR4.PGE.
pub fn flush_global() {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: Toggling CR4.PGE flushes all TLB entries including global ones.
        // Must be done in a critical section to avoid races.
        unsafe {
            let cr4: u64;
            core::arch::asm!(
                "mov {cr4}, cr4",
                "and {cr4}, {mask}",   // Clear PGE (bit 7)
                "mov cr4, {cr4}",
                "or  {cr4}, {pge}",    // Re-enable PGE
                "mov cr4, {cr4}",
                cr4  = out(reg) cr4,
                mask = const !0x80u64,
                pge  = const 0x80u64,
                options(nostack, nomem)
            );
            let _ = cr4;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: TLBI VMALLS12E1IS invalidates all stage-1 EL1 global TLB entries
        // across the inner-shareable domain.
        unsafe {
            core::arch::asm!(
                "dsb ishst",
                "tlbi vmalle1is",
                "dsb ish",
                "isb",
                options(nostack, nomem)
            );
        }
    }
    #[cfg(target_arch = "riscv64")]
    {
        // SAFETY: sfence.vma with ASID=0 flushes global TLB entries.
        unsafe {
            core::arch::asm!("sfence.vma zero, zero", options(nostack));
        }
    }
}

/// Returns whether the current CPU supports ASID/PCID.
pub fn has_asid_support() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        // Check CPUID.01H:ECX.PCID[bit 17]
        let ecx: u32;
        // SAFETY: CPUID with EAX=1 is always available on x86.
        // rbx is reserved by LLVM; save/restore it via xchg with a temp register.
        unsafe {
            core::arch::asm!(
                "xchg rbx, {tmp}",
                "cpuid",
                "xchg rbx, {tmp}",
                tmp = out(reg) _,
                lateout("eax") _,
                out("ecx") ecx,
                out("edx") _,
                in("eax") 1u32,
                options(nostack, nomem)
            );
        }
        ecx & (1 << 17) != 0
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        true // AArch64 and RISC-V always support ASID
    }
}
