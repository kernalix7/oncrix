// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! x86_64 Memory Management Unit (MMU) abstraction.
//!
//! Manages the x86_64 4-level (PML4) or 5-level (PML5) page table hierarchy,
//! CR3 loading for address space switching, and TLB maintenance instructions.
//!
//! # Page Table Hierarchy (4-level)
//!
//! - PML4 (Page Map Level 4): 512 entries, 48-bit virtual addresses
//! - PDPT (Page Directory Pointer Table): 512 entries per PML4 entry
//! - PD (Page Directory): 512 entries per PDPT entry
//! - PT (Page Table): 512 entries per PD entry, each maps 4 KB
//!
//! # References
//!
//! - Intel SDM Volume 3A, Chapter 4 (Paging)

#![allow(dead_code)]

use oncrix_lib::Result;

/// x86_64 page table entry flags.
pub mod pte_flags {
    /// Present: page is in memory.
    pub const PRESENT: u64 = 1 << 0;
    /// Read/Write: page is writable.
    pub const WRITABLE: u64 = 1 << 1;
    /// User/Supervisor: accessible from user mode.
    pub const USER: u64 = 1 << 2;
    /// Page-Level Write-Through.
    pub const PWT: u64 = 1 << 3;
    /// Page-Level Cache Disable.
    pub const PCD: u64 = 1 << 4;
    /// Accessed: CPU sets this on read/write.
    pub const ACCESSED: u64 = 1 << 5;
    /// Dirty: CPU sets this on write (leaf entries only).
    pub const DIRTY: u64 = 1 << 6;
    /// Page Size: maps a large page (2 MB/1 GB) rather than pointing to sub-table.
    pub const HUGE: u64 = 1 << 7;
    /// Global: TLB entry is not invalidated on CR3 switch.
    pub const GLOBAL: u64 = 1 << 8;
    /// Execute Disable: no instruction fetches from this page.
    pub const NO_EXEC: u64 = 1 << 63;
}

/// Mask to extract the physical address from a page table entry.
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// x86_64 page table entry.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct PageTableEntry(pub u64);

impl PageTableEntry {
    /// Creates an empty (not-present) entry.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Creates an entry pointing to a sub-table or leaf page.
    ///
    /// # Arguments
    ///
    /// * `phys_addr` - Physical address of the sub-table or page (must be page-aligned)
    /// * `flags` - Combination of `pte_flags::*` constants
    pub const fn new(phys_addr: u64, flags: u64) -> Self {
        Self((phys_addr & PTE_ADDR_MASK) | flags)
    }

    /// Returns the physical address encoded in this entry.
    pub fn phys_addr(self) -> u64 {
        self.0 & PTE_ADDR_MASK
    }

    /// Returns whether this entry is present.
    pub fn is_present(self) -> bool {
        self.0 & pte_flags::PRESENT != 0
    }

    /// Returns whether this is a huge page entry.
    pub fn is_huge(self) -> bool {
        self.0 & pte_flags::HUGE != 0
    }

    /// Returns the flags of this entry.
    pub fn flags(self) -> u64 {
        self.0 & !PTE_ADDR_MASK
    }
}

/// CR3 register value (physical address of PML4 + optional PCID).
#[derive(Debug, Clone, Copy)]
pub struct Cr3 {
    /// Physical address of PML4 table (must be 4 KB aligned).
    pub pml4_phys: u64,
    /// Process Context Identifier (requires CR4.PCIDE).
    pub pcid: u16,
    /// Whether to skip TLB flush on CR3 write (requires CR4.PCIDE).
    pub no_flush: bool,
}

impl Cr3 {
    /// Creates a CR3 value that flushes the TLB on write (no PCID).
    pub const fn new(pml4_phys: u64) -> Self {
        Self {
            pml4_phys,
            pcid: 0,
            no_flush: false,
        }
    }

    /// Creates a CR3 value with PCID.
    pub const fn with_pcid(pml4_phys: u64, pcid: u16, no_flush: bool) -> Self {
        Self {
            pml4_phys,
            pcid,
            no_flush,
        }
    }

    /// Encodes to the raw 64-bit CR3 register value.
    pub fn encode(&self) -> u64 {
        let mut val = (self.pml4_phys & PTE_ADDR_MASK) | (self.pcid as u64 & 0xFFF);
        if self.no_flush {
            val |= 1 << 63;
        }
        val
    }
}

/// x86_64 MMU controller.
pub struct X86Mmu {
    /// Current CR3 value.
    cr3: Cr3,
    /// Whether 5-level paging (PML5) is in use.
    pml5_enabled: bool,
}

impl X86Mmu {
    /// Creates a new x86_64 MMU controller.
    pub const fn new(cr3: Cr3) -> Self {
        Self {
            cr3,
            pml5_enabled: false,
        }
    }

    /// Loads a new page table root into CR3, switching the active address space.
    ///
    /// # Safety
    ///
    /// The caller must ensure the new PML4 table is valid and covers all
    /// required kernel mappings before switching.
    pub unsafe fn load_cr3(&mut self, cr3: Cr3) -> Result<()> {
        let raw = cr3.encode();
        self.cr3 = cr3;
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: Writing CR3 switches the active page table. The caller guarantees
            // a valid PML4 with required kernel mappings. This immediately flushes
            // non-global TLB entries unless the no_flush bit is set with PCID.
            unsafe {
                core::arch::asm!("mov cr3, {val}", val = in(reg) raw, options(nostack, nomem));
            }
        }
        let _ = raw;
        Ok(())
    }

    /// Reads the current CR3 value.
    #[cfg(target_arch = "x86_64")]
    pub fn read_cr3() -> u64 {
        let val: u64;
        // SAFETY: Reading CR3 is always safe in kernel context.
        unsafe {
            core::arch::asm!("mov {val}, cr3", val = out(reg) val, options(nostack, nomem));
        }
        val
    }

    /// Invalidates TLB for a specific linear address (`invlpg`).
    pub fn invlpg(vaddr: usize) {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: invlpg invalidates the TLB entry for a single virtual address.
            // This is always safe to call — at worst it causes an unnecessary TLB miss.
            unsafe {
                core::arch::asm!("invlpg [{addr}]", addr = in(reg) vaddr, options(nostack));
            }
        }
        let _ = vaddr;
    }

    /// Flushes the entire TLB by reloading CR3.
    pub fn flush_all(&self) {
        #[cfg(target_arch = "x86_64")]
        {
            let raw = self.cr3.encode() & !(1u64 << 63); // Clear no_flush bit
            // SAFETY: Rewriting CR3 with the flush bit clear invalidates all
            // non-global TLB entries. Safe when the current CR3 is still valid.
            unsafe {
                core::arch::asm!("mov cr3, {val}", val = in(reg) raw, options(nostack, nomem));
            }
        }
    }

    /// Enables Write Protect (CR0.WP) so kernel cannot write to read-only user pages.
    pub fn enable_write_protect() {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: Setting CR0.WP causes page-fault on kernel writes to R/O pages.
            // Required for security: prevents kernel from accidentally bypassing page protection.
            unsafe {
                core::arch::asm!(
                    "mov {tmp}, cr0",
                    "or  {tmp}, {wp}",
                    "mov cr0, {tmp}",
                    tmp = out(reg) _,
                    wp  = const 0x10000u64,
                    options(nostack, nomem)
                );
            }
        }
    }

    /// Enables No-Execute support (EFER.NXE).
    pub fn enable_nx() -> Result<()> {
        #[cfg(target_arch = "x86_64")]
        {
            const EFER_MSR: u32 = 0xC000_0080;
            const NXE_BIT: u64 = 1 << 11;
            let lo: u32;
            let hi: u32;
            // SAFETY: Reading EFER MSR is safe in kernel context. NXE bit enables
            // the No-Execute page attribute used by pte_flags::NO_EXEC.
            unsafe {
                core::arch::asm!(
                    "rdmsr",
                    in("ecx") EFER_MSR,
                    out("eax") lo,
                    out("edx") hi,
                    options(nostack, nomem)
                );
                let val = ((hi as u64) << 32) | (lo as u64) | NXE_BIT;
                core::arch::asm!(
                    "wrmsr",
                    in("ecx") EFER_MSR,
                    in("eax") (val & 0xFFFF_FFFF) as u32,
                    in("edx") (val >> 32) as u32,
                    options(nostack, nomem)
                );
            }
        }
        Ok(())
    }

    /// Checks whether 5-level paging is active.
    pub fn is_pml5(&self) -> bool {
        self.pml5_enabled
    }

    /// Returns the current CR3 configuration.
    pub fn cr3(&self) -> &Cr3 {
        &self.cr3
    }
}

impl Default for X86Mmu {
    fn default() -> Self {
        Self::new(Cr3::new(0))
    }
}
