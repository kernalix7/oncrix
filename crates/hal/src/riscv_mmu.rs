// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RISC-V Memory Management Unit (MMU) abstraction using Sv39/Sv48/Sv57.
//!
//! Manages the RISC-V MMU by configuring the `satp` CSR (Supervisor Address
//! Translation and Protection) and providing utilities for page table entry
//! construction and TLB maintenance.
//!
//! # Addressing Modes
//!
//! - **Sv39**: 39-bit virtual addresses, 3-level page tables (512 GB VA space)
//! - **Sv48**: 48-bit virtual addresses, 4-level page tables (256 TB VA space)
//! - **Sv57**: 57-bit virtual addresses, 5-level page tables (128 PB VA space)
//!
//! # References
//!
//! - RISC-V Privileged Architecture Specification, Chapter 10 (Supervisor-Level ISA)

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// RISC-V MMU addressing mode (SATP.MODE field).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum SatpMode {
    /// No translation (bare mode).
    Bare = 0,
    /// Sv39: 3-level page table, 39-bit VA.
    Sv39 = 8,
    /// Sv48: 4-level page table, 48-bit VA.
    Sv48 = 9,
    /// Sv57: 5-level page table, 57-bit VA.
    Sv57 = 10,
}

impl SatpMode {
    /// Returns the number of virtual address bits for this mode.
    pub const fn va_bits(self) -> u32 {
        match self {
            Self::Bare => 0,
            Self::Sv39 => 39,
            Self::Sv48 => 48,
            Self::Sv57 => 57,
        }
    }

    /// Returns the number of page table levels.
    pub const fn levels(self) -> u32 {
        match self {
            Self::Bare => 0,
            Self::Sv39 => 3,
            Self::Sv48 => 4,
            Self::Sv57 => 5,
        }
    }
}

/// Page Table Entry flags for RISC-V.
pub mod pte_flags {
    /// Valid bit: entry is active.
    pub const V: u64 = 1 << 0;
    /// Read permission.
    pub const R: u64 = 1 << 1;
    /// Write permission.
    pub const W: u64 = 1 << 2;
    /// Execute permission.
    pub const X: u64 = 1 << 3;
    /// User accessible.
    pub const U: u64 = 1 << 4;
    /// Global mapping (present in all address spaces).
    pub const G: u64 = 1 << 5;
    /// Accessed: set by hardware on first access.
    pub const A: u64 = 1 << 6;
    /// Dirty: set by hardware on first write.
    pub const D: u64 = 1 << 7;
}

/// A RISC-V page table entry.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct PageTableEntry(pub u64);

impl PageTableEntry {
    /// Creates an invalid (empty) PTE.
    pub const fn invalid() -> Self {
        Self(0)
    }

    /// Creates a leaf PTE mapping a physical page frame with the given flags.
    ///
    /// # Arguments
    ///
    /// * `ppn` - Physical Page Number (physical address >> 12)
    /// * `flags` - Combination of `pte_flags::*` constants
    pub const fn leaf(ppn: u64, flags: u64) -> Self {
        // PPN stored in bits [53:10]; flags in bits [7:0]
        Self((ppn << 10) | flags | pte_flags::V)
    }

    /// Creates a non-leaf (pointer) PTE referencing a sub-table.
    pub const fn branch(ppn: u64) -> Self {
        Self((ppn << 10) | pte_flags::V)
    }

    /// Returns the Physical Page Number from this PTE.
    pub fn ppn(self) -> u64 {
        (self.0 >> 10) & 0x0FFF_FFFF_FFFF
    }

    /// Returns the physical address of the referenced page.
    pub fn phys_addr(self) -> u64 {
        self.ppn() << 12
    }

    /// Returns whether this PTE is valid.
    pub fn is_valid(self) -> bool {
        self.0 & pte_flags::V != 0
    }

    /// Returns whether this is a leaf PTE (has R, W, or X flags).
    pub fn is_leaf(self) -> bool {
        self.0 & (pte_flags::R | pte_flags::W | pte_flags::X) != 0
    }

    /// Returns the flags of this PTE.
    pub fn flags(self) -> u64 {
        self.0 & 0xFF
    }
}

/// RISC-V MMU controller via the `satp` CSR.
pub struct RiscvMmu {
    /// Active addressing mode.
    mode: SatpMode,
    /// Root page table physical address.
    root_ppn: u64,
    /// Address space identifier (ASID).
    asid: u16,
    /// Whether the MMU is currently active.
    active: bool,
}

impl RiscvMmu {
    /// Creates a new RISC-V MMU controller.
    ///
    /// # Arguments
    ///
    /// * `mode` - Virtual addressing mode
    /// * `root_table_pa` - Physical address of the root page table (must be page-aligned)
    /// * `asid` - Address Space Identifier (0 if not used)
    pub const fn new(mode: SatpMode, root_table_pa: u64, asid: u16) -> Self {
        Self {
            mode,
            root_ppn: root_table_pa >> 12,
            asid,
            active: false,
        }
    }

    /// Builds the `satp` CSR value from current configuration.
    pub fn satp_value(&self) -> u64 {
        let mode = self.mode as u64;
        let asid = self.asid as u64;
        (mode << 60) | (asid << 44) | self.root_ppn
    }

    /// Activates the MMU by writing `satp` and issuing `sfence.vma`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the root page table is valid and contains
    /// correct mappings for the current execution context (kernel text, stack).
    pub unsafe fn activate(&mut self) -> Result<()> {
        if self.mode == SatpMode::Bare {
            return Err(Error::InvalidArgument);
        }
        let _satp = self.satp_value();
        #[cfg(target_arch = "riscv64")]
        {
            // SAFETY: Writing satp switches the active page table. The caller guarantees
            // valid mappings exist. sfence.vma flushes the TLB to reflect the new translation.
            unsafe {
                core::arch::asm!(
                    "csrw satp, {satp}",
                    "sfence.vma zero, zero",
                    satp = in(reg) _satp,
                    options(nostack)
                );
            }
        }
        self.active = true;
        Ok(())
    }

    /// Deactivates the MMU (switches to bare/physical mode).
    pub fn deactivate(&mut self) {
        #[cfg(target_arch = "riscv64")]
        {
            // SAFETY: Setting satp to 0 disables virtual memory, reverting to physical addressing.
            unsafe {
                core::arch::asm!("csrw satp, zero", "sfence.vma zero, zero", options(nostack));
            }
        }
        self.active = false;
    }

    /// Flushes all TLB entries.
    pub fn flush_all(&self) {
        #[cfg(target_arch = "riscv64")]
        {
            // SAFETY: sfence.vma with zero operands flushes all TLB entries.
            // This is the standard RISC-V TLB shootdown mechanism.
            unsafe {
                core::arch::asm!("sfence.vma zero, zero", options(nostack));
            }
        }
    }

    /// Flushes TLB entries for a specific virtual address.
    pub fn flush_page(&self, vaddr: usize) {
        #[cfg(target_arch = "riscv64")]
        {
            // SAFETY: sfence.vma with a specific address flushes TLB entries for that VA.
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

    /// Switches to a new address space (updates ASID and root page table).
    pub fn switch_asid(&mut self, root_pa: u64, asid: u16) {
        self.root_ppn = root_pa >> 12;
        self.asid = asid;
        let satp = self.satp_value();
        #[cfg(target_arch = "riscv64")]
        {
            // SAFETY: Updating satp for a context switch. sfence.vma ensures prior
            // memory accesses with the old translation are complete.
            unsafe {
                core::arch::asm!(
                    "csrw satp, {satp}",
                    "sfence.vma zero, zero",
                    satp = in(reg) satp,
                    options(nostack)
                );
            }
        }
        let _ = satp;
    }

    /// Returns whether the MMU is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the current addressing mode.
    pub fn mode(&self) -> SatpMode {
        self.mode
    }
}

impl Default for RiscvMmu {
    fn default() -> Self {
        Self::new(SatpMode::Sv39, 0, 0)
    }
}
