// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ARM Memory Management Unit (MMU) abstraction.
//!
//! Provides an interface to the ARM MMU using the AArch64 Virtual Memory System
//! Architecture (VMSA). Manages translation table configuration, page attributes,
//! and MMU enable/disable via system registers.
//!
//! # Translation Granules
//!
//! AArch64 supports three translation granule sizes:
//! - 4 KB (TCR_EL1.TG0/TG1 = 0b00)
//! - 16 KB (TCR_EL1.TG0/TG1 = 0b10)
//! - 64 KB (TCR_EL1.TG0/TG1 = 0b01)
//!
//! # References
//!
//! - ARM Architecture Reference Manual (AArch64), Chapter D5 (AArch64 VMSAv8-64)

#![allow(dead_code)]

use oncrix_lib::{Error, Result};

/// Page granule sizes supported by AArch64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Granule {
    /// 4 KB pages.
    Kb4,
    /// 16 KB pages.
    Kb16,
    /// 64 KB pages.
    Kb64,
}

impl Granule {
    /// Returns the page size in bytes.
    pub const fn page_size(self) -> usize {
        match self {
            Self::Kb4 => 4096,
            Self::Kb16 => 16384,
            Self::Kb64 => 65536,
        }
    }

    /// Returns the TCR_EL1 TG field value.
    pub const fn tcr_tg(self) -> u64 {
        match self {
            Self::Kb4 => 0b00,
            Self::Kb16 => 0b10,
            Self::Kb64 => 0b01,
        }
    }
}

/// Memory attribute indices in MAIR_EL1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MemAttr {
    /// Device-nGnRnE (strongly ordered, non-cacheable).
    DeviceNGnRnE = 0,
    /// Normal, Inner/Outer Write-Back, Non-transient.
    NormalWbCacheable = 1,
    /// Normal, Non-cacheable.
    NormalNonCacheable = 2,
    /// Normal, Inner Write-Through, Outer Write-Back.
    NormalWtWb = 3,
}

/// MAIR_EL1 encoding for standard memory attributes.
///
/// Byte layout: [DeviceNGnRnE, NormalWB, NormalNC, NormalWT-WB, 0, 0, 0, 0]
pub const MAIR_EL1_VALUE: u64 = 0x00 |           // Index 0: Device-nGnRnE
    (0xFF << 8) |    // Index 1: Normal WB cacheable
    (0x44 << 16) |   // Index 2: Normal Non-cacheable
    (0xBB << 24); // Index 3: Normal WT outer, WB inner

/// TCR_EL1 configuration for the ARM MMU.
#[derive(Debug, Clone, Copy)]
pub struct TcrConfig {
    /// Translation granule for TTBR0 (user space).
    pub granule0: Granule,
    /// Translation granule for TTBR1 (kernel space).
    pub granule1: Granule,
    /// Virtual address size in bits (T0SZ = 64 - va_bits).
    pub va_bits: u8,
    /// Whether to enable hardware update of access flags.
    pub ha: bool,
    /// Whether to enable hardware update of dirty state.
    pub hd: bool,
}

impl TcrConfig {
    /// Encodes this configuration into the TCR_EL1 register value.
    pub fn encode(&self) -> u64 {
        let t0sz = (64 - self.va_bits) as u64;
        let t1sz = (64 - self.va_bits) as u64;
        let tg0 = self.granule0.tcr_tg();
        let tg1 = self.granule1.tcr_tg();
        let ha = if self.ha { 1u64 << 39 } else { 0 };
        let hd = if self.hd { 1u64 << 40 } else { 0 };
        // IPS = 0b101 (48-bit PA), IRGN0/IRGN1 = 0b01 (WB WA cacheable), ORGN0/ORGN1 = 0b01
        t0sz
            | (0b01 << 8)   // IRGN0
            | (0b01 << 10)  // ORGN0
            | (0b11 << 12)  // SH0 = inner shareable
            | (tg0 << 14)
            | (t1sz << 16)
            | (0b01 << 24)  // IRGN1
            | (0b01 << 26)  // ORGN1
            | (0b11 << 28)  // SH1 = inner shareable
            | (tg1 << 30)
            | (0b101 << 32) // IPS = 48-bit PA
            | ha
            | hd
    }
}

/// ARM MMU controller using AArch64 VMSAv8-64.
pub struct ArmMmu {
    /// Translation table base for EL1 kernel space (TTBR1_EL1).
    ttbr1: u64,
    /// Translation table base for EL0 user space (TTBR0_EL1).
    ttbr0: u64,
    /// TCR configuration.
    tcr_config: TcrConfig,
    /// Whether the MMU is currently enabled.
    enabled: bool,
}

impl ArmMmu {
    /// Creates a new ARM MMU instance.
    pub const fn new(ttbr0: u64, ttbr1: u64, tcr_config: TcrConfig) -> Self {
        Self {
            ttbr1,
            ttbr0,
            tcr_config,
            enabled: false,
        }
    }

    /// Initializes the ARM MMU with the configured translation tables.
    ///
    /// Sets up MAIR_EL1, TCR_EL1, TTBR0_EL1, and TTBR1_EL1 before enabling the MMU.
    pub fn init(&mut self) -> Result<()> {
        if self.tcr_config.va_bits < 32 || self.tcr_config.va_bits > 48 {
            return Err(Error::InvalidArgument);
        }

        #[cfg(target_arch = "aarch64")]
        {
            let tcr_val = self.tcr_config.encode();
            let ttbr0 = self.ttbr0;
            let ttbr1 = self.ttbr1;
            // SAFETY: Writing system registers in sequence (MAIR, TCR, TTBR0/1, ISB)
            // is the standard ARM MMU initialization sequence. ISB ensures all
            // register writes are visible before the MMU is enabled.
            unsafe {
                core::arch::asm!(
                    "msr mair_el1, {mair}",
                    "msr tcr_el1,  {tcr}",
                    "msr ttbr0_el1, {ttbr0}",
                    "msr ttbr1_el1, {ttbr1}",
                    "isb",
                    mair  = in(reg) MAIR_EL1_VALUE,
                    tcr   = in(reg) tcr_val,
                    ttbr0 = in(reg) ttbr0,
                    ttbr1 = in(reg) ttbr1,
                    options(nostack)
                );
            }
        }

        Ok(())
    }

    /// Enables the ARM MMU (sets SCTLR_EL1.M).
    ///
    /// # Safety
    ///
    /// The caller must ensure that valid translation tables are installed and
    /// all required memory mappings (kernel text, stack, etc.) are in place.
    pub unsafe fn enable(&mut self) -> Result<()> {
        if self.enabled {
            return Err(Error::AlreadyExists);
        }
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: Enabling the MMU is only safe when valid translation tables
            // covering the PC and SP are installed. The caller is responsible for
            // this invariant. ISB after the write ensures the MMU is active before
            // the next instruction fetch.
            unsafe {
                core::arch::asm!(
                    "mrs {tmp}, sctlr_el1",
                    "orr {tmp}, {tmp}, #1",
                    "msr sctlr_el1, {tmp}",
                    "isb",
                    tmp = out(reg) _,
                    options(nostack)
                );
            }
        }
        self.enabled = true;
        Ok(())
    }

    /// Disables the ARM MMU (clears SCTLR_EL1.M).
    pub fn disable(&mut self) {
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: Disabling the MMU returns to flat (PA = VA) addressing.
            // Must only be done when the physical layout matches the virtual layout.
            unsafe {
                core::arch::asm!(
                    "mrs {tmp}, sctlr_el1",
                    "bic {tmp}, {tmp}, #1",
                    "msr sctlr_el1, {tmp}",
                    "isb",
                    tmp = out(reg) _,
                    options(nostack)
                );
            }
        }
        self.enabled = false;
    }

    /// Invalidates all TLB entries (TLBI VMALLE1IS).
    pub fn flush_tlb_all(&self) {
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: TLBI VMALLE1IS invalidates all TLB entries for EL1 inner-shareable domain.
            // DSB ensures all prior memory accesses are visible before invalidation.
            // ISB ensures the CPU fetches new instructions after the flush.
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
    }

    /// Invalidates TLB entries for a specific virtual address.
    pub fn flush_tlb_page(&self, vaddr: u64) {
        #[cfg(target_arch = "aarch64")]
        {
            let page_addr = vaddr >> 12;
            // SAFETY: TLBI VAE1IS invalidates TLB entries for a specific VA in EL1.
            // The address is shifted right by 12 as required by the instruction encoding.
            unsafe {
                core::arch::asm!(
                    "dsb ishst",
                    "tlbi vae1is, {addr}",
                    "dsb ish",
                    "isb",
                    addr = in(reg) page_addr,
                    options(nostack, nomem)
                );
            }
        }
        let _ = vaddr;
    }

    /// Returns whether the MMU is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Updates the user-space translation table base (TTBR0_EL1).
    pub fn set_user_table(&mut self, ttbr0: u64) {
        self.ttbr0 = ttbr0;
        #[cfg(target_arch = "aarch64")]
        {
            // SAFETY: Writing TTBR0_EL1 switches the user-space page table.
            // ISB ensures the CPU uses the new table for subsequent fetches.
            unsafe {
                core::arch::asm!(
                    "msr ttbr0_el1, {val}",
                    "isb",
                    val = in(reg) ttbr0,
                    options(nostack)
                );
            }
        }
    }
}

impl Default for ArmMmu {
    fn default() -> Self {
        Self::new(
            0,
            0,
            TcrConfig {
                granule0: Granule::Kb4,
                granule1: Granule::Kb4,
                va_bits: 48,
                ha: false,
                hd: false,
            },
        )
    }
}
