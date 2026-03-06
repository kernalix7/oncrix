// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ARM GICv3 Generic Interrupt Controller driver.
//!
//! The GICv3 architecture provides a centralized interrupt management
//! unit for ARM-based systems. It consists of:
//!
//! - **Distributor (GICD)** — global interrupt routing and enable/disable
//! - **Redistributor (GICR)** — per-CPU interface for SGIs and PPIs
//! - **CPU Interface (ICC)** — system register-based CPU interface (no GICC MMIO)
//!
//! This module implements GICv3 initialization, interrupt enable/disable,
//! priority configuration, and end-of-interrupt signaling.
//!
//! Reference: ARM IHI0069 GICv3 Architecture Specification.

use oncrix_lib::{Error, Result};

// ── GICv3 Distributor register offsets (GICD) ──────────────────────────────

/// Distributor Control Register.
pub const GICD_CTLR: u32 = 0x0000;
/// Interrupt Controller Type Register.
pub const GICD_TYPER: u32 = 0x0004;
/// Interrupt Group Registers base (32 IRQs per register).
pub const GICD_IGROUPR: u32 = 0x0080;
/// Interrupt Set-Enable Registers base.
pub const GICD_ISENABLER: u32 = 0x0100;
/// Interrupt Clear-Enable Registers base.
pub const GICD_ICENABLER: u32 = 0x0180;
/// Interrupt Set-Pending Registers base.
pub const GICD_ISPENDR: u32 = 0x0200;
/// Interrupt Priority Registers base (8 bits per IRQ).
pub const GICD_IPRIORITYR: u32 = 0x0400;
/// Interrupt Configuration Registers base.
pub const GICD_ICFGR: u32 = 0x0C00;
/// Interrupt Routing Registers base (64-bit, one per SPI).
pub const GICD_IROUTER: u32 = 0x6000;

// ── GICv3 Redistributor register offsets (GICR) ────────────────────────────

/// Redistributor Control Register.
pub const GICR_CTLR: u32 = 0x0000;
/// Redistributor Type Register.
pub const GICR_TYPER: u32 = 0x0008;
/// Redistributor Wake Register.
pub const GICR_WAKER: u32 = 0x0014;
/// SGI/PPI Interrupt Group Register 0.
pub const GICR_IGROUPR0: u32 = 0x0080;
/// SGI/PPI Set-Enable Register 0.
pub const GICR_ISENABLER0: u32 = 0x0100;
/// SGI/PPI Clear-Enable Register 0.
pub const GICR_ICENABLER0: u32 = 0x0180;
/// SGI/PPI Priority Registers base.
pub const GICR_IPRIORITYR: u32 = 0x0400;

// ── GICD_CTLR bits ─────────────────────────────────────────────────────────

/// Enable Group 0 interrupts.
const GICD_CTLR_ENABLE_GRP0: u32 = 1 << 0;
/// Enable Group 1 (NS) interrupts.
const GICD_CTLR_ENABLE_GRP1NS: u32 = 1 << 1;
/// ARE (Affinity Routing Enable) for non-secure state.
const GICD_CTLR_ARE_NS: u32 = 1 << 4;

/// Maximum number of redistributors (CPUs) supported.
const MAX_REDIST: usize = 8;
/// Maximum SPIs supported per distributor.
const MAX_SPIS: usize = 988;
/// Default interrupt priority (mid-level, preemptable).
const DEFAULT_PRIORITY: u8 = 0xA0;

// ── MMIO helpers ───────────────────────────────────────────────────────────

/// Read a 32-bit MMIO register.
///
/// # Safety
/// `base` must be a valid mapped MMIO address; `offset` must be within the
/// mapped region and 4-byte aligned.
#[inline]
unsafe fn read32(base: usize, offset: u32) -> u32 {
    // SAFETY: caller guarantees base+offset is valid MMIO.
    unsafe { core::ptr::read_volatile((base + offset as usize) as *const u32) }
}

/// Write a 32-bit MMIO register.
///
/// # Safety
/// Same as [`read32`].
#[inline]
unsafe fn write32(base: usize, offset: u32, val: u32) {
    // SAFETY: caller guarantees base+offset is valid MMIO.
    unsafe { core::ptr::write_volatile((base + offset as usize) as *mut u32, val) }
}

// ── GICv3 Distributor ──────────────────────────────────────────────────────

/// GICv3 Distributor interface.
pub struct Gicd {
    base: usize,
    /// Number of SPIs (lines * 32 - 32).
    num_spis: usize,
}

impl Gicd {
    /// Create a new GICD handle.
    ///
    /// # Safety
    /// `base` must be the MMIO base address of a valid GICv3 Distributor,
    /// mapped read/write with device memory attributes.
    pub unsafe fn new(base: usize) -> Self {
        // SAFETY: caller guarantees base is valid MMIO.
        let typer = unsafe { read32(base, GICD_TYPER) };
        let it_lines = (typer & 0x1F) as usize;
        let num_spis = (it_lines + 1) * 32 - 32;
        Self {
            base,
            num_spis: num_spis.min(MAX_SPIS),
        }
    }

    /// Initialize the distributor: enable affinity routing and Group 1 NS.
    pub fn init(&mut self) -> Result<()> {
        // SAFETY: self.base is valid MMIO set in new().
        unsafe {
            write32(
                self.base,
                GICD_CTLR,
                GICD_CTLR_ARE_NS | GICD_CTLR_ENABLE_GRP1NS | GICD_CTLR_ENABLE_GRP0,
            );
        }
        Ok(())
    }

    /// Enable a Shared Peripheral Interrupt (SPI, intid >= 32).
    pub fn enable_spi(&mut self, intid: u32) -> Result<()> {
        if intid < 32 || intid as usize >= self.num_spis + 32 {
            return Err(Error::InvalidArgument);
        }
        let reg = GICD_ISENABLER + (intid / 32) * 4;
        let bit = 1u32 << (intid % 32);
        // SAFETY: reg offset within GICD range.
        unsafe { write32(self.base, reg, bit) }
        Ok(())
    }

    /// Disable a Shared Peripheral Interrupt.
    pub fn disable_spi(&mut self, intid: u32) -> Result<()> {
        if intid < 32 || intid as usize >= self.num_spis + 32 {
            return Err(Error::InvalidArgument);
        }
        let reg = GICD_ICENABLER + (intid / 32) * 4;
        let bit = 1u32 << (intid % 32);
        // SAFETY: reg offset within GICD range.
        unsafe { write32(self.base, reg, bit) }
        Ok(())
    }

    /// Set the priority of an SPI (0 = highest, 0xFF = lowest).
    pub fn set_priority(&mut self, intid: u32, priority: u8) -> Result<()> {
        if (intid as usize) >= self.num_spis + 32 {
            return Err(Error::InvalidArgument);
        }
        let byte_offset = GICD_IPRIORITYR + intid;
        let word_offset = byte_offset & !3;
        let byte_pos = (byte_offset & 3) * 8;
        // SAFETY: word_offset within GICD range.
        let val = unsafe { read32(self.base, word_offset) };
        let val = (val & !(0xFF << byte_pos)) | ((priority as u32) << byte_pos);
        // SAFETY: same.
        unsafe { write32(self.base, word_offset, val) }
        Ok(())
    }

    /// Route an SPI to a specific CPU by MPIDR affinity value.
    pub fn route_spi(&mut self, intid: u32, mpidr: u64) -> Result<()> {
        if intid < 32 || intid as usize >= self.num_spis + 32 {
            return Err(Error::InvalidArgument);
        }
        let offset = GICD_IROUTER + intid as u32 * 8;
        // SAFETY: offset within GICD IROUTER range.
        unsafe {
            core::ptr::write_volatile(
                (self.base + offset as usize) as *mut u64,
                mpidr & 0xFF_00FF_FFFF,
            )
        }
        Ok(())
    }
}

// ── GICv3 Redistributor ────────────────────────────────────────────────────

/// GICv3 Redistributor (one per CPU).
pub struct Gicr {
    base: usize,
}

impl Gicr {
    /// Create a new GICR handle for a specific CPU redistributor.
    ///
    /// # Safety
    /// `base` must be the MMIO base of the correct CPU's redistributor frame,
    /// mapped with device memory attributes.
    pub unsafe fn new(base: usize) -> Self {
        Self { base }
    }

    /// Wake the redistributor (clear ProcessorSleep, wait for ChildAsleep clear).
    pub fn wake(&mut self) -> Result<()> {
        // SAFETY: self.base valid MMIO.
        let waker = unsafe { read32(self.base, GICR_WAKER) };
        let waker = waker & !(1 << 1); // clear ProcessorSleep
        unsafe { write32(self.base, GICR_WAKER, waker) }
        // Poll until ChildrenAsleep (bit 2) clears.
        for _ in 0..100_000 {
            let w = unsafe { read32(self.base, GICR_WAKER) };
            if w & (1 << 2) == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Enable an SGI/PPI (intid < 32).
    pub fn enable_ppi(&mut self, intid: u32) -> Result<()> {
        if intid >= 32 {
            return Err(Error::InvalidArgument);
        }
        let bit = 1u32 << intid;
        // SAFETY: register within GICR SGI/PPI frame.
        unsafe { write32(self.base, GICR_ISENABLER0, bit) }
        Ok(())
    }

    /// Set the priority of an SGI/PPI.
    pub fn set_ppi_priority(&mut self, intid: u32, priority: u8) -> Result<()> {
        if intid >= 32 {
            return Err(Error::InvalidArgument);
        }
        let byte_offset = GICR_IPRIORITYR + intid;
        let word_offset = byte_offset & !3;
        let byte_pos = (byte_offset & 3) * 8;
        // SAFETY: word_offset within GICR range.
        let val = unsafe { read32(self.base, word_offset) };
        let val = (val & !(0xFF << byte_pos)) | ((priority as u32) << byte_pos);
        unsafe { write32(self.base, word_offset, val) }
        Ok(())
    }
}

// ── GICv3 Controller ───────────────────────────────────────────────────────

/// High-level GICv3 interrupt controller.
pub struct GicV3 {
    gicd: Gicd,
    redists: [Option<Gicr>; MAX_REDIST],
    redist_count: usize,
}

impl GicV3 {
    /// Create a GICv3 controller.
    ///
    /// # Safety
    /// `gicd_base` must be valid MMIO base for the Distributor.
    pub unsafe fn new(gicd_base: usize) -> Self {
        // SAFETY: caller guarantees gicd_base is valid.
        let gicd = unsafe { Gicd::new(gicd_base) };
        Self {
            gicd,
            redists: [const { None }; MAX_REDIST],
            redist_count: 0,
        }
    }

    /// Register a CPU redistributor.
    ///
    /// # Safety
    /// `gicr_base` must be valid MMIO for the redistributor frame.
    pub unsafe fn add_redistributor(&mut self, gicr_base: usize) -> Result<()> {
        if self.redist_count >= MAX_REDIST {
            return Err(Error::OutOfMemory);
        }
        // SAFETY: caller guarantees gicr_base valid.
        let gicr = unsafe { Gicr::new(gicr_base) };
        self.redists[self.redist_count] = Some(gicr);
        self.redist_count += 1;
        Ok(())
    }

    /// Initialize distributor and wake all registered redistributors.
    pub fn init(&mut self) -> Result<()> {
        self.gicd.init()?;
        for i in 0..self.redist_count {
            if let Some(ref mut r) = self.redists[i] {
                r.wake()?;
            }
        }
        Ok(())
    }

    /// Enable an interrupt by ID (SPI >= 32, PPI 16-31, SGI 0-15).
    pub fn enable_irq(&mut self, intid: u32) -> Result<()> {
        if intid < 32 {
            // PPI/SGI: enable on CPU 0 redistributor
            if let Some(ref mut r) = self.redists[0] {
                r.enable_ppi(intid)?;
            }
        } else {
            self.gicd.enable_spi(intid)?;
            self.gicd.set_priority(intid, DEFAULT_PRIORITY)?;
        }
        Ok(())
    }

    /// Disable an interrupt by ID.
    pub fn disable_irq(&mut self, intid: u32) -> Result<()> {
        if intid >= 32 {
            self.gicd.disable_spi(intid)?;
        }
        Ok(())
    }

    /// Signal end-of-interrupt via ICC_EOIR1_EL1 system register.
    #[cfg(target_arch = "aarch64")]
    pub fn eoi(intid: u32) {
        // SAFETY: ICC_EOIR1_EL1 is a write-only system register; writing
        // the interrupt ID signals EOI to the GIC CPU interface.
        unsafe {
            core::arch::asm!(
                "msr ICC_EOIR1_EL1, {}",
                in(reg) intid as u64,
                options(nostack, nomem),
            );
        }
    }
}
